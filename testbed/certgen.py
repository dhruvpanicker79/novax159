"""Generate real, properly signed X.509 certificates in pure Python.

Why this exists. `cryptography` imports but `cryptography.x509` does not -
Smart App Control blocks its Rust extension, exactly as it blocks numpy's C
extension (ADR-0012). `openssl` on this machine is blocked too. So the test
corpus needs certificates built from scratch.

This is not a security library and must never be used as one. The RSA key
generation here is straightforward Miller-Rabin with `random`, not a CSPRNG,
and the padding implementation is minimal. It exists to produce **test
artifacts with correct structure and genuine PKCS#1 v1.5 signatures**, so that
S5's parser and its chain validation - including real signature verification -
can be exercised against certificates that a CA actually signed.

    python testbed/certgen.py

Produces `testbed/certs/*.der` matching the scenarios in `manifest.json`.
"""

from __future__ import annotations

import hashlib
import random
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

# --------------------------------------------------------------------------- #
# DER encoding
# --------------------------------------------------------------------------- #


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def der_sequence(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def der_set(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(items))


def der_integer(value: int) -> bytes:
    if value == 0:
        return tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return tlv(0x02, body)


def der_bitstring(data: bytes, unused_bits: int = 0) -> bytes:
    return tlv(0x03, bytes([unused_bits]) + data)


def der_octetstring(data: bytes) -> bytes:
    return tlv(0x04, data)


def der_null() -> bytes:
    return tlv(0x05, b"")


def der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = bytearray([part & 0x7F])
        part >>= 7
        while part:
            chunk.insert(0, (part & 0x7F) | 0x80)
            part >>= 7
        body += bytes(chunk)
    return tlv(0x06, body)


def der_utf8(text: str) -> bytes:
    return tlv(0x0C, text.encode())


def der_ia5(text: str) -> bytes:
    return tlv(0x16, text.encode())


def der_utctime(when: datetime) -> bytes:
    return tlv(0x17, when.strftime("%y%m%d%H%M%SZ").encode())


def der_boolean(value: bool) -> bytes:
    return tlv(0x01, b"\xff" if value else b"\x00")


def context(number: int, value: bytes, constructed: bool = True) -> bytes:
    tag = 0xA0 | number if constructed else 0x80 | number
    return tlv(tag, value)


# --------------------------------------------------------------------------- #
# OIDs
# --------------------------------------------------------------------------- #

OID_CN = "2.5.4.3"
OID_O = "2.5.4.10"
OID_C = "2.5.4.6"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_SHA1_RSA = "1.2.840.113549.1.1.5"
OID_MD5_RSA = "1.2.840.113549.1.1.4"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_SUBJECT_ALT_NAME = "2.5.29.17"
OID_KEY_USAGE = "2.5.29.15"

#: DigestInfo prefixes for PKCS#1 v1.5. The full DER of the AlgorithmIdentifier
#: plus the OCTET STRING header, which precedes the raw hash.
DIGEST_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "md5": bytes.fromhex("3020300c06082a864886f70d020505000410"),
}
SIG_OID = {"sha256": OID_SHA256_RSA, "sha1": OID_SHA1_RSA, "md5": OID_MD5_RSA}


# --------------------------------------------------------------------------- #
# RSA - test quality only
# --------------------------------------------------------------------------- #


def _is_probable_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits: int, rng: random.Random) -> int:
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


@dataclass
class RsaKey:
    n: int
    e: int
    d: int
    bits: int

    def sign(self, message: bytes, digest: str) -> bytes:
        """PKCS#1 v1.5 signature. Test quality; see the module docstring."""
        hashed = hashlib.new(digest, message).digest()
        info = DIGEST_PREFIX[digest] + hashed
        size = (self.bits + 7) // 8
        padding = b"\xff" * (size - len(info) - 3)
        block = b"\x00\x01" + padding + b"\x00" + info
        value = int.from_bytes(block, "big")
        return pow(value, self.d, self.n).to_bytes(size, "big")

    def spki(self) -> bytes:
        """SubjectPublicKeyInfo for an RSA key."""
        rsa_public = der_sequence(der_integer(self.n), der_integer(self.e))
        return der_sequence(
            der_sequence(der_oid(OID_RSA_ENCRYPTION), der_null()),
            der_bitstring(rsa_public),
        )


def generate_rsa(bits: int, seed: int) -> RsaKey:
    """Deterministic for a given seed, so the corpus is reproducible."""
    rng = random.Random(seed)
    e = 65537
    while True:
        p = _random_prime(bits // 2, rng)
        q = _random_prime(bits // 2, rng)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        return RsaKey(n=n, e=e, d=pow(e, -1, phi), bits=bits)


# --------------------------------------------------------------------------- #
# Certificate assembly
# --------------------------------------------------------------------------- #


def name(common_name: str, org: str = "SecureMailScope Testbed",
         country: str = "IN") -> bytes:
    return der_sequence(
        der_set(der_sequence(der_oid(OID_C), tlv(0x13, country.encode()))),
        der_set(der_sequence(der_oid(OID_O), der_utf8(org))),
        der_set(der_sequence(der_oid(OID_CN), der_utf8(common_name))),
    )


def _san_extension(dns_names: list[str]) -> bytes:
    entries = b"".join(tlv(0x82, n.encode()) for n in dns_names)
    return der_sequence(
        der_oid(OID_SUBJECT_ALT_NAME),
        der_octetstring(der_sequence(entries)),
    )


def _basic_constraints(is_ca: bool) -> bytes:
    inner = der_sequence(der_boolean(True)) if is_ca else der_sequence()
    return der_sequence(
        der_oid(OID_BASIC_CONSTRAINTS),
        der_boolean(True),                     # critical
        der_octetstring(inner),
    )


def build_certificate(
    subject_cn: str,
    issuer_cn: str,
    subject_key: RsaKey,
    issuer_key: RsaKey,
    not_before: datetime,
    not_after: datetime,
    serial: int,
    digest: str = "sha256",
    is_ca: bool = False,
    dns_names: list[str] | None = None,
) -> bytes:
    """Produce a signed DER certificate."""
    dns_names = dns_names if dns_names is not None else [subject_cn]
    algorithm = der_sequence(der_oid(SIG_OID[digest]), der_null())

    extensions = [_basic_constraints(is_ca)]
    if dns_names:
        extensions.append(_san_extension(dns_names))

    tbs = der_sequence(
        context(0, der_integer(2)),            # version v3
        der_integer(serial),
        algorithm,
        name(issuer_cn),
        der_sequence(der_utctime(not_before), der_utctime(not_after)),
        name(subject_cn),
        subject_key.spki(),
        context(3, der_sequence(*extensions)),
    )
    signature = issuer_key.sign(tbs, digest)
    return der_sequence(tbs, algorithm, der_bitstring(signature))


# --------------------------------------------------------------------------- #
# The corpus
# --------------------------------------------------------------------------- #

NOW = datetime(2026, 9, 23, 10, 0, tzinfo=timezone.utc)


@dataclass
class CertBundle:
    """A certificate plus whatever the server actually sends with it."""

    name: str
    chain: list[bytes]          #: leaf first, as a server presents it
    description: str


def build_corpus() -> dict[str, CertBundle]:
    """The four scenarios named in `testbed/manifest.json`."""
    ca_key = generate_rsa(1024, seed=1)        # small: keygen speed, not realism
    ca = build_certificate(
        "SecureMailScope Test Root CA", "SecureMailScope Test Root CA",
        ca_key, ca_key, NOW - timedelta(days=3650), NOW + timedelta(days=3650),
        serial=1, is_ca=True, dns_names=[],
    )

    out: dict[str, CertBundle] = {}

    leaf_key = generate_rsa(2048, seed=2)
    out["valid"] = CertBundle(
        "valid",
        [build_certificate("mail-healthy.test", "SecureMailScope Test Root CA",
                           leaf_key, ca_key, NOW - timedelta(days=30),
                           NOW + timedelta(days=90), serial=100), ca],
        "healthy: 2048-bit RSA, SHA-256, complete chain",
    )

    weak_key = generate_rsa(1024, seed=3)
    out["expiring"] = CertBundle(
        "expiring",
        [build_certificate("mail-degraded.test", "SecureMailScope Test Root CA",
                           weak_key, ca_key, NOW - timedelta(days=356),
                           NOW + timedelta(days=9), serial=101, digest="sha1"), ca],
        "degraded: 1024-bit RSA, SHA-1 signature, 9 days remaining",
    )

    self_key = generate_rsa(2048, seed=4)
    out["expired_selfsigned"] = CertBundle(
        "expired_selfsigned",
        [build_certificate("mail-compromised.test", "mail-compromised.test",
                           self_key, self_key, NOW - timedelta(days=412),
                           NOW - timedelta(days=47), serial=102)],
        "compromised: self-signed, expired 47 days ago",
    )

    partial_key = generate_rsa(2048, seed=5)
    out["missing_intermediate"] = CertBundle(
        "missing_intermediate",
        [build_certificate("mail-partial.test", "SecureMailScope Test Root CA",
                           partial_key, ca_key, NOW - timedelta(days=10),
                           NOW + timedelta(days=90), serial=103)],
        "valid leaf, but the CA is not served alongside it",
    )

    out["_ca"] = CertBundle("_ca", [ca], "the test root, for the trust store")
    return out


def main() -> None:
    out_dir = Path(__file__).resolve().parent / "certs"
    out_dir.mkdir(parents=True, exist_ok=True)
    for key, bundle in build_corpus().items():
        for index, der in enumerate(bundle.chain):
            suffix = "" if index == 0 else f".{index}"
            path = out_dir / f"{key}{suffix}.der"
            path.write_bytes(der)
        print(f"  {key:22} {len(bundle.chain)} cert(s)  {bundle.description}")


if __name__ == "__main__":
    main()
