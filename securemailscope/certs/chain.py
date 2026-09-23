"""S5 - passive chain validation. Deliverable D09.

Passive means we judge what the server actually sent. A browser can fetch a
missing intermediate over AIA and recover; we deliberately do not model that,
because the finding *is* that some clients will fail where others succeed, and
that is the intermittent mail-delivery bug administrators chase for weeks.

What we check:
    - ordering: each certificate's issuer should be the next one's subject
    - completeness: does the presented chain reach a self-signed root?
    - self-signed leaf
    - validity window, both ends, against the time of the capture
    - hostname match against the SNI the client asked for
    - **signature verification** for RSA, done properly

What we do NOT check, and say so:
    - ECDSA and Ed25519 signatures. Verifying those needs elliptic-curve
      arithmetic that stdlib does not provide, and an unverified-but-claimed
      check would be worse than an honest gap. Those chains report
      `signature_verified = None`, not False.
    - Trust-store anchoring, unless a trust store is supplied. Guessing at the
      platform root store would produce results we could not defend.

Severity is NOT decided here. This emits facts; `rules/severity.py` applies the
role-aware adjustment (USP-01), because the same defect means different things
on port 25 and port 993.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from schema import ChainResult, ChainStatus, PubKeyAlgorithm, SignatureAlgorithm

from .extract import ParsedCertificate

#: DigestInfo prefixes for PKCS#1 v1.5, per RFC 8017 - the DER of the
#: AlgorithmIdentifier plus the OCTET STRING header that precedes the hash.
_DIGEST_INFO = {
    SignatureAlgorithm.SHA256_RSA: (
        "sha256", bytes.fromhex("3031300d060960864801650304020105000420")),
    SignatureAlgorithm.SHA384_RSA: (
        "sha384", bytes.fromhex("3041300d060960864801650304020205000430")),
    SignatureAlgorithm.SHA512_RSA: (
        "sha512", bytes.fromhex("3051300d060960864801650304020305000440")),
    SignatureAlgorithm.SHA1_RSA: (
        "sha1", bytes.fromhex("3021300906052b0e03021a05000414")),
    SignatureAlgorithm.MD5_RSA: (
        "md5", bytes.fromhex("3020300c06082a864886f70d020505000410")),
}


def verify_rsa_signature(signed_data: bytes, signature: bytes,
                         modulus: int, exponent: int,
                         algorithm: SignatureAlgorithm) -> bool | None:
    """Verify a PKCS#1 v1.5 signature. Returns None when we cannot check.

    `pow(sig, e, n)` is all the arithmetic RSA verification needs, and Python's
    built-in modular exponentiation is fast enough for a 4096-bit modulus. The
    padding check is done in full rather than by searching for the hash: a
    parser that merely looks for the digest somewhere in the recovered block
    accepts forged signatures (the Bleichenbacher '06 class of bug).
    """
    if algorithm not in _DIGEST_INFO or not signature or not modulus:
        return None

    digest_name, prefix = _DIGEST_INFO[algorithm]
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False

    recovered = pow(int.from_bytes(signature, "big"), exponent, modulus)
    block = recovered.to_bytes(size, "big")

    # EM = 0x00 || 0x01 || PS || 0x00 || T   where PS is at least 8 x 0xFF
    if len(block) < 11 or block[0] != 0x00 or block[1] != 0x01:
        return False
    separator = block.find(b"\x00", 2)
    if separator < 10:
        return False
    if block[2:separator] != b"\xff" * (separator - 2):
        return False

    expected = prefix + hashlib.new(digest_name, signed_data).digest()
    return block[separator + 1:] == expected


def hostname_matches(hostname: str, names: list[str]) -> bool:
    """RFC 6125 matching, including wildcards.

    A wildcard covers exactly one label: `*.example.com` matches
    `mail.example.com` but neither `example.com` nor `a.b.example.com`.
    Getting that wrong in the permissive direction would let us pass a
    certificate a real client would reject.
    """
    if not hostname or not names:
        return False
    target = hostname.lower().rstrip(".")
    for candidate in names:
        entry = candidate.lower().rstrip(".")
        if entry == target:
            return True
        if entry.startswith("*."):
            suffix = entry[2:]
            if not suffix or "." not in suffix:
                continue
            if target.endswith("." + suffix):
                prefix = target[: -(len(suffix) + 1)]
                if prefix and "." not in prefix:
                    return True
    return False


@dataclass
class ChainValidation:
    """The full outcome, including the parts that do not fit `ChainResult`."""

    result: ChainResult
    signature_verified: bool | None = None
    signature_note: str = ""


def validate(certificates: list[ParsedCertificate],
             server_name: str | None = None,
             as_of: datetime | None = None,
             trust_store: list[ParsedCertificate] | None = None) -> ChainValidation:
    """Validate a presented chain. Deliverable D09."""
    if not certificates:
        return ChainValidation(ChainResult(status=ChainStatus.ABSENT, chain_length=0))

    now = as_of or datetime.now(tz=timezone.utc)
    leaf = certificates[0]
    result = ChainResult(chain_length=len(certificates), evidence=leaf.certificate.evidence)
    issues: list[str] = []

    # -- validity window ----------------------------------------------------
    not_before = leaf.certificate.not_before
    not_after = leaf.certificate.not_after
    expired = bool(not_after and not_after < now)
    not_yet_valid = bool(not_before and not_before > now)
    if expired:
        issues.append(f"leaf expired on {not_after:%Y-%m-%d}")
    if not_yet_valid:
        issues.append(f"leaf not valid until {not_before:%Y-%m-%d}")

    # -- hostname -----------------------------------------------------------
    if server_name:
        names = list(leaf.certificate.subject_alt_names)
        # Fall back to CN only when there is no SAN at all. Modern clients
        # ignore CN entirely, so a CN-only certificate is itself a defect.
        if not names and leaf.certificate.subject_cn:
            names = [leaf.certificate.subject_cn]
            issues.append("certificate has no subjectAltName; CN fallback is "
                          "rejected by current clients")
        result.matched_against = server_name
        result.hostname_matched = hostname_matches(server_name, names)
        if not result.hostname_matched:
            issues.append(f"no name in the certificate matches {server_name}")

    # -- ordering and completeness -----------------------------------------
    ordered = True
    for index in range(len(certificates) - 1):
        if certificates[index].issuer != certificates[index + 1].subject:
            ordered = False
            issues.append(f"chain position {index} is not issued by position {index + 1}")
    if not ordered:
        result.issues = issues

    last = certificates[-1]
    reaches_root = last.certificate.is_self_signed
    result.complete = ordered and reaches_root and len(certificates) > 1

    # -- trust anchor -------------------------------------------------------
    if trust_store:
        anchors = {c.subject for c in trust_store}
        result.root_in_trust_store = last.issuer in anchors or last.subject in anchors
        if not result.root_in_trust_store:
            issues.append("chain does not terminate in a trusted root")
    else:
        # Honest default: we were given no trust store, so we did not check.
        result.root_in_trust_store = None

    # -- signature ----------------------------------------------------------
    verified: bool | None = None
    note = ""
    if len(certificates) > 1:
        issuer = certificates[1]
    elif leaf.certificate.is_self_signed:
        issuer = leaf
    else:
        issuer = None

    if issuer is None:
        note = "issuer certificate was not presented, so the signature cannot be checked"
    elif issuer.certificate.public_key_algorithm is not PubKeyAlgorithm.RSA:
        note = (f"issuer key is {issuer.certificate.public_key_algorithm.value}; "
                f"only RSA signatures are verified")
    elif issuer.rsa_modulus is None or issuer.rsa_exponent is None:
        note = "issuer public key could not be read"
    else:
        verified = verify_rsa_signature(
            leaf.tbs_bytes, leaf.signature,
            issuer.rsa_modulus, issuer.rsa_exponent,
            leaf.certificate.signature_algorithm)
        if verified is False:
            issues.append("leaf signature does not verify against the presented issuer")
            note = "signature check failed"
        elif verified is None:
            note = (f"signature algorithm {leaf.certificate.signature_algorithm.value} "
                    f"is not one we verify")
        else:
            note = "leaf signature verified against the presented issuer"

    # -- overall status -----------------------------------------------------
    if expired:
        status = ChainStatus.EXPIRED
    elif not_yet_valid:
        status = ChainStatus.NOT_YET_VALID
    elif leaf.certificate.is_self_signed:
        status = ChainStatus.SELF_SIGNED
    elif not ordered:
        status = ChainStatus.WRONG_ORDER
    elif result.hostname_matched is False:
        status = ChainStatus.NAME_MISMATCH
    elif not result.complete:
        status = ChainStatus.INCOMPLETE
    elif result.root_in_trust_store is False:
        status = ChainStatus.UNKNOWN_ISSUER
    else:
        status = ChainStatus.VALID

    result.status = status
    result.issues = issues
    return ChainValidation(result=result, signature_verified=verified,
                           signature_note=note)


def load_trust_store(paths: list[str]) -> list[ParsedCertificate]:
    """Load DER anchors from disk. Used by tests and by the testbed."""
    from pathlib import Path  # noqa: PLC0415

    from .extract import parse_certificate  # noqa: PLC0415

    out: list[ParsedCertificate] = []
    for path in paths:
        blob = Path(path).read_bytes()
        parsed = parse_certificate(blob)
        if parsed is not None:
            out.append(parsed)
    return out
