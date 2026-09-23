"""S5 - X.509 extraction. Deliverables D08, D10, D11, D12.

IMPORTANT AND OFTEN MISSED: in TLS 1.3 the Certificate message is **encrypted**.
Everything from EncryptedExtensions onward is protected, so a passive observer
cannot see the chain at all. That is not a bug and it is not an empty panel -
`tls/__init__.py` reports `ChainStatus.OPAQUE_TLS13` with a reason, and the
feature extractor sets certificate features to their benign values so no
CERT-* rule fires on data we never saw (ADR-0014).

Everything here is stdlib, built on `certs/der.py`, because `cryptography`'s
Rust extension is blocked on the team's machines (ADR-0012).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from schema import Certificate, Evidence, PubKeyAlgorithm, SignatureAlgorithm

from . import der
from .der import DistinguishedName, Element

# --------------------------------------------------------------------------- #
# OID maps
# --------------------------------------------------------------------------- #

SIGNATURE_OIDS = {
    "1.2.840.113549.1.1.4": SignatureAlgorithm.MD5_RSA,
    "1.2.840.113549.1.1.5": SignatureAlgorithm.SHA1_RSA,
    "1.2.840.113549.1.1.11": SignatureAlgorithm.SHA256_RSA,
    "1.2.840.113549.1.1.12": SignatureAlgorithm.SHA384_RSA,
    "1.2.840.113549.1.1.13": SignatureAlgorithm.SHA512_RSA,
    "1.2.840.113549.1.1.10": SignatureAlgorithm.RSASSA_PSS,
    "1.2.840.10045.4.1": SignatureAlgorithm.SHA1_ECDSA,
    "1.2.840.10045.4.3.2": SignatureAlgorithm.SHA256_ECDSA,
    "1.2.840.10045.4.3.3": SignatureAlgorithm.SHA384_ECDSA,
    "1.2.840.10045.4.3.4": SignatureAlgorithm.SHA512_ECDSA,
    "1.3.101.112": SignatureAlgorithm.ED25519,
}

PUBKEY_OIDS = {
    "1.2.840.113549.1.1.1": PubKeyAlgorithm.RSA,
    "1.2.840.10045.2.1": PubKeyAlgorithm.ECDSA,
    "1.3.101.112": PubKeyAlgorithm.ED25519,
    "1.3.101.113": PubKeyAlgorithm.ED448,
    "1.2.840.10040.4.1": PubKeyAlgorithm.DSA,
}

#: Named curve OID -> key size in bits, for D11 on ECDSA certificates.
CURVE_BITS = {
    "1.2.840.10045.3.1.7": 256,     # prime256v1 / P-256
    "1.3.132.0.34": 384,            # secp384r1
    "1.3.132.0.35": 521,            # secp521r1
    "1.3.132.0.10": 256,            # secp256k1
}

OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_SUBJECT_ALT_NAME = "2.5.29.17"
OID_KEY_USAGE = "2.5.29.15"

KEY_USAGE_BITS = [
    "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
    "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly",
]


@dataclass
class ParsedCertificate:
    """Everything S5 recovered, including what chain validation needs.

    `tbs_bytes` and `signature` are kept so `chain.py` can verify the signature
    - the DER of the tbsCertificate is exactly what was signed.
    """

    certificate: Certificate
    subject: DistinguishedName
    issuer: DistinguishedName
    tbs_bytes: bytes = b""
    signature: bytes = b""
    signature_oid: str = ""
    public_key_der: bytes = b""
    rsa_modulus: int | None = None
    rsa_exponent: int | None = None
    parse_errors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Field extraction
# --------------------------------------------------------------------------- #


def _algorithm_oid(element: Element) -> str:
    first = element.child(0)
    return der.decode_oid(first.value) if first else ""


def _rsa_key_size(spki_bitstring: bytes) -> tuple[int | None, int | None, int]:
    """(modulus, exponent, bit length) from an RSAPublicKey.

    The bit length of the modulus is the key size, which is D11 - and the
    reason a 1024-bit certificate is detectable at all.
    """
    try:
        sequence = der.parse(spki_bitstring)
        kids = sequence.children
        if len(kids) < 2:
            return None, None, 0
        modulus = der.decode_integer(kids[0].value)
        exponent = der.decode_integer(kids[1].value)
        return modulus, exponent, modulus.bit_length()
    except der.DerError:
        return None, None, 0


def _subject_alt_names(extension_value: bytes) -> list[str]:
    """GeneralNames: dNSName is [2], iPAddress is [7]."""
    names: list[str] = []
    try:
        sequence = der.parse(extension_value)
    except der.DerError:
        return names
    for entry in sequence.children:
        tag = entry.tag & 0x1F
        if tag == 2:
            names.append(entry.value.decode("utf-8", errors="replace"))
        elif tag == 7 and len(entry.value) == 4:
            names.append(".".join(str(b) for b in entry.value))
    return names


def _key_usage(extension_value: bytes) -> list[str]:
    try:
        bits = der.parse(extension_value)
    except der.DerError:
        return []
    raw = bits.value
    if len(raw) < 2:
        return []
    unused = raw[0]
    data = raw[1:]
    total = len(data) * 8 - unused
    out: list[str] = []
    for index in range(min(total, len(KEY_USAGE_BITS))):
        byte = data[index // 8]
        if byte & (0x80 >> (index % 8)):
            out.append(KEY_USAGE_BITS[index])
    return out


def _extensions(tbs_children: list[Element]) -> dict[str, bytes]:
    """Pull the [3] EXPLICIT extensions block out of the tbsCertificate."""
    out: dict[str, bytes] = {}
    for element in tbs_children:
        if element.tag != 0xA3:
            continue
        for wrapper in element.children:
            for extension in wrapper.children:
                kids = extension.children
                if len(kids) < 2:
                    continue
                oid = der.decode_oid(kids[0].value)
                # The OCTET STRING is last; a critical BOOLEAN may sit between.
                out[oid] = kids[-1].value
    return out


def parse_certificate(data: bytes, position: int = 0,
                      evidence: Evidence | None = None) -> ParsedCertificate | None:
    """Parse one DER certificate. Deliverables D08, D10, D11, D12.

    Returns None only when the bytes are not a certificate at all. A
    certificate that parses but is missing optional fields comes back with
    those fields empty and a note in `parse_errors` - a truncated capture
    should still tell us the subject and the expiry date.
    """
    try:
        root = der.parse(data)
    except der.DerError:
        return None
    if root.tag != der.SEQUENCE:
        return None

    top = root.children
    if len(top) < 3:
        return None
    tbs, algorithm, signature_bits = top[0], top[1], top[2]

    result = ParsedCertificate(
        certificate=Certificate(chain_position=position,
                                evidence=evidence or Evidence()),
        subject=DistinguishedName(),
        issuer=DistinguishedName(),
        tbs_bytes=data[tbs.offset - root.offset: tbs.offset - root.offset + tbs.total_length],
        signature=der.decode_bitstring(signature_bits.value),
        signature_oid=_algorithm_oid(algorithm),
    )
    cert = result.certificate

    children = tbs.children
    index = 0
    # [0] EXPLICIT version is optional and defaults to v1.
    if children and children[0].tag == 0xA0:
        index = 1

    def at(offset: int) -> Element | None:
        position_ = index + offset
        return children[position_] if position_ < len(children) else None

    serial = at(0)
    if serial is not None:
        cert.serial_number = ":".join(f"{b:02x}" for b in serial.value) or "0"

    issuer_element = at(2)
    if issuer_element is not None:
        result.issuer = der.parse_name(issuer_element)
        cert.issuer = result.issuer.rfc4514()
        cert.issuer_cn = result.issuer.common_name

    validity = at(3)
    if validity is not None and len(validity.children) >= 2:
        cert.not_before = der.decode_time(validity.children[0])
        cert.not_after = der.decode_time(validity.children[1])
    else:
        result.parse_errors.append("validity period unreadable")

    subject_element = at(4)
    if subject_element is not None:
        result.subject = der.parse_name(subject_element)
        cert.subject = result.subject.rfc4514()
        cert.subject_cn = result.subject.common_name

    spki = at(5)
    if spki is not None and len(spki.children) >= 2:
        algorithm_oid = _algorithm_oid(spki.children[0])
        cert.public_key_algorithm = PUBKEY_OIDS.get(algorithm_oid, PubKeyAlgorithm.UNKNOWN)
        key_bits = der.decode_bitstring(spki.children[1].value)
        result.public_key_der = key_bits
        if cert.public_key_algorithm is PubKeyAlgorithm.RSA:
            modulus, exponent, size = _rsa_key_size(key_bits)
            result.rsa_modulus, result.rsa_exponent = modulus, exponent
            cert.public_key_bits = size or None
        elif cert.public_key_algorithm is PubKeyAlgorithm.ECDSA:
            parameters = spki.children[0].child(1)
            curve = der.decode_oid(parameters.value) if parameters else ""
            cert.public_key_bits = CURVE_BITS.get(curve)
        elif cert.public_key_algorithm is PubKeyAlgorithm.ED25519:
            cert.public_key_bits = 256
    else:
        result.parse_errors.append("public key unreadable")

    cert.signature_algorithm = SIGNATURE_OIDS.get(
        result.signature_oid, SignatureAlgorithm.UNKNOWN)

    extensions = _extensions(children)
    if OID_SUBJECT_ALT_NAME in extensions:
        cert.subject_alt_names = _subject_alt_names(extensions[OID_SUBJECT_ALT_NAME])
    if OID_KEY_USAGE in extensions:
        cert.key_usage = _key_usage(extensions[OID_KEY_USAGE])
    if OID_BASIC_CONSTRAINTS in extensions:
        try:
            constraints = der.parse(extensions[OID_BASIC_CONSTRAINTS])
            first = constraints.child(0)
            cert.is_ca = bool(first and first.tag == der.BOOLEAN and first.value == b"\xff")
        except der.DerError:
            pass

    cert.is_self_signed = (result.subject == result.issuer
                           and bool(result.subject.attributes))
    cert.sha256_fingerprint = _fingerprint(data[: root.total_length])
    return result


def _fingerprint(data: bytes) -> str:
    import hashlib  # noqa: PLC0415

    return hashlib.sha256(data).hexdigest()


def parse_chain(certificates: list[bytes],
                evidence: Evidence | None = None) -> list[ParsedCertificate]:
    """Parse a presented chain, leaf first, keeping positions as sent.

    Position matters: a chain served out of order is a real finding, so we
    record what the server actually did rather than sorting it into the right
    shape and hiding the defect.
    """
    out: list[ParsedCertificate] = []
    for position, blob in enumerate(certificates):
        parsed = parse_certificate(blob, position, evidence)
        if parsed is not None:
            out.append(parsed)
    return out


def days_until(cert: Certificate, as_of: datetime | None = None) -> int | None:
    return cert.days_to_expiry(as_of)
