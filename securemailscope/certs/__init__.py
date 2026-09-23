"""S5 - X.509 extraction and chain validation. Deliverables D08-D12.

Owner: person B.

    der.py       a minimal DER reader, stdlib only
    extract.py   certificate field extraction
    chain.py     chain validation, including real RSA signature verification

Built without `cryptography` because Smart App Control blocks its Rust
extension on the team's machines (ADR-0012), and without `openssl` because that
is blocked too. See ADR-0017.

`attach()` below is the stage entry point the pipeline calls.
"""

from __future__ import annotations

from schema import (
    AttackEvidence,
    ChainResult,
    ChainStatus,
    Confidence,
    MailSession,
    TlsVersion,
)

from ..capture.reassemble import ReassembledFlow
from ..tls.records import HS_CERTIFICATE
from . import der  # noqa: F401 - re-exported for convenience
from .chain import validate
from .extract import ParsedCertificate, parse_certificate

#: Certificates observed per server identity, used to spot substitution across
#: sessions within one capture (USP-02). Keyed by "host:port".
_SEEN_FINGERPRINTS: dict[str, set[str]] = {}


def reset_fingerprint_cache() -> None:
    """Clear the cross-session fingerprint memory. Called per capture."""
    _SEEN_FINGERPRINTS.clear()


def parse_certificate_message(body: bytes) -> list[bytes]:
    """Split a TLS 1.2 Certificate message into its DER blobs.

    Layout: a 3-byte total length, then repeated 3-byte length + certificate,
    leaf first. TLS 1.3 adds a request context and per-certificate extensions,
    but a 1.3 Certificate message is encrypted so we never see one.
    """
    if len(body) < 3:
        return []
    total = int.from_bytes(body[0:3], "big")
    data = body[3: 3 + total]
    out: list[bytes] = []
    offset = 0
    while offset + 3 <= len(data):
        length = int.from_bytes(data[offset: offset + 3], "big")
        offset += 3
        if length == 0 or offset + length > len(data):
            break
        out.append(data[offset: offset + length])
        offset += length
    return out


def attach(session: MailSession, flow: ReassembledFlow,
           trust_store: list[ParsedCertificate] | None = None) -> MailSession:
    """Extract and validate the server's certificate chain. D08-D12.

    Sets `ChainStatus.OPAQUE_TLS13` when the session negotiated TLS 1.3: the
    Certificate message is encrypted, so there is nothing to extract. Saying so
    explicitly is the point - an empty panel would read as "no certificate",
    which is a completely different and much worse finding.
    """
    handshake = session.handshake
    if handshake is None:
        return session

    if handshake.negotiated_version is TlsVersion.TLS1_3:
        session.chain = ChainResult(
            status=ChainStatus.OPAQUE_TLS13,
            chain_length=0,
            issues=["TLS 1.3 encrypts the Certificate message; a passive "
                    "observer cannot inspect the chain. This is the expected "
                    "behaviour of a correctly configured modern server."],
            evidence=handshake.evidence,
        )
        return session

    # -- locate the Certificate message ------------------------------------
    from ..tls import _tls_offset  # noqa: PLC0415 - avoids a circular import
    from ..tls.records import iter_handshake_messages  # noqa: PLC0415

    server_bytes = flow.server_bytes
    start = _tls_offset(server_bytes)
    if start is None:
        return session

    blobs: list[bytes] = []
    message_offset = 0
    for message in iter_handshake_messages(server_bytes, start):
        if message.msg_type == HS_CERTIFICATE:
            blobs = parse_certificate_message(message.body)
            message_offset = message.offset
            break

    if not blobs:
        return session

    evidence = flow.evidence_for(
        "s2c", message_offset, message_offset + 64, note="Certificate message")

    parsed: list[ParsedCertificate] = []
    for position, blob in enumerate(blobs):
        result = parse_certificate(blob, position, evidence)
        if result is not None:
            parsed.append(result)

    if not parsed:
        session.chain = ChainResult(
            status=ChainStatus.ABSENT, chain_length=len(blobs),
            issues=["a Certificate message was sent but no certificate in it "
                    "could be parsed"],
            evidence=evidence)
        return session

    session.certificates = [p.certificate for p in parsed]

    server_name = None
    if handshake.client_hello is not None:
        server_name = handshake.client_hello.server_name

    validation = validate(
        parsed, server_name=server_name,
        as_of=session.flow.started_at if session.flow else None,
        trust_store=trust_store)

    result = validation.result
    if validation.signature_note:
        result.issues.append(validation.signature_note)
    session.chain = result

    # -- certificate substitution across sessions (USP-02) -----------------
    key = f"{session.server_host}:{session.server_port}"
    fingerprint = parsed[0].certificate.sha256_fingerprint
    seen = _SEEN_FINGERPRINTS.setdefault(key, set())
    seen.add(fingerprint)
    if len(seen) > 1:
        evidence_block = session.attack_evidence or AttackEvidence()
        evidence_block.certificate_substitution = True
        evidence_block.observed_fingerprints = sorted(seen)
        evidence_block.corroborating_signals.append(
            f"{len(seen)} distinct leaf certificates presented by {key} "
            f"within one capture")
        evidence_block.confidence = Confidence.MEDIUM
        evidence_block.evidence = evidence
        session.attack_evidence = evidence_block

    return session
