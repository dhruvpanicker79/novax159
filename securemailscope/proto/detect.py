"""S2 - identify SMTP / IMAP / POP3. Deliverable D01.

The port is a HINT, never a conclusion. Two failure modes to avoid:

    - a mail service on a non-standard port going unidentified
    - something that is not mail sitting on port 25 being reported as SMTP

So the banner decides and the port corroborates. Confidence reflects which
evidence we actually had:

    CONFIRMED  banner and port agree
    HIGH       banner alone identifies it, on a non-standard port
    MEDIUM     no banner (implicit TLS starts with a ClientHello, so there is
               nothing to read) but the port is a known mail port
    LOW        port only, and it is ambiguous

Implicit TLS is the interesting case: on 465/993/995 the first server byte is
a TLS record, not a greeting, so there is no banner at all. That is not a
detection failure - it is the correct observation, and it sets `tls_mode` to
IMPLICIT.
"""

from __future__ import annotations

import re

from schema import Confidence, MailProtocol, MailSession, TlsMode

from ..capture.reassemble import ReassembledFlow
from .roles import classify_port, infer_role_from_protocol

#: Server greetings. Anchored at the start of the stream: these protocols all
#: have the server speak first, so a match anywhere else is a coincidence.
_SMTP_BANNER = re.compile(rb"^220[ -].{0,200}?(ESMTP|SMTP)", re.IGNORECASE | re.DOTALL)
_SMTP_LOOSE = re.compile(rb"^220[ -]")
_IMAP_BANNER = re.compile(rb"^\*\s+(OK|PREAUTH|BYE)", re.IGNORECASE)
_POP3_BANNER = re.compile(rb"^\+OK")

#: A TLS record: handshake content type, then a plausible legacy version.
#:
#: Two patterns, deliberately. The anchored one asks "does this stream BEGIN
#: with TLS?" (implicit TLS). The unanchored one asks "does TLS appear anywhere
#: in it?" (a STARTTLS upgrade part way through). Calling .search() on the
#: anchored pattern silently answers the first question while reading like the
#: second, which is how every STARTTLS session got reported as cleartext.
_TLS_RECORD = re.compile(rb"^\x16\x03[\x00-\x04]")
_TLS_RECORD_ANYWHERE = re.compile(rb"\x16\x03[\x00-\x04]", re.DOTALL)

#: Any TLS record type - ChangeCipherSpec, Alert, Handshake, ApplicationData.
#: Matched only at offset 0, for a capture that STARTED MID-SESSION: the
#: handshake happened before recording began, so the first bytes we have are
#: protected application data. That is a normal forensic situation, and
#: classifying it as cleartext would be badly wrong - it is an encrypted
#: session we simply cannot inspect. Restricted to offset 0 because these
#: content-type bytes are far less distinctive than a handshake record.
_TLS_ANY_RECORD_AT_START = re.compile(rb"^[\x14-\x17]\x03[\x00-\x04]")


def looks_like_tls(data: bytes) -> bool:
    """Does this stream begin with a TLS *handshake* record?"""
    return bool(_TLS_RECORD.match(data[:5]))


def looks_like_mid_session_tls(data: bytes) -> bool:
    """Does this stream begin with protected TLS records but no handshake?

    The signature of a capture that started after the session was established.
    We cannot assess its cryptography, but calling it cleartext would be a
    serious misreport - so it is encrypted-but-uninspectable, and the coverage
    rule (ADR-0014) says so in the report.
    """
    return bool(_TLS_ANY_RECORD_AT_START.match(data[:5])) and not looks_like_tls(data)


def banner_protocol(first_bytes: bytes) -> tuple[MailProtocol, Confidence]:
    """Identify the protocol from the server's greeting alone."""
    head = first_bytes[:256]
    if _SMTP_BANNER.match(head):
        return MailProtocol.SMTP, Confidence.HIGH
    if _IMAP_BANNER.match(head):
        return MailProtocol.IMAP, Confidence.HIGH
    if _POP3_BANNER.match(head):
        return MailProtocol.POP3, Confidence.HIGH
    if _SMTP_LOOSE.match(head):
        # A 220 greeting without the ESMTP token. Still very likely SMTP, but
        # FTP also greets with 220, so do not claim certainty.
        return MailProtocol.SMTP, Confidence.MEDIUM
    return MailProtocol.UNKNOWN, Confidence.LOW


def first_line(data: bytes, limit: int = 200) -> str | None:
    if not data:
        return None
    line = data.split(b"\r\n", 1)[0][:limit]
    return line.decode("utf-8", errors="replace")


def identify(reassembled: ReassembledFlow) -> MailSession | None:
    """Classify a reconstructed flow as email, or return None.

    Returning None matters as much as returning a session: a capture of a real
    network is mostly not mail, and reporting posture on someone's HTTPS
    traffic would be noise at best.
    """
    flow = reassembled.flow
    server_data = reassembled.server_bytes
    port = flow.dst_port

    port_protocol, port_role, port_implicit = classify_port(port)
    banner_prot, banner_conf = banner_protocol(server_data)
    client_data = reassembled.client_bytes
    is_tls_first = looks_like_tls(server_data) or looks_like_tls(client_data)
    is_mid_session = (looks_like_mid_session_tls(server_data)
                      or looks_like_mid_session_tls(client_data))

    # -- decide the protocol ------------------------------------------------
    if banner_prot is not MailProtocol.UNKNOWN:
        protocol = banner_prot
        if port_protocol is protocol:
            confidence = Confidence.CONFIRMED
        elif port_protocol is MailProtocol.UNKNOWN:
            confidence = Confidence.HIGH
        else:
            # Banner and port disagree. Trust the banner - it is what the
            # server actually said - but say we are less sure.
            confidence = Confidence.MEDIUM
    elif (is_tls_first or is_mid_session) and port_protocol is not MailProtocol.UNKNOWN:
        # Implicit TLS: no greeting to read, the port is all we have.
        protocol = port_protocol
        confidence = Confidence.MEDIUM
    elif port_protocol is not MailProtocol.UNKNOWN and server_data:
        protocol = port_protocol
        confidence = Confidence.LOW
    else:
        return None

    role = port_role if port_role.value != "unknown" else \
        infer_role_from_protocol(protocol, port)

    # -- decide how TLS was reached ----------------------------------------
    if is_tls_first or is_mid_session:
        # Either implicit TLS from byte zero, or a capture that began after the
        # handshake completed. Both are encrypted sessions; neither is cleartext.
        tls_mode = TlsMode.IMPLICIT
    elif (_TLS_RECORD_ANYWHERE.search(server_data)
          or _TLS_RECORD_ANYWHERE.search(client_data)):
        tls_mode = TlsMode.STARTTLS
    else:
        tls_mode = TlsMode.CLEARTEXT

    return MailSession(
        session_id=f"s{flow.stream_id:03d}",
        flow=flow,
        protocol=protocol,
        protocol_confidence=confidence,
        port_role=role,
        tls_mode=tls_mode,
        server_host=flow.dst_ip,
        server_port=port,
        client_host=flow.src_ip,
        banner=None if (is_tls_first or is_mid_session) else first_line(server_data),
        evidence=reassembled.evidence_for("s2c", 0, min(len(server_data), 64),
                                          note="server greeting"),
    )
