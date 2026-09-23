"""S2 - assign a port role to a session. The foundation of USP-01.

Email TLS does not have one threat model, it has three, and which one applies
is decided by what the port is *for*:

    port 25   MTA relay      server-to-server. Opportunistic security by design
                             (RFC 7435). The sending MTA usually has no trust
                             anchor for the receiver, so certificate validation
                             failures are EXPECTED, not critical. Encrypting
                             with an unvalidated certificate still beats
                             cleartext, which is the whole point of RFC 7435.

    587 / 465 Submission     a user is about to send credentials. RFC 8314 and
                             RFC 4954 require TLS with a validated certificate.

    143 / 993 Mail access    same: credentials on the wire.
    110 / 995

Generic TLS scanners apply web-server rules to all of these, which is why they
drown mail administrators in false alarms on port 25. Getting this right is
~50 lines and is the strongest signal that we understand email rather than just
TLS.
"""

from __future__ import annotations

from schema import MailProtocol, PortRole, TlsMode
from schema.models import PORT_TABLE


def classify_port(port: int) -> tuple[MailProtocol, PortRole, bool]:
    """Map a TCP port to `(protocol_hint, role, tls_is_implicit)`.

    The protocol here is only a HINT - S2 confirms it from the server banner,
    so a mail service on a non-standard port is still identified correctly.

    Unknown ports return `(UNKNOWN, UNKNOWN, False)`; the caller should fall
    back to `infer_role_from_protocol` once the banner has been read.
    """
    return PORT_TABLE.get(port, (MailProtocol.UNKNOWN, PortRole.UNKNOWN, False))


def infer_role_from_protocol(protocol: MailProtocol, port: int) -> PortRole:
    """Best-effort role for a mail service on a non-standard port.

    Used when the banner identified the protocol but the port is not one of the
    seven standard ones - for example an SMTP submission service on 2587. We
    assume submission rather than relay for non-standard SMTP ports, because a
    relay listening anywhere other than 25 would not receive public mail, so
    the traffic is far more likely to be a client submitting.
    """
    known = PORT_TABLE.get(port)
    if known is not None:
        return known[1]
    if protocol is MailProtocol.SMTP:
        return PortRole.SUBMISSION
    if protocol in (MailProtocol.IMAP, MailProtocol.POP3):
        return PortRole.MAIL_ACCESS
    return PortRole.UNKNOWN


def expected_tls_mode(port: int) -> TlsMode:
    """What this port *should* be doing, which is not what it *is* doing.

    Comparing the expectation against the observed mode is how we detect a
    submission port serving cleartext.
    """
    known = PORT_TABLE.get(port)
    if known is None:
        return TlsMode.UNKNOWN
    return TlsMode.IMPLICIT if known[2] else TlsMode.STARTTLS


def requires_validated_certificate(role: PortRole) -> bool:
    """Does RFC 8314 demand a trusted, name-matching certificate here?

    False for MTA relay: RFC 7435 opportunistic security explicitly accepts
    unauthenticated encryption where authentication is not possible.
    """
    return role in (PortRole.SUBMISSION, PortRole.MAIL_ACCESS)


def carries_credentials(role: PortRole) -> bool:
    """Will a user password cross this session?

    Drives the blast-radius component of prioritisation (D18) and the cleartext
    credential capping rule in S9.
    """
    return role in (PortRole.SUBMISSION, PortRole.MAIL_ACCESS)
