"""Citations, defined once and referenced by every rule.

This module is USP-08. Because every `Finding` carries `standards[]`, the
compliance report card is a `collections.Counter` over this field rather than a
separate subsystem -- but only because the references are attached at
rule-authoring time. Backfilling them on day four does not happen.

The CERT-In entry is deliberate. SIH judging panels are government-adjacent,
and citing the Indian national compliance regime alongside the IETF documents
lands differently from citing RFCs alone.
"""

from __future__ import annotations

from schema import StandardRef

# --------------------------------------------------------------------------- #
# IETF
# --------------------------------------------------------------------------- #

RFC8996 = StandardRef(
    body="RFC", identifier="8996", clause="Section 3",
    requirement="TLS 1.0 and TLS 1.1 MUST NOT be used",
    url="https://www.rfc-editor.org/rfc/rfc8996",
)
RFC8996_SSL = StandardRef(
    body="RFC", identifier="6176",
    requirement="SSL 2.0 MUST NOT be used; RFC 7568 prohibits SSL 3.0",
    url="https://www.rfc-editor.org/rfc/rfc6176",
)
RFC9325 = StandardRef(
    body="RFC", identifier="9325", clause="Section 4.2",
    requirement="Implementations MUST NOT negotiate cipher suites offering less "
                "than 112 bits of security, and SHOULD prefer AEAD suites",
    url="https://www.rfc-editor.org/rfc/rfc9325",
)
RFC9325_PFS = StandardRef(
    body="RFC", identifier="9325", clause="Section 4.1",
    requirement="Implementations SHOULD prefer cipher suites that provide forward secrecy",
    url="https://www.rfc-editor.org/rfc/rfc9325",
)
RFC7465 = StandardRef(
    body="RFC", identifier="7465",
    requirement="RC4 cipher suites MUST NOT be used",
    url="https://www.rfc-editor.org/rfc/rfc7465",
)
RFC8314 = StandardRef(
    body="RFC", identifier="8314", clause="Section 3",
    requirement="Mail submission and access MUST use TLS, with certificate validation",
    url="https://www.rfc-editor.org/rfc/rfc8314",
)
RFC7435 = StandardRef(
    body="RFC", identifier="7435", clause="Section 3",
    requirement="Opportunistic security: unauthenticated encryption is acceptable "
                "where authentication is not possible",
    url="https://www.rfc-editor.org/rfc/rfc7435",
    # Cited to JUSTIFY the relay downgrade, never as a breached requirement.
    relation="context",
)
RFC3207 = StandardRef(
    body="RFC", identifier="3207", clause="Section 4.2",
    requirement="After the TLS handshake the client MUST discard cached server "
                "state and re-issue EHLO",
    url="https://www.rfc-editor.org/rfc/rfc3207",
)
RFC4954 = StandardRef(
    body="RFC", identifier="4954", clause="Section 4",
    requirement="A server MUST NOT advertise plaintext AUTH mechanisms before TLS",
    url="https://www.rfc-editor.org/rfc/rfc4954",
)
RFC5746 = StandardRef(
    body="RFC", identifier="5746",
    requirement="Endpoints MUST support the renegotiation_info extension",
    url="https://www.rfc-editor.org/rfc/rfc5746",
)
RFC8461 = StandardRef(
    body="RFC", identifier="8461",
    requirement="MTA-STS allows a domain to require authenticated TLS from senders",
    url="https://www.rfc-editor.org/rfc/rfc8461",
    # An optional mechanism we RECOMMEND, not a control anyone is in breach of.
    # Not publishing an MTA-STS policy is not "failing RFC 8461".
    relation="context",
)
RFC7672 = StandardRef(
    body="RFC", identifier="7672",
    requirement="DANE TLSA records let an SMTP server publish its expected certificate",
    url="https://www.rfc-editor.org/rfc/rfc7672",
    # As with MTA-STS: an optional mechanism we recommend, not a breached control.
    relation="context",
)
RFC8446_DOWNGRADE = StandardRef(
    body="RFC", identifier="8446", clause="Section 4.1.3",
    requirement="A TLS 1.3 server negotiating an older version MUST set the "
                "downgrade sentinel in ServerHello.random",
    url="https://www.rfc-editor.org/rfc/rfc8446",
    # We cite this to explain HOW we detected the downgrade. The server set the
    # sentinel correctly - it complied. Marking it failed would be backwards.
    relation="context",
)

# --------------------------------------------------------------------------- #
# NIST, CIS, PCI, CERT-In
# --------------------------------------------------------------------------- #

NIST_80052 = StandardRef(
    body="NIST", identifier="SP 800-52 Rev 2", clause="Section 3.1",
    requirement="Servers shall support TLS 1.2 and should support TLS 1.3; "
                "TLS 1.0 and 1.1 shall not be used",
)
NIST_80052_KEY = StandardRef(
    body="NIST", identifier="SP 800-52 Rev 2", clause="Section 3.4",
    requirement="RSA keys shall be at least 2048 bits; ECDSA keys at least 256 bits",
)
NIST_FIPS203 = StandardRef(
    body="NIST", identifier="FIPS 203",
    requirement="ML-KEM standardised for post-quantum key encapsulation",
    # A readiness target, not a control anyone is currently in breach of.
    relation="context",
)
CIS_TLS = StandardRef(
    body="CIS", identifier="Benchmark - TLS configuration",
    requirement="Disable deprecated protocol versions and weak cipher suites",
)
PCI_DSS = StandardRef(
    body="PCI-DSS", identifier="4.0", clause="Requirement 4.2.1",
    requirement="Strong cryptography must protect account data in transit over open networks",
)
CERT_IN = StandardRef(
    body="CERT-In", identifier="Cryptographic Controls Advisory",
    requirement="Deprecated TLS versions and weak ciphers must be disabled on "
                "government and critical-sector infrastructure",
)

#: Every standard we can report on, for the compliance report card (USP-08).
#: A standard is "fail" only when a finding cites it with relation="violates".
#: Entries marked relation="context" are explanatory - we quote them to justify
#: our reasoning or to describe a recommended mechanism, and a report that
#: called those failures would overstate the findings.
ALL_STANDARDS = [
    RFC8996, RFC8996_SSL, RFC9325, RFC7465, RFC8314, RFC7435, RFC3207,
    RFC4954, RFC5746, RFC8461, RFC7672, RFC8446_DOWNGRADE,
    NIST_80052, NIST_80052_KEY, NIST_FIPS203, CIS_TLS, PCI_DSS, CERT_IN,
]


def standard_key(ref: StandardRef) -> str:
    """Stable display key, e.g. 'RFC 8996' or 'NIST SP 800-52 Rev 2'."""
    return f"{ref.body} {ref.identifier}".strip()
