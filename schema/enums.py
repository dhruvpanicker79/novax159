"""Controlled vocabularies for the SecureMailScope data model.

Every enum here is part of the frozen contract (ADR-0005). If you add a member,
update docs/03_ARCHITECTURE.md in the same commit and tell the team, because the
frontend switches on these string values.

All enums are `str`-valued so they serialise to readable JSON.
"""

from enum import Enum


class MailProtocol(str, Enum):
    """Application-layer protocol identified at stage S2. Deliverable D01."""

    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"
    UNKNOWN = "unknown"


class PortRole(str, Enum):
    """What the port is *for*, which determines how harshly we judge it.

    This is the core of USP-01 (role-aware severity). Email TLS has a different
    threat model per role:

    - MTA_RELAY (25): server-to-server. Opportunistic security by design
      (RFC 7435). The sender usually has no trust anchor for the receiver, so
      certificate validation failures are expected, not critical.
    - SUBMISSION (587 STARTTLS, 465 implicit): a user is about to send
      credentials. Strict TLS is mandatory (RFC 8314, RFC 4954).
    - MAIL_ACCESS (143/993 IMAP, 110/995 POP3): a user is about to send
      credentials. Strict TLS is mandatory (RFC 8314).
    """

    MTA_RELAY = "mta_relay"
    SUBMISSION = "submission"
    MAIL_ACCESS = "mail_access"
    UNKNOWN = "unknown"


class TlsMode(str, Enum):
    """How (or whether) the session got to TLS.

    IMPLICIT is what the PS dataset guidance describes (IMAPS/POP3S/SMTPS).
    STARTTLS is the opportunistic upgrade path that D02 requires and that most
    competing teams will not capture. See ADR-0008.
    """

    IMPLICIT = "implicit"
    STARTTLS = "starttls"
    CLEARTEXT = "cleartext"
    UNKNOWN = "unknown"


class PhaseKind(str, Enum):
    """A segment of a session's lifetime. Deliverable D02/D03."""

    PLAINTEXT = "plaintext"
    STARTTLS_NEGOTIATION = "starttls_negotiation"
    ENCRYPTED = "encrypted"


class TlsVersion(str, Enum):
    """Negotiated TLS version. Deliverable D05.

    WARNING for stage S4: a TLS 1.3 server sets ServerHello.legacy_version to
    0x0303 (TLS 1.2) and signals the real version in the `supported_versions`
    extension. Parsing legacy_version alone misreports every 1.3 session as 1.2.
    """

    SSL2 = "ssl2"
    SSL3 = "ssl3"
    TLS1_0 = "tls1.0"
    TLS1_1 = "tls1.1"
    TLS1_2 = "tls1.2"
    TLS1_3 = "tls1.3"
    UNKNOWN = "unknown"

    @property
    def numeric(self) -> float:
        """Ordered numeric form for the feature vector (S7)."""
        return {
            "ssl2": 0.2,
            "ssl3": 0.3,
            "tls1.0": 1.0,
            "tls1.1": 1.1,
            "tls1.2": 1.2,
            "tls1.3": 1.3,
            "unknown": 0.0,
        }[self.value]

    @property
    def is_deprecated(self) -> bool:
        """SSLv2/SSLv3 are prohibited; TLS 1.0/1.1 deprecated by RFC 8996."""
        return self in {
            TlsVersion.SSL2,
            TlsVersion.SSL3,
            TlsVersion.TLS1_0,
            TlsVersion.TLS1_1,
        }


class KeyExchange(str, Enum):
    """Key exchange mechanism. Deliverable D07, feeds Forward Secrecy (D15)."""

    RSA = "rsa"
    DH = "dh"
    DHE = "dhe"
    ECDH = "ecdh"
    ECDHE = "ecdhe"
    PSK = "psk"
    DH_ANON = "dh_anon"
    ECDH_ANON = "ecdh_anon"
    TLS13_EPHEMERAL = "tls13_ephemeral"
    UNKNOWN = "unknown"

    @property
    def has_forward_secrecy(self) -> bool:
        """Deliverable D15. Ephemeral exchanges only. TLS 1.3 is always PFS."""
        return self in {
            KeyExchange.DHE,
            KeyExchange.ECDHE,
            KeyExchange.TLS13_EPHEMERAL,
        }


class PubKeyAlgorithm(str, Enum):
    """Certificate public key algorithm. Deliverable D11."""

    RSA = "rsa"
    ECDSA = "ecdsa"
    ED25519 = "ed25519"
    ED448 = "ed448"
    DSA = "dsa"
    UNKNOWN = "unknown"


class SignatureAlgorithm(str, Enum):
    """Certificate signature algorithm. Deliverable D12."""

    MD5_RSA = "md5WithRSA"
    SHA1_RSA = "sha1WithRSA"
    SHA256_RSA = "sha256WithRSA"
    SHA384_RSA = "sha384WithRSA"
    SHA512_RSA = "sha512WithRSA"
    RSASSA_PSS = "rsassaPss"
    SHA1_ECDSA = "ecdsa-with-SHA1"
    SHA256_ECDSA = "ecdsa-with-SHA256"
    SHA384_ECDSA = "ecdsa-with-SHA384"
    SHA512_ECDSA = "ecdsa-with-SHA512"
    ED25519 = "ed25519"
    UNKNOWN = "unknown"

    @property
    def is_weak(self) -> bool:
        """MD5 and SHA-1 signatures are collision-broken."""
        return self in {
            SignatureAlgorithm.MD5_RSA,
            SignatureAlgorithm.SHA1_RSA,
            SignatureAlgorithm.SHA1_ECDSA,
        }


class ChainStatus(str, Enum):
    """Outcome of passive chain validation. Deliverable D09.

    OPAQUE_TLS13 is not a failure: in TLS 1.3 the Certificate message is
    encrypted, so a passive observer cannot see it. We say so explicitly rather
    than rendering an empty panel. See docs/02_USP.md hostile question 5.
    """

    VALID = "valid"
    SELF_SIGNED = "self_signed"
    INCOMPLETE = "incomplete"          # missing intermediate(s)
    UNKNOWN_ISSUER = "unknown_issuer"  # root not in trust store
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    NAME_MISMATCH = "name_mismatch"
    WRONG_ORDER = "wrong_order"
    OPAQUE_TLS13 = "opaque_tls13"
    ABSENT = "absent"


class Severity(str, Enum):
    """Finding severity. Both the base and the role-adjusted value are kept."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Confidence(str, Enum):
    """How sure we are. Forensic findings report confidence, not certainty."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class Grade(str, Enum):
    """Posture grade, SSL-Labs style. Deliverable D19."""

    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"

    #: We could not inspect enough of this host to grade it - a truncated
    #: capture, or a handshake we could not parse. Showing "?" is the honest
    #: answer; showing A+ because nothing was found would imply we looked.
    INCOMPLETE = "?"


class FindingCategory(str, Enum):
    """Top-level grouping, used for the dashboard's category subscores."""

    PROTOCOL = "protocol"            # D13 deprecated versions
    CIPHER = "cipher"                # D13 weak suites
    KEY_EXCHANGE = "key_exchange"    # D07, D15

    #: Certificate TRUST: expiry, self-signed, chain, name mismatch. These
    #: depend on the trust relationship, which differs by port role, so they
    #: ARE role-adjusted (USP-01). A validation failure on an opportunistic
    #: relay is expected (RFC 7435); on a credential-bearing port it is not.
    CERTIFICATE = "certificate"      # D09, D10

    #: Certificate STRENGTH: key size, signature algorithm. A 1024-bit key is
    #: weak everywhere, so these are NEVER role-adjusted. Splitting this out
    #: stops the relay exemption from quietly excusing broken cryptography.
    CERTIFICATE_STRENGTH = "certificate_strength"  # D11, D12

    CONFIGURATION = "configuration"  # D14
    STARTTLS = "starttls"            # D02
    ATTACK_EVIDENCE = "attack_evidence"   # USP-02
    POST_QUANTUM = "post_quantum"         # USP-05
    COMPLIANCE = "compliance"             # USP-08


class Persona(str, Enum):
    """The four users the PS names. One analysis, four reports. USP-06."""

    SOC = "soc"
    FORENSICS = "forensics"
    INCIDENT_RESPONSE = "incident_response"
    ADMINISTRATOR = "administrator"
