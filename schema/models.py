"""The SecureMailScope data model — THE CONTRACT.

This file is frozen per ADR-0005. Six people build against it in parallel, and
the frontend generates its TypeScript types from it. If you change a field:

    1. change it here,
    2. update docs/03_ARCHITECTURE.md in the SAME commit,
    3. tell the team.

Every object carries an `evidence: Evidence` block (ADR-0004 / USP-03).
Every `Finding` carries `standards` and `remediation` (USP-08 / O02). Populate
them when you author the rule; they will not get backfilled on day four.

Deliverable IDs (D01-D21, O01-O02) refer to docs/01_PROBLEM_STATEMENT.md.
Stage IDs (S0-S11) refer to docs/03_ARCHITECTURE.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .base import Evidence, JsonModel
from .enums import (
    ChainStatus,
    Confidence,
    FindingCategory,
    Grade,
    KeyExchange,
    MailProtocol,
    PhaseKind,
    PortRole,
    PubKeyAlgorithm,
    Severity,
    SignatureAlgorithm,
    TlsMode,
    TlsVersion,
)

SCHEMA_VERSION = "1.0.0"


# --------------------------------------------------------------------------- #
# Port role table  --  the heart of USP-01
# --------------------------------------------------------------------------- #

#: Port -> (protocol, role, is TLS implicit from byte zero).
#: RFC 8314 defines implicit TLS on 465/993/995; RFC 3207/2595 define the
#: STARTTLS upgrade on 25/587/143/110. RFC 7435 makes port 25 opportunistic,
#: which is why certificate failures there are informational, not critical.
PORT_TABLE: dict[int, tuple[MailProtocol, PortRole, bool]] = {
    25: (MailProtocol.SMTP, PortRole.MTA_RELAY, False),
    587: (MailProtocol.SMTP, PortRole.SUBMISSION, False),
    465: (MailProtocol.SMTP, PortRole.SUBMISSION, True),
    143: (MailProtocol.IMAP, PortRole.MAIL_ACCESS, False),
    993: (MailProtocol.IMAP, PortRole.MAIL_ACCESS, True),
    110: (MailProtocol.POP3, PortRole.MAIL_ACCESS, False),
    995: (MailProtocol.POP3, PortRole.MAIL_ACCESS, True),
}


# --------------------------------------------------------------------------- #
# S0 / S1  --  capture and flows
# --------------------------------------------------------------------------- #


@dataclass
class Capture(JsonModel):
    """The source artifact. Stage S0.

    `sha256` is the root of the chain of custody — every Evidence block quotes
    it, so a reader can confirm which file our findings came from.
    """

    path: str = ""
    filename: str = ""
    sha256: str = ""
    size_bytes: int = 0
    packet_count: int = 0
    first_packet_at: datetime | None = None
    last_packet_at: datetime | None = None
    link_type: str = "ethernet"
    #: Frames whose **link layer** we could parse — including ARP and other
    #: non-IP traffic, which is readable but simply is not mail. A capture whose
    #: link layer we cannot decode yields no sessions, which is indistinguishable
    #: from a healthy estate unless we say so — same rule as ADR-0014.
    decoded_frame_count: int = 0
    link_layer_note: str = ""
    analysed_at: datetime | None = None
    tool_version: str = SCHEMA_VERSION


@dataclass
class Flow(JsonModel):
    """One reconstructed TCP conversation. Stage S1. Deliverable D03.

    `c2s_bytes` / `s2c_bytes` hold the reassembled application-layer stream for
    each direction, with retransmissions removed and out-of-order segments put
    back in place. `byte_to_frame` maps an offset in that stream back to the
    packet it arrived in, which is what makes USP-03 possible.
    """

    stream_id: int = 0
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    started_at: datetime | None = None
    ended_at: datetime | None = None
    packet_count: int = 0
    c2s_bytes: int = 0
    s2c_bytes: int = 0
    #: Sparse map: reassembled-stream offset -> originating frame number.
    #: Keys are stringified ints so the structure survives a JSON round trip.
    byte_to_frame_c2s: dict[str, int] = field(default_factory=dict)
    byte_to_frame_s2c: dict[str, int] = field(default_factory=dict)
    has_gaps: bool = False
    retransmission_count: int = 0
    evidence: Evidence = field(default_factory=Evidence)


# --------------------------------------------------------------------------- #
# S3  --  STARTTLS validation and credential exposure
# --------------------------------------------------------------------------- #


@dataclass
class StarttlsValidation(JsonModel):
    """The ten checks behind deliverable D02.

    "Detection *and validation*" is two verbs. Detection is seeing the keyword;
    validation is these ten questions. See docs/01_PROBLEM_STATEMENT.md 3.1.

    Fields are tri-state: True, False, or None for "not applicable / unknown"
    (for example, every check is None on an implicit-TLS session).
    """

    v1_advertised: bool | None = None           #: STARTTLS in EHLO/CAPABILITY/CAPA
    v2_capability_mangled: bool | None = None   #: e.g. '250-XXXXXXXA' -> stripping
    v3_client_issued: bool | None = None        #: client actually sent the command
    v4_server_accepted: bool | None = None      #: 220 / +OK / OK
    v5_clienthello_followed: bool | None = None #: a real handshake began
    v6_handshake_completed: bool | None = None  #: CCS + encrypted application data
    v7_ehlo_reissued: bool | None = None        #: required by RFC 3207 after TLS
    v8_auth_offered_before_tls: bool | None = None  #: RFC 4954 violation
    v9_credentials_before_tls: bool | None = None   #: CRITICAL if True
    v10_command_injection: bool | None = None       #: CVE-2011-0411 class

    #: The raw capability line as observed, for the evidence panel.
    observed_capability_line: str | None = None
    evidence: Evidence = field(default_factory=Evidence)

    @property
    def upgrade_succeeded(self) -> bool:
        return bool(self.v5_clienthello_followed and self.v6_handshake_completed)

    @property
    def failed_checks(self) -> list[str]:
        """Names of the checks that came back bad. Drives the UI panel."""
        bad: list[str] = []
        good_when_true = (
            "v1_advertised", "v3_client_issued", "v4_server_accepted",
            "v5_clienthello_followed", "v6_handshake_completed", "v7_ehlo_reissued",
        )
        good_when_false = (
            "v2_capability_mangled", "v8_auth_offered_before_tls",
            "v9_credentials_before_tls", "v10_command_injection",
        )
        for name in good_when_true:
            if getattr(self, name) is False:
                bad.append(name)
        for name in good_when_false:
            if getattr(self, name) is True:
                bad.append(name)
        return bad


@dataclass
class CredentialExposure(JsonModel):
    """Authentication material observed in a cleartext phase.

    The single most damaging thing we can show on stage (USP-02). We decode the
    base64 to prove it is real, but store only a redacted form by default.
    """

    mechanism: str = ""               #: LOGIN, PLAIN, CRAM-MD5, ...
    username: str | None = None
    password_redacted: str | None = None   #: e.g. 'hu**********23'
    password_length: int | None = None
    raw_b64: str | None = None        #: kept for the forensic export only
    evidence: Evidence = field(default_factory=Evidence)


@dataclass
class Phase(JsonModel):
    """A segment of the session's lifetime. Stages S3/S4. Deliverable D02/D03."""

    kind: PhaseKind = PhaseKind.PLAINTEXT
    started_at: datetime | None = None
    ended_at: datetime | None = None
    byte_range_c2s: list[int] | None = None
    byte_range_s2c: list[int] | None = None
    #: Application-layer commands seen, for the reconstructed-stream view.
    commands: list[str] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)


# --------------------------------------------------------------------------- #
# S4  --  TLS handshake
# --------------------------------------------------------------------------- #


@dataclass
class ClientHelloInfo(JsonModel):
    """Parsed ClientHello. Feeds JA3, PQ readiness (USP-05) and the cipher
    intersection anomaly detector (USP-02)."""

    legacy_version: TlsVersion = TlsVersion.UNKNOWN
    supported_versions: list[TlsVersion] = field(default_factory=list)
    cipher_suites: list[int] = field(default_factory=list)
    cipher_suite_names: list[str] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    supported_group_names: list[str] = field(default_factory=list)
    signature_algorithms: list[str] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    server_name: str | None = None          #: SNI
    alpn: list[str] = field(default_factory=list)
    compression_methods: list[int] = field(default_factory=list)
    #: RFC 7507. Its presence means the client is guarding against fallback.
    fallback_scsv: bool = False
    session_ticket_offered: bool = False
    ja3: str | None = None                  #: MD5 of the JA3 string
    ja3_string: str | None = None
    evidence: Evidence = field(default_factory=Evidence)


@dataclass
class ServerHelloInfo(JsonModel):
    """Parsed ServerHello.

    S4 IMPLEMENTATION WARNING: read the negotiated version from
    `supported_versions`, not from `legacy_version`. A TLS 1.3 server puts
    0x0303 (TLS 1.2) in legacy_version. Teams that miss this misreport every
    single 1.3 session.
    """

    legacy_version: TlsVersion = TlsVersion.UNKNOWN
    negotiated_version: TlsVersion = TlsVersion.UNKNOWN
    cipher_suite: int | None = None
    cipher_suite_name: str | None = None
    extensions: list[int] = field(default_factory=list)
    selected_group: int | None = None
    selected_group_name: str | None = None
    alpn: str | None = None
    compression_method: int | None = None
    renegotiation_info: bool = False        #: absent -> CVE-2009-3555 exposure
    session_resumed: bool = False
    #: RFC 8446 4.1.3: last 8 bytes of ServerHello.random carry the DOWNGRD
    #: sentinel when a 1.3-capable server negotiates something older.
    downgrade_sentinel: str | None = None
    ja3s: str | None = None
    ja3s_string: str | None = None
    evidence: Evidence = field(default_factory=Evidence)


@dataclass
class TlsHandshake(JsonModel):
    """Reconstructed handshake. Stage S4. Deliverables D04-D07.

    D04 says *reconstruction*, which means this has to be rendered as a ladder
    diagram in the UI, not merely parsed. See docs/01_PROBLEM_STATEMENT.md 3.2.
    """

    client_hello: ClientHelloInfo | None = None
    server_hello: ServerHelloInfo | None = None
    negotiated_version: TlsVersion = TlsVersion.UNKNOWN
    cipher_suite_name: str | None = None
    key_exchange: KeyExchange = KeyExchange.UNKNOWN
    key_exchange_bits: int | None = None      #: curve/group strength
    cipher_bits: int | None = None            #: symmetric key size
    is_aead: bool = False
    has_forward_secrecy: bool = False         #: D15
    #: Ordered message types as they appeared, for the ladder diagram.
    message_sequence: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    completed: bool = False
    #: USP-05: hybrid post-quantum groups offered / selected.
    pq_groups_offered: list[str] = field(default_factory=list)
    pq_group_negotiated: str | None = None
    evidence: Evidence = field(default_factory=Evidence)

    @property
    def pq_ready(self) -> bool:
        return bool(self.pq_groups_offered)


# --------------------------------------------------------------------------- #
# S5  --  certificates
# --------------------------------------------------------------------------- #


@dataclass
class Certificate(JsonModel):
    """One X.509 certificate. Stage S5. Deliverables D08, D10-D12."""

    chain_position: int = 0              #: 0 = leaf
    subject: str = ""
    subject_cn: str | None = None
    issuer: str = ""
    issuer_cn: str | None = None
    serial_number: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    sha256_fingerprint: str = ""
    public_key_algorithm: PubKeyAlgorithm = PubKeyAlgorithm.UNKNOWN
    public_key_bits: int | None = None            #: D11
    signature_algorithm: SignatureAlgorithm = SignatureAlgorithm.UNKNOWN  #: D12
    subject_alt_names: list[str] = field(default_factory=list)
    is_ca: bool = False
    is_self_signed: bool = False
    key_usage: list[str] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)

    def days_to_expiry(self, as_of: datetime | None = None) -> int | None:
        """Negative when already expired. Deliverable D10."""
        if self.not_after is None:
            return None
        ref = as_of or datetime.now(tz=self.not_after.tzinfo)
        return (self.not_after - ref).days


@dataclass
class ChainResult(JsonModel):
    """Outcome of passive chain validation. Stage S5. Deliverable D09.

    Passive means we validate what the server actually sent. A missing
    intermediate is a real finding: it means some clients will fail to build a
    path even though the certificate itself is fine.
    """

    status: ChainStatus = ChainStatus.ABSENT
    chain_length: int = 0
    complete: bool = False
    hostname_matched: bool | None = None
    matched_against: str | None = None       #: the SNI or IP we checked
    root_in_trust_store: bool | None = None
    issues: list[str] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)


# --------------------------------------------------------------------------- #
# S6  --  findings
# --------------------------------------------------------------------------- #


@dataclass
class StandardRef(JsonModel):
    """A citation. Populate this when you WRITE the rule (USP-08).

    Aggregating this field across findings produces the compliance report card
    for free. Backfilling it on day four will not happen.
    """

    body: str = ""          #: RFC, NIST, CIS, PCI-DSS, CERT-In
    identifier: str = ""    #: 8996, SP 800-52 Rev 2, ...
    clause: str | None = None
    requirement: str | None = None
    url: str | None = None

    #: "violates" - this finding breaches the cited requirement.
    #: "context"  - the document explains our reasoning but is not breached.
    #:
    #: The distinction matters: RFC 7435 is cited to JUSTIFY downgrading a
    #: certificate finding on an opportunistic relay. Counting that as a
    #: compliance failure would be exactly backwards, and the compliance report
    #: card (USP-08) counts only "violates".
    relation: str = "violates"


@dataclass
class Remediation(JsonModel):
    """What to actually do about it. Objective O02.

    The admin persona (USP-06) wants a snippet to paste, not prose.
    """

    summary: str = ""
    postfix: str | None = None
    dovecot: str | None = None
    exchange: str | None = None
    generic: str | None = None
    effort: str = "unknown"          #: trivial | low | medium | high
    risk_of_change: str = "unknown"  #: e.g. "may break legacy clients"
    #: True when this text came from the LLM layer rather than the rule pack.
    llm_generated: bool = False


@dataclass
class Finding(JsonModel):
    """One detected issue. Stage S6. Deliverables D13, D14, D15.

    USP-01 lives in `base_severity` vs `severity`: the rule emits a base value
    and the role engine adjusts it for the port's actual purpose. We keep BOTH
    and show the reasoning, so an analyst can see why an expired certificate on
    port 25 was downgraded to informational.
    """

    rule_id: str = ""                #: e.g. 'TLS-DEPRECATED-VERSION'
    title: str = ""
    description: str = ""
    category: FindingCategory = FindingCategory.CONFIGURATION
    base_severity: Severity = Severity.INFO
    severity: Severity = Severity.INFO          #: after role adjustment
    severity_adjustment_reason: str | None = None
    confidence: Confidence = Confidence.HIGH
    affected_host: str | None = None
    affected_port: int | None = None
    port_role: PortRole = PortRole.UNKNOWN
    session_ids: list[str] = field(default_factory=list)
    standards: list[StandardRef] = field(default_factory=list)
    remediation: Remediation | None = None
    #: Named attacks this enables. USP-09.
    related_attacks: list[str] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)

    @property
    def was_adjusted(self) -> bool:
        return self.base_severity != self.severity


# --------------------------------------------------------------------------- #
# USP-02  --  attack evidence
# --------------------------------------------------------------------------- #


@dataclass
class AttackEvidence(JsonModel):
    """Signals that an attack has ALREADY happened, not merely that it could.

    This is USP-02 and it is what makes the project a forensic tool rather than
    a configuration linter. All five detectors are purely passive.
    """

    starttls_stripping_suspected: bool = False
    credential_exposure: list[CredentialExposure] = field(default_factory=list)
    downgrade_sentinel_present: bool = False
    fallback_scsv_present: bool = False
    #: Server picked a suite materially weaker than the best mutually supported
    #: one. Requires comparing ClientHello against ServerHello.
    cipher_intersection_anomaly: bool = False
    weakest_selected_over_available: str | None = None
    #: Same server identity presenting different certificates within one capture.
    certificate_substitution: bool = False
    observed_fingerprints: list[str] = field(default_factory=list)
    corroborating_signals: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW
    evidence: Evidence = field(default_factory=Evidence)

    @property
    def any_detected(self) -> bool:
        return any([
            self.starttls_stripping_suspected,
            bool(self.credential_exposure),
            self.downgrade_sentinel_present,
            self.cipher_intersection_anomaly,
            self.certificate_substitution,
        ])


# --------------------------------------------------------------------------- #
# S7  --  the feature vector  (objective O01)
# --------------------------------------------------------------------------- #


@dataclass
class FeatureVector(JsonModel):
    """Explicit, named, inspectable ML input. Objective O01.

    The PS lists feature extraction as its own capability, so this must be a
    documented artifact with a panel in the UI -- not an anonymous array hidden
    inside a `predict()` call. See docs/01_PROBLEM_STATEMENT.md 3.3.

    Keep `field_names()` and the training generator in lockstep: the column
    order here IS the model's input order.
    """

    # -- protocol version ---------------------------------------------------
    tls_version_num: float = 0.0
    is_deprecated_version: bool = False
    version_downgrade_from_offered: float = 0.0   #: best offered minus negotiated

    # -- cipher -------------------------------------------------------------
    cipher_strength_bits: int = 0
    cipher_is_aead: bool = False
    cipher_is_cbc: bool = False
    cipher_is_rc4: bool = False
    cipher_is_3des: bool = False
    cipher_is_null_or_anon: bool = False
    cipher_is_export: bool = False

    # -- key exchange -------------------------------------------------------
    kex_is_ephemeral: bool = False
    kex_is_anon: bool = False
    kex_group_bits: int = 0
    has_forward_secrecy: bool = False

    # -- post-quantum (USP-05) ---------------------------------------------
    pq_hybrid_offered: bool = False
    pq_hybrid_negotiated: bool = False

    # -- certificate --------------------------------------------------------
    cert_present: bool = False
    cert_opaque_tls13: bool = False
    cert_days_to_expiry: int = 0
    cert_is_expired: bool = False
    cert_is_self_signed: bool = False
    cert_key_bits: int = 0
    cert_key_is_rsa: bool = False
    cert_sig_is_weak: bool = False
    cert_chain_length: int = 0
    cert_chain_complete: bool = False
    cert_hostname_match: bool = False

    # -- session context (USP-01) ------------------------------------------
    port_role_is_relay: bool = False
    port_role_is_submission: bool = False
    port_role_is_access: bool = False
    tls_mode_is_implicit: bool = False
    tls_mode_is_starttls: bool = False
    tls_mode_is_cleartext: bool = False

    # -- STARTTLS behaviour (D02) ------------------------------------------
    starttls_advertised: bool = False
    starttls_completed: bool = False
    starttls_ehlo_reissued: bool = False   #: check V7, required by RFC 3207
    starttls_stripped_suspected: bool = False
    credentials_in_cleartext: bool = False
    auth_before_tls: bool = False

    # -- attack evidence (USP-02) ------------------------------------------
    downgrade_sentinel_present: bool = False
    fallback_scsv_present: bool = False
    cipher_intersection_anomaly: bool = False
    certificate_substitution: bool = False

    # -- configuration hygiene (D14) ---------------------------------------
    renegotiation_info_present: bool = False
    compression_enabled: bool = False
    sni_present: bool = False
    alpn_present: bool = False
    session_resumed: bool = False
    handshake_alert_count: int = 0

    # -- fleet-relative (computed at S9, used by the anomaly layer) --------
    ja3_rarity: float = 0.0       #: 1.0 = unique in this capture
    ja3s_rarity: float = 0.0

    @classmethod
    def field_names(cls) -> list[str]:
        """Column order for the model matrix. Do not reorder casually."""
        from dataclasses import fields as _fields
        return [f.name for f in _fields(cls)]

    def as_row(self) -> list[float]:
        """Numeric row for scikit-learn. Booleans become 0.0/1.0."""
        row: list[float] = []
        for name in self.field_names():
            value = getattr(self, name)
            row.append(float(value) if not isinstance(value, bool) else float(bool(value)))
        return row


# --------------------------------------------------------------------------- #
# S8  --  AI output
# --------------------------------------------------------------------------- #


@dataclass
class ShapContribution(JsonModel):
    """One bar of the explanation waterfall. USP-04.

    The explanation is the deliverable; a bare risk number is useless to an
    analyst who has to justify the remediation ticket.
    """

    feature: str = ""
    value: float = 0.0
    contribution: float = 0.0     #: signed push on the score
    human_readable: str = ""      #: 'RC4 cipher suite negotiated'


@dataclass
class SessionAssessment(JsonModel):
    """AI output for one session. Deliverables D16, D17, D18."""

    risk_score: float = 0.0              #: 0.0-1.0 calibrated probability
    risk_label: Severity = Severity.INFO
    shap_contributions: list[ShapContribution] = field(default_factory=list)
    anomaly_score: float = 0.0           #: higher = more unusual
    is_anomalous: bool = False
    anomaly_reasons: list[str] = field(default_factory=list)
    priority_rank: int | None = None     #: D18, position in the triage queue
    #: D18 is not D16: priority folds in exposure and exploitability, not just
    #: severity. Kept separate so the difference is auditable.
    exploitability: float = 0.0
    blast_radius: float = 0.0
    model_version: str = "0.1.0"


@dataclass
class MailSession(JsonModel):
    """A flow identified as email, with everything we learned about it.

    This is the central object: stages S2-S8 all attach to it, and it is what
    the dashboard renders as a session card.
    """

    session_id: str = ""
    flow: Flow | None = None
    protocol: MailProtocol = MailProtocol.UNKNOWN      #: D01
    protocol_confidence: Confidence = Confidence.LOW
    port_role: PortRole = PortRole.UNKNOWN             #: USP-01
    tls_mode: TlsMode = TlsMode.UNKNOWN
    server_host: str | None = None
    server_port: int = 0
    client_host: str | None = None
    banner: str | None = None
    phases: list[Phase] = field(default_factory=list)  #: D02/D03
    starttls: StarttlsValidation | None = None         #: D02
    handshake: TlsHandshake | None = None              #: D04-D07
    certificates: list[Certificate] = field(default_factory=list)  #: D08
    chain: ChainResult | None = None                   #: D09
    attack_evidence: AttackEvidence | None = None      #: USP-02
    features: FeatureVector | None = None              #: O01
    assessment: SessionAssessment | None = None        #: D16-D18
    findings: list[Finding] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)


# --------------------------------------------------------------------------- #
# S9  --  aggregation
# --------------------------------------------------------------------------- #


@dataclass
class CategoryScore(JsonModel):
    """Subscore for one finding category, so the dashboard can show a breakdown."""

    category: FindingCategory = FindingCategory.CONFIGURATION
    score: float = 100.0         #: 0-100, higher is better
    finding_count: int = 0
    worst_severity: Severity = Severity.INFO


@dataclass
class HostPosture(JsonModel):
    """Per-server rollup. The PS says 'infrastructureS' -- fleet view is required."""

    host: str = ""
    ports: list[int] = field(default_factory=list)
    protocols: list[MailProtocol] = field(default_factory=list)
    session_count: int = 0
    score: float = 100.0
    grade: Grade = Grade.A
    category_scores: list[CategoryScore] = field(default_factory=list)
    worst_tls_version: TlsVersion = TlsVersion.UNKNOWN
    forward_secrecy_ratio: float = 1.0     #: D15
    pq_ready: bool = False                 #: USP-05
    finding_counts: dict[str, int] = field(default_factory=dict)
    top_findings: list[Finding] = field(default_factory=list)


@dataclass
class FleetPosture(JsonModel):
    """Capture-wide assessment. Deliverable D19."""

    score: float = 100.0
    grade: Grade = Grade.A
    host_count: int = 0
    session_count: int = 0
    category_scores: list[CategoryScore] = field(default_factory=list)
    forward_secrecy_ratio: float = 1.0
    pq_ready_hosts: int = 0
    deprecated_version_sessions: int = 0
    cleartext_credential_sessions: int = 0
    #: USP-08: standard identifier -> pass/fail/partial.
    compliance: dict[str, str] = field(default_factory=dict)
    summary: str = ""


# --------------------------------------------------------------------------- #
# S10  --  the report
# --------------------------------------------------------------------------- #


@dataclass
class Report(JsonModel):
    """Top-level export. Deliverable D20, consumed by the dashboard (D21).

    `report.json` is the single artifact the frontend loads; HTML and PDF are
    rendered from the same object so all three exports always agree.
    """

    schema_version: str = SCHEMA_VERSION
    capture: Capture | None = None
    sessions: list[MailSession] = field(default_factory=list)
    hosts: list[HostPosture] = field(default_factory=list)
    fleet: FleetPosture | None = None
    #: D18 -- the ranked triage queue, most urgent first.
    prioritised_findings: list[Finding] = field(default_factory=list)
    executive_summary: str = ""
    generated_at: datetime | None = None
    #: USP-07: accuracy numbers from the ground-truth testbed, when available.
    evaluation_metrics: dict[str, float] = field(default_factory=dict)
