// GENERATED FILE - do not edit by hand.
// Regenerate with:  python -m schema.jsonschema
// Source of truth:  schema/models.py

export type AttackVerdict = "feasible" | "not_applicable" | "not_observable";
export type ChainStatus = "valid" | "self_signed" | "incomplete" | "unknown_issuer" | "expired" | "not_yet_valid" | "name_mismatch" | "wrong_order" | "opaque_tls13" | "absent";
export type Confidence = "low" | "medium" | "high" | "confirmed";
export type FindingCategory = "protocol" | "cipher" | "key_exchange" | "certificate" | "certificate_strength" | "configuration" | "starttls" | "attack_evidence" | "post_quantum" | "compliance";
export type Grade = "A+" | "A" | "B" | "C" | "D" | "E" | "F" | "?";
export type KeyExchange = "rsa" | "dh" | "dhe" | "ecdh" | "ecdhe" | "psk" | "dh_anon" | "ecdh_anon" | "tls13_ephemeral" | "unknown";
export type MailProtocol = "smtp" | "imap" | "pop3" | "unknown";
export type Persona = "soc" | "forensics" | "incident_response" | "administrator";
export type PhaseKind = "plaintext" | "starttls_negotiation" | "encrypted";
export type PortRole = "mta_relay" | "submission" | "mail_access" | "unknown";
export type PubKeyAlgorithm = "rsa" | "ecdsa" | "ed25519" | "ed448" | "dsa" | "unknown";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type SignatureAlgorithm = "md5WithRSA" | "sha1WithRSA" | "sha256WithRSA" | "sha384WithRSA" | "sha512WithRSA" | "rsassaPss" | "ecdsa-with-SHA1" | "ecdsa-with-SHA256" | "ecdsa-with-SHA384" | "ecdsa-with-SHA512" | "ed25519" | "unknown";
export type TlsMode = "implicit" | "starttls" | "cleartext" | "unknown";
export type TlsVersion = "ssl2" | "ssl3" | "tls1.0" | "tls1.1" | "tls1.2" | "tls1.3" | "unknown";

/** One step in the remediation plan. Objective O02. */
export interface ActionItem {
  order: number;
  title: string;
  rationale: string;
  severity: Severity;
  affected: string[];
  rule_ids: string[];
  effort: string;
  risk_of_change: string;
  platform: string;
  config: string;
  standards: string[];
}

/** One named attack, judged against what this capture actually showed. */
export interface AttackAssessment {
  attack_id: string;
  name: string;
  reference: string;
  year: number;
  verdict: AttackVerdict;
  severity: Severity;
  precondition: string;
  rationale: string;
  affected: string[];
  sessions_evaluated: number;
  sessions_matching: number;
  related_rules: string[];
}

/** Signals that an attack has ALREADY happened, not merely that it could. */
export interface AttackEvidence {
  starttls_stripping_suspected: boolean;
  credential_exposure: CredentialExposure[];
  downgrade_sentinel_present: boolean;
  fallback_scsv_present: boolean;
  cipher_intersection_anomaly: boolean;
  weakest_selected_over_available: string | null;
  certificate_substitution: boolean;
  observed_fingerprints: string[];
  corroborating_signals: string[];
  confidence: Confidence;
  evidence: Evidence;
}

/** The source artifact. Stage S0. */
export interface Capture {
  path: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  packet_count: number;
  first_packet_at: string | null;
  last_packet_at: string | null;
  link_type: string;
  decoded_frame_count: number;
  link_layer_note: string;
  analysed_at: string | null;
  tool_version: string;
}

/** Subscore for one finding category, so the dashboard can show a breakdown. */
export interface CategoryScore {
  category: FindingCategory;
  score: number;
  finding_count: number;
  worst_severity: Severity;
}

/** One X.509 certificate. Stage S5. Deliverables D08, D10-D12. */
export interface Certificate {
  chain_position: number;
  subject: string;
  subject_cn: string | null;
  issuer: string;
  issuer_cn: string | null;
  serial_number: string;
  not_before: string | null;
  not_after: string | null;
  sha256_fingerprint: string;
  public_key_algorithm: PubKeyAlgorithm;
  public_key_bits: number | null;
  signature_algorithm: SignatureAlgorithm;
  subject_alt_names: string[];
  is_ca: boolean;
  is_self_signed: boolean;
  key_usage: string[];
  evidence: Evidence;
}

/** Outcome of passive chain validation. Stage S5. Deliverable D09. */
export interface ChainResult {
  status: ChainStatus;
  chain_length: number;
  complete: boolean;
  hostname_matched: boolean | null;
  matched_against: string | null;
  root_in_trust_store: boolean | null;
  issues: string[];
  evidence: Evidence;
}

/** Parsed ClientHello. Feeds JA3, PQ readiness (USP-05) and the cipher */
export interface ClientHelloInfo {
  legacy_version: TlsVersion;
  supported_versions: TlsVersion[];
  cipher_suites: number[];
  cipher_suite_names: string[];
  extensions: number[];
  supported_groups: number[];
  supported_group_names: string[];
  signature_algorithms: string[];
  ec_point_formats: number[];
  server_name: string | null;
  alpn: string[];
  compression_methods: number[];
  fallback_scsv: boolean;
  session_ticket_offered: boolean;
  ja3: string | null;
  ja3_string: string | null;
  evidence: Evidence;
}

/** Authentication material observed in a cleartext phase. */
export interface CredentialExposure {
  mechanism: string;
  username: string | null;
  password_redacted: string | null;
  password_length: number | null;
  raw_b64: string | null;
  evidence: Evidence;
}

/** Where in the capture this fact came from. */
export interface Evidence {
  capture_sha256: string;
  stream_id: number | null;
  frame_numbers: number[];
  byte_range: number[] | null;
  direction: string | null;
  timestamp: string | null;
  note: string | null;
}

/** Explicit, named, inspectable ML input. Objective O01. */
export interface FeatureVector {
  tls_version_num: number;
  is_deprecated_version: boolean;
  version_downgrade_from_offered: number;
  cipher_strength_bits: number;
  cipher_is_aead: boolean;
  cipher_is_cbc: boolean;
  cipher_is_rc4: boolean;
  cipher_is_3des: boolean;
  cipher_is_null_or_anon: boolean;
  cipher_is_export: boolean;
  kex_is_ephemeral: boolean;
  kex_is_anon: boolean;
  kex_group_bits: number;
  has_forward_secrecy: boolean;
  pq_hybrid_offered: boolean;
  pq_hybrid_negotiated: boolean;
  cert_present: boolean;
  cert_opaque_tls13: boolean;
  cert_days_to_expiry: number;
  cert_is_expired: boolean;
  cert_is_self_signed: boolean;
  cert_key_bits: number;
  cert_key_is_rsa: boolean;
  cert_sig_is_weak: boolean;
  cert_chain_length: number;
  cert_chain_complete: boolean;
  cert_hostname_match: boolean;
  port_role_is_relay: boolean;
  port_role_is_submission: boolean;
  port_role_is_access: boolean;
  tls_mode_is_implicit: boolean;
  tls_mode_is_starttls: boolean;
  tls_mode_is_cleartext: boolean;
  starttls_advertised: boolean;
  starttls_completed: boolean;
  starttls_ehlo_reissued: boolean;
  starttls_stripped_suspected: boolean;
  credentials_in_cleartext: boolean;
  auth_before_tls: boolean;
  downgrade_sentinel_present: boolean;
  fallback_scsv_present: boolean;
  cipher_intersection_anomaly: boolean;
  certificate_substitution: boolean;
  renegotiation_info_present: boolean;
  compression_enabled: boolean;
  sni_present: boolean;
  alpn_present: boolean;
  session_resumed: boolean;
  handshake_alert_count: number;
  ja3_rarity: number;
  ja3s_rarity: number;
}

/** One detected issue. Stage S6. Deliverables D13, D14, D15. */
export interface Finding {
  rule_id: string;
  title: string;
  description: string;
  category: FindingCategory;
  base_severity: Severity;
  severity: Severity;
  severity_adjustment_reason: string | null;
  confidence: Confidence;
  affected_host: string | null;
  affected_port: number | null;
  port_role: PortRole;
  session_ids: string[];
  standards: StandardRef[];
  remediation: Remediation | null;
  related_attacks: string[];
  evidence: Evidence;
}

/** Capture-wide assessment. Deliverable D19. */
export interface FleetPosture {
  score: number;
  grade: Grade;
  host_count: number;
  session_count: number;
  category_scores: CategoryScore[];
  forward_secrecy_ratio: number;
  pq_ready_hosts: number;
  deprecated_version_sessions: number;
  cleartext_credential_sessions: number;
  compliance: Record<string, string>;
  summary: string;
}

/** One reconstructed TCP conversation. Stage S1. Deliverable D03. */
export interface Flow {
  stream_id: number;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  started_at: string | null;
  ended_at: string | null;
  packet_count: number;
  c2s_bytes: number;
  s2c_bytes: number;
  byte_to_frame_c2s: Record<string, number>;
  byte_to_frame_s2c: Record<string, number>;
  has_gaps: boolean;
  retransmission_count: number;
  evidence: Evidence;
}

/** How one host's posture moved between two captures. USP-10. */
export interface HostDrift {
  host: string;
  status: string;
  before_grade: string;
  after_grade: string;
  before_score: number;
  after_score: number;
  appeared: string[];
  resolved: string[];
}

/** Per-server rollup. The PS says 'infrastructureS' -- fleet view is required. */
export interface HostPosture {
  host: string;
  ports: number[];
  protocols: MailProtocol[];
  session_count: number;
  score: number;
  grade: Grade;
  category_scores: CategoryScore[];
  worst_tls_version: TlsVersion;
  forward_secrecy_ratio: number;
  pq_ready: boolean;
  finding_counts: Record<string, number>;
  top_findings: Finding[];
}

/** A flow identified as email, with everything we learned about it. */
export interface MailSession {
  session_id: string;
  flow: Flow | null;
  protocol: MailProtocol;
  protocol_confidence: Confidence;
  port_role: PortRole;
  tls_mode: TlsMode;
  server_host: string | null;
  server_port: number;
  client_host: string | null;
  banner: string | null;
  phases: Phase[];
  starttls: StarttlsValidation | null;
  handshake: TlsHandshake | null;
  certificates: Certificate[];
  chain: ChainResult | null;
  attack_evidence: AttackEvidence | null;
  features: FeatureVector | null;
  assessment: SessionAssessment | null;
  findings: Finding[];
  evidence: Evidence;
}

/** The written half of the report. Objective O02, USP-04 layer 3. */
export interface Narrative {
  executive_summary: string;
  action_plan: ActionItem[];
  closing_note: string;
  generated_by: string;
  verification: string;
  grounding_sha256: string;
}

/** A segment of the session's lifetime. Stages S3/S4. Deliverable D02/D03. */
export interface Phase {
  kind: PhaseKind;
  started_at: string | null;
  ended_at: string | null;
  byte_range_c2s: number[] | null;
  byte_range_s2c: number[] | null;
  commands: string[];
  evidence: Evidence;
}

/** The diff between two captures of the same estate. USP-10. */
export interface PostureDrift {
  before_capture: string;
  after_capture: string;
  before_sha256: string;
  after_sha256: string;
  before_at: string | null;
  after_at: string | null;
  before_grade: string;
  after_grade: string;
  before_score: number;
  after_score: number;
  direction: string;
  host_overlap: number;
  comparable: boolean;
  incomparable_reason: string;
  appeared: Finding[];
  resolved: Finding[];
  persisted_count: number;
  hosts: HostDrift[];
  summary: string;
}

/** What to actually do about it. Objective O02. */
export interface Remediation {
  summary: string;
  postfix: string | null;
  dovecot: string | null;
  exchange: string | null;
  generic: string | null;
  effort: string;
  risk_of_change: string;
  llm_generated: boolean;
}

/** Top-level export. Deliverable D20, consumed by the dashboard (D21). */
export interface Report {
  schema_version: string;
  capture: Capture | null;
  sessions: MailSession[];
  hosts: HostPosture[];
  fleet: FleetPosture | null;
  prioritised_findings: Finding[];
  executive_summary: string;
  narrative: Narrative | null;
  attack_matrix: AttackAssessment[];
  generated_at: string | null;
  evaluation_metrics: Record<string, number>;
}

/** Parsed ServerHello. */
export interface ServerHelloInfo {
  legacy_version: TlsVersion;
  negotiated_version: TlsVersion;
  cipher_suite: number | null;
  cipher_suite_name: string | null;
  extensions: number[];
  selected_group: number | null;
  selected_group_name: string | null;
  alpn: string | null;
  compression_method: number | null;
  renegotiation_info: boolean;
  session_resumed: boolean;
  downgrade_sentinel: string | null;
  ja3s: string | null;
  ja3s_string: string | null;
  evidence: Evidence;
}

/** AI output for one session. Deliverables D16, D17, D18. */
export interface SessionAssessment {
  risk_score: number;
  risk_label: Severity;
  shap_contributions: ShapContribution[];
  anomaly_score: number;
  is_anomalous: boolean;
  anomaly_reasons: string[];
  priority_rank: number | null;
  exploitability: number;
  blast_radius: number;
  model_version: string;
}

/** One bar of the explanation waterfall. USP-04. */
export interface ShapContribution {
  feature: string;
  value: number;
  contribution: number;
  human_readable: string;
}

/** A citation. Populate this when you WRITE the rule (USP-08). */
export interface StandardRef {
  body: string;
  identifier: string;
  clause: string | null;
  requirement: string | null;
  url: string | null;
  relation: string;
}

/** The ten checks behind deliverable D02. */
export interface StarttlsValidation {
  v1_advertised: boolean | null;
  v2_capability_mangled: boolean | null;
  v3_client_issued: boolean | null;
  v4_server_accepted: boolean | null;
  v5_clienthello_followed: boolean | null;
  v6_handshake_completed: boolean | null;
  v7_ehlo_reissued: boolean | null;
  v8_auth_offered_before_tls: boolean | null;
  v9_credentials_before_tls: boolean | null;
  v10_command_injection: boolean | null;
  observed_capability_line: string | null;
  evidence: Evidence;
}

/** Reconstructed handshake. Stage S4. Deliverables D04-D07. */
export interface TlsHandshake {
  client_hello: ClientHelloInfo | null;
  server_hello: ServerHelloInfo | null;
  negotiated_version: TlsVersion;
  cipher_suite_name: string | null;
  key_exchange: KeyExchange;
  key_exchange_bits: number | null;
  cipher_bits: number | null;
  is_aead: boolean;
  has_forward_secrecy: boolean;
  message_sequence: string[];
  alerts: string[];
  completed: boolean;
  pq_groups_offered: string[];
  pq_group_negotiated: string | null;
  evidence: Evidence;
}
