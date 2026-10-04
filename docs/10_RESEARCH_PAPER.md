# CyberKavach — Passive Cryptographic Posture Assessment for Email Infrastructure

### An evidence-first, offline framework for assessing SMTP, IMAP and POP3 transport security from packet captures

**Team:** [TEAM NAME]
**Team ID:** [TEAM ID]
**Problem Statement ID:** SIH26159
**Problem Statement Title:** SecureMailScope — AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications
**Organisation:** National Technical Research Organisation (NTRO)
**Theme:** Blockchain & Cybersecurity
**Category:** Software
**Smart India Hackathon 2026**
**3 October 2026**

---

## Abstract

Electronic mail carries password resets, financial instructions and legal notices, yet the cryptography that
protects it in transit was added as an afterthought and is designed to fail silently: where encryption cannot be
negotiated, mail is delivered in plain text and neither party is informed. Measurement has established the
consequences. Of roughly 700,000 SMTP servers, 82% offer TLS but only 35% are configured so the peer can
authenticate them; 65% of SMTP hosts present self-signed certificates; over 40 implementation flaws have been
catalogued in the STARTTLS upgrade mechanism, with 320,000 servers — 2% of all mail servers — vulnerable to a
credential-stealing command injection; and 41,405 servers across 193 countries have been observed having
encryption stripped in transit. The protocols meant to close this gap are barely deployed and often
misconfigured: MTA-STS reaches 0.07% of `.com` domains with 29.6% of deployments incorrect.

Every one of those studies measured the ecosystem by scanning servers from outside. None could tell an
individual operator what happened to their own mail. This paper presents **CyberKavach**, a passive,
offline-first framework that answers that question. It ingests authorised packet captures, reconstructs every
SMTP, IMAP and POP3 session, parses TLS handshakes and X.509 certificates without decrypting any payload,
evaluates 34 rules across ten categories, extracts 51 features per session, and emits a graded report in which
every finding is traceable to a capture hash, frame number and byte range. Four decisions distinguish it:
severity is adjusted by the role of the port; five passive detectors report evidence that an attack has already
occurred; a host whose handshake could not be parsed is graded `?` rather than given a pass it did not earn; and
an attack-feasibility matrix reports what it has **ruled out** as well as what it found. The system is
approximately 15,800 lines of Python with three runtime dependencies and **277 passing tests**. Against a
ground-truth corpus derived from generator configuration rather than from tool output, it shows **no
disagreement across 14 captures and 20 rules**. Its risk model is a gradient-boosted ensemble trained in pure
Python in twelve seconds, reaching a held-out **MAE of 0.0451 against a 0.1681 rule-derived baseline — 73%
better, R² 0.94**.

**Keywords:** Email security, STARTTLS, passive network forensics, cryptographic posture assessment,
post-quantum readiness, digital evidence

---

## Contents

1. Introduction
2. Literature Review and Related Work
3. Technical Architecture and Design
4. Detailed Technical Implementation
5. The Machine Learning Layer
6. Testing, Evaluation and Measured Results
7. User Flows and System Interactions
8. Innovation and Technical Features
9. Technology Stack and Platform Layer
10. Feasibility Analysis
11. Challenges and Solutions
12. Impact Assessment and Benefits
13. Sustainability and Long-Term Viability
14. International Benchmarking and Best Practices
15. Implementation Roadmap
16. Risk Management and Mitigation
17. Limitations and Future Enhancements
18. Conclusion
19. References and Appendices

---

# 1. Introduction

## 1.1 Background and Motivation

SMTP was specified without confidentiality or authentication. Both were retro-fitted: first through the STARTTLS
extension (RFC 3207), which upgrades an established plaintext connection in place, and later through implicit
TLS on dedicated ports (RFC 8314). The retro-fit was deliberately permissive. RFC 7435 formalised the resulting
model as *opportunistic security*: encrypt when both ends agree, proceed in plain text when they do not, on the
reasoning that partial protection deployed widely beats strong protection deployed nowhere.

That reasoning was sound for adoption and is corrosive for assurance. Three properties follow, and together they
define the problem this work addresses.

**It fails open, silently.** Where a TLS negotiation errors — or is made to error — the mail is delivered anyway,
unencrypted. Durumeric et al. tested five widely deployed mail transfer agents and found all five fall back to
cleartext when STARTTLS fails, and that two of the three most popular platforms do not attempt STARTTLS at all
unless explicitly configured. No signal reaches the user, and the protocol offers no mechanism for a sender to
require secure transport or for a recipient to learn that a message travelled insecurely.

**It is rarely authenticated.** Encrypting to an unverified peer defeats an eavesdropper but not an active
attacker. Mayer et al. scanned the entire IPv4 address space across SMTP, POP3 and IMAP — 20 million IP/port
combinations and more than 10 billion TLS handshakes over three months — and found 65% of SMTP hosts presenting
self-signed certificates, with only 33–37% of mail-access deployments presenting certificates that validate.
Durumeric et al. presented a self-signed certificate to 19 major providers: not one rejected it.

**The upgrade step is itself a vulnerability class.** Poddebniak et al. performed the first structured security
analysis of STARTTLS across SMTP, POP3 and IMAP, testing 28 clients and 23 servers with a 100-test-case toolkit.
They reported more than 40 distinct flaws, found only 3 of 28 clients exhibited no STARTTLS-specific issue, and
scanned the internet to establish that 320,000 mail servers — 2% of all mail servers — were vulnerable to a
command injection permitting credential theft. Their conclusion is unambiguous: STARTTLS is error-prone to
implement, under-specified, and should be avoided in favour of implicit TLS.

These are not theoretical risks. Durumeric et al. found 41,405 SMTP servers across 4,714 autonomous systems in
193 countries whose STARTTLS negotiations were being corrupted in transit, and measured the effect at Gmail:
96.13% of mail sent from Tunisia arrived in plain text, with seven countries above 20%. Of the 423 autonomous
systems where every observed mail server showed stripping behaviour, 13.5% were financial institutions and 7.1%
were government networks.

## 1.2 Problem Statement

Problem statement SIH26159, set by the National Technical Research Organisation, asks for a passive,
evidence-driven framework that ingests authorised PCAP/PCAPNG captures of SMTP, IMAP and POP3 traffic;
reconstructs complete TCP sessions; parses TLS handshakes and extracts X.509 certificates; identifies weak
algorithms and deprecated protocol versions against NIST SP 800-52 Rev 2 and the relevant RFCs; applies machine
learning for risk classification and anomaly detection; and exports prioritised, evidence-backed findings as
JSON, HTML and PDF with an interactive dashboard. The statement is explicit that every finding must be reported
as OBSERVED, NOT_FOUND, UNKNOWN or INSUFFICIENT_EVIDENCE, never as an inference presented as fact.

Our decomposition into 21 numbered deliverables (D01–D21) plus two objectives (O01, O02) and a traceability
matrix is recorded in `docs/01_PROBLEM_STATEMENT.md`; verified status is generated mechanically by
`scripts/audit.py`.

The framing that matters is narrower. The literature establishes what is wrong with email transport security at
ecosystem scale, and does so entirely through **active measurement**: ZMap sweeps, DNS scans, probes issued to
endpoints. An operator reading those papers learns the problem is severe and learns nothing about their own
estate. The question *"what did my mail actually do, and did anyone interfere with it?"* has no tool behind it —
and under the CERT-In Directions of 2022 an Indian organisation must answer a version of it within six hours of
noticing an incident, using log data it is separately required to retain for 180 days.

## 1.3 Solution Overview

CyberKavach is an eleven-stage analysis pipeline that converts a packet capture into a graded, evidence-linked
cryptographic posture report. It performs no decryption, makes no network calls, and requires no service to be
reachable.

Given a capture it decodes seven link-layer encapsulations; reassembles TCP streams while retaining a
byte-to-frame provenance map; identifies mail protocols from the server banner and command grammar rather than
the port number; runs a STARTTLS state machine with ten checks; parses TLS records and handshake messages,
computing JA3 and JA3S fingerprints and detecting post-quantum key-exchange groups; parses X.509 certificates
from DER and verifies RSA signatures; evaluates 34 rules across ten finding categories; extracts 51 features per
session; scores risk with a gradient-boosted ensemble, detects anomalies with an isolation forest and orders
findings by priority; aggregates to per-host and fleet grades on an A+ to F scale with `?` reserved for hosts
that could not be fully assessed; judges 16 named attacks as feasible, ruled out or not observable; compares two
captures for posture drift; generates a narrative mechanically verified against the report's own facts; and
writes JSON, a single self-contained HTML file, CEF and ECS exports for a SIEM, and a twelve-view operations
console.

Every finding carries the SHA-256 of the capture, the stream index, the frame numbers and the byte range that
produced it, together with the standards clause it enforces and the configuration change that fixes it.

## 1.4 Market Analysis and Current State

### 1.4.1 The threat, in financial terms

The FBI's Internet Crime Complaint Center recorded $20.877 billion in reported losses in 2025 across 1,008,597
complaints, a 26% year-on-year increase. Business email compromise accounted for **$3.046 billion** — the
second-largest single loss category after investment fraud — across 24,768 complaints, an average of roughly
$123,000 per incident.

### 1.4.2 The cryptographic posture of mail infrastructure, as measured

| Measurement | Finding | Source |
|---|---|---|
| SMTP servers offering TLS vs. authenticating properly | 82% offer, **35%** configured for authentication | Durumeric et al., IMC 2015 |
| Self-signed certificates on SMTP | **65%** of distinct hosts | Mayer et al., ARES 2016 |
| Mail-access deployments validating correctly | **33–37%** | Mayer et al., ARES 2016 |
| POP3/IMAP hosts offering static RSA as sole key exchange | **15–17%** | Mayer et al., ARES 2016 |
| STARTTLS implementation flaws | **40+** across 28 clients, 23 servers; only 3/28 clients clean | Poddebniak et al., USENIX Sec 2021 |
| Servers vulnerable to STARTTLS command injection | **320,000 (2%)** | Poddebniak et al., USENIX Sec 2021 |
| Servers observed with STARTTLS stripped in transit | **41,405** in 193 countries | Durumeric et al., IMC 2015 |
| MTA-STS adoption / misconfiguration | **0.07% of `.com`**, 0.12% of `.org`; **29.6% wrong** | Ashiq, Fiebig & Chung, IMC 2025 |
| DANE TLSA records failing validation | **>30%**; 87% of servers rolled keys over incorrectly | Lee et al., USENIX Sec 2022 |
| Post-quantum key exchange: web vs. mail | **44.0%** of HTTPS vs **6.4%** of SMTP endpoints | Loizou & Ghadafi, 2026 |
| Post-quantum certificates | **zero**, across every study to date | Loizou & Ghadafi; arXiv 2606.16473 |

In India, CERT-In handled **29.44 lakh** incidents in 2025, up from 20.41 lakh in 2024, of which **3,41,646**
were classified as vulnerable services — the precise category for which this tool produces evidence.

### 1.4.3 Regulatory drivers and market size

**Incident forensics.** The CERT-In Directions of 28 April 2022 require reporting within six hours of noticing an
incident and retention of ICT system logs for 180 days within Indian jurisdiction. The Digital Personal Data
Protection Rules, notified 13 November 2025, require a detailed breach report within 72 hours, with penalties to
₹200 crore.

**Evidence admissibility.** Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 conditions admissibility of
electronic records on a certificate stating the record's hash value, and courts have been directed to treat an
unexplained hash variation between seizure and presentation as raising a strong presumption of tampering.

**Cryptographic inventory and the post-quantum transition.** The Department of Science and Technology's task
force under the National Quantum Mission published India's PQC migration roadmap in February 2026. Its first
milestone — *inventory cryptographic assets and assess quantum risk* — falls due in **2027** for critical
information infrastructure and 2028 for enterprises, with full adoption by 2029/2033 and **Cryptographic Bills
of Materials required from vendors from FY 2027–28**. The UK's NCSC places cryptographic discovery at 2028. NIST
IR 8547 deprecates RSA-2048 and P-256 after 2030 and disallows them after 2035. Every roadmap begins with
discovery; for email infrastructure no discovery tool exists.

Market sizing — vendor research rather than peer-reviewed measurement — puts the India email security market at
$0.427 billion in 2025 rising to $1.31 billion by 2035 (11.82% CAGR), and post-quantum cryptography at $810
million rising to $18.19 billion. CERT-In had empanelled 231 cybersecurity audit organisations by end-2025.

---

# 2. Literature Review and Related Work

## 2.1 Measurement of email transport security

**Durumeric et al. (IMC 2015)** is the canonical study, combining a snapshot of SMTP configuration for the Alexa
top million with over a year of Gmail connection logs. Uniquely, it presented evidence of attacks in the wild
rather than only of weak configuration. Its two attack findings are the intellectual basis of our
attack-evidence detectors: STARTTLS capability stripping, where a network device rewrites the server's EHLO
response so the capability is no longer advertised (the dominant observed style being a same-length substitution
consistent with a commercial appliance's documented behaviour), and DNS-based MX hijacking, with 14,600 publicly
accessible resolvers in 521 autonomous systems returning fraudulent MX records.

**Mayer et al. (ARES 2016)** provides the certificate and cipher baseline: full-IPv4 coverage including legacy
ports, 2,115,228 unique leaf certificates analysed, and the observation that securing server-to-server mail is
inherently harder than client-to-server. That asymmetry is the empirical justification for role-aware severity.

**Holz et al. (NDSS 2016)** remains the broadest study of TLS across SMTP, IMAP, POP3, XMPP and IRC, and is the
only one in this set to combine active scanning with passive monitoring. It is the closest methodological
antecedent, and the difference is instructive: it monitored at a research vantage point to characterise an
ecosystem, not to serve the operator of a specific estate.

**Foster et al. (ACM CCS 2015)** examined provider-based email security end to end, establishing that the
security properties of a mail path are compositional and that a single weak hop determines the outcome.

## 2.2 STARTTLS as a vulnerability class

**Poddebniak et al. (USENIX Security 2021)** is the most important paper for this project. It systematises
STARTTLS flaws into distinct attack classes — negotiation, buffering, tampering, session — and introduces EAST,
a toolkit of more than 100 test cases. Two findings shape our design. First, it states the role asymmetry
explicitly: the security implications for submission and retrieval are more critical than for transport
*because those connections carry user credentials granting access to a mailbox archive, not merely individual
messages*. Our severity policy implements that sentence. Second, a ten-year-old command injection permitting
plaintext insertion remained unfixed in multiple servers, and eight new instances were discovered of a bug class
that had already received several CVEs.

## 2.3 Certificate validation and the X.509 ecosystem

**Georgiev et al. (ACM CCS 2012)** showed SSL certificate validation is broken across a wide range of
non-browser software, attributing the root cause to badly designed library APIs rather than exotic bugs.
**Brubaker et al. (IEEE S&P 2014)** extended this by differential testing with synthesised "frankencerts".
Mail software is precisely the class these papers describe, which is why certificate findings in mail deserve
first-class treatment; and a purpose-built parser that allocates nothing, links no native code and is exercised
against certificates generated for the purpose is a defensible choice for code that will be pointed at a hostile
certificate.

## 2.4 Authenticated transport: MTA-STS, DANE and TLS reporting

**Ashiq, Fiebig & Chung (IMC 2025)**: 31 months of DNS scans covering over 87 million domains across four TLDs.
Adoption rose three- to four-fold over the study period and remains at 52,641 `.com` domains (0.07%) and 7,192
`.org` domains (0.12%). Of the 68,000 domains publishing a record, 29.6% were incorrectly configured and 3.2%
badly enough that a compliant sender would fail to deliver. Their survey of 117 operators found 94.7% aware of
MTA-STS, 48.8% citing operational complexity as the reason for not deploying, and 26.8% reporting difficulty
managing policy updates.

**Lee et al. (USENIX Security 2022)** performs the equivalent analysis for DANE across more than a million
domains with TLSA records: over 30% could not be validated owing to a broken DNSSEC chain, 3.6% did not match
the corresponding certificate, and more than 87% of servers performed key rollovers incorrectly. The authors
attribute this directly to the absence of automated tooling.

Together these make an unusual argument in our favour: the standards exist, operators know about them, and the
binding constraint is tooling.

## 2.5 Machine learning on encrypted traffic

**Sommer & Paxson (IEEE S&P 2010)** is the governing methodological reference. Intrusion detection differs from
other machine-learning applications in ways that defeat naive application: the base-rate problem means that where
benign traffic dominates, even a small false-positive rate yields an unusable alert volume; the semantic gap
means an alert an operator cannot trace to a cause is one they will not act on; and adversarial adaptation
undermines closed-world assumptions. Our architecture is a direct response — cryptographic facts are produced
deterministically, learning is confined to ranking and anomaly scoring, and every output is traceable to bytes.

**Anderson, Paul & McGrew (2018)** established that TLS metadata alone, without decryption, distinguishes
malicious from enterprise traffic across millions of flows and attributes malware family from a single encrypted
flow across 18 families. **Jafari Siavoshani et al. (Soft Computing 2023)** identified which handshake fields
carry the discriminative signal; our 51-field vector is shaped by that result. **Singh, Kashyap & Cherukuri
(2025)** combined XGBoost, Random Forest and Isolation Forest with SHAP attribution across CIC-Darknet2020,
USTC-TFC2016 and CSE-CIC-IDS2018, reporting 99.94% accuracy for XGBoost (90.9% precision, 88.2% recall, 93.0%
F1) against 97.92% for Random Forest, and argued post-hoc interpretability is a compliance requirement.
**INTACT (2026)** reframes cryptographic violation detection as a policy-constraint problem — modelling
violation probability conditioned on observed behaviour *and declared security intent*, covering key reuse,
downgrade prevention and bounded key lifetimes — reporting AUROC up to 1.0000 on a real flow dataset alongside a
210,000-trace synthetic corpus. That framing is the closest published analogue to our rule-plus-role-policy
engine.

**Friedman (2001)** on gradient boosting and **Liu, Ting & Zhou (ICDM 2008)** on isolation forests are the
primary sources for the two algorithms we implemented from scratch (§5).

## 2.6 Post-quantum readiness

**Loizou & Ghadafi (2026)** is the most relevant recent measurement because it is the only study to measure
HTTPS and SMTP STARTTLS endpoints for the same organisations. Across 4,665 UK organisations, 44.0% of reachable
HTTPS services supported at least one evaluated post-quantum key-exchange group against **6.4% of SMTP
services** — a matched odds ratio of 16.89 — with only 144 organisations supporting PQC across both, and no
post-quantum certificate signatures observed anywhere.

Complementary studies agree: arXiv 2606.16473 finds 49.3% of 32,011 domains supporting hybrid post-quantum key
exchange with 0% PQ certificates and 15.7% still on TLS 1.2, notably in banking and government; arXiv 2607.29005,
analysing more than two billion handshakes from eleven vantage points, finds adoption concentrated in a single
hybrid construction (X25519MLKEM768), driven overwhelmingly by managed infrastructure providers, with
owner-managed and government-operated domains still defaulting to classical cryptography.

## 2.7 Notification and remediation effectiveness

**Li et al. (USENIX Security 2016)** ran a randomised experiment notifying thousands of operators and tracking
remediation. Notifications containing remediation steps were 56.5% more effective than terse ones after two days
for the IPv6 condition and 55.5% for industrial control — although the authors note these differences are not
statistically significant after Bonferroni correction, and that fewer than 40% of operators who read the
detailed material fixed anything. The honest reading, which we adopt, is that actionable specificity helps
materially but most findings still go unremediated, which argues for prioritisation as much as for clarity.

## 2.8 Gaps in current research

**Gap 1 — the operator's own traffic is unexamined.** Every large-scale study measures the ecosystem from
outside: Durumeric and Mayer by scanning the address space, Ashiq and Lee by scanning DNS, Loizou by probing
endpoints, Foster by sending test mail. Holz alone monitored passively, at a single research vantage point. The
question an operator or incident responder actually has — *what happened on my network, and was it tampered
with* — has no corresponding instrument. Active scanners cannot answer it in principle, because the evidence is
historical.

**Gap 2 — severity models are protocol-agnostic where the threat model is not.** The literature is explicit that
the requirements of relay, submission and access differ, and that the difference is about whether credentials
cross the link. No assessment tool encodes this. The consequence is predicted by Sommer & Paxson: alarm volumes
operators learn to ignore.

**Gap 3 — the post-quantum discovery problem excludes mail.** Regulatory roadmaps in India, the UK and the US
begin with cryptographic inventory. Measurement shows mail is where migration has least progressed. Commercial
discovery tooling — IBM Quantum Safe Explorer, SandboxAQ AQtive Guard, Keyfactor AgileSec — operates on source
code, container images or host agents. None derives an inventory from observed mail traffic.

---

# 3. Technical Architecture and Design

## 3.1 Design principles

Thirty-two architecture decision records are maintained in `docs/04_DECISIONS.md`. Six principles govern the
design.

1. **The schema is the contract.** `schema/` has zero dependencies and generates both JSON Schema and TypeScript
   definitions (ADR-0009). Six people working in parallel across eleven stages requires one authoritative data
   model; a change to a field changes the architecture document in the same commit.
2. **Evidence is designed in, not added later.** Every finding carries provenance from the moment it is created
   (ADR-0004). Byte-to-frame mapping is cheap at the point of reassembly and impractical to reconstruct
   afterwards.
3. **Facts are deterministic.** A cryptographic property is parsed, not predicted. Machine learning is confined
   to prioritisation and anomaly scoring, for the reasons Sommer & Paxson set out.
4. **Absence of evidence is reported as such.** A host whose handshake could not be parsed is graded `?`
   (ADR-0014). No verdict is upgraded to a pass by default. An undecodable capture grades `?`, never A+
   (ADR-0027).
5. **Negative results are deliverables.** The attack matrix is worth more for what it rules out than for what it
   confirms (ADR-0030); drift refuses to compare estates that are not the same estate (ADR-0029); generated
   prose is discarded whole if it names anything not in the facts (ADR-0028).
6. **No compiled dependencies.** Forced by the environment, retained because it is correct for the deployment
   target. The tool must install where there is no package manager and no network.

## 3.2 The pipeline

| Stage | Name | Function |
|---|---|---|
| S0 | Ingest | Read PCAP/PCAPNG, decode seven link-layer encapsulations, compute capture SHA-256, index frames |
| S1 | TCP reassembly | Rebuild bidirectional streams with a byte-to-frame provenance map |
| S2 | Protocol identification | Identify SMTP/IMAP/POP3 from banner and command grammar; assign port role |
| S3 | STARTTLS state machine | Ten checks over the plaintext negotiation phase |
| S4 | TLS handshake | Parse records and handshake messages; JA3/JA3S; key-exchange groups including post-quantum |
| S5 | X.509 | Parse DER certificates, build chains, verify RSA signatures, validate names and dates |
| S6 | Rule evaluation | 34 rules across ten categories, each with standards citation and remediation |
| S7 | Feature extraction | 51 fields per session |
| S8 | AI layer | Gradient-boosted risk model, isolation-forest anomaly detection, priority ordering, grounded narrative |
| S9 | Aggregation | Per-category, per-host and fleet scores and grades; capping rules; attack matrix; drift |
| S10 | Reporting | JSON, self-contained HTML, CEF/ECS, twelve-view console |

## 3.3 Component layers

| Package | Stage | Responsibility |
|---|---|---|
| `schema/` | — | The data contract; zero dependencies; generates JSON Schema and TypeScript |
| `schema/platform.py` | — | Jobs, dispositions, audit events, posture snapshots (ADR-0022) |
| `securemailscope/capture/` | S0–S1 | Link-layer decode (ADR-0027) and the TCP reassembler with provenance |
| `securemailscope/proto/` | S2–S3 | Protocol identification, STARTTLS state machine, credential recovery |
| `securemailscope/tls/` | S4 | TLS record and handshake parser, fingerprints, post-quantum group detection |
| `securemailscope/certs/` | S5 | DER/X.509 parser and RSA signature verification |
| `securemailscope/rules/` | S6 | Rule pack, standards catalogue, role-aware severity policy |
| `securemailscope/features/` | S7 | The 51-field feature vector |
| `securemailscope/ml/` | S8 | `gbt.py`, `iforest.py`, classifier, anomaly, priority, corpus (ADR-0031) |
| `securemailscope/llm/` | S8 | Grounded fact sheet, deterministic template, hallucination verifier (ADR-0028) |
| `securemailscope/attacks.py` | S9 | Attack feasibility matrix, 16 attacks, three verdicts (ADR-0030) |
| `securemailscope/drift.py` | S9 | Temporal posture comparison (ADR-0029) |
| `securemailscope/report/` | S10 | JSON and self-contained HTML |
| `securemailscope/siem.py` | S10 | CEF and ECS export |
| `securemailscope/store.py` | — | stdlib `sqlite3`, five tables, no ORM |
| `securemailscope/api/` | — | Flask service, stdlib auth (ADR-0024), twelve-view console (ADR-0026) |
| `testbed/` | — | `synth.py` writes PCAPs byte by byte; `certgen.py` issues signed certificates |

## 3.4 Data model

The report is a closed hierarchy: a `capture` record (path, SHA-256, frame count, time bounds); `sessions`, each
with protocol, port, port role, TLS mode, handshake detail, certificate chain, feature vector and findings;
`hosts` with per-category scores and a grade; a `fleet` rollup; `prioritised_findings`; an `executive_summary`;
and `evaluation_metrics`.

Enumerations are fixed and small, which makes the contract enforceable: ten finding categories (`protocol`,
`cipher`, `key_exchange`, `certificate`, `certificate_strength`, `configuration`, `starttls`, `attack_evidence`,
`post_quantum`, `compliance`); four port roles (`mta_relay`, `submission`, `mail_access`, `unknown`); five
severities; and eight grades (`A+`, `A`, `B`, `C`, `D`, `E`, `F`, `?`).

## 3.5 The evidence model

An `Evidence` record accompanies every finding, holding capture SHA-256, stream id, frame numbers, byte range,
direction, timestamp and a human-readable note. A report states a claim, and the claim names the bytes that
support it.

---

# 4. Detailed Technical Implementation

## 4.1 Link-layer decoding and ingest (S0)

Seven encapsulations are decoded: Ethernet, 802.1Q and QinQ VLAN tags, Linux cooked capture v1 and v2, raw IPv4
and IPv6, BSD loopback, and the IPv6 extension-header chain. This was not cosmetic work. Before ADR-0027, five
of seven encapsulations lost *every frame* and the tool reported a clean A+ on a capture it had entirely failed
to read. An undecodable capture now grades `?`.

## 4.2 TCP reassembly with provenance (S1)

Streams are rebuilt per direction with sequence-number ordering, retransmission and overlap handling, and a
provenance structure mapping every byte offset in the reassembled stream to its source frame. Findings cite
offsets into this stream; the map converts them into frame numbers an analyst can open in Wireshark. Incomplete
streams are retained and marked rather than discarded, because a truncated capture is the normal case in
forensic work.

## 4.3 Protocol identification (S2)

Identification is banner-led. The server greeting and subsequent command grammar determine whether a stream is
SMTP, IMAP or POP3; the port is recorded and used to assign a role but is not trusted to identify the protocol.
Dreger et al. established the principle in 2006: traffic on non-standard ports is disproportionately interesting
precisely because avoiding a standard port is itself a way of evading inspection. **Measured protocol
identification accuracy against ground truth: 1.00.**

## 4.4 The STARTTLS state machine (S3)

Ten checks over the plaintext phase, structured around the published attack classes: whether the capability was
advertised; whether it was advertised then unused; whether the advertised set is internally consistent with the
observed negotiation; whether EHLO was correctly re-issued after the upgrade (RFC 3207 §4.2); whether plaintext
AUTH was offered before TLS (RFC 4954); whether the capability line shows the same-length rewrite signature;
whether the server rejected the command; whether the session continued in plaintext after a failed upgrade;
whether credentials appeared before the upgrade; and whether the transition boundary is consistent with the
record layer that follows.

## 4.5 TLS handshake parsing (S4)

A record-layer parser feeds a handshake parser extracting ClientHello and ServerHello, offered and selected
cipher suites, supported groups and key shares, extensions, ALPN, SNI, session resumption indicators and alerts.
JA3 and JA3S fingerprints are computed from the ordered field sets. Post-quantum readiness is determined from
named groups — hybrid constructions such as X25519MLKEM768 — recorded separately for *offered* and *negotiated*,
because those are different facts. Version downgrade is detected both by comparing offered against negotiated
and by testing for the RFC 8446 sentinel. Cipher suite properties are derived from IANA names rather than
tabulated (ADR-0015), so a suite we have never seen is still classified correctly.

## 4.6 DER and X.509 (S5)

A DER reader with explicit length and tag validation, an X.509 structure decoder, chain construction against a
supplied trust anchor, and RSA PKCS#1 v1.5 signature verification implemented over Python integers. Validity
windows, self-signature, key size, signature hash algorithm, chain completeness and name matching are all
evaluated. Where the certificate is encrypted by TLS 1.3, the chain is recorded as `OPAQUE_TLS13` rather than
absent. Certificate findings are split into *trust* and *strength* (ADR-0010), because an expired certificate
and a 1024-bit key are different problems with different fixes.

## 4.7 The rule engine and severity policy (S6)

Each rule is a frozen dataclass: identifier, title, category, base severity, predicate, description, standards
tuple, related attacks, remediation block and evidence note. Predicates are functions of a narrow `RuleContext`
— the feature vector plus host, port and role — and a rule that raises is treated as not firing, so a defect in
one rule cannot abort a run.

The narrow context is a deliberate consequence of ADR-0003: because rules are predicates over the feature vector
rather than over parsed session objects, the *same* rule implementations run over real sessions and over
synthetic feature vectors. The labelling oracle used to generate training data therefore cannot drift from the
shipping detector.

Severity is emitted as a base value and then adjusted by a policy table keyed on `(category, role)`, with the
adjustment and its plain-English justification recorded on the finding.

## 4.8 Aggregation and grading (S9)

Per-category scores aggregate to a host score and grade; host grades aggregate to a fleet score and grade.
Thresholds are 95 for A+, 85 for A, 75 for B and downwards. Two capping rules matter: a critical finding caps
the achievable grade regardless of arithmetic, and any host with an incomplete handshake analysis that would
otherwise grade A+, A or B is reassigned `?`.

---

# 5. The Machine Learning Layer

This section is given in full because it is the part of the system most often asserted and least often
demonstrated. Everything below was produced by running `python scripts/train_local.py`.

## 5.1 Why we wrote the algorithms ourselves

The problem statement names XGBoost and Isolation Forest. Neither can be installed on these machines: Windows
Smart App Control blocks `numpy`'s compiled `_multiarray_umath` extension, and scikit-learn and XGBoost both
depend on it (ADR-0012). The project initially planned to train off-machine in Colab (ADR-0020). That left a
deliverable dependent on a human remembering to run a notebook, which ADR-0031 identified as the wrong kind of
dependency for a system that must be demonstrable on demand.

Both algorithms were therefore implemented from scratch in pure Python: `securemailscope/ml/gbt.py` (390 lines)
and `securemailscope/ml/iforest.py` (182 lines). Training the complete pipeline takes **under fifteen seconds**
on an ordinary laptop with no GPU, no numerical library and no network.

## 5.2 The training corpus

`securemailscope/ml/corpus.py` generates **10,000 rows across 55 columns**. Rows are synthetic feature vectors,
not parsed captures — ADR-0006 separates these deliberately: the model trains on synthetic vectors, PCAPs are
reserved for validation and demonstration, so the two never contaminate each other.

Labels come from the rule engine (ADR-0003). This is the single most important design property of the layer:
the labelling oracle is literally the same code that ships as the detector, so the model cannot learn a
different notion of risk from the one the product enforces.

**One column is deliberately excluded. `archetype` — the generator's latent variable describing which scenario
it was drawing from — is dropped as leakage.** A model given it would predict risk almost perfectly and learn
nothing, because the generator's intent is not available at inference time. The trainer removes it explicitly
and reports the exclusion.

The split is **8,000 training rows and 2,000 held out**, with indices shuffled together before splitting
(ADR-0020). That ADR exists because of a bug found by running: `train_test_split` shuffles by default, and an
earlier version scored the model on rows it had trained on.

## 5.3 The risk model: gradient-boosted regression trees

An ensemble of **200 regression trees at depth 3**, trained by gradient boosting in the sense of Friedman
(2001): each tree is fitted to the residuals of the ensemble so far, and predictions are the sum of the
ensemble's outputs.

Training converges smoothly — train MAE falls 0.1015 → 0.0696 → 0.0565 → 0.0502 → 0.0477 → 0.0455 → 0.0431 →
0.0423 at rounds 25 through 200 — and completes in **12.0 seconds**.

### Measured results on the 2,000 held-out rows

| Metric | Value | Meaning |
|---|---|---|
| **Baseline MAE** | **0.1681** | The rule-derived score, i.e. what the system outputs with no model at all |
| **Model MAE** | **0.0451** | Mean absolute error of the trained ensemble |
| **Improvement** | **0.1230 (73%)** | How much the model beats the baseline it must justify itself against |
| **R²** | **0.9429** | Variance explained |
| **Spearman ρ** | **0.9225** | Rank correlation — *the figure that matters for a triage queue* |

Spearman is quoted deliberately. A triage queue is an ordering problem, not a regression problem: what matters
is whether the right finding is at the top, not whether its score is 0.81 or 0.84.

**The trainer refuses to write a model that loses to the baseline.** If the ensemble fails to beat the
rule-derived score on held-out data, no model file is produced and the system continues on the baseline. A model
worse than no model should not ship, and the check is mechanical rather than a matter of discipline.

### Feature importances

The eight most-used features, by split frequency weighted by gain:

| Weight | Feature | Interpretation |
|---|---|---|
| 0.115 | `kex_group_bits` | Key-exchange strength dominates |
| 0.101 | `cert_days_to_expiry` | Certificate lifecycle is the next strongest signal |
| 0.053 | `starttls_stripped_suspected` | Attack evidence carries weight, as it should |
| 0.052 | `cert_chain_complete` | Chain construction |
| 0.050 | `downgrade_sentinel_present` | RFC 8446 sentinel |
| 0.045 | `cipher_intersection_anomaly` | The corroborated anomaly (ADR-0023) |
| 0.042 | `cert_hostname_match` | Name validation |
| 0.040 | `auth_before_tls` | Plaintext AUTH exposure |

This distribution is itself a result worth reporting: the model independently concentrates on key-exchange
strength and certificate lifecycle, which is where the measurement literature says the weaknesses actually are,
and it gives real weight to the attack-evidence features rather than treating them as rare noise.

## 5.4 Anomaly detection: isolation forest

**150 trees over 256-row subsamples**, following Liu, Ting & Zhou (2008): anomalies are easier to isolate, so
the expected path length to isolate a point is shorter for outliers. Training takes **2.4 seconds**.

The decision threshold is **0.5856**, flagging **99 of 2,000 held-out rows (5.0%)**. That rate is a deliberate
operational choice rather than a statistical one — it is the volume a human triage queue can absorb.

**The baseline rejects contaminated sessions before learning (ADR-0019).** An earlier version built the fleet
baseline from the capture *including its attack sessions*, which let the attacks vote on what counted as normal
— so the more compromised an estate was, the less anomalous its compromise appeared. The baseline is now built
in two passes with outliers rejected before the second.

## 5.5 The narrative layer: verified, not trusted (ADR-0028)

Three components: `grounding.py` builds a `FactSheet` from the report — a closed vocabulary of every host, rule
identifier, standard, CVE and attack name that legitimately appears; `templates.py` renders a deterministic
narrative that ships by default and needs no network; `verify.py` exposes `check()` and `verdict()`, which
compare generated prose against the fact sheet and **discard the text whole** if it names any host, rule, RFC or
CVE not present in the facts.

This is the answer to "how do you stop it hallucinating?" — a mechanical closed-vocabulary check rather than a
prompt instruction. The deterministic template means the demonstration never requires a network call, and the
verifier means that if a language model is attached, its output is still gated by the report's own facts.

## 5.6 The analyst feedback loop

Dispositions marked `FALSE_POSITIVE` in the console are served at `/api/training-signal` as labelled examples.
Triage work therefore becomes supervised signal rather than evaporating — the one data source in this domain
that is both genuinely labelled and genuinely free.

---

# 6. Testing, Evaluation and Measured Results

## 6.1 The test suite

**277 tests pass**, in twelve modules — `contract`, `ml`, `gbt`, `parsing`, `tls`, `certs`, `report`,
`platform`, `linklayer`, `llm`, `drift`, `attacks` — run without pytest so that testing introduces no
dependency.

Coverage is structured by risk. `contract` asserts the schema round-trips and that generated JSON Schema matches
the dataclasses. `certs` verifies RSA signature validation against certificates from `testbed/certgen.py`,
including deliberately invalid chains. `parsing`, `tls` and `linklayer` exercise truncated records, malformed
lengths and incomplete handshakes — the paths a hostile input would take. `report` asserts the HTML contains no
external references and that injected markup never reaches the document body.

## 6.2 Ground truth, and how it was authored

`testbed/synth.py` writes PCAP files byte by byte rather than capturing traffic, which is what makes ground
truth possible: the generator knows exactly which weaknesses it encoded. `testbed/certgen.py` issues genuinely
signed certificates from a generated CA, including expired, self-signed, weak-key and mismatched-name variants.
`testbed/relink.py` re-encapsulates the corpus into seven link-layer variants.

**Expectations in `testbed/manifest.json` were derived by reading `testbed/synth.py`, never from the tool's
output.** This is the methodological point on which the entire evaluation rests. If ground truth is copied from
what the tool produced, precision becomes 1.0 by construction and the figure means nothing.

## 6.3 Measured accuracy

Produced by `python scripts/evaluate.py` on the date of writing:

| Measure | Result |
|---|---|
| Captures matching ground truth exactly | **14 / 14** |
| Rules exercised without error | **20 / 20** |
| True positives | **30** |
| False positives | **0** |
| False negatives | **0** |
| Precision | **1.00** |
| Recall | **1.00** |
| F1 | **1.00** |
| Severity accuracy (role-aware adjustment, USP-01) | **1.00** |
| Protocol identification accuracy | **1.00** |
| Throughput | 0.05 MB/s |

Per-rule results are uniform across all 20 rules exercised, including all five attack detectors
(`ATTACK-STARTTLS-STRIPPED`, `ATTACK-CLEARTEXT-CREDENTIALS`, `ATTACK-DOWNGRADE-SENTINEL`,
`ATTACK-CIPHER-INTERSECTION-ANOMALY`, `ATTACK-CERT-SUBSTITUTION`).

**How this must be quoted.** The audit script states the required framing itself, and we repeat it: this is *"no
disagreement with independently-derived ground truth on a synthetic corpus"*, **not** perfection. The corpus is
ours. The result measures implementation correctness against declared intent — that every rule fires when and
only when the generator encoded the condition it detects. It does not measure field accuracy, which would
require labelled real-world captures that do not publicly exist. Anyone quoting 1.00 without that sentence is
overclaiming, and an evaluator will say so.

**Throughput of 0.05 MB/s is a real limitation** and is reported rather than omitted. It is the price of a pure
Python implementation with no compiled dependencies: acceptable for forensic analysis of bounded captures,
unsuitable for line-rate monitoring.

## 6.4 Deliverable verification

`scripts/audit.py` mechanically verifies every deliverable and objective. Current state: **32 met, 1 partial, 1
not met.**

| Status | Items |
|---|---|
| **Met (32)** | D01–D19, D21, O01, O02, USP-01 to USP-10 |
| **Partial (1)** | D20 — PDF export; Playwright is blocked, browser print works with the print stylesheet applied |
| **Not met (1)** | USP-11 — passive DNS / DANE / MTA-STS correlation; needs DNS extraction from the capture |

The audit has already caught regressions manual review missed: the role-aware severity side-by-side panel
silently stopped producing output when the corpus moved from synthetic to genuinely signed certificates. The
evaluation caught a rule reporting every legacy server as under attack, which led to ADR-0023.

## 6.5 Verification from a clean clone

Because the corpus, certificates and models are gitignored build artifacts, a clean `git status` says nothing
about whether a fresh clone works. Verification is therefore performed from an empty directory:

```
git clone . /tmp/x && cd /tmp/x && ./run.sh --check     # must print 32 met
```

The first attempt printed 26: a documented command that silently did nothing, a launcher that reported the
failure as something reassuring, and an audit missing artifacts nobody had generated.

---

# 7. User Flows and System Interactions

## 7.1 The analyst flow

1. A capture is obtained from existing infrastructure — a SPAN port, a tap, or an archived capture retained under
   the CERT-In 180-day requirement. CyberKavach does not capture traffic itself; separating collection from
   analysis is what lets it run on a machine that is not on the monitored network.
2. One command: `python scripts/analyse.py capture.pcap --out out/ --trust ca.der`.
3. The analyst opens `out/report.html` — a single self-contained file — or the console at port 8000.
4. Any finding expands to show capture hash, stream, frames, byte range, the standards clause and the fix.

## 7.2 The administrator flow

The administrator view groups findings by *fix* rather than by finding, because one configuration change
frequently resolves several findings across several hosts. The rationale is empirical: remediation tracks how
specific and actionable a notice is, and most findings otherwise go unremediated.

## 7.3 The auditor flow

A compliance report card mapping observed posture to the clauses of NIST SP 800-52 Rev 2 and the relevant RFCs —
**17 standards tracked, 10 failing** on the demonstration corpus — plus an evidence pack. Each row states
whether the control was OBSERVED, NOT_FOUND, UNKNOWN or INSUFFICIENT_EVIDENCE. Context-only citations are
excluded from the failure count, so citing a standard is never counted as violating it.

## 7.4 The incident responder flow

Sessions ordered by time, attack-evidence findings marked, recovered plaintext credentials shown as proof of
exposure (redacted by default), per-session handshake detail, and the attack feasibility matrix.

## 7.5 The four persona views

All four — SOC triage, forensics evidence packet, incident-response timeline, and administrator — render from
**one analysis**, which a test enforces. They are views of the same facts, not four separate analyses that could
disagree.

---

# 8. Innovation and Technical Features

## 8.1 Role-aware severity (USP-01)

Every session is assigned a `port_role` at S2. The severity engine applies a documented adjustment to the base
severity, keyed on `(finding category, port role)`, and writes the reasoning into the finding — for example
*"Downgraded from HIGH to INFO: port 25 is MTA-to-MTA relay, where TLS is opportunistic (RFC 7435) and the
sender has no trust anchor"*, against *"Raised from HIGH to CRITICAL: user credentials traverse this session, so
RFC 8314 requires a validated certificate"*.

| Role | Ports | TLS expectation | Certificate validation failure |
|---|---|---|---|
| `mta_relay` | 25 | Opportunistic (RFC 7435) | Informational |
| `submission` | 587 (STARTTLS), 465 (implicit) | Mandatory (RFC 8314, RFC 4954) | Critical |
| `mail_access` | 143, 993, 110, 995 | Mandatory (RFC 8314) | Critical |

The justification is the literature's, not ours. Poddebniak et al. state the asymmetry directly; Mayer et al.
reach it from measurement; Sommer & Paxson explain the cost of ignoring it. **Measured severity accuracy against
ground truth: 1.00.**

## 8.2 Attack evidence (USP-02)

Five detectors report that an attack has occurred rather than that one is possible, all operating on plaintext
portions of the session with no decryption:

1. **STARTTLS capability stripping** — advertised capability set compared against the negotiation that follows,
   including the same-length substitution pattern documented in the wild.
2. **Cleartext credentials** — AUTH exchanges recovered from sessions never upgraded, reported as proof of
   exposure and redacted by default.
3. **The RFC 8446 downgrade sentinel** — the specified ServerHello random suffix signalling a version downgrade.
4. **Cipher-intersection anomaly** — the server selected a suite weaker than the strongest both parties offered,
   requiring both halves of the handshake and therefore invisible to an active scanner.
5. **Certificate substitution** — the same host presenting different certificates across sessions.

The intersection anomaly **requires corroboration** (ADR-0023). Without it, every legacy server looks like an
attack — a finding produced by the evaluation harness, not by review.

## 8.3 Evidence-linked findings (USP-03)

Capture SHA-256, stream id, frame numbers, byte range, direction and timestamp on every finding. This addresses
the semantic gap Sommer & Paxson identify, and has a legal consequence (§10.3): it is the form section 63 of the
Bharatiya Sakshya Adhiniyam, 2023 expects of electronic evidence.

## 8.4 Reporting what could not be observed (USP-04)

TLS 1.3 encrypts the Certificate message. A tool reporting "no certificate found" is reporting a parsing
limitation as a security fact. CyberKavach reports `OPAQUE_TLS13` with the reason, continues to assess what
remains visible, and grades the host `?`.

## 8.5 The attack feasibility matrix (USP-09, ADR-0030)

Sixteen named attacks are judged against the observed evidence, with three possible verdicts: **feasible**,
**not applicable** (ruled out) and **not observable passively**. On the demonstration corpus: **9 feasible, 6
ruled out, 1 not observable.** Fourteen attack names are also attached to individual findings.

The attacks assessed are STARTTLS stripping, credential interception, server impersonation, RC4 keystream
biases, Sweet32, FREAK, Logjam, ROBOT/Bleichenbacher, POODLE, BEAST, Lucky 13, CRIME, renegotiation prefix
injection, retrospective decryption, harvest-now-decrypt-later, and Heartbleed.

**The ruled-out rows are the deliverable.** A report that lists only what is broken reads identically to a
report by a tool that never looked for the rest. Stating that Logjam is not applicable *because the observed
key-exchange group is 2048 bits or larger* is positive assurance an auditor can act on, and no competing tool
produces it. The third verdict exists because honesty requires distinguishing "we checked and it is not
possible" from "this cannot be determined from a passive capture".

## 8.6 Temporal posture drift (USP-10, ADR-0029)

Two captures of the same estate are compared: findings that appeared, resolved or carried forward, and hosts
whose grade moved. On the demonstration pair (`fleet.pcap` vs `fleet_later.pcap`): 100% host overlap, fleet
grade D→D, **7 appeared, 6 resolved, 23 carried forward, 2 hosts moved**.

The fleet score moved −0.3 while one host fell 99 points and another rose 96 — which is the point. An aggregate
that barely moves can conceal complete reversals underneath, and drift is what surfaces them.

**Drift refuses to compare estates with under 50% host overlap.** The arithmetic works on any two reports, and a
confident wrong trend is worse than a blank panel.

## 8.7 Post-quantum readiness (USP-05)

Hybrid key-exchange groups are detected in `supported_groups` and recorded separately for offered and
negotiated. On the demonstration corpus, one session offered a hybrid group and **1 of 11 hosts is PQ-ready**.
The claim is deliberately two-part, following the measurement literature: *key exchange is migrating,
certificates have not started*.

## 8.8 Deployment without dependencies

Three runtime dependencies — `dpkt` for capture parsing, `flask` for the service, `waitress` for production
serving. The TCP reassembler, TLS parser, DER/X.509 parser, RSA verification, gradient-boosting trainer,
isolation forest and PDF renderer are all written for this project. No compiled extensions, no container
requirement, no model download, no network calls. The tool installs by file copy on a machine with no internet
and no package manager — the environment this problem statement's originating organisation works in.

---

# 9. Technology Stack and Platform Layer

## 9.1 Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.11 | Available on target systems; readable by a six-person team of mixed experience |
| Capture parsing | `dpkt` | Pure Python, not blocked by the compiled-extension restriction |
| Reassembly, TLS, X.509 | Written for this project | Byte-to-frame provenance is not offered by existing libraries (ADR-0002, ADR-0017) |
| Rules | Declarative frozen dataclasses | Predicate, standards and remediation in one object |
| Machine learning | `gbt.py` + `iforest.py`, pure Python | ADR-0031; numpy is blocked, and the deliverable should not depend on a human running a notebook |
| Narrative | Deterministic template + closed-vocabulary verifier | ADR-0028 |
| Service | **Flask**, not FastAPI | `pydantic_core` is blocked (ADR-0021) |
| Production server | `waitress` | Pure Python WSGI server |
| Persistence | stdlib `sqlite3`, five tables, no ORM | ADR-0021, ADR-0022 |
| Auth | stdlib only | ADR-0024 |
| Console | Hash-routed vanilla JS, hand-drawn SVG charts | ADR-0025; node/npm never installed |
| Reporting | Self-contained HTML, JSON, CEF, ECS | ADR-0018 |
| Testing | Standard library, no pytest | Tests must not add a dependency |

Approximately **15,800 lines of Python**, plus roughly 2,200 lines of console CSS, JS and HTML.

## 9.2 The platform layer (ADR-0022)

Five SQLite tables: `jobs`, `reports`, `dispositions`, `audit`, `snapshots`. No ORM. The `audit` table directly
serves the CERT-In six-hour reporting obligation: every action against the system is recorded with actor,
timestamp and subject, so the question "who looked at what, and when" has an answer before it is asked.

## 9.3 The console (ADR-0025, ADR-0026)

A twelve-view single-page operations console served by Flask, hash-routed in vanilla JavaScript with hand-drawn
SVG charts. There is deliberately **no geographic threat map** — it would be decorative, since a capture carries
no reliable geography, and a dashboard that implies knowledge it does not have is the same failure mode as an
empty certificate panel.

## 9.4 SIEM export

`siem.py` emits two formats: **CEF** (ArcSight Common Event Format, understood by Splunk, QRadar and Sentinel),
with our five severity levels mapped onto CEF's 0–10 scale leaving headroom at the top; and **ECS** (Elastic
Common Schema) as newline-delimited JSON. Both carry the capture hash, so a finding in a SIEM remains traceable
to the bytes that produced it.

## 9.5 Deployment

`DEPLOY.md` covers Render, Railway and Docker, and what the public demonstration instance accepts.
`SMS_BEHIND_TLS=0 python -m securemailscope.api.production` runs the waitress server. Branding is a single
configuration value — `app.config["BRAND"]` or the `SMS_BRAND` environment variable (ADR-0026).

---

# 10. Feasibility Analysis

## 10.1 Technical feasibility

The system exists, runs end to end, and has been measured. Approximately 15,800 lines of Python with 277 passing
tests, 34 detection rules, eleven pipeline stages, a trained model and a working console, with **32 of 34
tracked deliverables mechanically verified**. The feasibility risk usual to a project of this kind — that the
hard parsing work proves intractable within the timeframe — has been retired. What remains is additive.

Deployment feasibility is stronger than for any comparable design: three pure-Python dependencies mean
installation is a file copy, with no package manager, no network access, no container runtime, no GPU and no
model artifact to fetch. The training step, which in most systems is the part that cannot be reproduced on
demand, completes in under fifteen seconds on a laptop.

## 10.2 Economic feasibility

The engine and rule pack are open, because government adoption depends on source availability. Revenue sits
above it: a continuous sensor with a fleet view; an annual posture attestation a CERT-In empanelled auditor can
sign; and a cryptographic-inventory subscription as the FY 2027–28 CBOM requirement takes effect.

Demand is documented rather than assumed, which is unusual. Ashiq et al. surveyed 117 email operators: 94.7%
were aware of MTA-STS and 48.8% named operational complexity as the reason they had not deployed it. Lee et al.
attribute 87% incorrect DANE key rollovers to the absence of automated tooling. The constraint in this market is
instrumentation, not awareness.

Comparable products in cryptographic discovery — IBM Quantum Safe Explorer, SandboxAQ AQtive Guard, Keyfactor
AgileSec — establish that enterprises pay for cryptographic inventory. All derive it from source code, container
images or host agents; none derives it from observed mail traffic.

## 10.3 Regulatory and legal feasibility

**Compliance mapping.** Findings cite NIST SP 800-52 Rev 2, NIST SP 800-45 Rev 2 and RFCs 3207, 4954, 5746,
6176, 7435, 7465, 7672, 8314, 8446, 8460, 8461, 8996 and 9325. SEBI's Cybersecurity and Cyber Resilience
Framework (August 2024) requires TLS 1.2 or better for data in transit across regulated entities; CERT-In's June
2023 guidelines for government entities require encrypted connections to mail servers and deployment of SPF,
DKIM and DMARC. The tool produces the evidence those requirements presuppose — **17 standards tracked**, each
reported as passing, failing or not observable.

**Evidence admissibility.** Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 conditions admissibility of an
electronic record on a certificate stating the record's hash value, signed by the person in charge of the device
and by an expert. Courts have been directed to treat an unexplained variation in hash value between seizure and
presentation as raising a strong presumption of tampering. Because CyberKavach computes and reports the
capture's SHA-256 and anchors every finding to frames and byte ranges within that capture, its output maps
directly onto what the provision requires.

**Privacy and lawfulness of capture.** The tool operates only on captures the operator is authorised to hold,
performs no decryption, copies no message content, redacts recovered credentials by default and makes no network
calls. Under the DPDP Rules notified 13 November 2025 a data fiduciary must file a detailed breach report within
72 hours; a forensic tool that never copies message content is materially easier to clear for use than one that
does. The `audit` table records every action against the system with actor, timestamp and subject, which is what
the CERT-In six-hour obligation actually requires an organisation to be able to produce.

## 10.4 Operational feasibility

The tool consumes a file format every existing capture infrastructure already produces and emits JSON, CEF and
ECS that an existing SIEM can ingest. It installs no agents and requires no change to mail servers. The
operational burden is therefore the capture policy, which in Indian regulated entities already exists by
mandate.

---

# 11. Challenges and Solutions

## 11.1 Technical challenges

**TLS 1.3 conceals the certificate.** The most common objection. The response is not to guess: report
`OPAQUE_TLS13` with the reason, assess the substantial information that remains visible in the handshake, and
grade the host `?`. This converts a blind spot into a reported fact.

**The environment blocks the numerical toolchain.** Smart App Control on the development machines blocks
compiled extensions, which has prevented `numpy` (and therefore scikit-learn and XGBoost), `cryptography`,
Pillow, OpenSSL, `pydantic`/`fastapi` and git's HTTPS transport from loading. The consequences were absorbed
rather than worked around: we wrote the DER/X.509 parser, the certificate generator, the gradient-boosting
trainer and the isolation forest ourselves, moved the service to Flask, and moved git to SSH. A secondary lesson
worth recording is that `import cryptography` succeeds while `cryptography.x509` fails, and `import reportlab`
fails only because it imports Pillow — so the actual call path must be tested, not the import.

**A baseline built from an attacked capture treats attacks as normal.** Two-pass construction with outlier
rejection before the second pass (ADR-0019).

**An anomaly rule that fires on every legacy server.** The cipher-intersection detector initially reported every
old server as under attack. It now requires corroboration (ADR-0023). This was found by the evaluation harness,
not by review — which is the argument for having one.

**Captures that silently decode to nothing.** Five of seven link-layer encapsulations once lost every frame and
produced a clean A+. Fixed by explicit decoding of all seven, and by the rule that an undecodable capture grades
`?` (ADR-0027).

**Certificate parsers are a classic source of defects.** Mitigated by writing the parser in pure Python with no
memory management, testing against deliberately malformed inputs, and planned cross-validation against an
independent implementation. The literature supports the approach: Georgiev et al. and Brubaker et al. found the
mainstream libraries' own APIs are the dominant source of validation failures.

## 11.2 Operational challenges

**Alert fatigue.** The failure mode of every security tool, and the one Sommer & Paxson predict from the base
rate. Addressed by role-aware severity, prioritisation, and the decision to report low-consequence findings as
informational rather than suppressing or inflating them. Measured severity accuracy is 1.00.

**Findings nobody acts on.** Li et al. measured this: even among operators who read detailed remediation
material, fewer than 40% fixed the problem. The response is to make the fix as close to copy-and-paste as
possible and to order the queue so the first three items are the ones that matter.

**Capture coverage.** A capture taken at the wrong point sees the wrong thing. Documented as a deployment
requirement, with the threat model stating what a given vantage point can and cannot establish.

**A server that restarts but does not.** During console development, a second server that failed to bind exited
silently while the stale one kept serving, costing half a session. Recorded in the worklog with the check that
prevents it.

**Six contributors on a four-day build.** Managed by treating the schema as a frozen contract with generated
fixtures, so stages could be developed against the contract rather than against each other, and by running
`scripts/audit.py` before and after every change.

---

# 12. Impact Assessment and Benefits

## 12.1 Capability impact

The primary impact is a capability that currently has no instrument: assessing the cryptographic posture of an
email estate from evidence rather than from access. Three consequences follow.

- **Incident response within the statutory window.** CERT-In requires reporting within six hours; the log and
  capture material is already retained for 180 days by mandate. A one-command analysis producing a graded,
  evidence-linked report converts existing raw material into a filing, and the audit table answers "who looked
  at what, and when".
- **Assessment of estates that cannot be probed.** Active scanning requires reachability and authorisation. A
  capture requires neither, which is what makes assessment of third-party, partner and legacy infrastructure
  possible at all.
- **Cryptographic inventory ahead of a deadline.** India's roadmap requires CII to inventory cryptographic
  assets by 2027 and vendors to supply CBOMs from FY 2027–28. For mail the measured baseline is 6.4%
  post-quantum readiness against 44.0% for the web, and no post-quantum certificates anywhere.

## 12.2 Stakeholder benefits

**Government and regulators.** Evidence-grade posture reporting for the NIC-operated government mail estate,
whose single-operator structure means one deployment covers it; sectoral assessment for NCIIPC; a defensible
basis for CERT-In filings; and progress measurement against the PQC roadmap.

**Mail administrators.** Configuration changes rather than findings, grouped by fix, with the clause that
justifies each one.

**Auditors.** A compliance report card with explicit OBSERVED / NOT_FOUND / UNKNOWN / INSUFFICIENT_EVIDENCE
verdicts across 17 tracked standards, an evidence pack satisfying section 63, and an attack matrix whose
ruled-out rows are positive assurance.

**Incident responders.** Five attack detectors, a timeline, recovered credentials as proof of exposure, and
drift analysis that surfaces host-level reversals an aggregate score conceals.

**Citizens.** Email carries password resets, financial instructions and legal notices for several hundred
million Indians, and users have no way to know whether a message crossed the network protected — a point Mayer
et al. make explicitly.

## 12.3 Economic impact

Business email compromise accounted for $3.046 billion of reported losses in 2025 across 24,768 complaints. Of
the 29.44 lakh incidents CERT-In handled in 2025, 3,41,646 were vulnerable exposed services. A tool that reduces
the time from capture to actionable finding acts on both numbers, though we make no claim about the size of the
reduction until it is measured.

Two market figures frame the commercial opportunity, and should be presented as vendor research: India's email
security market at $0.427 billion in 2025 rising to $1.31 billion by 2035, and the post-quantum cryptography
market at $810 million rising to $18.19 billion over the same period.

## 12.4 Alignment with the Sustainable Development Goals

**SDG 9 — industry, innovation and infrastructure.** The ITU situates the strengthening of cybersecurity within
Goal 9, and target 9.c's commitment to universal ICT access presupposes the infrastructure beneath it can be
trusted. Email transport is a component of that infrastructure currently unmeasured at the level of the
individual operator.

**SDG 16 — peace, justice and strong institutions.** Target 16.6, effective and accountable institutions, is
served directly by evidence-linked findings: accountability requires verifiable claims. Target 16.4, the
reduction of illicit financial flows, is served because business email compromise — $3.046 billion in a single
year in reported US losses alone — is precisely such a flow.

A third, weaker alignment exists with target 8.2, productivity through technological upgrading. We claim two
goals rather than six because the additional claims would be decorative.

---

# 13. Sustainability and Long-Term Viability

## 13.1 Technical sustainability

The dependency surface is three pure-Python libraries, which is the strongest available guarantee against
bit-rot: no compiled ABI to break, no model artifact to expire, no external service to be deprecated. The rule
pack is data rather than control flow, so keeping pace with standards means editing declarative objects, and the
standards citation attached to each rule makes it auditable which revision a rule implements.

**Crypto-agility is the central long-term design concern**, and it is also the product. Between now and 2035 the
cryptographic landscape changes twice: hybrid post-quantum key exchange becomes the default, and post-quantum
certificates begin to appear, currently at zero adoption. A tool whose job is to report which algorithms are in
use must be able to name algorithms that do not yet exist in deployments. Because group and algorithm
identifiers are parsed and reported rather than matched against a closed list, and cipher properties are derived
from IANA names rather than tabulated (ADR-0015), unknown identifiers are surfaced as unrecognised rather than
silently dropped.

## 13.2 Environmental footprint

Modest, and worth one sentence rather than a section: analysis is single-pass over a file on one machine,
training takes fifteen seconds without a GPU, and there are no cloud round trips and no always-on service. The
comparison class — continuous active scanning of an address space, or a hosted dashboard with a persistent
backend — consumes considerably more.

## 13.3 Institutional and financial sustainability

An open engine with paid operational tooling above it is the model that has worked for comparable security
instrumentation, and it is compatible with government procurement, which requires source availability. The
CERT-In empanelment structure — 231 audit organisations — provides a distribution route that does not require
building a direct sales operation. The 2027 and FY 2027–28 regulatory milestones provide a demand event with a
date attached, which is a more reliable basis for planning than a market forecast.

---

# 14. International Benchmarking and Best Practices

## 14.1 Comparison with existing tools

| Tool | What it does | From a capture | Offline | Mail-aware severity | Attack evidence | Rules out attacks |
|---|---|---|---|---|---|---|
| SSL Labs | Grades a web TLS endpoint | No | No | No | No | No |
| testssl.sh / sslyze | Enumerates endpoint capability | No | No | No | No | No |
| internet.nl mail test | Scores STARTTLS, DANE, SPF/DKIM/DMARC; does not test MTA-STS | No | No | Partial | No | No |
| CheckTLS | Tests a mail domain's transport | No | No | No | No | No |
| Wireshark / tshark | Decodes packets | Yes | Yes | No | No | No |
| Zeek + JA4 | Logs TLS metadata at scale | Yes | Yes | No | No | No |
| IBM / SandboxAQ / Keyfactor | Cryptographic inventory | No (source, container or agent) | Varies | No | No | No |
| **CyberKavach** | Graded posture with evidence, remediation and an attack matrix | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |

The pattern is consistent: tools that judge require access, and tools that work from captures decode without
judging. Zeek is the closest and the distinction is precise — it produces excellent logs and no assessment,
which makes it a sensible *input* to a large-scale deployment of this analysis rather than a competitor.

## 14.2 International policy benchmarking

| Jurisdiction | Instrument | First required step | Date |
|---|---|---|---|
| India | DST / National Quantum Mission PQC roadmap (Feb 2026) | Inventory cryptographic assets, assess quantum risk | **2027** (CII) |
| India | CBOM requirement for vendors | Submit cryptographic bill of materials | **FY 2027–28** |
| United Kingdom | NCSC phased migration timeline | Cryptographic discovery, dependency mapping, planning | **2028** |
| United States | NIST IR 8547 | RSA-2048 / P-256 deprecated, then disallowed | **2030 / 2035** |
| European Union | Coordinated PQC transition recommendation | National roadmaps across member states | — |

Three jurisdictions independently place *discovery* first. The measurement literature independently finds mail
the least ready protocol. The intersection is the strategic case for this work.

## 14.3 Where India is positioned

MTA-STS and DANE adoption is low everywhere — even the Netherlands, which has pushed hardest through
internet.nl, reported 14% DANE and 6% MTA-STS in September 2025. India's advantage is structural rather than
technical: because official government mail is centralised at NIC under the E-mail Policy of the Government of
India, a single operator decision propagates across the whole government estate. The binding constraint is
measurement, and that is what this tool supplies.

---

# 15. Implementation Roadmap

## 15.1 Completed

Schema frozen and contract generated; link-layer decoding across seven encapsulations; TCP reassembly with
provenance; protocol identification and the STARTTLS state machine; TLS record and handshake parsing with
JA3/JA3S and post-quantum group detection; DER/X.509 parsing with RSA signature verification; the 34-rule pack
with standards and remediation on every rule; role-aware severity; 51-field feature extraction; a
gradient-boosted risk model and isolation forest trained locally in pure Python; the grounded narrative layer
with its verifier; scoring and aggregation; the attack feasibility matrix; temporal drift; JSON, self-contained
HTML, CEF and ECS outputs; the Flask service with stdlib authentication and a twelve-view console; the synthetic
corpus, ground-truth manifest and evaluation harness; 277 tests; `scripts/audit.py` and `scripts/evaluate.py`.

## 15.2 Immediate

1. **USP-11 — passive DNS, DANE and MTA-STS correlation.** The one unbuilt differentiator, and the
   highest-value remaining feature.
2. **Real-world captures.** Every capture measured so far is synthetic and self-authored. This is now the most
   likely cause of an unpleasant surprise under demonstration.
3. **Human review of the offline HTML report**, which has been verified structurally but never looked at. The
   console has been driven end to end in a browser; the report is a separate renderer.
4. **A deliberate decision on the scoring curve**, so that a cleartext relay does not reach the top grade (§17.2).

## 15.3 Phase 1 (Months 1–3)

Cross-validation of the handshake parse against an independent implementation; a CBOM export in CycloneDX form;
the evidence certificate annexe in the form section 63 expects; PDF export once a renderer is available.

## 15.4 Phase 2 (Months 4–9)

Continuous sensor mode with a rolling baseline and drift detection; fleet aggregation across captures and over
time; deeper SIEM integration; a pilot with a CERT-In empanelled auditor.

## 15.5 Phase 3 (Months 10–18)

Deployment against a government estate in coordination with NIC; sector-level baselines for NCIIPC; longitudinal
posture measurement as the PQC migration proceeds; publication of the rule pack and corpus as a public
benchmark, which the research community currently lacks.

---

# 16. Risk Management and Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Real-world captures behave unlike the synthetic corpus | **High** | **High** | Seven link-layer encapsulations covered; undecodable captures grade `?`; truncation paths tested; obtaining real captures is the first roadmap item |
| A defect in our own TLS or X.509 parser | Medium | High | 277 tests including malformed input; pure-Python parser with no memory management; independent cross-validation planned |
| The scoring curve is attacked on stage ("you gave a plaintext server an A+") | Medium | Medium | The finding *is* reported and correctly downgraded per RFC 7435; the curve is a deliberate open decision, documented rather than hidden |
| Environment blocks a further dependency | Medium | Low | Three pure-Python dependencies; policy of testing the call path, not the import |
| Model degrades or fails to beat the baseline | Low | Low | The trainer refuses to write a model that loses to the baseline; the deterministic engine carries the product regardless |
| Capture vantage point misleads the analysis | Medium | Medium | Explicit threat model; `?` grading when evidence is insufficient; drift refuses non-overlapping estates |
| Findings dismissed as false alarms | Low | High | Role-aware severity with measured 1.00 severity accuracy; documented justification on every adjusted finding; analyst dispositions feed back as training signal |
| Legal challenge to a capture's provenance | Low | High | Capture hash, frame-level anchoring, section 63 alignment, no decryption, credentials redacted, full audit trail |
| Generated narrative states something untrue | Low | High | Closed-vocabulary verification discards offending text whole; deterministic template ships by default |
| Six contributors diverging | Medium | Medium | Frozen schema, ADR discipline, audit must pass before merge, verification from a clean clone |

---

# 17. Limitations and Future Enhancements

A research document that conceals its own limitations is worth less than one that names them. These are stated
plainly, and every one is reproducible from the repository.

## 17.1 Current limitations

1. **Every capture is synthetic.** The corpus is self-authored. The evaluation therefore measures implementation
   correctness against declared intent, not field accuracy. This is the single largest limitation of the work.
2. **USP-11 is not built.** Passive DNS extraction for DANE and MTA-STS correlation remains unimplemented, which
   is also the highest-value remaining feature given the measured adoption and misconfiguration rates.
3. **PDF export is partial.** Playwright is blocked on the development machines; browser print works with the
   print stylesheet applied.
4. **Throughput is 0.05 MB/s.** Pure Python with no compiled dependencies. Suitable for bounded forensic
   captures, unsuitable for line-rate monitoring.
5. **The offline HTML report has never been reviewed by a human.** Verified structurally only.
6. **The scoring curve permits a top grade for a cleartext relay.** See §17.2.
7. **The parsers have not yet been cross-validated** against an independent implementation.

## 17.2 The scoring curve, stated as an open question

`smtp_relay_cleartext.pcap` grades A+ at 95/100. This is *correct* under role-aware severity: the relay finding
is downgraded to LOW because opportunistic relay is outside the operator's control under RFC 7435, and the
evaluation harness agrees with ground truth. The finding is reported. But A+ is the top grade, and "you gave an
A+ to a plaintext mail server" is a one-line objection with a three-line defence. We record it as a deliberate
open decision in `pipeline.py` rather than quietly adjusting the curve, because changing a score to win an
argument is how a scoring system stops meaning anything.

## 17.3 Highest-value additions

**Authenticated-transport assessment (MTA-STS, DANE, TLSRPT).** The research case is unusually strong: 0.07%
MTA-STS adoption with 29.6% of deployments broken, over 30% of DANE TLSA records unvalidatable, 87% of key
rollovers incorrect — and both papers attribute the failures to missing tooling. Combining capture-observed
behaviour with published policy allows a check no existing tool performs: *did this session actually honour the
policy this domain published?*

**Cryptographic Bill of Materials export.** A CycloneDX CBOM (ECMA-424) describing algorithms, key sizes,
certificates and protocol versions observed across a mail estate. The only feature on this list with a statutory
deadline attached — FY 2027–28 — and the existing tools in that market derive inventory from code and hosts
rather than traffic.

**Real-world corpus and public benchmark.** The absence of labelled mail captures with known cryptographic
weaknesses is a genuine obstacle to research in this area. Our generator plus manifest is a candidate
contribution, and would be the most useful thing this project could give back.

**Encrypted Client Hello.** As ECH deploys, the requested name leaves the clear portion of the handshake. Work
is needed on what can still be established and — consistent with §8.4 — on reporting honestly what cannot.

**JA4+ fingerprints** alongside JA3/JA3S, which are more robust to the client-side randomisation that has
degraded JA3's discriminative power.

**Passive detection of SMTP smuggling** and related message-boundary attacks, adjacent to our STARTTLS analysis
and with a recent literature of its own.

---

# 18. Conclusion

Email transport security has been measured extensively and instrumented hardly at all. The literature
establishes that opportunistic encryption fails open by design, that authentication is largely absent in
practice, that the STARTTLS upgrade is a recurring vulnerability class, that downgrade attacks occur at
measurable scale, that the standards intended to fix all of this are deployed on a fraction of a percent of
domains and misconfigured in roughly a third of those, and that mail is the protocol furthest behind on the
post-quantum transition. What the literature does not provide — because its method is active scanning — is a way
for a specific operator to learn what happened to their own mail.

CyberKavach is that instrument. It grades an email estate from a packet capture alone, on an A+ to F scale with
`?` reserved for what it could not see; it ranks each weakness by the role of the port, which the literature
says is the correct discrimination and which no existing tool makes; it reports five classes of evidence that an
attack has already occurred; it judges sixteen named attacks and reports what it has ruled out as carefully as
what it found; and it anchors every claim to a capture hash, frame number and byte range, which is both what
makes a finding checkable and what Indian evidence law now expects.

The claims are measured rather than asserted. 277 tests pass. Against ground truth derived from generator
configuration rather than from tool output, there is no disagreement across 14 captures and 20 rules. The risk
model — gradient-boosted trees written from scratch because the standard libraries cannot be installed — trains
in twelve seconds and beats its rule-derived baseline by 73%, with a Spearman correlation of 0.92 on the
ordering that a triage queue actually depends on. Thirty-two of thirty-four deliverables verify mechanically.

What is not yet true is stated as such. Every capture measured is synthetic. DANE and MTA-STS correlation is
unbuilt. The parsers have not been cross-validated against an independent implementation. Throughput suits
forensic analysis and not line-rate monitoring.

The strategic case is a coincidence of two independent findings. Three jurisdictions have now placed
cryptographic discovery as the first required step of the post-quantum transition, with India's critical
infrastructure deadline in 2027 and a vendor CBOM requirement in FY 2027–28. And the most recent measurement of
post-quantum readiness finds mail at 6.4% against 44.0% for the web, with no post-quantum certificates in
existence anywhere. Discovery is mandated, mail is furthest behind, and for mail there is no discovery tool.
That is the gap this work occupies.

---

# 19. References

## Peer-reviewed papers

1. Durumeric, Z., Adrian, D., Mirian, A., Kasten, J., Bursztein, E., Lidzborski, N., Thomas, K., Eranti, V.,
   Bailey, M., Halderman, J.A. "Neither Snow Nor Rain Nor MITM… An Empirical Analysis of Email Delivery
   Security." *Proc. ACM IMC*, 2015. https://doi.org/10.1145/2815675.2815695
2. Mayer, W., Zauner, A., Schmiedecker, M., Huber, M. "No Need for Black Chambers: Testing TLS in the E-mail
   Ecosystem at Large." *Proc. ARES*, 2016. https://arxiv.org/abs/1510.08646
3. Holz, R., Amann, J., Mehani, O., Wachs, M., Kaafar, M.A. "TLS in the Wild: An Internet-wide Analysis of
   TLS-based Protocols for Electronic Communication." *NDSS*, 2016. https://arxiv.org/abs/1511.00341
4. Foster, I.D., Larson, J., Masich, M., Snoeren, A.C., Savage, S., Levchenko, K. "Security by Any Other Name:
   On the Effectiveness of Provider Based Email Security." *Proc. ACM CCS*, 2015.
5. Poddebniak, D., Ising, F., Böck, H., Schinzel, S. "Why TLS is better without STARTTLS: A Security Analysis of
   STARTTLS in the Email Context." *30th USENIX Security Symposium*, 2021.
   https://www.usenix.org/system/files/sec21-poddebniak.pdf
6. Lee, H., Ashiq, M.I., Müller, M., van Rijswijk-Deij, R., Kwon, T., Chung, T. "Under the Hood of DANE
   Mismanagement in SMTP." *31st USENIX Security Symposium*, 2022.
   https://www.usenix.org/system/files/sec22-lee.pdf
7. Ashiq, M.I., Fiebig, T., Chung, T. "Unraveling the Complexities of MTA-STS Deployment and Management in
   Securing Email." *Proc. ACM IMC*, 2025. https://doi.org/10.1145/3730567.3732916
8. Georgiev, M., Iyengar, S., Jana, S., Anubhai, R., Boneh, D., Shmatikov, V. "The Most Dangerous Code in the
   World: Validating SSL Certificates in Non-Browser Software." *Proc. ACM CCS*, 2012.
9. Brubaker, C., Jana, S., Ray, B., Khurshid, S., Shmatikov, V. "Using Frankencerts for Automated Adversarial
   Testing of Certificate Validation in SSL/TLS Implementations." *IEEE S&P*, 2014.
10. Sommer, R., Paxson, V. "Outside the Closed World: On Using Machine Learning for Network Intrusion
    Detection." *IEEE S&P*, 2010.
11. Dreger, H., Feldmann, A., Mai, M., Paxson, V., Sommer, R. "Dynamic Application-Layer Protocol Analysis for
    Network Intrusion Detection." *15th USENIX Security Symposium*, 2006.
12. Li, F., Durumeric, Z., Czyz, J., Karami, M., Bailey, M., McCoy, D., Savage, S., Paxson, V. "You've Got
    Vulnerability: Exploring Effective Vulnerability Notifications." *25th USENIX Security Symposium*, 2016.
13. Anderson, B., Paul, S., McGrew, D. "Deciphering malware's use of TLS (without decryption)." *Journal of
    Computer Virology and Hacking Techniques*, 2018.
14. Jafari Siavoshani, M., et al. "Machine learning interpretability meets TLS fingerprinting." *Soft Computing*
    27(11), 2023, 7191–7208.
15. Friedman, J.H. "Greedy Function Approximation: A Gradient Boosting Machine." *Annals of Statistics* 29(5),
    2001.
16. Liu, F.T., Ting, K.M., Zhou, Z.-H. "Isolation Forest." *IEEE ICDM*, 2008.
17. Chen, T., Guestrin, C. "XGBoost: A Scalable Tree Boosting System." *Proc. ACM KDD*, 2016.
18. Lundberg, S.M., Lee, S.-I. "A Unified Approach to Interpreting Model Predictions." *NeurIPS*, 2017.
19. Rousseeuw, P.J., Van Driessen, K. "A Fast Algorithm for the Minimum Covariance Determinant Estimator."
    *Technometrics* 41(3), 1999.

## Preprints

20. Loizou, K., Ghadafi, E. "Measuring Post-Quantum TLS Deployment Across UK Internet Sectors." arXiv
    2608.02147, 2026. https://arxiv.org/abs/2608.02147
21. "Measurement Study of Post-Quantum Readiness of Internet: 2026." arXiv 2606.16473.
22. "Mind the Gap: Policy vs Reality in Post-Quantum TLS Deployment." arXiv 2607.29005.
23. Singh, K., Kashyap, A., Cherukuri, A.K. "Interpretable Anomaly Detection in Encrypted Traffic Using SHAP
    with Machine Learning Models." arXiv 2505.16261, 2025.
24. "INTACT: Intent-Aware Representation Learning for Cryptographic Traffic Violation Detection." arXiv
    2602.21252.

## Standards and specifications

25. RFC 3207 — SMTP Service Extension for Secure SMTP over TLS.
26. RFC 4954 — SMTP Service Extension for Authentication.
27. RFC 5746 — TLS Renegotiation Indication Extension.
28. RFC 6176 — Prohibiting SSL Version 2.0.
29. RFC 7435 — Opportunistic Security: Some Protection Most of the Time.
30. RFC 7465 — Prohibiting RC4 Cipher Suites.
31. RFC 7672 — SMTP Security via Opportunistic DANE TLS.
32. RFC 8314 — Cleartext Considered Obsolete: Use of TLS for Email Submission and Access.
33. RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3.
34. RFC 8460 — SMTP TLS Reporting.
35. RFC 8461 — SMTP MTA Strict Transport Security (MTA-STS).
36. RFC 8996 — Deprecating TLS 1.0 and TLS 1.1.
37. RFC 9325 — Recommendations for Secure Use of TLS and DTLS.
38. NIST SP 800-52 Rev 2 — Guidelines for the Selection, Configuration and Use of TLS Implementations.
39. NIST SP 800-45 Ver 2 — Guidelines on Electronic Mail Security.
40. NIST IR 8547 — Transition to Post-Quantum Cryptography Standards.
41. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM).
42. CycloneDX Cryptography Bill of Materials / ECMA-424.
43. ArcSight Common Event Format (CEF); Elastic Common Schema (ECS).

## Indian policy and law

44. Information Technology Act, 2000, section 70B.
45. CERT-In Directions under section 70B(6), 28 April 2022 — six-hour incident reporting, 180-day log retention.
46. CERT-In, *Guidelines on Information Security Practices for Government Entities*, 30 June 2023.
47. MeitY, *E-mail Policy of the Government of India*.
48. Digital Personal Data Protection Act, 2023; DPDP Rules, 2025 (notified 13 November 2025).
49. Bharatiya Sakshya Adhiniyam, 2023, section 63.
50. SEBI, *Cybersecurity and Cyber Resilience Framework (CSCRF)*, 20 August 2024.
51. MeitY / CERT-In / SISA, *Transitioning to Quantum Cyber Readiness*, July 2025.
52. Department of Science and Technology, National Quantum Mission task force, *India's Post-Quantum
    Cryptography Migration Roadmap*, February 2026.
53. CERT-In, *Annual Report 2025*.

## Reports and datasets

54. FBI Internet Crime Complaint Center, *2025 Internet Crime Report*.
55. International Telecommunication Union, Goal 9 — Infrastructure, Industrialization, Innovation.
56. Canadian Institute for Cybersecurity, CIC-IDS2017 intrusion detection evaluation dataset.
57. Market Research Future, *India Email Security Market* (vendor research, cited for market sizing only).

---

# Appendices

## Appendix A — Architecture

```
  capture.pcap
      |
      v
  S0  ingest .............. 7 link-layer encapsulations, SHA-256, frame index
  S1  reassembly .......... TCP streams + byte->frame provenance map
  S2  protocol ID ......... SMTP/IMAP/POP3 by banner; port role assigned
  S3  STARTTLS ............ ten checks over the plaintext phase
  S4  TLS ................. records, handshake, JA3/JA3S, PQ groups
  S5  X.509 ............... DER parse, chain build, RSA signature verify
  S6  rules ............... 34 rules x 10 categories + role-aware severity
  S7  features ............ 51 fields per session
  S8  AI .................. GBT risk + isolation forest + priority + narrative
  S9  aggregate ........... host/fleet grades A+..F or ?, attack matrix, drift
  S10 report .............. JSON | self-contained HTML | CEF | ECS | console
```

Every finding references `(capture SHA-256, stream id, frame numbers, byte range, direction, timestamp)`. The
provenance map built at S1 is what makes the last four resolvable.

## Appendix B — Report structure (JSON)

Top-level keys: `schema_version`, `capture`, `sessions`, `hosts`, `fleet`, `prioritised_findings`,
`executive_summary`, `generated_at`, `evaluation_metrics`. `fleet` carries `score`, `grade`, `host_count`,
`session_count` and `category_scores`. JSON Schema and TypeScript definitions are generated from the dataclasses
by `python -m schema.jsonschema`, so the contract cannot drift from the code.

## Appendix C — Rule catalogue (34 rules)

| Rule ID | Category | Base severity | Primary standard |
|---|---|---|---|
| TLS-SSL-PROHIBITED | protocol | critical | RFC 6176 |
| TLS-DEPRECATED-VERSION | protocol | high | RFC 8996 §3 |
| TLS-WEAK-CIPHER-RC4 | cipher | high | RFC 7465 |
| TLS-WEAK-CIPHER-3DES | cipher | high | RFC 9325 §4 |
| TLS-NULL-OR-ANON-CIPHER | cipher | critical | RFC 9325 §4 |
| TLS-EXPORT-CIPHER | cipher | critical | RFC 9325 §4 |
| TLS-WEAK-CIPHER-BITS | cipher | high | RFC 9325 §4 |
| TLS-CBC-CIPHER | cipher | medium | RFC 9325 §4 |
| TLS-NO-FORWARD-SECRECY | key_exchange | medium | RFC 9325 §4 |
| TLS-ANON-KEY-EXCHANGE | key_exchange | critical | RFC 9325 §4 |
| TLS-WEAK-DH-GROUP | key_exchange | high | RFC 9325 §4 |
| CERT-EXPIRED | certificate | high | RFC 8314 §3 |
| CERT-EXPIRED-SELF-SIGNED | certificate | high | RFC 8314 §3 |
| CERT-EXPIRING-SOON | certificate | medium | RFC 8314 §3 |
| CERT-SELF-SIGNED | certificate | medium | RFC 8314 §3 |
| CERT-CHAIN-INCOMPLETE | certificate | medium | RFC 8314 §3 |
| CERT-HOSTNAME-MISMATCH | certificate | high | RFC 8314 §3 |
| CERT-WEAK-KEY | certificate_strength | high | NIST SP 800-52 Rev 2 |
| CERT-WEAK-SIGNATURE | certificate_strength | high | RFC 9325 §4 |
| STARTTLS-ADVERTISED-NOT-USED | starttls | high | RFC 8314 §3 |
| STARTTLS-NOT-OFFERED | starttls | high | RFC 8314 §3 |
| STARTTLS-EHLO-NOT-REISSUED | configuration | low | RFC 3207 §4.2 |
| ATTACK-STARTTLS-STRIPPED | attack_evidence | critical | RFC 8314 §3 |
| ATTACK-CLEARTEXT-CREDENTIALS | attack_evidence | critical | RFC 8314 §3 |
| ATTACK-AUTH-BEFORE-TLS | configuration | high | RFC 4954 §4 |
| ATTACK-DOWNGRADE-SENTINEL | attack_evidence | high | RFC 8446 §4.1.3 |
| ATTACK-CIPHER-INTERSECTION-ANOMALY | attack_evidence | medium | RFC 9325 §4 |
| ATTACK-CERT-SUBSTITUTION | attack_evidence | high | RFC 8314 §3 |
| CONFIG-NO-RENEGOTIATION-INFO | configuration | medium | RFC 5746 |
| CONFIG-COMPRESSION-ENABLED | configuration | medium | RFC 9325 §4 |
| CONFIG-NO-SNI | configuration | low | RFC 9325 §4 |
| SMTP-RELAY-NO-TLS | configuration | medium | RFC 7435 §3 |
| ANALYSIS-INCOMPLETE-HANDSHAKE | configuration | info | NIST SP 800-52 Rev 2 |
| PQ-NOT-READY | post_quantum | low | NIST FIPS 203 |

Base severity is what the rule emits; the role-aware policy then adjusts it and records the justification.

## Appendix D — The 51-field feature vector

| Group | Fields |
|---|---|
| Protocol version (3) | `tls_version_num`, `is_deprecated_version`, `version_downgrade_from_offered` |
| Cipher (7) | `cipher_strength_bits`, `cipher_is_aead`, `cipher_is_cbc`, `cipher_is_rc4`, `cipher_is_3des`, `cipher_is_null_or_anon`, `cipher_is_export` |
| Key exchange (4) | `kex_is_ephemeral`, `kex_is_anon`, `kex_group_bits`, `has_forward_secrecy` |
| Post-quantum (2) | `pq_hybrid_offered`, `pq_hybrid_negotiated` |
| Certificate (11) | `cert_present`, `cert_opaque_tls13`, `cert_days_to_expiry`, `cert_is_expired`, `cert_is_self_signed`, `cert_key_bits`, `cert_key_is_rsa`, `cert_sig_is_weak`, `cert_chain_length`, `cert_chain_complete`, `cert_hostname_match` |
| Port role (3) | `port_role_is_relay`, `port_role_is_submission`, `port_role_is_access` |
| TLS mode (3) | `tls_mode_is_implicit`, `tls_mode_is_starttls`, `tls_mode_is_cleartext` |
| STARTTLS state (3) | `starttls_advertised`, `starttls_completed`, `starttls_ehlo_reissued` |
| Attack indicators (7) | `starttls_stripped_suspected`, `credentials_in_cleartext`, `auth_before_tls`, `downgrade_sentinel_present`, `fallback_scsv_present`, `cipher_intersection_anomaly`, `certificate_substitution` |
| Configuration (5) | `renegotiation_info_present`, `compression_enabled`, `sni_present`, `alpn_present`, `session_resumed` |
| Diagnostics and fingerprints (3) | `handshake_alert_count`, `ja3_rarity`, `ja3s_rarity` |

The same vector is the input to the rule predicates and to the classifier, which is what prevents the
machine-learning labelling oracle from diverging from the shipping detector (ADR-0003).

## Appendix E — Evaluation protocol and results

**Corpus.** Captures generated by `testbed/synth.py` against certificates from `testbed/certgen.py`, with
expected findings declared per capture in `testbed/manifest.json` and derived by reading the generator, never
from tool output. `testbed/relink.py` produces seven link-layer variants.

**Procedure.** For each capture, run the pipeline and compare produced findings against declared findings by
rule identifier. Classify each as true positive, false positive, false negative, or *insufficient evidence*
where the rule could not fire because the required material was encrypted.

**Results.** 14/14 captures exact; 20/20 rules exercised without error; TP 30, FP 0, FN 0; precision 1.00,
recall 1.00, F1 1.00; severity accuracy 1.00; protocol identification accuracy 1.00; throughput 0.05 MB/s.

**Required framing.** *"No disagreement with independently-derived ground truth on a synthetic corpus"* — not
perfection, and not field accuracy.

**Model results.** Corpus 10,000 × 55 with `archetype` excluded as leakage; 8,000/2,000 split; GBT 200 trees
depth 3 in 12.0 s; baseline MAE 0.1681, model MAE 0.0451 (73% better), R² 0.9429, Spearman 0.9225; isolation
forest 150 trees over 256-row subsamples in 2.4 s, threshold 0.5856, flagging 99/2,000 (5.0%).

## Appendix F — Decision record index

Thirty-two ADRs are maintained in `docs/04_DECISIONS.md`. Those most load-bearing for this paper:

| ADR | Decision |
|---|---|
| 0002 | `dpkt` plus a custom parser, not `pyshark`/`tshark` at runtime |
| 0003 | The rule engine is the labelling oracle for supervised ML |
| 0004 | Evidence references are born with the data, not added later |
| 0006 | ML trains on synthetic feature vectors; PCAPs are for validation and demo |
| 0009 | The schema package has zero dependencies |
| 0010 | Certificate findings are split into trust and strength |
| 0012 | Smart App Control confirmed blocking numpy |
| 0014 | Unanalysed is reported as unknown, never as clean |
| 0015 | Cipher properties derived from IANA names, not tabulated |
| 0017 | X.509 parsed in pure Python |
| 0018 | The dashboard is a single self-contained HTML file |
| 0019 | The anomaly baseline rejects contaminated sessions before learning |
| 0020 | Corpus split shuffles indices together |
| 0021 | Flask, not FastAPI; stdlib sqlite3 for persistence |
| 0023 | The cipher intersection anomaly requires corroboration |
| 0024 | Real authentication after all, stdlib only |
| 0026 | The console: no geographic threat map |
| 0027 | Link-layer decoding, and never letting an unreadable capture read as clean |
| 0028 | The narrative layer is verified, not trusted |
| 0029 | Drift refuses to compare estates that are not the same estate |
| 0030 | The attack matrix is worth more for what it rules out |
| 0031 | Train the model locally, in pure Python |

---

## Document notes

**Placeholders to fill:** `[TEAM NAME]`, `[TEAM ID]`.

**Naming.** This document uses **CyberKavach**. The code, README and most other documents use
**SecureMailScope**; the console wordmark says **Kavach**. The conflict is recorded as unresolved in
`CLAUDE.md` and should be settled before submission — the UI half is a single configuration value
(`app.config["BRAND"]` or `SMS_BRAND`), the documentation half is a decision.

**Reproducing every number in this paper:**

```
python testbed/certgen.py && python testbed/synth.py && python testbed/relink.py
python scripts/train_local.py      # §5 figures
python scripts/evaluate.py         # §6.3 figures
python scripts/audit.py            # §6.4 figures
```
