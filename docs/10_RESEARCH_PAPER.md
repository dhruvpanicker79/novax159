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
**27 September 2026**

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
every finding is traceable to a capture hash, frame number and byte offset. Three decisions distinguish it:
severity is adjusted by the role of the port, since an expired certificate is routine between two relays and
critical where a password crosses; five passive detectors report evidence that an attack has already occurred
rather than that one is possible; and a host whose handshake could not be fully parsed is graded `?` rather than
given a pass it did not earn. It is implemented in some 13,300 lines of Python with one pure-Python dependency
and 168 passing tests, so that it runs on an air-gapped machine.

**Keywords:** Email security, STARTTLS, passive network forensics, cryptographic posture assessment,
post-quantum readiness, digital evidence

---

## Contents

1. Introduction
2. Literature Review and Related Work
3. Technical Architecture and Design
4. Testing and Validation Methodology
5. User Flows and System Interactions
6. Innovation and Technical Features
7. Technology Stack and Implementation
8. Detailed Technical Implementation
9. Feasibility Analysis
10. Challenges and Solutions
11. Impact Assessment and Benefits
12. Sustainability and Long-Term Viability
13. International Benchmarking and Best Practices
14. Implementation Roadmap
15. Risk Management and Mitigation
16. Future Enhancements and Scalability
17. Conclusion
18. References
19. Appendices A–F

---

# 1. Introduction

## 1.1 Background and Motivation

SMTP was specified without confidentiality or authentication. Both were retro-fitted: first through the
STARTTLS extension (RFC 3207), which upgrades an established plaintext connection in place, and later through
implicit TLS on dedicated ports (RFC 8314). The retro-fit was deliberately permissive. RFC 7435 formalised the
resulting model as *opportunistic security*: encrypt when both ends agree, and proceed in plain text when they
do not, on the reasoning that partial protection deployed widely beats strong protection deployed nowhere.

That reasoning was sound for adoption and is corrosive for assurance. Three properties follow from it, and
together they define the problem this project addresses.

**It fails open, silently.** Where a TLS negotiation errors — or is made to error — the mail is delivered
anyway, unencrypted. Durumeric et al. tested five widely deployed mail transfer agents and found that all five
fall back to cleartext when STARTTLS fails, and that two of the three most popular platforms do not attempt
STARTTLS at all unless explicitly configured to. No signal reaches the user, and the protocol provides no
mechanism for a sender to require secure transport or for a recipient to learn that a message travelled
insecurely.

**It is rarely authenticated.** Encrypting to an unverified peer defeats an eavesdropper but not an active
attacker. Mayer et al. scanned the entire IPv4 address space across SMTP, POP3 and IMAP — 20 million IP/port
combinations and more than 10 billion TLS handshakes over three months — and found 65% of SMTP hosts
presenting self-signed certificates, with only 33–37% of mail-access deployments presenting certificates that
validate correctly. Durumeric et al. tested 19 major providers by presenting a self-signed certificate: not one
rejected it.

**The upgrade step itself is a vulnerability class.** Poddebniak et al. performed the first structured security
analysis of STARTTLS across SMTP, POP3 and IMAP, testing 28 clients and 23 servers with a 100-test-case
toolkit. They reported more than 40 distinct flaws, found that only 3 of 28 clients exhibited no
STARTTLS-specific issue, and scanned the internet to establish that 320,000 mail servers — 2% of all mail
servers — were vulnerable to a command injection that permits credential theft. Their conclusion is
unambiguous: STARTTLS is error-prone to implement, under-specified in the standards, and should be avoided in
favour of implicit TLS.

These are not theoretical risks. Durumeric et al. found 41,405 SMTP servers across 4,714 autonomous systems in
193 countries whose STARTTLS negotiations were being corrupted in transit, and measured the effect at Gmail:
96.13% of mail sent from Tunisia arrived in plain text, with seven countries above 20%. Of the 423 autonomous
systems where every observed mail server showed stripping behaviour, 13.5% were financial institutions and
7.1% were government networks.

## 1.2 Problem Statement

Problem statement SIH26159, set by the National Technical Research Organisation, asks for a passive,
evidence-driven framework that ingests authorised PCAP/PCAPNG captures of SMTP, IMAP and POP3 traffic;
reconstructs complete TCP sessions; parses TLS handshakes and extracts X.509 certificates; identifies weak
algorithms and deprecated protocol versions against NIST SP 800-52 Rev 2 and the relevant RFCs; applies machine
learning for risk classification and anomaly detection; and exports prioritised, evidence-backed findings as
JSON, HTML and PDF with an interactive dashboard. The statement is explicit that every finding must be reported
as OBSERVED, NOT_FOUND, UNKNOWN or INSUFFICIENT_EVIDENCE, never as an inference presented as a fact.

Our own decomposition of the statement into 21 numbered deliverables (D01–D21) plus two objectives (O01, O02)
and a traceability matrix is recorded in `docs/01_PROBLEM_STATEMENT.md`; verified status is generated
mechanically by `scripts/audit.py` and recorded in `docs/06_STATUS.md`.

The framing that matters for this paper is narrower. The published literature establishes what is wrong with
email transport security at ecosystem scale. It does so entirely through **active measurement**: ZMap sweeps of
the address space, DNS scans, probes issued to endpoints. An operator reading those papers learns that the
problem is severe and learns nothing about their own estate. The question *"what did my mail actually do, and
did anyone interfere with it?"* has no tool behind it — and under the CERT-In Directions of 2022 an Indian
organisation must answer a version of it within six hours of noticing an incident, using log data it is
separately required to retain for 180 days.

## 1.3 Solution Overview

CyberKavach is a twelve-stage analysis pipeline that converts a packet capture into a graded, evidence-linked
cryptographic posture report. It performs no decryption, makes no network calls, and requires no service to be
reachable.

Given a capture, it reassembles TCP streams while retaining a byte-to-frame provenance map; identifies mail
protocols from the server banner and command grammar rather than the port number; runs a STARTTLS state machine
with ten checks; parses TLS records and handshake messages, computing JA3 and JA3S fingerprints and detecting
post-quantum key-exchange groups; parses X.509 certificates from DER and verifies RSA signatures; evaluates 34
rules across ten finding categories; extracts 51 features per session; scores risk, detects anomalies against a
fleet baseline and orders findings by priority; aggregates to per-host and fleet grades on an A+ to F scale with
`?` reserved for hosts that could not be fully assessed; and writes JSON, a single self-contained HTML file
that is also the interactive dashboard, and PDF.

Every finding carries the SHA-256 of the capture, the stream index, the frame numbers and the byte offsets that
produced it, together with the standards clause it enforces and the configuration change that fixes it.

## 1.4 Market Analysis and Current State

### 1.4.1 The threat, in financial terms

The FBI's Internet Crime Complaint Center recorded $20.877 billion in reported losses in 2025 across 1,008,597
complaints, a 26% year-on-year increase. Business email compromise accounted for **$3.046 billion** of that —
the second-largest single loss category after investment fraud — across 24,768 complaints, an average of
roughly $123,000 per incident. BEC is an identity and trust failure rather than purely a transport failure, but
transport security is the layer at which message tampering, credential capture and relay interception are
prevented, and it is the layer at which a forensic capture can establish what was possible.

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

In India specifically, CERT-In handled **29.44 lakh** incidents in 2025, up from 20.41 lakh in 2024, of which
**3,41,646** were classified as vulnerable services — the precise category for which this tool produces
evidence.

### 1.4.3 Regulatory drivers and market size

Three regulatory currents converge on this capability.

**Incident forensics.** The CERT-In Directions of 28 April 2022 require reporting within six hours of noticing
an incident and the retention of ICT system logs for 180 days within Indian jurisdiction. The Digital Personal
Data Protection Rules, notified 13 November 2025, require a detailed breach report within 72 hours, with
penalties to ₹200 crore for failure to notify.

**Evidence admissibility.** Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 conditions the admissibility of
electronic records on a certificate stating the record's hash value, and courts have been directed to treat an
unexplained hash variation between seizure and presentation as raising a strong presumption of tampering.

**Cryptographic inventory and the post-quantum transition.** The Department of Science and Technology's task
force under the National Quantum Mission published India's PQC migration roadmap in February 2026. Its first
milestone — *inventory cryptographic assets and assess quantum risk* — falls due in **2027** for critical
information infrastructure and 2028 for enterprises, with high-priority migration by 2028/2030, full adoption
by 2029/2033, and **Cryptographic Bills of Materials required from vendors from FY 2027–28**. MeitY, CERT-In
and SISA set the same direction in a July 2025 whitepaper. The UK's NCSC places cryptographic discovery,
dependency mapping and migration planning at 2028. NIST IR 8547 deprecates RSA-2048 and P-256 after 2030 and
disallows them after 2035. Every roadmap begins with discovery; for email infrastructure no discovery tool
exists.

Market sizing, which should be read as vendor research rather than peer-reviewed measurement, puts the India
email security market at $0.427 billion in 2025 rising to $1.31 billion by 2035 (11.82% CAGR), and the
post-quantum cryptography market at $810 million in 2025 rising to $18.19 billion by 2035. The relevant
distribution channel already exists: CERT-In had empanelled 231 cybersecurity audit organisations by the end of
2025.

---

# 2. Literature Review and Related Work

Seven papers are reviewed in depth in `docs/07_RELATED_WORK.md`. This section situates the contribution against
the fourteen studies that bear on it directly.

## 2.1 Measurement of email transport security

**Durumeric et al. (IMC 2015)** is the canonical study. Combining a snapshot of SMTP configuration for the
Alexa top million with over a year of Gmail connection logs, it established the global adoption rates of
STARTTLS, SPF, DKIM and DMARC, and — uniquely — presented evidence of attacks in the wild rather than only of
weak configuration. Its two attack findings are the intellectual basis of our attack-evidence detectors:
STARTTLS capability stripping, where a network device rewrites the server's EHLO response so that the
capability is no longer advertised (the dominant observed style being a same-length substitution consistent
with a commercial appliance's documented behaviour), and DNS-based MX hijacking, with 14,600 publicly
accessible resolvers in 521 autonomous systems returning fraudulent MX records for major providers.

**Mayer et al. (ARES 2016)** provides the certificate and cipher baseline: full-IPv4 coverage of SMTP, POP3 and
IMAP including legacy ports, 2,115,228 unique leaf certificates analysed, and the observation that securing
server-to-server mail is inherently harder than securing client-to-server mail. That asymmetry is the empirical
justification for role-aware severity.

**Holz et al. (NDSS 2016)** remains the broadest study of TLS across SMTP, IMAP, POP3, XMPP and IRC, and is the
only one in this set to combine active scanning with passive monitoring — pairing what servers offer with what
clients actually do. It is the closest methodological antecedent to our work, and the difference is instructive:
it monitored passively at a research vantage point to characterise an ecosystem, not to serve the operator of a
specific estate.

**Foster et al. (ACM CCS 2015)** examined provider-based email security end to end, evaluating whether each
provider supports TLS at each hop and SPF and DKIM on inbound and outbound mail — establishing that security
properties of a mail path are compositional and that a single weak hop determines the outcome.

## 2.2 STARTTLS as a vulnerability class

**Poddebniak et al. (USENIX Security 2021)** is the most important paper for this project. It systematises
STARTTLS flaws into distinct attack classes — negotiation, buffering, tampering and session — and introduces
EAST, a semi-automatic toolkit of more than 100 test cases. Beyond the headline counts, two findings shape our
design. First, the paper states the role asymmetry explicitly: the security implications for submission and
retrieval are more critical than for transport *because those connections carry user credentials granting
access to a mailbox archive, not merely individual messages*. Our severity policy is an implementation of that
sentence. Second, a ten-year-old command injection permitting plaintext insertion remained unfixed in multiple
servers, and eight new instances were discovered of a bug class that had already received several CVEs —
evidence that this is a persistent implementation hazard rather than a solved problem.

## 2.3 Certificate validation and the X.509 ecosystem

**Georgiev et al. (ACM CCS 2012)** showed that SSL certificate validation is broken across a wide range of
non-browser software, and attributed the root cause not to exotic bugs but to badly designed library APIs
presenting developers with confusing arrays of options. **Brubaker et al. (IEEE S&P 2014)** extended this by
differential testing with synthesised "frankencerts", uncovering further discrepancies among mainstream
implementations. Two consequences follow for us: mail software is precisely the class of non-browser software
these papers describe, which is why certificate findings in mail deserve first-class treatment; and a
purpose-built parser that allocates nothing, links no native code, and is exercised against certificates
generated for the purpose is a defensible engineering choice for code that will be pointed at a hostile
certificate.

## 2.4 Authenticated transport: MTA-STS, DANE and TLS reporting

**Ashiq, Fiebig & Chung (IMC 2025)** is the current reference on MTA-STS: 31 months of DNS scans covering over
87 million domains across four TLDs, with ten further months of component scanning. Adoption rose three- to
four-fold over the study period and remains at 52,641 `.com` domains (0.07%) and 7,192 `.org` domains (0.12%).
Of the 68,000 domains publishing a record in the latest snapshot, 29.6% were incorrectly configured and 3.2%
misconfigured badly enough that a compliant sender would fail to deliver. The authors also surveyed 117 email
operators: 94.7% were aware of MTA-STS, while 48.8% cited operational complexity as the reason for not
deploying it, 45.4% preferred DANE, and 26.8% reported difficulty managing policy updates.

**Lee et al. (USENIX Security 2022)** performs the equivalent analysis for DANE in SMTP across more than a
million domains with TLSA records: over 30% of TLSA records could not be validated owing to a broken DNSSEC
chain, 3.6% did not match the corresponding certificate, and more than 87% of SMTP servers performed key
rollovers incorrectly. The authors attribute this directly to the absence of automated tooling for key
management.

Taken together these two papers make an unusual argument in our favour: the standards that would close the
opportunistic-encryption gap exist, operators know about them, and the binding constraint is tooling.

## 2.5 Machine learning on encrypted traffic

**Sommer & Paxson (IEEE S&P 2010)** is the governing methodological reference. Its argument is that intrusion
detection differs from other machine-learning applications in ways that defeat naive application: the base-rate
problem means that where benign traffic dominates, even a small false-positive rate yields an unusable alert
volume; the semantic gap means an alert an operator cannot trace to a cause is an alert they will not act on;
and adversarial adaptation and distribution shift undermine closed-world assumptions. Our architecture is a
direct response — cryptographic facts are produced deterministically, learning is confined to ranking and
anomaly scoring, and every output is traceable to bytes.

**Anderson, Paul & McGrew (2018)** established that TLS metadata alone, without decryption, is sufficient to
distinguish malicious from enterprise traffic across millions of flows and to attribute malware family from a
single encrypted flow across 18 families. **Jafari Siavoshani et al. (Soft Computing 2023)** applied
interpretability methods to TLS fingerprinting and identified which handshake fields carry the discriminative
signal; our 51-field feature vector is shaped by that result. **Singh, Kashyap & Cherukuri (2025)** combined
XGBoost, Random Forest and Isolation Forest with SHAP attribution across CIC-Darknet2020, USTC-TFC2016 and
CSE-CIC-IDS2018, reporting 99.94% accuracy for XGBoost (90.9% precision, 88.2% recall, 93.0% F1) against 97.92%
for Random Forest, and argued that post-hoc interpretability is a compliance requirement rather than a
convenience. **INTACT (2026)** reframes cryptographic violation detection as a policy-constraint problem —
modelling the probability of violation conditioned on both observed behaviour and *declared security intent*,
covering key reuse, downgrade prevention and bounded key lifetimes — and reports AUROC up to 1.0000 on a real
flow dataset alongside a 210,000-trace synthetic multi-intent corpus. That framing is the closest published
analogue to our rule-plus-role-policy engine.

## 2.6 Post-quantum readiness

**Loizou & Ghadafi (2026)** is the single most relevant recent measurement for this project because it is the
only study to measure HTTPS and SMTP STARTTLS endpoints for the same organisations. Across 4,665 UK
organisations in ten sectors, 44.0% of reachable HTTPS services supported at least one evaluated post-quantum
key-exchange group against **6.4% of SMTP services** — a matched odds ratio of 16.89 — with only 144
organisations supporting PQC across both web and email, and no post-quantum certificate signatures observed
anywhere. The authors further find that infrastructure-provider identity predicts deployment better than
organisational sector, and caution that observable deployment should not be read as organisational readiness.

Complementary studies agree on the shape: arXiv 2606.16473 finds 49.3% of 32,011 domains supporting hybrid
post-quantum key exchange with 0% adoption of post-quantum certificates and 15.7% still on TLS 1.2, notably in
banking and government; and arXiv 2607.29005, analysing more than two billion handshakes across a million
domains from eleven vantage points, finds adoption concentrated in a single hybrid construction
(X25519MLKEM768), driven overwhelmingly by managed infrastructure providers, with owner-managed and
government-operated domains still defaulting to classical cryptography.

## 2.7 Notification and remediation effectiveness

**Li et al. (USENIX Security 2016)** ran a randomised experiment notifying thousands of operators of
vulnerabilities in their networks and tracking remediation over several weeks. Notifications containing
remediation steps were 56.5% more effective than terse notifications after two days for the IPv6 condition and
55.5% for the industrial-control condition — although the authors note that these differences are not
statistically significant after Bonferroni correction, and that fewer than 40% of operators who read the
detailed material fixed anything. Prior work they cite found notified operators patching at a rate almost 50%
greater than controls. The honest reading, which we adopt, is that actionable specificity helps materially but
that most findings still go unremediated, which is an argument for prioritisation as much as for clarity.

## 2.8 Gaps in current research

Three gaps follow from the above, and the contribution of this work is to close them.

**Gap 1 — the operator's own traffic is unexamined.** Every large-scale study of email transport security
measures the ecosystem from the outside: Durumeric and Mayer by scanning the address space, Ashiq and Lee by
scanning DNS, Loizou by probing endpoints, Foster by sending and receiving test mail. Holz alone monitored
passively, at a single research vantage point, to characterise the ecosystem. The question an operator or an
incident responder actually has — *what happened on my network, and was it tampered with* — has no
corresponding instrument. Active scanners cannot answer it in principle, because the evidence is historical.

**Gap 2 — severity models are protocol-agnostic where the threat model is not.** The literature is explicit
that the security requirements of relay, submission and access differ, and that the difference is about whether
credentials cross the link. No assessment tool encodes this. The consequence is predicted by Sommer & Paxson:
alarm volumes that operators learn to ignore.

**Gap 3 — the post-quantum discovery problem excludes mail.** Regulatory roadmaps in India, the UK and the US
begin with cryptographic inventory. The measurement literature shows mail is where the migration has least
progressed. Commercial discovery tooling — IBM Quantum Safe Explorer, SandboxAQ AQtive Guard, Keyfactor
AgileSec — operates on source code, container images or host agents. None derives an inventory from observed
mail traffic.

---

# 3. Technical Architecture and Design

## 3.1 Design principles

Eighteen architecture decision records are maintained in `docs/04_DECISIONS.md`. Five principles govern the
design.

1. **The schema is the contract.** The `schema/` package has zero dependencies and generates both JSON Schema
   and TypeScript definitions (ADR-0009). Six people working in parallel across twelve stages requires one
   authoritative data model; a change to a field changes the architecture document in the same commit.
2. **Evidence is designed in, not added later.** Every finding carries its provenance from the moment it is
   created (ADR-0004). Byte-to-frame mapping must be preserved through reassembly, which is cheap to do at
   the point of reassembly and impractical to reconstruct afterwards.
3. **Facts are deterministic.** A cryptographic property is parsed, not predicted. Machine learning is confined
   to prioritisation and anomaly scoring, for the reasons Sommer & Paxson set out.
4. **Absence of evidence is reported as such.** A host whose handshake could not be parsed is graded `?`
   (ADR-0014). No verdict is upgraded to a pass by default.
5. **No compiled dependencies.** Forced by the development environment, retained because it is the correct
   property for the deployment target. The tool must install where there is no package manager and no network.

## 3.2 The twelve-stage pipeline

| Stage | Name | Function |
|---|---|---|
| S0 | Ingest | Read PCAP/PCAPNG, compute capture SHA-256, index frames |
| S1 | TCP reassembly | Rebuild bidirectional streams with a byte-to-frame provenance map |
| S2 | Protocol identification | Identify SMTP/IMAP/POP3 from banner and command grammar; assign port role |
| S3 | STARTTLS state machine | Ten checks over the plaintext negotiation phase |
| S4 | TLS handshake | Parse records and handshake messages; JA3/JA3S; key-exchange groups including post-quantum |
| S5 | X.509 | Parse DER certificates, build chains, verify RSA signatures, validate names and dates |
| S6 | Rule evaluation | 34 rules across ten categories, each with standards citation and remediation |
| S7 | Feature extraction | 51 fields per session |
| S8 | AI layer | Risk classification, anomaly detection against a fleet baseline, priority ordering |
| S9 | Aggregation | Per-category, per-host and fleet scores and grades; capping rules |
| S10 | Reporting | JSON, self-contained HTML dashboard, PDF |

## 3.3 Component layers

| Package | Stages | Responsibility |
|---|---|---|
| `schema/` | — | The data contract; zero dependencies; generates JSON Schema and TypeScript |
| `securemailscope/capture/` | S0–S1 | PCAP ingest and the TCP reassembler with provenance |
| `securemailscope/proto/` | S2–S3 | Protocol identification, STARTTLS state machine, credential recovery |
| `securemailscope/tls/` | S4 | TLS record and handshake parser, fingerprints, post-quantum group detection |
| `securemailscope/certs/` | S5 | DER/X.509 parser and RSA signature verification |
| `securemailscope/rules/` | S6 | Rule pack, standards catalogue, role-aware severity policy |
| `securemailscope/features/` | S7 | The 51-field feature vector |
| `securemailscope/ml/` | S8 | Classifier, anomaly detector, priority model, corpus generator, training |
| `securemailscope/report/` | S10 | JSON, HTML and PDF emitters from a single `Report` object |
| `testbed/` | — | `synth.py` writes PCAPs byte by byte; `certgen.py` issues signed certificates |

## 3.4 Data model

The report object is a closed hierarchy: a `capture` record (path, SHA-256, frame count, time bounds); a list
of `sessions`, each with protocol, port, port role, TLS mode, handshake detail, certificate chain, feature
vector and findings; a list of `hosts` with per-category scores and a grade; a `fleet` rollup; a
`prioritised_findings` queue; an `executive_summary`; and an `evaluation_metrics` block reserved for measured
accuracy.

Enumerations are fixed and small, which is what makes the contract enforceable: ten finding categories
(`protocol`, `cipher`, `key_exchange`, `certificate`, `certificate_strength`, `configuration`, `starttls`,
`attack_evidence`, `post_quantum`, `compliance`); four port roles (`mta_relay`, `submission`, `mail_access`,
`unknown`); five severities (`info`, `low`, `medium`, `high`, `critical`); and eight grades (`A+`, `A`, `B`,
`C`, `D`, `E`, `F`, `?`).

## 3.5 The evidence model

An `Evidence` record accompanies every finding and holds the capture SHA-256, the stream index, the frame
numbers involved, the byte offsets within the reassembled stream, and a human-readable note. This is what makes
a finding checkable: the report states a claim, and the claim names the bytes that support it. Section 9.3
discusses the legal consequences.

---

# 4. Testing and Validation Methodology

## 4.1 The test suite

168 tests pass, organised into six modules — `contract`, `ml`, `parsing`, `tls`, `certs`, `report` — and run
without pytest so that testing does not itself introduce a dependency:

```
for t in contract ml parsing tls certs report; do python tests/test_$t.py; done
```

Coverage is structured by risk. The `contract` tests assert that the schema round-trips and that JSON Schema
generation matches the dataclasses. The `certs` tests verify RSA signature validation against certificates
generated by `testbed/certgen.py`, including deliberately invalid chains. The `parsing` and `tls` tests exercise
truncated records, malformed lengths and incomplete handshakes — the paths a hostile input would take. The
`report` tests assert that HTML output contains no external references and that injected markup never reaches
the document body.

## 4.2 The synthetic corpus and ground truth

`testbed/synth.py` writes PCAP files byte by byte rather than capturing traffic, which is what makes ground
truth possible: the generator knows exactly which weaknesses it encoded. `testbed/certgen.py` issues genuinely
signed certificates from a generated CA, including expired, self-signed, weak-key and mismatched-name variants.
`testbed/manifest.json` declares the expected findings for each of 18 captures.

This is a deliberate response to a gap. No public corpus exists of mail sessions labelled with cryptographic
weaknesses. The intrusion-detection corpora that exist — CIC-IDS2017 and CSE-CIC-IDS2018, UNSW-NB15, the
Stratosphere and CTU malware captures — are built for attack classification; several, including MAWI, contain
packet headers only and therefore cannot exercise a certificate parser at all.

## 4.3 Evaluation methodology

The evaluation design is a per-rule comparison between declared and produced findings across the corpus,
yielding precision, recall and F1 per rule and in aggregate, with a fourth outcome class for cases where a rule
could not fire because the required evidence was encrypted. Those are counted as *insufficient evidence*, not
as misses, because counting them as misses would penalise the system for being honest about TLS 1.3.

**Status, stated plainly: `scripts/evaluate.py` is currently a stub that raises `NotImplementedError`.** The
manifest declares expected findings and the pipeline produces actual findings, so the remaining work is the
comparison loop. Until it is run, this paper reports no accuracy figures, and the claim that the system's
precision and recall are known is not made. Section 16.1 lists this as the first item of future work for that
reason.

When the numbers exist they must be reported with their scope: a synthetic corpus measures *implementation
correctness against declared intent*, not field accuracy. Field accuracy would require labelled real-world
captures, which do not publicly exist.

## 4.4 Independent cross-validation

Because our TLS and X.509 parsers are our own, a second opinion is necessary. The intended method is to run
`tshark` over the same capture and compare the extracted protocol version, cipher suite, certificate subject,
issuer, validity dates and public-key parameters field by field. Disagreement indicates a parser defect in one
implementation or the other; agreement across an 18-capture corpus is meaningful evidence that the parse is
correct. This is stronger than self-consistency testing and weaker than formal verification, which is the
correct level of assurance for the claim being made.

## 4.5 Deliverable verification

`scripts/audit.py` mechanically verifies every deliverable and objective and regenerates `docs/06_STATUS.md`.
It is run before and after every change, and it has already caught a regression that manual review missed: the
role-aware severity side-by-side panel silently stopped producing output when the corpus moved from synthetic
to genuinely signed certificates.

---

# 5. User Flows and System Interactions

## 5.1 The analyst flow

1. A capture is obtained from existing infrastructure — a SPAN port, a tap, or an archived capture retained
   under the CERT-In 180-day requirement. CyberKavach does not capture traffic itself; separating collection
   from analysis is what allows it to run on a machine that is not on the monitored network.
2. One command: `python scripts/analyse.py capture.pcap --out out/ --trust ca.der`.
3. The analyst opens `out/report.html` — a single self-contained file — and reads the fleet grade, the
   executive summary, and the prioritised triage queue.
4. Any finding expands to show its evidence: capture hash, stream, frames, byte offsets, the standards clause,
   and the remediation.

## 5.2 The administrator flow

The administrator view groups findings by *fix* rather than by finding, because one configuration change
frequently resolves several findings across several hosts. Each group carries the configuration lines for the
relevant server software and the clause that justifies the change. The design rationale is empirical:
remediation tracks how specific and actionable a notice is, and most findings otherwise go unremediated.

## 5.3 The auditor flow

The auditor view is a compliance report card mapping observed posture to the clauses of NIST SP 800-52 Rev 2
and the relevant RFCs, plus an evidence pack. Each row states whether the control was OBSERVED, NOT_FOUND,
UNKNOWN or INSUFFICIENT_EVIDENCE, which is what distinguishes an audit artefact from a scanner's opinion.

## 5.4 The incident responder flow

The responder view is a timeline: sessions ordered by time, with attack-evidence findings marked, recovered
plaintext credentials shown as proof of exposure (redacted by default), and per-session handshake detail. The
question this view answers is whether interference occurred, when, and against which hosts.

---

# 6. Innovation and Technical Features

## 6.1 Role-aware severity

Every session is assigned a `port_role` at S2. The severity engine then applies a documented adjustment to the
base severity a rule emitted, keyed on the pair `(finding category, port role)`, and writes the reasoning into
the finding itself — for example, *"downgraded from HIGH to INFO: port 25 MTA relay, opportunistic TLS per RFC
7435."*

| Role | Ports | TLS expectation | Certificate validation failure |
|---|---|---|---|
| `mta_relay` | 25 | Opportunistic (RFC 7435) | Informational |
| `submission` | 587 (STARTTLS), 465 (implicit) | Mandatory (RFC 8314, RFC 4954) | Critical |
| `mail_access` | 143, 993, 110, 995 | Mandatory (RFC 8314) | Critical |

The justification is not stylistic. Poddebniak et al. state that submission and retrieval are more critical
because they carry credentials granting mailbox access. Mayer et al. reach the same asymmetry from measurement,
observing that server-to-server security is inherently harder and that SMTP does not validate certificates by
default — hence 65% self-signed. And Sommer & Paxson explain the cost of ignoring it: with benign traffic
dominating, a protocol-agnostic severity model produces an alert stream operators stop reading.

## 6.2 Attack evidence

Five detectors report that an attack has occurred rather than that one is possible. All five operate on
plaintext portions of the session and require no decryption.

1. **STARTTLS capability stripping** — the advertised capability set is compared against the negotiation that
   follows, including the same-length substitution pattern documented in the wild.
2. **Cleartext credentials** — AUTH exchanges recovered from sessions that were never upgraded, reported as
   proof of exposure and redacted by default.
3. **The RFC 8446 downgrade sentinel** — the specified ServerHello random suffix that signals a version
   downgrade.
4. **Cipher-intersection anomaly** — the server selected a suite weaker than the strongest both parties
   offered, which requires both halves of the handshake to detect and is therefore invisible to an active
   scanner.
5. **Certificate substitution** — the same host presenting different certificates across sessions in one
   capture.

`attack_evidence` is one of the ten scored categories, not an annotation.

## 6.3 Evidence-linked findings

Every finding carries the capture SHA-256, stream index, frame numbers and byte offsets. This addresses the
semantic gap identified by Sommer & Paxson — the reason operators discard alerts they cannot trace — and it has
a second consequence discussed in §9.3: it is the form in which section 63 of the Bharatiya Sakshya Adhiniyam,
2023 expects electronic evidence to be presented.

## 6.4 Reporting what could not be observed

TLS 1.3 encrypts the Certificate message. A tool that reports "no certificate found" in that situation is
reporting a parsing limitation as a security fact. CyberKavach reports `OPAQUE_TLS13` with the reason, continues
to assess what remains visible — negotiated version, key-exchange groups, server fingerprint, requested name —
and grades the host `?` rather than allowing it to reach A+ or A on the strength of checks that never ran. The
problem statement requires exactly this discipline; INTACT makes the research case for modelling uncertainty
explicitly rather than inferring absence.

## 6.5 Deployment without dependencies

One pure-Python runtime dependency (`dpkt`); everything else is the standard library. The TCP reassembler, the
TLS parser, the DER/X.509 parser with RSA signature verification and the PDF renderer are all written for this
project. There are no compiled extensions, no container requirement, no model download and no network calls at
any point. The practical consequence is that the tool installs by file copy on a machine with no internet and
no package manager, which is the environment the problem statement's originating organisation works in.

## 6.6 Standards mapping and remediation

Each of the 34 rules carries its standards citation and its remediation inline, authored at the same time as
the predicate. This produces the compliance report card and the per-finding configuration snippet without a
separate mapping exercise, and it makes the citation a first-class property of the rule rather than
documentation that can drift.

---

# 7. Technology Stack and Implementation

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.11 | Available on target systems; readable by a six-person team of mixed experience |
| Capture parsing | `dpkt` — the single runtime dependency | Pure Python, so it is not blocked by the compiled-extension restriction |
| Reassembly | Written for this project | Byte-to-frame provenance is not offered by existing libraries |
| TLS parsing | Written for this project | Record and handshake layer, JA3/JA3S, key-exchange groups including ML-KEM hybrids |
| X.509 | Written for this project | DER parser plus RSA PKCS#1 v1.5 signature verification (ADR-0017) |
| Rules | Declarative dataclasses | Predicate plus standards plus remediation in one object |
| Feature extraction | Standard library | 51 fields, no numerical dependency |
| Machine learning | XGBoost and Isolation Forest, trained off-box | The methods the problem statement names; the pipeline and corpus export are complete |
| Reporting | Single self-contained HTML file, JSON, PDF | No CDN, no fonts, no build step (ADR-0018); PDF degrades cleanly if the renderer is absent |
| Testing | Standard library, no pytest | Tests must not add a dependency |
| Documentation | Markdown in git | Ten documents, all versioned with the code |

Approximately 13,300 lines of Python; 168 tests passing.

---

# 8. Detailed Technical Implementation

## 8.1 TCP reassembly with provenance (S1)

Streams are rebuilt per direction with sequence-number ordering, retransmission and overlap handling, and a
provenance structure mapping every byte offset in the reassembled stream to the frame it came from. Findings
later cite offsets into this stream, and the provenance map converts those offsets into frame numbers an analyst
can open in Wireshark. Incomplete streams are retained and marked rather than discarded, because a truncated
capture is the normal case in forensic work.

## 8.2 Protocol identification (S2)

Identification is banner-led. The server's greeting and the subsequent command grammar determine whether a
stream is SMTP, IMAP or POP3; the port is recorded and used to assign a role, but is not trusted to identify
the protocol. Dreger et al. established the principle in 2006 and the reasoning has not changed: traffic on
non-standard ports is disproportionately interesting precisely because avoiding a standard port is itself a way
of evading inspection.

## 8.3 The STARTTLS state machine (S3)

Ten checks over the plaintext phase, structured around the published attack classes: whether the capability was
advertised; whether it was advertised and then not used; whether the advertised set is internally consistent
with the observed negotiation; whether EHLO was correctly re-issued after the upgrade (RFC 3207 §4.2); whether
plaintext AUTH was offered before TLS (RFC 4954); whether the capability line shows the same-length rewrite
signature; whether the server rejected the command; whether the session continued in plaintext after a failed
upgrade; whether credentials appeared before the upgrade; and whether the transition boundary is consistent
with the record layer that follows.

## 8.4 TLS handshake parsing (S4)

A record-layer parser feeds a handshake parser that extracts ClientHello and ServerHello, offered and selected
cipher suites, supported groups and key shares, extensions, ALPN, SNI, session resumption indicators and
alerts. JA3 and JA3S fingerprints are computed from the ordered field sets. Post-quantum readiness is
determined from the named groups — hybrid constructions such as X25519MLKEM768 — recorded separately for
*offered* and *negotiated*, because those are different facts with different meanings. Version downgrade is
detected both by comparing offered against negotiated and by testing for the RFC 8446 sentinel.

## 8.5 DER and X.509 (S5)

A DER reader with explicit length and tag validation, an X.509 structure decoder, chain construction against a
supplied trust anchor, and RSA PKCS#1 v1.5 signature verification implemented over Python integers. Validity
windows, self-signature, key size, signature hash algorithm, chain completeness and name matching are all
evaluated. Where the certificate is encrypted by TLS 1.3, the chain is recorded as `OPAQUE_TLS13` rather than
absent.

## 8.6 The rule engine and severity policy (S6)

Each rule is a frozen dataclass: identifier, title, category, base severity, predicate, description, standards
tuple, related attacks, remediation block and evidence note. Predicates are functions of a narrow
`RuleContext` — the feature vector plus host, port and role — and a rule that raises an exception is treated as
not firing, so a defect in one rule cannot abort a run.

The narrow context is a deliberate consequence of one decision worth highlighting (ADR-0003): because rules are
predicates over the feature vector rather than over parsed session objects, the *same* rule implementations run
over real sessions and over synthetic feature vectors. The labelling oracle used to generate machine-learning
training data therefore cannot drift from the shipping detector.

Severity is emitted as a base value by the rule and then adjusted by a policy table keyed on `(category,
role)`, with the adjustment and its justification recorded on the finding.

## 8.7 Feature extraction (S7)

51 fields per session, grouped as: protocol version and downgrade indicators (3); cipher properties (7); key
exchange and forward secrecy (5); post-quantum offered and negotiated (2); certificate properties (11); port
role (3); TLS mode (3); STARTTLS state (3); attack indicators (7); configuration flags (5); and fingerprint
rarity (2). The full list is in Appendix D.

## 8.8 The AI layer (S8)

Three functions over the feature vector. **Risk classification** produces a 0–100 score per session, with
XGBoost as the intended model and a rule-derived baseline in place until training completes. **Anomaly
detection** scores each session against a fleet baseline built from the capture, with Isolation Forest as the
intended model; the baseline is computed in two passes with outliers rejected before the second, because a
baseline built in one pass from a capture containing attacks allows the attacks to define normality — the same
concern that motivates robust covariance estimation. **Priority ordering** combines adjusted severity, risk
score, anomaly score and blast radius into the triage queue. Every score carries the features that drove it, in
the spirit of SHAP attribution, because a score an operator cannot interrogate is a score they will not trust.

## 8.9 Scoring and grading (S9)

Per-category scores aggregate to a host score and a host grade; host grades aggregate to a fleet score and
grade. Thresholds are 95 for A+, 85 for A, 75 for B and downwards. Two capping rules matter: a critical finding
caps the achievable grade regardless of the arithmetic, and any host with an incomplete handshake analysis that
would otherwise grade A+, A or B is reassigned `?`.

## 8.10 Reporting (S10)

One `Report` object emits all three formats, so they cannot disagree. The HTML is a single file with CSS,
script and data inlined — no CDN, no web fonts, no build step — and is also the interactive dashboard: posture
grade, executive summary, fleet table, filterable triage queue, per-session handshake detail, the STARTTLS
checks, the certificate chain, the risk waterfall, anomaly reasons, the feature vector, the compliance report
card, and a side-by-side panel that assembles itself from whichever rule produced opposite verdicts under
different port roles. Four persona views share one analysis, which a test enforces. Dark by default, with a
light theme and print rules so that Print to PDF produces the same document.

---

# 9. Feasibility Analysis

## 9.1 Technical feasibility

The system exists and runs end to end: approximately 13,300 lines, 168 passing tests, 34 rules, twelve stages,
one command, with 25 of 34 tracked deliverables mechanically verified. The unusual feasibility risk in a project
like this — that the hard parsing work turns out to be intractable within the timeframe — has already been
retired. What remains is additive.

Deployment feasibility is stronger than for any comparable design: a single pure-Python dependency means
installation is a file copy, with no package manager, no network access, no container runtime and no model
artefact required.

## 9.2 Economic feasibility

The engine and rule pack are open, because government adoption depends on source availability. Revenue sits
above it: a continuous sensor with a fleet view; an annual posture attestation that a CERT-In empanelled auditor
can sign; and a cryptographic-inventory subscription as the FY 2027–28 CBOM requirement takes effect.

Demand is documented rather than assumed, which is unusual and worth stating explicitly. Ashiq et al. surveyed
117 email operators: 94.7% were aware of MTA-STS and 48.8% named operational complexity as the reason they had
not deployed it. Lee et al. attribute 87% incorrect DANE key rollovers to the absence of automated tooling. The
constraint in this market is instrumentation, not awareness.

Comparable products in cryptographic discovery — IBM Quantum Safe Explorer, SandboxAQ AQtive Guard, Keyfactor
AgileSec (following its acquisition of InfoSec Global) — establish that enterprises pay for cryptographic
inventory. All of them derive it from source code, container images or host agents; none derives it from
observed mail traffic.

## 9.3 Regulatory and legal feasibility

**Compliance mapping.** Findings cite NIST SP 800-52 Rev 2, NIST SP 800-45 Rev 2 and RFCs 7435, 8314, 8461,
7672, 8460, 8996, 9325 and 8446. SEBI's Cybersecurity and Cyber Resilience Framework (August 2024) requires TLS
1.2 or better for data in transit across regulated entities; CERT-In's June 2023 guidelines for government
entities require encrypted connections to mail servers and the deployment of SPF, DKIM and DMARC. This tool
produces the evidence those requirements presuppose.

**Evidence admissibility.** Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 conditions admissibility of an
electronic record on a certificate that states the record's hash value, signed by the person in charge of the
device and by an expert. Courts have been directed to treat an unexplained variation in hash value between
seizure and presentation as raising a strong presumption of tampering. Because CyberKavach computes and reports
the capture's SHA-256 and anchors every finding to frames and byte offsets within that capture, its output maps
directly onto what the provision requires. Appendix C of the implementation plan includes generating that
certificate as a report annexe.

**Privacy and lawfulness of capture.** The tool operates only on captures the operator is authorised to hold,
performs no decryption, copies no message content, redacts recovered credentials by default and makes no network
calls. Under the DPDP Rules notified 13 November 2025, a data fiduciary must file a detailed breach report
within 72 hours; a forensic tool that never copies message content is materially easier to clear for use than
one that does.

## 9.4 Operational feasibility

The tool consumes a file format every existing capture infrastructure already produces and emits JSON that an
existing SIEM can ingest. It installs no agents and requires no change to mail servers. The operational burden
is therefore the capture policy, which in Indian regulated entities already exists by mandate.

---

# 10. Challenges and Solutions

## 10.1 Technical challenges

**TLS 1.3 conceals the certificate.** Approximately the single most common objection. The response is not to
guess: report `OPAQUE_TLS13` with the reason, assess the substantial information that remains visible in the
handshake, and grade the host `?`. This converts a blind spot into a reported fact.

**The environment blocks the numerical toolchain.** Windows Smart App Control on the development machines
blocks compiled extensions, which has so far prevented `numpy` (and therefore scikit-learn), `cryptography`,
Pillow, OpenSSL and git's networking library from loading. The consequences were absorbed rather than worked
around: we wrote the DER/X.509 parser and the certificate generator ourselves, and the classifier trains off-box
with the feature pipeline and CSV export complete. A secondary lesson worth recording is that `import
cryptography` succeeds while `from cryptography import x509` fails, so the actual call path must be tested, not
the import.

**A baseline built from an attacked capture treats attacks as normal.** Two-pass construction with outlier
rejection before the second pass, following the logic of robust covariance estimation.

**No public ground truth.** Solved by construction: a byte-level PCAP generator, a real certificate authority,
and a manifest of expected findings; validated externally by comparing the parse against `tshark`.

**Certificate parsers are a classic source of defects.** Mitigated by writing the parser in pure Python with no
memory management, testing it against deliberately malformed inputs, and cross-validating against an
independent implementation. The literature is on our side here in an unexpected way: Georgiev et al. and
Brubaker et al. found that the mainstream libraries' own APIs are the dominant source of validation failures.

## 10.2 Operational challenges

**Alert fatigue.** The failure mode of every security tool. Addressed by role-aware severity, prioritisation
and the explicit decision to report low-consequence findings as informational rather than suppressing or
inflating them.

**Findings that nobody acts on.** Li et al. measured this directly: even among operators who read detailed
remediation material, fewer than 40% fixed the problem. The response is to make the fix as close to
copy-and-paste as possible and to order the queue so that the first three items are the ones that matter.

**Capture coverage.** A capture taken at the wrong point sees the wrong thing. Documented as a deployment
requirement, with the threat model stating explicitly what a given vantage point can and cannot establish.

**Six contributors on a four-day build.** Managed by treating the schema as a frozen contract with generated
fixtures, so that stages could be developed against the contract rather than against each other, and by
running `scripts/audit.py` before and after every change.

---

# 11. Impact Assessment and Benefits

## 11.1 Capability impact

The primary impact is the existence of a capability that currently has no instrument: assessing the
cryptographic posture of an email estate from evidence rather than from access. Three consequences follow.

- **Incident response within the statutory window.** CERT-In requires reporting within six hours; the log and
  capture material is already retained for 180 days by mandate. A one-command analysis that produces a graded,
  evidence-linked report converts existing raw material into a filing.
- **Assessment of estates that cannot be probed.** Active scanning requires reachability and authorisation. A
  capture requires neither, which is what makes assessment of third-party, partner and legacy infrastructure
  possible at all.
- **Cryptographic inventory ahead of a deadline.** India's roadmap requires critical infrastructure to inventory
  cryptographic assets by 2027 and vendors to supply CBOMs from FY 2027–28. For mail, the measured baseline is
  6.4% post-quantum readiness against 44.0% for the web, and no post-quantum certificates anywhere.

## 11.2 Stakeholder benefits

**Government and regulators.** Evidence-grade posture reporting for the NIC-operated government mail estate,
whose single-operator structure means one deployment covers it; sectoral assessment for NCIIPC; a defensible
basis for CERT-In filings; and progress measurement against the PQC roadmap.

**Mail administrators.** Configuration changes rather than findings, grouped by fix, with the clause that
justifies each one.

**Auditors.** A compliance report card with explicit OBSERVED / NOT_FOUND / UNKNOWN / INSUFFICIENT_EVIDENCE
verdicts and an evidence pack that satisfies section 63.

**Incident responders.** Five attack detectors, a timeline, and recovered credentials as proof of exposure
rather than an inference of it.

**Citizens.** Email carries password resets, financial instructions and legal notices for several hundred
million Indians, and users have no way to know whether a message crossed the network protected — a point Mayer
et al. make explicitly in observing that users are left in the dark about whether their mail travels in
plaintext.

## 11.3 Economic impact

Business email compromise accounted for $3.046 billion of reported losses in 2025 across 24,768 complaints. Of
the 29.44 lakh incidents CERT-In handled in 2025, 3,41,646 were vulnerable exposed services. A tool that reduces
the time from capture to actionable finding acts on both numbers, though we make no claim about the size of the
reduction until it is measured.

Two market figures frame the commercial opportunity, and should be presented as vendor research: India's email
security market at $0.427 billion in 2025 rising to $1.31 billion by 2035, and the post-quantum cryptography
market at $810 million rising to $18.19 billion over the same period.

## 11.4 Alignment with the Sustainable Development Goals

**SDG 9 — industry, innovation and infrastructure.** The ITU situates the strengthening of cybersecurity within
Goal 9, and target 9.c's commitment to universal ICT access presupposes that the infrastructure beneath it can
be trusted. Email transport is a component of that infrastructure that is currently unmeasured at the level of
the individual operator.

**SDG 16 — peace, justice and strong institutions.** Target 16.6, effective and accountable institutions, is
served directly by evidence-linked findings: accountability requires verifiable claims. Target 16.4, the
reduction of illicit financial flows, is served because business email compromise — $3.046 billion in a single
year in reported US losses alone — is precisely such a flow.

A third, weaker alignment exists with target 8.2, productivity through technological upgrading. We claim two
goals rather than six because the additional claims would be decorative.

---

# 12. Sustainability and Long-Term Viability

## 12.1 Technical sustainability

The dependency surface is one pure-Python library, which is the strongest available guarantee against
bit-rot: there is no compiled ABI to break, no model artefact to expire, and no external service to be
deprecated. The rule pack is data rather than control flow, so keeping pace with standards means editing
declarative objects, and the standards citation attached to each rule makes it auditable which revision a rule
implements.

**Crypto-agility is the central long-term design concern**, and it is also the product. Between now and 2035 the
cryptographic landscape changes twice: hybrid post-quantum key exchange becomes the default, and post-quantum
certificates begin to appear, currently at zero adoption. A tool whose job is to report which algorithms are in
use must be able to name algorithms that do not yet exist in deployments. Because group and algorithm
identifiers are parsed and reported rather than matched against a closed list, unknown identifiers are surfaced
as unrecognised rather than silently dropped.

## 12.2 Environmental footprint

Modest and worth one sentence rather than a section: analysis is single-pass over a file on one machine, with no
training at inference time, no cloud round trips and no always-on service. The comparison class — continuous
active scanning of an address space, or a hosted dashboard with a persistent backend — consumes considerably
more.

## 12.3 Institutional and financial sustainability

An open engine with paid operational tooling above it is the model that has worked for comparable
security instrumentation, and it is compatible with government procurement, which requires source
availability. The CERT-In empanelment structure — 231 audit organisations — provides a distribution route that
does not require building a direct sales operation. The 2027 and FY 2027–28 regulatory milestones provide a
demand event with a date attached, which is a more reliable basis for planning than a market forecast.

---

# 13. International Benchmarking and Best Practices

## 13.1 Comparison with existing tools

| Tool | What it does | Works from a capture | Works offline | Mail-aware severity | Attack evidence |
|---|---|---|---|---|---|
| SSL Labs | Grades a web TLS endpoint thoroughly | No | No | No | No |
| testssl.sh / sslyze | Enumerates endpoint capability | No | No | No | No |
| internet.nl mail test | Scores STARTTLS, DANE, SPF/DKIM/DMARC per domain; does not test MTA-STS | No | No | Partial | No |
| CheckTLS | Tests a mail domain's transport | No | No | No | No |
| Wireshark / tshark | Decodes packets | Yes | Yes | No | No |
| Zeek + JA4 | Logs TLS metadata at scale from capture or wire | Yes | Yes | No | No |
| IBM Quantum Safe / SandboxAQ / Keyfactor | Cryptographic inventory | No (source, container or agent) | Varies | No | No |
| **CyberKavach** | Graded posture assessment with evidence and remediation | **Yes** | **Yes** | **Yes** | **Yes** |

The pattern is consistent: tools that judge require access, and tools that work from captures decode without
judging. Zeek is the closest and the distinction is precise — it produces excellent logs and no assessment,
which is why it would be a sensible input to a large-scale deployment of this analysis rather than a competitor
to it.

## 13.2 International policy benchmarking

| Jurisdiction | Instrument | First required step | Date |
|---|---|---|---|
| India | DST / National Quantum Mission PQC roadmap (Feb 2026) | Inventory cryptographic assets, assess quantum risk | **2027** (CII) |
| India | CBOM requirement for vendors | Submit cryptographic bill of materials | **FY 2027–28** |
| United Kingdom | NCSC phased migration timeline | Cryptographic discovery, dependency mapping, migration planning | **2028** |
| United States | NIST IR 8547 | RSA-2048 / P-256 deprecated, then disallowed | **2030 / 2035** |
| European Union | Coordinated PQC transition recommendation | National roadmaps across member states | — |

Three jurisdictions independently place *discovery* first. The measurement literature independently finds mail
the least ready protocol. The intersection of those two facts is the strategic case for this work.

## 13.3 Where India is positioned

MTA-STS and DANE adoption is low everywhere — even the Netherlands, which has pushed hardest on mail security
standards through internet.nl, reported 14% DANE and 6% MTA-STS in September 2025. India's advantage is
structural rather than technical: because official government mail is centralised at NIC under the E-mail Policy
of the Government of India, a single operator decision propagates across the whole government estate. The
binding constraint is measurement, and that is what this tool supplies.

---

# 14. Implementation Roadmap

## 14.1 Completed (Days 1–3, 23–26 September 2026)

Schema frozen and contract generated; PCAP ingest and TCP reassembly with provenance; protocol identification
and the STARTTLS state machine; TLS record and handshake parsing with JA3/JA3S and post-quantum group
detection; DER/X.509 parsing with RSA signature verification; the 34-rule pack with standards and remediation on
every rule; role-aware severity; 51-field feature extraction; the AI layer on a rule-derived baseline; scoring
and aggregation; JSON, self-contained HTML dashboard and PDF reporting; the synthetic corpus and ground-truth
manifest; 168 tests; `scripts/audit.py`.

## 14.2 Immediate (before submission)

1. **`scripts/evaluate.py`** — the per-rule precision and recall loop. Highest priority; a claimed
   differentiator with no data behind it is worse than an unmade claim.
2. **Two-pass anomaly baseline** — approximately 40 lines, removes a known methodological defect.
3. **Human review of the dashboard's visual design**, which has been verified structurally but never looked at.
4. **`tshark` cross-validation** of the handshake parse across the corpus.

## 14.3 Phase 1 (Months 1–3): completeness against the problem statement

Domain-mode assessment — MTA-STS, DANE and TLSRPT lookups for a supplied domain, which the problem statement
accepts alongside a capture; the FastAPI service so a capture can be uploaded rather than passed on a command
line; the trained classifier; the evidence certificate annexe in the form section 63 expects.

## 14.4 Phase 2 (Months 4–9): operational deployment

Continuous sensor mode with a rolling baseline and drift detection; fleet aggregation across captures and over
time; SIEM integration through JSON; CBOM export in CycloneDX form; a pilot with a CERT-In empanelled auditor.

## 14.5 Phase 3 (Months 10–18): scale and institutionalisation

Deployment against a government estate in coordination with NIC; sector-level baselines for NCIIPC; longitudinal
posture measurement as the PQC migration proceeds; contribution of the rule pack and corpus as a public
benchmark, which the research community currently lacks.

---

# 15. Risk Management and Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Accuracy figures never produced | Medium | **High** — the central claim of §4.3 goes unsupported | `evaluate.py` is scoped and the inputs exist; treat as a submission blocker |
| A defect in our own TLS or X.509 parser | Medium | High | 168 tests including malformed inputs; `tshark` cross-validation; pure-Python parser with no memory management |
| Environment blocks a further dependency | Medium | Low | Standard-library-only policy already in force; test the call path, not the import |
| Trained model never materialises | Medium | Low | The deterministic engine carries the product; training is off-box and optional |
| Capture vantage point misleads the analysis | Medium | Medium | Explicit threat model stating what a vantage point can establish; `?` grading when evidence is insufficient |
| Findings dismissed as false alarms | Low | High | Role-aware severity, prioritisation, and a documented justification on every adjusted finding |
| Competing implementations of the same problem statement | High | Medium | Differentiate on role-aware severity, attack evidence, evidence linkage, honest unknowns and dependency-free deployment — not on dashboard polish |
| Legal challenge to a capture's provenance | Low | High | Capture hash, frame-level anchoring, section 63 alignment, no decryption, credentials redacted |
| Six contributors diverging on one branch | Medium | Medium | Frozen schema, branch per stage, `scripts/audit.py` must pass before merge |

---

# 16. Future Enhancements and Scalability

## 16.1 Immediate gaps in the current implementation

Stated plainly, because a research document that conceals its own gaps is not useful.

1. **`scripts/evaluate.py` is a stub.** No precision or recall figures exist. First priority.
2. **The anomaly baseline is single-pass** and therefore includes the attack sessions it should exclude.
3. **No trained model.** The corpus exporter produces CSV; training requires a working numerical toolchain.
4. **`securemailscope/api/` is a stub.** The command line is the only entry point.
5. **`securemailscope/llm/` is a stub.** The natural-language explanation layer is unbuilt.
6. **The dashboard's visual design has never been reviewed by a human**, only verified structurally.
7. **MTA-STS, DANE and TLSRPT assessment is unbuilt**, which matters because the problem statement accepts a
   domain name as input.

## 16.2 Highest-value additions

**Authenticated-transport assessment (MTA-STS, DANE, TLSRPT).** The research case is unusually strong: 0.07%
MTA-STS adoption with 29.6% of deployments broken, over 30% of DANE TLSA records unvalidatable, 87% of key
rollovers incorrect — and both papers attribute the failures to missing tooling. Combining capture-observed
behaviour with published policy allows a check no existing tool performs: *did this session actually honour the
policy this domain published?*

**Cryptographic Bill of Materials export.** A CycloneDX CBOM (ECMA-424) describing the algorithms, key sizes,
certificates and protocol versions observed across a mail estate. This is the only feature on this list with a
statutory deadline attached — FY 2027–28 — and the existing tools in that market derive inventory from code and
hosts rather than traffic, so the passive-network path is unoccupied.

**A trained and evaluated classifier.** XGBoost over the 51-field vector for risk, Isolation Forest for
anomalies, with SHAP attribution surfaced in the report. The comparison point is established: recent work
reports 99.94% accuracy for XGBoost on encrypted-traffic anomaly detection with SHAP explanations, which is the
bar for a credible claim.

**Post-quantum posture as a first-class report section.** Given a measured 6.4% readiness for mail against 44.0%
for the web, and zero post-quantum certificates anywhere, separating *key exchange is migrating* from
*certificates have not started* is a distinction the parser can already report and the roadmaps require.

**Session-level continuous monitoring.** A sensor maintaining a rolling baseline with drift detection, which
converts a point-in-time assessment into posture measurement over time — the form in which regulatory progress
against the 2027–2029 milestones must be demonstrated.

## 16.3 Research directions

**Passive detection of SMTP smuggling and related message-boundary attacks**, which are adjacent to our
STARTTLS analysis and have a recent literature of their own.

**Encrypted Client Hello.** As ECH deploys, the requested name leaves the clear portion of the handshake. Work
is needed on what can still be established, and — consistent with §6.4 — on reporting honestly what cannot.

**JA4+ fingerprints** alongside JA3/JA3S, which are more robust to the client-side randomisation that has
degraded JA3's discriminative power.

**A public benchmark corpus.** The absence of labelled mail captures with known cryptographic weaknesses is a
genuine obstacle to research in this area, and our generator plus manifest is a candidate contribution. This is
the most useful thing this project could give back.

**Per-rule false-positive characterisation on real traffic**, which requires labelled captures and is the
honest prerequisite for any claim about field accuracy.

---

# 17. Conclusion

Email transport security has been measured extensively and instrumented hardly at all. The literature
establishes that opportunistic encryption fails open by design, that authentication is largely absent in
practice, that the STARTTLS upgrade is a recurring vulnerability class, that downgrade attacks occur at
measurable scale, that the standards intended to fix all of this are deployed on a fraction of a percent of
domains and misconfigured in roughly a third of those, and that mail is the protocol furthest behind on the
post-quantum transition. What the literature does not provide — because its method is active scanning — is a way
for a specific operator to learn what happened to their own mail.

CyberKavach is that instrument. It grades an email estate from a packet capture alone, on an A+ to F scale with
`?` reserved for what it could not see; it ranks each weakness by the role of the port it was found on, which
the literature says is the correct discrimination and which no existing tool makes; it reports five classes of
evidence that an attack has already occurred; and it anchors every claim to a capture hash, frame number and
byte offset, which is both what makes a finding checkable and what Indian evidence law now expects. It is
implemented in approximately 13,300 lines of Python with one pure-Python dependency and 168 passing tests, so
that it runs on an air-gapped machine.

Two things are not yet true and are stated as such. The per-rule precision and recall the evaluation design
calls for have not been computed, because `scripts/evaluate.py` is a stub. And the classifier is untrained, so
the risk score currently derives from a rule-based baseline. Neither affects the deterministic findings, and
both are scoped work rather than open problems.

The strategic case is a coincidence of two independent findings. Three jurisdictions have now placed
cryptographic discovery as the first required step of the post-quantum transition, with India's critical
infrastructure deadline falling in 2027 and a vendor CBOM requirement in FY 2027–28. And the most recent
measurement of post-quantum readiness finds mail at 6.4% against 44.0% for the web, with no post-quantum
certificates in existence anywhere. Discovery is mandated, mail is furthest behind, and for mail there is no
discovery tool. That is the gap this work occupies.

---

# 18. References

## Peer-reviewed papers

1. Durumeric, Z., Adrian, D., Mirian, A., Kasten, J., Bursztein, E., Lidzborski, N., Thomas, K., Eranti, V.,
   Bailey, M., Halderman, J.A. "Neither Snow Nor Rain Nor MITM… An Empirical Analysis of Email Delivery
   Security." *Proc. ACM Internet Measurement Conference (IMC)*, 2015. https://doi.org/10.1145/2815675.2815695
2. Mayer, W., Zauner, A., Schmiedecker, M., Huber, M. "No Need for Black Chambers: Testing TLS in the E-mail
   Ecosystem at Large." *Proc. ARES*, 2016. https://arxiv.org/abs/1510.08646
3. Holz, R., Amann, J., Mehani, O., Wachs, M., Kaafar, M.A. "TLS in the Wild: An Internet-wide Analysis of
   TLS-based Protocols for Electronic Communication." *NDSS*, 2016. https://arxiv.org/abs/1511.00341
4. Foster, I.D., Larson, J., Masich, M., Snoeren, A.C., Savage, S., Levchenko, K. "Security by Any Other Name:
   On the Effectiveness of Provider Based Email Security." *Proc. ACM CCS*, 2015.
   https://klevchen.ece.illinois.edu/pubs/flmssl-ccs15.pdf
5. Poddebniak, D., Ising, F., Böck, H., Schinzel, S. "Why TLS is better without STARTTLS: A Security Analysis
   of STARTTLS in the Email Context." *30th USENIX Security Symposium*, 2021.
   https://www.usenix.org/system/files/sec21-poddebniak.pdf
6. Lee, H., Ashiq, M.I., Müller, M., van Rijswijk-Deij, R., Kwon, T., Chung, T. "Under the Hood of DANE
   Mismanagement in SMTP." *31st USENIX Security Symposium*, 2022.
   https://www.usenix.org/system/files/sec22-lee.pdf
7. Ashiq, M.I., Fiebig, T., Chung, T. "Unraveling the Complexities of MTA-STS Deployment and Management in
   Securing Email." *Proc. ACM IMC*, 2025. https://doi.org/10.1145/3730567.3732916
8. Georgiev, M., Iyengar, S., Jana, S., Anubhai, R., Boneh, D., Shmatikov, V. "The Most Dangerous Code in the
   World: Validating SSL Certificates in Non-Browser Software." *Proc. ACM CCS*, 2012.
   https://doi.org/10.1145/2382196.2382204
9. Brubaker, C., Jana, S., Ray, B., Khurshid, S., Shmatikov, V. "Using Frankencerts for Automated Adversarial
   Testing of Certificate Validation in SSL/TLS Implementations." *IEEE Symposium on Security and Privacy*,
   2014.
10. Sommer, R., Paxson, V. "Outside the Closed World: On Using Machine Learning for Network Intrusion
    Detection." *IEEE Symposium on Security and Privacy*, 2010.
11. Dreger, H., Feldmann, A., Mai, M., Paxson, V., Sommer, R. "Dynamic Application-Layer Protocol Analysis for
    Network Intrusion Detection." *15th USENIX Security Symposium*, 2006.
    https://www.usenix.org/legacy/events/sec06/tech/full_papers/dreger/dreger.pdf
12. Li, F., Durumeric, Z., Czyz, J., Karami, M., Bailey, M., McCoy, D., Savage, S., Paxson, V. "You've Got
    Vulnerability: Exploring Effective Vulnerability Notifications." *25th USENIX Security Symposium*, 2016.
    https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_li.pdf
13. Anderson, B., Paul, S., McGrew, D. "Deciphering malware's use of TLS (without decryption)." *Journal of
    Computer Virology and Hacking Techniques*, 2018. https://doi.org/10.1007/s11416-017-0306-6
14. Jafari Siavoshani, M., et al. "Machine learning interpretability meets TLS fingerprinting." *Soft
    Computing* 27(11), 2023, 7191–7208.
15. Chen, T., Guestrin, C. "XGBoost: A Scalable Tree Boosting System." *Proc. ACM KDD*, 2016.
16. Liu, F.T., Ting, K.M., Zhou, Z.-H. "Isolation Forest." *IEEE ICDM*, 2008.
17. Lundberg, S.M., Lee, S.-I. "A Unified Approach to Interpreting Model Predictions." *NeurIPS*, 2017.
18. Rousseeuw, P.J., Van Driessen, K. "A Fast Algorithm for the Minimum Covariance Determinant Estimator."
    *Technometrics* 41(3), 1999.

## Preprints

19. Loizou, K., Ghadafi, E. "Measuring Post-Quantum TLS Deployment Across UK Internet Sectors." arXiv
    2608.02147, August 2026. https://arxiv.org/abs/2608.02147
20. "Measurement Study of Post-Quantum Readiness of Internet: 2026." arXiv 2606.16473.
    https://arxiv.org/abs/2606.16473
21. "Mind the Gap: Policy vs Reality in Post-Quantum TLS Deployment." arXiv 2607.29005.
    https://arxiv.org/abs/2607.29005
22. Singh, K., Kashyap, A., Cherukuri, A.K. "Interpretable Anomaly Detection in Encrypted Traffic Using SHAP
    with Machine Learning Models." arXiv 2505.16261, May 2025. https://arxiv.org/abs/2505.16261
23. "INTACT: Intent-Aware Representation Learning for Cryptographic Traffic Violation Detection." arXiv
    2602.21252. https://arxiv.org/abs/2602.21252

## Standards and specifications

24. RFC 3207 — SMTP Service Extension for Secure SMTP over TLS.
25. RFC 4954 — SMTP Service Extension for Authentication.
26. RFC 5746 — TLS Renegotiation Indication Extension.
27. RFC 6176 — Prohibiting Secure Sockets Layer (SSL) Version 2.0.
28. RFC 7435 — Opportunistic Security: Some Protection Most of the Time.
29. RFC 7465 — Prohibiting RC4 Cipher Suites.
30. RFC 7672 — SMTP Security via Opportunistic DANE TLS.
31. RFC 8314 — Cleartext Considered Obsolete: Use of TLS for Email Submission and Access.
32. RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3.
33. RFC 8460 — SMTP TLS Reporting.
34. RFC 8461 — SMTP MTA Strict Transport Security (MTA-STS).
35. RFC 8996 — Deprecating TLS 1.0 and TLS 1.1.
36. RFC 9325 — Recommendations for Secure Use of TLS and DTLS.
37. NIST SP 800-52 Rev 2 — Guidelines for the Selection, Configuration and Use of TLS Implementations.
38. NIST SP 800-45 Ver 2 — Guidelines on Electronic Mail Security.
39. NIST IR 8547 — Transition to Post-Quantum Cryptography Standards.
    https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf
40. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM).
41. CycloneDX Cryptography Bill of Materials / ECMA-424. https://cyclonedx.org/capabilities/cbom/

## Indian policy and law

42. Information Technology Act, 2000, section 70B.
43. CERT-In Directions under section 70B(6), 28 April 2022 — six-hour incident reporting, 180-day log
    retention.
44. CERT-In, *Guidelines on Information Security Practices for Government Entities*, 30 June 2023.
    https://www.cert-in.org.in/PDF/guidelinesgovtentities.pdf
45. Ministry of Electronics and Information Technology, *E-mail Policy of the Government of India*.
    https://www.meity.gov.in/static/uploads/2024/02/E-mail_policy_of_Government_of_India_3-2.pdf
46. Digital Personal Data Protection Act, 2023.
47. Digital Personal Data Protection Rules, 2025, notified 13 November 2025.
    https://static.pib.gov.in/WriteReadData/specificdocs/documents/2025/nov/doc20251117695301.pdf
48. Bharatiya Sakshya Adhiniyam, 2023, section 63. https://indiankanoon.org/doc/125020475/
49. SEBI, *Cybersecurity and Cyber Resilience Framework (CSCRF) for SEBI Regulated Entities*, 20 August 2024.
50. MeitY / CERT-In / SISA, *Transitioning to Quantum Cyber Readiness*, July 2025.
51. Department of Science and Technology, National Quantum Mission task force, *India's Post-Quantum
    Cryptography Migration Roadmap*, February 2026. Summary:
    https://www.orfonline.org/expert-speak/india-s-post-quantum-cryptography-migration-roadmap
52. CERT-In, *Annual Report 2025*. https://www.cert-in.org.in/s2cMainServlet?pageid=PUBANULREPRT

## Reports and datasets

53. Federal Bureau of Investigation, Internet Crime Complaint Center, *2025 Internet Crime Report*.
    https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf
54. International Telecommunication Union, Goal 9 — Infrastructure, Industrialization, Innovation.
    https://www.itu.int/en/sustainable-world/Pages/goal9.aspx
55. Canadian Institute for Cybersecurity, CIC-IDS2017 intrusion detection evaluation dataset.
    https://www.unb.ca/cic/datasets/ids-2017.html
56. Suricata public PCAP dataset index. https://docs.suricata.io/en/latest/public-data-sets.html
57. Market Research Future, *India Email Security Market* (vendor research, cited for market sizing only).

---

# 19. Appendices

## Appendix A — Architecture diagrams

**A.1 High-level pipeline**

```
                  ┌─────────────────────────────────────────────────────────────┐
  capture.pcap ──▶│ S0 ingest        SHA-256, frame index                       │
                  │ S1 reassembly    streams + byte→frame provenance            │
                  │ S2 protocol ID   SMTP/IMAP/POP3 by banner; port role        │
                  │ S3 STARTTLS      ten checks over the plaintext phase        │
                  │ S4 TLS           records, handshake, JA3/JA3S, PQ groups    │
                  │ S5 X.509         DER parse, chain, RSA signature verify     │
                  │ S6 rules         34 rules × 10 categories + severity policy │
                  │ S7 features      51 fields per session                      │
                  │ S8 AI            risk · anomaly · priority                  │
                  │ S9 aggregate     category → host → fleet, grades A+…F, ?     │
                  │ S10 report       JSON · self-contained HTML · PDF           │
                  └─────────────────────────────────────────────────────────────┘
```

**A.2 Evidence flow** — Every finding references `(capture SHA-256, stream index, frame numbers, byte offsets)`.
The provenance map built at S1 is what makes the last two resolvable, and it is why S1 cannot be replaced with a
stock reassembler.

## Appendix B — Report structure (JSON)

Top-level keys: `schema_version`, `capture`, `sessions`, `hosts`, `fleet`, `prioritised_findings`,
`executive_summary`, `generated_at`, `evaluation_metrics`.

`fleet` carries `score`, `grade`, `host_count`, `session_count` and `category_scores`, where each category score
reports `category`, `score`, `finding_count` and `worst_severity`. JSON Schema and TypeScript definitions are
generated from the dataclasses by `python -m schema.jsonschema`, so the contract cannot drift from the code.

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

**Severity policy entries** are keyed on `(category, port role)` and currently cover: certificate findings on
relay, submission and access; configuration findings on relay; STARTTLS findings on submission and access; and
attack-evidence findings on submission and access.

## Appendix D — The 51-field feature vector

| Group | Fields |
|---|---|
| Protocol version (3) | `tls_version_num`, `is_deprecated_version`, `version_downgrade_from_offered` |
| Cipher (7) | `cipher_strength_bits`, `cipher_is_aead`, `cipher_is_cbc`, `cipher_is_rc4`, `cipher_is_3des`, `cipher_is_null_or_anon`, `cipher_is_export` |
| Key exchange (5) | `kex_is_ephemeral`, `kex_is_anon`, `kex_group_bits`, `has_forward_secrecy`, (with PQ below) |
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

## Appendix E — Evaluation protocol

**Corpus.** 18 captures generated by `testbed/synth.py` against certificates from `testbed/certgen.py`, with
expected findings declared per capture in `testbed/manifest.json`.

**Procedure.** For each capture, run the pipeline and compare produced findings against declared findings by
rule identifier. Classify each as true positive, false positive, false negative, or *insufficient evidence*
where the rule could not fire because the required material was encrypted. Report precision, recall and F1 per
rule and in aggregate.

**Scope statement to accompany any figure.** The corpus is ours, so the result measures implementation
correctness against declared intent, not field accuracy. Field accuracy requires labelled real-world captures,
which do not publicly exist.

**Independent check.** Compare the S4/S5 parse against `tshark` on the same capture, field by field.

**Current status.** Not yet run; `scripts/evaluate.py` raises `NotImplementedError`.

## Appendix F — Risk register

See §15 for the full table. The single entry that should be treated as a submission blocker is the absence of
measured precision and recall, because it is the only risk whose mitigation is fully scoped, cheap, and
currently unstarted.

---

## Document notes

**Placeholders to fill:** `[TEAM NAME]`, `[TEAM ID]`, and the member list if the template requires one.

**Two discrepancies found while writing this document**, both worth fixing in the repository:

1. `CLAUDE.md` and several documents state **33 rules**. The rule pack contains **34** (`len(pack.RULES) == 34`).
   This document uses 34.
2. `CLAUDE.md` attributes arXiv 2606.16473 to authors I could not confirm; it is cited here by title and
   identifier.
