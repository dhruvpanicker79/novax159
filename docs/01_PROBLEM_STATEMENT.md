# 01 — Problem Statement, Decomposed

## 1. The statement (as issued)

**Title:** SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications

**Background.** Email remains critical for governments, enterprises, financial institutions and academia. Despite
widespread TLS adoption, many SMTP, IMAP and POP3 deployments still suffer from cryptographic misconfigurations —
obsolete TLS versions, weak cipher suites, insecure STARTTLS implementations, expired or improperly configured
certificates, and non-compliance with modern standards. These expose email infrastructure to downgrade attacks,
man-in-the-middle attacks and passive interception.

Existing network analysis tools give packet-level visibility but focus on protocol decoding and traffic inspection.
They do **not** automatically evaluate overall cryptographic security posture, nor provide intelligent risk
assessment and prioritisation for analysts.

**Description.** Design an **AI-assisted passive network forensic framework** that analyses captured traffic (PCAP)
containing SMTP, IMAP and POP3 communications to automatically assess the cryptographic security posture of
enterprise email infrastructures: reconstruct sessions, identify encryption transitions, analyse TLS negotiations,
validate certificates, detect cryptographic weaknesses, and apply AI/ML to classify risk, detect anomalous TLS
behaviour and generate actionable recommendations.

**Named users:** Security Operations Centres (SOC), Digital Forensics teams, Incident Response teams, enterprise
administrators.

**Dataset guidance (as issued):** *Synthetic — participants may generate IMAPS, POP3S, SMTPS data using any email
server/client of their interest and capture a PCAP dump.*

---

## 2. The 21 scored deliverables

The "Expected Solution/Deliverables" list is what judges will check off. Numbered here so every rule, module and
slide can cite an ID.

| ID | Deliverable |
|---|---|
| D01 | Automatic identification of SMTP, IMAP and POP3 protocols |
| D02 | STARTTLS negotiation detection **and validation** |
| D03 | Complete TCP stream reconstruction |
| D04 | TLS handshake reconstruction |
| D05 | Detection of negotiated TLS versions |
| D06 | Identification of negotiated cipher suites |
| D07 | Identification of key exchange mechanisms |
| D08 | Extraction of X.509 certificates |
| D09 | Certificate chain validation |
| D10 | Certificate expiration analysis |
| D11 | Public key algorithm and key length analysis |
| D12 | Digital signature algorithm identification |
| D13 | Detection of weak cryptographic algorithms and deprecated TLS versions |
| D14 | Identification of insecure protocol configurations |
| D15 | Forward Secrecy assessment |
| D16 | AI-based cryptographic risk scoring |
| D17 | AI-assisted anomaly detection for suspicious TLS sessions |
| D18 | Prioritized security findings |
| D19 | Comprehensive cryptographic security posture assessment |
| D20 | Exportable forensic reports in JSON, PDF and HTML |
| D21 | Interactive visualization dashboard |

Plus two items that appear only in the Objectives list but are still scoreable:

| ID | Objective-only requirement |
|---|---|
| O01 | Extraction of cryptographic features for intelligent analysis |
| O02 | Recommendation of mitigation measures |

---

## 3. Six requirements hidden in the wording

Most teams will read the bullet list and miss these. They are free marks.

### 3.1 "STARTTLS detection **and validation**" (D02)

*Validation* is a second verb. Detection is "I saw the STARTTLS keyword." Validation is these ten checks:

| # | Check | Failure means |
|---|---|---|
| V1 | Was STARTTLS advertised in `EHLO` / `CAPABILITY` / `CAPA`? | Server does not support TLS at all |
| V2 | Was the capability line **mangled** (e.g. `250-XXXXXXXA`)? | **Active STARTTLS stripping in progress** |
| V3 | Did the client issue the command? | Client-side policy failure |
| V4 | Did the server answer `220` / `+OK` / `OK`? | Server refused the upgrade |
| V5 | Did a real ClientHello follow the go-ahead? | Upgrade announced but never happened |
| V6 | Did the handshake complete (CCS + encrypted application data)? | Failed negotiation, likely cleartext fallback |
| V7 | Did the client re-issue `EHLO` after TLS, as RFC 3207 requires? | Protocol violation — **but see note below: only observable when the upgrade failed** |
| V8 | Was `AUTH` advertised *before* TLS? | RFC 4954 violation |
| V9 | Did credentials transit before the upgrade? | **Critical — credential exposure** |
| V10 | Plaintext command injection across the TLS boundary? | CVE-2011-0411 class vulnerability |

**Correction, found while implementing S3.** V7 is **not passively observable when the upgrade succeeds.**
Once the handshake completes, the re-issued `EHLO` travels inside the encrypted channel and we cannot see it. We
therefore report V7 as *not applicable* whenever the handshake completed, and only evaluate it when the upgrade
failed and the conversation stayed readable.

That is worth saying out loud rather than quietly dropping: knowing which of our own checks are observable is the
same kind of honesty as reporting TLS 1.3 certificates as *opaque* rather than absent. Nine of the ten checks are
fully passive; the tenth is conditional. Claiming a violation we could not see would be a fabricated finding, which
is worse than a missing one.

### 3.2 "Reconstruction" appears twice (D03, D04)

TCP streams *and* TLS handshakes. That verb means **show it**, not parse it. If we parse silently and print a
verdict, we technically did the work but lose the deliverable. The dashboard must render the reassembled
conversation and a handshake ladder diagram.

### 3.3 Feature extraction is its own stage (O01)

They list it as a distinct capability. So the feature vector must be an explicit, named, documented, **inspectable**
artifact — not an anonymous array inside a `predict()` call. It gets a panel in the UI.

### 3.4 Scoring and prioritisation are two different asks (D16 vs D18)

*Scoring* is a number per session or host. *Prioritisation* is an ordering across the whole capture, which requires
blast radius, exposure and exploitability — not just severity. Two separate pieces of code.

### 3.5 Four personas are named

SOC, Digital Forensics, Incident Response, enterprise administrators. They want different artifacts from the same
analysis. See USP-06 in [02_USP.md](02_USP.md).

### 3.6 "Enterprise email infrastructure**s**" — plural

Fleet-level aggregation is required, not a bonus. The demo cannot be a single session; it must be a fleet view of
many servers with per-host and per-domain rollups.

---

## 4. What the PS does **not** ask for

Stating the boundary confidently reads as maturity, and pre-empts the obvious hostile question.

| Out of scope | Why |
|---|---|
| Decrypting TLS payloads | The PS says *passive* analysis of *encrypted* traffic. Posture assessment needs no keys |
| Live capture / active probing / scanning | Input is explicitly PCAP files |
| Email **content** analysis | Not cryptographic posture |
| Phishing / spam / malware detection | Different problem class entirely |
| Endpoint agents | The framework is network-side and passive |
| Executing remediation | The ask is *recommendation* of mitigation measures |

**The trap:** SPF / DKIM / DMARC. These are email *authentication*, not transport cryptography, and chasing them
dilutes the pitch. One narrow exception is defensible and is documented as a Tier-3 USP in [02_USP.md](02_USP.md).

---

## 5. Reading the dataset guidance

> *Synthetic — participants may generate IMAPS, POP3S, SMTPS data using any email server/client and capture a PCAP dump.*

Three consequences, and one of them is a competitive gift.

**5.1 They named only the implicit-TLS ports.** IMAPS (993), POP3S (995) and SMTPS (465) are TLS-from-byte-zero.
There is no cleartext phase and no protocol upgrade to observe. That is the *easy* capture to produce — point any
mail client at any provider and hit record.

**5.2 But STARTTLS is explicitly required by the objectives (D02).** STARTTLS lives on the *other* ports — 25, 587,
143, 110 — and requires deliberately configuring a server for opportunistic TLS. Teams that follow the dataset hint
literally will capture only implicit TLS and will under-deliver on D02 and on the entire cleartext-phase analysis.
**We capture both**, which means our tool handles a case most submissions cannot even demonstrate.

**5.3 Synthetic data means we own the ground truth.** We choose the TLS version, cipher, key size and certificate
validity for every capture we generate. So we can build a **labelled validation set** and report real precision and
recall per detection rule, instead of the usual hackathon hand-wave. See USP-07 in [02_USP.md](02_USP.md).

**Capture matrix to produce (target ~18 PCAPs):**

| Protocol / port | Implicit TLS | STARTTLS | Cleartext (negative control) |
|---|---|---|---|
| SMTP relay (25) | — | yes | yes |
| SMTP submission (587) | — | yes | yes |
| SMTPS (465) | yes | — | — |
| IMAP (143) | — | yes | yes |
| IMAPS (993) | yes | — | — |
| POP3 (110) | — | yes | yes |
| POP3S (995) | yes | — | — |

Each crossed with three health tiers — **healthy** (TLS 1.3, ECDHE, valid chain), **degraded** (TLS 1.2, CBC-SHA1,
1024-bit RSA, certificate expiring soon) and **compromised** (TLS 1.0, 3DES or RC4, expired self-signed certificate,
STARTTLS stripped, credentials in the clear).

---

## 6. Traceability matrix

Every deliverable, the pipeline stage that produces it, and the screen where a judge can *see* it. Stage IDs are
defined in [03_ARCHITECTURE.md](03_ARCHITECTURE.md).

| ID | Deliverable | Stage | Visible where |
|---|---|---|---|
| D01 | Protocol identification | S2 | Fleet table — protocol column |
| D02 | STARTTLS detection + validation | S3 | Session timeline + 10-check validation panel |
| D03 | TCP stream reconstruction | S1 | Stream viewer (rendered bytes) |
| D04 | TLS handshake reconstruction | S4 | **Handshake ladder diagram** |
| D05 | Negotiated TLS version | S4 | Session card + fleet heatmap |
| D06 | Cipher suite | S4 | Session card + distribution chart |
| D07 | Key exchange mechanism | S4 | Session card |
| D08 | X.509 extraction | S5 | Certificate inspector |
| D09 | Chain validation | S5 | **Chain visualiser** |
| D10 | Expiration analysis | S5 | Expiry timeline |
| D11 | Public key algorithm + length | S5 | Certificate inspector |
| D12 | Signature algorithm | S5 | Certificate inspector |
| D13 | Weak algorithms + deprecated TLS | S6 | Findings board |
| D14 | Insecure protocol configuration | S6 | Findings board |
| D15 | Forward Secrecy assessment | S6 | Fleet PFS gauge |
| D16 | AI risk scoring | S8 | Score gauge + **SHAP waterfall** |
| D17 | AI anomaly detection | S8 | Anomaly lane + JA3 rarity plot |
| D18 | Prioritised findings | S8 | **Triage queue** |
| D19 | Posture assessment | S9 | Executive dashboard + grade |
| D20 | JSON / PDF / HTML export | S10 | Export menu |
| D21 | Interactive dashboard | S11 | The application |
| O01 | Feature extraction | S7 | **Feature inspector panel** |
| O02 | Mitigation recommendations | S8 | Config snippet per finding |

This table goes in the PPT. It is also the pre-demo checklist: if any row cannot be shown on screen, we have lost a
mark for work we already did.
