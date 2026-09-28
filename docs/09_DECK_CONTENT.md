# 09 — Deck content, slide by slide

Slide copy plus the published source behind every line. Built to be lifted onto the slide directly; the
"evidence base" column is what you say when a judge asks "how do you know that?".

Companion: [08_PITCH.md](08_PITCH.md) for deck craft, policy timelines, judge Q&A and the full reference list.

Citation keys used below:

| Key | Paper |
|---|---|
| **Dur15** | Durumeric et al., "Neither Snow Nor Rain Nor MITM… An Empirical Analysis of Email Delivery Security", **IMC 2015** (Michigan + Google) |
| **May16** | Mayer, Zauner, Schmiedecker, Huber, "No Need for Black Chambers: Testing TLS in the E-mail Ecosystem at Large", **ARES 2016** |
| **Holz16** | Holz, Amann, Mehani, Wachs, Kaafar, "TLS in the Wild: An Internet-wide Analysis of TLS-based Protocols for Electronic Communication", **NDSS 2016** |
| **Pod21** | Poddebniak, Ising, Böck, Schinzel, "Why TLS is better without STARTTLS: A Security Analysis of STARTTLS in the Email Context", **USENIX Security 2021** |
| **Lee22** | Lee, Ashiq, Müller, van Rijswijk-Deij, Kwon, Chung, "Under the Hood of DANE Mismanagement in SMTP", **USENIX Security 2022** |
| **Ash25** | Ashiq, Fiebig, Chung, "Unraveling the Complexities of MTA-STS Deployment and Management in Securing Email", **IMC 2025** |
| **Loi26** | Loizou & Ghadafi, "Measuring Post-Quantum TLS Deployment Across UK Internet Sectors", **arXiv 2608.02147**, Aug 2026 |
| **PQ26** | "Measurement Study of Post-Quantum Readiness of Internet: 2026", **arXiv 2606.16473** |
| **SP10** | Sommer & Paxson, "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection", **IEEE S&P 2010** |
| **Li16** | Li, Durumeric, Czyz, Karami, Bailey, McCoy, Savage, Paxson, "You've Got Vulnerability: Exploring Effective Vulnerability Notifications", **USENIX Security 2016** |
| **Sin25** | Singh, Kashyap, Cherukuri, "Interpretable Anomaly Detection in Encrypted Traffic Using SHAP", **arXiv 2505.16261** |
| **INT26** | "INTACT: Intent-Aware Representation Learning for Cryptographic Traffic Violation Detection", **arXiv 2602.21252** |
| **Sia23** | Jafari Siavoshani et al., "Machine learning interpretability meets TLS fingerprinting", **Soft Computing** 27 (2023) |
| **Fos15** | Foster, Larson, Masich, Snoeren, Savage, Levchenko, "Security by Any Other Name: On the Effectiveness of Provider Based Email Security", **ACM CCS 2015** |

---

# SLIDE 2 — Idea, solution, novelty, USP, user flow

## The sentence that carries the slide

Read the measurement literature end to end and one fact falls out that nobody has written down:

> **Every large study of email encryption scanned servers from the outside. Not one of them could tell an
> individual operator what actually happened to their own mail.**

Dur15 scanned IPv4 with ZMap and read Gmail's connection logs. May16 scanned 20 million IP/port pairs and ran
10 billion handshakes. Ash25 scanned DNS across 87 million domains. Lee22 scanned TLSA records. Loi26 probed
4,665 organisations' endpoints. Holz16 is the only one that used passive monitoring at all, and it did so at one
research vantage point to describe the ecosystem — not to serve an operator.

All of them answer *"what will this server agree to if I ask?"* None answers *"what did my mail actually do
last Tuesday, and did anyone interfere with it?"* That second question is the one a CERT team has to answer in
six hours, and CyberKavach is built for it. **That is the novelty claim, and it is checkable against the
literature.**

---

## Box 1 — Definition

> **CyberKavach — an encryption audit that needs evidence, not access.**
> Grades every mail server in a packet capture A+ to F, ranks each weakness by what that port is really for, and
> traces every finding to the byte that caused it. It reads the envelope, never the letter.

| Phrase | Why it is defensible |
|---|---|
| "evidence, not access" | Every study above needed reachable servers. We need a file. |
| "A+ to F" | `pipeline.py:_grade()`; `Grade.INCOMPLETE` → `?` when the handshake was not fully parsed |
| "what that port is really for" | `port_role` — `mta_relay` / `submission` / `mail_access`; the asymmetry is stated explicitly in **Pod21** |
| "to the byte" | capture SHA-256 + stream index + frame number + byte offset on every finding |
| "reads the envelope, never the letter" | no decryption anywhere in the pipeline |

---

## Box 2 — "How it addresses the problem"

Five lines. Pick four for the slide; keep the fifth for the viva.

**Slide copy:**

- **Email encryption is optional by design and fails silently.** If it cannot be negotiated, mail goes out in
  plain text and nobody is told. All five major mail servers tested behave this way. *(RFC 7435; Dur15)*
- **Almost nothing is actually authenticated.** **65% of SMTP servers** present a self-signed certificate, and
  across mail-access protocols only **33–37% validate correctly**. Of 19 major providers tested, **not one**
  rejected a self-signed certificate. *(May16 — full IPv4, 2.1M certificates; Dur15)*
- **The upgrade step itself is broken.** A structured audit of 28 mail clients and 23 servers found **more than
  40 STARTTLS flaws**; only **3 of the 28 clients** were clean; and an internet-wide scan found **320,000 mail
  servers — 2% of all of them — vulnerable to command injection** that can steal credentials. *(Pod21)*
- **This is being exploited right now.** **41,405 mail servers across 4,714 networks in 193 countries** were
  observed having encryption stripped in transit. In Tunisia, **96.13%** of mail to Gmail was forced back to
  plain text; seven countries were above 20%. *(Dur15)*
- **And the fixes are barely deployed, or deployed wrong.** MTA-STS is on **0.07% of `.com`** domains and
  **29.6% of those who publish it get it wrong** *(Ash25)*. For DANE, **over 30% of TLSA records fail
  validation** and **87% of servers rolled keys over incorrectly** *(Lee22)*.

**The line that opens the gap** — put this one in bold, bottom of the box:

> Every one of those studies scanned servers from outside. None of them could tell one operator what happened
> to their own mail.

---

## Box 3 — "Detailed explanation of the proposed solution"

**Slide copy:**

- Feed it an **authorised packet capture**. It finds every SMTP, IMAP and POP3 session — identified from how the
  server speaks, not from the port number.
- Rebuilds each conversation byte by byte, then reads the TLS handshake and the certificate chain. **Nothing is
  decrypted.**
- **33 checks across six scored areas** — protocol, cipher, key exchange, certificate, STARTTLS behaviour, and
  **evidence of attack** — each naming the RFC or NIST clause it enforces.
- Grades every server **A+ to F**, and **`?`** where the evidence was encrypted or incomplete.
- Every finding ships with **the config lines that fix it**. Notification studies show that remediation depends
  on the notice being specific and actionable, not on the finding existing. *(Li16)*
- **It already runs:** 13,300 lines, 168 tests passing, one dependency, one command.

---

## Box 4 — "Innovation and uniqueness" (highlight this box)

Four claims. Each has a paper behind it, which is what makes them survive questioning.

### 1. Severity that knows mail from web

**Slide:** *An expired certificate is routine between two relays on port 25 and an emergency on port 993, where
a password crosses. We are the only submission that scores it differently — and says why, in plain English, on
the finding itself.*

**Evidence base.** This is not our opinion, it is the literature's. Pod21 states the asymmetry directly: the
security implications on submission and retrieval are more critical *because those connections carry user
credentials, not just individual messages*. May16 reaches the same conclusion from the other direction —
securing server-to-server mail is inherently harder than client-to-server, which is why 65% of SMTP hosts run
self-signed certificates and why SMTP does not validate by default. The standards encode the same split: RFC
7435 defines relay TLS as opportunistic security, RFC 8314 makes strict TLS mandatory for submission and
access. **The threat model is known to differ by role; no tool implements that difference.** SP10 explains the
cost of ignoring it — with benign traffic dominating, even a small false-positive rate produces an alert volume
operators stop reading.

### 2. It finds attacks, not just weak settings

**Slide:** *Five passive detectors — including the exact same-length capability rewrite documented in the wild
— so the report says whether someone has already interfered, not only whether they could.*

**Evidence base.** Dur15 found stripping by scanning servers from outside; Pod21 found injection by testing
implementations in a lab. Both are ecosystem methods: neither can tell a specific operator that *their* session
was tampered with. The five detectors run on the operator's own capture, which is the gap. `attack_evidence` is
one of the six scored categories, not a footnote.

### 3. Every claim is traceable to the byte that caused it

**Slide:** *Capture hash, frame number, byte offset on every finding. Open the capture in Wireshark and check
it — which is also what section 63 of the Bharatiya Sakshya Adhiniyam, 2023 asks of digital evidence.*

**Evidence base.** SP10's central operational objection to machine learning in security is the semantic gap —
an alert an operator cannot trace back to a cause is an alert they cannot act on. Byte-level provenance closes
it. Sin25 argues the same for compliance: an unexplainable verdict cannot be used to justify a decision. And
s.63(4) BSA 2023 requires a certificate stating the record's hash value, with courts directed to treat a hash
mismatch as presumptive tampering.

### 4. It says what it could not see

**Slide:** *TLS 1.3 encrypts the certificate. We report that and grade the host `?` — never a pass it did not
earn.*

**Evidence base.** The PS requires every finding to be OBSERVED, NOT_FOUND, UNKNOWN or INSUFFICIENT_EVIDENCE.
INT26 makes the research case: crypto violations should be judged against *declared policy*, with uncertainty
modelled explicitly, rather than inferred as statistical oddities — and reports near-perfect discrimination
doing it that way. Our verdict enum and the `?` grade are that design.

### Strap line under the box

> One pure-Python dependency. No cloud, no internet, no model download — it runs on an air-gapped machine.

---

## Box 5 — User flow

`docs/assets/slide2_userflow.svg`. Analyst's path across the top, three outputs at the right (administrator →
config lines, auditor → evidence pack, investigator → attack timeline). Keep the twelve-stage pipeline for
slide 3; don't spend it twice.

---

## Every feature, and the published finding that makes it necessary

This is the table to have ready for the viva, and the source for slide 3's algorithm list. Nothing in our build
is there because it seemed like a good idea.

| What we built | The published finding that demands it | Source |
|---|---|---|
| Role-aware severity (`port_role`) | Submission and retrieval are more critical because credentials cross them; server-to-server is inherently harder to secure | Pod21, May16 |
| STARTTLS state machine, ten checks | 40+ STARTTLS flaws across 28 clients and 23 servers; only 3 clients clean; 7 of 23 servers never affected by injection; "error-prone, under-specified, should be avoided" | Pod21 |
| Capability-stripping detector (`250-XXXXXXXA`) | 41,405 servers stripped in the wild; the same-length rewrite is the dominant style, matching a commercial appliance's behaviour | Dur15 |
| Cleartext credential recovery | Credential theft is the most severe outcome of these flaws, and it is what submission/access ports expose | Pod21 |
| Certificate chain, expiry, key-size rules | 65% self-signed on SMTP; >50% on POP3/IMAP with only 33–37% validating; ~1% valid-but-expired; >99% RSA, >90% of trusted leaves 2048-bit | May16 |
| Cipher and key-exchange rules | 15–17% of POP3/IMAP hosts offer static RSA as their only key exchange; ~75% DHE; only 7–9% ECDHE | May16 |
| Protocol-version rules (TLS 1.0/1.1) | 15.7% of domains — concentrated in banking and government — still on TLS 1.2 or below | PQ26, RFC 8996 |
| Post-quantum group detection | **6.4% of SMTP endpoints PQ-ready against 44.0% of HTTPS**; zero PQ certificates anywhere | Loi26, PQ26 |
| MTA-STS and DANE checks (unbuilt, USP-11) | MTA-STS 0.07–0.12% adoption, 29.6% misconfigured; DANE >30% of TLSA records unvalidatable, 3.6% mismatched, 87% bad rollovers — attributed to the absence of automated tooling | Ash25, Lee22 |
| JA3/JA3S fingerprints, 51-feature vector | Handshake fields are where the signal is in encrypted traffic | Sia23 |
| Facts deterministic, ML only for ranking | The base-rate problem: in security, a small false-positive rate yields an unusable alert stream, and operators reject alerts they cannot trace to a cause | SP10 |
| Explanations attached to anomaly scores | Interpretability is a compliance requirement, not a nicety | Sin25 |
| Findings judged against declared policy | Violations modelled against intent outperform anomaly-only framing | INT26 |
| Config snippet on every finding | Notification content determines whether anything gets fixed | Li16 |
| Byte-level evidence, capture hash | Semantic gap (SP10); s.63(4) BSA 2023 hash certificate |  |
| `?` grade and `OPAQUE_TLS13` | PS requirement; uncertainty modelled rather than hidden | PS SIH26159, INT26 |

**How to use this table.** Don't put it on slide 2 — it goes on slide 6 (references) in compressed form, and
you keep the full version in your hands during the viva. When a judge asks "why did you build X?", the answer
is a paper and a number, not a preference.

---

## What to cut if the slide is crowded

In this order: the fifth problem bullet (MTA-STS/DANE — it reappears on slide 4 as the unbuilt feature with a
government deadline); the "identified from how the server speaks" clause (belongs on slide 3); the strap line
under Box 4 (say it out loud instead). Do not cut a number to make room for an adjective.

## Numbers to bold on slide 2, and only these

**65%** · **320,000 (2%)** · **41,405** · **96.13%** · **6.4% vs 44.0%**

Five is the limit before bold stops meaning anything. Note that four of the five are about attacks and failures
in the wild, and the fifth is the quantum gap — that is the emotional arc of the slide, and it lands before
anyone reads your feature list.

---

## Additional citation keys used from here on

| Key | Source |
|---|---|
| **Dre06** | Dreger, Feldmann, Mai, Paxson, Sommer, "Dynamic Application-Layer Protocol Analysis for Network Intrusion Detection", **USENIX Security 2006** |
| **Geo12** | Georgiev, Iyengar, Jana, Anubhai, Boneh, Shmatikov, "The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software", **ACM CCS 2012** |
| **Bru14** | Brubaker et al., "Using Frankencerts for Automated Adversarial Testing of Certificate Validation in SSL/TLS Implementations", **IEEE S&P 2014** |
| **AM18** | Anderson, Paul, McGrew, "Deciphering malware's use of TLS (without decryption)", **J. Computer Virology and Hacking Techniques**, 2018 |
| **Chen16** | Chen & Guestrin, "XGBoost: A Scalable Tree Boosting System", **KDD 2016** |
| **Liu08** | Liu, Ting, Zhou, "Isolation Forest", **IEEE ICDM 2008** |
| **Lund17** | Lundberg & Lee, "A Unified Approach to Interpreting Model Predictions" (SHAP), **NeurIPS 2017** |
| **Rou99** | Rousseeuw & Van Driessen, "A Fast Algorithm for the Minimum Covariance Determinant Estimator", **Technometrics** 41(3), 1999 |

---

# SLIDE 3 — Technical approach *(your slide 2)*

Official sub-headings: **Technologies to be used** and **Methodology and process for implementation**. The
diagram owns the middle of the slide; text goes down the sides.

## Box A — The pipeline (the diagram)

    PCAP -> ingest -> TCP reassembly -> protocol ID -> STARTTLS state machine -> TLS handshake -> X.509
         -> 33 rules -> 51 features -> AI layer (risk / anomaly / priority) -> aggregation -> JSON / HTML / PDF

**Twelve stages, S0-S10.** Label the diagram with the stage IDs; it makes the module ownership table in
`03_ARCHITECTURE.md` readable if a judge asks who built what.

## Box B — Algorithms, and why each one

Six bullets for the slide. **Bold the technique, keep the citation in brackets** — a bracketed venue name on a
technical slide is the cheapest credibility available.

- **Protocol identified from the conversation, not the port.** Port-based analysis misses exactly the traffic
  that matters, because a primary reason to avoid a standard port is to evade monitoring *(Dre06, USENIX Sec)*.
  Our S2 reads the server banner and the command grammar instead.
- **TCP reassembly that keeps byte-to-frame provenance.** Every byte of every rebuilt stream remembers its
  packet. This is what closes the **semantic gap** — the reason operators discard alerts they cannot trace to a
  cause *(SP10, IEEE S&P)*.
- **A STARTTLS state machine with ten checks**, derived from the four published attack classes — **negotiation,
  buffering, tampering, session** — found across 28 clients and 23 servers with a 100-test-case toolkit
  *(Pod21, USENIX Sec)*.
- **Our own TLS record and handshake parser, with JA3/JA3S fingerprints.** TLS metadata alone separates
  malicious from enterprise traffic across millions of flows and 18 malware families *(AM18)*; the handshake
  fields carrying that signal are the ones in our feature vector *(Sia23)*.
- **Our own DER/X.509 parser with real RSA signature verification.** Certificate validation is famously broken
  in non-browser software, and the root cause is confusing library APIs rather than exotic bugs *(Geo12, CCS;
  Bru14, IEEE S&P)*. A parser that allocates nothing, calls no C code, and is tested against certificates we
  generate ourselves is the conservative choice for code that will be pointed at an attacker's certificate.
- **33 rules over six scored categories**, each naming the clause it enforces — NIST SP 800-52r2, RFC 8996,
  9325, 8314, 7435 — and each carrying the config lines that fix the finding.

## Box C — The AI layer (expect this to be probed hardest)

**Slide copy — three bullets:**

- **Facts are deterministic; only the ranking is learned.** A cryptographic fact must never come from a
  probability. In security specifically, the **base-rate problem** means a small false-positive rate produces an
  alert stream operators stop reading *(SP10)*.
- **Risk scoring and anomaly detection over a 51-feature vector** — **XGBoost** *(Chen16)* for risk
  classification and **Isolation Forest** *(Liu08)* for anomalies, the two methods the problem statement names.
  Feature extraction, corpus generation and CSV export are complete; the classifier trains off-box.
- **Every score explains itself.** Feature attribution in the **SHAP** sense *(Lund17)*, which recent work
  shows is what makes anomaly detection on encrypted traffic usable for compliance at all *(Sin25)* — and
  violations are judged against **declared policy**, not treated as statistical oddities, which is the framing
  that currently performs best *(INT26)*.

**One extra line if a judge asks about the poisoned baseline:** a baseline built from a capture that contains
the attacks lets the attacks define normal. Ours is built in two passes with outliers rejected first — the same
principle as **robust covariance estimation** *(Rou99)*.

## Box D — Stack

- **Python 3.11**, one runtime dependency (**dpkt**, pure Python), standard library for everything else
- **Written from scratch:** TCP reassembler, TLS record/handshake parser, DER/X.509 parser with RSA signature
  verification, PDF renderer
- **Reports:** JSON; one **self-contained HTML file** that is also the dashboard — no CDN, no fonts, no build
  step; PDF
- **Testbed:** `synth.py` writes PCAPs byte by byte, `certgen.py` issues real signed certificates
- **168 tests**, run without pytest. **No compiled extensions, no container required, no network calls.**

> Say out loud: *"Everything in this stack was chosen so it installs on a machine with no internet and no
> package manager. That is not a limitation we worked around, it is the deployment target."*

---

# SLIDE 4 — Feasibility and viability *(your slide 4)*

Official sub-headings: **Analysis of the feasibility of the idea** / **Potential challenges and risks** /
**Strategies for overcoming these challenges**. Every winning deck used a two-column Challenge to Solution
table. Do the same.

## Box A — Feasibility: it already runs

- **13,300 lines of Python, 168 tests passing, 33 rules, 12 pipeline stages, one command**
- **25 of 34 deliverables verified** by `scripts/audit.py`, which runs before and after every change
- **One dependency** means deployment is a file copy — no package manager, no internet, no container
- Put the command on the slide: `python scripts/analyse.py capture.pcap --out out/`

## Box B — Government integration (name names and dates)

- **NIC** — under the **E-mail Policy of the Government of India** (2015, reissued 2024) all official
  government mail runs through NIC. **One operator, one estate**: a single deployment covers it.
- **CERT-In** — the 2022 directions require incident reporting within **six hours** and **180 days of ICT logs
  held in India**. The evidence already exists by law; what is missing is the thing that reads it in time.
- **NCIIPC**, which sits under NTRO, for critical-sector mail.
- **The deadline that makes this urgent** — India's PQC migration roadmap (DST task force under the National
  Quantum Mission, **February 2026**): *inventory cryptographic assets* for critical infrastructure by
  **2027**, high-priority migration **2028**, full adoption **2029**, and **CBOMs required from vendors from
  FY 2027-28**. The UK's NCSC sets the same first step at 2028. **Every roadmap begins with discovery, and for
  email there is no discovery tool.**
- **SEBI CSCRF** (Aug 2024) requires **TLS 1.2+** in transit for regulated entities — and gives them no way to
  prove it for mail.
- **231 CERT-In empanelled audit organisations** are the distribution channel.

## Box C — Viability: the demand is documented, not assumed

This is the strongest feasibility material available and almost no team will have anything like it — **published
evidence that operators want this and are blocked by the absence of tooling**:

- Ash25 surveyed **117 email operators**: **94.7% knew about MTA-STS**, yet **48.8% cited operational
  complexity** as the reason they had not deployed it and **26.8%** reported difficulty managing policy
  updates.
- Lee22 attributes DANE's **87% incorrect key rollovers** directly to *the lack of automated tools for key
  management*.
- Li16 measured what actually drives fixes: **notifications carrying remediation steps were 56.5% more
  effective than terse ones after two days** (IPv6), **55.5%** for ICS — although the authors note the
  difference is not statistically significant after correction, and that **fewer than 40%** of operators who
  read the detail fixed anything. **Say the caveat.** It is the difference between citing a paper and having
  read it.

**Commercial model:**

- **Open core** (engine + rules), because government adoption needs source availability
- **Paid:** continuous sensor with fleet view; annual posture attestation an empanelled auditor can sign;
  **CBOM subscription** as the FY 2027-28 requirement lands
- **Market anchors, labelled as vendor research:** India email security **$0.427B (2025) to $1.31B (2035)**,
  11.82% CAGR; post-quantum cryptography **$810M (2025) to $18.19B (2035)**
- **Comparables:** IBM Quantum Safe Explorer, SandboxAQ AQtive Guard, Keyfactor AgileSec — all discover
  cryptography from **source code, containers or host agents. None works passively from mail traffic.**

## Box D — Challenges to solutions

| Challenge | What we do about it |
|---|---|
| **TLS 1.3 encrypts the certificate** | Report `OPAQUE_TLS13` with the reason, grade the host `?`; keep assessing what stays visible — version, key-exchange groups, server fingerprint, SNI |
| **Toolchain blocks numerical libraries**, so we cannot train here | Features, corpus and CSV export are done; train off-box; the deterministic engine carries the tool without a model |
| **A baseline built from an attacked capture treats attacks as normal** | Two-pass baseline with outlier rejection, following robust-estimation practice *(Rou99)* |
| **No public ground truth** for mail sessions labelled with crypto weaknesses | Synthetic corpus with a manifest of expected findings; per-rule precision and recall; cross-check the handshake parse against `tshark` on the same bytes |
| **Security tools that cry wolf get switched off** | Role-aware severity — and the base-rate argument for why it matters *(SP10)* |
| **Capturing mail traffic is legally sensitive** | Authorised captures only; nothing decrypted; no message content copied; credentials redacted by default; all local. Under the **DPDP Rules (notified 13 Nov 2025)** a detailed breach report is due in **72 hours** — a tool that never copies content is far easier to clear |
| **Certificate parsers are a classic source of bugs** | Pure-Python parser, no memory management, 168 tests including signature verification; and the literature says the mainstream libraries' APIs are themselves the hazard *(Geo12, Bru14)* |

---

# SLIDE 5 — Impact and benefits *(your slide 3)*

Official sub-headings: **Potential impact on the target audience** / **Benefits of the solution (social /
economic / environmental etc.)**. Three audiences, one concrete thing each. Resist the ten-bullet benefit list —
two of the six decks I read padded this slide and it shows.

## Box A — Government

- **A capability that does not exist today:** point it at mail traffic from any estate, *including one you are
  not permitted to touch*, and get a ranked list of cryptographic weaknesses with evidence attached
- Answers the question **CERT-In's six-hour clock** asks, from the **180 days of logs** already mandated
- Produces the **cryptographic inventory** the **2027** roadmap milestone requires, in **CBOM** form ahead of
  the **FY 2027-28** vendor requirement
- **Closes a measured national gap:** India's PQC roadmap assumes organisations can enumerate their
  cryptography. For mail, **6.4% of servers are quantum-ready against 44.0% of web servers**, and **no
  post-quantum certificates exist anywhere** *(Loi26)*

## Box B — Users

- **Mail administrator** — not a lecture, the **config lines to paste**, per finding, per server software, with
  the RFC that explains why. Grounded: remediation tracks how specific and actionable the notice is *(Li16)*
- **Auditor** — a **compliance report card** plus an evidence pack whose **hash and frame numbers** satisfy
  **s.63 BSA 2023**
- **Incident responder** — five attack detectors, **recovered plaintext credentials as proof of exposure**
  rather than a theory of it, and a timeline

## Box C — Economic and social benefit

- **Business email compromise: $3.04 billion** in reported losses in 2025 — the **second-largest** loss
  category — across **24,768 complaints**, roughly **$123,000 per incident** *(FBI IC3 2025)*
- **CERT-In handled 29.44 lakh incidents in 2025**, including **3,41,646 vulnerable exposed services** — the
  exact category this tool produces evidence for
- **Social:** email carries password resets, legal notices and financial instructions for hundreds of millions
  of Indians who have no way to know whether their mail crossed the network encrypted — Mayer et al. make
  exactly this point, that users are left in the dark about whether mail travels in plaintext
- **Only two kinds of number belong on this slide** — published ones, and our own measured ones. If a figure is
  a projection, **write "projected" next to it**

## Box D — SDGs

Two, argued properly. Judges have seen the six-SDG slide and it reads as filler.

- **SDG 9 — resilient infrastructure.** The ITU places strengthening cybersecurity inside Goal 9; target
  **9.c**'s push for universal ICT access only works if the infrastructure beneath it can be trusted
- **SDG 16 — strong institutions.** **16.6** (effective, accountable institutions) because evidence-linked
  findings are what accountability is made of; **16.4** (reducing illicit financial flows) because that is
  precisely what **$3.04B** of business email compromise is
- Secondary if you need a third: **8.2**, productivity through technological upgrading

---

# SLIDE 6 — Research and references *(your slide 5)*

Built like Code Omega's — the best single slide in any deck I read. Their columns were Title / Approach /
Dataset / Accuracy. Ours splits into two tables because half our evidence is measurement, not modelling.

## Table 1 — The problem, measured

| Paper | Venue | Approach | Dataset / scale | Key result |
|---|---|---|---|---|
| Durumeric et al. | **IMC 2015** | IPv4 scanning + Gmail connection logs | 700K SMTP servers; 1 year of Gmail mail flow | **41,405 servers** stripped across 193 countries; **96.13%** of Tunisian mail to Gmail downgraded; only **35%** configured for authentication |
| Mayer et al. | **ARES 2016** | Full-IPv4 cipher-suite scanning | **20M IP/port pairs**, **10 billion handshakes**, 2.1M certificates | **65%** of SMTP hosts self-signed; only **33-37%** validate on mail-access ports; **15-17%** of POP3/IMAP offer static RSA only |
| Holz et al. | **NDSS 2016** | Active scans **plus passive monitoring** | SMTP, IMAP, POP3, XMPP, IRC | The reference study for mail-protocol TLS; pairs what servers offer with what clients do |
| Poddebniak et al. | **USENIX Sec 2021** | EAST toolkit, 100+ test cases, then IPv4 scan | **28 clients, 23 servers** | **40+ STARTTLS flaws**; only **3/28** clients clean; **320,000 servers (2%)** vulnerable to credential-stealing injection |
| Lee et al. | **USENIX Sec 2022** | DNS/TLSA + certificate scanning | >1M SMTP domains with TLSA records | **>30%** of TLSA records unvalidatable; **3.6%** mismatched; **87%** rolled keys over incorrectly |
| Ashiq, Fiebig, Chung | **IMC 2025** | 31 months of DNS scans + operator survey | **87M domains**, 4 TLDs; **117 operators** | MTA-STS on **0.07-0.12%** of domains; **29.6% misconfigured**; **48.8%** of operators blame operational complexity |
| Loizou & Ghadafi | **arXiv 2608.02147**, 2026 | Active probing, HTTPS **and** SMTP STARTTLS | **4,665 UK organisations**, 10 sectors | **44.0%** of HTTPS vs **6.4%** of SMTP PQ-ready; **zero** PQ certificates |
| — | **arXiv 2606.16473**, 2026 | Negotiated-parameter analysis | 32,011 domains | **49.3%** support hybrid PQ key exchange; **0%** PQ certificates; **15.7%** still TLS 1.2 |

## Table 2 — The method, with accuracy

| Paper | Venue | Approach | Dataset | Reported accuracy |
|---|---|---|---|---|
| Singh, Kashyap, Cherukuri | **arXiv 2505.16261**, 2025 | XGBoost / Random Forest / Isolation Forest + **SHAP** explanations | CIC-Darknet2020, USTC-TFC2016, CSE-CIC-IDS2018; 80:20 split, 10-fold CV | **XGBoost 99.94%** accuracy, 90.9% precision, 88.2% recall, **93.0% F1**; Random Forest 97.92% / 92.8% / 88.3% / 89.5% |
| INTACT | **arXiv 2602.21252**, 2026 | Violations scored against **declared policy** (key reuse, downgrade, key lifetime), not as anomalies | Real network-flow dataset + **210,000-trace** synthetic multi-intent corpus | **AUROC up to 1.0000** on the real dataset; best on relational and composite violations |
| Anderson, Paul, McGrew | **J. Comp. Virol. 2018** | TLS metadata classification **without decryption** | Millions of TLS flows; **18 malware families** | Malware's TLS use is distinct enough for family attribution from a **single encrypted flow** |
| Jafari Siavoshani et al. | **Soft Computing 2023** | Interpretability applied to TLS fingerprinting | TLS handshake features | Identifies which handshake fields carry the signal — the basis of our 51-feature vector |
| Sommer & Paxson | **IEEE S&P 2010** | Position paper on ML for intrusion detection | — | The **base-rate problem** and the **semantic gap**: why facts must stay deterministic and every alert must trace to a cause |
| Li et al. | **USENIX Sec 2016** | Randomised notification experiment | Thousands of operators, several weeks of scans | Notices with remediation steps **56.5% more effective** after 2 days; **under 40%** who read the detail fixed anything |

## Table 3 — Our own numbers

**Fill this in before submission. Do not leave it empty and do not invent it.**

| What | Status |
|---|---|
| Corpus | 18 captures, `testbed/manifest.json` declares expected findings per capture |
| Rules | 33, across six scored categories |
| Tests | **168 passing** |
| Per-rule precision / recall | **`scripts/evaluate.py` is a stub — wire it up.** Everything needed exists |
| Independent check | Cross-validate the handshake parse against `tshark` on the same bytes |

Phrase it like this when you have it, because the honesty is the differentiator against a rival repo already
claiming 100% precision and recall:

> Per-rule precision and recall against 18 captures with declared expected findings. The corpus is ours, so this
> measures implementation correctness, not field accuracy — which would need labelled real-world captures that
> do not publicly exist. Rules that cannot fire because the evidence was encrypted are counted as *insufficient
> evidence*, not as misses.

## Datasets

- **Ours:** `testbed/synth.py` (PCAPs written byte by byte), `testbed/certgen.py` (real signed certificates),
  `testbed/manifest.json` (ground truth)
- **Public, to validate against:** CIC-IDS2017 (**48.8 GB**, 5 days, 25 users, email protocols included),
  CSE-CIC-IDS2018, UNSW-NB15, Stratosphere / CTU malware captures, Netresec and
  malware-traffic-analysis.net, Wireshark's own SMTP/IMAP/POP3 samples, MAWI (headers only)
- **The honest gap, stated confidently:** no public corpus exists of mail sessions labelled with cryptographic
  weaknesses. Most IDS corpora are built for attack classification and several are header-only, so they cannot
  exercise a certificate parser. **That is why the synthetic corpus exists, and why the `tshark` cross-check
  matters.**

## Policy — past, present, future

| When | What | Relevance |
|---|---|---|
| 2000 | **IT Act**, s.70B — creates CERT-In | Statutory basis for everything below |
| Feb 2015 | **E-mail Policy of the Government of India** | Official mail must use NIC |
| Apr 2022 | **CERT-In Directions** | **6-hour** incident reporting; **180 days** of logs held in India |
| Jun 2023 | **CERT-In guidelines for government entities** | Dedicated mail servers, encrypted connections, SPF/DKIM/DMARC |
| Aug 2023 | **DPDP Act** | Security obligations for personal data |
| 2023 | **Bharatiya Sakshya Adhiniyam, s.63** | Electronic evidence needs a certificate stating its **hash** |
| Aug 2024 | **SEBI CSCRF** | **TLS 1.2+** in transit for regulated entities |
| Jul 2025 | **MeitY / CERT-In / SISA quantum-readiness whitepaper** | Finance, defence, healthcare migrate first |
| Nov 2025 | **DPDP Rules notified** | Detailed breach report in **72 hours**; penalties to **Rs 200 crore** |
| **Feb 2026** | **DST / NQM PQC roadmap** | **Crypto inventory for CII by 2027; CBOM from vendors FY 2027-28; full PQC 2029** |
| 2030 / 2035 | **NIST IR 8547** | RSA-2048 and P-256 **deprecated**, then **disallowed** |

**The shape of that table is the argument:** everything before 2026 tells you to encrypt mail properly, and
nothing tells you how to check whether you did.

## Links to put on the slide

Public demo repo or release zip; 90-second video; the sample HTML report (one self-contained file, opens from
a link); a sample capture; `docs/07_RELATED_WORK.md`. Four of the six decks did this and it costs nothing.
