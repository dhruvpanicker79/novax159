# 02 — Unique Selling Points

**Purpose of this document.** This is the reference for building the PPT and for answering judges. Every USP below
is written in a fixed format: the one-line pitch (slide text), the gap it fills, how it works, why competing teams
will not have it, the demo moment, the build cost, and what to say when a judge pushes back.

Companion docs: [01_PROBLEM_STATEMENT.md](01_PROBLEM_STATEMENT.md) for the deliverable IDs (D01–D21, O01–O02),
[03_ARCHITECTURE.md](03_ARCHITECTURE.md) for the pipeline stage IDs (S0–S11).

---

## 1. The one-sentence USP

> **SecureMailScope is the only submission that treats email TLS as *email* — judging every session by what that
> port is actually for, proving every finding with the exact bytes that caused it, and telling you not just that
> your crypto is weak but whether someone has already been exploiting it.**

## 2. The 30-second pitch

Wireshark shows you bytes. SSL Labs needs a live, internet-facing server. Neither one opens a PCAP and tells a SOC
analyst *"these three mail servers are your problem, in this order, and here is the Postfix config that fixes
them."*

SecureMailScope does that, and three things make it more than a checklist. It understands that a self-signed
certificate is *normal* on an MTA relay port and *critical* on a submission port — so it doesn't drown analysts in
false alarms the way generic TLS scanners do. It looks for evidence that a downgrade attack has *already happened*,
not just that one is possible. And every single finding is clickable down to the frame number and byte offset in
the original capture, which is what makes it admissible as forensic evidence rather than a scanner's opinion.

## 3. Positioning — why the existing tools don't solve this

This is the "gap" slide. The PS background paragraph practically writes it for us.

| Tool | What it does | Why it doesn't solve this PS |
|---|---|---|
| **Wireshark / tshark** | Decodes packets, shows TLS fields | Decoding, not judgement. No risk score, no prioritisation, no posture, no recommendations. Shows one session at a time |
| **SSL Labs / testssl.sh / sslyze** | Grades a TLS endpoint thoroughly | **Active** scanners. Need a reachable live server, cannot work from a capture, and are blind to STARTTLS *behaviour* and to attacks already in the traffic |
| **Zeek** | Logs TLS metadata from PCAP at scale | Produces logs, not assessment. No scoring, no certificate policy engine, no UI, no remediation. Would be a *component*, not a solution |
| **Nmap `ssl-enum-ciphers`** | Enumerates supported ciphers | Active, per-host, no email semantics, no reporting layer |
| **SIEM / commercial CASB** | Alerts on known IOCs | Not cryptographic posture; expensive; needs live telemetry, not forensic captures |
| **Other SIH teams (predicted)** | Parse PCAP, print TLS version, red/green table, a RandomForest, a Bootstrap dashboard | Satisfies the bullet list literally. No email semantics, no evidence linkage, no attack detection, no measured accuracy |

**The one-liner for the slide:** *Existing tools either decode without judging, or judge without being able to work
from a capture. Nothing does passive, offline, email-aware cryptographic posture assessment.*

---

# TIER 1 — The seven USPs that are the pitch

Build all seven. They are cheap, visible within thirty seconds of a demo, and defensible under questioning.

---

## USP-01 · Role-Aware Severity Engine

**Pitch:** *We grade each session by what that port is actually for. An expired certificate on an MTA relay is
expected; the same certificate on a submission port is critical. No generic TLS scanner makes that distinction.*

**Gap it fills.** Every off-the-shelf TLS tool applies web-server rules to email. That is wrong, and it produces the
single biggest source of false positives in real mail infrastructure. Server-to-server SMTP on port 25 is
*opportunistic security* by design (RFC 7435): the sending MTA usually cannot validate the receiving certificate,
and encrypting with an unvalidated certificate is still strictly better than cleartext. Flagging that as critical
trains analysts to ignore the tool. Meanwhile mail *submission* (587/465) and mail *access* (143/993, 110/995)
carry user credentials and must enforce strict validation per RFC 8314.

**How it works.** Every `MailSession` is assigned a `port_role` at stage S2:

| Role | Ports | TLS expectation | Certificate validation failure |
|---|---|---|---|
| `mta_relay` | 25 | Opportunistic (RFC 7435) | Low — informational |
| `submission` | 587 (STARTTLS), 465 (implicit) | **Mandatory** (RFC 8314, 4954) | **Critical** |
| `mail_access` | 143 (STARTTLS), 993 (implicit), 110, 995 | **Mandatory** (RFC 8314) | **Critical** |

The rule engine at S6 emits a base severity; the role engine then applies a documented multiplier before the
finding reaches the triage queue. The adjustment is shown in the UI, not hidden — "downgraded from HIGH to INFO:
port 25 MTA relay, opportunistic TLS per RFC 7435."

**Why others won't have it.** It requires knowing that email TLS has a different threat model from web TLS. Teams
reading the PS as a TLS-parsing exercise will never encounter this idea.

**Demo moment.** Show the same expired self-signed certificate in two sessions side by side — one green and
annotated "expected for opportunistic relay," one red and annotated "critical: credentials traverse this path."

**Build cost.** ~50 lines plus a YAML table. Highest value-per-line in the project.

**If a judge pushes back** ("isn't an expired cert always bad?"): *On the public internet, MTA-to-MTA SMTP has no
usable trust anchor — the sender has no way to know what certificate the receiver should present unless DANE or
MTA-STS is published. RFC 7435 defines this as opportunistic security, and encrypted-with-unvalidated-cert beats
cleartext. We report it, we just don't page a human at 3am for it. On the submission port, where a password is
about to cross the wire, the same certificate is a critical finding.*

---

## USP-02 · Attack-Evidence Layer — "has someone already been exploiting you?"

**Pitch:** *Everyone else tells you your configuration is weak. We tell you whether the attack has already
happened, with the evidence.*

**Gap it fills.** The PS says **forensic framework** and names Digital Forensics and Incident Response teams. A
configuration checker serves neither. Forensics asks a different question: not "could I be attacked?" but "was I?"

**How it works.** Five independent detectors, all purely passive:

| Detector | Signal | Meaning |
|---|---|---|
| **STARTTLS stripping** | Capability line mangled in transit (the classic `250-XXXXXXXA`), or advertised-then-never-used, followed by cleartext `AUTH` | Active MITM downgrading the session |
| **Credential exposure** | `AUTH LOGIN` / `AUTH PLAIN` base64 in a cleartext phase | We decode it on screen. Devastating and unambiguous |
| **Downgrade sentinel** | Last 8 bytes of ServerHello `random` equal the RFC 8446 §4.1.3 `DOWNGRD` marker; presence of `TLS_FALLBACK_SCSV` (RFC 7507) in the ClientHello | A TLS 1.3-capable server was forced down, or the client is defending against a fallback attack |
| **Cipher intersection anomaly** | Server selected a suite materially weaker than the strongest one both parties supported | A sabotaged, MITM'd, or badly misconfigured server. Rules alone cannot see this — it needs both halves of the handshake compared |
| **Certificate substitution** | Same server identity, different certificate fingerprints or issuers across sessions in one capture | Possible interception, or an unmanaged certificate rotation nobody approved |

**Why others won't have it.** It requires reading the PS as forensics rather than as auditing, and it requires
comparing ClientHello against ServerHello rather than just reading off the negotiated values.

**Demo moment.** **This is the emotional peak of the demo.** Load the compromised capture. The timeline shows the
server advertising STARTTLS, the capability line arriving mangled, the client falling back to cleartext, and then a
base64 blob that we decode live into `username:password`. Nobody in the room is looking at their phone.

**Build cost.** Moderate — roughly a day for one person, mostly in S3 and S4, and it reuses parsing work already
required by D02 and D04.

**If a judge pushes back** ("couldn't a mangled banner just be a bug?"): *Yes, and we report confidence rather than
certainty — the finding says "consistent with active stripping" and lists the corroborating signals: was the
capability well-formed on other sessions to the same host, did credentials follow, is the mangling the known
fixed-length pattern. We surface evidence and let the analyst conclude. That is what a forensic tool should do.*

---

## USP-03 · Evidence-Linked Findings (forensic provenance)

**Pitch:** *Every finding is clickable down to the frame number and byte offset in the original capture, under the
capture's SHA-256. This is the difference between a scanner's opinion and forensic evidence.*

**Gap it fills.** A finding with no provenance cannot be used in an incident report, a compliance audit or a legal
process. The PS explicitly names Digital Forensics teams — chain of custody is their entire discipline.

**How it works.** Every object in the data model carries an `evidence` block from birth:

```
evidence: {
  capture_sha256: "...",     # integrity of the source artifact
  stream_id: 14,             # which reconstructed TCP stream
  frame_numbers: [812, 813], # exact packets
  byte_range: [3480, 3712],  # offset within the reassembled stream
  timestamp: "..."           # when it happened on the wire
}
```

Clicking a finding jumps the stream viewer to those bytes and highlights them. The exported JSON and PDF carry the
same references, so a third party can re-open the original PCAP in Wireshark and verify us independently.

**Why others won't have it.** Not because it's hard, but because it has to be designed in on day one. Threading
byte offsets back through a parser you already wrote is miserable, so teams that don't plan for it never add it.

**Demo moment.** Click a HIGH finding in the triage queue. The raw reconstructed stream opens with the offending
bytes highlighted. Say: *"We can prove every claim we make. Verify it in Wireshark yourself — frame 812."*

**Build cost.** Low **if decided now**, high if retrofitted. This is ADR-0004 in [04_DECISIONS.md](04_DECISIONS.md).

**If a judge pushes back** ("why does provenance matter for a scanner?"): *Because the PS asks for a forensic
framework serving DFIR teams. Evidence that can't be traced to its source can't go in an incident report. It also
makes our own tool auditable — if our parser is wrong, you can catch us.*

---

## USP-04 · Three-Layer Explainable AI

**Pitch:** *Three AI layers doing three jobs rules can't do — ranking, baselining and generalising — and every score
comes with the reasons that produced it.*

**Gap it fills.** The predictable failure mode of this PS is a team bolting a RandomForest onto a rule engine and
calling it AI. The judge's question — *"isn't this just if-else?"* — is fatal if unprepared for. We answer it with
architecture, not adjectives.

**How it works.**

**Layer 1 — Supervised risk classification (D16).** Gradient-boosted trees over the 50-feature cryptographic
vector from S7. Training labels come from the rule engine acting as a **labelling oracle over synthetically
generated feature combinations** — a standard weak-supervision setup. Output is a calibrated risk probability plus
**SHAP values**, rendered as a waterfall: *"0.87 risk — RC4 cipher +0.31, expired certificate +0.24, no forward
secrecy +0.19, submission port +0.08."* The explanation is the deliverable; the number alone is worthless to an
analyst.

**Layer 2 — Unsupervised anomaly detection (D17).** Isolation Forest over the same feature space, plus **JA3/JA3S
fingerprint rarity** computed across the capture. This learns what *this organisation* normally does and flags the
outlier: the one server out of forty negotiating a suite nobody else negotiates, the client fingerprint that
appears exactly once. **No labels required**, which is precisely why it can catch things our rules don't encode.

**Layer 3 — LLM remediation generation (O02).** Findings are passed as structured facts to a language model that
produces an executive narrative and **working configuration snippets** for Postfix, Dovecot and Exchange. Strictly
grounded in extracted evidence, with a deterministic template fallback so the demo cannot fail on a network
timeout.

**Why others won't have it.** Most will ship one supervised model with no explanation layer and no unsupervised
component, and will have no answer to the if-else question.

**Demo moment.** Two screens: the SHAP waterfall explaining a score, then the anomaly lane highlighting the one
weird server in a fleet of forty with the caption *"no rule fired here — the model flagged it because it doesn't
look like anything else you run."*

**Build cost.** Low for layers 1–2 (scikit-learn, CPU, no GPU, no labelled corpus needed). Half a day for layer 3.

**If a judge pushes back** ("your model just learned your own rules"): *On the training distribution, yes — that is
deliberate, and it makes the model auditable, because we can prove what it learned. The value is in the three
things it does that the rules cannot: it produces a continuous ranking across thousands of sessions so an analyst
knows what to fix first; the unsupervised layer flags anomalies against a learned baseline with no rule at all; and
the classifier generalises to feature combinations we never wrote a rule for. We also report per-rule precision and
recall against ground truth — see USP-07 — which most people can't.*

---

## USP-05 · Post-Quantum Readiness Assessment

**Pitch:** *We report how much of your mail infrastructure is ready for post-quantum key exchange. The answer today
is almost certainly zero percent — and for archived email, "harvest now, decrypt later" makes that a present-tense
problem, not a future one.*

**Gap it fills.** Nobody else will have this slide. NIST finalised ML-KEM (FIPS 203) in August 2024, hybrid key
exchange is shipping in browsers and TLS libraries, and email infrastructure is essentially untouched by it. Email
is also the *worst* case for harvest-now-decrypt-later, because organisations retain mail for years and its
sensitivity does not decay.

**How it works.** The `supported_groups` extension in the ClientHello and the selected group in the ServerHello are
already parsed for D07. We simply also check them against the hybrid PQ codepoints in the IANA TLS Supported Groups
registry (`X25519MLKEM768` and the earlier `X25519Kyber768` draft group — *verify current codepoints against IANA
at build time rather than hardcoding from memory*). Output is a fleet-level PQ-readiness percentage, a per-session
flag, and a migration recommendation.

**Why others won't have it.** It requires knowing the PQ transition is happening. It is not in the PS text at all —
which is exactly why it reads as insight rather than compliance.

**Demo moment.** A single fleet tile: **"Post-Quantum readiness: 0 of 40 servers."** Then the line: *"Every message
in this capture is being archived by anyone on the path, to be decrypted when a cryptographically relevant quantum
computer exists. For a government mail system with a twenty-year retention policy, that is a today problem."*

**Build cost.** About 20 lines, because the parsing already exists for D07.

**If a judge pushes back** ("this is speculative"): *The threat is speculative; the migration is not. NIST published
the standards, the IETF assigned the codepoints, and browsers already negotiate hybrid groups by default. We're
reporting an observable fact about the infrastructure — whether it offers these groups — and every organisation
with a long retention requirement needs that number.*

---

## USP-06 · Four Reports, One Analysis — persona-aware output

**Pitch:** *The PS names four different users. We give each of them a different artifact from the same analysis,
because a SOC analyst and a mail administrator need opposite things.*

**Gap it fills.** Everyone will build one report. But a SOC analyst at 2am needs a ranked queue; a forensic
examiner needs evidence and hashes; an incident responder needs a timeline; a mail administrator needs a config
diff they can paste. One document serves none of them well.

**How it works.** A single `Assessment` object renders through four templates at S10:

| Persona | Artifact | Answers |
|---|---|---|
| **SOC analyst** | Ranked triage queue, severity × exploitability, with the anomaly lane | *What do I look at first?* |
| **Digital Forensics** | Evidence packet — capture hash, per-finding frame/offset references, certificate fingerprints, full chain of custody | *Can I prove this?* |
| **Incident Response** | Chronological session timeline of encryption transitions, exposures and attack evidence | *What happened, in what order?* |
| **Enterprise admin** | Per-host configuration diff with Postfix / Dovecot / Exchange snippets and a remediation checklist | *What do I paste to fix it?* |

**Why others won't have it.** The four personas are one clause in the PS background. Almost nobody will notice that
it's a specification.

**Demo moment.** One click cycling the same finding set through four views. *"Same analysis, four audiences — the
four the problem statement names."*

**Build cost.** Low — templating over an existing data model. Highest perceived-thoughtfulness per hour.

---

## USP-07 · Ground-Truth Testbed and Measured Accuracy

**Pitch:** *We built the lab that generates our own labelled captures, so unlike almost anyone else here, we can
tell you our tool's precision and recall — with numbers.*

**Gap it fills.** The dataset guidance says *synthetic — generate your own captures*. Most teams will read that as
"we have to make some test files." It is actually permission to **own the ground truth**, and that unlocks the
question every technical judge eventually asks: *how do you know it works?* The normal hackathon answer is a shrug.

**How it works.** A `docker-compose` testbed spins up mail servers with deliberately chosen cryptographic
configurations — specific TLS versions, cipher suites, key sizes, certificate validity windows, STARTTLS behaviour
— driven by a manifest. Each generated PCAP ships with a sidecar `.truth.json` stating exactly what was
configured. A regression harness runs the full pipeline across the corpus and reports:

- Per-rule precision and recall against known ground truth
- Protocol identification accuracy across all seven port/protocol combinations
- Classifier performance on a held-out split
- End-to-end runtime per megabyte of capture

**Why others won't have it.** It requires treating data generation as infrastructure rather than as a chore, and
building it on day one rather than the night before.

**Demo moment.** A metrics slide with actual numbers, and the line: *"This is reproducible — one command rebuilds
the entire corpus and re-runs the evaluation."* Then: *"And because the testbed is a manifest, we can generate a
capture for any misconfiguration you'd like to see us catch. Name one."* That invitation, if we're confident, is
the strongest possible close.

**Build cost.** Half a day on day 1, and it pays for itself immediately because the demo corpus and the ML
validation set both come out of it.

**If a judge pushes back** ("synthetic data proves nothing about real traffic"): *Fair — synthetic data proves our
detection logic is correct, not that the world looks like our lab. So we validate on two axes: our own labelled
corpus for correctness, and public real-world captures for robustness. The PS itself specifies synthetic data as
the dataset, and owning the labels is the advantage that comes with that.*

---

# TIER 2 — Build if on schedule; present regardless

These belong on the roadmap slide even if unbuilt, and each is cheap enough to finish if day 4 goes well.

## USP-08 · Compliance Report Card

Every finding already carries `standards[]`. Aggregating that field produces a per-standard pass/fail scorecard:
**RFC 8996** (TLS 1.0/1.1 deprecated), **RFC 9325 / BCP 195** (TLS recommendations), **RFC 8314** (implicit TLS for
submission and access), **RFC 7525**, **NIST SP 800-52 Rev 2**, **CIS Benchmarks**, **PCI-DSS 4.0**, and **CERT-In
guidance**.

*The CERT-In and Indian-standards citation is a deliberate scoring lever* — SIH judging panels are
government-adjacent, and demonstrating awareness of the national compliance regime lands differently from citing
only IETF documents. **Cost: a YAML table.** Do this one.

## USP-09 · Attack Feasibility Matrix

Map findings to named attacks with a feasibility verdict rather than a generic warning: *Sweet32 — feasible (3DES
with long-lived sessions observed)*, *Logjam — feasible (1024-bit DH parameters)*, *BEAST — feasible (TLS 1.0 CBC)*,
*POODLE — not applicable (no SSLv3 observed)*, *CRIME — not applicable (compression disabled)*, *Lucky13*,
*Heartbleed exposure*, *RC4 biases*. Converts a checklist into a threat model, and gives the PPT a memorable table.
**Cost: a lookup table.**

## USP-10 · Temporal Posture Drift

Ingest two captures from different dates and diff the posture: *"Grade fell from B+ to C on 14 March — mail-03 was
redeployed with a 1024-bit key."* Turns a one-shot analyser into a monitoring capability, and is nearly free if the
data model carries capture timestamps from the start.

## USP-11 · Passive DNS Policy Correlation (DANE / MTA-STS)

If the capture contains DNS traffic, extract **TLSA records** (RFC 6698 / 7672) and **MTA-STS policy TXT records**
(RFC 8461), then check whether the observed TLS sessions actually honour the published policy. Detects the
high-value failure "you published a strict MTA-STS policy and your traffic violates it." Fully passive, deeply
email-specific, and essentially nobody will think of it.

---

# TIER 3 — Roadmap slide only

A credible roadmap scores points on its own. These are named, scoped and explicitly deferred.

| # | Item | One line |
|---|---|---|
| 12 | **DKIM cryptographic assessment** | In cleartext sessions the `DKIM-Signature` header is visible; `a=rsa-sha1` and 1024-bit selectors are real weaknesses (RFC 8301). The *one* defensible intersection with email authentication, because it is genuinely about key strength |
| 13 | **JA4 / JA4S fingerprinting** | Successor to JA3 with better resistance to extension shuffling |
| 14 | **Session resumption and 0-RTT analysis** | Ticket reuse, ticket lifetime, and 0-RTT replay exposure |
| 15 | **Certificate Transparency correlation** | Check observed certificates against CT logs; flag issuers inconsistent with the organisation's norm |

---

## 4. The "where is the AI?" defence — say it in this order

This question *will* be asked. The order matters.

1. **"Rules find what we already know. That's necessary but it's not the hard part."**
2. **"The classifier ranks."** Thousands of sessions, one analyst, one morning. A continuous learned risk score
   orders the queue in a way severity labels cannot — and SHAP shows exactly why each item sits where it does.
3. **"The anomaly layer baselines."** Isolation Forest plus JA3 rarity learns what this organisation normally does
   and flags deviation *with no rule at all*. This is the part that catches what we didn't anticipate.
4. **"The classifier generalises."** It scores feature combinations we never wrote a rule for.
5. **"The LLM translates."** Structured findings become an executive narrative and a working config snippet,
   grounded strictly in extracted evidence.
6. **"And we measured it."** Per-rule precision and recall against ground truth from our own testbed (USP-07).

Then the closing line: *"The rule engine is our labelling oracle — which makes the model auditable. We can tell you
exactly what it learned. Most ML security tools cannot."*

---

## 5. Anticipated hostile questions

| Question | Answer |
|---|---|
| "Why not just use Wireshark?" | Wireshark decodes; it doesn't judge, score, prioritise, or recommend. It shows one session at a time and has no concept of fleet posture |
| "Why not SSL Labs?" | It's an active scanner needing a live reachable endpoint. It cannot read a capture, cannot see STARTTLS behaviour, and cannot detect an attack that already happened |
| "Isn't this just if-else with an ML sticker?" | See §4 above |
| "Can you decrypt the traffic?" | No, and we shouldn't. The PS specifies *passive* assessment of *encrypted* traffic. Everything we report is observable without keys — and the handshake, which is what determines posture, is in the clear by design |
| "TLS 1.3 encrypts the certificate. How do you extract it?" | We don't, and we say so explicitly rather than showing a blank. For TLS 1.3 sessions we report the certificate as *opaque* — which is itself the good news — and assess everything still observable: version, groups, cipher, SNI, ALPN. Knowing this limitation is the point |
| "Your synthetic data isn't realistic" | It's the dataset the PS specifies, and owning the labels lets us report measured accuracy. We also validate against public real-world captures |
| "What if the PCAP is 10 GB?" | Streaming reassembly with bounded per-flow buffers; we report throughput per megabyte in the metrics. Full-capture aggregation is a second pass over summaries, not raw packets |
| "How is this different from the other 200 teams?" | Role-aware severity, attack evidence, byte-level provenance, and measured accuracy. Most will have parsed TLS correctly and stopped there |

---

## 6. USP → slide mapping

Suggested placement when building the deck.

| Slide | Content | USPs |
|---|---|---|
| 3 | The gap — why existing tools fail | §3 positioning table |
| 4 | Solution overview + architecture | — |
| 6 | Where the AI is | USP-04 |
| 7 | Anomaly detection and fleet baselining | USP-04 layer 2 |
| 8 | **Email-aware scoring** | **USP-01** |
| 9 | **Attack evidence, not just weak config** | **USP-02** |
| 10 | Forensic provenance | USP-03 |
| 11 | Compliance report card | USP-08 |
| 12 | Post-quantum readiness | USP-05 |
| 13 | Four personas, four reports | USP-06 |
| 14 | **Measured accuracy** | **USP-07** |
| 15 | Dashboard screenshots | — |
| 16 | Limitations and roadmap | Tier 3 + TLS 1.3 cert opacity |

**If the deck must be short, the three that cannot be cut are USP-01, USP-02 and USP-07** — email-awareness,
attack evidence, and proof that it works.
