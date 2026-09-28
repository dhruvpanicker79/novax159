# 08 — The pitch, with sources

Material for the six-slide SIH idea submission and the viva behind it. Everything numeric in here has a source
in §8. Nothing in here is an estimate unless it says so.

Written after reading six SIH decks that went through (two 2024 winners, two 2025, two from the DJ teams) and
after checking every paper our own docs cite. Two of those citations were slightly wrong; see §9.

---

## 1. The template, and where your five slides sit in it

The official idea-submission deck is six slides and every one of the six decks I read used it unchanged:

| Slide | Official heading | Your numbering |
|---|---|---|
| 1 | Title page — PS ID, PS title, theme, category, team ID, team name | — |
| 2 | Idea / proposed solution | your 1 |
| 3 | Technical approach | your 2 |
| 4 | Feasibility and viability | your 4 |
| 5 | Impact and benefits | your 3 |
| 6 | Research and references | your 5 |

Two things to fix in your plan: you have no title slide, and you have impact before feasibility. Keep the
official order. Reviewers read hundreds of these against a rubric that follows the headings, and a deck that
reorders them reads as careless before anyone has assessed the idea.

**Who is judging this one.** PS **SIH26159** is from the **National Technical Research Organisation**. That is
India's technical intelligence body, and NCIIPC — the agency responsible for protecting critical information
infrastructure — sits under it. This changes the pitch. NTRO's people work with captures from networks they
cannot touch, on machines that are not on the internet, and their output has to survive scrutiny. So:

- "Passive, offline, nothing decrypted, nothing leaves the box" is not a limitation to apologise for. It is the
  requirement.
- A slide full of cloud logos (Vercel, AWS, Slack webhooks, Kubernetes) is a wrong answer here, however
  impressive it looks. Our `dpkt`-only, standard-library build installs on an air-gapped machine where nothing
  else will. Say that out loud.
- The PS itself asks that every finding be reported as OBSERVED / NOT_FOUND / UNKNOWN /
  INSUFFICIENT_EVIDENCE. That is ADR-0014 word for word. We are not being clever, we are being compliant —
  and most teams will skip it because an empty panel looks better than an honest one.

---

## 2. What the winning decks actually do differently

Read six of them. The gap between a deck that gets through and one that does not is smaller and more
mechanical than you would think.

**They give the product a name.** Asha, Margdarshak, PURVA, DrishyamAI, CIS Kurukshetra, Transformo Docs. Six
for six. Four used a Hindi or Sanskrit name. Nobody presented "our solution for PS 1683". A name gives the
judge a handle to argue about your work with the other judges after you leave the room.

Our name should be **Sakshi** — साक्षी, *witness*. It is the one word that describes what the tool actually
does: it witnessed the traffic and it can prove what it saw. It also sits next to the Bharatiya **Sakshya**
Adhiniyam, the evidence law our reports are built to satisfy (§6). Alternative: **Pramaan** (proof) — check for
clashes with existing government branding before using it. Keep "SecureMailScope" on the title slide as the PS
title; put the name on slide 2.

**There is a number on every slide.** PURVA: "permit verification delays cut by >90%", "40–60% fewer safety
incidents". DODS: "25% cost saving", "processing time down 40%". None of those are sourced and most are
guesses. Do not copy that habit — with NTRO on the other side of the table, invented precision is a liability.
Copy the *habit of quantifying* and beat them on sourcing: we have published measurements for the problem and
our own tool's output for the solution.

**Slide 6 is where the good decks separate from the rest.** The best single slide in all six is Code Omega's
references slide: a table of **Paper | Approach | Dataset | Accuracy**, five rows, real numbers. It takes ten
seconds to read and it tells the judge "these people read the literature". Compare Cyber Kurukshetra (PS 1679,
also Blockchain & Cybersecurity, the closest analogue to us) whose reference slide is five bare URLs. That is
the bar in our theme, and it is low.

We do the same table and add one column — *what we took from it* — plus one row for our own measured numbers.
No other team will put their own numbers in that table.

**They put live links on the slides.** DODS shipped a working MVP link on slide 2. Enthalpy put dataset, API
and Colab links on slide 4. PURVA and Asha linked a Figma and a research doc. A clickable link is a claim the
judge can check, and judges check maybe one of them — which is exactly why it works.

**Feasibility is always a two-column Challenge → Solution table.** Six for six. Do not invent a format.

**They name the government systems they plug into.** FOIS and the IRCTC API (Enthalpy). Aadhaar, DigiYatra,
API Setu, NIC Cloud (PURVA). DISHA and the DPDP Act (Asha). "Integrates with existing systems" scores nothing;
"reads from the 180-day log store CERT-In already mandates" scores. Our list is in §5.

**What none of the six did, which is our opening:**

1. Not one reported *its own* measured accuracy. Code Omega's accuracy table is other people's papers. If we
   report per-rule precision and recall from our own corpus, we are doing something none of six shortlisted
   decks did.
2. Not one addressed whether its output would stand up as evidence. Ours is built for it.
3. The cybersecurity deck was the weakest of the six. Generic impact wheel, no numbers, link-dump references.

---

## 3. Slide 2 — Idea: problem, solution, novelty, USP, user flow

### The problem, in plain words

Four sentences, in this order, is the whole story:

> Mail servers were retro-fitted with encryption, and the retro-fit was designed to fail quietly. When
> encryption cannot be negotiated, mail is sent in plain text and nobody is told. Attackers have been
> exploiting that silence for a decade. And the tools that could find it need to connect to your server from
> outside — which means nobody is checking the traffic that actually left the building.

### The numbers to put on the slide

Pick four. These are the strongest:

- **Only 35% of mail servers are configured so the other end can verify who they are talking to.** Of roughly
  700,000 SMTP servers behind the Alexa top million, 82% offered encryption but only 35% were set up properly
  enough for authentication to work (Durumeric et al., IMC 2015 — a Google + University of Michigan study).
- **41,405 mail servers, in 4,714 networks across 193 countries, were observed having their encryption
  stripped on the wire.** In Tunisia, 96.13% of mail sent to Gmail was pushed back to plain text. Seven
  countries were above 20%. Of the 423 networks where every mail server showed this behaviour, 7.1% were
  government networks and 13.5% were financial (same paper).
- **The fix exists and nobody has deployed it.** MTA-STS, the standard that tells senders "never downgrade my
  mail", is on 0.07% of `.com` and 0.12% of `.org` domains. Of the 68,000 domains that do publish it, **29.6%
  got it wrong** and 3.2% are misconfigured badly enough to lose mail (Ashiq, Fiebig & Chung, IMC 2025 — 87
  million domains, 31 months). The alternative, DANE, is capped by DNSSEC's ~4% adoption. Even the
  Netherlands, which pushes hardest on this, sits at 14% DANE and 6% MTA-STS.
- **Email is the part of the internet furthest behind on quantum readiness.** Across 4,665 UK organisations,
  44.0% of web endpoints offered a post-quantum key exchange — against **6.4% of mail endpoints**. Not one
  post-quantum certificate was found anywhere (Loizou & Ghadafi, August 2026).

And two for the "why should anyone pay for this" reflex:

- Business email compromise cost **$3.04 billion** in reported losses in 2025, the second-largest loss
  category in the FBI's figures, across 24,768 complaints — about $123,000 an incident.
- CERT-In handled **29.44 lakh incidents in 2025**, of which **3,41,646 were vulnerable exposed services** —
  the exact category this tool produces evidence for.

### The solution, in one line the judge can repeat

> Give it a capture of your mail traffic. It tells you every cryptographic weakness in it, ranked by how much
> that weakness actually matters on that port, with the frame numbers to prove each claim. Nothing is
> decrypted and nothing leaves the machine.

### Novelty — four claims, each defensible

1. **Severity that understands mail.** The same expired certificate is a footnote on port 25 and an emergency
   on port 993. On port 25 two mail servers relay to each other under opportunistic security, where RFC 7435
   says some encryption beats none. On port 993 a human's password crosses the link, and RFC 8314 says that
   must be properly protected. Generic TLS scanners apply web rules to mail, flag both identically, and bury
   the administrator in alarms they learn to ignore. Our severity table writes its own plain-English
   justification into every finding it adjusts.
2. **Evidence of attacks, not just a list of weak settings.** Five detectors that work without decrypting
   anything: STARTTLS capability stripping (including the same-length `250-XXXXXXXA` rewrite — the exact trick
   Durumeric's team documented in the wild), credentials recovered from traffic that was never encrypted, the
   RFC 8446 downgrade sentinel, a cipher-intersection contradiction that needs both halves of a handshake to
   spot, and the same certificate appearing where it should not.
3. **Every finding is checkable.** Capture SHA-256, stream index, frame numbers, byte offsets. Open the PCAP
   in Wireshark, go to that frame, see the claim. This matters legally, not just rhetorically: under section
   63 of the Bharatiya Sakshya Adhiniyam 2023, electronic evidence needs a certificate stating the record's
   hash value, and courts are being told to treat a hash mismatch as presumptive tampering. Our report can
   fill that certificate in.
4. **It tells you what it could not see.** TLS 1.3 encrypts the certificate, so we report `OPAQUE_TLS13` with
   the reason instead of an empty panel that reads as "no certificate found". A host whose handshake could not
   be parsed is graded `?` and never `A+`.

Optional fifth, if we build it (and it is worth building, see §5): the tool produces a **cryptographic
inventory of the mail estate** in the CycloneDX CBOM format, now standardised as ECMA-424.

### USP — why ours and not the four other teams building this

Say this without naming anyone: **it runs where the others cannot.** One pure-Python dependency, everything
else standard library, no compiled extensions, no model download, no network calls, no container required. We
wrote our own X.509 parser and our own TLS parser because we had to, and the side effect is a tool that
installs on a sealed government machine in one command. The competing approach — scikit-learn, Scapy,
PostgreSQL, Redis, React on Vercel, a backend on Railway, Slack and Jira webhooks — cannot be deployed in the
environment this PS comes from.

Supporting facts for that slide: 13,300 lines of Python, 168 tests passing, 33 detection rules each carrying
its standards citation and a copy-pasteable config fix, one self-contained HTML file as the report and the
dashboard.

### User flow

Keep it to five boxes and put the pipeline detail on slide 3:

    authorised capture  →  sessions rebuilt  →  crypto facts extracted  →  findings ranked  →  report + fix snippets

Underneath, three names: analyst drops a capture, administrator gets the config change, auditor gets the
evidence pack. If the domain-lookup mode gets built, add a second entry arrow labelled "or just a domain name"
— the PS asks for both.

---

## 4. Slide 3 — Technical approach

### The diagram is the slide

All six decks put a diagram in the middle of slide 3 with text around the edges. Use the twelve-stage
pipeline from `03_ARCHITECTURE.md`:

    PCAP → ingest → TCP reassembly → protocol ID → STARTTLS state machine → TLS handshake → X.509
         → 33 rules → 51 features → AI layer (risk / anomaly / priority) → aggregation → JSON · HTML · PDF

### Algorithms — say what is actually interesting, not what is standard

Three of these are worth a sentence each because they are non-obvious choices a judge can probe:

- **Protocol identification from the server banner, not the port.** Mail runs on non-standard ports constantly.
  Port-based identification is the mistake every naive tool makes.
- **Byte-to-frame provenance carried through reassembly.** Every byte of every rebuilt stream remembers which
  packet it came from. That is what makes claim-checking possible, and it is designed in from the start
  because retro-fitting it is miserable (ADR-0004).
- **Our own DER and X.509 parser with real RSA signature verification.** Forced on us — the standard library
  for this is a compiled extension that this machine blocks (ADR-0017) — but a parser that allocates nothing
  and calls no C code is also the one you would rather feed a hostile certificate to.

Plus: JA3/JA3S client and server fingerprints, post-quantum group detection in the key-share extension, ten
STARTTLS state checks, 51 features per session, and a declarative severity policy table rather than severity
hard-coded into each rule.

### The AI answer — get this right, it is the most probed slide

The PS asks for XGBoost and Isolation Forest. Here is the honest position, and it is a stronger position than
it first looks:

> Two layers. The deterministic layer decides *what is true* — this handshake offered TLS 1.0, this
> certificate expired in March — because a cryptographic fact should never come from a probability. The
> learned layer decides *what to look at first*: risk scoring across the 51 features, anomaly detection
> against a fleet baseline, and priority ordering. Feature extraction, the corpus generator and the CSV export
> are finished; the classifier is trained off-box because this machine's toolchain blocks the numerical
> libraries, and the tool works fully without it.

Two papers make this design look deliberate rather than convenient, and they are recent:

- Singh, Kashyap & Cherukuri (2025) applied SHAP to anomaly detection on encrypted traffic precisely because
  an unexplainable verdict is useless for compliance. Their conclusion is our architecture's premise.
- INTACT (2026) reframes cryptographic violations as breaches of *declared policy* rather than statistical
  oddities, and reports near-perfect discrimination on real traffic. That is what our rules-plus-role-policy
  engine is. We can say our design matches where this research is heading instead of bolting a classifier onto
  a parser.

One line to defend the anomaly baseline honestly: building "normal" from a capture that contains the attacks
lets the attacks vote on what normal is, so the baseline is built in two passes with outliers rejected first.

### Stack

Python 3.11 · `dpkt` · standard library for everything else · no compiled extensions · one self-contained HTML
file for the report and dashboard · PDF renderer written in-house. Tests run without pytest.

### Standards checked against

NIST SP 800-52 Rev 2 and SP 800-45 Rev 2; RFC 7435 (opportunistic security), 8314 (mail access and
submission), 8461 (MTA-STS), 7672 (DANE for SMTP), 8460 (TLS reporting), 8996 (TLS 1.0/1.1 deprecated), 9325
(current TLS recommendations), 8446 (the downgrade sentinel); NIST IR 8547 for the post-quantum timeline.
Every one of the 33 rules names its clause.

---

## 5. Slide 4 — Feasibility and viability

### The strongest feasibility argument is that it already runs

Lead with it: 13,300 lines, 168 tests passing, 33 rules, the full pipeline from capture to report in one
command, and an audit script that verifies every deliverable and is run before and after every change. Most
idea-submission decks describe something that does not exist yet. Say plainly that ours does, and put the
command on the slide.

### Government integration — name names and dates

- **NIC.** Under the E-mail Policy of the Government of India (2015, reissued 2024), official government mail
  must go through NIC. One operator, one estate — a single deployment covers it.
- **CERT-In.** The 2022 directions require incidents reported within **six hours** and ICT logs kept **180
  days, inside India**. The captures and logs already exist by law; what is missing is the thing that turns
  them into a report before the six hours are up.
- **NCIIPC**, under NTRO, for critical-sector mail infrastructure.
- **The post-quantum deadline, which is the real opening.** The Department of Science and Technology's task
  force under the National Quantum Mission published India's PQC migration roadmap in **February 2026**:
  preparatory stage — *inventory cryptographic assets and assess quantum risk* — by **2027** for critical
  information infrastructure, high-priority migration by 2028, full adoption by 2029, and **Cryptographic
  Bills of Materials required from vendors starting FY 2027–28**. MeitY, CERT-In and SISA had already set
  this direction in a July 2025 whitepaper. The UK's NCSC says the same thing with a 2028 date; NIST IR 8547
  deprecates RSA-2048 and P-256 after 2030 and disallows them after 2035.
  **Every one of those timelines starts with discovery, and for mail there is no discovery tool.** That is the
  sentence to say out loud.
- **SEBI's CSCRF** (August 2024) requires TLS 1.2 or better for data in transit across regulated entities —
  and gives them no way to prove it for mail.
- **231 CERT-In empanelled audit organisations** are the distribution channel; they need tooling, not another
  dashboard.

### Challenges and solutions — the two-column table

| Challenge | What we do about it |
|---|---|
| TLS 1.3 encrypts the certificate, so we cannot always see it | Report `OPAQUE_TLS13` with the reason and grade the host `?`, never `A+`; keep assessing what is still visible — version, key-exchange groups, server fingerprint, name in SNI |
| The environment blocks the numerical libraries, so we cannot train on this machine | Features, corpus generator and CSV export are done; train off-box; the deterministic engine carries the tool without a model |
| A baseline built from a capture containing attacks treats the attacks as normal | Two-pass baseline with outlier rejection before the second pass |
| No public ground truth exists for "mail sessions with known crypto weaknesses" | A synthetic corpus with a manifest of expected findings per capture, so precision and recall are computable per rule; cross-check the handshake parse against `tshark` on the same capture |
| Security tools that cry wolf get switched off | Role-aware severity — the entire point of the tool |
| Capturing mail traffic is legally sensitive | Authorised captures only, nothing decrypted, no message content copied, recovered credentials redacted by default, everything stays on the machine. Under the DPDP Rules notified 13 November 2025 a breach needs a detailed report within 72 hours; a tool that never copies content is far easier to clear for use |

### Money, honestly

Core engine open source, because government adoption needs source availability. Paid on top: a continuous
sensor with a fleet view, an annual posture attestation that empanelled auditors can put their name to, and a
CBOM subscription as the 2027–28 vendor requirement lands.

Market anchors — label these as vendor market research on the slide, because that is what they are: the India
email security market is put at $0.427B in 2025 rising to $1.31B by 2035 (11.82% CAGR); the post-quantum
cryptography market at $810M in 2025 to $18.19B by 2035. The comparable products in cryptographic discovery —
IBM Quantum Safe Explorer, SandboxAQ AQtive Guard, Keyfactor's AgileSec (InfoSec Global) — all work from
source code, containers or host agents. None works passively from mail traffic.

---

## 6. Slide 5 — Impact and benefits

Three audiences, one concrete thing each. Resist the ten-bullet benefits list that two of the six decks fell
into; it reads as padding.

**Government.** A capability that does not exist today: point it at mail traffic from any estate, including
one you are not allowed to touch, and get back a ranked list of cryptographic weaknesses with evidence
attached. It answers the question CERT-In's six-hour clock asks, and it produces the cryptographic inventory
the 2027 roadmap milestone requires.

**The mail administrator.** Not a lecture — the config lines to paste, per finding, per server software, with
the RFC that explains why. And 33 findings sorted so the three that matter are at the top instead of
alphabetically.

**The investigator.** Five attack detectors, recovered plaintext credentials as proof of exposure rather than
a theory of it, and an evidence pack whose hashes and frame numbers hold up under section 63.

**Quantifying it.** Only two kinds of number belong here. Published ones: BEC at $3.04B, 6.4% of mail servers
quantum-ready against 44% of web servers, 29.6% of MTA-STS deployments broken. And our own measured ones: how
many findings from a capture, how long a run takes, precision and recall per rule. If you want a projection,
say "projected" on the slide.

### SDGs

Two, argued properly, beats six listed. Judges have seen the six-SDG slide and it reads as filler.

- **SDG 9 — resilient infrastructure.** Direct. The ITU's own framing puts strengthening cybersecurity inside
  Goal 9, and target 9.c's push for universal ICT access only works if the infrastructure underneath is
  trustworthy.
- **SDG 16 — strong institutions.** Two targets, both genuinely ours: 16.6, effective and accountable
  institutions, because evidence-linked findings are what accountability is made of; and 16.4, reducing
  illicit financial flows, which is precisely what $3.04B of business email compromise is.

Secondary, if you need a third: SDG 8.2, productivity through technological upgrading.

---

## 7. Slide 6 — Research and references

### Build the table Code Omega built, then add a column

| Paper | What they measured | The number | What we took |
|---|---|---|---|
| Durumeric et al., IMC 2015 | STARTTLS in the wild, Gmail + Alexa top million | 41,405 servers stripped; 96.13% of Tunisian mail downgraded; only 35% of 700K servers authenticate properly | The stripping detector, including the same-length rewrite; the whole problem statement |
| Ashiq, Fiebig & Chung, IMC 2025 | MTA-STS across 87M domains, 31 months | 0.07–0.12% adoption; 29.6% of deployments misconfigured | Why the MTA-STS/DANE check is worth building, and why "has a policy" is not the same as "works" |
| Holz et al., NDSS 2016 | Internet-wide TLS across SMTP, IMAP, POP3, XMPP | The reference study for mail-protocol TLS, active scanning plus passive monitoring | Method: pair what servers *offer* with what clients *do* |
| Loizou & Ghadafi, 2026 | Post-quantum TLS across 4,665 UK organisations | 44.0% of web vs **6.4% of mail** endpoints; zero PQ certificates | The quantum-readiness gap, and the case for the PQ group detector |
| Measurement Study of Post-Quantum Readiness of the Internet, 2026 (arXiv 2606.16473) | 32,011 domains | 49.3% support hybrid PQ key exchange; 0% PQ certificates; 15.7% still on TLS 1.2 | Report key exchange and certificates as two separate stories, because they are |
| Singh, Kashyap & Cherukuri, 2025 | SHAP on encrypted-traffic anomaly detection | Interpretability as a compliance requirement | Why the AI layer explains itself |
| INTACT, 2026 (arXiv 2602.21252) | Crypto violations as policy breaches, not statistical outliers | AUROC up to 1.0000 on real flows | Validation of the rules-plus-policy design |
| Jafari Siavoshani et al., *Soft Computing* 2023 | Which TLS handshake fields carry signal | — | The shape of the 51-feature vector |

### Accuracy — read this before you write anything on the slide

**We do not have precision and recall numbers yet.** `scripts/evaluate.py` raises `NotImplementedError`. The
manifest states expected findings per capture and the pipeline produces actual findings, so this is a
comparison loop and a couple of hours of work. **Do it before the deck goes in.** A claimed differentiator
with no data behind it is worse than not claiming it, and one of the competing public repositories is already
claiming "100% precision and recall on a labelled corpus".

When you have the numbers, phrase them like this, and the honesty is the differentiator:

> Per-rule precision and recall against a corpus of 18 captures with declared expected findings. The corpus is
> ours, so this measures whether the implementation does what the rules say — not field accuracy, which would
> need labelled real-world captures that do not publicly exist. Where a rule cannot fire because the evidence
> is encrypted, it is counted as insufficient evidence rather than as a miss.

Anyone who claims field accuracy from a synthetic corpus is either confused or hoping you are.

### Datasets

Say what we use and why, and be straight about the gap — "we built the dataset because the dataset does not
exist" is a good answer, delivered confidently.

- **Ours.** `testbed/synth.py` writes PCAPs byte by byte; `testbed/certgen.py` issues real signed
  certificates; `testbed/manifest.json` declares the expected findings for 18 captures. This is what makes
  evaluation possible at all.
- **Public corpora to validate against.** CIC-IDS2017 (48.8 GB, five days, 25 simulated users, email
  protocols included) and CSE-CIC-IDS2018; UNSW-NB15; the Stratosphere/CTU malware captures; Netresec's and
  malware-traffic-analysis.net's published PCAPs; Wireshark's own sample captures for SMTP, IMAP and POP3;
  MAWI for volume, with the caveat that it is headers only.
- **The honest gap.** No public corpus exists of mail sessions labelled with cryptographic weaknesses. Most
  intrusion-detection corpora are built for attack classification, and several are header-only, so they cannot
  exercise a certificate parser. Hence the synthetic corpus, and hence the cross-check against `tshark` on the
  same bytes as an independent second opinion on our parser.

### Policy — past, present, future, on one line each

| When | What | Why it matters to us |
|---|---|---|
| 2000 | IT Act, section 70B — creates CERT-In | The statutory basis for everything below |
| Feb 2015 | E-mail Policy of the Government of India | Official mail must use NIC |
| Apr 2022 | CERT-In directions | Six-hour incident reporting; 180 days of logs held in India |
| Jun 2023 | CERT-In guidelines for government entities | Dedicated mail servers, encrypted connections, SPF/DKIM/DMARC |
| Aug 2023 | DPDP Act | Consent and security obligations for personal data |
| 2023 | Bharatiya Sakshya Adhiniyam, s.63 | Electronic evidence needs a certificate stating its hash |
| Aug 2024 | SEBI CSCRF | TLS 1.2+ in transit for regulated entities |
| 2024 | E-mail Policy reissued | NIC-only mail reaffirmed |
| Jul 2025 | MeitY / CERT-In / SISA quantum-readiness whitepaper | Finance, defence and healthcare migrate first |
| Nov 2025 | DPDP Rules notified | Detailed breach report within 72 hours; penalties to ₹200 crore |
| **Feb 2026** | **DST / National Quantum Mission PQC roadmap** | **Crypto inventory for CII by 2027; CBOMs from vendors FY 2027–28; full PQC by 2029** |
| 2030 / 2035 | NIST IR 8547 | RSA-2048 and P-256 deprecated, then disallowed |

The shape of that table is the argument: everything before 2026 tells you to encrypt mail properly, and
nothing tells you how to check whether you did.

### Links to put on the slide

A public demo repository or release zip, a 90-second video, the sample HTML report (it is one self-contained
file — it will open from a link), a sample capture, and `docs/07_RELATED_WORK.md`. Four of the six decks did
this and it costs nothing.

---

## 8. What else I would add

1. **A name on slide 2.** §2.
2. **A before-and-after pair of screenshots for the severity engine.** Generic scanner output on the left,
   forty findings, all red. Ours on the right, three criticals and the reason each was raised or lowered. This
   is the single most persuasive image available to us and it proves the main novelty claim visually in two
   seconds. The dashboard already builds this panel.
3. **One falsifiable invitation.** Put a frame number on a slide: "finding F-07 is at frame 1,284 of
   `fleet.pcap`, byte offset 412 — open it and check". No other team will hand the judges a claim they can
   disprove, and doing it is worth more than any adjective.
4. **A three-line threat model:** what we can see, what we cannot, and what we therefore refuse to say. NTRO
   evaluators will respect this more than a feature list, and it inoculates you against the "TLS 1.3 hides
   everything, so what is the point?" question.
5. **A competitive table** naming the alternatives — SSL Labs and testssl.sh (web, active), internet.nl (mail,
   active, and it does not even test MTA-STS), CheckTLS (active), Zeek with JA4 (passive, but logs facts
   rather than assessing posture) — with a column for "works from a capture" and one for "works offline". The
   pattern is immediately visible.
6. **The evidence certificate as a real artefact.** A generated annexe matching what section 63 asks for. It
   takes an afternoon and it is the kind of detail that makes an evaluator believe the rest.
7. **A cryptographic inventory export (CBOM).** The single highest-value unbuilt feature, because the
   February 2026 roadmap makes it a requirement with a date on it.
8. **Fix `evaluate.py` first.** Highest-value two hours available to this project.

### What not to put on the deck

- No claim of a trained model until one is trained. "Training runs off-box, the tool works without it" is a
  fine answer; a fabricated accuracy figure in front of NTRO is not.
- No invented percentages. If it is a projection, write "projected".
- No cloud architecture diagram. See §1.
- Not six SDGs.
- Don't say "AI-powered" more than once. The PS already says it; repetition reads as compensation.

---

## 9. Judge questions worth rehearsing

**"Isn't this just testssl.sh or SSL Labs?"** Those connect to a server from outside and ask what it will
agree to. We read what actually happened — which session really fell back to plain text, which credential
really crossed unencrypted. They also need reachability and permission; we need a file. And no active scanner
can tell you about the traffic that left last Tuesday.

**"TLS 1.3 hides the certificate. So what can you actually see?"** Version, cipher suite, key-exchange groups
including post-quantum ones, client and server fingerprints, the name requested, session timing, and the
entire STARTTLS negotiation — which happens in clear text before any of it. And when we cannot see something
we say so and grade the host `?`. An empty panel that looks like a pass is the failure mode we designed
against.

**"Where is the AI?"** §4. Give the two-layer answer, then say why a cryptographic fact must never come from a
probability.

**"What is your accuracy?"** Per-rule precision and recall on our corpus, with the caveat stated. If
`evaluate.py` is still a stub on the day: "the manifest and the pipeline exist, the comparison is not wired up
yet, here is what we will report." Do not invent a number.

**"Who captured this traffic, and is that legal?"** Authorised captures only. We never decrypt, never copy
message content, and redact recovered credentials by default. The organisation running the mail server is
already required to keep 180 days of logs.

**"Why not just fix the servers?"** Because you cannot fix what you cannot see, and 29.6% of the
organisations that tried to fix it got it wrong.

**"You wrote your own X.509 parser. Why should we trust it over OpenSSL?"** We would not have chosen to — the
library was blocked on our machines. Two consequences: 168 tests including signature verification against
certificates we generated, and cross-validation against `tshark`. And a parser that allocates nothing and
calls no C code is the one you would rather point at an attacker's certificate.

**"What if the capture is truncated or the handshake is incomplete?"** Insufficient evidence, stated as such,
with the host graded `?`. That path is tested.

---

## 10. The competitive field

**Tools.** SSL Labs and testssl.sh (web, active). internet.nl (mail, active — and it does not test MTA-STS at
all). CheckTLS (active). Zeek with the JA4 package (passive, and the closest thing to us — but it logs
handshake facts, it does not assess posture, rank findings, or produce remediation). Commercial crypto
discovery — IBM Quantum Safe Explorer, SandboxAQ AQtive Guard, Keyfactor AgileSec — works from source code,
containers or host agents, never from mail traffic.

**Other SIH teams.** At least five public repositories are working PS 159 right now, and two are substantial:
one 19-rule engine with a React dashboard, Postgres, Redis, Celery and webhook integrations that claims 100%
precision and recall on a labelled corpus; and another passive analyser with a 0–100 letter-graded score and
an Isolation Forest over JA3/JA4, with no accuracy numbers published.

Read against those, our defensible ground is exactly the four novelty claims in §3 plus the deployment story
in §3's USP paragraph: 33 rules against 19, role-aware severity that nobody else has, evidence linked to
frames and bytes, honest reporting of what could not be seen, and one dependency instead of a cloud stack.
What we must not do is compete on dashboard polish or on unverified accuracy claims.

---

## 11. Sources

Papers

- Durumeric, Adrian, Mirian, Kasten, Bursztein, Lidzborski, Thomas, Eranti, Bailey, Halderman. "Neither Snow
  Nor Rain Nor MITM… An Empirical Analysis of Email Delivery Security." IMC 2015.
  https://doi.org/10.1145/2815675.2815695 · PDF: https://conferences2.sigcomm.org/imc/2015/papers/p27.pdf
- Ashiq, Fiebig, Chung. "Unraveling the Complexities of MTA-STS Deployment and Management in Securing Email."
  IMC 2025. https://doi.org/10.1145/3730567.3732916 · PDF:
  https://taejoong.github.io/files/publications/ashiq-2025-mtasts.pdf
- Poddebniak, Ising, Böck, Schinzel. "Why TLS is better without STARTTLS: A Security Analysis of STARTTLS in
  the Email Context." USENIX Security 2021. https://www.usenix.org/system/files/sec21-poddebniak.pdf
- Lee, Ashiq, Müller, van Rijswijk-Deij, Kwon, Chung. "Under the Hood of DANE Mismanagement in SMTP." USENIX
  Security 2022. https://www.usenix.org/system/files/sec22-lee.pdf
- Mayer, Zauner, Schmiedecker, Huber. "No Need for Black Chambers: Testing TLS in the E-mail Ecosystem at
  Large." ARES 2016. https://arxiv.org/abs/1510.08646
- Sommer, Paxson. "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection." IEEE
  S&P 2010.
- Li, Durumeric, Czyz, Karami, Bailey, McCoy, Savage, Paxson. "You've Got Vulnerability: Exploring Effective
  Vulnerability Notifications." USENIX Security 2016.
  https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_li.pdf
- Foster, Larson, Masich, Snoeren, Savage, Levchenko. "Security by Any Other Name: On the Effectiveness of
  Provider Based Email Security." ACM CCS 2015. https://klevchen.ece.illinois.edu/pubs/flmssl-ccs15.pdf
- Holz, Amann, Mehani, Wachs, Kaafar. "TLS in the Wild: An Internet-wide Analysis of TLS-based Protocols for
  Electronic Communication." NDSS 2016. https://arxiv.org/abs/1511.00341
- Loizou, Ghadafi. "Measuring Post-Quantum TLS Deployment Across UK Internet Sectors." arXiv 2608.02147 (Aug
  2026). https://arxiv.org/abs/2608.02147
- "Measurement Study of Post-Quantum Readiness of Internet: 2026." arXiv 2606.16473.
  https://arxiv.org/abs/2606.16473
- "Mind the Gap: Policy vs Reality in Post-Quantum TLS Deployment." arXiv 2607.29005.
  https://arxiv.org/abs/2607.29005
- Singh, Kashyap, Cherukuri. "Interpretable Anomaly Detection in Encrypted Traffic Using SHAP with Machine
  Learning Models." arXiv 2505.16261. https://arxiv.org/abs/2505.16261
- "INTACT: Intent-Aware Representation Learning for Cryptographic Traffic Violation Detection." arXiv
  2602.21252. https://arxiv.org/abs/2602.21252
- Jafari Siavoshani et al. "Machine learning interpretability meets TLS fingerprinting." *Soft Computing* 27
  (2023) 7191–7208.

Standards

- NIST IR 8547, *Transition to Post-Quantum Cryptography Standards*.
  https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf
- NIST SP 800-52 Rev 2; NIST SP 800-45 Ver 2.
- RFC 7435, 8314, 8461, 7672, 8460, 8996, 9325, 8446.
- CycloneDX CBOM / ECMA-424. https://cyclonedx.org/capabilities/cbom/

India policy

- CERT-In Directions, 28 April 2022 (six-hour reporting, 180-day logs).
- CERT-In, *Guidelines on Information Security Practices for Government Entities*, 30 June 2023.
  https://www.cert-in.org.in/PDF/guidelinesgovtentities.pdf
- E-mail Policy of the Government of India.
  https://www.meity.gov.in/static/uploads/2024/02/E-mail_policy_of_Government_of_India_3-2.pdf
- Digital Personal Data Protection Rules, 2025 (notified 13 Nov 2025).
  https://static.pib.gov.in/WriteReadData/specificdocs/documents/2025/nov/doc20251117695301.pdf
- Bharatiya Sakshya Adhiniyam 2023, s.63. https://indiankanoon.org/doc/125020475/
- SEBI CSCRF, 20 August 2024.
  https://www.sebi.gov.in/legal/circulars/aug-2024/cybersecurity-and-cyber-resilience-framework-cscrf-for-sebi-regulated-entities-res-_85964.html
- India's PQC migration roadmap (DST task force under the National Quantum Mission, Feb 2026), summarised:
  https://www.orfonline.org/expert-speak/india-s-post-quantum-cryptography-migration-roadmap
- CERT-In Annual Report 2025 (29.44 lakh incidents; 3,41,646 vulnerable services).
  https://www.cert-in.org.in/s2cMainServlet?pageid=PUBANULREPRT

Figures and market

- FBI IC3, *2025 Internet Crime Report* — $20.877B total, BEC $3.04B, 24,768 BEC complaints.
  https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf
- India email security market, $0.427B (2025) → $1.31B (2035), 11.82% CAGR — Market Research Future. Vendor
  research, not peer-reviewed.
- Post-quantum cryptography market, $810M (2025) → $18.19B (2035). Vendor research.
- ITU on cybersecurity within SDG 9. https://www.itu.int/en/sustainable-world/Pages/goal9.aspx
- Netherlands email standards, Sept 2025: 14% DANE, 6% MTA-STS.
  https://www.zivver.com/blog/use-of-email-security-standards-in-the-netherlands-september-2025-only-14-dane-6-mta-sts

Datasets

- CIC-IDS2017. https://www.unb.ca/cic/datasets/ids-2017.html
- Suricata's public PCAP list. https://docs.suricata.io/en/latest/public-data-sets.html
- MAWI / MAWILab; UNSW-NB15; Stratosphere Malware Capture Facility; Netresec; malware-traffic-analysis.net.

---

## 12. Corrections to our own docs

Two numbers in `CLAUDE.md` and `07_RELATED_WORK.md` need fixing before they reach a slide:

1. **MTA-STS adoption is not 0.3%.** The IMC 2025 paper reports 52,641 `.com` domains (0.07%) and 7,192 `.org`
   domains (0.12%) as of September 2024. The 0.3% figure in our notes is a different statistic from the same
   paper (third-party-managed domains failing to present a valid certificate). The 29.6% misconfiguration
   figure is correct, and applies to the 68,000 domains publishing an MTA-STS record.
2. **The post-quantum measurement paper** at arXiv 2606.16473 is titled *Measurement Study of Post-Quantum
   Readiness of Internet: 2026*. Cite it by title and arXiv ID; our notes attribute authors I could not
   confirm. Its 49.3% hybrid key exchange and 0% PQ certificate figures are correct.

Everything else checked out. All five papers our docs claim to have verified are real, and the specific
figures we quote from Durumeric (seven countries above 20% cleartext) and Dubey (49.3% / zero PQ certificates)
are accurate.
