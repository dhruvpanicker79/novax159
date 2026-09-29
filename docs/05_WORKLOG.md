# 05 — Work Log

Append-only. One entry per working session: date, who, what changed, what broke, what's next. This is the raw
material for the final report and the PPT progress slide.

**Entry format:**

```
## YYYY-MM-DD — <who>
**Done:** ...
**Blocked / broken:** ...
**Next:** ...
```

---

## 2026-09-23 — planning session (Claude + team lead)

**Done:**
- Chose SecureMailScope as the problem statement. Feasibility assessed as high for a 5-day build: the work is
  deterministic parsing plus a thin, defensible ML layer. No GPU, no training corpus to hunt for, no research risk.
- Decomposed the problem statement into 21 scored deliverables (D01–D21) plus 2 objective-only items (O01–O02), and
  identified six requirements hidden in the wording — most importantly that "STARTTLS **validation**" is ten
  distinct checks, and that "reconstruction" appears twice and means *render it on screen*.
- Wrote the traceability matrix mapping every deliverable to a pipeline stage and to the screen where a judge can
  see it. This doubles as the pre-demo checklist.
- Read the dataset guidance (synthetic; IMAPS/POP3S/SMTPS). Two conclusions: the brief names only implicit-TLS
  ports, so STARTTLS coverage is a competitive gap we should exploit (ADR-0008); and owning synthetic ground truth
  lets us report measured precision and recall, which became USP-07.
- Defined the USP set: 7 Tier-1 (build), 4 Tier-2 (build if on schedule), 4 Tier-3 (roadmap slide).
- Defined the 12-stage pipeline (S0–S11), the 10-object data model, technology choices and per-person ownership.
- Recorded 8 architecture decisions (ADR-0001 to ADR-0008).
- Set up the documentation system in `docs/`.

**Blocked / broken:** Nothing yet. The known environmental risk is Windows Smart App Control blocking Python
packages, as it did on the team's previous project — mitigated by ADR-0001 (develop in WSL2).

**Next:**
1. WSL2 setup on every machine (one hour, do it first).
2. Freeze the schema: Pydantic models in `schema/`, export JSON Schema, hand-write ~12 fixtures.
3. Build the testbed (`docker-compose`) and generate the first captures.
4. Repo scaffold for all twelve stages so six people can start in parallel.

---

## 2026-09-23 (later) — scaffold built

**Done:**
- `schema/` frozen and working: 10 objects, 15 enums, `Evidence` on every object (ADR-0004). Zero dependencies
  (ADR-0009) — `python -c "import schema"` works on a bare Python 3.11 with nothing installed.
- `python -m schema.jsonschema` generates JSON Schema for the 5 top-level models **and**
  `web/src/types/schema.ts` (23 TypeScript interfaces), so the frontend never hand-writes types that drift.
- `fixtures/report.sample.json` (239 KB): 12 sessions, 8 hosts, 17 findings, fleet grade D. Plus one file per
  session for focused component work. The frontend, reporting and ML people are unblocked as of now.
- `securemailscope/` skeleton: 24 modules across all twelve stages, each carrying the implementation notes that
  matter — the TLS 1.3 `supported_versions` trap, the encrypted-Certificate-message limitation, GREASE stripping
  before JA3, the capability-mangling heuristic.
- **USP-01 implemented for real**: `proto/roles.py` + `rules/severity.py`. A declarative policy table with
  `steps` / `cap` / `floor` that writes its own plain-English justification into every adjusted finding.
- `testbed/manifest.json`: 18 captures with full ground truth and expected findings — 7 healthy, 4 degraded,
  7 compromised; 9 implicit TLS, 6 STARTTLS, 3 cleartext; 15 rules under test. Plus `make_certs.sh` for the four
  certificate scenarios.
- 22 contract tests, all passing. Runnable as plain `python tests/test_contract.py` with no pytest installed,
  which matters before anyone has an environment.

**Found and fixed:** the first version of the severity policy downgraded *every* certificate finding on port 25,
which would also have excused a 1024-bit key and a SHA-1 signature there. A test caught it. Split into
`CERTIFICATE` (trust, role-adjusted) and `CERTIFICATE_STRENGTH` (never adjusted) — ADR-0010. Worth knowing,
because a judge asking "so your tool ignores weak keys on port 25?" would have been right.

**Blocked / broken:**
- **WSL is not installed on the dev machine.** `wsl --install` needs admin rights and a reboot, so it is the
  team's action. Until then only the zero-dependency parts run on Windows — which, by design, is the entire
  schema, the fixture generator and the whole test suite.
- No pip packages installed yet: no `dpkt`, `cryptography`, `scikit-learn`, `fastapi`.

**Next:**
1. `wsl --install`, reboot, then `pip install -e ".[parse,ml,serve,dev]"` inside WSL.
2. Person A: S0/S1 — ingest and reassembly, with byte-to-frame provenance from the first commit.
3. Person C: `ml/train.py` — the synthetic corpus needs no parser (ADR-0006), so this can start today.
4. Persons E/F: `npx create-next-app web/`, pointed at `fixtures/report.sample.json`.
5. Testbed: run `make_certs.sh`, then write `docker-compose.yml`.

---

## 2026-09-23 (evening) — S6 rule pack and S8 AI layer

**Done:**
- **S6 rule pack**: 33 rules across protocol, cipher, key exchange, certificate trust, certificate strength,
  STARTTLS, attack evidence, configuration and post-quantum. Every rule carries its standards citations and its
  remediation config snippets inline, enforced by a test.
- Rules are predicates over a `FeatureVector`, so the *same* code labels the ML corpus and analyses real sessions
  (ADR-0003). The oracle can never drift from the shipping detector.
- **S8 layer 1** `ml/classifier.py`: two backends, trained model or rule-derived baseline (ADR-0011), plus
  `humanise()` so the waterfall reads "RC4 cipher suite negotiated" rather than `cipher_is_rc4 = 1.0`.
- **S8 layer 2** `ml/anomaly.py`: JA3/JA3S rarity plus peer deviation from the fleet's modal configuration.
  Isolation Forest when sklearn exists; explainable either way.
- **S8 layer 3** `ml/priority.py`: D18 as distinct code from D16 — severity leads, then exploitability, blast
  radius and breadth, with a written rationale for every position. Plus `remediation_batches()` for the admin view.
- **Corpus generator** `ml/corpus.py`: archetype-first sampling so weak settings correlate the way they do in
  reality. 10,000 labelled vectors in 0.3s, pure stdlib, CSV export so training can happen on any machine.
- `ml/train.py`: gradient boosting over 5 severity classes plus an Isolation Forest fitted on the healthy majority
  only. Compares itself against the baseline and warns if it does not win.
- `scripts/demo_analysis.py`: runs S6→S8 over the fixture fleet and prints the demo in the order we will tell it.
- 31 new tests. 53 passing in total.

**Found and fixed — three bugs, all the same class:** citing a standard is not the same as violating it. RFC 7435
(justifies the relay downgrade), RFC 8461 and RFC 7672 (mechanisms we *recommend*) and RFC 8446 (which the server
actually complied with) were all being reported as compliance failures. Added `StandardRef.relation`; the
compliance report now counts only `violates`. Failures went from 14 of 17 to 11 of 17, and every remaining one is a
genuine MUST violation. Worth catching before a judge did.

**Blocked:**
- **Confirmed: Smart App Control blocks numpy on this machine** (ADR-0012). `pip install` succeeds, `import numpy`
  fails with "An Application Control policy has blocked this file". WSL2 is now mandatory, not advisory.
- Consequence: `ml/train.py` cannot run here. Everything else in S6–S8 runs and is tested, because the rule pack,
  the corpus generator and the baseline scorer are all pure stdlib.

**Next:**
1. `wsl --install -d Ubuntu-22.04`, reboot, `pip install -e ".[parse,ml,serve,dev]"`, then
   `python -m securemailscope.ml.train` — it should take about two minutes and produce the metrics slide numbers.
2. Person A: S0/S1, the last big unbuilt piece.
3. Persons E/F: the dashboard now has real scored data to render — `python scripts/demo_analysis.py` shows
   exactly what the screens need to show.

---

## 2026-09-23 (night) — S0-S3 and the first real end-to-end run

**Done:**
- Discovered `dpkt` is pure Python, so Smart App Control does **not** block it. That unlocked the whole parsing
  path on Windows, well ahead of schedule.
- `testbed/synth.py` (ADR-0013): writes PCAPs byte by byte — Ethernet/IPv4/TCP with correct checksums, plus
  hand-built TLS ClientHello, ServerHello, Certificate and ChangeCipherSpec records. Seven scenarios, no Docker.
- **S0** `capture/ingest.py`: streaming SHA-256, format detection from the magic number, 1-based frame numbers
  matching Wireshark so evidence references are typeable into a display filter.
- **S1** `capture/reassemble.py`: TCP reassembly handling out-of-order segments, retransmissions, partial overlaps
  and gaps, with byte-offset → frame provenance recorded as it goes (ADR-0004). Gaps are recorded, never filled
  with invented bytes.
- **S2** `proto/detect.py`: banner-led protocol identification with the port as corroboration, graded confidence,
  and correct handling of implicit TLS (no banner exists to read).
- **S3** `proto/starttls.py`: the ten checks, capability-mangling detection, and credential recovery for SMTP AUTH
  LOGIN/PLAIN, IMAP LOGIN and POP3 USER/PASS. Passwords stored redacted.
- **S7** `features/__init__.py`: real feature extraction from a parsed session.
- **`pipeline.py`**: PCAP in, `Report` out. S0→S3→S7→S6→S8→S9 runs end to end today.
- `scripts/analyse.py`: the command the demo runs. With no argument it generates the corpus and analyses it, so a
  fresh clone goes to a full report in one command.
- 28 new tests. **81 passing in total.**

**Found and fixed — three bugs, all caught by running it rather than by reading it:**

1. `_TLS_RECORD` was `^`-anchored but used with `.search()`, so **every STARTTLS session was reported as
   cleartext**. Split into anchored and unanchored patterns with a comment explaining why both exist.
2. `STARTTLS-ADVERTISED-NOT-USED` fired at HIGH on port 25, where the client is a remote peer MTA outside this
   organisation's control and `SMTP-RELAY-NO-TLS` already covers it. That is precisely the false positive USP-01
   exists to prevent, occurring inside our own rule pack.
3. Four hosts scored **A+ with zero findings** because S4 does not exist yet — they had not been assessed at all.
   Fixed with ADR-0014: a coverage rule, a summary sentence, and `Grade.INCOMPLETE`.

**Spec correction:** V7 (EHLO re-issued after TLS) is **not passively observable** when the upgrade succeeds — the
re-issued EHLO is inside the encrypted channel. It now reports as not-applicable in that case. Nine of the ten
checks are fully passive; the tenth is conditional. Documented in `01_PROBLEM_STATEMENT.md` section 3.1.

**Still blocked:** scikit-learn and `cryptography` need WSL2 (ADR-0012). `cryptography` is a Rust extension, so S5
(X.509) will be blocked the same way numpy was — S4 (handshake parsing) is pure byte work and is not.

**Next:**
1. **S4 — TLS handshake parsing.** The single highest-value remaining piece: it turns the four "?" hosts into real
   grades and switches on roughly half the rule pack. Pure stdlib, so it can be built here. Mind the
   `supported_versions` trap; the synthetic corpus already contains a TLS 1.3 ServerHello that exercises it.
2. S5 X.509 — needs WSL, or a small DER parser if WSL keeps slipping.
3. Frontend: `out/report.json` is now a real analysed report, not a fixture.

---

## 2026-09-23 (late) — S4 TLS handshake parsing

**Done:**
- `tls/ciphers.py`: suite and named-group tables with properties **derived from IANA names** (ADR-0015), plus the
  hybrid post-quantum groups for USP-05.
- `tls/records.py`: record layer with stream offsets, handshake messages re-joined across records, alert decoding,
  and passive handshake-completion detection via ChangeCipherSpec / application data.
- `tls/handshake.py`: ClientHello and ServerHello parsing. **The TLS 1.3 trap is handled** — negotiated version
  comes from `supported_versions`, not `legacy_version`. Also extracts the RFC 8446 DOWNGRD sentinel,
  TLS_FALLBACK_SCSV, supported groups and the full client cipher list.
- `tls/fingerprint.py`: JA3 / JA3S with GREASE stripped before hashing.
- `tls/__init__.attach()`: the stage entry point, wired into `pipeline.py`.
- **Cipher intersection anomaly** (USP-02) now works: it compares what the server *could* have chosen against what
  it did, which no rule looking only at the negotiated suite can see. Conservative by design (ADR-0016).
- 34 new tests. **114 passing in total.**

**Now firing end to end from a real PCAP:** deprecated version, RC4, 3DES, NULL/anon, export, CBC, weak strength,
no forward secrecy, weak DH group, downgrade sentinel, intersection anomaly, missing renegotiation_info,
compression, missing SNI, post-quantum readiness.

**Found and fixed:**
1. A bug in my own *test data*, not the parser: the downgrade scenario passed a version number (0x0303) where a
   cipher suite belongs, so S4 correctly reported `UNKNOWN_CIPHER_SUITE_0x0303`. Now uses 0x009D
   (`TLS_RSA_WITH_AES_256_GCM_SHA384`), which also makes the session a genuine forward-secrecy downgrade and gives
   the intersection anomaly something real to catch.
2. **A capture that starts mid-session was classified as cleartext.** Rewriting a stale test surfaced it: when
   recording begins after the handshake, the first bytes are protected application data and there is no
   ClientHello. That is a normal forensic situation and calling it cleartext would be a serious misreport. Now
   detected as encrypted-but-uninspectable, with a new `imaps_mid_session` scenario pinning it.
3. Grammar in the executive summary — "1 encrypted session ... so their scores". User-facing text on the one line
   a decision-maker reads.

**Still blocked:** S5 (X.509) needs `cryptography`, a Rust extension, so it will be blocked the same way numpy was
until WSL2 exists. Everything else now runs on stock Windows Python plus `dpkt`.

**Next:**
1. **S5 X.509** — the last parsing stage. Needs WSL, or a ~200-line DER parser if WSL keeps slipping. Until it
   lands, the seven CERT-* rules cannot fire and certificate deliverables D08–D12 are unmet.
2. **S10 report export** (JSON done; HTML and PDF pending) and the FastAPI service.
3. **Frontend** — `out/report.json` is a real analysed report with handshakes, fingerprints and findings.

---

## 2026-09-24 (early) — S5 certificates: the last parsing stage

**Done:**
- Tested `cryptography` properly instead of trusting the import: `import cryptography` succeeds but
  `from cryptography import x509` fails, because Smart App Control blocks its Rust extension. `openssl` is blocked
  too. So S5 went pure Python (ADR-0017).
- `testbed/certgen.py`: RSA key generation (Miller-Rabin), PKCS#1 v1.5 signing, a DER builder and the four
  certificate scenarios from `manifest.json`. Real signatures, 3 seconds to generate the whole set.
- `certs/der.py`: minimal DER reader with bounds checking, OID decoding, the RFC 5280 UTCTime year pivot, and
  RFC 5280 name matching.
- `certs/extract.py`: subject, issuer, serial, validity, public key algorithm **and size**, signature algorithm,
  SANs, key usage, basicConstraints, SHA-256 fingerprint. D08, D10, D11, D12.
- `certs/chain.py`: ordering, completeness, expiry, hostname matching with correct wildcard semantics, and **real
  RSA signature verification** with the full padding check — a verifier that just looks for the digest somewhere
  in the recovered block accepts forgeries. D09.
- `certs/__init__.attach()`: the stage entry point, plus certificate-substitution detection across sessions
  (USP-02).
- Two new capture scenarios with observable TLS 1.2 chains, and the existing ones now carry real certificates.
- 32 new tests. **149 passing in total.**

**Found and fixed:** an element declaring 65535 bytes with none present parsed "successfully" with an empty value.
A certificate truncated by a capture that stopped mid-transfer would have read as a certificate that simply has no
extensions — and "no subjectAltName" is a finding, while "we only received half of this" is not. `Element` now
carries `declared_length` and a `truncated` flag, and `parse_all` stops at a short element rather than misreading
whatever follows.

**Deliverable status: 20 of 21 met.** D01–D19 and both objectives (O01, O02) are implemented and tested from PCAP
bytes. D20 is partial — JSON export works, HTML and PDF are pending. D21 (the dashboard) has not started.

**Next:**
1. **S10 exports** — HTML via Jinja2, PDF via Playwright (ADR-0007), and the four persona views (USP-06).
2. **FastAPI service** so the dashboard has something to call.
3. **The dashboard (D21)** — the largest remaining piece and the one judges see first. `out/report.json` is now a
   complete analysed report: handshakes, certificates, fingerprints, findings, scores and evidence references.
4. WSL2 remains needed only for `ml/train.py` — the rule-derived baseline covers D16/D17/D18 in the meantime.

---

## 2026-09-24 (mid) — S10 exports and the dashboard

**Done:**
- `securemailscope/report/`: JSON, HTML and PDF from one `Report` object, so the three can never disagree.
- The HTML is **one self-contained file** — CSS, script and data inlined, no CDN, no fonts, no build step
  (ADR-0018). Verified: zero external references in the markup.
- It is also the dashboard (D21): posture grade, executive summary, fleet table, filterable triage queue with
  expandable findings, per-session cards with the handshake ladder (D04), the ten STARTTLS checks (D02), the
  certificate chain (D08–D12), the risk waterfall (D16), anomaly reasons (D17), the feature vector (O01), the
  compliance report card (USP-08) and a USP-01 side-by-side panel that builds itself from whichever rule produced
  opposite verdicts.
- Four persona views (USP-06): SOC triage, forensics evidence packet, an IR **timeline** and an administrator
  view grouped by fix rather than by finding. All four share one analysis, which a test enforces.
- Dark by default with a light theme for printing; `@media print` rules so Print to PDF produces the same document.
- `scripts/analyse.py --out DIR` writes everything.
- 19 new tests. **168 passing in total.**

**Verification note, stated honestly:** the preview pane renders local pages as static snapshots, so I could not
get a reliable *visual* check of the design. I verified it structurally instead — served the file over HTTP and
confirmed via the DOM that the page is 3779px tall at 1265px wide with 25 findings, 10 session cards and 17
compliance rows all rendering correctly. **Someone should open `out/report.html` in a real browser and look at
it**, because layout polish is not something I have confirmed.

**Two tests I had to correct rather than the code:** both asserted the wrong property. RFC URLs and any injected
markup legitimately appear inside the JSON data island — that element is `type="application/json"`, the browser
does not execute it, and every value is escaped on render. The meaningful assertion is that they never reach the
document *markup*, which is what the tests now check.

**Deliverable status: 21 of 21 implemented.** D20 covers JSON and HTML with PDF degrading cleanly when Playwright
is absent; D21 is the interactive HTML dashboard.

**Next:**
1. **Open the report in a browser and polish the design.** The one thing I could not verify.
2. The FastAPI service, so a PCAP can be uploaded rather than passed on the command line.
3. WSL2 for `ml/train.py` and Playwright — the last two blocked pieces.
4. The Docker testbed for real captures alongside the synthetic corpus.

---

## 2026-09-26 — pitch research (`docs/08_PITCH.md`)

**Done:**
- Read six SIH decks that got through (SIH1714 Asha, SIH25022 Margdarshak, SIH25002 PURVA, SIH1669 Transformo
  Docs, SIH1679 CIS Kurukshetra, SIH1683 DrishyamAI) and extracted what separates them mechanically: a named
  product, a number on every slide, a *table* on the references slide rather than a link dump, live links, the
  Challenge→Solution two-column feasibility layout, and named integration with existing government systems.
  The closest analogue to us — SIH1679, also Blockchain & Cybersecurity — is the weakest of the six.
- **Verified every paper our docs cite.** All five external papers are real and the figures we quote are
  accurate, with one exception: MTA-STS adoption is 0.07% of `.com` / 0.12% of `.org`, not 0.3%. Corrected in
  `CLAUDE.md`. The 29.6% misconfiguration figure was right.
- Added new sources that matter: Holz et al. NDSS 2016 (the reference mail-TLS measurement study), Loizou &
  Ghadafi Aug 2026 (**44.0% of web endpoints quantum-ready vs 6.4% of mail** — the strongest single statistic
  available to this pitch), INTACT arXiv 2602.21252 (crypto violations as policy breaches, which is our design),
  and India's PQC migration roadmap (DST/NQM, Feb 2026: **crypto inventory for CII by 2027, CBOM from vendors
  FY 2027–28**).
- **Found out who set the PS.** SIH26159 is from **NTRO**. Recorded what that implies for the pitch: offline,
  air-gapped, evidence-grade, no cloud. Our one-dependency build is the differentiator, not an apology.
- **Found at least five other public repos working PS 159.** Two are substantial; one claims 100% precision and
  recall on a labelled corpus with a 19-rule engine. Competitive analysis in §10 of the pitch doc.

**What this changes:**
1. `scripts/evaluate.py` is now the highest-priority item by a wide margin — a rival is already publishing
   accuracy numbers and ours do not exist.
2. USP-11 (DANE/MTA-STS) is probably a stated PS requirement, not an extra: the PS accepts "a packet capture,
   a domain name, or both".
3. A CBOM export has a government deadline attached to it (FY 2027–28), which makes it the best-justified
   unbuilt feature.

**Next:** wire up `evaluate.py`; produce the before/after severity screenshot pair for slide 2; pick the name.

---

## 2026-09-27 — full deck content, sourced (`docs/09_DECK_CONTENT.md`)

**Done:** all five content slides written with a published source behind every line. Eight new papers pulled and
read for numbers, four of which change what we say:

- **Poddebniak et al., USENIX Security 2021** — the citation USP-01 was missing. States the role asymmetry
  directly: submission and retrieval are more critical *because they carry user credentials*. Also gives the best
  number on slide 2: **40+ STARTTLS flaws across 28 clients / 23 servers, only 3 clients clean, and 320,000
  servers (2% of all mail servers) vulnerable to credential-stealing command injection**.
- **Mayer et al., ARES 2016** — full IPv4, 20M IP/port pairs, 10 billion handshakes: **65% of SMTP hosts
  self-signed**, only **33-37%** validating on mail-access ports, **15-17%** of POP3/IMAP offering static RSA as
  their only key exchange. The evidence base for the certificate and cipher rules.
- **Lee et al., USENIX Security 2022** — DANE in SMTP: **>30% of TLSA records unvalidatable, 87% incorrect key
  rollovers**, attributed by the authors to *the lack of automated tooling*. A peer-reviewed request for USP-11.
- **Sommer & Paxson, IEEE S&P 2010** — base-rate problem and semantic gap. Makes our "facts deterministic, only
  the ranking learned" architecture look deliberate, and gives role-aware severity a false-positive argument.

Also added: **Dreger et al. USENIX Sec 2006** (port-independent protocol detection, which is exactly S2),
**Georgiev CCS 2012** + **Brubaker S&P 2014** (certificate validation is broken because of library APIs — the
defence for writing our own parser), **Anderson/McGrew 2018** (TLS metadata alone attributes malware families),
**Li et al. USENIX Sec 2016** (notices carrying remediation steps 56.5% more effective after two days, though
not significant after correction — quote the caveat), and the primary sources for XGBoost, Isolation Forest,
SHAP and robust covariance estimation.

**The novelty claim, now checkable against the literature:** every large study of email encryption scanned
servers from the outside — ZMap sweeps, DNS scans, active probes. Not one could tell an individual operator what
happened to their own mail. Holz 2016 is the only one that used passive monitoring at all, and that was one
research vantage point describing the ecosystem.

**Slide 6 is built as Code Omega's was** (Paper / Approach / Dataset / Accuracy) in three tables: measurement
evidence, method evidence with real accuracy figures, and our own numbers — which are still blank because
`scripts/evaluate.py` is a stub.

**Next:** `evaluate.py`, then the before/after severity screenshot for slide 2.

---

## 2026-09-27 (later) — research paper, first iteration (`docs/10_RESEARCH_PAPER.md`)

**Done:** full research document in the SIH research-doc format taken from the PURVA (SIH25002) submission — 19
numbered sections plus appendices A-F, abstract, keywords, contents, 57 numbered references. **29 pages, ~13,000
words**, rendered to `out/10_RESEARCH_PAPER.pdf` with the project's own `scripts/md_to_pdf.py`.

Appendices are generated from the code rather than written from memory: the full 34-rule catalogue with
categories, base severities and primary standards; the 51-field feature vector grouped and named exactly as
`schema.FeatureVector` declares it; the JSON report structure; and the evaluation protocol.

**Two discrepancies found against our own docs while writing it:**
1. The rule pack holds **34 rules**, not 33. `len(pack.RULES) == 34`. `CLAUDE.md` and several docs say 33.
2. `CLAUDE.md` attributes arXiv 2606.16473 to "Dubey & Varshney"; I could not confirm those authors, so the
   paper cites it by title and identifier. Its figures (49.3% hybrid KEX, 0% PQ certificates) are correct.

**Stated honestly throughout, in four places:** `scripts/evaluate.py` is a stub, so the paper reports no
precision or recall and does not claim to know them; the classifier is untrained; the anomaly baseline is still
single-pass; and the dashboard's visual design has never been reviewed by a human. Section 16.1 lists all seven
current gaps. A research document that hides its own gaps is worth less than one that names them, and NTRO
evaluators will find them anyway.

**Placeholders left for the team:** `[TEAM NAME]`, `[TEAM ID]`, member list if required.

**Next:** `scripts/evaluate.py`, so section 4.3 and Appendix E can carry real numbers.

---

## 2026-09-27 (evening) — paper formatting (`scripts/md_to_paper.py`)

**Done:** new renderer that puts the research document in the same format as the reference SIH research papers
(ITerative Bytes, SIH25002). ADR-0019 records why it is a separate script rather than a flag.

- **Times New Roman throughout**, registered as a TrueType family so the em dash, rupee sign and arrows render;
  falls back to built-in Times and degrades those characters, as `md_to_pdf.py` already does.
- **Title page** carrying title, italic subtitle, the centred metadata block, the abstract and the keywords —
  all on page 1, as the reference has it.
- **Generated contents** with dotted leaders and real page numbers, three levels, via `multiBuild` and an
  `afterFlowable` hook. Page numbers cannot be known until the document has been laid out once, hence two passes.
- **Running header** (`SIH 2026  CyberKavach`) with a rule, and centred page numbers. No header on page 1.
- Heading sizes follow LaTeX article at 10pt: 14.4 / 12 / 10.95pt, bold, flush left.

**34 pages.** `python scripts/md_to_paper.py docs/10_RESEARCH_PAPER.md --out out/`

**One bug found only by looking at it.** The abstract was emitting one `Paragraph` per source line, so every
hard-wrapped line was justified independently and orphan words sat alone ("can", "been", "payload,"). Text
extraction showed nothing wrong; it was visible only in the rendered page. Fixed by folding lines into
paragraphs. Worth remembering given the dashboard has the same unreviewed-visual-design risk recorded on
2026-09-24.

**Also:** abstract tightened to ~320 words and keywords to six so that page 1 holds the whole front matter, and
the per-section page breaks were removed — the reference lets sections flow on, which is what LaTeX does.

**Still placeholders:** `[TEAM NAME]`, `[TEAM ID]`.

---

## 2026-09-28 — user-flow diagram corrected against the code

Reviewed the team's draft slide-2 user flow (SIH 2026 template export) against what the system actually does and
rebuilt it as `docs/assets/slide2_userflow.svg`.

**Three boxes in the draft would have damaged us in front of NTRO:**
1. `MITM ATTACK (Downgrade if enabled)` → `FORCE PLAINTEXT DOWNGRADE` read as though CyberKavach *performs* the
   downgrade. We are passive. Replaced with attack **evidence detected, never caused**.
2. `PERFORM IN-BAND INSPECTION` — "in-band" means interception. Now **passive handshake inspection, nothing
   decrypted**.
3. `MAIL STREAM CAPTURE` / `Analyst Specifies Device/Filter` / `Receive Data Stream` implied live capture from an
   interface. We ingest a file. Removed.

**Claims with no code behind them, removed:** `EXPORT TO SIEM`, `Cert Added to DB`, `DB Updated`, `DB Archival` —
grepped, there is no database and no SIEM integration. Output is `report.json` + `report.html`, so the JSON is
described as SIEM-ingestible rather than integrated. `web/src/` was cited for the dashboard; it holds one
generated `schema.ts` and no UI (ADR-0018 rejected a build-step frontend).

**Logic error fixed:** `Anomaly detected? NO → INCIDENT CLOSED (False Positive)`. No anomaly is not a false
positive.

**Four USPs were missing from the flow and are now on it:** port-role assignment, the OPAQUE_TLS13 / `?` grade
path (which the PS itself requires), evidence linkage, and banner-led protocol identification.

**Module citations verified against the tree** — the draft's five were all real; `proto/identify.py` did not
exist and is now `proto/detect.py + roles.py`, and `features/` has no submodule so the package is cited.

---

## 2026-09-28 — anomaly baseline fix, and the training path

**Done:**
- **Fixed the poisoned anomaly baseline** (ADR-0019). `FleetBaseline.build()` now rejects contaminated sessions
  before computing the modal configuration, while keeping every session in the fingerprint-rarity denominator.
  `pipeline.py` reordered so S6 runs before the baseline. On the demo capture, 6 of 13 sessions are now excluded
  from defining normal.
- **Reviewed `ml/train.py`, which had never been executed, and found three bugs** — see ADR-0020. The worst:
  `train_test_split` shuffles, so the baseline-vs-model comparison was scoring the model on rows it had trained
  on. That would have put an unfounded "model beats baseline" number on the metrics slide.
- Added anomaly evaluation to `train.py`: ROC-AUC and precision at the top 10%. D17 previously had no metrics at
  all — "we have an anomaly detector" is not a claim until it is measured.
- `ml/corpus.py` now emits `baseline_risk` per row, making `data/corpus.csv` self-sufficient for training
  anywhere. 10,000 rows in 0.9 seconds, 2.5 MB.
- `notebooks/train_models.ipynb`: 20 cells, Colab-ready — classifier, confusion matrix, baseline comparison,
  Isolation Forest with evaluation, SHAP importances, and joblib bundles in the exact format
  `RiskModel.load()` expects. Every code cell syntax-checked, and the feature/metadata column split validated
  against the real CSV.
- 3 new tests. **171 passing.**

**Also confirmed, before it cost a day: FastAPI cannot run on these machines.** Pydantic v2's `_pydantic_core`
is blocked — the seventh Smart App Control block. Flask, Starlette, Jinja2 and stdlib `sqlite3` all work.
`docs/03_ARCHITECTURE.md` and the `api/` stub still specify FastAPI and need updating.

**The bar for the model:** baseline MAE **0.1683** over the 10,000-row corpus. If the trained model does not beat
that, the baseline is what ships and the slide says so.

**Next:**
1. Run `notebooks/train_models.ipynb` in Colab (~15 min) → D16/D17 move from PARTIAL to MET.
2. `scripts/evaluate.py` — still a stub; USP-07 still claims precision and recall we do not have.
3. The platform layer: Flask + sqlite3 job model, then finding dispositions.

---

## 2026-09-28 (later) — the platform layer

**Done:** every remaining ❌ box in the user-flow diagram, plus the ⚠️ on ingestion validation (ADR-0022).

- `schema/platform.py` — `AnalysisJob`, `FindingDisposition`, `AuditEvent`, `PostureSnapshot`, with a disposition
  state machine and legal-transition table.
- `securemailscope/store.py` — stdlib `sqlite3`, five tables, no ORM. Every human-caused write also writes an
  audit event, because a log that depends on callers remembering to append to it is not an audit log.
- `securemailscope/siem.py` — CEF and ECS export. Carries frame numbers and stream id, because a SIEM alert
  nobody can verify against the capture is noise. Defaults to MEDIUM and above: forwarding everything is how a
  feed gets muted.
- `securemailscope/api/` — Flask, 16 endpoints. Upload, progress, report JSON/HTML, SIEM, dispositions, audit,
  snapshots, and bundled samples so a demo never depends on a live upload working.
- 25 new tests. **196 passing.**

**Verified over HTTP, not just in tests:** `POST /api/samples/fleet.pcap/analyse` → completed, 13 sessions,
32 findings, grade D → `CEF:0|SecureMailScope|...|ATTACK-CLEARTEXT-CREDENTIALS|...|9` → snapshot archived and
finalised → disposition acknowledged → audit trail showing all six actions.

**Note on the workflow diagram:** the `MITM ATTACK / FORCE PLAINTEXT DOWNGRADE` boxes are still on the slide and
still show *our tool* performing an active attack. Nothing in the code does that and nothing should. That remains
the highest-priority slide fix.

**Next:**
1. The browser UI on top of these endpoints — the one piece of the platform still missing.
2. `scripts/evaluate.py` (USP-07 still claims numbers we do not have), after rewriting the stale manifest.
3. Colab training run → D16/D17 to MET.

**Console added.** `securemailscope/api/console.html` - one self-contained page served at `/`, no CDN and no
build step, same constraint as the offline report. Drop-zone upload, bundled-capture dropdown, live job queue with
progress, the triage queue with disposition buttons that follow the state machine, posture snapshots with
finalisation, and the audit log.

**Driven in a real browser, not only in tests:** submitted `fleet.pcap` through the UI, watched the job reach
completed, report auto-loaded (13 sessions, 32 findings, grade D), then clicked a finding from new to acknowledged
to resolved. The offered buttons changed with each state, the audit log recorded the transition, and
`/api/training-signal` returned the resolved finding as a labelled example.

**197 tests passing.**

---

## 2026-09-28 (evening) — evaluate.py, and what it immediately found

**Done:**
- **Rewrote `testbed/manifest.json`.** The old one listed 18 aspirational captures whose names matched nothing
  `synth.py` produces, which is why `evaluate.py` could not be written against it. It now covers the 13 real
  scenarios, and every `expect` list was derived by reading each scenario's *configuration* — cipher suite,
  version, certificate, STARTTLS exchange — and reasoning about what should fire. Each capture carries a
  `reasoning` field explaining the call, including the rules that must **not** fire and why.
- **`scripts/evaluate.py`** is no longer a stub. Per-rule precision, recall and F1; severity accuracy against
  pinned expectations; protocol identification accuracy; throughput. Exits non-zero on any disagreement so it can
  gate a merge. `scope: fleet` expectations (certificate substitution needs two sessions to one host) are scored
  against `fleet.pcap` separately.
- **It found two real false positives on its first run** — see ADR-0023. `ATTACK-CIPHER-INTERSECTION-ANOMALY` was
  firing on any legacy server, because a modern client offers modern suites to everything. Fixed by requiring
  corroboration from a DOWNGRD sentinel or TLS_FALLBACK_SCSV.
- 2 new tests. **199 passing.**

**USP-07 now has numbers:**

| | |
|---|---|
| captures matching exactly | 14/14 |
| rules exercised with no error | 20/20 |
| precision | 1.00 |
| recall | 1.00 |
| severity accuracy (USP-01 role adjustment) | 1.00 |
| protocol identification accuracy | 1.00 |

**State these honestly.** The corpus is 13 synthetic captures that we authored, exercising 20 of 34 rules. 1.00
means "no disagreement with independently-derived ground truth on this corpus", not "the tool is perfect". The
right framing for a judge is the process, not the number: the ground truth was written from the scenario
configuration rather than from the output, and the first run found a real bug. A corpus that cannot fail is not a
measurement — and this one did fail, which is what makes the figure worth quoting.

**Next:** real-world PCAPs are now the highest-value corpus work — everything measured so far is self-authored.

---

## Session 6 — 2026-09-29 · the console and its front door

**What shipped.** The SOC console: a login page, nine views, detail drawers, and real authentication. Two ADRs
(0024, 0025). The test count went from 199 to 201 and all seven suites pass; `scripts/audit.py` is unchanged at
**26 met / 6 partial / 2 not built**, which is the point of running it before and after.

**Files.** `securemailscope/api/auth.py` (new), `static/app.css` (new, ~700 lines), `static/app.js` (new, ~800
lines), `templates/login.html` and `templates/app.html` (new), `securemailscope/api/__init__.py` (auth wiring,
`/login`, `/logout`, `/api/me`, role gate on finalisation), `schema/platform.py` (two audit actions),
`tests/test_platform.py` (one test rewritten, two added). `securemailscope/api/console.html` deleted.

**The reversal.** ADR-0022 argued against authentication and it was wrong — not about the value, about the
price. An `X-Actor` header is a label the caller picks, so the audit trail recorded a claim rather than a fact,
which is a bad thing to demonstrate for a tool that sells verifiable evidence. PBKDF2 out of `hashlib` cost
~150 lines and no dependency. ADR-0024 says so explicitly rather than quietly changing it.

### Bugs and near-misses this session

**The old console test encoded the old console.** `test_console_is_served_and_self_contained` asserted on
`id="jobs"`, `id="queue"` and the absence of `src=` — all true of a single-file page and all false of a shell
plus two static files. The tempting fix was to loosen it until it passed. It was rewritten instead to test the
*intent*: every `href`/`src` in the shell must resolve to this service, and the served CSS and JS must contain
no `http://`, `https://`, `//cdn` or `@import url(`. That is a stronger test than the one it replaced.

**A role check that lived only in the UI would not have been a role check.** The first pass hid the Finalise
button from analysts. The API still accepted the call. Moved server-side, with a test for both sides.

**Template caching, mistaken for a CSS bug.** An edit to `app.html` did not appear after a hard reload. Jinja's
`auto_reload` is off when `debug=False`, so the template was cached for the process lifetime. Six people
iterating on this UI would each lose time to it once, so `TEMPLATES_AUTO_RELOAD=True` is now set explicitly.

**A layout bug that was not one.** The mobile rail refused to slide in: `.rail.open { transform: none }` matched,
had higher specificity, came later, and the computed transform stayed at `-232px`. The cause was the browser pane
being hidden — `requestAnimationFrame` never fires, so the transition started and never advanced, and
`playState` reported `running` forever. The same thing produced screenshots with a black band and the app
squeezed to the bottom. **Worth remembering: a hidden or minimised preview pane pauses compositing, so animated
CSS and screenshots both lie.** Check `getBoundingClientRect()` and `offsetLeft` before believing either.

**Still sloppy, now fixed:** `transition: .2s` is `transition: all .2s`, which animated the rail's border and
background along with its position.

**What the console is for.** Three panels exist to make the reasoning visible rather than to decorate it: the
STARTTLS grid renders V7 as *not observable*; the certificate view prints TLS 1.3's encrypted Certificate
message as expected behaviour rather than a missing certificate; every role-adjusted finding carries its own
justification. USP-01, USP-04 and ADR-0014, on screen.

**Next:** unchanged — real-world PCAPs, link-layer coverage (IPv6/VLAN/SLL), and the Colab training run. None of
them are UI work, which is the right place to be.

---

## Session 7 — 2026-09-29 · the Kavach console

**What changed.** The console was rebuilt against a supplied reference design: crimson on near-black,
a split login, a search-led topbar, KPI cards with sparklines and deltas, and a tabbed session-detail
page in place of the drawer. Twelve views. ADR-0026. 201 tests still pass; `scripts/audit.py` is
unchanged at **26 / 6 / 2** and `scripts/evaluate.py` still reports precision 1.00, recall 1.00 — the
point of running both before and after a change that touched no analysis code.

**Files.** `static/app.css` and `static/app.js` rewritten, `templates/login.html` and
`templates/app.html` rewritten, `securemailscope/api/__init__.py` (brand setting + context processor),
`tests/test_platform.py` (nav list updated).

### The decision worth remembering

**The reference had a geographic threat map. We refused to build it.** It showed countries with IP
counts and finding totals. Every host in the corpus is RFC 1918 — `10.20.1.23` has no country — no
GeoIP database ships with the tool, and the project's whole claim is that any finding can be checked
against the PCAP. That map would have been the only panel on screen a judge could not verify, and the
first one they would test. Replaced with an **Exposure Map** of the real observed topology, laid out
in three lanes by port role, which occupies the same space and happens to be the clearest single
picture of USP-01. Written up as ADR-0026 because the refusal, not the replacement, is the decision.

### Bugs found by running it

**Wrong schema field names, three of them.** The session panel read `s.client_port` and
`s.flow.byte_count`; the contract has `flow.src_port`, `flow.c2s_bytes` and `flow.s2c_bytes`. They
rendered as an em dash rather than throwing, which is exactly how this kind of thing survives a code
read. Found by looking at the page. The fix also surfaced `stream_id`, duration, retransmission count
and gap state, which were in the contract and unused.

**A percentage that was true and misleading.** The KPI deltas compared the two most recent
`PostureSnapshot`s. Running a 1-session capture and then a 13-session one produced "+1200% sessions",
which reads as estate growth and is really two different PCAPs. Cards now print `vs previous capture
(N)` under the figure and switch to an absolute difference past ±999%.

**Severity colours borrowed for something that is not severity.** The protocol donut used the severity
ramp, so IMAP came out orange and POP3 yellow — implying danger where the only fact is volume. Neutral
ramp now. Colour means one thing in this console.

**Two servers on one port, and half an hour of chasing a ghost.** The brand wordmark rendered empty
after the change. The running process was an *older* server that had never registered the context
processor; because `TEMPLATES_AUTO_RELOAD` is on it happily re-read the new template with `{{ brand }}`
in it and rendered nothing. A second `python -m securemailscope.api` had failed to bind and exited,
leaving the stale one serving. **Check `netstat -ano | grep :8000` before believing a restart happened**
— a failed bind is silent from the browser's side.

**The smoke test logged itself out.** The asset check walks every `href` in the shell, and one of them
is `/logout`. Everything after it 401'd. The script's bug, not the app's, and it did confirm logout
works.

### Flagged, not changed

`smtp_relay_cleartext.pcap` grades **A+ (95/100)**. That is USP-01 working as designed — the
`SMTP-RELAY-NO-TLS` finding is downgraded MEDIUM → LOW because opportunistic relay on port 25 is
outside the operator's control (RFC 7435) — and `scripts/evaluate.py` agrees with the hand-authored
ground truth on both the finding and its severity. But *A+ is the top grade*, and "your tool gave an
A+ to a server sending mail in plaintext" is a one-sentence attack with a three-sentence defence.
The finding is reported; the curve is the question. **This is a scoring decision in `pipeline.py`, not
a UI one**, so it was left alone and is recorded here for a deliberate call.

**Next:** unchanged — real-world PCAPs, link-layer coverage (IPv6/VLAN/SLL), the Colab training run,
and settling the project name.
