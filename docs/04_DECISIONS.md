# 04 — Decision Log

Numbered architecture decisions. Each records what we chose, what we rejected, and why. Append new ones; never
delete. If a decision is reversed, add a new ADR superseding the old one rather than editing history.

---

## ADR-0001 — Develop in WSL2, not native Windows

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** On the team's previous project, Windows Smart App Control blocked `rasterio`, `polars` and `pydantic`
from running, costing days. This project needs `dpkt`, `cryptography`, `scikit-learn`, `playwright` and Docker.

**Decision.** All backend work, data generation and testing happens inside WSL2 Ubuntu. The Next.js frontend may
run on either side.

**Rejected.** (a) Native Windows — same failure mode, already observed. (b) Disabling Smart App Control —
irreversible without reinstalling Windows, and it is a security setting that is the team's call, not a default.
(c) Colab-only — works for the pipeline but is awkward for Docker and for the web app.

**Consequence.** One hour of setup on day 1 removes the team's single biggest historical blocker.

---

## ADR-0002 — `dpkt` plus a custom parser, not `pyshark`/`tshark` at runtime

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** We need packet decode, TCP reassembly and TLS handshake parsing.

**Decision.** `dpkt` for packet decode, a custom TCP reassembler (~150 lines) and a custom TLS handshake parser
(~250 lines). `pyshark`/`tshark` is a **development-time cross-check oracle only**.

**Rejected.** (a) `pyshark` at runtime — drags in a `tshark` subprocess, adds an install dependency for judges and
deployment, is slow, and gives us no control over byte-offset provenance. (b) Scapy's TLS layer — heavier, and
still needs our own reassembly.

**Consequence.** More code, but full control over the evidence provenance that USP-03 depends on, and a
pip-installable tool with no external binaries.

---

## ADR-0003 — The rule engine is the labelling oracle for supervised ML

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** Supervised risk classification (D16) needs labels. No labelled corpus of email TLS risk exists, and we
have days, not months.

**Decision.** Generate synthetic **feature vectors** across the realistic configuration space, label them with the
deterministic rule engine, and train on that — standard weak supervision. Anomaly detection (D17) stays
unsupervised, so it is not bounded by the rules.

**Rejected.** (a) Hand-labelling — impossible at the needed volume. (b) Public datasets — none exist for this task.
(c) Skipping ML — fails D16, D17 outright.

**Consequence.** The model reproduces the rules on the training distribution. That is a known, disclosed property,
and it makes the model auditable. The defence is written out in [02_USP.md](02_USP.md) §4.

---

## ADR-0004 — Evidence references are born with the data, not added later

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** USP-03 (forensic provenance) requires every finding to trace to frame numbers and byte offsets in the
source capture.

**Decision.** The reassembler records frame number and offset for every emitted byte, and every schema object
carries an `evidence` block from construction.

**Rejected.** Adding provenance after the parsers work — retrofitting offsets through a completed parser is
expensive and usually gets dropped.

**Consequence.** Slightly more plumbing in S1 and S4. Enables our strongest forensic differentiator.

---

## ADR-0005 — Contract first: freeze the schema before parallel work begins

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** Six people, five days. The failure mode is everyone waiting on the parser.

**Decision.** In the first two hours the whole team agrees the schema in
[03_ARCHITECTURE.md](03_ARCHITECTURE.md) §2, exports JSON Schema, and hand-writes ~12 fixture sessions covering the
healthy / degraded / compromised tiers. Frontend, ML and reporting build against fixtures immediately.

**Rejected.** Sequential development — would leave four people idle for two days.

**Consequence.** Schema changes must be announced and must update the doc in the same commit.

---

## ADR-0006 — ML trains on synthetic feature vectors; PCAPs are for validation and demo

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** Training needs thousands of samples. Generating thousands of real captures is not feasible in the time
available.

**Decision.** Training corpus = ~10,000 synthetically sampled feature vectors (no PCAPs involved). The ~18 generated
PCAPs from the testbed are used for end-to-end validation, accuracy measurement and the demo.

**Consequence.** Decouples the ML timeline from the parser timeline entirely — C can train on day 2 whether or not
the parser works yet.

---

## ADR-0007 — PDF via Playwright print-to-PDF

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** D20 requires PDF export.

**Decision.** Render the Jinja2 HTML report, then print it to PDF with headless Chromium via Playwright.

**Rejected.** (a) WeasyPrint — GTK/Cairo dependency hell on Windows. (b) ReportLab — a second, divergent layout to
maintain.

**Consequence.** One HTML template produces both the HTML and the PDF deliverable, with identical styling.

---

## ADR-0008 — Capture both implicit TLS and STARTTLS, exceeding the dataset brief

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** The PS dataset guidance names only IMAPS, POP3S and SMTPS — the implicit-TLS ports, which have no
cleartext phase. But the objectives explicitly require STARTTLS detection and validation (D02).

**Decision.** The testbed generates captures for both: implicit TLS on 465/993/995 and STARTTLS on 25/587/143/110,
each across three health tiers.

**Consequence.** Extra testbed configuration work, in exchange for covering a deliverable that teams following the
dataset hint literally will be unable to demonstrate. See [01_PROBLEM_STATEMENT.md](01_PROBLEM_STATEMENT.md) §5.

---

## ADR-0009 — The schema package has zero dependencies

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** The contract in `schema/` is imported by every module and by all six people. On the team's previous
project Windows Smart App Control blocked **pydantic** specifically, among others. WSL2 (ADR-0001) is the fix, but
it is not installed on the development machine yet, and a contract layer that cannot import blocks everyone at once.

**Decision.** `schema/` uses stdlib `dataclasses` only. Serialisation, JSON Schema generation and TypeScript type
generation are hand-rolled in `schema/base.py` and `schema/jsonschema.py` (about 300 lines total).

**Rejected.** Pydantic — nicer validation and free JSON Schema, but it is the exact package that failed before, and
the failure mode here is everyone blocked rather than one person.

**Consequence.** Validation is weaker than pydantic would give. In exchange, `python -c "import schema"` works on
any Python 3.10+ with no install step at all, and `python -m schema.jsonschema` regenerates both the JSON Schema
and `web/src/types/schema.ts` so the frontend never hand-writes types that drift.

---

## ADR-0010 — Certificate findings are split into trust and strength

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** USP-01 downgrades certificate findings on port 25, because RFC 7435 makes MTA-to-MTA TLS
opportunistic. A test caught the consequence: a blanket downgrade would also have excused a 1024-bit RSA key and a
SHA-1 signature on that port.

**Decision.** `FindingCategory.CERTIFICATE` covers trust and validation (expiry, self-signed, chain, name mismatch)
and is role-adjusted. `FindingCategory.CERTIFICATE_STRENGTH` covers key size and signature algorithm and is in
`NEVER_ADJUSTED`.

**Rejected.** A single certificate category with a larger downgrade — simpler, but it would have made the USP-01
argument dishonest, and a judge who noticed would have been right to.

**Consequence.** The severity policy is defensible under questioning: trust expectations vary by port role, but
cryptographic strength does not.

---

## ADR-0011 — Ship a rule-derived baseline scorer alongside the trained model

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** D16 needs a risk score. The trained classifier needs scikit-learn, which is currently unusable on the
development machine (Smart App Control blocks numpy's compiled extensions — see ADR-0012). A pipeline that cannot
produce a score without a pickle file is fragile in exactly the wrong place.

**Decision.** `ml/classifier.py` has two interchangeable backends behind one interface: `gradient_boosting` (the
trained model, explained with SHAP) and `rule_baseline` (a noisy-OR over the findings the rule pack produced,
explained by finding attribution). `RiskModel.load()` degrades to the baseline without raising, and reports which
backend ran.

**Rejected.** Requiring the trained model — one missing file takes the demo down. Shipping only the baseline —
fails D16's "AI-based" wording and forfeits USP-04.

**Consequence.** Three benefits beyond robustness: the whole analysis chain runs today with zero dependencies, the
rest of the team is unblocked, and we gain an honest yardstick. `train.py` reports `baseline_mae` against
`model_mae` and prints a warning if the model does not beat the baseline — so the metrics slide cannot claim an
improvement that did not happen.

---

## ADR-0012 — Smart App Control confirmed blocking numpy on this machine

**Date:** 2026-09-23 · **Status:** Accepted (supersedes nothing; reinforces ADR-0001)

**Context.** ADR-0001 assumed the previous project's Smart App Control problem would recur. It was tested directly:

```
pip install numpy scikit-learn        # succeeds
python -c "import numpy"
ImportError: DLL load failed while importing _multiarray_umath:
An Application Control policy has blocked this file.
```

**Decision.** WSL2 is mandatory, not advisory, for every stage that needs a compiled dependency: S0–S5 (`dpkt`,
`cryptography`), S8 training (`scikit-learn`), S10 PDF export (`playwright`). `ml/train.py` detects this specific
failure and prints the fix rather than a raw traceback.

**Consequence.** Confirms the zero-dependency decisions were right, not paranoid. The schema (ADR-0009), the rule
pack, the corpus generator and the baseline scorer (ADR-0011) all run on stock Windows Python — which is why
roughly half the pipeline is already working and tested while the environment is still unresolved.

---

## ADR-0013 — Write PCAPs directly, as well as capturing them

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** The Docker testbed (ADR-0008) needs WSL2, Docker and old OpenSSL builds, none of which are available
yet, and modern OpenSSL refuses to negotiate several of the configurations we most need to test — RC4, SSLv3, a
mangled STARTTLS capability, a DOWNGRD sentinel.

**Decision.** `testbed/synth.py` writes PCAP files byte by byte with no dependencies: Ethernet, IPv4 and TCP with
correct checksums, plus hand-built TLS records. Seven scenarios today, one per file plus a combined fleet capture.

**Rejected.** Waiting for Docker — blocks S0–S5 development entirely. Downloading public sample captures — useful
for robustness but no ground truth, and none contain the specific attacks we need to demonstrate.

**Consequence.** S0–S3 were built and tested the same day. Checksums are computed properly so the files open
cleanly in Wireshark, which matters: the USP-03 provenance claim is only convincing if a judge can open the capture
and land on the frame we cited. This does **not** replace the Docker testbed — real captures catch things
hand-written ones cannot, so `testbed/manifest.json` remains the ground truth.

---

## ADR-0014 — Unanalysed is reported as unknown, never as clean

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** With S4 (handshake parsing) unbuilt, encrypted sessions yielded no findings, so four hosts in the
first end-to-end run scored **A+ with zero findings**. They had not been assessed at all.

**Decision.** Three changes. A rule, `ANALYSIS-INCOMPLETE-HANDSHAKE`, fires whenever a session reached TLS but the
handshake was not parsed. The fleet summary states the coverage gap in its own sentence. And `Grade.INCOMPLETE`
("?") replaces any A/A+/B on a host whose sessions we could not inspect.

The same principle governs the feature extractor: when something is unobservable — certificates in TLS 1.3, an
EHLO re-issue inside an encrypted channel — the feature takes the value that makes the rule *not* fire.

**Rejected.** Leaving the score as-is and relying on the reader to notice. Defaulting missing features to their
"bad" values, which would manufacture findings out of absent data.

**Consequence.** A host we could not inspect shows "?" instead of "A+". Less flattering, and the only defensible
option: a security tool that reports an uninspected host as clean is worse than one that reports nothing.

---

## ADR-0015 — Cipher suite properties are derived from IANA names, not tabulated

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** S4 needs key exchange, cipher, strength, AEAD/CBC mode and forward secrecy for every suite it sees.

**Decision.** `tls/ciphers.py` maps codepoint → IANA name and **derives** everything else by parsing that name.
`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` already states its key exchange, cipher, mode and MAC.

**Rejected.** A hand-maintained property table per suite — hundreds of rows, each an opportunity for a silent
error. A wrong `has_forward_secrecy` flag would quietly corrupt D15 across every report, and nothing would fail
loudly enough to catch it.

**Consequence.** Adding a suite means adding one line. Unknown codepoints return `known=False` with neutral
properties: we report the number and say we do not recognise it, rather than guessing. An honest "unknown" beats a
confident wrong answer on a forward-secrecy verdict.

---

## ADR-0016 — The cipher intersection anomaly is deliberately conservative

**Date:** 2026-09-23 · **Status:** Accepted

**Context.** USP-02 claims to detect a server choosing something weaker than both parties supported. The obvious
implementation — flag any suite weaker than the client's best — fires constantly.

**Decision.** Only a loss of **forward secrecy** or of **AEAD** counts. A smaller key size does not: preferring
AES-128 over AES-256 is a legitimate performance decision that thousands of well-run servers make.

**Rejected.** Flagging any downgrade in the ordering. It would have produced a finding on most healthy sessions,
which is precisely the false-positive behaviour USP-01 exists to avoid.

**Consequence.** The detector is quiet on reasonable configurations and fires on the ones that matter — a server
selecting static RSA when the client offered ECDHE. Both behaviours are pinned by tests.

---

## ADR-0017 — X.509 parsed in pure Python, not via `cryptography`

**Date:** 2026-09-23 · **Status:** Accepted (supersedes the `cryptography` row in ADR-0002)

**Context.** ADR-0002 chose `cryptography` for X.509. Testing it properly showed the choice is unavailable:

```
python -c "import cryptography"        # succeeds - the top level is pure Python
python -c "from cryptography import x509"
ImportError: DLL load failed while importing _rust:
An Application Control policy has blocked this file.
openssl version
/mingw64/bin/openssl: Permission denied
```

The bare import succeeding made this look fine at first glance, which is why it was worth checking the actual
call path rather than the import.

**Decision.** `certs/der.py` implements a minimal DER reader (definite-length only, no BER, no streaming — exactly
what certificates on the wire use). `certs/extract.py` pulls the X.509 fields. `certs/chain.py` validates, and
**verifies RSA PKCS#1 v1.5 signatures for real** — `pow(sig, e, n)` is all the arithmetic that needs, and Python's
built-in modular exponentiation is fast enough for a 4096-bit modulus.

`testbed/certgen.py` generates genuinely signed test certificates the same way, because openssl is blocked too.
It is explicitly **not** a security library: the key generation uses `random`, not a CSPRNG. It exists to produce
test artifacts with correct structure and real signatures.

**Rejected.** Waiting for WSL2 — it has slipped repeatedly and S5 is the last parsing stage. Shipping structural
validation without signature checking — weaker, and the arithmetic turned out to be about forty lines.

**Consequence.** Zero blocked dependencies across the entire parsing path; the only runtime dependency left is
`dpkt`. The honest limitation is that **ECDSA and Ed25519 signatures are not verified** — that needs elliptic-curve
arithmetic stdlib does not provide. Those chains report `signature_verified = None`, meaning "not checked", never
`False`, which would claim we found a forgery.

---

## ADR-0018 — The dashboard is a single self-contained HTML file, not a build-step app

**Date:** 2026-09-24 · **Status:** Accepted (revises the frontend row in ADR-0002)

**Context.** The plan was a Next.js dashboard. Checking the machine: `node` is not installed, `npm` is not
installed, and `jinja2` is not installed either. That is the fourth dependency block on this project after
pydantic/numpy (ADR-0012), `cryptography` and `openssl` (ADR-0017).

**Decision.** `securemailscope/report/` emits one HTML file with its CSS, its script and the report data all
inlined, generated with stdlib string handling. The report data sits in a `<script type="application/json">`
island and the page renders itself client-side, so the same artifact is both the export (D20) and the interactive
dashboard (D21).

**Rejected.** Waiting for node — after four dependency blocks, a deliverable that needs a build step is a
deliverable that might not exist on demo day. Server-side rendering only — loses the interactivity D21 asks for.

**Consequence.** `python scripts/analyse.py capture.pcap --out out/` produces a dashboard that opens by
double-clicking, works offline, travels on a USB stick and attaches to an incident ticket. It also prints: the
PDF export is the same file through headless Chromium (ADR-0007), with a print stylesheet already applied, so a
missing Playwright degrades the export rather than the report.

A Next.js app remains worth building **if** node gets installed and there is time — it would be a better
long-term product. It is no longer on the critical path for the demo, which is the point.

**Security note.** Banners, capability lines and SNI all come from the observed server, so a hostile one could try
to inject markup. Values are escaped at render time, the data island is `type="application/json"` so the browser
does not execute it, and `</` inside the JSON is escaped so the element cannot be closed early. All three are
pinned by tests.
