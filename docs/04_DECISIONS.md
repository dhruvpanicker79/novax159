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

---

## ADR-0019 — The anomaly baseline rejects contaminated sessions before learning

**Date:** 2026-09-28 · **Status:** Accepted

**Context.** `ml/anomaly.py` learned "normal" from the modal configuration of the capture — using **every**
session, including the compromised ones. The KMIP work (Baee et al., 2024) puts an unsupervised outlier-rejection
stage *ahead* of learning for exactly this reason, and reviewing it against our code exposed the flaw.

The failure mode is not subtle: it inverts the detector. On a fleet where most hosts are compromised, the attack
configuration becomes the mode, so the attacks stop looking anomalous and the healthy hosts start to. The more
widespread the compromise, the less it is detected — the opposite of what a detector should do.

**Decision.** `FleetBaseline.build()` takes a `contaminated` flag per session. Two populations, deliberately:

- **modal configuration** — clean sessions only. The pipeline marks a session contaminated when it carries a
  finding of HIGH or above, which requires S6 to run *before* the baseline is built, so `pipeline.py` was
  reordered.
- **fingerprint rarity** — every session. Rarity is a property of the observed population; excluding an
  attacker's JA3 from its own denominator would hide the signal we want.

If fewer than three clean sessions remain, fall back to the full population and record that in
`contaminated_count`. A baseline built on two sessions is worse than no baseline.

**Rejected.** Purely unsupervised outlier rejection as in the KMIP paper — we already have rule severities, which
are a stronger and explainable signal than a distance threshold.

**Consequence.** On the demo capture, 6 of 13 sessions are now excluded from defining normal. Three tests pin the
behaviour, including one that demonstrates the inversion the old code produced.

---

## ADR-0020 — Models are trained off-machine, from a self-sufficient corpus

**Date:** 2026-09-28 · **Status:** Accepted

**Context.** scikit-learn cannot run on the development machines (ADR-0012), and WSL2 is still not installed.
`ml/train.py` had therefore never been executed — and reviewing it found two real bugs, one of which silently
flattered the model.

**Decision.** `ml/corpus.py` now writes a `baseline_risk` column alongside the features and label, making
`data/corpus.csv` **self-sufficient**: a training run needs the CSV and nothing else from this repository — not
the rule engine, not the schema. `notebooks/train_models.ipynb` trains both models in Colab and emits joblib
bundles in exactly the format `RiskModel.load()` expects.

**Bugs found while reviewing code that had never run:**

1. `train_test_split` shuffles, but the baseline comparison sliced `samples` by position afterwards. The two sets
   did not correspond, and the "test" rows largely overlapped the training data — so the model-beats-baseline
   claim was measured against rows the model had seen. Now the indices are split alongside the arrays.
2. The Isolation Forest was fitted on healthy rows from the **whole** corpus, leaking test rows, and was never
   evaluated at all. It now fits on the training split only and reports ROC-AUC and precision at the top 10%.
3. `classification_report` was passed five `target_names` without pinning `labels`, which raises if a severity is
   absent from the test split.

**Consequence.** D16/D17 stay PARTIAL until someone runs the notebook, but the path is now fifteen minutes rather
than blocked on WSL2. The bar to beat is recorded: **baseline MAE 0.1683** on the 10,000-row corpus.

---

## ADR-0021 — Flask, not FastAPI; stdlib sqlite3 for persistence

**Date:** 2026-09-28 · **Status:** Accepted (supersedes the backend row in ADR-0002)

**Context.** `docs/03_ARCHITECTURE.md` and the `api/` stub both specified FastAPI. Before building against it, the
call path was tested rather than the import:

```
python -c "import fastapi"
ImportError: DLL load failed while importing _pydantic_core:
An Application Control policy has blocked this file.
```

FastAPI depends on Pydantic v2, which ships a compiled Rust core. That is the **seventh** Smart App Control block
on this project. Flask, Starlette, Jinja2 and stdlib `sqlite3` were all tested and all work.

**Decision.** The HTTP service is **Flask**. Persistence is **stdlib `sqlite3`** — no ORM, no migration framework,
no new dependency of any kind.

**Rejected.** Starlette — works, but async adds friction for a beginner team and buys nothing here. Waiting for
WSL2 — it has slipped for five days. Pydantic v1 — unmaintained, and FastAPI's modern versions require v2.

**Consequence.** Had this not been checked first, it would have been discovered mid-build. The general lesson is
already in CLAUDE.md and is now proven a second time: **on these machines, test the call path, not the import.**
`import cryptography` succeeds while `cryptography.x509` fails; `import pydantic` fails outright but only when the
model class is touched.

---

## ADR-0022 — The platform layer: Flask, sqlite3, and a name instead of an identity system

**Date:** 2026-09-28 · **Status:** Accepted

**Context.** Every box in the user-flow diagram that carries *state* rather than facts was unbuilt: no job model,
no persistence, no triage decision, no audit trail, no archive. The analysis engine was complete and the
application around it did not exist.

**Decision.** Four new contract objects in `schema/platform.py`, persisted by `securemailscope/store.py` in one
SQLite file, exposed by a Flask app in `securemailscope/api/`:

| Object | Workflow box |
|---|---|
| `AnalysisJob` | QUEUE FOR INGESTION, and `REJECTED` *is* the ABORT/ERROR LOG outcome |
| `FindingDisposition` | TRIAGE ALERT / INCIDENT CLOSED (false positive) |
| `AuditEvent` | LOG AUDIT DATA |
| `PostureSnapshot` | REPORT ARCHIVED / AUDIT POSTURE FINALIZATION |

Three decisions inside that are worth stating, because each had a tempting wrong answer:

**`REJECTED` is not `FAILED`.** Rejected means we refused the input; failed means we accepted it and broke.
Collapsing them hides our own bugs behind "bad file".

**Dispositions are keyed on `rule@host:port`, not on a per-run finding id.** An analyst's decision has to survive
re-analysing the same infrastructure. Keyed on a run id, every run resets the queue and the decisions are
worthless. The transitions are a state machine, and an illegal one raises rather than being silently accepted —
an audit trail is only worth something if the transitions in it were legal. Accepting risk requires a written
justification, because an unexplained acceptance is indistinguishable from an unread alert.

**`Actor` is a name on a request header, not an identity system.** The SECURITY ADMIN lane needs attribution, not
authentication. OAuth would cost a day and impress nobody.

**Rejected.** FastAPI (blocked — ADR-0021). An ORM or migration framework: five tables do not need one, and after
seven dependency blocks the thing that persists state must not add a dependency. Celery or Redis for the job
queue: a daemon thread is sufficient for single-file analysis and adds no infrastructure.

**Consequence.** `python -m securemailscope.api` serves the whole workflow. Verified over HTTP end to end: sample
capture → queued → 13 sessions, 32 findings, grade D → CEF export → snapshot archived and finalised → disposition
recorded → six audit events. 25 new tests.

**The loop this closes:** `DispositionState.FALSE_POSITIVE` is exposed at `GET /api/training-signal` as a labelled
example. Analyst work becomes supervised signal instead of evaporating, which turns the AI story from a one-shot
score into a system that improves with use.

---

## ADR-0023 — The cipher intersection anomaly requires corroboration

**Date:** 2026-09-28 · **Status:** Accepted (revises ADR-0016)

**Context.** `scripts/evaluate.py` was written and run for the first time. On its first execution it reported two
false positives, both `ATTACK-CIPHER-INTERSECTION-ANOMALY`:

- `imaps_implicit_weak` — client offers RC4 *and* modern suites; server picks RC4. Forward secrecy and AEAD both
  lost, so the raw signal is true.
- `imaps_expiring_cert` — server picks a CBC suite over an available AEAD one. Forward secrecy retained.

ADR-0016 already made this detector "deliberately conservative" by requiring a loss of forward secrecy or AEAD.
That is still too loose, and the reason is structural: **a modern client offers modern suites to every server it
meets.** So any legacy server will always appear to "select something weaker than was available". The detector
was therefore firing on age, not on attack — and doing so in the `ATTACK_EVIDENCE` category, which alleges that
someone is attacking you. The deprecated-version, weak-cipher and no-forward-secrecy rules already reported the
actual problem correctly; this was a fourth finding for the same fact, with a false story attached.

**Decision.** The intersection anomaly is only reported as attack evidence when **corroborated** by an explicit
protocol-level downgrade signal: the RFC 8446 §4.1.3 `DOWNGRD` sentinel, or `TLS_FALLBACK_SCSV` (RFC 7507), which
a client sends only when retrying after a handshake failed. The raw comparison is still computed — it is a fact
about the handshake — but on its own it is not evidence of anything.

**Rejected.** Lowering its severity instead: the category would still be wrong. Removing the detector: with
corroboration it catches something no single-suite rule can see, namely *what was lost* in a downgrade.

**Consequence.** Precision across the ground-truth corpus went from 0.9375 to 1.0, with recall unchanged at 1.0.
Two tests pin both directions — the legacy server must stay quiet, the corroborated downgrade must still fire.

**How this was found is the point.** The manifest's expectations were derived from `testbed/synth.py`'s scenario
configuration, never from the analyser's output. Had they been generated by running the tool, precision would
have been 1.0 from the start and this bug would have shipped into the demo.

---

## ADR-0024 — Real authentication after all, stdlib only

**Date:** 2026-09-29 · **Status:** Accepted (revises ADR-0022)

**Context.** ADR-0022 said *"`Actor` is a name on a request header, not an identity system. The SECURITY ADMIN
lane needs attribution, not authentication. OAuth would cost a day and impress nobody."* Two of those three
sentences were right. The third was wrong about the cost.

An `X-Actor` header is not attribution, it is a self-declared label: anyone can claim to be anyone, so the audit
trail records a string the caller chose. For a tool whose pitch is *forensic evidence you can verify*, an audit
log that cannot say who acted is the wrong thing to demonstrate. The console also has to be shown to judges, and
a dashboard with no front door reads as a report viewer rather than a platform.

**Decision.** `securemailscope/api/auth.py`: PBKDF2-HMAC-SHA256, 240,000 iterations, per-user salt, via stdlib
`hashlib`. A signed Flask session cookie, a `users` table in the same SQLite file, and two seeded demo accounts.
`actor()` now returns the signed-in username and falls back to the header only for scripted callers.

It is roughly 150 lines and adds no dependency, which is the part ADR-0022 got wrong — OAuth would have cost a
day, but a password check does not.

**What it deliberately is not.** No password reset, no MFA, no lockout, no rate limit, no password policy. This
is a hackathon MVP with seeded demo credentials, not an identity provider, and pretending otherwise would be
worse than saying so. Anyone deploying it must change the seeds and put it behind a real front door.

**Two details that are not decoration.** A failed login spends the hashing time even when the username does not
exist, so probing for valid usernames is not faster than guessing passwords; and both failures return the same
message, so the response does not say which half was wrong. `hmac.compare_digest` does the comparison.

**One role boundary, enforced server-side.** Finalising a `PostureSnapshot` is a sign-off and is irreversible, so
it is the SOC manager's action, not an analyst's. The API returns 403, rather than the console merely hiding the
button — a boundary that exists only in the UI is not a boundary. `test_only_an_admin_can_finalise_a_posture`
asserts both halves: analyst 403, admin through to 404 on an unknown id.

**Consequence.** Every audit event now carries a username the caller could not choose. Sign-in and sign-out are
themselves audited (`AuditAction.SESSION_STARTED` / `SESSION_ENDED`, added to `schema/platform.py`). Tests stay
hermetic: `login_required` is bypassed when `TESTING` or `AUTH_DISABLED` is set, so the existing API tests did
not change, while the two new auth tests build an app with `AUTH_DISABLED = False` deliberately.

**Rejected.** Flask-Login (a dependency, for a session dict and a decorator). JWTs (no second service to talk
to; a signed cookie is the same guarantee with less to get wrong). Storing the session key in the source
(regenerated once into `data/session.key`, overridable by `SMS_SECRET`, so a restart does not sign everybody
out and the key is not in git).

---

## ADR-0025 — The console is hash-routed vanilla JS with hand-drawn SVG charts

**Date:** 2026-09-29 · **Status:** Accepted (extends ADR-0018)

**Context.** The first console was one self-contained HTML file with four panels. It proved the API worked. It
was not a product: no navigation, no session detail, no filtering, and nothing that showed the reasoning the
whole project is built on. The nine things worth seeing — posture, ingestion, sessions, triage, certificates,
compliance, audit, archive, export — do not fit on one page.

**Decision.** A Jinja shell (`templates/app.html`) plus two static files: `static/app.css` and `static/app.js`.
Nine views behind a hash router. No build step, no framework, no CDN — same reasoning as ADR-0018, and the same
constraint: node and npm were never installable on these machines.

**Charts are hand-drawn SVG**, about 90 lines for a sparkline, a bar chart, a donut and a gauge. Chart.js from a
CDN would be three lines and would break the one claim that makes the offline story true. The charts are plain
`<path>` and `<circle>` elements with computed coordinates; they render in any browser, offline, forever.

**The UI's job is to make the reasoning visible, not to decorate it.** Three panels exist specifically for that:
the STARTTLS ten-check grid renders V7 as *not observable* rather than as a pass or a fail; the certificate view
prints TLS 1.3's encrypted Certificate message as *the expected behaviour of a correctly configured modern
server*, not as a missing certificate; and every role-adjusted finding shows its own plain-English justification
in the drawer. Those are USP-01, USP-04 and ADR-0014 rendered, and they are the panels to point at on stage.

**Consequence.** `securemailscope/api/console.html` is deleted — superseded, and leaving a second console in the
tree is how a demo ends up opening the wrong one. `test_console_is_served_and_self_contained` was rewritten
rather than relaxed: it now extracts every `href`/`src` from the shell, asserts each resolves to this service,
and greps the served CSS and JS for `http://`, `https://`, `//cdn` and `@import url(`. The offline guarantee is
still tested, against the structure that now exists.

**Verified by driving it**, not by reading it (the rule in `docs/11_TODO.md`): signed in, ran `fleet.pcap` from
the bundled-capture dropdown, 13 sessions and 30 findings at grade D, opened a session drawer and a finding
drawer, acknowledged a finding and confirmed the disposition and its audit event persisted with actor `admin`,
finalised a snapshot, exported CEF and ECS, and restarted the service to confirm the session and the disposition
both survived.

---

## ADR-0026 — The Kavach console: crimson operations UI, and no geographic threat map

**Date:** 2026-09-29 · **Status:** Accepted (supersedes the visual half of ADR-0025)

**Context.** ADR-0025 built a nine-view console on a cyan-on-black palette. A reference design was then
supplied — dark crimson, a split login with a photographic panel, a search-led topbar, KPI cards with
sparklines and percentage deltas, and a tabbed session-detail page. The information architecture from
ADR-0025 survives; the visual language and two of the views do not.

**Decision.** Rebuilt `static/app.css`, `static/app.js`, `templates/login.html` and `templates/app.html`
against that design. Crimson `#dc2626` on `#0a0a0c`, twelve views, a global `Ctrl-K` search across
sessions, findings and certificates, and the session drawer replaced by a full detail page with
Overview / Handshake / Certificates / Evidence / Remediation tabs.

**The reference showed a geographic threat map. We did not build one, and the refusal is the decision.**
It listed countries — Russia, China, Iran, North Korea — with IP counts and finding totals. We cannot
produce that honestly:

- Every host in the corpus is RFC 1918 private space. `10.20.1.23` has no country. Neither will most
  hosts in any *internal* mail capture, which is the use case the problem statement describes.
- No GeoIP database ships with this tool, and adding one means a dependency plus a licensed data file
  on machines where seven compiled packages are already blocked (§5 of `CLAUDE.md`).
- The tool's entire claim is that **every finding is verifiable against the PCAP** (ADR-0004). A world
  map with countries on it would be the one panel on screen that a judge could not verify — and the
  first one they would test.

Fabricating attribution to make a panel look impressive is the exact failure this project has avoided
everywhere else. **Replaced with an Exposure Map**: the real observed topology, three lanes for the
three port roles, one node per server endpoint, radius by session count, colour by worst finding,
dashed ring for anything that carried cleartext. It occupies the same visual space and it doubles as
the clearest statement of USP-01 — the lanes *are* the severity policy.

**Two smaller honesty calls in the same build.**

*Protocol distribution does not use the severity ramp.* Colouring IMAP orange and POP3 yellow implies
IMAP is more dangerous, when it only means there are more IMAP sessions. Colour means severity
everywhere in this console, so the protocol donut uses a neutral red-to-grey ramp instead.

*KPI deltas say what they are measured against.* Comparing two `PostureSnapshot`s is genuine drift
only when they cover the same estate. Across unrelated captures the arithmetic is correct and the
meaning is not — a 1-session capture followed by a 13-session one reads as "+1200%". Each card now
prints `vs previous capture (N)` beneath it, and switches from a percentage to an absolute difference
past ±999%. With one snapshot it says *no prior capture to compare* rather than showing a flat 0%.

**The brand is a setting, not a string.** The reference wordmark says *Kavach*; the code says
*SecureMailScope*; `docs/10_RESEARCH_PAPER.md` says *CyberKavach*. That conflict is still unresolved
(`docs/11_TODO.md` §A), so `app.config["BRAND"]` holds it, a context processor injects it, and the
templates interpolate it. Settling the name is now one line, or `SMS_BRAND` in the environment.

**Consequence.** `test_console_is_served_and_self_contained` was updated to the new eleven-view nav and
still asserts the offline guarantee — every `href`/`src` resolves to this service, and the served CSS
and JS contain no `http://`, `https://`, `//cdn` or `@import url(`. All charts remain hand-drawn SVG.
201 tests pass, `scripts/audit.py` is unchanged at 26 met / 6 partial / 2 not built, and
`scripts/evaluate.py` still reports precision 1.00 / recall 1.00.

**Verified by driving it**: signed in, ran two bundled captures, confirmed the KPI delta path with two
real snapshots, opened all five session tabs, exercised the global search, acknowledged a finding,
finalised as admin and was refused as analyst, and repeated the whole sequence against an empty
database.

---

## ADR-0027 — Link-layer decoding, and never letting an unreadable capture read as clean

**Date:** 2026-09-29 · **Status:** Accepted (extends ADR-0014)

**Context.** S1 decoded exactly one thing: IPv4 over Ethernet. `dpkt.ethernet.Ethernet(buf)` followed by
`isinstance(ip, dpkt.ip.IP)`. That is correct for the synthetic corpus, because `testbed/synth.py` writes
Ethernet, and it was never tested against anything else.

Measured against re-wrapped copies of `fleet.pcap`, **five of seven common encapsulations lost every
single frame**:

| Encapsulation | How you get one | Old path |
|---|---|---|
| Ethernet | the corpus | 236/236 |
| 802.1Q VLAN, QinQ | trunk port | 236/236 (dpkt strips tags) |
| **Linux cooked (SLL)** | **`tcpdump -i any`** | **0/236** |
| **Linux cooked v2 (SLL2)** | newer `tcpdump -i any` | **0/236** |
| **Raw IP** | VPN / tunnel interface | **0/236** |
| **BSD loopback** | `tcpdump -i lo0` on macOS | **0/236** |
| **IPv6** | any modern network | **0/236** |

`tcpdump -i any` is the single most common way an administrator captures traffic. Handing its output to
an Ethernet parser does not raise — it reads the first 16 bytes as a MAC header, produces nonsense,
fails the `isinstance` check, and drops the frame. The capture then analyses **cleanly**, reports *no
mail sessions found*, and scores **A+ / 100**.

**That is the worst failure this tool can have.** It is not a crash, it is a confident wrong answer that
looks exactly like a healthy estate, and it would have happened on stage the first time a judge supplied
their own capture.

**Decision — three parts.**

**1. `securemailscope/capture/linklayer.py`** decodes Ethernet (with 802.1Q and QinQ), Linux cooked v1
and v2, raw IPv4 and IPv6, and BSD loopback, and walks the IPv6 extension-header chain to reach the TCP
segment. Addresses go through `inet_ntop`, not `inet_ntoa`, which is 4-byte only. The link type is read
from the file rather than assumed. It never raises: a malformed frame is counted, not thrown, because a
single bad packet must not end a million-packet run.

**2. `testbed/relink.py`** re-wraps an existing capture into every one of those encapsulations. Because
the TCP payloads are byte-identical, the analysis **must** produce the same findings — so the test is
invariance, and any difference is a link-layer bug and nothing else. `fleet_ipv6.pcap` maps addresses
into `2001:db8::/32`, which RFC 3849 reserves for documentation.

**3. A capture-level finding, `ANALYSIS-CAPTURE-NOT-READABLE`**, and a forced `Grade.INCOMPLETE`.
Decoding more link types is not enough — 802.11, PPP and the rest still yield nothing, and *something
will always be unsupported*. So when the decode rate collapses, the report says so at HIGH severity and
**the fleet grade becomes `?` with a score of 0**, never A+. This is ADR-0014 one layer down: absence of
evidence is not evidence of absence.

**The false positive this introduced, and the fix.** The first version counted *IP-bearing* frames as
"decoded", so a capture containing only ARP — perfectly readable, simply not mail — was reported as
unreadable. `Capture.decoded_frame_count` now means *frames whose link layer we could parse*, non-IP
included. Caught by `test_a_readable_capture_with_no_mail_is_not_flagged`, which exists because this
project's own rule is that a tool which cries wolf is worse than one that says nothing (USP-01).

**Contract change.** `Capture` gains `decoded_frame_count` and `link_layer_note`. Coverage is evidence,
so it belongs in the report rather than in a log line. `schema/generated/` and
`web/src/types/schema.ts` regenerated; `docs/03_ARCHITECTURE.md` updated in the same commit, per the
documentation rules.

**Rejected.** Scapy (a dependency, and it is slow). Shelling out to `tshark` (not installed, and it
would move the parsing we deliberately own out of process). Silently ignoring undecodable frames — which
is what the old code did, and is the entire reason this ADR exists.

**Consequence.** 11 new tests in `tests/test_linklayer.py`. All seven encapsulations now produce
**13 sessions, 30 findings, grade D** — identical to the Ethernet baseline. `scripts/audit.py` unchanged
at 26 / 6 / 2; `scripts/evaluate.py` unchanged at precision 1.00 / recall 1.00.

---

## ADR-0028 — The narrative layer is verified, not trusted

**Date:** 2026-09-29 · **Status:** Accepted

**Context.** O02 asks for mitigation recommendations and USP-04 claims three explainable-AI layers, of
which the third — a language model turning findings into prose — was a stub. The obvious build is: send
the findings to a model, print what comes back.

That would have destroyed the thing this project actually sells. Every other number in the report traces
to a deterministic rule with an RFC citation behind it, and every finding carries frame numbers a judge
can type into Wireshark. A model breaks that by construction: it emits fluent text whose relationship to
the input is unverified, and its failure mode is not gibberish but a *plausible* host, a *plausible*
CVE, a rule identifier that sounds exactly like one of ours. **In a security report, a confident
invented fact is worse than no report at all.**

**Decision — four parts.**

**1. Grounded.** `llm/grounding.py` builds a `FactSheet`: counts, rule identifiers, severities, and the
remediation text the rule pack already wrote. Never capture bytes, credentials, banners or payloads. The
model cannot leak what it was never shown, which is cheaper and more reliable than redaction. The sheet
is hashed and the hash travels on the narrative, so *"this text describes that report"* is checkable
rather than asserted.

**2. Verified.** `llm/verify.py` treats generated prose as untrusted input and checks it against the
sheet's closed vocabulary — every IP address, hostname, rule identifier, RFC, NIST reference and CVE
must already appear in the facts, and severity claims must not contradict the counts. **Anything
unverifiable and the entire narrative is discarded**, not flagged and not repaired. A partially
hallucinated security report is not a degraded report, it is an untrustworthy one, and the deterministic
path is always available and always correct.

**3. Deterministic by default.** `llm/templates.py` produces the full narrative — executive summary,
action plan, scope note — with no network, no model and no API key. **It was written first and it is
what ships**; the model is an optional improvement judged against it. Writing the fallback second is how
projects end up with a fallback nobody would want to read. `SMS_LLM_BACKEND` is unset by default, so the
demo path never makes a call and cannot die on a timeout.

**4. Structurally unable to analyse.** `narrate()` is handed a *finished* `Report` and only the
`narrative` field comes back. It cannot add, remove or re-score a finding, and
`test_the_layer_cannot_change_the_analysis` asserts the findings and fleet grade are byte-identical
before and after. That boundary is what keeps the AI story defensible under questioning.

**The plan is not the finding list.** Thirteen sessions with one weak cipher is one action, and two
rules closed by the same config line is one action. 30 findings collapse to 17 actions on the corpus. A
plan that repeats itself is a plan nobody finishes, and listing the same `smtpd_tls_security_level`
change twice makes the tool look like it cannot count.

**Two bugs the guardrail found in itself.** The first version rejected *our own template output*,
because the rule pack cites "NIST SP 800-52 Rev 2" and the prose says "NIST SP 800-52" — fixed with
prefix matching in both directions. The second **accepted `mail.corp.internal`**, because it checked IP
addresses and not DNS names, which is the most natural thing for a model to invent and the easiest to
believe. A verifier that rejects correct text gets switched off; one that accepts fabrications is
decoration. Both cases are now in `test_verifier_rejects_every_kind_of_fabrication`.

**The audit was changed too.** It previously scored this deliverable by counting lines in
`llm/__init__.py` — `len(...) > 40`. That is exactly the "do not claim it works without running it"
failure the project has a rule about, sitting inside the tool that verifies the other rules. It now
calls `narrate()` and checks the plan it gets back.

**Contract change.** `ActionItem` and `Narrative` added to `schema/models.py`; `Report.narrative`.
Provenance (`generated_by`, `verification`, `grounding_sha256`) is part of the contract, not a log line,
because a narrative that cannot say where it came from is not evidence. Regenerated
`schema/generated/` and `web/src/types/schema.ts`; `docs/03_ARCHITECTURE.md` updated in the same commit.

**Rejected.** Letting the model write the action plan (it would then be inventing remediation, which is
the one place a wrong answer breaks production). Retrying or repairing rejected output (a model talked
into passing a verifier has learned to pass the verifier). Shipping the model path by default (a demo
that needs a network is a demo that fails on stage).

**Consequence.** **O02 goes PARTIAL → MET.** USP-04 layer 3 is built; the USP stays PARTIAL only
because layer 1 still lacks the trained model, which is blocked on the Colab run. 20 new tests, 231
total. `scripts/evaluate.py` unchanged at precision 1.00 / recall 1.00 — the layer touches no rule.

---

## ADR-0029 — Drift refuses to compare estates that are not the same estate

**Date:** 2026-09-29 · **Status:** Accepted

**Context.** USP-10 promises *"grade fell from B+ to C on 14 March — mail-03 was redeployed with a
1024-bit key."* The data has been available since ADR-0022: a `PostureSnapshot` is archived for every
completed job and the full report is kept alongside it, so the diff was a matter of writing it.

The trap is not the diff. It is that **the arithmetic works on any two reports**. Compare a one-host
capture with a fleet capture and you get "grade fell from A+ to D", which reads as a catastrophe and is
really two unrelated files. The console already made a softer version of this mistake — KPI deltas
showing "+1200% sessions" across two different PCAPs (ADR-0026) — and the fix there was to label the
comparison. At the source, labelling is not enough.

**Decision.** `securemailscope/drift.py` computes host overlap first and **refuses** when it falls below
50%: `comparable` is False, the finding lists are left empty, and the summary says why. It also refuses
when both sides are the same capture file, which is the other way to produce a confident zero.

Fifty percent is a judgement call and is stated as one. Half the hosts in common is a re-scoped capture
of one network; a quarter is two different networks that happen to share a subnet convention. The floor
is a parameter so a caller with better knowledge can override it, and the test suite exercises the
boundary in both directions.

**Findings are identified by `rule_id@host:port`** — the same key dispositions use (ADR-0022), verified
by a test, so an analyst's decision and a drift entry refer to the same thing. That key is deliberately
**not unique within a report**: two sessions to one endpoint each produce their own finding, and
`PQ-NOT-READY@10.20.1.23:993` legitimately appears twice in the corpus. The key identifies *a condition
on an endpoint*, which is the right granularity for both a disposition and a drift entry, so the
partition is over distinct keys rather than raw findings.

**Per-host drift matters more than fleet drift.** On the corpus the fleet score moves **−0.3** while
`10.20.1.11` falls 99 points (A+ → F, redeployed with RC4 and TLS 1.0) and `10.20.1.16` rises 96
(remediated to TLS 1.3). A monitoring tool that reported only the fleet number would have said *nothing
happened* on the day a mail server was rebuilt wrong. The summary therefore names the largest regressing
host and the finding that caused it, because "grade fell" without a reason is not actionable.

A host whose score held but whose findings changed is reported as `changed`, not `unchanged` — two
findings swapping out at equal weight is exactly how a redeployment slips past a monitor.

**The corpus.** `testbed/synth.py` gained `fleet_later.pcap`: the same eleven hosts, two of them
changed. The new scenarios are **deliberately not in `SCENARIOS`**, because adding them would change
`fleet.pcap` and invalidate the hand-authored ground truth in `manifest.json` — the rule from
`CLAUDE.md` §8 about never letting the corpus drift under the evaluation.

**One portability bug worth recording.** The summary used `→`. A Windows console is cp1252 and cannot
encode U+2192, so printing a drift summary crashed — on the machines this team actually uses, from a
script that already prints summaries. Now ASCII, with `test_summary_is_ascii_printable_on_a_windows_console`
to keep it that way.

**Consequence.** **USP-10 goes NOT BUILT → MET**; the audit reads **28 met / 5 partial / 1 not built**.
`GET /api/drift` defaults to the two most recent snapshots and takes `?before=&after=`. The console
gains a Posture Drift view that renders the refusal as prominently as the diff. 16 new tests, 247 total.
`scripts/evaluate.py` unchanged at precision 1.00 / recall 1.00 — drift touches no rule.

**Rejected.** Diffing the `PostureSnapshot` rows alone (they carry counts, not findings, so the answer
would be "grade fell" with no cause — the half of the sentence that matters). Warning instead of
refusing on low overlap (a warning above a filled-in chart is read as a chart). Matching hosts
fuzzily by subnet (guessing which machines are "the same" is exactly the kind of inference this tool
does not make).

---

## ADR-0030 — The attack matrix is worth more for what it rules out

**Date:** 2026-09-29 · **Status:** Accepted

**Context.** USP-09 promised named attacks with feasibility verdicts. `Finding.related_attacks` already
carried the names — *BEAST*, *Lucky13*, *Sweet32* — but a name attached to a finding is a label, not a
verdict. "RC4 was negotiated (see: RC4 biases)" tells an administrator nothing they did not know.

**Decision.** `securemailscope/attacks.py` holds sixteen named attacks, each with a stated precondition
and a predicate evaluated against every session. The fleet verdict is FEASIBLE if any session meets the
precondition, NOT APPLICABLE if sessions were checked and none did, NOT OBSERVABLE if nothing could be
judged.

**The NOT APPLICABLE rows are the deliverable.** A report listing only what is broken is
indistinguishable from a report by a tool that never looked. *"POODLE: not applicable — checked 9 of 13
sessions, none negotiated SSL 3.0"* is a claim with a method behind it, and a judge can test it by
handing us a capture that does contain SSLv3. The audit enforces this: USP-09 is only MET when the
matrix contains **both** feasible and ruled-out entries, because a matrix that only ever says "feasible"
has not demonstrated that it checked anything.

**Three verdicts, not two.** `NOT_OBSERVABLE` exists because TLS 1.3 encrypts the certificate, an
unparsed handshake hides everything, and the corpus contains sessions with no TLS at all. Every
predicate is wrapped so that a session without a parsed handshake returns `None` rather than `False` —
answering "not vulnerable" about a session we could not read is the exact class of bug this project
keeps catching. `test_a_capture_with_no_handshakes_judges_nothing_rather_than_clearing_it` pins it.

**Heartbleed is in the registry specifically to always read NOT OBSERVABLE.** CVE-2014-0160 needs the
heartbeat extension *and* a vulnerable OpenSSL build on the server, and a passive observer sees neither
the server's version nor, necessarily, any heartbeat message. Including it and refusing to rule it out
is a stronger statement than omitting it.

**Two bugs found by reading the generated table rather than the code.**

*POODLE reported FEASIBLE against TLS 1.2.* The predicate was `tls_version_num <= 3.0`, and on that
scale TLS 1.0 is `1.00` — so it matched every session in the corpus. A false positive on the most
recognisable CVE in the table, and precisely the sort of thing that gets found on stage. Version
comparisons now go through the `TlsVersion` enum, where `SSL3` cannot be confused with `1.2`.

*Heartbleed reported NOT APPLICABLE.* The predicate returned `False` when the ClientHello did not offer
the heartbeat extension — which only says this *client* did not ask for it. Clearing a server of
Heartbleed on that basis is false reassurance of exactly the kind the rest of the tool refuses to give.

Both were visible the moment the table was printed, and invisible while reading the predicates.

**Consequence.** **USP-09 goes PARTIAL → MET**; the audit reads **29 met / 4 partial / 1 not built**.
On the corpus: 9 feasible, 6 ruled out, 1 not observable. 16 new tests, 263 total. `scripts/evaluate.py`
unchanged at precision 1.00 / recall 1.00 — the matrix reads the analysis and does not alter it.

**Rejected.** Scoring attacks by CVSS (a number about the CVE in general, not about this estate; the
useful severity is what it costs *here*, which the port role already decides). Attempting exploitation
to confirm feasibility (the entire project is passive). Listing only feasible attacks — which would have
halved the work and removed the reason it is interesting.

---

## ADR-0031 — Train the model locally, in pure Python, and stop depending on Colab

**Date:** 2026-09-29 · **Status:** Accepted (supersedes the training half of ADR-0012)

**Context.** ADR-0012 concluded that no trained model was possible here: Smart App Control blocks numpy's
C extensions, scikit-learn will not install, and the answer was `notebooks/train_models.ipynb` on Colab.
That left the project's only remaining human-blocked item, and it made the demo's AI layer depend on a
Google login — for a tool whose entire pitch is that it has no dependencies to be blocked.

That conclusion was too quick. The blocked thing is *scikit-learn*, not *machine learning*. The corpus is
10,000 rows by 54 features, which is small, and this project has already written a DER parser, RSA
signature verification and a certificate generator from scratch for exactly the same reason.

**Decision.** `securemailscope/ml/gbt.py` (histogram gradient-boosted regression trees) and
`ml/iforest.py` (isolation forest), pure stdlib, plus `scripts/train_local.py`. Training takes **eleven
seconds** and needs nothing that is not already installed.

Histogram-based split finding, following LightGBM (Ke et al., NIPS 2017): each feature is bucketed into
at most 64 bins once, so split search scans bins rather than rows. That is the difference between a
one-minute run and a twenty-minute one, and in CPython it is what makes this practical at all.

**Results on held-out data** — 8,000 train / 2,000 held out, split by index:

| | |
|---|---|
| Rule-derived baseline MAE | **0.1681** |
| Trained model MAE | **0.0451** |
| Improvement | **73%** |
| R² | 0.9429 |
| Spearman (ordering, which is what a triage queue needs) | 0.9225 |

**`archetype` is excluded as leakage**, and finding that mattered more than the model. It is the corpus
generator's latent variable: it decides how a row is drawn, is not a field of `FeatureVector`, and does
not exist when a real session is scored. Training on it would have taught the model
"archetype=compromised implies high risk" — circular, flattering, and worthless on real traffic.

**Explanations are exact, not approximate.** Contributions come from path decomposition (Saabas): each
split attributes the change in node mean to the feature that caused it, and they sum to
`prediction − bias`. `test_contributions_sum_exactly_to_the_prediction` asserts that identity, and it
immediately caught a missing term — each tree's **root value** is the mean residual before any split, so
it belongs to no feature and folds into the bias. The contributions were "nearly right", which is the
kind of wrong an explanation panel ships with.

**The trainer refuses to write a model that loses.** The rule-derived baseline is a real product. If the
model does not beat it on held-out data, `train_local.py` prints why and exits non-zero without writing,
and the baseline ships. `--force` exists for a deliberate override.

**The grade stays rule-derived.** Wiring the model in immediately produced two regressions: a session
with **zero findings** graded B because the model returned 0.18, and a host whose handshake could not be
parsed graded **F** rather than `?`. Host scoring had been reading `assessment.risk_score`, which was
findings-derived only because the baseline is. The fix is a principle, not a patch: **the posture grade
(D19) is computed from findings, every one of which carries an RFC citation and frame numbers; the model
scores risk for triage (D16) and ordering (D18).** A model that can move a grade with nothing to point
at would make the headline number the one thing in the report that cannot be checked.

Note the second regression was ADR-0014 half-implemented — the guard downgraded A+/A/B to `?` but had
nothing to stop a host we could not inspect being *condemned*. Over-crediting and over-condemning an
uninspected host are the same error.

**One pre-existing bug surfaced.** `_LABELS` in `ml/classifier.py` is read as *(phrase when 0, phrase
when 1)*, but six entries were written as *(good, bad)* — the same thing only when 1 means bad. So
`has_forward_secrecy=1` rendered as **"No forward secrecy"** and `pq_hybrid_offered=1` as **"No
post-quantum group offered"**, in the panel that exists to demonstrate USP-04. It was invisible while the
baseline rarely surfaced those features; the trained model put them at the top of the waterfall.

**Consequence.** **D16 and D17 go PARTIAL → MET**, and USP-04 with them — the audit reads **32 met /
1 partial / 1 not built**. Nothing is blocked on a human any more. `run.sh` / `run.ps1` bring a clean
checkout to a running console in one command. 15 new tests, 277 total. `scripts/evaluate.py` unchanged
at precision 1.00 / recall 1.00, because the rule engine is untouched.

**The audit was wrong too.** D16's check was `backend == "gradient"` against a value of
`"gradient_boosting"`, so it could never have reported MET even with a model loaded. Fixed, and it now
quotes the held-out metrics rather than asserting a file exists.

**Rejected.** Keeping the Colab notebook as the primary path (a demo that needs a Google login is a demo
that can fail on someone else's network). Pickle or joblib for the model file (both want numpy here;
JSON is 674 KB and readable). Implementing full TreeSHAP (path decomposition is exact for this and an
order of magnitude simpler). Deleting the notebook — it stays as a cross-check, now clearly marked
optional.

---

## ADR-0032 — The research paper gets its own renderer, not a flag on `md_to_pdf.py`

**Date:** 2026-09-27 · **Status:** Accepted

**Context.** The submitted research document has to match the format the reference SIH research papers use —
a LaTeX `article` look: Times serif throughout, a title page carrying the abstract and keywords, a generated
table of contents with dotted leaders and real page numbers, a running header, centred page numbers.
`scripts/md_to_pdf.py` produces a deliberately different thing: a sans face, coloured headings, a band across
the top. That is right for the working documents and wrong for a paper. Neither can be the other with a
stylesheet swap, because the paper also needs a two-pass build (a table of contents cannot know page numbers
until the document has been laid out once) and a different document template class.

**Decision.** `scripts/md_to_paper.py` is a separate entry point. It imports `md_to_pdf` — which is also what
installs the PIL stub (ADR-0012) — and reuses `inline()`, `_table()` and the font discovery, then overrides the
styles, swaps `SimpleDocTemplate` for a `BaseDocTemplate` with `multiBuild` and an `afterFlowable` hook that
notifies each heading's page, and adds title-page and front-matter handling.

**Rejected.** A `--style paper` flag on `md_to_pdf.py` — the two differ in document class, build method and
front-matter handling, so the flag would have branched most of the module. Generating LaTeX and compiling it —
no TeX distribution on these machines, which is the same constraint that produced the renderer in the first
place. Hand-formatting in Word — the document changes every time the code does, and a format that cannot be
regenerated from Markdown will silently go stale.

**Consequence.** `python scripts/md_to_paper.py docs/10_RESEARCH_PAPER.md --out out/` regenerates the paper
after any edit. The source of truth stays Markdown in git. The two renderers share the parts that are genuinely
shared and nothing else.

**Note for whoever touches it next:** the abstract handler folds hard-wrapped source lines back into paragraphs.
A first cut emitted one `Paragraph` per source line, which justified each line separately and left orphan words
("can", "been", "payload,") stranded on their own lines. It looked broken and the text extraction did not show
it — it was only visible by rendering the page and looking at it.
