# 11 — What to do

No dates, no estimates. Ordered by value, with the reason each item matters. Tick things off here as they land.

**Before starting anything:** `python scripts/audit.py`. **After finishing anything:** run it again.

---

## A. Blocked on a human

Nothing in the repo can move these.

- [ ] **Push the outstanding commits.** Git cannot push from these machines (`libcurl-4.dll` blocked). Use GitHub
      Desktop or VS Code's built-in git. This is the only item that risks *losing* work.
- [ ] **Run `notebooks/train_models.ipynb` in Colab** with `data/corpus.csv`. Drop the three output files into
      `models/`. → **D16 and D17 go PARTIAL → MET.** The bar to beat is baseline MAE **0.1683**; if the model
      loses, the notebook says so and the baseline is what ships.
- [ ] **Fix the MITM box on the user-flow slide.** The flowchart currently shows *our tool* performing
      `MITM ATTACK → FORCE PLAINTEXT DOWNGRADE`. It contradicts the PS (passive), our own scope boundary, and
      USP-02. Replace with `Downgrade evidence present? → classify attack evidence`. Also drop
      `MAIL STREAM CAPTURE` — live capture is out of scope.
- [ ] **Settle the name.** `docs/10_RESEARCH_PAPER.md` says *CyberKavach*; code, README, slides and every other
      doc say *SecureMailScope*. Every hour this stays open is another place to change.

---

## B. Close the remaining partials

The audit currently reads **25 met / 7 partial / 2 not built**. These four items take it to **31 / 1 / 2**.
The last partial is D20's PDF, which needs Playwright and is already covered by browser print.

- [ ] **`scripts/evaluate.py`** → closes **USP-07**. *Top code priority.*
      It still raises `NotImplementedError`, while USP-07 claims *"unlike almost anyone else, we can tell you our
      precision and recall."* **A claimed differentiator with no data is worse than not claiming it**, and it is
      the first thing a technical judge probes.

      **Known obstacle:** `testbed/manifest.json` was written on day one as a spec and lists 18 captures whose
      names do **not** match the 13 scenarios `testbed/synth.py` actually produces. The manifest has to be
      rewritten against reality first.

      **Do this honestly:** derive `expected_findings` from each scenario's *configuration* in `synth.py` — the
      cipher suites, versions and certificates it sets — reasoning about which rules *should* fire. **Do not
      generate them by running the tool**, or the ground truth becomes a copy of the output and the precision
      figure means nothing. Disagreements between the hand-derived truth and the actual output are the entire
      point: that is where the number comes from.

- [ ] **LLM remediation layer** (`securemailscope/llm/`) → closes **O02 + USP-04**.
      Follow the Dynamic Metric Engine pattern from Unal & Celiktas (`docs/07_RELATED_WORK.md` §3): the model
      consumes structured findings and emits narrative and config text only. It may **never** introduce, remove or
      re-score a finding. Deterministic template fallback so a demo cannot die on an API timeout.

- [ ] **Attack feasibility matrix** → closes **USP-09**.
      `Finding.related_attacks` already exists. Needs a feasibility verdict per attack (*Sweet32 — feasible:
      3DES with long-lived sessions*; *POODLE — not applicable*) and a panel in the report.

- [ ] **Two-part PQ claim** → sharpens **USP-05**.
      Dubey & Varshney: 49.3% of domains support hybrid PQ key exchange but **zero** use PQ certificates. The
      parser already reads `supported_groups`, so report both dimensions instead of one number.

---

## C. The platform layer  —  **built** (ADR-0022)

Everything below shipped. `python -m securemailscope.api` serves it on port 8000; the whole
workflow was exercised over HTTP end to end. What remains here is the browser UI on top.

This is what makes the demo match the user-flow slide. It closes no deliverables but it is what judges *see*.
Build order matters — each item depends on the one above.

**Stack is settled: Flask + stdlib `sqlite3` + Jinja2.** FastAPI is unusable here (ADR-0021).

- [x] **`AnalysisJob` + SQLite + Flask upload/progress/result.**
      States: `queued → validating → running(stage) → completed | failed | rejected(reason)`.
      Unlocks every other box in the workflow; `rejected` *is* the ABORT/ERROR LOG box.
- [x] **Serve the existing HTML dashboard from Flask** — `GET /api/reports/<id>/html`, plus
      `GET /api/samples` and `POST /api/samples/<name>/analyse` for the demo safety net., plus a sample-capture dropdown so the demo never depends
      on upload working.
- [x] **`FindingDisposition`** — `new → acknowledged → in_progress → resolved | false_positive | accepted_risk`.
      The single item that turns a report generator into a platform. **And it closes a loop:** every
      `false_positive` is a labelled training example, which makes the AI story a system rather than a one-shot
      score.
- [x] **`AuditEvent`** — append-only `(timestamp, actor, action, object, before, after)`. Serves the LOG AUDIT
      DATA box, the forensics persona, and the CERT-In six-hour reporting hook.
- [x] **SIEM export** — findings as CEF or ECS over syslog/webhook. Roughly 80 lines, and it is the difference
      between "a tool" and "a tool that fits an existing SOC".
- [x] **`PostureSnapshot`** — immutable finalised snapshot. Covers REPORT ARCHIVED and AUDIT POSTURE FINALIZATION,
      **and gives USP-10 temporal drift for free**, because two snapshots are a diff.
- [x] **`Actor`** — a name and role on jobs and audit events. **Do not build real auth.** A name field satisfies
      the SECURITY ADMIN lane; OAuth eats a day and impresses nobody.

---

## D. Robustness — insurance against the worst demo moment

- [ ] **Link-layer coverage.** Currently **IPv4 over Ethernet only**. A judge's capture could be IPv6, VLAN-tagged
      (802.1Q) or Linux cooked capture (SLL), and we would report "no mail sessions found". This is the most
      likely cause of an on-stage failure.
- [ ] **Malformed-input harness.** Truncated, empty and random-byte files through the pipeline; assert no crash.
      Then the claim is "N malformed inputs, 0 crashes".
- [ ] **Real-world PCAPs.** Everything in the corpus is synthetic *and* self-authored. Even five public captures
      (Wireshark sample wiki, malware-traffic-analysis.net) parsing correctly kills the "you only test your own
      output" objection. It will also find bugs.
- [ ] **Look at the dashboard in a real browser.** Verified structurally only — nobody has actually seen it.

---

## E. Documentation debt

- [x] `docs/03_ARCHITECTURE.md` and `api/__init__.py` corrected from FastAPI to Flask (ADR-0021).
- [x] CLAUDE.md records all seven dependency blocks and the known-good library list.
- [ ] Commit the three untracked docs (`08_PITCH`, `09_DECK_CONTENT`, `10_RESEARCH_PAPER`) into the index in
      `docs/00_INDEX.md` — they exist but are not listed.
- [ ] `docs/06_STATUS.md` is generated; regenerate it after the Colab run lands.

---

## Rules that stop repeat mistakes

These are not style preferences. Each one is here because ignoring it already cost time.

1. **Test the call path, not the import.** `import cryptography` succeeds while `cryptography.x509` fails.
   `import reportlab` fails only because it imports Pillow. `import fastapi` fails on Pydantic's Rust core.
2. **Run it before claiming it works.** Bugs found only by running: an anchored regex made every STARTTLS session
   report as cleartext; citing a standard was being counted as violating it; the anomaly baseline learned "normal"
   from the attacks; `train_test_split` shuffles, so the model was scored on rows it had trained on.
3. **Never let unanalysed read as clean.** A host we could not inspect grades `?`, not `A+` (ADR-0014).
4. **Ground truth must be authored independently of the tool.** If expected results are generated by running the
   thing under test, the accuracy figure is meaningless.
5. **Every rule carries its citation when written.** Backfilling on the last day does not happen.
6. **`scripts/audit.py` before and after.** It caught the USP-01 side-by-side silently breaking when the corpus
   moved to real certificates.
