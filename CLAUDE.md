# SecureMailScope — project context

Read this first. It is the handoff brief for a new session.

**What:** AI-assisted passive cryptographic posture assessment for email infrastructure. Takes a PCAP,
reconstructs every SMTP/IMAP/POP3 session, parses TLS handshakes and X.509 certificates, finds cryptographic
weaknesses, ranks them, and emits config snippets to fix them. **Nothing is decrypted.**

**Why:** Smart India Hackathon 2026, problem statement "SecureMailScope". Team of six, beginners, code written
with AI assistance. Repo: `github.com/dhruvpanicker79/novax159` (private).

> **Naming conflict, unresolved.** `docs/10_RESEARCH_PAPER.md` calls the project **CyberKavach**; the code,
> README and every other doc say **SecureMailScope**; the console's wordmark says **Kavach**. Settle this
> before submission — it touches the slides, the paper and the repo. The UI half is now one line:
> `app.config["BRAND"]` in `securemailscope/api/__init__.py`, or the `SMS_BRAND` environment variable
> (ADR-0026).

---

## 1. Current state

| | |
|---|---|
| Python | ~15,800 lines, plus ~2,200 of console CSS/JS/HTML |
| Tests | **211, all passing** |
| Docs | ~51,000 words across 12 documents, **28 ADRs** |
| Deliverables | **26 met, 6 partial, 2 not built** — verify with `python scripts/audit.py` |
| Accuracy | precision 1.00, recall 1.00 over 14 captures / 20 rules (`scripts/evaluate.py`) |
| Runtime dependency | **`dpkt`** for analysis, **`flask`** for the service. Nothing else |

```bash
pip install dpkt flask
python testbed/certgen.py && python testbed/synth.py     # build the corpus
python testbed/relink.py                                 # + 7 link-layer variants
python scripts/analyse.py testbed/out/fleet.pcap --out out/ --trust testbed/certs/_ca.der
python -m securemailscope.api                            # the Kavach console, port 8000
                                                         # analyst/analyst123 · admin/admin123
python scripts/audit.py                                  # verify every deliverable
python scripts/evaluate.py                               # measure accuracy; non-zero exit on disagreement
for t in contract ml parsing tls certs report platform linklayer; do python tests/test_$t.py; done
```

**Eight commits are unpushed.** Git cannot push from this machine — see §5.

---

## 2. Documentation

| Doc | What it holds |
|---|---|
| `docs/00_INDEX.md` | Map, and the documentation rules the project follows |
| `docs/01_PROBLEM_STATEMENT.md` | PS decomposed into 21 deliverables (D01–D21) + O01/O02, traceability matrix |
| `docs/02_USP.md` | The 11 USPs, with judge Q&A and slide mapping. **The PPT reference** |
| `docs/03_ARCHITECTURE.md` | Pipeline, data model, module ownership |
| `docs/04_DECISIONS.md` | **28 ADRs.** Every non-obvious decision, with what was rejected |
| `docs/05_WORKLOG.md` | Session-by-session record, including every bug found |
| `docs/06_STATUS.md` | Verified deliverable status (`06_STATUS_GENERATED.txt` is the raw audit output) |
| `docs/07_RELATED_WORK.md` | Seven papers reviewed; what to adopt from each |
| `docs/08_PITCH.md` | Slide-by-slide pitch guidance with sources |
| `docs/09_DECK_CONTENT.md` | Deck content, box by box |
| `docs/10_RESEARCH_PAPER.md` | Full paper draft (uses the name *CyberKavach*) |
| `docs/11_TODO.md` | **The backlog.** Ordered by value, no dates |

**Rules:** every non-obvious decision becomes a numbered ADR; every session appends to the worklog; the schema is
the contract and changes update `03_ARCHITECTURE.md` in the same commit; every detection rule carries its
RFC/NIST citation.

---

## 3. Architecture

```
PCAP → S0 ingest → S1 TCP reassembly → S2 protocol ID → S3 STARTTLS state machine
     → S4 TLS handshake → S5 X.509 → S6 rules (34) → S7 features (51)
     → S8 AI (risk / anomaly / priority) → S9 aggregation → S10 JSON·HTML·PDF
```

| Package | Stage | Notes |
|---|---|---|
| `schema/` | — | **The contract. Zero dependencies** (ADR-0009). Generates JSON Schema + TypeScript |
| `schema/platform.py` | — | Jobs, dispositions, audit events, posture snapshots (ADR-0022) |
| `securemailscope/capture/` | S0–S1 | Link-layer decode (ADR-0027) + own TCP reassembler with byte→frame provenance |
| `securemailscope/proto/` | S2–S3 | Banner-led protocol ID; ten STARTTLS checks; credential recovery |
| `securemailscope/tls/` | S4 | Own record + handshake parser, JA3/JA3S, PQ groups |
| `securemailscope/certs/` | S5 | **Own DER/X.509 parser + real RSA signature verification** |
| `securemailscope/rules/` | S6 | 34 rules, each with standards citations and config snippets |
| `securemailscope/features/` | S7 | 51-field feature vector |
| `securemailscope/ml/` | S8 | Classifier, anomaly, priority, corpus generator, training |
| `securemailscope/report/` | S10 | JSON + single self-contained HTML |
| `securemailscope/store.py` | — | stdlib `sqlite3`, five tables, no ORM |
| `securemailscope/siem.py` | — | CEF and ECS export |
| `securemailscope/api/` | — | **Flask** service, stdlib auth (ADR-0024), and the twelve-view console (ADR-0026) |
| `testbed/` | — | `synth.py` writes PCAPs byte by byte; `certgen.py` makes signed certs |

**Almost everything is written from scratch and stdlib-only.** That was forced (see §5), not stylistic.

---

## 4. The four USPs that are the pitch

1. **Role-aware severity** — the same expired certificate is INFO on port 25 (MTA relay, opportunistic security,
   RFC 7435) and CRITICAL on 993 (credentials cross it, RFC 8314). Generic TLS scanners apply web rules to mail
   and drown admins in false alarms. `rules/severity.py` is a declarative policy table that writes its own
   plain-English justification into every adjusted finding.
2. **Attack evidence, not just weak config** — five passive detectors: STARTTLS capability stripping (the
   same-length `250-XXXXXXXA` rewrite), credentials recovered from cleartext, the RFC 8446 DOWNGRD sentinel, a
   cipher-intersection anomaly needing both halves of the handshake, and certificate substitution across
   sessions. All five fire on the corpus. The intersection anomaly requires corroboration (ADR-0023) —
   without it, every legacy server looks like an attack.
3. **Evidence-linked findings** — every finding carries capture SHA-256, stream index, frame numbers and byte
   offsets. Open the PCAP in Wireshark and verify any claim (ADR-0004).
4. **Reporting what could not be seen** — TLS 1.3 encrypts the Certificate message, so we report
   `OPAQUE_TLS13` with a reason rather than an empty panel reading as "no certificate". A host whose handshake
   could not be parsed grades `?`, never `A+` (ADR-0014).

**Analyst feedback loop:** `DispositionState.FALSE_POSITIVE` is served at `/api/training-signal` as a labelled
example, so triage work becomes supervised signal rather than evaporating.

---

## 5. Environment — read this before suggesting any dependency

**Windows Smart App Control on these machines blocks compiled extensions.** Seven confirmed blocks:

| Blocked | Consequence |
|---|---|
| `numpy` (`_multiarray_umath`) | No scikit-learn → no trained model (ADR-0012) |
| `cryptography` (`_rust`) | Wrote our own DER/X.509 parser (ADR-0017) |
| `openssl` | Wrote `testbed/certgen.py` to generate certificates |
| Pillow (`_imaging`) | PDF renderer stubs PIL before importing ReportLab |
| git's `libcurl-4.dll` | **`git push` fails from here** |
| node / npm (never installed) | Dashboard is one self-contained HTML file (ADR-0018) |
| `pydantic` / `fastapi` (`_pydantic_core`) | **Flask + stdlib `sqlite3`** (ADR-0021) |

**Test the call path, not the import.** `import cryptography` succeeds while `cryptography.x509` fails;
`import reportlab` fails only because it imports Pillow. Run the thing you actually intend to call.

**Known good:** `dpkt`, `flask`, `starlette`, `jinja2`, `reportlab` (with the PIL stub), stdlib `sqlite3`.

**WSL2 is not installed.** Only still needed for the ML training path — and **Colab is the faster route**
(`notebooks/train_models.ipynb` + `data/corpus.csv`, ~15 min).

**To push:** GitHub Desktop or VS Code's built-in git, which bundle their own networking.

---

## 6. Known gaps, in priority order

1. **No trained model.** `notebooks/train_models.ipynb` is ready; run it in Colab with `data/corpus.csv` and
   drop the output into `models/`. → **D16 and D17 go PARTIAL → MET.** Bar to beat: baseline MAE **0.1683**;
   if the model loses, the notebook says so and the baseline ships.
2. **`securemailscope/llm/` is a stub** — USP-04 layer 3. O02 is otherwise complete. Follow the Dynamic Metric
   Engine pattern (`docs/07_RELATED_WORK.md` §3): the model may emit narrative and config text only, never
   introduce, remove or re-score a finding.
3. **USP-09 attack feasibility matrix** — `Finding.related_attacks` exists; needs feasibility verdicts and a panel.
4. **USP-11 DANE / MTA-STS** — the highest-value unbuilt feature, see §7.
5. **USP-10 temporal drift** — now cheap: `PostureSnapshot` already archives every run, so two snapshots are a diff.
6. ~~**Link-layer coverage.**~~ **Done (ADR-0027).** Ethernet + 802.1Q/QinQ, Linux cooked v1/v2, raw
   IPv4/IPv6, BSD loopback, and the IPv6 extension-header chain. Five of seven encapsulations previously
   lost *every frame* and reported a clean A+. An undecodable capture now grades `?`, never A+.
7. **Real-world PCAPs.** Every capture measured so far is synthetic and self-authored. **Now the most
   likely cause of an on-stage surprise**, though link-layer variance is no longer part of it.
8. **PDF export** needs Playwright (blocked); browser print works and the print stylesheet is applied.
9. **The offline HTML report has never been looked at by a human.** The console has been driven end to
   end in a browser (ADR-0025, ADR-0026); the report is a separate renderer and has not been.
10. **`smtp_relay_cleartext.pcap` grades A+ (95/100).** Correct per USP-01 — the relay finding is
   downgraded to LOW because opportunistic relay is outside the operator's control (RFC 7435), and
   `evaluate.py` agrees with ground truth. But *A+* is the top grade, and "you gave an A+ to a plaintext
   mail server" is a one-line attack with a three-line defence. The finding is reported; the **curve** is
   the open question. A scoring decision in `pipeline.py` — decide it deliberately, and re-run
   `scripts/evaluate.py` if you touch it.

`securemailscope/scoring/` is an empty stub, but that is cosmetic: its logic lives in `pipeline.py` and works.

---

## 7. Research grounding

`docs/07_RELATED_WORK.md` reviews seven papers. Five external papers were separately verified as the
recommended reference set:

- **Durumeric et al., IMC 2015** — STARTTLS stripping *in the wild*; 7 countries with >20% of inbound Gmail in
  cleartext. The canonical citation for USP-02.
- **Ashiq, Fiebig & Chung, IMC 2025** — 87M domains; **MTA-STS at 0.07% of `.com` / 0.12% of `.org`, 29.6% of
  the 68K domains publishing a record misconfigured.**
- **Siavoshani et al., Soft Computing 2023** — which TLS handshake fields leak most; backs the feature vector.
- **Singh, Kashyap & Cherukuri, arXiv 2505.16261** — SHAP anomaly detection on encrypted traffic; backs USP-04.
- **Dubey & Varshney, arXiv 2606.16473** — 49.3% support hybrid PQ key exchange, **zero PQ certificates.**

**Two findings should change priorities:** MTA-STS under 0.15% with a third broken makes USP-11 the
highest-value unbuilt feature. And USP-05's claim should be two-part — *key exchange is migrating, certificates
have not started* — which the parser can already report.

Policy, SDG and monetization have **no paper literature**; use primary sources: CERT-In Directions 2022
(**6-hour incident reporting** — a strong hook for a forensic tool, and the audit log serves it directly),
DPDP Act 2023, FBI IC3 2025 ($3.04B BEC losses), India email security market ~$0.427B→$1.31B by 2035.

---

## 8. How to work on this

- **Run `python scripts/audit.py` before and after any change**, and `python scripts/evaluate.py` after touching
  a rule. The audit caught the USP-01 side-by-side silently breaking when the corpus moved to real certificates;
  the evaluation caught a rule that reported every legacy server as under attack.
- Tests run without pytest: `python tests/test_<name>.py`.
- **Working on the console?** `netstat -ano | grep :8000` before trusting a restart — a second server
  that fails to bind exits silently and the stale one keeps serving, which cost half a session once
  (worklog 7). Templates auto-reload; a new route or context processor does not.
- Regenerate the contract after schema changes: `python -m schema.jsonschema`.
- **Ground truth is authored from configuration, never from output.** `testbed/manifest.json` expectations were
  derived by reading `testbed/synth.py`. If evaluate.py disagrees, decide on the merits — do not paste in what
  the tool produced, or precision becomes 1.0 by construction and the figure means nothing.
- **Do not claim something works without running it.** Bugs found only by running: an anchored regex made every
  STARTTLS session look like cleartext; citing a standard was counted as violating it; the anomaly baseline
  learned "normal" from the attacks; `train_test_split` shuffles, so the model was scored on rows it trained on.
