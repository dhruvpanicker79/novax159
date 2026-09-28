# 06 — Status: what is actually built

**This document is not a claim, it is a check.** Run it yourself:

```bash
python scripts/audit.py
```

`scripts/audit.py` ignores the documentation entirely. It runs the pipeline over the corpus and inspects the
resulting `Report` for the evidence each deliverable requires, then prints MET / PARTIAL / NOT MET with the
observation that justifies the verdict. The generated output is checked in at
[06_STATUS_GENERATED.txt](06_STATUS_GENERATED.txt).

Last run: **25 met, 7 partial, 2 not met.**

---

## 1. Problem statement deliverables

| ID | Deliverable | Status | Where |
|---|---|---|---|
| D01 | SMTP / IMAP / POP3 identification | **MET** | `proto/detect.py` |
| D02 | STARTTLS detection **and validation** | **MET** | `proto/starttls.py` |
| D03 | Complete TCP stream reconstruction | **MET** | `capture/reassemble.py` |
| D04 | TLS handshake reconstruction | **MET** | `tls/handshake.py` |
| D05 | Negotiated TLS versions | **MET** | `tls/handshake.py` |
| D06 | Cipher suites | **MET** | `tls/ciphers.py` |
| D07 | Key exchange mechanisms | **MET** | `tls/ciphers.py` |
| D08 | X.509 extraction | **MET** | `certs/extract.py` |
| D09 | Chain validation | **MET** | `certs/chain.py` |
| D10 | Expiration analysis | **MET** | `certs/extract.py` |
| D11 | Public key algorithm and length | **MET** | `certs/extract.py` |
| D12 | Signature algorithm | **MET** | `certs/extract.py` |
| D13 | Weak algorithms, deprecated versions | **MET** | `rules/pack.py` |
| D14 | Insecure configuration | **MET** | `rules/pack.py` |
| D15 | Forward secrecy | **MET** | `tls/ciphers.py` |
| D16 | AI risk scoring | *PARTIAL* | `ml/classifier.py` |
| D17 | AI anomaly detection | *PARTIAL* | `ml/anomaly.py` |
| D18 | Prioritised findings | **MET** | `ml/priority.py` |
| D19 | Posture assessment | **MET** | `pipeline.py` |
| D20 | JSON / PDF / HTML export | *PARTIAL* | `report/__init__.py` |
| D21 | Interactive dashboard | **MET** | `report/assets.py` |
| O01 | Feature extraction | **MET** | `features/__init__.py` |
| O02 | Mitigation recommendations | *PARTIAL* | `rules/pack.py` |

### Why the four partials

**D16 and D17 — the models are written but cannot be trained here.** `ml/train.py` fits a gradient-boosted
classifier and an Isolation Forest, and `ml/corpus.py` generates the 10,000-row labelled corpus in 0.3 seconds. But
scikit-learn cannot import on this machine: Smart App Control blocks numpy's compiled extension (ADR-0012). So
the pipeline runs on the **rule-derived baseline** (ADR-0011), which produces the same `SessionAssessment` shape
with finding-attribution explanations, and the anomaly layer runs peer deviation plus JA3 rarity instead of
Isolation Forest.

Both deliverables produce real output today. They go from PARTIAL to MET with one command inside WSL2:

```bash
pip install -e ".[ml]" && python -m securemailscope.ml.train
```

**D20 — PDF needs Playwright**, which is also not installed. JSON and HTML both work; the HTML carries a print
stylesheet, so any browser's Print to PDF produces the same document. The export degrades rather than failing.

**O02 — remediation exists, the LLM narrative does not.** All 25 findings carry a remediation summary and 13 carry
Postfix / Dovecot / Exchange config snippets, written into the rule pack at authoring time. What is **not** built
is `securemailscope/llm/` — the layer that turns findings into an executive narrative. That is USP-04 layer 3.

---

## 2. Unique selling points

| ID | USP | Status |
|---|---|---|
| USP-01 | Role-aware severity engine | **MET** |
| USP-02 | Attack-evidence layer | **MET** — 5/5 detectors, all firing |
| USP-03 | Evidence-linked findings | **MET** — 25/25 findings traceable |
| USP-04 | Three-layer explainable AI | *PARTIAL* — layer 3 not built |
| USP-05 | Post-quantum readiness | **MET** |
| USP-06 | Four persona views | **MET** |
| USP-07 | Ground-truth testbed + measured accuracy | *PARTIAL* — **accuracy not measured** |
| USP-08 | Compliance report card | **MET** |
| USP-09 | Attack feasibility matrix | *PARTIAL* — attacks named, no feasibility verdicts |
| USP-10 | Temporal posture drift | **NOT BUILT** |
| USP-11 | Passive DNS / DANE / MTA-STS | **NOT BUILT** |

### The one that matters most

**USP-07 is the weakest claim in the deck.** The ground-truth manifest exists with 18 labelled captures, the
synthetic corpus generates, and the pipeline runs over it — but `scripts/evaluate.py` still raises
`NotImplementedError`. **Precision and recall are not measured.**

That matters more than the other gaps because USP-07's whole pitch is *"unlike almost anyone else here, we can
tell you our tool's precision and recall — with numbers."* Presenting that claim without the numbers would be
worse than not making it. Either finish `evaluate.py` or cut the slide.

Everything it needs is already in place: the manifest states `expected_findings` per capture, and the pipeline
produces the actual findings. It is a comparison loop, not new research.

### USP-01 and USP-02, verified rather than asserted

The audit checks these two specifically, because they are the demo:

- **USP-01** — 12 findings adjusted by port role, and `CERT-EXPIRED-SELF-SIGNED` produces **opposite verdicts** on
  different roles: INFO on the port-25 relay, CRITICAL on 993. The same certificate bytes, in both captures.
- **USP-02** — all five detectors fire on the corpus: STARTTLS stripping, credential exposure, downgrade sentinel,
  cipher intersection anomaly, certificate substitution.

The audit caught that the USP-01 side-by-side had stopped firing when the corpus moved to real certificates — the
port-25 relay scenario the manifest calls for had never been written. That is exactly what this script is for.

---

## 3. Documentation

| Document | Words | Purpose |
|---|---|---|
| [00_INDEX.md](00_INDEX.md) | 667 | Map and documentation rules |
| [01_PROBLEM_STATEMENT.md](01_PROBLEM_STATEMENT.md) | 1,848 | PS decomposed, traceability matrix |
| [02_USP.md](02_USP.md) | 4,195 | PPT reference, judge Q&A |
| [03_ARCHITECTURE.md](03_ARCHITECTURE.md) | 1,145 | Pipeline, data model, ownership |
| [04_DECISIONS.md](04_DECISIONS.md) | 2,680 | **18 ADRs** |
| [05_WORKLOG.md](05_WORKLOG.md) | 2,883 | 7 sessions, every bug found |
| [06_STATUS.md](06_STATUS.md) | this | Verified status |
| [testbed/README.md](../testbed/README.md) | 627 | Corpus and ground truth |

About 14,000 words. Every architecture decision is recorded with what was rejected and why, including all four
dependency blocks that shaped the build (ADR-0012, ADR-0017, ADR-0018).

---

## 4. Honest gaps, in priority order

1. ~~`scripts/evaluate.py` is a stub.~~ **Done** — precision 1.00, recall 1.00, severity accuracy 1.00; the
   first run found two real false positives (ADR-0023), which is what makes the figure worth quoting.
2. **`securemailscope/llm/` is a stub.** USP-04 layer 3; O02 is otherwise complete. Now the top gap.
3. ~~`securemailscope/api/` is a stub.~~ **Done** — Flask service (ADR-0021/0022) and the SOC console with
   stdlib authentication (ADR-0024/0025). The CLI is no longer the only entry point.
4. **No trained model.** Needs WSL2. The baseline covers D16/D17 meanwhile.
5. **No PDF export.** Needs Playwright. Browser print works.
6. **The offline HTML report's visual design has never been looked at by a human.** Verified structurally only.
   The *console* has now been driven end to end in a browser (ADR-0025); the report is a separate renderer and
   has not been.
7. **No Docker testbed.** `testbed/README.md` describes a `docker-compose.yml` that was never written; the
   synthetic corpus (ADR-0013) covers the same ground without Docker, but real captures would catch things
   hand-written ones cannot.
8. **USP-09, USP-10, USP-11 not built.** Tier 2 by design; they belong on the roadmap slide.

`securemailscope/scoring/` is also an empty stub, but that is cosmetic: the S9 aggregation logic it describes
lives in `pipeline.py` and works.
