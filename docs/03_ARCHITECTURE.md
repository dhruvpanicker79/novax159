# 03 — Architecture

## 1. The twelve-stage pipeline

Each stage has a frozen input and output contract, so six people build in parallel and only the schema is a shared
dependency. Stage IDs are cited by the traceability matrix in [01_PROBLEM_STATEMENT.md](01_PROBLEM_STATEMENT.md).

| Stage | Name | Input | Output | Satisfies |
|---|---|---|---|---|
| **S0** | Ingest | `.pcap` / `.pcapng` | `Capture` — path, SHA-256, packet count, time range, link type | — |
| **S1** | Reassemble | Packets | `Flow[]` — 5-tuple, stream id, per-direction byte streams, segment index | D03 |
| **S2** | Classify | `Flow` | `MailSession` — protocol, `port_role`, confidence | D01, USP-01 |
| **S3** | Cleartext phase | `MailSession` | `Phase[]` + STARTTLS validation (V1–V10), credential exposure | D02, USP-02 |
| **S4** | TLS parse | Encrypted phase bytes | `TlsHandshake` — versions, cipher, KEX, groups, extensions, alerts, JA3, JA3S, PQ groups | D04–D07, USP-05 |
| **S5** | Certificates | Certificate message | `Certificate[]` + `ChainResult` | D08–D12 |
| **S6** | Rules | All of the above | `Finding[]` — rule id, severity, confidence, evidence, standards, remediation | D13–D15, USP-01 |
| **S7** | Features | All of the above | `FeatureVector` — 50 named, documented fields | O01 |
| **S8** | AI | `FeatureVector`, `Finding[]` | risk score, SHAP contributions, anomaly score, priority rank, LLM remediation | D16–D18, O02 |
| **S9** | Aggregate | Per-session results | `HostPosture[]`, `DomainPosture[]`, `FleetPosture` | D19 |
| **S10** | Report | `Assessment` | `report.json`, `report.html`, `report.pdf`, 4 persona views | D20, USP-06 |
| **S11** | Dashboard | `report.json` via API | Next.js application | D21 |

### Stage notes that matter

- **S1** must handle retransmissions, out-of-order segments and gaps, and must record the originating frame number
  and byte offset for every byte it emits. See ADR-0004.
- **S2** uses the port as a hint, not a conclusion: banner regex (`220...ESMTP`, `* OK ... IMAP`, `+OK`) confirms
  the protocol, so a mail service on a non-standard port is still identified.
- **S4** must read the negotiated version from the **`supported_versions` extension** of the ServerHello, not from
  `legacy_version`. A TLS 1.3 server sets `legacy_version` to 1.2, so the naive parse misreports every 1.3 session.
- **S5** must handle the fact that **TLS 1.3 encrypts the Certificate message**. For 1.3 sessions, emit an explicit
  `opaque` status with a reason, not an empty result.
- **S6** applies the `port_role` severity adjustment (USP-01) and records both the base and adjusted severity.
- **S6 category split, important:** `CERTIFICATE` means certificate *trust* (expiry, self-signed, chain, name
  mismatch) and IS role-adjusted, because trust expectations differ by port. `CERTIFICATE_STRENGTH` means key size
  and signature algorithm and is NEVER role-adjusted, because a 1024-bit key is weak wherever it is presented.
  Without this split the opportunistic-relay exemption would quietly excuse broken cryptography, which would be a
  real hole in the USP-01 argument.

## 2. Data model — freeze before any code

Ten objects. This is the contract; changing a field means updating this document in the same commit.

| Object | Purpose |
|---|---|
| `Capture` | The source artifact and its integrity hash |
| `Flow` | One reconstructed TCP conversation |
| `MailSession` | A flow identified as SMTP / IMAP / POP3, with its port role |
| `Phase` | A segment of a session: `plaintext`, `starttls_negotiation`, or `encrypted` |
| `TlsHandshake` | Parsed handshake, both directions, with fingerprints |
| `Certificate` | One X.509 certificate plus its position in the presented chain |
| `Finding` | One detected issue, with evidence, standards and remediation |
| `FeatureVector` | The explicit 50-field input to the ML layer |
| `Assessment` | Scores, anomaly, priority ranking, recommendations |
| `HostPosture` / `FleetPosture` | Aggregation rollups |

### Two fields that must exist from day one

**Every object carries `evidence`:**

```
evidence: { capture_sha256, stream_id, frame_numbers[], byte_range, timestamp }
```

This is USP-03 and it cannot be retrofitted cheaply.

**Every `Finding` carries `standards[]` and `remediation{}`:**

```
standards:   [{ body: "RFC", id: "8996", clause: "...", requirement: "..." }]
remediation: { summary, postfix, dovecot, exchange, effort, risk_of_change }
```

These two fields give us D13/D14 citations (O02) and the compliance report card (USP-08) for free — but only if
they are populated at rule-authoring time. Backfilling on day 4 will not happen.

## 3. Technology choices

| Layer | Choice | Rationale |
|---|---|---|
| Packet decode | `dpkt` | Pure pip, fast, stable, no Npcap needed to *read* files |
| Reassembly | Custom (~150 lines) | Full control over byte-offset provenance |
| TLS parsing | Custom (~250 lines) | Length-prefixed structures; avoids a `tshark` runtime dependency |
| X.509 | `cryptography` | Certificates, key sizes, signature algorithms, SANs |
| Contract (`schema/`) | **stdlib dataclasses, zero dependencies** | ADR-0009 — everyone imports it, so it must never fail to install |
| ML | `scikit-learn` + `shap` | CPU only, no GPU, no deep learning |
| Backend | **`Flask` + stdlib `sqlite3`** | FastAPI is UNUSABLE here: Pydantic v2's `_pydantic_core` is blocked (ADR-0021). Flask, Starlette and `sqlite3` all work |
| Reports | `Jinja2` → `Playwright` print-to-PDF | Avoids the WeasyPrint/GTK install problem on Windows |
| Frontend | Next.js + Tailwind + shadcn/ui + framer-motion + Recharts | Fast to a polished dark SOC aesthetic |
| Testbed | `docker-compose` + `openssl` + Postfix/Dovecot | Generates the labelled corpus (USP-07) |
| Dev environment | **WSL2 Ubuntu** | See ADR-0001 |

`pyshark` / `tshark` are installed in development **only**, as a cross-check oracle to validate our parser against.
They are not runtime dependencies.

## 4. Module layout

```
securemailscope/
  capture/      S0, S1   pcap ingest, link-layer decode, TCP reassembly
  proto/        S2, S3   protocol ID, STARTTLS state machine, credential detection
  tls/          S4       record + handshake parser, JA3/JA3S, PQ group detection
  certs/        S5       X.509 extraction, chain assembly, validation
  rules/        S6       YAML rule pack + role-aware severity engine
  features/     S7       feature extraction
  ml/           S8       classifier, anomaly detector, SHAP
  llm/          S8       grounded narrative: fact sheet, template, verifier (ADR-0028)
  scoring/      S9       posture scoring, grading, prioritisation
  report/       S10      JSON / HTML / PDF, four persona templates
  api/          S10      Flask service + SOC console (auth, templates, static)
schema/                  dataclass models + generated JSON Schema + TS types (the contract)
testbed/                 manifests, capture generator, certificate generator
fixtures/                generated sample report + per-session files for parallel development
web/                     generated TypeScript types only - the console is server-rendered
docs/                    this documentation
```

### Link layers (ADR-0027)

`capture/linklayer.py` decodes Ethernet (including 802.1Q and QinQ), Linux cooked capture v1 and v2,
raw IPv4 and IPv6, and BSD loopback, and walks the IPv6 extension-header chain. `Capture` carries
`link_type`, `decoded_frame_count` and `link_layer_note` so coverage is **in the report**, not in a log
line: a capture whose link layer we cannot read yields no sessions, and without those fields that is
indistinguishable from a healthy estate. When the decode rate collapses the pipeline emits
`ANALYSIS-CAPTURE-NOT-READABLE` and forces `Grade.INCOMPLETE`.

`decoded_frame_count` counts frames whose **link layer** parsed, ARP and other non-IP traffic included.
Counting only IP-bearing frames reports an ARP-only capture as unreadable, which it is not.

### The narrative layer (ADR-0028)

`llm/` is handed a **finished** `Report` and returns only a `Narrative`. It cannot add, remove or
re-score a finding — the boundary is structural, not a convention. Three files:

| File | Job |
|---|---|
| `grounding.py` | Extracts a `FactSheet`: counts, rule ids, severities, remediation text. No capture bytes, no credentials, no banners. Hashed, and the hash travels on the narrative |
| `templates.py` | The deterministic generator. **This is what ships** — no network, no model, no key |
| `verify.py` | Checks generated prose against the fact sheet's closed vocabulary. Anything unverifiable and the whole narrative is discarded |

`Report.narrative` carries `generated_by`, `verification` and `grounding_sha256`, so a reader can check
that the text describes that report rather than being asked to trust it.

**The plan is not the finding list.** Actions are merged by `(remediation summary, config snippet)`:
thirteen sessions with one weak cipher is one action, and two rules closed by the same config line is
one action. 30 findings become 17 actions on the corpus.

### Temporal drift (ADR-0029)

`drift.py` diffs two finished reports into a `PostureDrift`. Findings are matched on `rule_id@host:port`,
the same key dispositions use, so an analyst's decision and a drift entry name the same thing — a
*condition on an endpoint*, which is why the key is intentionally not unique within a single report.

`comparable` is the field that matters. Below 50% host overlap the diff is refused rather than reported:
the arithmetic runs on any two reports, and "grade fell from A+ to D" across unrelated captures is a
confident lie. Per-host drift is carried separately from fleet drift because the fleet number hides
exactly the event this feature exists to catch — on the corpus it moves −0.3 while two hosts move ~100
points in opposite directions.

### Attack feasibility (ADR-0030)

`attacks.py` judges sixteen named attacks against the report and writes `Report.attack_matrix`. Each has
a stated precondition and a predicate returning `True` / `False` / `None`; `None` (cannot judge) is
distinct from `False` (checked, not possible), and every predicate returns `None` for a session with no
parsed handshake. The fleet verdict is FEASIBLE / NOT APPLICABLE / NOT OBSERVABLE accordingly.

Heartbleed is present specifically to always read NOT OBSERVABLE — its precondition includes the
server's OpenSSL build, which a passive capture never shows.

### Training, locally (ADR-0031)

`ml/gbt.py` is histogram gradient-boosted regression trees and `ml/iforest.py` an isolation forest, both
pure stdlib, because scikit-learn cannot run here. `scripts/train_local.py` trains both in about eleven
seconds and writes JSON — joblib and pickle both want numpy.

Two boundaries that matter:

* **`archetype` is excluded from training.** It is the corpus generator's latent variable and does not
  exist at inference time; training on it is label leakage.
* **The posture grade is rule-derived, the risk score is not.** The grade (D19) comes from findings,
  each carrying an RFC citation and frame numbers. The model scores risk for triage (D16) and ordering
  (D18). A model that could move a grade with no finding behind it would make the headline number the
  one unverifiable thing in the report.

Contributions are exact path decomposition, and `bias + sum(contributions) == prediction` is asserted.

## 5. Ownership and the parallelisation rule

| Person | Stages |
|---|---|
| A | S0, S1, S2, S3 |
| B | S4, S5 |
| C | S6, S7, S8 |
| D | S9, S10, API |
| E | S11 — layout, components, session views |
| F | S11 — charts, diagrams, animation |

**The rule:** the schema is frozen in the first two hours and backed by hand-written fixtures in `fixtures/`. C, D,
E and F build against fixtures from minute one and never wait on the parser. This is the single change that makes
five days feasible for six people.
