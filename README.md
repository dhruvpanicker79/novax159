# SecureMailScope

**AI-assisted passive cryptographic posture assessment for email infrastructure.**

Point it at a PCAP. It reconstructs every SMTP, IMAP and POP3 session, reads the TLS handshakes and X.509
certificates, finds the cryptographic weaknesses, ranks them by what to fix first, and tells you what to paste into
Postfix or Dovecot to fix them — all without decrypting anything.

Built for Smart India Hackathon 2026.

```bash
python scripts/analyse.py                      # generates a corpus and analyses it
python scripts/analyse.py capture.pcap --out out/
```

That produces `out/report.html` — a single self-contained dashboard you can open by double-clicking.
There is a rendered example in [`examples/sample-report.html`](examples/sample-report.html).

---

## Why this is not another TLS scanner

Existing tools either **decode without judging** (Wireshark) or **judge without being able to read a capture**
(SSL Labs, testssl.sh — both are active scanners that need a live, reachable server). Nothing does passive,
offline, *email-aware* posture assessment. Four things make this different:

**It knows email TLS has three threat models, not one.** Server-to-server SMTP on port 25 is *opportunistic
security* by design (RFC 7435) — the sender has no trust anchor for the receiver, so a certificate failure there is
expected. On a submission or mail-access port, where a password is about to cross the wire, RFC 8314 makes the
identical certificate a critical finding. The corpus contains the same certificate bytes on both, and the tool
grades one INFO and the other CRITICAL, with the reasoning written into the finding. Generic scanners apply
web-server rules to mail and drown administrators in false alarms on port 25.

**It looks for attacks that already happened, not just weak configuration.** Five passive detectors: STARTTLS
capability stripping (the classic same-length `250-XXXXXXXA` rewrite), credentials recovered from a cleartext
phase, the RFC 8446 downgrade sentinel, a cipher-intersection anomaly that needs both halves of the handshake
compared, and certificate substitution across sessions. The problem statement asks for a *forensic framework*;
a configuration linter is not one.

**Every finding is traceable to bytes.** Each one carries the capture's SHA-256, the TCP stream index, frame
numbers and byte offsets. Open the original PCAP in Wireshark and verify any claim independently. That is what
separates forensic evidence from a scanner's opinion.

**It reports what it could not see.** TLS 1.3 encrypts the Certificate message, so a passive observer cannot
inspect the chain — the tool says `OPAQUE_TLS13` with a reason rather than showing an empty panel that reads as
"no certificate". A host whose handshake could not be parsed is graded `?`, never `A+`. A security tool that
reports an uninspected host as clean is worse than one that reports nothing.

---

## Quick start

No dependencies are required to run the tests or generate the corpus. Analysis needs one package.

```bash
pip install dpkt
python testbed/certgen.py          # generate test certificates (pure Python)
python testbed/synth.py            # generate the PCAP corpus (pure Python)
python scripts/analyse.py testbed/out/fleet.pcap --out out/ --trust testbed/certs/_ca.der
```

Verify the build:

```bash
python scripts/audit.py            # checks every deliverable against live output
for t in contract ml parsing tls certs report; do python tests/test_$t.py; done
```

---

## Pipeline

```
PCAP → S0 ingest → S1 TCP reassembly → S2 protocol ID → S3 STARTTLS state machine
     → S4 TLS handshake → S5 X.509 → S6 rules (33) → S7 features (51)
     → S8 AI (risk / anomaly / priority) → S9 aggregation → S10 JSON·HTML·PDF
```

| Module | Stage | What it does |
|---|---|---|
| `capture/` | S0–S1 | PCAP ingest, TCP reassembly with byte→frame provenance |
| `proto/` | S2–S3 | Protocol identification, ten STARTTLS checks, credential recovery |
| `tls/` | S4 | Record and handshake parser, JA3/JA3S, post-quantum group detection |
| `certs/` | S5 | Pure-Python DER and X.509, chain validation, **RSA signature verification** |
| `rules/` | S6 | 33 detection rules, each with standards citations and config snippets |
| `features/` | S7 | 51-field cryptographic feature vector |
| `ml/` | S8 | Risk scoring with explanations, anomaly detection, triage ranking |
| `report/` | S10 | JSON, self-contained HTML dashboard, PDF, four persona views |
| `schema/` | — | The data contract. **Zero dependencies** |

Everything except PCAP decoding is stdlib. The TLS parser, the DER parser and the RSA signature verification are
all written from scratch — deliberately, because the dependencies they would normally use are blocked in the
team's environment. See [`docs/04_DECISIONS.md`](docs/04_DECISIONS.md).

---

## Status

Run `python scripts/audit.py`. It ignores this README, runs the pipeline, and checks the actual output.

**25 met · 7 partial · 2 not built** — the full breakdown, including the honest gaps, is in
[`docs/06_STATUS.md`](docs/06_STATUS.md).

All 21 problem-statement deliverables are implemented. The partials are mostly environment-blocked rather than
unwritten: the gradient-boosted classifier and Isolation Forest exist in `ml/train.py` but scikit-learn cannot be
installed on the development machines, so the pipeline runs a rule-derived baseline that produces the same output
shape. `scripts/evaluate.py` is still a stub, which means the measured precision and recall are not yet available.

---

## Documentation

| | |
|---|---|
| [`docs/00_INDEX.md`](docs/00_INDEX.md) | Map and documentation rules |
| [`docs/01_PROBLEM_STATEMENT.md`](docs/01_PROBLEM_STATEMENT.md) | The PS decomposed into 21 deliverables, with a traceability matrix |
| [`docs/02_USP.md`](docs/02_USP.md) | What makes this different, and how to defend it under questioning |
| [`docs/03_ARCHITECTURE.md`](docs/03_ARCHITECTURE.md) | Pipeline, data model, module ownership |
| [`docs/04_DECISIONS.md`](docs/04_DECISIONS.md) | 18 architecture decision records |
| [`docs/05_WORKLOG.md`](docs/05_WORKLOG.md) | What was built, and every bug found along the way |
| [`docs/06_STATUS.md`](docs/06_STATUS.md) | Verified status of every deliverable |
| [`testbed/README.md`](testbed/README.md) | The ground-truth corpus |

---

## Testbed

`testbed/manifest.json` is the ground truth: 13 captures, each stating exactly what was configured and which
findings must fire. `testbed/synth.py` writes the PCAPs byte by byte — Ethernet, IPv4 and TCP with correct
checksums, plus hand-built TLS records — so the corpus needs no Docker, no mail servers, and no old OpenSSL build
willing to negotiate RC4. `testbed/certgen.py` generates genuinely signed X.509 certificates the same way.

Checksums are computed properly so the captures open cleanly in Wireshark. That matters: the provenance claim is
only convincing if you can open the file yourself and land on the frame we cited.

---

## Scope

Passive analysis only. **No traffic is decrypted** — the problem statement specifies passive assessment of
encrypted traffic, and everything reported is observable without keys. No live capture, no active probing, no
email content analysis.

---

## License

MIT — see [LICENSE](LICENSE).
