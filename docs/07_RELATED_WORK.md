# 07 — Related work: what the literature gives us

Seven papers reviewed against SecureMailScope. This document records what is **usable**, what should change in
our design as a result, and what we can claim as genuinely unaddressed by prior work.

**Headline finding: no paper in this set does passive, PCAP-based cryptographic posture assessment of email.**
The closest work is either *active* (MECSA probes live servers; TLSAssistant scans live endpoints) or targets a
different protocol entirely. That gap is our novelty claim, and it is now defensible with citations rather than
assertion.

---

## Relevance ranking

| Paper | Relevance | Why |
|---|---|---|
| **Kambourakis et al., "What Email Servers Can Tell to Johnny"** (IEEE Access, 2020) | **Critical** | The closest prior work. Defines the problem space and supplies real-world adoption statistics |
| **Germenia et al., "Automating Compliance for Improving TLS Security Postures"** (SECRYPT 2024) | **Critical** | A far better compliance model than ours, and directly upgradeable |
| **Unal & Celiktas, "Automating Cyber Risk Assessment With Public LLMs"** (IEEE Access, 2026) | **High** | Gives us the architecture for our unbuilt LLM layer, and a citable weighting method |
| **Baee et al., "Anomaly Detection in KMIP Using Metadata"** (IEEE Access, 2024) | **High** | Metadata anomaly detection on encrypted traffic; exposes a real flaw in our baseline |
| **Su, "Security Assessment Model for Symmetric Cryptographic Algorithms"** | Moderate | Per-algorithm security scoring; a candidate feature |
| **Diallo & Thapar, "Hybrid Approach for Phishing Email Detection"** | Low | Different problem, but validates our scope boundary |
| **Cotroneo et al., "Automating the Correctness Assessment of AI-generated Code"** (arXiv 2310.18834) | **None** | Zero mentions of email, SMTP, TLS or certificates. It evaluates AI-generated assembly with symbolic execution. Do not cite it as related work |

---

## 1. Kambourakis, Draper Gil, Sanchez — *What Email Servers Can Tell to Johnny*

European Commission JRC. Built **MECSA**, a public web service assessing provider-to-provider (MTA-to-MTA)
email security. ~7,650 assessments across 3,236 unique providers over 15 months.

### What it validates

Their adversary model is ours almost word for word: *"An active adversary is able to strip or distort the
announcement of TLS to force the receiving end to fall back to cleartext"* — that is our USP-02 STARTTLS
stripping detector. They also state plainly that **RFC 7817 certificate rules do not apply to MTA-to-MTA**, and
that relay TLS should instead involve DANE or MTA-STS. That is independent, peer-reviewed confirmation of the
RFC 7435 reasoning behind **USP-01**.

### How we differ — the positioning statement

MECSA is explicitly **active**: it triggers STARTTLS tests against live MTAs and requires users to send and reply
to real emails. They describe it as "non-intrusive" only in the sense of not being exhaustive. It also covers
**MTA-to-MTA only** — not submission, not IMAP, not POP3.

> SecureMailScope is passive and forensic: it needs no access to the servers, works from a capture after the fact,
> and covers submission and mail-access ports where the credentials actually are. MECSA tells you what your
> provider does today; we tell you what happened on this wire, and prove it with frame numbers.

### Numbers to put in the PPT

From the inbound-channel results (2019–2020 data — **state the year when citing**, MTA-STS and DANE adoption has
moved since):

| Finding | Value |
|---|---|
| Domains with at least one STARTTLS-enabled MTA | 97.6% |
| MTAs still using SSLv3 / TLS 1.0 | ~3% |
| Certificates passing **all** validation checks | 72.3% |
| Certificates failing FQDN validation | ~22.3% |
| Certificates failing signature validation | ~17.3% |
| — of those, missing intermediates | 19% |
| Certificates expired | ~8.2% |
| RSA keys weaker than 1024-bit | ~2.5% |
| Domains with any TLSA (DANE) record | ~24.8% |
| Domains with DNSSEC-protected TLSA | ~17.6% |
| **Receiving MTAs supporting MTA-STS** | **5.6%** |
| Domains fully supporting DNSSEC | 23.23% |

This is the slide-3 problem framing: **STARTTLS is nearly universal, but a quarter of certificates fail
validation and 94% of servers have no MTA-STS policy.** Encryption is deployed; *authenticated* encryption is not.

### What to build because of it

Their inbound check list maps almost exactly onto rules we already have. The two we do **not** have are DANE/TLSA
and MTA-STS — which is our unbuilt **USP-11**. This paper makes USP-11 substantially more valuable: it is the
single most under-adopted control in the entire email ecosystem, and we would be reporting on it.

---

## 2. Germenia, Manfredi, Rizzi, Sciarretta, Tomasi, Ranise — *Automating Compliance for Improving TLS Security Postures*

Fondazione Bruno Kessler / University of Trento. Built a compliance module for **TLSAssistant**
(github.com/stfbk/tlsassistant) plus an auditable machine-readable dataset of requirements from **NIST, BSI
(Germany), ANSSI (France), AgID (Italy) and Mozilla**.

### Why this matters most for USP-08

**Our compliance card is crude by comparison.** We emit binary pass/fail with a `relation` field. They use a
model that is both more expressive and more defensible:

**Requirement levels from RFC 2119** — `MUST`, `MUST NOT`, `RECOMMENDED`, `NOT RECOMMENDED`, `OPTIONAL` — with a
two-dimensional verdict table:

| Requirement level | Element detected | Element missing |
|---|---|---|
| MUST | do nothing | **ERROR: enable** |
| MUST NOT | **ERROR: disable** | do nothing |
| RECOMMENDED | do nothing | *ALERT: enable* |
| NOT RECOMMENDED | *ALERT: disable* | do nothing |
| OPTIONAL | do nothing | do nothing |

The **ERROR vs ALERT** split is exactly the distinction our `relation: violates | context` field was groping
towards, but principled and standards-anchored.

### The genuinely novel idea: compare-to-many

Different national guidelines **disagree**. NIST says TLS 1.2 is "not recommended" for user-facing servers while
AgID says it is a MUST. RFC 2119 defines no ordering between requirement levels, so they define two **partial
orders (posets)** and let the administrator choose:

- **Security wins** — prefer `NOT RECOMMENDED` over `RECOMMENDED`; stricter, may break legacy clients
- **Legacy wins** — prefer `RECOMMENDED`; more available, keeps weaker features

**This is a feature nobody at SIH will have.** "Your mail fleet is compliant with NIST but fails AgID, and here is
the one setting that satisfies both" is a memorable demo. It also directly serves the PS's *"ensuring compliance
with modern cryptographic best practices"* and multiplies the value of our existing CERT-In citation — the same
machinery extends to Indian guidelines.

### What to build

Restructure `rules/standards.py` so each `StandardRef` carries an RFC 2119 **requirement level per guideline**,
not a global pass/fail. Then `compliance_report()` becomes compare-to-one, and a new `compare_to_many()` applies
the poset. Roughly 4 hours, and it upgrades USP-08 from "a table" to "a method".

---

## 3. Unal & Celiktas — *Automating Cyber Risk Assessment With Public LLMs*

Isik University. An expert-validated framework where LLMs interpret context but **do not score**.

### The architectural principle we should adopt verbatim

> *"Rather than positioning the LLM as the final decision-maker, the framework decouples semantic interpretation
> from risk scoring authority through a transparent, deterministic Dynamic Metric Engine."*

This is **exactly** the design we already chose in ADR-0003 (the rule engine is the authority; ML generalises) —
now with a peer-reviewed citation. When a judge asks *"how do you stop the AI hallucinating a finding?"*, the
answer is a named architecture from the literature, not our own assurance.

It is also the blueprint for our **unbuilt LLM layer (USP-04 layer 3 / O02)**: the LLM may only consume structured
findings and emit narrative and config text. It may never introduce, remove or re-score a finding.

### The weighting method we should steal

Our prioritisation weights in `ml/priority.py` are **hand-picked** — `0.45 × exploitability + 0.35 × blast_radius
+ 0.20 × breadth`. They derive weights with **Rank Order Centroid** from an expert survey (n=101):

```
w_k = (1/M) · Σ(i=k..M) 1/i
```

ROC converts an ordinal *ranking* into cardinal weights, which removes the "where did 0.45 come from?" question.
We cannot run a 101-expert survey in three days, but we can rank our factors, derive ROC weights, and cite the
method. That turns arbitrary constants into a defensible procedure.

They also split scoring into **Likelihood (L)** and **Impact (I)**, with `R = αL + (1−α)I`. Our
`exploitability × blast_radius` is already that decomposition — we should name it as such and adopt the
generalised form, which lets an operator tune risk appetite.

One more idea worth taking: **non-zero residual floors.** They argue a risk score of exactly zero implies "zero
threat", which is never true. Our healthy sessions currently score 0.00.

---

## 4. Baee, Simpson, Armstrong — *Anomaly Detection in KMIP Using Metadata*

QUT / QuintessenceLabs. Anomaly detection on **encrypted** key-management traffic using metadata only.

### The flaw it exposes in our design

Their framework has four stages, and **Stage A is unsupervised outlier rejection *before* learning what normal
looks like.** Only then does Stage B train on the cleaned data.

We do not do this. `ml/anomaly.py` builds `FleetBaseline` from **the capture itself** — including the attack
sessions. Our demo capture contains a stripped STARTTLS session, a downgrade and an RC4 server, and all three are
contributing to the "normal" modal configuration we compare against. **The baseline is poisoned by the very
things we are trying to find.** With enough compromised hosts, the attacks become normal and stop being flagged.

**This is a real bug, not a theoretical one, and it is cheap to fix:** compute the baseline, discard sessions with
high rule-severity findings, recompute. Two passes, maybe 40 lines.

### Method notes

They use an **LSTM autoencoder** with reconstruction error as the anomaly score, reporting P/R/F1 = 1.0 on their
scenarios. Two things to take rather than the model itself:

- **Reconstruction error as an anomaly score** is worth a sentence in the roadmap, but a sequence model is
  overkill for our per-session feature vectors. Isolation Forest remains the right choice.
- **Their ablations are the template for our metrics slide:** they vary feature count and training-set size and
  show where accuracy holds. Doing the same with our corpus would make USP-07 genuinely rigorous.

They also justify metadata analysis of encrypted traffic in terms we should reuse: *"Although KMIP traffic is
encrypted, monitoring traffic and usage patterns may enable detection of anomalous activity not detectable by
other means."* That is our answer to "why not just decrypt it?"

---

## 5. Su — *Security Assessment Model for Symmetric Cryptographic Algorithms Based on ML*

Produces **per-algorithm security scores** — AES-128 = 0.92, SM4 = 0.87, **DES = 0.34** — using an SVM
(94.2% accuracy, AUC 0.951) over cryptographic feature sets, explicitly framed for the post-quantum era.

**What to take:** the idea of a continuous `cipher_security_score` feature rather than our discrete
`cipher_strength_bits` plus boolean flags. It would let the model express that 3DES is weak-but-not-broken while
RC4 is broken, which bit-count alone does not capture.

**Treat with caution.** The methodology is thin — it is not obvious what "features of a symmetric algorithm"
means as ML input when the algorithm set is tiny and fixed, and a 94.2% accuracy over a handful of algorithms is
not a meaningful generalisation claim. Cite it for the *concept* of quantified algorithm scoring, not as
authority. Our IANA-name-derived properties (ADR-0015) are more defensible for what we actually do.

---

## 6. Diallo & Thapar — *A Hybrid Approach for Phishing Email Detection using AI and Cryptography*

Random Forest and XGBoost over headers, content, URLs and attachments, combined with SPF/DKIM/DMARC/S-MIME/PGP
verification.

**This is the paper that proves our scope boundary was right.** It is the *other* email security problem — content
authenticity and sender legitimacy — and it needs mail content, not packet captures. Everything it does is
orthogonal to transport cryptography.

**Use it in the deck as contrast:** "Prior email-security ML work targets phishing and sender authentication
(SPF/DKIM/DMARC). We target the transport layer those messages travel over — a problem that is passively
observable and, unlike content analysis, requires no access to anyone's mail."

It does support one Tier-3 idea: DKIM is genuinely cryptographic (key length, `rsa-sha1` vs `rsa-sha256`), so
assessing DKIM *key strength* from a cleartext session stays within our remit while their content analysis does not.

---

## 7. Cotroneo et al. — *Automating the Correctness Assessment of AI-generated Code* (arXiv 2310.18834)

**Not relevant.** Zero mentions of email, SMTP, TLS or certificates across 48 pages. It proposes ACCA, a symbolic-
execution method for checking whether AI-generated **assembly code** matches a reference implementation.

Do not put it on the references slide — a judge who checks will notice, and it undermines the six citations that
genuinely do apply. The only transferable thread is methodological and thin: they validate an automated evaluator
against human judgement (Pearson r = 0.84) as ground truth, which is the same shape as our `evaluate.py`
validating against the manifest. Not worth a slide.

---

## Consolidated actions

Ordered by value, with effort:

| # | Action | From | Effort | Why |
|---|---|---|---|---|
| 1 | **Fix the poisoned anomaly baseline** — two-pass outlier rejection | KMIP §4 | 1h | A real bug in shipping code |
| 2 | **RFC 2119 requirement levels + ERROR/ALERT** in the compliance model | TLS Compliance §2 | 3h | Upgrades USP-08 from table to method |
| 3 | **compare-to-many with Security-wins / Legacy-wins posets** | TLS Compliance §2 | 2h | A feature nobody else will have |
| 4 | **ROC-derived priority weights**, L/I decomposition, residual floors | LLM Risk §E | 2h | Removes "where did 0.45 come from?" |
| 5 | **LLM layer built as a Dynamic-Metric-Engine analogue** | LLM Risk §III | 3h | Completes USP-04 layer 3 with a citable architecture |
| 6 | **Real-world statistics on the problem slide** | MECSA §IV | 30min | Makes the problem concrete and cited |
| 7 | **Feature-count and corpus-size ablations** | KMIP §VI | 2h | Makes USP-07 rigorous rather than just present |
| 8 | **DANE / MTA-STS checks** (USP-11) | MECSA §II-B | 4h | The least-adopted control in email; high novelty |
| 9 | `cipher_security_score` continuous feature | Symmetric Crypto | 1h | Optional refinement |

### The novelty claim, now defensible

> Prior work assesses email transport security **actively** (MECSA) or assesses TLS compliance **actively against
> web endpoints** (TLSAssistant). Anomaly detection on encrypted-traffic metadata is established for other
> protocols (KMIP). **No prior work performs passive, forensic, PCAP-based cryptographic posture assessment of
> email infrastructure, across all three mail protocols, with port-role-aware severity.**

Every clause in that sentence is now backed by a citation, and the last clause is the one no reviewed paper
addresses at all.
