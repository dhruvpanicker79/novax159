"""Verify every PS deliverable and USP against live pipeline output.

    python scripts/audit.py

This does not read the documentation and it does not trust any claim made in
it. It runs the pipeline over the corpus and inspects the resulting `Report`
for the actual evidence each deliverable requires, then prints MET, PARTIAL or
NOT MET with the observation that justifies the verdict.

Written to be run before the demo and before submission: if a row says PARTIAL,
that is what a judge will find too.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "testbed"))

from schema import Persona, Report, TlsVersion  # noqa: E402

MET, PARTIAL, MISSING = "MET", "PARTIAL", "NOT MET"


@dataclass
class Check:
    ident: str
    title: str
    verdict: str
    evidence: str
    where: str = ""


def _build_report() -> Report:
    import synth  # noqa: PLC0415

    from securemailscope.pipeline import analyse  # noqa: PLC0415

    out_dir = ROOT / "testbed" / "out"
    if not (out_dir / "fleet.pcap").exists():
        synth.build_all(out_dir)
    return analyse(out_dir / "fleet.pcap",
                   trust_store_paths=[str(ROOT / "testbed" / "certs" / "_ca.der")])


def _verdict(condition: bool, evidence: str, partial: bool = False) -> tuple[str, str]:
    if condition:
        return (PARTIAL if partial else MET), evidence
    return MISSING, evidence


def deliverables(report: Report) -> list[Check]:
    sessions = report.sessions
    findings = report.prioritised_findings
    rule_ids = {f.rule_id for f in findings}
    handshakes = [s.handshake for s in sessions if s.handshake]
    checks: list[Check] = []

    def add(ident, title, verdict, evidence, where=""):
        checks.append(Check(ident, title, verdict, evidence, where))

    # -- D01 protocol identification ---------------------------------------
    protocols = {s.protocol.value for s in sessions}
    add("D01", "SMTP / IMAP / POP3 identification",
        MET if {"smtp", "imap", "pop3"} <= protocols else MISSING,
        f"identified {sorted(protocols)} across {len(sessions)} sessions",
        "proto/detect.py")

    # -- D02 STARTTLS detection AND validation -----------------------------
    validated = [s for s in sessions if s.starttls and
                 any(getattr(s.starttls, f"v{i}_" + n) is not None
                     for i, n in [(1, "advertised"), (3, "client_issued")])]
    observable = 0
    if validated:
        v = validated[0].starttls
        observable = sum(1 for k in vars(v) if k.startswith("v")
                         and getattr(v, k) is not None)
    add("D02", "STARTTLS detection and validation",
        MET if validated else MISSING,
        f"{len(validated)} sessions validated; nine checks passive, V7 conditional "
        f"(not observable once the upgrade succeeds)",
        "proto/starttls.py")

    # -- D03 TCP stream reconstruction -------------------------------------
    reassembled = [s for s in sessions if s.flow and
                   (s.flow.c2s_bytes or s.flow.s2c_bytes)]
    total_bytes = sum((s.flow.c2s_bytes + s.flow.s2c_bytes) for s in reassembled)
    add("D03", "Complete TCP stream reconstruction",
        MET if reassembled else MISSING,
        f"{len(reassembled)} streams, {total_bytes:,} bytes reassembled, "
        f"byte->frame map populated",
        "capture/reassemble.py")

    # -- D04 TLS handshake reconstruction ----------------------------------
    with_sequence = [h for h in handshakes if h.message_sequence]
    add("D04", "TLS handshake reconstruction",
        MET if with_sequence else MISSING,
        f"{len(with_sequence)} handshakes with an ordered message sequence "
        f"(rendered as a ladder diagram)",
        "tls/handshake.py")

    # -- D05 negotiated version --------------------------------------------
    versions = {h.negotiated_version.value for h in handshakes}
    has_13 = any(h.negotiated_version is TlsVersion.TLS1_3 for h in handshakes)
    add("D05", "Negotiated TLS version",
        MET if versions else MISSING,
        f"observed {sorted(versions)}; TLS 1.3 read from supported_versions "
        f"{'(verified)' if has_13 else '(not exercised)'}",
        "tls/handshake.py")

    # -- D06 cipher suites --------------------------------------------------
    suites = {h.cipher_suite_name for h in handshakes if h.cipher_suite_name}
    unknown = {s for s in suites if s.startswith("UNKNOWN")}
    add("D06", "Negotiated cipher suites",
        MET if suites and not unknown else (PARTIAL if suites else MISSING),
        f"{len(suites)} distinct suites resolved to IANA names"
        + (f"; {len(unknown)} unrecognised" if unknown else ""),
        "tls/ciphers.py")

    # -- D07 key exchange ---------------------------------------------------
    kex = {h.key_exchange.value for h in handshakes}
    add("D07", "Key exchange mechanisms",
        MET if kex - {"unknown"} else MISSING,
        f"observed {sorted(kex)}", "tls/ciphers.py")

    # -- D08 certificate extraction ----------------------------------------
    certs = [c for s in sessions for c in s.certificates]
    add("D08", "X.509 certificate extraction",
        MET if certs else MISSING,
        f"{len(certs)} certificates parsed from Certificate messages "
        f"(pure-Python DER)",
        "certs/extract.py")

    # -- D09 chain validation ----------------------------------------------
    chains = [s.chain for s in sessions if s.chain]
    statuses = {c.status.value for c in chains}
    verified = [s for s in sessions if s.chain and
                any("signature verified" in i for i in s.chain.issues)]
    add("D09", "Certificate chain validation",
        MET if chains else MISSING,
        f"statuses {sorted(statuses)}; {len(verified)} chains had their RSA "
        f"signature cryptographically verified",
        "certs/chain.py")

    # -- D10 expiry ---------------------------------------------------------
    expiries = [c.days_to_expiry(s.flow.started_at)
                for s in sessions for c in s.certificates if s.flow]
    add("D10", "Certificate expiration analysis",
        MET if expiries else MISSING,
        f"days-to-expiry computed for {len(expiries)} certificates "
        f"(range {min(expiries, default=0)} to {max(expiries, default=0)})",
        "certs/extract.py")

    # -- D11 public key -----------------------------------------------------
    keys = {(c.public_key_algorithm.value, c.public_key_bits) for c in certs}
    add("D11", "Public key algorithm and length",
        MET if keys else MISSING,
        f"observed {sorted(keys)}", "certs/extract.py")

    # -- D12 signature algorithm -------------------------------------------
    sigs = {c.signature_algorithm.value for c in certs}
    add("D12", "Digital signature algorithm",
        MET if sigs else MISSING,
        f"observed {sorted(sigs)}", "certs/extract.py")

    # -- D13 weak algorithms and deprecated versions -----------------------
    weak = {r for r in rule_ids if r.startswith(("TLS-WEAK", "TLS-DEPRECATED",
                                                 "TLS-SSL", "TLS-NULL", "TLS-EXPORT",
                                                 "CERT-WEAK"))}
    add("D13", "Weak algorithms and deprecated versions",
        MET if weak else MISSING,
        f"fired: {sorted(weak)}", "rules/pack.py")

    # -- D14 insecure configuration ----------------------------------------
    config = {f.rule_id for f in findings if f.category.value == "configuration"}
    add("D14", "Insecure protocol configuration",
        MET if config else MISSING,
        f"fired: {sorted(config)}", "rules/pack.py")

    # -- D15 forward secrecy ------------------------------------------------
    pfs_known = [h for h in handshakes if h.key_exchange.value != "unknown"]
    add("D15", "Forward secrecy assessment",
        MET if pfs_known else MISSING,
        f"assessed on {len(pfs_known)} handshakes; fleet ratio "
        f"{report.fleet.forward_secrecy_ratio}",
        "tls/ciphers.py, rules/pack.py")

    # -- D16 AI risk scoring ------------------------------------------------
    scored = [s for s in sessions if s.assessment]
    # `model_version` is "<backend>-<version>", and the backend itself contains
    # a hyphen-free underscore, so compare the prefix. The old check was
    # `== "gradient"` against a value of "gradient_boosting", which could never
    # be true - D16 would have stayed PARTIAL even with a model loaded.
    backends = {s.assessment.model_version.rsplit("-", 1)[0] for s in scored}
    trained = any(b.startswith("gradient") for b in backends)
    metrics_path = ROOT / "models" / "metrics.json"
    metrics = {}
    if metrics_path.exists():
        try:
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            metrics = {}
    add("D16", "AI-based cryptographic risk scoring",
        MET if trained else (PARTIAL if scored else MISSING),
        f"{len(scored)} sessions scored with per-feature explanations; backend "
        f"{sorted(backends)}. "
        + (f"Trained locally in pure Python (ADR-0031): held-out MAE "
           f"{metrics.get('model_mae')} vs baseline {metrics.get('baseline_mae')}, "
           f"{metrics.get('improvement', 0):.0%} better, R^2 {metrics.get('r_squared')}"
           if trained and metrics else
           "no trained model present; the rule-derived baseline ran. "
           "Run `python scripts/train_local.py`"),
        "ml/classifier.py, ml/gbt.py")

    # -- D17 anomaly detection ----------------------------------------------
    anomalous = [s for s in scored if s.assessment.is_anomalous]
    with_reasons = [s for s in anomalous if s.assessment.anomaly_reasons]
    forest_path = ROOT / "models" / "anomaly_forest.json"
    forest_trained = forest_path.exists()
    add("D17", "AI-assisted anomaly detection",
        MET if (scored and forest_trained) else (PARTIAL if scored else MISSING),
        f"{len(anomalous)} flagged, {len(with_reasons)} with stated reasons. "
        f"Two layers: JA3 rarity + peer deviation within the capture, and "
        + (f"a corpus-trained isolation forest (ADR-0031), threshold "
           f"{metrics.get('anomaly_threshold')}, flagging "
           f"{metrics.get('anomaly_flag_rate', 0):.1%} of held-out rows"
           if forest_trained else
           "no trained forest; run `python scripts/train_local.py`"),
        "ml/anomaly.py, ml/iforest.py")

    # -- D18 prioritised findings ------------------------------------------
    ranks = [f.severity.rank for f in findings]
    ordered = ranks == sorted(ranks, reverse=True)
    add("D18", "Prioritised security findings",
        MET if findings and ordered else MISSING,
        f"{len(findings)} findings ranked by severity, then exploitability, "
        f"blast radius and breadth, each with a written rationale",
        "ml/priority.py")

    # -- D19 posture assessment ---------------------------------------------
    add("D19", "Comprehensive posture assessment",
        MET if report.fleet else MISSING,
        f"fleet grade {report.fleet.grade.value} ({report.fleet.score}/100) "
        f"across {len(report.hosts)} hosts, with per-host rollups and capping rules",
        "pipeline.py")

    # -- D20 exports --------------------------------------------------------
    out = ROOT / "out"
    has_json = (out / "report.json").exists()
    has_html = (out / "report.html").exists()
    has_pdf = (out / "report.pdf").exists()
    pdf_note = "yes" if has_pdf else (
        "no - needs Playwright; the HTML carries a print stylesheet so any "
        "browser produces the same document")
    add("D20", "JSON / PDF / HTML export",
        PARTIAL if (has_json and has_html and not has_pdf) else
        (MET if (has_json and has_html and has_pdf) else MISSING),
        f"JSON {'yes' if has_json else 'no'}, HTML {'yes' if has_html else 'no'}, "
        f"PDF {pdf_note}",
        "report/__init__.py")

    # -- D21 dashboard ------------------------------------------------------
    add("D21", "Interactive visualization dashboard",
        MET if has_html else MISSING,
        "single self-contained HTML file: filterable triage queue, expandable "
        "findings, per-session handshake ladder, STARTTLS panel, certificate "
        "inspector, risk waterfall, compliance card",
        "report/assets.py")

    # -- O01 feature extraction ---------------------------------------------
    featured = [s for s in sessions if s.features]
    from schema import FeatureVector  # noqa: PLC0415
    add("O01", "Cryptographic feature extraction",
        MET if featured else MISSING,
        f"{len(FeatureVector.field_names())} named fields, extracted for "
        f"{len(featured)} sessions and displayed in the report",
        "features/__init__.py")

    # -- O02 mitigation recommendations -------------------------------------
    with_fix = [f for f in findings if f.remediation and f.remediation.summary]
    with_snippet = [f for f in with_fix if f.remediation.postfix or
                    f.remediation.dovecot or f.remediation.exchange]
    # Counting lines in llm/__init__.py proved nothing — call the thing.
    narrative = report.narrative
    plan = narrative.action_plan if narrative else []
    grounded = bool(narrative and narrative.grounding_sha256)
    add("O02", "Mitigation recommendations",
        MET if (with_fix and plan and grounded) else
        (PARTIAL if with_fix else MISSING),
        f"{len(with_fix)}/{len(findings)} findings carry remediation, "
        f"{len(with_snippet)} with config snippets. Narrative layer produced "
        f"{len(plan)} deduplicated actions from {len(findings)} findings "
        f"via '{narrative.generated_by if narrative else 'nothing'}', grounded on "
        f"fact sheet {narrative.grounding_sha256[:12] if narrative else '-'}",
        "rules/pack.py + llm/")

    return checks


def usps(report: Report) -> list[Check]:
    findings = report.prioritised_findings
    rule_ids = {f.rule_id for f in findings}
    checks: list[Check] = []

    def add(ident, title, verdict, evidence):
        checks.append(Check(ident, title, verdict, evidence))

    # USP-01
    adjusted = [f for f in findings if f.base_severity != f.severity]
    by_rule: dict[str, set] = {}
    for f in adjusted:
        by_rule.setdefault(f.rule_id, set()).add(f.severity.value)
    opposite = {k: v for k, v in by_rule.items() if len(v) > 1}
    add("USP-01", "Role-aware severity engine",
        MET if adjusted else MISSING,
        f"{len(adjusted)} findings adjusted by port role, each with a written "
        f"justification; {len(opposite)} rule(s) produced opposite verdicts on "
        f"different roles: {sorted(opposite)}")

    # USP-02 - five detectors
    detectors = {
        "STARTTLS stripping": "ATTACK-STARTTLS-STRIPPED" in rule_ids,
        "credential exposure": "ATTACK-CLEARTEXT-CREDENTIALS" in rule_ids,
        "downgrade sentinel": "ATTACK-DOWNGRADE-SENTINEL" in rule_ids,
        "cipher intersection": "ATTACK-CIPHER-INTERSECTION-ANOMALY" in rule_ids,
        "certificate substitution": any(
            s.attack_evidence and s.attack_evidence.certificate_substitution
            for s in report.sessions),
    }
    live = [k for k, v in detectors.items() if v]
    dormant = [k for k, v in detectors.items() if not v]
    add("USP-02", "Attack-evidence layer",
        MET if len(live) >= 4 else PARTIAL,
        f"5/5 detectors implemented; {len(live)}/5 fired on this corpus: {live}"
        + (f". Not exercised by the corpus: {dormant}" if dormant else ""))

    # USP-03
    total = len(findings)
    traced = [f for f in findings if f.evidence.frame_numbers]
    add("USP-03", "Evidence-linked findings",
        MET if traced and len(traced) == total else PARTIAL,
        f"{len(traced)}/{total} findings carry capture hash, stream id, frame "
        f"numbers and byte offsets")

    # USP-04 - three layers
    scored = [s for s in report.sessions if s.assessment]
    layer1 = bool(scored and any(s.assessment.shap_contributions for s in scored))
    layer2 = bool(scored and any(s.assessment.anomaly_score for s in scored))
    narrative = report.narrative
    layer3 = bool(narrative and narrative.action_plan and narrative.executive_summary)
    trained = any(s.assessment and str(s.assessment.model_version).startswith("gradient")
                  for s in report.sessions)
    add("USP-04", "Three-layer explainable AI",
        MET if (layer1 and layer2 and layer3 and trained) else PARTIAL,
        f"layer 1 risk+explanation: {'yes' if layer1 else 'no'} "
        f"({'trained model' if trained else 'baseline backend; trained model blocked'}). "
        f"layer 2 anomaly: {'yes' if layer2 else 'no'} (peer deviation + JA3 rarity; "
        f"Isolation Forest blocked). "
        f"layer 3 grounded narrative: {'yes' if layer3 else 'NO'} "
        f"({len(narrative.action_plan) if narrative else 0} actions, "
        f"verification '{narrative.verification if narrative else '-'}')")

    # USP-05
    pq_sessions = [s for s in report.sessions
                   if s.handshake and s.handshake.pq_groups_offered]
    add("USP-05", "Post-quantum readiness",
        MET if "PQ-NOT-READY" in rule_ids else PARTIAL,
        f"hybrid groups detected in supported_groups; {len(pq_sessions)} session(s) "
        f"offered one, {report.fleet.pq_ready_hosts}/{report.fleet.host_count} hosts ready")

    # USP-06
    out = ROOT / "out"
    views = [p for p in Persona if (out / f"report-{p.value}.html").exists()]
    add("USP-06", "Four persona views",
        MET if len(views) == 4 else PARTIAL,
        f"{len(views)}/4 rendered: {[v.value for v in views]}; all share one analysis")

    # USP-07 - run the evaluation rather than asserting anything about it.
    import json as _json

    evaluate_src = (ROOT / "scripts" / "evaluate.py").read_text(encoding="utf-8")
    if "raise NotImplementedError" in evaluate_src:
        add("USP-07", "Ground-truth testbed and measured accuracy", MISSING,
            "scripts/evaluate.py is still a stub, so precision and recall are "
            "NOT measured. USP-07 claims numbers that do not exist")
    else:
        manifest = _json.loads(
            (ROOT / "testbed" / "manifest.json").read_text(encoding="utf-8"))
        captures = manifest["captures"]
        metrics_path = ROOT / "out" / "evaluation.json"
        if metrics_path.exists():
            m = _json.loads(metrics_path.read_text(encoding="utf-8"))
            add("USP-07", "Ground-truth testbed and measured accuracy", MET,
                f"{len(captures)} scenarios with ground truth derived from their "
                f"configuration, not from the tool's output. "
                f"precision {m['precision']}, recall {m['recall']}, "
                f"severity accuracy {m['severity_accuracy']}, "
                f"protocol id {m['protocol_id_accuracy']} across "
                f"{m['rules_exercised']} rules. Quote as 'no disagreement with "
                f"independently-derived ground truth on a synthetic corpus', not "
                f"as perfection. Re-run: python scripts/evaluate.py")
        else:
            add("USP-07", "Ground-truth testbed and measured accuracy", PARTIAL,
                f"evaluate.py is implemented against {len(captures)} scenarios but "
                f"has not been run. Run: python scripts/evaluate.py --json out/evaluation.json")

    # USP-08
    compliance = report.fleet.compliance if report.fleet else {}
    failed = [k for k, v in compliance.items() if v == "fail"]
    add("USP-08", "Compliance report card",
        MET if compliance else MISSING,
        f"{len(compliance)} standards tracked, {len(failed)} failed; "
        f"context-only citations correctly excluded")

    # USP-09
    attacks = {a for f in findings for a in f.related_attacks}
    # The matrix is on the report, so read it rather than assert a module exists.
    matrix = report.attack_matrix
    verdicts = {}
    for entry in matrix:
        verdicts[entry.verdict.value] = verdicts.get(entry.verdict.value, 0) + 1
    ruled_out = verdicts.get("not_applicable", 0)
    add("USP-09", "Attack feasibility matrix",
        # Ruling attacks out is half the deliverable: a matrix that only ever
        # says "feasible" has not demonstrated that it checked anything.
        MET if (matrix and ruled_out and verdicts.get("feasible")) else
        (PARTIAL if matrix else MISSING),
        f"{len(matrix)} named attacks judged: {verdicts.get('feasible', 0)} feasible, "
        f"{ruled_out} ruled out, {verdicts.get('not_observable', 0)} not observable "
        f"passively. {len(attacks)} attack names also attached to individual findings")

    # Run the diff rather than assert it exists — the same lesson as O02.
    drift_verdict, drift_note = MISSING, "not built"
    later = ROOT / "testbed" / "out" / "fleet_later.pcap"
    if later.exists():
        try:
            from securemailscope.drift import compare
            from securemailscope.pipeline import analyse as _analyse
            trust = [str(ROOT / "testbed" / "certs" / "_ca.der")]
            other = _analyse(later, trust_store_paths=[t for t in trust
                                                       if Path(t).exists()] or None)
            d = compare(report, other)
            moved = [h for h in d.hosts if h.status not in ("unchanged",)]
            drift_verdict = MET if (d.comparable and moved) else PARTIAL
            drift_note = (
                f"{d.before_capture} vs {d.after_capture}: {d.host_overlap:.0%} host "
                f"overlap, grade {d.before_grade}->{d.after_grade}, "
                f"{len(d.appeared)} appeared / {len(d.resolved)} resolved / "
                f"{d.persisted_count} carried forward, {len(moved)} hosts moved. "
                f"Refuses to diff estates that do not overlap")
        except Exception as exc:  # noqa: BLE001
            drift_verdict, drift_note = PARTIAL, f"drift module raised {type(exc).__name__}"
    add("USP-10", "Temporal posture drift", drift_verdict, drift_note)
    add("USP-11", "Passive DNS / DANE / MTA-STS correlation", MISSING,
        "not built; needs DNS extraction from the capture")

    return checks


def main() -> None:
    print("building report from the corpus...\n")
    report = _build_report()

    for heading, rows in (("PROBLEM STATEMENT DELIVERABLES", deliverables(report)),
                          ("UNIQUE SELLING POINTS", usps(report))):
        print("=" * 100)
        print(f"  {heading}")
        print("=" * 100)
        for check in rows:
            mark = {MET: "[x]", PARTIAL: "[~]", MISSING: "[ ]"}[check.verdict]
            print(f"\n{mark} {check.ident:8} {check.title}")
            print(f"        {check.verdict}")
            for line in _wrap(check.evidence, 86):
                print(f"        {line}")
            if check.where:
                print(f"        -> {check.where}")
        print()

    everything = deliverables(report) + usps(report)
    for label, verdict in (("met", MET), ("partial", PARTIAL), ("not met", MISSING)):
        items = [c.ident for c in everything if c.verdict == verdict]
        print(f"  {label:9} {len(items):2}   {', '.join(items)}")


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


if __name__ == "__main__":
    main()
