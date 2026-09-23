"""Run stages S6-S8 over the fixture fleet and print a SOC-style report.

    python scripts/demo_analysis.py

This is the integration proof for the analysis half of the pipeline: rule pack
-> role-aware severity -> risk scoring -> anomaly detection -> triage queue,
end to end, with zero dependencies installed. The parsing half (S0-S5) feeds it
the same `FeatureVector` objects once it exists.

It also doubles as the rehearsal script for the demo: this is the order the
story is told on stage.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from schema import PortRole, Report, Severity  # noqa: E402
from securemailscope.ml import anomaly, priority  # noqa: E402
from securemailscope.ml.classifier import RiskModel  # noqa: E402
from securemailscope.rules import pack  # noqa: E402

BAR = "=" * 78
COLOURS = {"critical": "!!", "high": " !", "medium": " ~", "low": " .", "info": "  "}


def rule(title: str) -> None:
    print(f"\n{BAR}\n  {title}\n{BAR}")


def main() -> None:
    report = Report.from_json(
        (ROOT / "fixtures" / "report.sample.json").read_text(encoding="utf-8"))
    sessions = report.sessions

    model = RiskModel.load("models")
    rule(f"SecureMailScope  |  {report.capture.filename}")
    print(f"  risk backend : {model.backend}")
    print(f"  sessions     : {len(sessions)}")
    print(f"  capture sha  : {report.capture.sha256[:32]}...")

    # ---------------------------------------------------------------- S6-S8
    baseline = anomaly.FleetBaseline.build([
        (s.features,
         s.handshake.client_hello.ja3 if s.handshake and s.handshake.client_hello else None,
         s.handshake.server_hello.ja3s if s.handshake and s.handshake.server_hello else None)
        for s in sessions if s.features
    ])

    all_findings = []
    for s in sessions:
        if not s.features:
            continue
        # Passing the session's evidence is not optional: findings that cannot
        # point back at the bytes that caused them are not forensic evidence,
        # they are opinions (USP-03 / ADR-0004).
        ctx = pack.RuleContext(s.features, host=s.server_host,
                               port=s.server_port, port_role=s.port_role,
                               evidence=s.evidence)
        findings = pack.evaluate(ctx)
        for f in findings:
            f.session_ids = [s.session_id]
        s.findings = findings
        s.assessment = model.assess(ctx, findings)

        result = anomaly.detect(
            s.features, baseline,
            ja3=s.handshake.client_hello.ja3 if s.handshake and s.handshake.client_hello else None,
            ja3s=s.handshake.server_hello.ja3s if s.handshake and s.handshake.server_hello else None,
        )
        s.assessment.anomaly_score = result.score
        s.assessment.is_anomalous = result.is_anomalous
        s.assessment.anomaly_reasons = result.reasons
        all_findings.extend(findings)

    ordered, workings = priority.prioritise(all_findings, sessions)

    # ---------------------------------------------------------------- output
    rule("SESSIONS  (D01, D05, D06, D16, D17)")
    print(f"  {'session':8} {'host':22} {'port':>5} {'role':12} "
          f"{'ver':5} {'risk':>5} {'anom':>5}")
    for s in sorted(sessions, key=lambda x: -(x.assessment.risk_score if x.assessment else 0)):
        a = s.assessment
        version = s.handshake.negotiated_version.value if s.handshake else "none"
        flag = COLOURS[a.risk_label.value]
        star = " *" if a.is_anomalous else "  "
        print(f"{flag}{star}{s.session_id:8} {s.server_host:22} {s.server_port:>5} "
              f"{s.port_role.value:12} {version:5} {a.risk_score:>5.2f} {a.anomaly_score:>5.2f}")

    rule("USP-01  |  IDENTICAL CERTIFICATE, OPPOSITE VERDICTS")
    for f in all_findings:
        if f.rule_id == "CERT-EXPIRED-SELF-SIGNED":
            print(f"\n  {f.affected_host}:{f.affected_port}  ({f.port_role.value})")
            print(f"    base     : {f.base_severity.value.upper()}")
            print(f"    adjusted : {f.severity.value.upper()}")
            if f.severity_adjustment_reason:
                for line in _wrap(f.severity_adjustment_reason, 68):
                    print(f"      {line}")

    rule("USP-02  |  ATTACK EVIDENCE")
    found = False
    for s in sessions:
        for f in s.findings:
            if f.category.value == "attack_evidence":
                found = True
                print(f"\n  [{f.severity.value.upper()}] {f.title}")
                print(f"    {s.server_host}:{s.server_port}   {f.evidence.describe()}")
                for line in _wrap(f.description, 70):
                    print(f"    {line}")
        if s.attack_evidence:
            for exposure in s.attack_evidence.credential_exposure:
                print(f"    -> recovered: {exposure.username} / "
                      f"{exposure.password_redacted} "
                      f"({exposure.mechanism}, {exposure.password_length} chars)")
    if not found:
        print("  none detected")

    rule("USP-04  |  WHY THIS SESSION SCORED WHAT IT DID")
    worst = max(sessions, key=lambda s: s.assessment.risk_score if s.assessment else 0)
    print(f"  {worst.server_host}:{worst.server_port}   "
          f"risk {worst.assessment.risk_score:.2f} "
          f"({worst.assessment.risk_label.value.upper()})")
    for c in worst.assessment.shap_contributions:
        bar = "#" * max(1, int(c.contribution * 60))
        print(f"    {c.contribution:+.3f}  {bar:<32} {c.human_readable}")

    rule("USP-04 LAYER 2  |  ANOMALIES (no rule fired for these)")
    any_anom = False
    for s in sessions:
        if s.assessment and s.assessment.is_anomalous:
            any_anom = True
            print(f"\n  {s.server_host}:{s.server_port}  score {s.assessment.anomaly_score:.2f}")
            for reason in s.assessment.anomaly_reasons:
                print(f"    - {reason}")
    if not any_anom:
        print("  none")

    rule("D18  |  TRIAGE QUEUE")
    for i, f in enumerate(ordered[:10], start=1):
        key = f"{f.rule_id}@{f.affected_host}:{f.affected_port}"
        w = workings[key]
        print(f"\n  {i:2}. [{f.severity.value.upper():8}] {f.title}")
        print(f"      {f.affected_host}:{f.affected_port}   score {w.score:.2f}")
        print(f"      why: {w.rationale}")

    rule("O02  |  WHAT TO ACTUALLY DO  (administrator view, USP-06)")
    for batch in priority.remediation_batches(ordered)[:4]:
        print(f"\n  [{batch['severity'].upper()}] {batch['title']}")
        print(f"    hosts  : {batch['host_count']}  ({', '.join(batch['hosts'][:4])})")
        print(f"    effort : {batch['effort']}")
        rem = batch["remediation"] or {}
        if rem.get("summary"):
            for line in _wrap(rem["summary"], 70):
                print(f"    {line}")
        if rem.get("postfix"):
            print("    postfix:")
            for line in str(rem["postfix"]).splitlines():
                print(f"      {line}")

    rule("USP-08  |  COMPLIANCE REPORT CARD")
    compliance = pack.compliance_report(all_findings)
    for standard, verdict in sorted(compliance.items(), key=lambda kv: (kv[1], kv[0])):
        mark = "FAIL" if verdict == "fail" else "pass"
        print(f"    {mark:5} {standard}")

    rule("SUMMARY")
    counts: dict[str, int] = {}
    for f in all_findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    print(f"  findings     : {len(all_findings)}  " +
          "  ".join(f"{k}={v}" for k, v in
                    sorted(counts.items(), key=lambda kv: -Severity(kv[0]).rank)))
    pq = sum(1 for s in sessions if s.handshake and s.handshake.pq_ready)
    print(f"  PQ readiness : {pq} of {len(sessions)} sessions")
    failed = sum(1 for v in compliance.values() if v == "fail")
    print(f"  compliance   : {failed} of {len(compliance)} standards failed")


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
