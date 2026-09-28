"""Measure the analyser against ground truth. This is USP-07.

    python scripts/evaluate.py                 # summary
    python scripts/evaluate.py --verbose       # every disagreement, per capture
    python scripts/evaluate.py --json out/metrics.json

Reads `testbed/manifest.json`, runs the full pipeline over each generated
capture, and compares what fired against what the scenario's *configuration*
says should have fired. Reports per-rule precision, recall and F1, plus
severity accuracy and protocol identification.

The ground truth was authored by reading `testbed/synth.py`, never by running
this tool. That is the whole point: if the expectations came from the output,
precision would be 1.0 by construction and the number would mean nothing. So a
disagreement here is real information — either a rule is wrong or the manifest
is, and the reasoning field on each capture is there to help decide which.

Exit code is non-zero when anything disagrees, so this can gate a merge.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "testbed"))

CAPTURES = ROOT / "testbed" / "out"
TRUST = ROOT / "testbed" / "certs" / "_ca.der"


@dataclass
class RuleScore:
    """Confusion counts for one rule across every capture."""

    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 1.0

    @property
    def perfect(self) -> bool:
        return self.fp == 0 and self.fn == 0


@dataclass
class CaptureResult:
    name: str
    ok: bool = True
    missed: list[str] = field(default_factory=list)      # expected, did not fire
    spurious: list[str] = field(default_factory=list)    # fired, not expected
    severity_errors: list[str] = field(default_factory=list)
    protocol_ok: bool = True
    note: str = ""


def _ensure_corpus() -> None:
    if not (CAPTURES / "fleet.pcap").exists():
        import synth
        print("generating the corpus first...")
        synth.build_all(CAPTURES)


def _analyse(path: Path):
    from securemailscope.pipeline import analyse
    trust = [str(TRUST)] if TRUST.exists() else None
    return analyse(path, trust_store_paths=trust)


def evaluate(verbose: bool = False) -> dict:
    manifest = json.loads((ROOT / "testbed" / "manifest.json").read_text(encoding="utf-8"))
    captures = manifest["captures"]
    _ensure_corpus()

    scores: dict[str, RuleScore] = defaultdict(RuleScore)
    results: list[CaptureResult] = []
    severity_total = severity_right = 0
    protocol_total = protocol_right = 0
    bytes_analysed = 0
    started = time.time()

    for spec in captures:
        name = spec["name"]
        result = CaptureResult(name=name)
        path = CAPTURES / f"{name}.pcap"
        if not path.exists():
            result.ok = False
            result.note = "capture not generated"
            results.append(result)
            continue

        bytes_analysed += path.stat().st_size
        report = _analyse(path)

        expected = set(spec.get("expect", []))
        actual = {f.rule_id for f in report.prioritised_findings}

        for rule in expected & actual:
            scores[rule].tp += 1
        for rule in expected - actual:
            scores[rule].fn += 1
            result.missed.append(rule)
        for rule in actual - expected:
            scores[rule].fp += 1
            result.spurious.append(rule)

        # -- severity, where the manifest pins it --------------------------
        by_rule = {f.rule_id: f for f in report.prioritised_findings}
        for rule, want in (spec.get("expect_severity") or {}).items():
            severity_total += 1
            got = by_rule[rule].severity.value if rule in by_rule else "absent"
            if got == want:
                severity_right += 1
            else:
                result.severity_errors.append(f"{rule}: expected {want}, got {got}")

        # -- protocol identification ---------------------------------------
        if spec.get("protocol") and report.sessions:
            protocol_total += 1
            if report.sessions[0].protocol.value == spec["protocol"]:
                protocol_right += 1
            else:
                result.protocol_ok = False

        result.ok = not (result.missed or result.spurious or result.severity_errors
                         or not result.protocol_ok)
        results.append(result)

    # -- fleet-scoped expectations ----------------------------------------
    fleet_expected: set[str] = set()
    for spec in captures:
        fleet_expected |= set(spec.get("expect_fleet", []))
    fleet_result = CaptureResult(name="fleet.pcap (cross-session rules)")
    if fleet_expected:
        fleet = _analyse(CAPTURES / "fleet.pcap")
        fired = {f.rule_id for f in fleet.prioritised_findings}
        for rule in fleet_expected:
            if rule in fired:
                scores[rule].tp += 1
            else:
                scores[rule].fn += 1
                fleet_result.missed.append(rule)
        fleet_result.ok = not fleet_result.missed
        results.append(fleet_result)

    elapsed = time.time() - started
    tp = sum(s.tp for s in scores.values())
    fp = sum(s.fp for s in scores.values())
    fn = sum(s.fn for s in scores.values())
    micro_p = tp / (tp + fp) if (tp + fp) else 1.0
    micro_r = tp / (tp + fn) if (tp + fn) else 1.0

    metrics = {
        "captures": len(results),
        "captures_exact": sum(1 for r in results if r.ok),
        "rules_exercised": len(scores),
        "rules_perfect": sum(1 for s in scores.values() if s.perfect),
        "true_positives": tp, "false_positives": fp, "false_negatives": fn,
        "precision": round(micro_p, 4),
        "recall": round(micro_r, 4),
        "f1": round(2 * micro_p * micro_r / (micro_p + micro_r)
                    if (micro_p + micro_r) else 1.0, 4),
        "severity_accuracy": round(severity_right / severity_total, 4) if severity_total else None,
        "protocol_id_accuracy": round(protocol_right / protocol_total, 4) if protocol_total else None,
        "throughput_mb_per_second": round(
            (bytes_analysed / 1_048_576) / elapsed, 2) if elapsed else None,
        "seconds": round(elapsed, 2),
    }
    return {"metrics": metrics, "scores": scores, "results": results}


def report(outcome: dict, verbose: bool) -> None:
    metrics, scores, results = outcome["metrics"], outcome["scores"], outcome["results"]

    print("=" * 78)
    print("  PER-RULE ACCURACY   (ground truth: testbed/manifest.json)")
    print("=" * 78)
    print(f"  {'rule':40} {'TP':>3} {'FP':>3} {'FN':>3}  {'prec':>6} {'rec':>6} {'F1':>6}")
    for rule in sorted(scores):
        s = scores[rule]
        mark = "  " if s.perfect else " <"
        print(f"  {rule:40} {s.tp:>3} {s.fp:>3} {s.fn:>3}  "
              f"{s.precision:>6.2f} {s.recall:>6.2f} {s.f1:>6.2f}{mark}")

    imperfect = [r for r in results if not r.ok]
    if imperfect:
        print()
        print("=" * 78)
        print("  DISAGREEMENTS")
        print("=" * 78)
        for r in imperfect:
            print(f"\n  {r.name}")
            if r.note:
                print(f"      {r.note}")
            for rule in r.missed:
                print(f"      MISSED     {rule}  (expected, did not fire)")
            for rule in r.spurious:
                print(f"      SPURIOUS   {rule}  (fired, not expected)")
            for err in r.severity_errors:
                print(f"      SEVERITY   {err}")
            if not r.protocol_ok:
                print("      PROTOCOL   misidentified")
        print("\n  Each of these is either a rule bug or a manifest bug. Read the")
        print("  `reasoning` field on the capture in the manifest and decide on the")
        print("  merits. Do not 'fix' it by copying the tool's output.")
    elif verbose:
        print("\n  every capture matched its expectations exactly")

    m = metrics
    print()
    print("=" * 78)
    print("  SUMMARY")
    print("=" * 78)
    print(f"  captures               {m['captures_exact']}/{m['captures']} exact")
    print(f"  rules exercised        {m['rules_perfect']}/{m['rules_exercised']} with no error")
    print(f"  precision              {m['precision']}")
    print(f"  recall                 {m['recall']}")
    print(f"  F1                     {m['f1']}")
    if m["severity_accuracy"] is not None:
        print(f"  severity accuracy      {m['severity_accuracy']}   (role-aware adjustment, USP-01)")
    if m["protocol_id_accuracy"] is not None:
        print(f"  protocol id accuracy   {m['protocol_id_accuracy']}")
    print(f"  throughput             {m['throughput_mb_per_second']} MB/s")
    print(f"  TP {m['true_positives']}   FP {m['false_positives']}   FN {m['false_negatives']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--json", type=Path, help="write metrics here")
    args = parser.parse_args()

    outcome = evaluate(args.verbose)
    report(outcome, args.verbose)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(outcome["metrics"], indent=2), encoding="utf-8")
        print(f"\n  wrote {args.json}")

    failures = outcome["metrics"]["false_positives"] + outcome["metrics"]["false_negatives"]
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
