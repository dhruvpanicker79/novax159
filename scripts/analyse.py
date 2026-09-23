"""Analyse a PCAP and write a report. The command the demo actually runs.

    python scripts/analyse.py testbed/out/fleet.pcap
    python scripts/analyse.py capture.pcap --json out/report.json --quiet

With no argument it generates the synthetic corpus first and analyses the
combined fleet capture, so a fresh clone goes from nothing to a full report in
one command with no Docker, no servers and no WSL.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securemailscope.pipeline import analyse  # noqa: E402
from securemailscope.report import write_all  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", nargs="?", help="capture to analyse")
    parser.add_argument("--json", type=Path, help="write the full report here")
    parser.add_argument("--out", type=Path,
                        help="write every export here: JSON, HTML, PDF and the "
                             "four persona views")
    parser.add_argument("--trust", action="append", default=[],
                        help="DER trust anchor; repeatable")
    parser.add_argument("--models", type=Path, default=Path("models"))
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    path = Path(args.pcap) if args.pcap else None
    if path is None:
        sys.path.insert(0, str(ROOT / "testbed"))
        import synth  # noqa: PLC0415

        print("no capture given - generating the synthetic corpus first")
        synth.build_all(ROOT / "testbed" / "out")
        path = ROOT / "testbed" / "out" / "fleet.pcap"

    report = analyse(path, args.models, trust_store_paths=args.trust or None)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(report.to_json(), encoding="utf-8")
        print(f"wrote {args.json}")

    if args.out:
        for label, written in write_all(report, args.out).items():
            if written:
                print(f"  {label:18} {written}")

    if args.quiet:
        return

    fleet = report.fleet
    print()
    print(f"  {report.capture.filename}  -  {report.capture.packet_count:,} packets, "
          f"sha256 {report.capture.sha256[:16]}...")
    print(f"  {fleet.session_count} mail sessions across {fleet.host_count} hosts")
    print(f"  posture: {fleet.grade.value}  ({fleet.score}/100)")
    print()
    for line in _wrap(fleet.summary, 76):
        print(f"  {line}")

    print(f"\n  {'host':18} {'grade':>5} {'score':>6}  findings")
    for host in report.hosts:
        counts = "  ".join(f"{k}={v}" for k, v in sorted(host.finding_counts.items()))
        print(f"  {host.host:18} {host.grade.value:>5} {host.score:>6.1f}  {counts or '-'}")

    print(f"\n  triage queue (top {args.top}):")
    for index, finding in enumerate(report.prioritised_findings[:args.top], start=1):
        print(f"  {index:2}. [{finding.severity.value.upper():8}] {finding.title}")
        print(f"        {finding.affected_host}:{finding.affected_port}   "
              f"{finding.evidence.describe()}")

    failed = [k for k, v in fleet.compliance.items() if v == "fail"]
    print(f"\n  compliance: {len(failed)} of {len(fleet.compliance)} standards failed")
    if failed:
        print(f"    {', '.join(sorted(failed))}")


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
