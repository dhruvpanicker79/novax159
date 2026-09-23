"""Measure the pipeline against the ground-truth corpus. This is USP-07.

    python scripts/evaluate.py testbed/out/

Reads `testbed/manifest.json`, runs the full pipeline over each generated
capture, and compares what we found against what was actually configured.

Reports, per the metrics slide:
    - per-rule precision and recall
    - protocol identification accuracy across all seven port/protocol pairs
    - role-aware severity accuracy (did the SAME certificate get INFO on the
      relay and CRITICAL on the access port?)
    - classifier ROC-AUC on a held-out split
    - throughput in MB/s

The output of this script is the answer to "how do you know it works?", which
most teams cannot answer at all. Keep it runnable end to end with one command:
reproducibility is the claim, not just the numbers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def load_manifest() -> dict:
    """The ground truth. See testbed/README.md."""
    return json.loads((ROOT / "testbed" / "manifest.json").read_text(encoding="utf-8"))


def evaluate(capture_dir: Path) -> dict[str, float]:
    """Run the pipeline over every capture and score it against the manifest.

    For each capture:
        1. run S0-S9 to produce a Report
        2. compare found rule_ids against `expected_findings`
        3. compare severities against `expected_severity` where stated
        4. accumulate true positives / false positives / false negatives
    """
    raise NotImplementedError(
        "Blocked on S0-S9. Until the pipeline lands, the manifest is still the "
        "spec the rule authors write against."
    )


def main() -> None:
    manifest = load_manifest()
    captures = manifest["captures"]
    print(f"ground-truth corpus: {len(captures)} captures")

    by_tier: dict[str, int] = {}
    by_mode: dict[str, int] = {}
    rules: set[str] = set()
    for c in captures:
        by_tier[c["tier"]] = by_tier.get(c["tier"], 0) + 1
        by_mode[c["tls_mode"]] = by_mode.get(c["tls_mode"], 0) + 1
        rules.update(c.get("expected_findings", []))

    print(f"  tiers:      {by_tier}")
    print(f"  tls modes:  {by_mode}")
    print(f"  rules under test: {len(rules)}")
    for rule in sorted(rules):
        covered = sum(1 for c in captures if rule in c.get("expected_findings", []))
        print(f"    {rule:38} {covered} capture(s)")

    if len(sys.argv) > 1:
        evaluate(Path(sys.argv[1]))


if __name__ == "__main__":
    main()
