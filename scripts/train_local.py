"""Train the risk model and the anomaly detector. Locally. No dependencies.

    python scripts/train_local.py

Replaces the Colab notebook, which existed only because scikit-learn cannot run
on these machines (ADR-0012) and which made the trained model depend on a
Google login. `securemailscope/ml/gbt.py` and `ml/iforest.py` are pure stdlib,
so this runs anywhere Python does, in about ten seconds.

Three rules, each here because getting it wrong produces a number that looks
good and means nothing:

**1. Split indices, not arrays.** The notebook shuffled the rows and then took
the test set by position, so the model was scored on rows it had trained on
(ADR-0020). Here one shuffled index list slices every array, and a test asserts
the two sets do not intersect.

**2. `archetype` is excluded.** It is the corpus generator's latent variable —
it decides how a row was drawn, is not part of `FeatureVector`, and does not
exist when a real session is scored. Training on it is label leakage: the model
would learn "archetype=compromised implies high risk", which is circular, and
the score would collapse on real traffic.

**3. If the model loses, the baseline ships.** The rule-derived baseline is a
real product, not a placeholder. This script refuses to write a model that does
not beat it, and says so.

Exit codes: 0 wrote a model, 2 no corpus, **3 the model lost and nothing was
written**. Deliberately not 1 for that last one - Python exits 1 for an
uncaught exception and for a SyntaxError, and `run.sh` was reporting a crash in
this file as the reassuring "model did not beat the baseline".
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securemailscope.ml.gbt import (  # noqa: E402
    GradientBoostedTrees, mean_absolute_error, r_squared, spearman)
from securemailscope.ml.iforest import IsolationForest  # noqa: E402

#: Columns that are answers, not inputs.
TARGET_COLUMNS = {"label", "target", "baseline_risk"}
#: Columns that leak the generator's intent. See rule 2 above.
LEAKING_COLUMNS = {"archetype"}
#: Columns that are categorical and get one-hot encoded.
CATEGORICAL_COLUMNS = {"port_role"}


def load_corpus(path: Path):
    """Return `(rows, targets, baseline, feature_names)` with leakage removed."""
    with path.open(encoding="utf-8") as handle:
        raw = list(csv.DictReader(handle))
    if not raw:
        raise SystemExit(f"{path} is empty — run `python -m securemailscope.ml.corpus`")

    header = list(raw[0])
    numeric = [c for c in header
               if c not in TARGET_COLUMNS | LEAKING_COLUMNS | CATEGORICAL_COLUMNS]
    categories = {c: sorted({row[c] for row in raw})
                  for c in CATEGORICAL_COLUMNS if c in header}

    names = numeric + [f"{col}={value}"
                       for col, values in categories.items() for value in values]
    rows = [
        [float(row[c]) for c in numeric]
        + [1.0 if row[col] == value else 0.0
           for col, values in categories.items() for value in values]
        for row in raw
    ]
    targets = [float(row["target"]) for row in raw]
    baseline = [float(row["baseline_risk"]) for row in raw]
    dropped = sorted(LEAKING_COLUMNS & set(header))
    return rows, targets, baseline, names, dropped


def split_indices(n: int, holdout: float, seed: int):
    """One shuffled index list, used to slice every array. ADR-0020."""
    order = list(range(n))
    random.Random(seed).shuffle(order)
    cut = int(n * (1.0 - holdout))
    return order[:cut], order[cut:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=ROOT / "data" / "corpus.csv")
    parser.add_argument("--out", type=Path, default=ROOT / "models")
    parser.add_argument("--trees", type=int, default=200)
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--learning-rate", type=float, default=0.1)
    parser.add_argument("--holdout", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--force", action="store_true",
                        help="write the model even if it loses to the baseline")
    args = parser.parse_args()

    if not args.corpus.exists():
        print(f"no corpus at {args.corpus}")
        print("  build one with:  python -m securemailscope.ml.corpus")
        return 2

    print("=" * 74)
    print("  Local training — pure Python, no numpy, no scikit-learn")
    print("=" * 74)

    rows, targets, baseline, names, dropped = load_corpus(args.corpus)
    train_idx, test_idx = split_indices(len(rows), args.holdout, args.seed)
    assert not (set(train_idx) & set(test_idx)), "train and test overlap"

    print(f"  corpus        {len(rows):,} rows x {len(names)} features")
    if dropped:
        print(f"  excluded      {', '.join(dropped)}  (generator latent variable — leakage)")
    print(f"  split         {len(train_idx):,} train / {len(test_idx):,} held out "
          f"(indices shuffled together, ADR-0020)")

    X_train = [rows[i] for i in train_idx]
    y_train = [targets[i] for i in train_idx]
    X_test = [rows[i] for i in test_idx]
    y_test = [targets[i] for i in test_idx]
    base_test = [baseline[i] for i in test_idx]

    # -- risk model ------------------------------------------------------- #
    print(f"\n  [1/2] gradient boosting  ({args.trees} trees, depth {args.depth})")
    started = time.time()
    model = GradientBoostedTrees(n_estimators=args.trees, max_depth=args.depth,
                                 learning_rate=args.learning_rate, seed=args.seed)
    model.fit(X_train, y_train, names,
              on_round=lambda n, mae: print(f"        round {n:3}   train MAE {mae:.4f}"))
    elapsed = time.time() - started

    predicted = model.predict(X_test)
    model_mae = mean_absolute_error(y_test, predicted)
    base_mae = mean_absolute_error(y_test, base_test)
    beats = model_mae < base_mae

    print(f"\n        trained in {elapsed:.1f}s")
    print(f"        baseline MAE   {base_mae:.4f}   (the rule-derived score)")
    print(f"        model    MAE   {model_mae:.4f}")
    print(f"        R^2            {r_squared(y_test, predicted):.4f}")
    print(f"        Spearman       {spearman(y_test, predicted):.4f}   "
          f"(ordering, which is what a triage queue needs)")
    print(f"        verdict        {'BEATS' if beats else 'LOSES TO'} the baseline "
          f"by {abs(base_mae - model_mae):.4f} "
          f"({abs(base_mae - model_mae) / base_mae:.0%})")

    important = list(model.feature_importance().items())[:8]
    print("\n        most used features:")
    for name, weight in important:
        print(f"          {weight:6.3f}  {name}")

    # -- anomaly detector -------------------------------------------------- #
    print(f"\n  [2/2] isolation forest  (150 trees, 256-row subsamples)")
    started = time.time()
    forest = IsolationForest(n_estimators=150, sample_size=256, seed=args.seed)
    forest.fit(X_train, names)
    flagged = sum(1 for row in X_test if forest.is_anomalous(row))
    print(f"        trained in {time.time() - started:.1f}s")
    print(f"        threshold      {forest.threshold_score:.4f}")
    print(f"        flags          {flagged} of {len(X_test)} held-out rows "
          f"({flagged / len(X_test):.1%})")

    # -- write, or refuse -------------------------------------------------- #
    if not beats and not args.force:
        print("\n" + "=" * 74)
        print("  NOT WRITING THE MODEL.")
        print("  It does not beat the rule-derived baseline, so the baseline is")
        print("  the better product and it is what ships. That is a real result,")
        print("  not a failure — re-run with --force to override deliberately.")
        print("=" * 74)
        return 3

    args.out.mkdir(parents=True, exist_ok=True)
    model.save(args.out / "risk_model.json")
    forest.save(args.out / "anomaly_forest.json")
    metrics = {
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "corpus_rows": len(rows),
        "features": len(names),
        "excluded_as_leakage": dropped,
        "train_rows": len(train_idx),
        "holdout_rows": len(test_idx),
        "baseline_mae": round(base_mae, 4),
        "model_mae": round(model_mae, 4),
        "improvement": round((base_mae - model_mae) / base_mae, 4),
        "r_squared": round(r_squared(y_test, predicted), 4),
        "spearman": round(spearman(y_test, predicted), 4),
        "anomaly_threshold": round(forest.threshold_score, 4),
        "anomaly_flag_rate": round(flagged / len(X_test), 4),
        "trainer": "securemailscope.ml.gbt (pure Python)",
        "top_features": [name for name, _ in important],
    }
    (args.out / "metrics.json").write_text(json.dumps(metrics, indent=2),
                                           encoding="utf-8")

    size = sum(p.stat().st_size for p in args.out.glob("*.json")) / 1024
    print("\n" + "=" * 74)
    print(f"  Written to {args.out}/  ({size:.0f} KB)")
    print("    risk_model.json      gradient boosted trees")
    print("    anomaly_forest.json  isolation forest")
    print("    metrics.json         the numbers above, for the audit and the deck")
    print("\n  Re-run `python scripts/audit.py` — D16 and D17 should now read MET.")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
