"""S8 - generate the corpus and fit the models. ADR-0003, ADR-0006.

    python -m securemailscope.ml.train --samples 10000 --out models/

Needs scikit-learn, so it runs inside WSL2 (ADR-0001). Everything upstream of
this - the rule pack, the corpus generator, the baseline scorer - is pure
stdlib and runs anywhere, which is what lets the rest of the team keep working
while the environment is being sorted out.

Produces:
    models/risk_classifier.joblib   gradient boosting + SHAP explainer  (D16)
    models/anomaly_detector.joblib  Isolation Forest                    (D17)
    models/metrics.json             held-out scores for the metrics slide

The classifier trains on 5 severity classes rather than a binary label, so the
expected-severity calculation in `classifier.py` yields a calibrated
continuous score instead of a hard yes/no.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from schema import FeatureVector

from . import corpus


def _require_sklearn():
    """Import scikit-learn, or explain precisely what to do about it.

    A bare ImportError traceback here would be the third time this team loses
    an afternoon to the same Windows problem.
    """
    try:
        import sklearn  # noqa: F401, PLC0415
        import numpy  # noqa: F401, PLC0415
    except Exception as exc:  # noqa: BLE001
        print(
            "\n"
            "scikit-learn / numpy are not usable in this interpreter.\n"
            f"  cause: {type(exc).__name__}: {exc}\n\n"
            "If the message mentions an Application Control policy, Windows Smart\n"
            "App Control is blocking numpy's compiled extensions. That is ADR-0001:\n"
            "run this inside WSL2.\n\n"
            "    wsl --install -d Ubuntu-22.04     # then reboot\n"
            "    pip install -e \".[ml]\"\n"
            "    python -m securemailscope.ml.train\n\n"
            "Meanwhile the corpus itself needs nothing installed:\n"
            "    python -m securemailscope.ml.train --corpus-only\n"
            "and the pipeline runs on the rule-derived baseline scorer, so no one\n"
            "is blocked on this step.\n",
            file=sys.stderr,
        )
        raise SystemExit(2) from exc


def train(samples: list[corpus.Sample], out_dir: Path) -> dict[str, float]:
    """Fit both models and report held-out performance."""
    _require_sklearn()

    import joblib
    import numpy as np
    from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        roc_auc_score,
    )
    from sklearn.model_selection import train_test_split

    feature_names = FeatureVector.field_names()
    X = np.array([s.features.as_row() for s in samples], dtype=float)
    y = np.array([s.label.rank for s in samples], dtype=int)

    # Split the INDICES alongside the arrays. `train_test_split` shuffles, so
    # slicing `samples` by position afterwards gives a different set from
    # X_test - and one that overlaps the training data, which silently
    # flatters the model in the baseline comparison below.
    indices = np.arange(len(samples))
    X_train, X_test, y_train, y_test, _idx_train, idx_test = train_test_split(
        X, y, indices, test_size=0.25, random_state=42, stratify=y)

    clf = GradientBoostingClassifier(
        n_estimators=300, learning_rate=0.08, max_depth=4, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    proba = clf.predict_proba(X_test)

    metrics: dict[str, float] = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
    }
    try:
        metrics["roc_auc_ovr"] = round(
            float(roc_auc_score(y_test, proba, multi_class="ovr")), 4)
    except ValueError:
        pass

    # The baseline is the honest yardstick: a model that cannot beat the
    # rule-derived scorer is not earning its place in the pipeline.
    from .classifier import baseline_score
    from ..rules.pack import RuleContext, evaluate

    test_samples = [samples[i] for i in idx_test]
    # Batch the predictions; one call per row is needlessly slow on 2,500 rows.
    proba_test = clf.predict_proba(np.array([s.features.as_row()
                                             for s in test_samples], dtype=float))
    ranks = np.array([int(c) for c in clf.classes_], dtype=float) / 4.0

    baseline_err = 0.0
    model_err = 0.0
    for s, row in zip(test_samples, proba_test):
        ctx = RuleContext(s.features, port=s.port, port_role=s.port_role)
        b_risk, _ = baseline_score(evaluate(ctx))
        m_risk = float((row * ranks).sum())
        baseline_err += abs(b_risk - s.target)
        model_err += abs(m_risk - s.target)
    n = len(test_samples) or 1
    metrics["baseline_mae"] = round(baseline_err / n, 4)
    metrics["model_mae"] = round(model_err / n, 4)

    # Explainer. TreeExplainer is exact for gradient boosting; if shap is not
    # installed the classifier falls back to finding attribution, which is
    # still a real explanation.
    explainer = None
    try:
        import shap  # noqa: PLC0415
        explainer = shap.TreeExplainer(clf)
    except Exception as exc:  # noqa: BLE001
        print(f"[train] shap unavailable ({type(exc).__name__}); "
              f"explanations will use rule attribution")

    # -- anomaly detector (D17) --------------------------------------------
    # Fit on the healthy archetypes of the TRAINING split only. Two reasons:
    # fitting on the full corpus leaks test rows into the model, and fitting on
    # all archetypes teaches it that compromised sessions are normal - the same
    # mistake the fleet baseline used to make (ADR-0019).
    HEALTHY = ("modern", "standard", "dated")
    train_samples = [samples[i] for i in _idx_train]
    healthy = np.array(
        [s.features.as_row() for s in train_samples if s.archetype in HEALTHY],
        dtype=float)
    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    iso.fit(healthy)

    # Evaluate it. D17 previously had no numbers at all: "we have an anomaly
    # detector" is not a claim until it is measured. Anything outside the
    # healthy archetypes counts as a true anomaly.
    is_anomalous = np.array([s.archetype not in HEALTHY for s in test_samples])
    # decision_function is negative for outliers; negate so higher = stranger.
    anomaly_scores = -iso.decision_function(X_test)
    if is_anomalous.any() and not is_anomalous.all():
        metrics["anomaly_roc_auc"] = round(
            float(roc_auc_score(is_anomalous, anomaly_scores)), 4)
        k = max(1, int(0.10 * len(anomaly_scores)))
        top_k = np.argsort(anomaly_scores)[::-1][:k]
        metrics["anomaly_precision_at_10pct"] = round(
            float(is_anomalous[top_k].mean()), 4)
        metrics["anomaly_base_rate"] = round(float(is_anomalous.mean()), 4)

    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "explainer": explainer,
                 "feature_names": feature_names, "version": "0.1.0"},
                out_dir / "risk_classifier.joblib")
    joblib.dump({"model": iso, "feature_names": feature_names, "version": "0.1.0"},
                out_dir / "anomaly_detector.joblib")
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print("\nclassification report (held out):")
    # Pin the labels: if a severity happens not to appear in the test split,
    # passing five target_names against four observed classes raises.
    print(classification_report(y_test, y_pred, labels=[0, 1, 2, 3, 4],
                                target_names=["info", "low", "medium", "high", "critical"],
                                zero_division=0))
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20260923)
    parser.add_argument("--out", type=Path, default=Path("models"))
    parser.add_argument("--csv", type=Path, default=Path("data/corpus.csv"))
    parser.add_argument("--corpus-only", action="store_true",
                        help="generate and describe the corpus without fitting "
                             "anything (needs no dependencies)")
    args = parser.parse_args()

    print(f"generating {args.samples} labelled feature vectors...")
    samples = corpus.generate(args.samples, seed=args.seed)
    print(json.dumps(corpus.describe(samples), indent=2))

    path = corpus.write_csv(samples, args.csv)
    print(f"wrote {path}")

    if args.corpus_only:
        return

    metrics = train(samples, args.out)
    print(json.dumps(metrics, indent=2))
    if metrics.get("model_mae", 1) < metrics.get("baseline_mae", 0):
        print("\nthe trained model beats the rule-derived baseline.")
    else:
        print("\nWARNING: the trained model does NOT beat the baseline. "
              "Do not claim it does on the metrics slide.")


if __name__ == "__main__":
    main()
