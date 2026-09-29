"""The pure-Python trainer. D16, D17, ADR-0031.

Written because scikit-learn cannot run on these machines. Three things have to
hold for that to be a defensible substitute rather than a toy:

* it has to **learn** — beating the rule-derived baseline on held-out data is
  the whole justification for existing;
* the explanations have to **add up** — contributions that do not sum to the
  prediction are decoration, and this project's claim is that its output is
  checkable;
* it must **round-trip through JSON**, because the model ships as a file and a
  model that cannot be reloaded has not been trained.

    python tests/test_gbt.py
"""

from __future__ import annotations

import csv
import json
import random
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securemailscope.ml.gbt import (  # noqa: E402
    Binner, GradientBoostedTrees, mean_absolute_error, r_squared, spearman)
from securemailscope.ml.iforest import IsolationForest  # noqa: E402

CORPUS = ROOT / "data" / "corpus.csv"
MODELS = ROOT / "models"
_DATA: dict = {}


def _corpus():
    """A slice of the real corpus, leakage removed, split by index."""
    if "rows" not in _DATA:
        if not CORPUS.exists():
            raise RuntimeError("no corpus; run `python -m securemailscope.ml.corpus`")
        with CORPUS.open(encoding="utf-8") as handle:
            raw = list(csv.DictReader(handle))[:4000]
        skip = {"label", "target", "baseline_risk", "archetype", "port_role"}
        names = [c for c in raw[0] if c not in skip]
        _DATA["names"] = names
        _DATA["rows"] = [[float(r[c]) for c in names] for r in raw]
        _DATA["y"] = [float(r["target"]) for r in raw]
        _DATA["base"] = [float(r["baseline_risk"]) for r in raw]
        idx = list(range(len(raw)))
        random.Random(7).shuffle(idx)
        cut = int(len(idx) * 0.8)
        _DATA["train"], _DATA["test"] = idx[:cut], idx[cut:]
    return _DATA


def _fit(**kwargs) -> GradientBoostedTrees:
    d = _corpus()
    model = GradientBoostedTrees(n_estimators=kwargs.pop("n_estimators", 60),
                                 max_depth=3, learning_rate=0.15, **kwargs)
    return model.fit([d["rows"][i] for i in d["train"]],
                     [d["y"][i] for i in d["train"]], d["names"])


# --------------------------------------------------------------------------- #
# Binning
# --------------------------------------------------------------------------- #

def test_binner_keeps_every_value_of_a_low_cardinality_feature():
    """Most features here are booleans. Equal-width bins would put every row in
    one bucket and make the histogram useless."""
    binner = Binner.fit([[0.0, 1.0, 0.0, 1.0, 1.0]])
    assert binner.n_bins(0) == 2
    assert binner.transform_columns([[0.0, 1.0]])[0] == [0, 1]


def test_binner_caps_a_continuous_feature_at_max_bins():
    column = [float(i) for i in range(5000)]
    binner = Binner.fit([column], max_bins=64)
    assert binner.n_bins(0) <= 64
    bins = binner.transform_columns([column])[0]
    assert bins == sorted(bins), "binning must preserve order"


# --------------------------------------------------------------------------- #
# It has to actually learn
# --------------------------------------------------------------------------- #

def test_it_learns_a_signal_it_could_not_guess():
    model = GradientBoostedTrees(n_estimators=40, max_depth=3, learning_rate=0.2)
    rng = random.Random(1)
    rows = [[rng.random(), rng.random(), rng.random()] for _ in range(600)]
    targets = [2.0 * r[0] - r[1] for r in rows]           # r[2] is noise
    model.fit(rows, targets, ["a", "b", "noise"])
    predicted = model.predict(rows)
    assert mean_absolute_error(targets, predicted) < 0.12
    assert r_squared(targets, predicted) > 0.9
    importance = model.feature_importance()
    assert importance.get("noise", 0.0) < max(importance.get("a", 0),
                                              importance.get("b", 0))


def test_it_beats_the_rule_derived_baseline_on_held_out_rows():
    """The justification for the module existing at all."""
    d = _corpus()
    model = _fit()
    test = d["test"]
    predicted = model.predict([d["rows"][i] for i in test])
    actual = [d["y"][i] for i in test]
    model_mae = mean_absolute_error(actual, predicted)
    base_mae = mean_absolute_error(actual, [d["base"][i] for i in test])
    assert model_mae < base_mae, f"model {model_mae:.4f} vs baseline {base_mae:.4f}"
    assert spearman(actual, predicted) > 0.8, "ordering is what a triage queue needs"


def test_training_and_test_rows_never_overlap():
    """ADR-0020: the notebook shuffled the arrays and sliced the test set by
    position, so the model was scored on rows it had trained on."""
    d = _corpus()
    assert not (set(d["train"]) & set(d["test"]))
    assert len(d["train"]) + len(d["test"]) == len(d["rows"])


# --------------------------------------------------------------------------- #
# The explanation has to add up
# --------------------------------------------------------------------------- #

def test_contributions_sum_exactly_to_the_prediction():
    """`bias + sum(contributions) == prediction`, to floating-point tolerance.

    The reference point is `bias`, not `base`: every tree's root value is the
    mean residual before any split, so it belongs to no feature. Omitting it
    made the contributions miss by a small constant, which is exactly the kind
    of "nearly right" an explanation panel would have shipped with.
    """
    d = _corpus()
    model = _fit(n_estimators=40)
    for i in d["test"][:25]:
        row = d["rows"][i]
        predicted, contributions = model.explain_row(row)
        assert abs(model.predict_row(row) - predicted) < 1e-9
        assert abs(model.bias + sum(contributions) - predicted) < 1e-6, (
            f"contributions sum to {sum(contributions):.6f}, prediction is "
            f"{predicted - model.bias:.6f} above bias")


def test_an_unused_feature_gets_no_contribution():
    model = GradientBoostedTrees(n_estimators=20, max_depth=2, learning_rate=0.2)
    rng = random.Random(3)
    rows = [[rng.random(), 0.5] for _ in range(300)]       # column 1 is constant
    model.fit(rows, [r[0] for r in rows], ["signal", "constant"])
    _, contributions = model.explain_row(rows[0])
    assert abs(contributions[1]) < 1e-9


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #

def test_the_model_round_trips_through_json():
    d = _corpus()
    model = _fit(n_estimators=30)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "risk_model.json"
        model.save(path)
        reloaded = GradientBoostedTrees.load(path)
        for i in d["test"][:40]:
            assert abs(model.predict_row(d["rows"][i])
                       - reloaded.predict_row(d["rows"][i])) < 1e-12
        assert reloaded.feature_names == model.feature_names


def test_the_saved_model_needs_no_third_party_import():
    """It is JSON on purpose: joblib and pickle both need numpy here."""
    if not (MODELS / "risk_model.json").exists():
        return
    payload = json.loads((MODELS / "risk_model.json").read_text(encoding="utf-8"))
    assert payload["kind"] == "gbt_regressor"
    assert payload["feature_names"] and payload["trees"]


# --------------------------------------------------------------------------- #
# Isolation forest
# --------------------------------------------------------------------------- #

def test_the_forest_scores_an_outlier_above_the_crowd():
    rng = random.Random(11)
    normal = [[rng.gauss(0, 1), rng.gauss(0, 1)] for _ in range(500)]
    forest = IsolationForest(n_estimators=80, sample_size=128).fit(normal, ["a", "b"])
    outlier = [14.0, -14.0]
    typical = sum(forest.score(row) for row in normal[:100]) / 100
    assert forest.score(outlier) > typical, "an outlier did not score above normal"
    assert forest.is_anomalous(outlier)


def test_the_forest_flags_roughly_the_contamination_rate():
    rng = random.Random(5)
    rows = [[rng.gauss(0, 1) for _ in range(4)] for _ in range(800)]
    forest = IsolationForest(n_estimators=60, sample_size=128,
                             contamination=0.05).fit(rows, list("abcd"))
    flagged = sum(1 for row in rows if forest.is_anomalous(row)) / len(rows)
    assert 0.02 <= flagged <= 0.12, f"flagged {flagged:.1%}, expected about 5%"


def test_the_forest_round_trips_through_json():
    rng = random.Random(2)
    rows = [[rng.gauss(0, 1), rng.gauss(0, 1)] for _ in range(300)]
    forest = IsolationForest(n_estimators=40, sample_size=64).fit(rows, ["a", "b"])
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "forest.json"
        forest.save(path)
        reloaded = IsolationForest.load(path)
        for row in rows[:30]:
            assert abs(forest.score(row) - reloaded.score(row)) < 1e-12
        assert reloaded.threshold_score == forest.threshold_score


# --------------------------------------------------------------------------- #
# The pipeline actually uses it
# --------------------------------------------------------------------------- #

def test_the_pipeline_picks_up_a_trained_model_when_one_is_present():
    if not (MODELS / "risk_model.json").exists():
        return                                     # not trained here; nothing to check
    from securemailscope.pipeline import analyse

    capture = ROOT / "testbed" / "out" / "fleet.pcap"
    if not capture.exists():
        return
    report = analyse(capture, trust_store_paths=[
        str(ROOT / "testbed" / "certs" / "_ca.der")])
    versions = {s.assessment.model_version for s in report.sessions if s.assessment}
    assert any(v.startswith("gradient") for v in versions), versions
    assert any(s.assessment.shap_contributions for s in report.sessions)


def test_the_grade_does_not_move_with_the_model():
    """The posture grade is rule-derived (D19); the model scores risk for triage
    (D16). When the model was first wired in, a session with zero findings
    graded B and an uninspectable host graded F instead of '?'."""
    import tempfile as tf

    sys.path.insert(0, str(ROOT / "testbed"))
    import synth
    from securemailscope.pipeline import analyse

    out = Path(tf.mkdtemp()) / "healthy.pcap"
    synth.write_pcap(out, [synth.smtp_starttls_healthy()])
    report = analyse(out)
    assert not report.prioritised_findings
    assert report.hosts[0].grade.value == "A+", (
        f"zero findings but graded {report.hosts[0].grade.value}")

    mid = ROOT / "testbed" / "out" / "imaps_mid_session.pcap"
    if mid.exists():
        incomplete = analyse(mid)
        assert incomplete.hosts[0].grade.value == "?", (
            "a host whose handshake could not be parsed was given a real grade")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
            except AssertionError as exc:
                failures += 1
                print(f"  FAIL  {name}: {exc}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
    print(f"\n{failures} failure(s)")
    sys.exit(1 if failures else 0)
