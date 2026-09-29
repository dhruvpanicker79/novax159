"""Histogram gradient-boosted regression trees. Pure stdlib.

Written because scikit-learn cannot run here: Smart App Control blocks numpy's
C extensions, so `sklearn` is not installable and the training notebook only
works on Colab (ADR-0012). That made the trained model depend on a Google
login, which is a poor thing for a demo to depend on.

This is the same decision the project already made for DER parsing, RSA
verification and certificate generation — write it, because the alternative is
not available. It is not a general-purpose library and does not try to be: it
does regression on a dense numeric table of a few tens of thousands of rows,
which is exactly the shape of `data/corpus.csv`.

**Histogram-based**, following the LightGBM design (Ke et al., NIPS 2017): each
feature is bucketed into at most 64 bins once, up front, and split-finding then
scans bins rather than rows. That is the difference between a training run of
about a minute and one of twenty, and in CPython it is the only thing that
makes this practical at all.

Predictions come with **exact per-feature contributions** by path decomposition
(Saabas): walking a tree, each split assigns the change in node mean to the
feature that caused it. The contributions sum exactly to the prediction minus
the base value, which is what makes the explanation checkable rather than
indicative.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field

MAX_BINS = 64


# --------------------------------------------------------------------------- #
# Binning
# --------------------------------------------------------------------------- #

def _quantile_edges(values: list[float], max_bins: int = MAX_BINS) -> list[float]:
    """Split points for one feature, at quantiles of the observed values.

    Quantiles rather than equal width: most of these features are booleans or
    small counts, and equal-width bins put 9,900 rows in one bucket and nothing
    in the rest, which makes the histogram useless.
    """
    unique = sorted(set(values))
    if len(unique) <= max_bins:
        # Few enough distinct values to keep them all; midpoints are the edges.
        return [(a + b) / 2.0 for a, b in zip(unique, unique[1:])]
    ordered = sorted(values)
    step = len(ordered) / max_bins
    edges: list[float] = []
    for i in range(1, max_bins):
        candidate = ordered[min(int(i * step), len(ordered) - 1)]
        if not edges or candidate > edges[-1]:
            edges.append(candidate)
    return edges


def _bin_of(value: float, edges: list[float]) -> int:
    lo, hi = 0, len(edges)
    while lo < hi:                       # bisect_right, inlined for speed
        mid = (lo + hi) // 2
        if value < edges[mid]:
            hi = mid
        else:
            lo = mid + 1
    return lo


@dataclass
class Binner:
    """Maps a row of floats to a row of small ints, once."""

    edges: list[list[float]] = field(default_factory=list)

    @classmethod
    def fit(cls, columns: list[list[float]], max_bins: int = MAX_BINS) -> Binner:
        return cls(edges=[_quantile_edges(col, max_bins) for col in columns])

    def transform_columns(self, columns: list[list[float]]) -> list[list[int]]:
        return [[_bin_of(v, edges) for v in col]
                for col, edges in zip(columns, self.edges)]

    def n_bins(self, feature: int) -> int:
        return len(self.edges[feature]) + 1

    def threshold(self, feature: int, bin_index: int) -> float:
        """The real-valued split point a bin boundary corresponds to."""
        edges = self.edges[feature]
        if not edges:
            return 0.0
        return edges[min(bin_index, len(edges) - 1)]


# --------------------------------------------------------------------------- #
# One regression tree
# --------------------------------------------------------------------------- #

@dataclass
class Node:
    value: float = 0.0
    feature: int = -1
    threshold: float = 0.0
    bin_split: int = -1
    left: int = -1
    right: int = -1
    n: int = 0

    @property
    def is_leaf(self) -> bool:
        return self.feature < 0


@dataclass
class Tree:
    nodes: list[Node] = field(default_factory=list)

    def predict_row(self, row: list[float]) -> float:
        i = 0
        while not self.nodes[i].is_leaf:
            node = self.nodes[i]
            i = node.left if row[node.feature] < node.threshold else node.right
        return self.nodes[i].value

    def contributions(self, row: list[float], out: list[float]) -> float:
        """Path decomposition (Saabas): attribute each step to its split feature.

        Accumulates into `out` and returns the leaf value, so the caller can
        assert `base + sum(out) == prediction`.
        """
        i = 0
        while not self.nodes[i].is_leaf:
            node = self.nodes[i]
            nxt = node.left if row[node.feature] < node.threshold else node.right
            out[node.feature] += self.nodes[nxt].value - node.value
            i = nxt
        return self.nodes[i].value


def _build_tree(binned: list[list[int]], residuals: list[float], rows: list[int],
                features: list[int], binner: Binner, max_depth: int,
                min_samples_leaf: int) -> Tree:
    """Greedy depth-limited tree on binned features, split by variance reduction."""
    tree = Tree(nodes=[])

    def mean(idx: list[int]) -> float:
        return sum(residuals[i] for i in idx) / len(idx) if idx else 0.0

    def build(idx: list[int], depth: int) -> int:
        node_id = len(tree.nodes)
        tree.nodes.append(Node(value=mean(idx), n=len(idx)))

        if depth >= max_depth or len(idx) < 2 * min_samples_leaf:
            return node_id

        total = sum(residuals[i] for i in idx)
        count = len(idx)
        best = (0.0, -1, -1)            # (gain, feature, bin)

        for f in features:
            column = binned[f]
            nbins = binner.n_bins(f)
            sums = [0.0] * nbins
            counts = [0] * nbins
            for i in idx:                       # one pass per feature per node
                b = column[i]
                sums[b] += residuals[i]
                counts[b] += 1

            left_sum = 0.0
            left_n = 0
            for b in range(nbins - 1):
                left_sum += sums[b]
                left_n += counts[b]
                if left_n < min_samples_leaf:
                    continue
                right_n = count - left_n
                if right_n < min_samples_leaf:
                    break
                right_sum = total - left_sum
                # Variance reduction, dropping the constant term.
                gain = (left_sum * left_sum) / left_n + (right_sum * right_sum) / right_n
                if gain > best[0]:
                    best = (gain, f, b)

        gain, feature, split_bin = best
        if feature < 0:
            return node_id

        threshold = binner.threshold(feature, split_bin)
        column = binned[feature]
        left_idx = [i for i in idx if column[i] <= split_bin]
        right_idx = [i for i in idx if column[i] > split_bin]
        if len(left_idx) < min_samples_leaf or len(right_idx) < min_samples_leaf:
            return node_id

        node = tree.nodes[node_id]
        node.feature = feature
        node.threshold = threshold
        node.bin_split = split_bin
        node.left = build(left_idx, depth + 1)
        node.right = build(right_idx, depth + 1)
        return node_id

    build(rows, 0)
    return tree


# --------------------------------------------------------------------------- #
# The ensemble
# --------------------------------------------------------------------------- #

@dataclass
class GradientBoostedTrees:
    """Least-squares gradient boosting. Small, explicit, and stdlib only."""

    n_estimators: int = 200
    learning_rate: float = 0.08
    max_depth: int = 3
    min_samples_leaf: int = 20
    subsample: float = 0.7
    colsample: float = 0.5
    seed: int = 42

    base: float = 0.0
    trees: list[Tree] = field(default_factory=list)
    feature_names: list[str] = field(default_factory=list)
    version: str = "1.0.0"

    # -- training ---------------------------------------------------------- #

    def fit(self, rows: list[list[float]], targets: list[float],
            feature_names: list[str] | None = None,
            on_round=None) -> GradientBoostedTrees:
        n_features = len(rows[0])
        self.feature_names = feature_names or [f"f{i}" for i in range(n_features)]
        columns = [[row[f] for row in rows] for f in range(n_features)]
        binner = Binner.fit(columns)
        binned = binner.transform_columns(columns)

        self.base = sum(targets) / len(targets)
        predictions = [self.base] * len(targets)
        rng = random.Random(self.seed)
        all_rows = list(range(len(targets)))
        n_sub = max(1, int(len(all_rows) * self.subsample))
        n_cols = max(1, int(n_features * self.colsample))

        self.trees = []
        for round_index in range(self.n_estimators):
            residuals = [t - p for t, p in zip(targets, predictions)]
            sample = rng.sample(all_rows, n_sub)
            features = rng.sample(range(n_features), n_cols)
            tree = _build_tree(binned, residuals, sample, features, binner,
                               self.max_depth, self.min_samples_leaf)
            # Predict on every row, not just the sample - the sample only
            # decides the tree's shape.
            for i in all_rows:
                predictions[i] += self.learning_rate * tree.predict_row(rows[i])
            self.trees.append(tree)
            if on_round and (round_index + 1) % 25 == 0:
                mae = sum(abs(t - p) for t, p in zip(targets, predictions)) / len(targets)
                on_round(round_index + 1, mae)
        return self

    # -- inference --------------------------------------------------------- #

    def predict_row(self, row: list[float]) -> float:
        total = self.base
        for tree in self.trees:
            total += self.learning_rate * tree.predict_row(row)
        return total

    def predict(self, rows: list[list[float]]) -> list[float]:
        return [self.predict_row(row) for row in rows]

    @property
    def bias(self) -> float:
        """The row-independent part of every prediction.

        Each tree's **root value** is the mean residual before any split, so it
        belongs to no feature and cannot be attributed to one. It is constant
        across rows, so it folds into the bias — the reference point the
        contributions are measured from. Leaving it out made the contributions
        miss by a small fixed amount, which the reconciliation test caught.
        """
        return self.base + self.learning_rate * sum(
            tree.nodes[0].value for tree in self.trees if tree.nodes)

    def explain_row(self, row: list[float]) -> tuple[float, list[float]]:
        """`(prediction, contributions)`, where the contributions sum exactly to
        `prediction - bias`. That identity is asserted in the tests, because an
        explanation that does not reconcile is decoration."""
        out = [0.0] * len(row)
        total = self.base
        for tree in self.trees:
            scratch = [0.0] * len(row)
            leaf = tree.contributions(row, scratch)
            total += self.learning_rate * leaf
            for i, value in enumerate(scratch):
                if value:
                    out[i] += self.learning_rate * value
        return total, out

    def feature_importance(self) -> dict[str, float]:
        """How often each feature was chosen to split, weighted by node size."""
        weight: dict[int, float] = {}
        for tree in self.trees:
            for node in tree.nodes:
                if not node.is_leaf:
                    weight[node.feature] = weight.get(node.feature, 0.0) + node.n
        total = sum(weight.values()) or 1.0
        named = {self.feature_names[f]: round(w / total, 6)
                 for f, w in weight.items()}
        return dict(sorted(named.items(), key=lambda kv: -kv[1]))

    # -- persistence: JSON, because joblib needs numpy --------------------- #

    def to_dict(self) -> dict:
        return {
            "kind": "gbt_regressor",
            "version": self.version,
            "base": self.base,
            "learning_rate": self.learning_rate,
            "feature_names": self.feature_names,
            "trees": [[[n.value, n.feature, n.threshold, n.left, n.right, n.n]
                       for n in tree.nodes] for tree in self.trees],
        }

    @classmethod
    def from_dict(cls, payload: dict) -> GradientBoostedTrees:
        model = cls(learning_rate=payload["learning_rate"])
        model.base = payload["base"]
        model.version = payload.get("version", "1.0.0")
        model.feature_names = payload["feature_names"]
        model.trees = [
            Tree(nodes=[Node(value=v, feature=f, threshold=t, left=l, right=r, n=n)
                        for v, f, t, l, r, n in nodes])
            for nodes in payload["trees"]]
        return model

    def save(self, path) -> None:
        from pathlib import Path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.to_dict(), separators=(",", ":")),
                              encoding="utf-8")

    @classmethod
    def load(cls, path) -> GradientBoostedTrees:
        from pathlib import Path
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def mean_absolute_error(actual: list[float], predicted: list[float]) -> float:
    return sum(abs(a - p) for a, p in zip(actual, predicted)) / len(actual)


def r_squared(actual: list[float], predicted: list[float]) -> float:
    mean = sum(actual) / len(actual)
    ss_res = sum((a - p) ** 2 for a, p in zip(actual, predicted))
    ss_tot = sum((a - mean) ** 2 for a in actual)
    return 1.0 - ss_res / ss_tot if ss_tot else 0.0


def spearman(actual: list[float], predicted: list[float]) -> float:
    """Rank correlation. For a triage queue the *order* matters more than the
    absolute score, and MAE alone does not measure order."""
    def ranks(values: list[float]) -> list[float]:
        order = sorted(range(len(values)), key=lambda i: values[i])
        out = [0.0] * len(values)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
                j += 1
            average = (i + j) / 2.0 + 1.0
            for k in range(i, j + 1):
                out[order[k]] = average
            i = j + 1
        return out

    ra, rp = ranks(actual), ranks(predicted)
    n = len(ra)
    mean_a, mean_p = sum(ra) / n, sum(rp) / n
    num = sum((a - mean_a) * (p - mean_p) for a, p in zip(ra, rp))
    den = math.sqrt(sum((a - mean_a) ** 2 for a in ra)
                    * sum((p - mean_p) ** 2 for p in rp))
    return num / den if den else 0.0
