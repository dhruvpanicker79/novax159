"""Isolation Forest. Pure stdlib. D17.

Liu, Ting & Zhou (ICDM 2008). Anomalies are easier to isolate than normal
points, so build trees that split on a random feature at a random value and
measure how few splits it takes to reach each point. Short average path length
means unusual.

Written here for the same reason as `gbt.py`: scikit-learn will not run on
these machines (ADR-0012). It is also genuinely easy — the algorithm's whole
appeal is that it needs no distance metric, no density estimate and no labels,
which is what makes it about a hundred lines.

This does **not** replace `anomaly.py`. That layer explains *why* a session is
unusual for its own fleet, in sentences an analyst can act on, and it works on
a single capture. This gives a corpus-trained score for how unusual a session
is against ten thousand synthetic servers. The two answer different questions
and the report carries both.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field


def _harmonic(n: int) -> float:
    return math.log(n - 1) + 0.5772156649 if n > 1 else 0.0


def _expected_path(n: int) -> float:
    """Average path length of an unsuccessful BST search over n points — the
    normaliser that makes scores comparable across sample sizes."""
    if n <= 1:
        return 0.0
    return 2.0 * _harmonic(n) - 2.0 * (n - 1) / n


@dataclass
class _Node:
    feature: int = -1
    threshold: float = 0.0
    left: int = -1
    right: int = -1
    size: int = 0

    @property
    def is_leaf(self) -> bool:
        return self.feature < 0


@dataclass
class IsolationForest:
    n_estimators: int = 150
    sample_size: int = 256
    seed: int = 42
    contamination: float = 0.05

    trees: list[list[_Node]] = field(default_factory=list)
    feature_names: list[str] = field(default_factory=list)
    height_limit: int = 8
    threshold_score: float = 0.5
    version: str = "1.0.0"

    # -- training ---------------------------------------------------------- #

    def fit(self, rows: list[list[float]],
            feature_names: list[str] | None = None) -> IsolationForest:
        n_features = len(rows[0])
        self.feature_names = feature_names or [f"f{i}" for i in range(n_features)]
        rng = random.Random(self.seed)
        size = min(self.sample_size, len(rows))
        self.height_limit = max(1, int(math.ceil(math.log2(size)))) if size > 1 else 1

        self.trees = []
        for _ in range(self.n_estimators):
            sample = rng.sample(rows, size)
            self.trees.append(self._build(sample, rng))

        # Where to draw the line, from the training distribution itself rather
        # than a magic number: the top `contamination` fraction is "anomalous".
        scores = sorted(self.score(row) for row in rows)
        cut = int(len(scores) * (1.0 - self.contamination))
        self.threshold_score = scores[min(cut, len(scores) - 1)]
        return self

    def _build(self, rows: list[list[float]], rng: random.Random) -> list[_Node]:
        nodes: list[_Node] = []

        def grow(subset: list[list[float]], depth: int) -> int:
            node_id = len(nodes)
            nodes.append(_Node(size=len(subset)))
            if depth >= self.height_limit or len(subset) <= 1:
                return node_id

            # Only split on features that actually vary in this subset;
            # otherwise most splits are no-ops and the trees are stunted.
            n_features = len(subset[0])
            candidates = list(range(n_features))
            rng.shuffle(candidates)
            for feature in candidates:
                values = [row[feature] for row in subset]
                low, high = min(values), max(values)
                if high - low <= 1e-12:
                    continue
                threshold = rng.uniform(low, high)
                left = [r for r in subset if r[feature] < threshold]
                right = [r for r in subset if r[feature] >= threshold]
                if not left or not right:
                    continue
                node = nodes[node_id]
                node.feature = feature
                node.threshold = threshold
                node.left = grow(left, depth + 1)
                node.right = grow(right, depth + 1)
                return node_id
            return node_id                     # every feature is constant here

        grow(rows, 0)
        return nodes

    # -- scoring ----------------------------------------------------------- #

    def _path_length(self, nodes: list[_Node], row: list[float]) -> float:
        i, depth = 0, 0
        while not nodes[i].is_leaf:
            node = nodes[i]
            i = node.left if row[node.feature] < node.threshold else node.right
            depth += 1
        # Credit the unsplit remainder of the leaf, per the paper.
        return depth + _expected_path(nodes[i].size)

    def score(self, row: list[float]) -> float:
        """0 to 1. Above ~0.5 is unusual; near 1.0 is isolated almost at once."""
        if not self.trees:
            return 0.0
        mean_path = sum(self._path_length(t, row) for t in self.trees) / len(self.trees)
        norm = _expected_path(min(self.sample_size, 256))
        return 2.0 ** (-mean_path / norm) if norm else 0.0

    def is_anomalous(self, row: list[float]) -> bool:
        return self.score(row) >= self.threshold_score

    # -- persistence ------------------------------------------------------- #

    def to_dict(self) -> dict:
        return {
            "kind": "isolation_forest",
            "version": self.version,
            "sample_size": self.sample_size,
            "height_limit": self.height_limit,
            "threshold_score": self.threshold_score,
            "contamination": self.contamination,
            "feature_names": self.feature_names,
            "trees": [[[n.feature, n.threshold, n.left, n.right, n.size] for n in tree]
                      for tree in self.trees],
        }

    @classmethod
    def from_dict(cls, payload: dict) -> IsolationForest:
        forest = cls(sample_size=payload["sample_size"],
                     contamination=payload.get("contamination", 0.05))
        forest.version = payload.get("version", "1.0.0")
        forest.height_limit = payload["height_limit"]
        forest.threshold_score = payload["threshold_score"]
        forest.feature_names = payload["feature_names"]
        forest.trees = [[_Node(feature=f, threshold=t, left=l, right=r, size=s)
                         for f, t, l, r, s in tree] for tree in payload["trees"]]
        forest.n_estimators = len(forest.trees)
        return forest

    def save(self, path) -> None:
        from pathlib import Path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.to_dict(), separators=(",", ":")),
                              encoding="utf-8")

    @classmethod
    def load(cls, path) -> IsolationForest:
        from pathlib import Path
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
