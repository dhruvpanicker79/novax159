"""S8 layer 2 - unsupervised anomaly detection. Deliverable D17, USP-04.

This is the layer that answers "your rules only find what you already know."
It learns what *this organisation* normally does and flags deviation, with no
rule and no label involved.

Two signals, combined:

    JA3 / JA3S rarity   a fingerprint seen once in forty sessions is worth a
                        look even when every rule passed. Pure counting, so it
                        needs no dependencies at all.

    Isolation Forest    over the full feature space, when scikit-learn is
                        available. Falls back to peer deviation - how far this
                        session sits from the fleet's modal configuration -
                        which is cruder but works with nothing installed and
                        is trivially explainable.

Both paths produce reasons, not just a score. "Anomalous, confidence 0.79" is
useless to an analyst; "DHE key exchange used by no other host in the fleet" is
actionable.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from schema import FeatureVector

#: Features worth reporting on when a session deviates from its peers. Chosen
#: because each one names something an analyst can act on; counting a deviation
#: in `handshake_alert_count` would be noise.
_PEER_FEATURES = [
    "tls_version_num", "cipher_strength_bits", "cipher_is_aead", "cipher_is_cbc",
    "cipher_is_rc4", "cipher_is_3des", "kex_is_ephemeral", "kex_group_bits",
    "has_forward_secrecy", "pq_hybrid_offered", "cert_key_bits",
    "cert_is_self_signed", "cert_chain_complete", "renegotiation_info_present",
    "tls_mode_is_cleartext", "compression_enabled", "session_resumed",
]

_PEER_LABELS: dict[str, str] = {
    "tls_version_num": "negotiates a TLS version",
    "cipher_strength_bits": "uses a cipher strength",
    "cipher_is_aead": "uses an AEAD setting",
    "cipher_is_cbc": "uses a CBC setting",
    "cipher_is_rc4": "uses RC4",
    "cipher_is_3des": "uses 3DES",
    "kex_is_ephemeral": "uses a key exchange type",
    "kex_group_bits": "uses a key exchange group size",
    "has_forward_secrecy": "has a forward-secrecy setting",
    "pq_hybrid_offered": "offers a post-quantum group",
    "cert_key_bits": "uses a certificate key size",
    "cert_is_self_signed": "uses a self-signed certificate",
    "cert_chain_complete": "serves a chain",
    "renegotiation_info_present": "has a renegotiation setting",
    "tls_mode_is_cleartext": "runs in cleartext",
    "compression_enabled": "enables compression",
    "session_resumed": "resumes sessions",
}


@dataclass
class FleetBaseline:
    """What normal looks like for this capture.

    Built from the capture itself, which is the point: a configuration that
    would be unremarkable in one estate is an outlier in another.
    """

    ja3_counts: Counter = field(default_factory=Counter)
    ja3s_counts: Counter = field(default_factory=Counter)
    modal: dict[str, float] = field(default_factory=dict)
    session_count: int = 0
    #: Sessions actually used to define "normal", after contaminated ones were
    #: rejected. Reported so the UI can say what the comparison was against.
    clean_count: int = 0
    contaminated_count: int = 0

    #: Below this many clean sessions the modal configuration is meaningless,
    #: so we fall back to using every session and say so.
    MIN_CLEAN = 3

    @classmethod
    def build(cls, sessions: list[tuple[FeatureVector, str | None, str | None]],
              contaminated: list[bool] | None = None) -> FleetBaseline:
        """Learn what normal looks like for this capture.

        `sessions` is (features, ja3, ja3s) per session. `contaminated[i]` marks
        a session that should NOT help define normal - typically one carrying a
        high-severity finding.

        Two populations, deliberately:

        - **modal configuration** is computed from clean sessions only. Building
          it from every session lets the attacks define normal, so the more
          hosts are compromised the less anomalous compromise looks. That is
          backwards, and it is the unsupervised outlier-rejection stage the KMIP
          work (Baee et al., 2024) puts ahead of learning - see
          docs/07_RELATED_WORK.md section 4.
        - **fingerprint rarity** is computed over ALL sessions, because rarity
          is a property of the observed population. An attacker's JA3 being rare
          among everything present is exactly the signal we want; excluding it
          from its own denominator would hide it.
        """
        flags = contaminated or [False] * len(sessions)
        if len(flags) != len(sessions):
            flags = [False] * len(sessions)

        base = cls(session_count=len(sessions))

        # Rarity: every session counts.
        for features, ja3, ja3s in sessions:
            if ja3:
                base.ja3_counts[ja3] += 1
            if ja3s:
                base.ja3s_counts[ja3s] += 1

        clean = [s for s, bad in zip(sessions, flags) if not bad]
        base.contaminated_count = len(sessions) - len(clean)
        if len(clean) < cls.MIN_CLEAN:
            # Nothing trustworthy to learn from. Use everything rather than
            # produce a baseline built on two sessions, and record that we did.
            clean = list(sessions)
            base.contaminated_count = 0
        base.clean_count = len(clean)

        values: dict[str, list[float]] = {name: [] for name in _PEER_FEATURES}
        for features, _ja3, _ja3s in clean:
            for name in _PEER_FEATURES:
                values[name].append(float(getattr(features, name)))
        for name, column in values.items():
            if column:
                base.modal[name] = Counter(column).most_common(1)[0][0]
        return base

    def rarity(self, fingerprint: str | None, server_side: bool = False) -> float:
        """1.0 when the fingerprint is unique in the capture, 0.0 when ubiquitous."""
        counts = self.ja3s_counts if server_side else self.ja3_counts
        if not fingerprint or not counts or self.session_count == 0:
            return 0.0
        seen = counts.get(fingerprint, 0)
        if seen == 0:
            return 1.0
        return round(1.0 - (seen - 1) / max(self.session_count - 1, 1), 3)


@dataclass
class AnomalyResult:
    score: float = 0.0
    is_anomalous: bool = False
    reasons: list[str] = field(default_factory=list)
    backend: str = "peer_deviation"


def peer_deviation(features: FeatureVector, baseline: FleetBaseline) -> tuple[float, list[str]]:
    """How far does this session sit from the fleet's modal configuration?

    Deliberately simple and deliberately explainable: it returns the names of
    the settings that differ, which is the part an analyst reads.
    """
    # Guard on the CLEAN population: that is what the modal values came from.
    if not baseline.modal or baseline.clean_count < FleetBaseline.MIN_CLEAN:
        return 0.0, []

    differing: list[str] = []
    for name in _PEER_FEATURES:
        expected = baseline.modal.get(name)
        if expected is None:
            continue
        actual = float(getattr(features, name))
        if abs(actual - expected) > 1e-9:
            differing.append(name)

    score = len(differing) / len(_PEER_FEATURES)
    reasons = [
        f"{_PEER_LABELS.get(name, name)} unlike the rest of the fleet"
        for name in differing[:4]
    ]
    return round(score, 3), reasons


def detect(features: FeatureVector, baseline: FleetBaseline,
           ja3: str | None = None, ja3s: str | None = None,
           model: object | None = None) -> AnomalyResult:
    """Score one session for unusualness. Deliverable D17.

    `model` is a fitted IsolationForest when one is available; without it the
    peer-deviation path runs and the result says which backend produced it.
    """
    reasons: list[str] = []

    ja3_rarity = baseline.rarity(ja3)
    ja3s_rarity = baseline.rarity(ja3s, server_side=True)
    if ja3_rarity >= 0.95 and baseline.session_count >= 5:
        reasons.append(
            f"client TLS fingerprint seen once in {baseline.session_count} sessions")
    if ja3s_rarity >= 0.95 and baseline.session_count >= 5:
        reasons.append(
            f"server TLS fingerprint seen once in {baseline.session_count} sessions")

    if model is not None:
        try:
            # decision_function is negative for outliers; map to 0..1 where
            # higher means more unusual.
            raw = float(model.decision_function([features.as_row()])[0])  # type: ignore[union-attr]
            score = max(0.0, min(1.0, 0.5 - raw))
            _, peer_reasons = peer_deviation(features, baseline)
            reasons.extend(peer_reasons[:2])
            return AnomalyResult(round(score, 3), score > 0.6, reasons, "isolation_forest")
        except Exception:  # noqa: BLE001 - degrade rather than fail the run
            pass

    peer_score, peer_reasons = peer_deviation(features, baseline)
    reasons.extend(peer_reasons)
    fingerprint_signal = max(ja3_rarity, ja3s_rarity)
    # Weighted so a unique fingerprint alone is suggestive but not conclusive.
    score = round(min(1.0, 0.65 * peer_score + 0.35 * fingerprint_signal), 3)
    return AnomalyResult(score, score > 0.6, reasons, "peer_deviation")
