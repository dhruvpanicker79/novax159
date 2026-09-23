"""S8 layer 1 - risk scoring with explanations. Deliverable D16, USP-04.

Two backends behind one interface:

    "gradient_boosting"  the trained scikit-learn model, explained with SHAP
    "rule_baseline"      a deterministic scorer derived from the rule pack

The baseline is not a toy. It exists for three reasons:

    1. The demo cannot die because a pickle is missing or a library failed to
       install. Same reasoning as the LLM fallback in `llm/`.
    2. The whole pipeline runs end to end today, with zero dependencies, which
       is how the rest of the team stays unblocked.
    3. It is the honest yardstick for the metrics slide. "Our model beats the
       rule-derived baseline by X" is a real claim; "our model scored 0.98"
       against no baseline is not.

Both backends return the same `SessionAssessment` shape, so S9, the report
layer and the dashboard never care which one ran.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

from schema import Finding, SessionAssessment, Severity, ShapContribution

from ..rules.pack import RuleContext, evaluate

# --------------------------------------------------------------------------- #
# Rule-derived baseline
# --------------------------------------------------------------------------- #

#: Independent "probability of badness" contributed by one finding at each
#: severity. Combined with a noisy-OR, so several medium findings accumulate
#: into real risk without any single one saturating the score.
#:
#: These are derived from the severity scale rather than hand-tuned per rule,
#: which keeps the baseline explainable: a judge can follow the arithmetic.
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.01,
    Severity.LOW: 0.05,
    Severity.MEDIUM: 0.18,
    Severity.HIGH: 0.45,
    Severity.CRITICAL: 0.80,
}


def _noisy_or(weights: list[float]) -> float:
    """P(at least one) for independent contributions. Saturates gracefully."""
    survival = 1.0
    for w in weights:
        survival *= (1.0 - min(max(w, 0.0), 0.999))
    return 1.0 - survival


def baseline_score(findings: list[Finding]) -> tuple[float, list[ShapContribution]]:
    """Score a session from the findings the rule pack produced.

    The explanation is the finding attribution itself, which is exactly what an
    analyst needs to justify a remediation ticket -- no surrogate model, no
    approximation.
    """
    if not findings:
        return 0.0, []

    weights = [SEVERITY_WEIGHT[f.severity] for f in findings]
    risk = _noisy_or(weights)

    # Attribute the final score back to each finding in proportion to how much
    # it moved the noisy-OR, so the contributions sum to the score.
    total = sum(weights) or 1.0
    contributions = [
        ShapContribution(
            feature=f.rule_id,
            value=1.0,
            contribution=round(risk * (w / total), 4),
            human_readable=f.title,
        )
        for f, w in zip(findings, weights)
    ]
    contributions.sort(key=lambda c: -abs(c.contribution))
    return round(risk, 4), contributions


# --------------------------------------------------------------------------- #
# Model wrapper
# --------------------------------------------------------------------------- #


def _severity_for(risk: float) -> Severity:
    if risk >= 0.85:
        return Severity.CRITICAL
    if risk >= 0.60:
        return Severity.HIGH
    if risk >= 0.35:
        return Severity.MEDIUM
    if risk >= 0.15:
        return Severity.LOW
    return Severity.INFO


@dataclass
class RiskModel:
    """Scores one session. Loads the trained model when it is available."""

    backend: str = "rule_baseline"
    model: object | None = None
    explainer: object | None = None
    feature_names: list[str] | None = None
    version: str = "0.1.0"

    # -- construction -------------------------------------------------------

    @classmethod
    def load(cls, model_dir: str | Path = "models") -> RiskModel:
        """Load the trained classifier, or fall back to the baseline.

        Never raises: a missing model or a blocked import degrades to the
        baseline and says so in `backend`, which the UI displays. Failing
        loudly here would take the demo down; failing visibly does not.
        """
        path = Path(model_dir) / "risk_classifier.joblib"
        if not path.exists():
            return cls(backend="rule_baseline")
        try:
            import joblib  # noqa: PLC0415 - optional dependency by design

            bundle = joblib.load(path)
            return cls(
                backend="gradient_boosting",
                model=bundle["model"],
                explainer=bundle.get("explainer"),
                feature_names=bundle.get("feature_names"),
                version=bundle.get("version", "0.1.0"),
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[risk] trained model unavailable ({type(exc).__name__}); "
                  f"using the rule-derived baseline")
            return cls(backend="rule_baseline")

    # -- scoring ------------------------------------------------------------

    def assess(self, ctx: RuleContext,
               findings: list[Finding] | None = None) -> SessionAssessment:
        """Produce the D16/D18 assessment for one session."""
        findings = evaluate(ctx) if findings is None else findings

        if self.backend == "gradient_boosting" and self.model is not None:
            risk, contributions = self._model_score(ctx, findings)
        else:
            risk, contributions = baseline_score(findings)

        return SessionAssessment(
            risk_score=risk,
            risk_label=_severity_for(risk),
            shap_contributions=contributions[:8],
            exploitability=self._exploitability(findings),
            blast_radius=self._blast_radius(ctx),
            model_version=f"{self.backend}-{self.version}",
        )

    def _model_score(self, ctx: RuleContext,
                     findings: list[Finding]) -> tuple[float, list[ShapContribution]]:
        """Trained-model path. Expected-severity over the predicted classes."""
        row = [ctx.features.as_row()]
        proba = self.model.predict_proba(row)[0]  # type: ignore[union-attr]
        classes = list(self.model.classes_)       # type: ignore[union-attr]
        # Classes are severity ranks 0-4; expected rank normalised to 0-1 gives
        # a calibrated continuous score rather than a hard class.
        risk = sum(p * (int(c) / 4.0) for p, c in zip(proba, classes))

        contributions = self._shap_contributions(row)
        if not contributions:
            _, contributions = baseline_score(findings)
        return round(float(risk), 4), contributions

    def _shap_contributions(self, row: list[list[float]]) -> list[ShapContribution]:
        """Per-feature attribution for this prediction. USP-04's visible artifact."""
        if self.explainer is None or not self.feature_names:
            return []
        try:
            values = self.explainer.shap_values(row)  # type: ignore[union-attr]
            # Multiclass explainers return a list per class; collapse by taking
            # the signed mean so one bar per feature reaches the waterfall.
            if isinstance(values, list):
                merged = [
                    sum(v[0][i] for v in values) / len(values)
                    for i in range(len(self.feature_names))
                ]
            else:
                merged = list(values[0])
            out = [
                ShapContribution(
                    feature=name,
                    value=float(row[0][i]),
                    contribution=round(float(merged[i]), 4),
                    human_readable=humanise(name, row[0][i]),
                )
                for i, name in enumerate(self.feature_names)
                if abs(merged[i]) > 1e-4
            ]
            out.sort(key=lambda c: -abs(c.contribution))
            return out
        except Exception:  # noqa: BLE001
            return []

    # -- prioritisation inputs (D18 is not D16) -----------------------------

    @staticmethod
    def _exploitability(findings: list[Finding]) -> float:
        """How practical is an attack, given what we found?

        Attack evidence means it is not hypothetical, so it dominates. Named
        attacks raise it; a purely forward-looking finding does not.
        """
        if not findings:
            return 0.0
        score = 0.0
        for f in findings:
            if f.category.value == "attack_evidence":
                score = max(score, 1.0)
            elif f.related_attacks:
                score = max(score, 0.35 + 0.15 * min(len(f.related_attacks), 3))
            else:
                score = max(score, 0.2)
        return round(min(score, 1.0), 3)

    @staticmethod
    def _blast_radius(ctx: RuleContext) -> float:
        """How much damage does a compromise here do?

        Credential-bearing ports score highest: a password recovered there
        unlocks an account, not just one message.
        """
        f = ctx.features
        if f.credentials_in_cleartext:
            return 1.0
        if f.port_role_is_submission or f.port_role_is_access:
            return 0.85
        if f.port_role_is_relay:
            return 0.4
        return 0.5


# --------------------------------------------------------------------------- #
# Feature names in English, for the waterfall labels
# --------------------------------------------------------------------------- #

_LABELS: dict[str, tuple[str, str]] = {
    "tls_version_num": ("Modern TLS version", "Old TLS version"),
    "is_deprecated_version": ("Version not deprecated", "Deprecated TLS version"),
    "cipher_is_rc4": ("", "RC4 cipher suite negotiated"),
    "cipher_is_3des": ("", "3DES cipher suite negotiated"),
    "cipher_is_cbc": ("", "Non-AEAD CBC cipher suite"),
    "cipher_is_aead": ("AEAD cipher suite", ""),
    "cipher_is_export": ("", "Export-grade cipher suite"),
    "cipher_is_null_or_anon": ("", "NULL or anonymous cipher suite"),
    "has_forward_secrecy": ("Forward secrecy present", "No forward secrecy"),
    "pq_hybrid_offered": ("Hybrid post-quantum group offered", "No post-quantum group offered"),
    "cert_is_expired": ("Certificate within validity", "Certificate has expired"),
    "cert_is_self_signed": ("", "Self-signed certificate"),
    "cert_key_bits": ("Adequate certificate key size", "Short certificate key"),
    "cert_sig_is_weak": ("", "Weak certificate signature algorithm"),
    "cert_chain_complete": ("Complete certificate chain", "Incomplete certificate chain"),
    "cert_hostname_match": ("Hostname matches certificate", "Hostname mismatch"),
    "cert_opaque_tls13": ("", "Certificate encrypted (TLS 1.3)"),
    "credentials_in_cleartext": ("", "Credentials sent without encryption"),
    "starttls_stripped_suspected": ("", "STARTTLS capability stripped in transit"),
    "starttls_completed": ("STARTTLS upgrade completed", "STARTTLS upgrade did not complete"),
    "auth_before_tls": ("", "Plaintext AUTH offered before TLS"),
    "downgrade_sentinel_present": ("", "TLS downgrade sentinel present"),
    "cipher_intersection_anomaly": ("", "Weaker suite than both parties supported"),
    "certificate_substitution": ("", "Server presented differing certificates"),
    "tls_mode_is_cleartext": ("", "Session never encrypted"),
    "port_role_is_relay": ("MTA relay: opportunistic TLS per RFC 7435", ""),
    "port_role_is_submission": ("", "Submission port carries credentials"),
    "port_role_is_access": ("", "Mail access port carries credentials"),
    "renegotiation_info_present": ("Secure renegotiation supported", "Secure renegotiation absent"),
    "compression_enabled": ("", "TLS compression enabled"),
    "sni_present": ("SNI sent", "No SNI sent"),
}


def humanise(feature: str, value: float) -> str:
    """Turn a feature name and value into a phrase an analyst can read.

    A waterfall labelled `cert_sig_is_weak = 1.0` explains nothing to the
    person who has to act on it.
    """
    good, bad = _LABELS.get(feature, ("", ""))
    if feature == "tls_version_num":
        return f"TLS {value:g} negotiated" if value > 0 else "No TLS negotiated"
    if feature in ("cert_key_bits", "kex_group_bits") and value:
        return f"{feature.replace('_', ' ')}: {int(value)}"
    if feature == "cert_days_to_expiry":
        days = int(value)
        return (f"Certificate expired {abs(days)} days ago" if days < 0
                else f"Certificate expires in {days} days")
    phrase = bad if value else good
    return phrase or feature.replace("_", " ")
