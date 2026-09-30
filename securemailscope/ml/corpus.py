"""S8 - synthetic training corpus. ADR-0003 and ADR-0006.

The corpus is ~10,000 **feature vectors**, not captures. That is the decision
that decouples the ML timeline from the parser timeline: person C can train on
day two whether or not S0-S5 exist yet.

Naive sampling would draw each field independently, which produces nonsense
like "TLS 1.3 with an RC4 cipher and a 1024-bit SHA-1 certificate". A model
trained on that learns a boundary no real server sits near. So we sample an
**archetype** first - the kind of mail server this is - and then draw the
fields conditionally. Weak configurations then correlate the way they do in
reality: the host still running TLS 1.0 is also the host whose certificate
expired and whose key is too short.

Labels come from the rule pack acting as an oracle (ADR-0003), including the
role-aware adjustment, so the classifier learns the shipping policy rather than
a parallel definition that could drift from it.

Pure stdlib - uses `random`, not numpy, so it runs with nothing installed.
"""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from pathlib import Path

from schema import FeatureVector, PortRole, Severity

from ..rules.pack import RuleContext, oracle_label

# --------------------------------------------------------------------------- #
# Archetypes
# --------------------------------------------------------------------------- #

#: name -> relative weight. Roughly models a real mixed estate: most servers
#: are fine, a meaningful tail is not, and outright compromise is rare. The
#: imbalance is deliberate -- a corpus that is 50% catastrophic teaches the
#: model that catastrophe is normal.
ARCHETYPES: dict[str, float] = {
    "modern": 0.30,       # TLS 1.3, AEAD, valid chain, sometimes PQ
    "standard": 0.34,     # TLS 1.2, ECDHE, AEAD, valid chain
    "dated": 0.18,        # TLS 1.2 CBC, RSA 2048, chain quirks
    "legacy": 0.10,       # TLS 1.0/1.1, weak ciphers, old certificates
    "neglected": 0.05,    # expired or self-signed, weak keys, no PFS
    "compromised": 0.03,  # cleartext credentials, stripping, downgrade evidence
}

#: port -> (role, implicit TLS). Weighted towards the ports that actually carry
#: most traffic in an enterprise capture.
PORT_CHOICES: list[tuple[int, PortRole, bool, float]] = [
    (25,  PortRole.MTA_RELAY,   False, 0.26),
    (587, PortRole.SUBMISSION,  False, 0.16),
    (465, PortRole.SUBMISSION,  True,  0.10),
    (143, PortRole.MAIL_ACCESS, False, 0.10),
    (993, PortRole.MAIL_ACCESS, True,  0.26),
    (110, PortRole.MAIL_ACCESS, False, 0.04),
    (995, PortRole.MAIL_ACCESS, True,  0.08),
]


@dataclass
class Sample:
    """One labelled training row."""

    features: FeatureVector
    port: int
    port_role: PortRole
    archetype: str
    label: Severity

    @property
    def target(self) -> float:
        """Continuous 0.0-1.0 risk, for regression or for ranking."""
        return self.label.rank / 4.0


def _weighted(rng: random.Random, options: dict[str, float]) -> str:
    return rng.choices(list(options), weights=list(options.values()), k=1)[0]


def _pick_port(rng: random.Random) -> tuple[int, PortRole, bool]:
    rows = PORT_CHOICES
    port, role, implicit, _ = rng.choices(rows, weights=[r[3] for r in rows], k=1)[0]
    return port, role, implicit


# --------------------------------------------------------------------------- #
# Sampling
# --------------------------------------------------------------------------- #


def sample_features(rng: random.Random, archetype: str,
                    port: int, role: PortRole, implicit: bool) -> FeatureVector:
    """Draw one realistic feature vector for the given archetype."""
    f = FeatureVector()

    # -- how the session reached TLS, if it did ----------------------------
    cleartext = archetype == "compromised" and rng.random() < 0.55
    if archetype == "neglected" and rng.random() < 0.12:
        cleartext = True
    # Opportunistic relay sessions genuinely do fall back to cleartext often.
    if role is PortRole.MTA_RELAY and rng.random() < 0.18:
        cleartext = True

    f.tls_mode_is_implicit = implicit and not cleartext
    f.tls_mode_is_starttls = (not implicit) and not cleartext
    f.tls_mode_is_cleartext = cleartext

    f.port_role_is_relay = role is PortRole.MTA_RELAY
    f.port_role_is_submission = role is PortRole.SUBMISSION
    f.port_role_is_access = role is PortRole.MAIL_ACCESS

    # -- STARTTLS behaviour -------------------------------------------------
    if not implicit:
        f.starttls_advertised = rng.random() < (0.35 if cleartext else 0.99)
        f.starttls_completed = not cleartext
        f.starttls_ehlo_reissued = f.starttls_completed and rng.random() < 0.94
    if cleartext:
        f.starttls_completed = False
        if archetype == "compromised":
            f.starttls_stripped_suspected = rng.random() < 0.45
            if f.starttls_stripped_suspected:
                f.starttls_advertised = False
            f.credentials_in_cleartext = (
                role is not PortRole.MTA_RELAY and rng.random() < 0.8)
            f.auth_before_tls = role is not PortRole.MTA_RELAY

    if cleartext:
        # Nothing below this point applies: there is no handshake to describe.
        f.sni_present = False
        return f

    # -- protocol version ---------------------------------------------------
    version = {
        "modern": lambda: 1.3,
        "standard": lambda: 1.3 if rng.random() < 0.25 else 1.2,
        "dated": lambda: 1.2,
        "legacy": lambda: rng.choice([1.0, 1.1, 1.2]),
        "neglected": lambda: rng.choice([1.0, 1.1, 1.2]),
        "compromised": lambda: rng.choice([0.3, 1.0, 1.0, 1.1]),
    }[archetype]()
    f.tls_version_num = version
    f.is_deprecated_version = version < 1.2

    # -- cipher suite -------------------------------------------------------
    if version >= 1.3:
        f.cipher_is_aead = True
        f.cipher_strength_bits = rng.choice([128, 256, 256])
    elif archetype in ("modern", "standard"):
        f.cipher_is_aead = True
        f.cipher_strength_bits = rng.choice([128, 256])
    elif archetype == "dated":
        f.cipher_is_aead = rng.random() < 0.45
        f.cipher_is_cbc = not f.cipher_is_aead
        f.cipher_strength_bits = rng.choice([128, 256])
    else:
        roll = rng.random()
        if roll < 0.28:
            f.cipher_is_rc4 = True
            f.cipher_strength_bits = 128
        elif roll < 0.48:
            f.cipher_is_3des = True
            f.cipher_is_cbc = True
            f.cipher_strength_bits = 112
        elif roll < 0.54 and archetype == "compromised":
            f.cipher_is_export = True
            f.cipher_strength_bits = rng.choice([40, 56])
        elif roll < 0.58 and archetype == "compromised":
            f.cipher_is_null_or_anon = True
            f.cipher_strength_bits = 0
        else:
            f.cipher_is_cbc = True
            f.cipher_strength_bits = 128

    # -- key exchange and forward secrecy ----------------------------------
    if version >= 1.3:
        f.kex_is_ephemeral = True
        f.kex_group_bits = 256
    else:
        pfs_chance = {"modern": 0.99, "standard": 0.95, "dated": 0.82,
                      "legacy": 0.55, "neglected": 0.45, "compromised": 0.35}[archetype]
        f.kex_is_ephemeral = rng.random() < pfs_chance
        if f.kex_is_ephemeral:
            # Mostly elliptic curves; a minority still use finite-field DH,
            # and some of those groups are too small (Logjam).
            if rng.random() < 0.15:
                f.kex_group_bits = rng.choice([1024, 1024, 2048, 3072])
            else:
                f.kex_group_bits = rng.choice([256, 256, 384])
        else:
            f.kex_group_bits = 2048
        f.kex_is_anon = f.cipher_is_null_or_anon and rng.random() < 0.5
    f.has_forward_secrecy = f.kex_is_ephemeral and not f.kex_is_anon

    # -- post-quantum (USP-05) ---------------------------------------------
    pq_chance = {"modern": 0.22, "standard": 0.04}.get(archetype, 0.0)
    f.pq_hybrid_offered = version >= 1.3 and rng.random() < pq_chance
    f.pq_hybrid_negotiated = f.pq_hybrid_offered and rng.random() < 0.9

    # -- certificate --------------------------------------------------------
    # In TLS 1.3 the Certificate message is encrypted, so a passive observer
    # sees nothing. The corpus has to contain these or the model never learns
    # that an absent certificate at 1.3 is normal rather than alarming.
    f.cert_opaque_tls13 = version >= 1.3 and rng.random() < 0.55
    f.cert_present = not f.cert_opaque_tls13

    if f.cert_present:
        if archetype in ("modern", "standard"):
            f.cert_key_is_rsa = rng.random() < 0.55
            f.cert_key_bits = rng.choice([2048, 3072]) if f.cert_key_is_rsa else 256
            f.cert_days_to_expiry = rng.randint(14, 365)
            f.cert_chain_complete = rng.random() < 0.96
            f.cert_chain_length = rng.choice([2, 2, 3])
            f.cert_hostname_match = rng.random() < 0.98
        elif archetype == "dated":
            f.cert_key_is_rsa = True
            f.cert_key_bits = 2048
            f.cert_days_to_expiry = rng.randint(-5, 300)
            f.cert_chain_complete = rng.random() < 0.85
            f.cert_chain_length = rng.choice([1, 2, 2])
            f.cert_hostname_match = rng.random() < 0.94
            f.cert_sig_is_weak = rng.random() < 0.08
        else:
            f.cert_key_is_rsa = True
            f.cert_key_bits = rng.choice([1024, 1024, 2048])
            f.cert_days_to_expiry = rng.randint(-400, 120)
            f.cert_chain_complete = rng.random() < 0.45
            f.cert_chain_length = rng.choice([1, 1, 2])
            f.cert_hostname_match = rng.random() < 0.65
            f.cert_sig_is_weak = rng.random() < 0.4
            # A legacy server usually has a real certificate that is simply old.
            # Self-signed is the mark of neglect or of something deliberately
            # standing in the path, so keep the rates distinct.
            f.cert_is_self_signed = rng.random() < (
                0.15 if archetype == "legacy" else 0.5)
        f.cert_is_expired = f.cert_days_to_expiry < 0
        if f.cert_is_self_signed:
            f.cert_chain_length = 1
            f.cert_chain_complete = False

    # -- configuration hygiene ---------------------------------------------
    f.sni_present = rng.random() < (0.97 if archetype in ("modern", "standard") else 0.8)
    f.alpn_present = rng.random() < 0.3
    f.renegotiation_info_present = version >= 1.3 or rng.random() < (
        0.98 if archetype in ("modern", "standard", "dated") else 0.6)
    f.compression_enabled = archetype in ("legacy", "neglected", "compromised") \
        and rng.random() < 0.08
    f.session_resumed = rng.random() < 0.25
    f.handshake_alert_count = 0 if rng.random() < 0.93 else rng.randint(1, 3)

    # -- attack evidence ----------------------------------------------------
    if archetype == "compromised":
        f.downgrade_sentinel_present = rng.random() < 0.3
        f.fallback_scsv_present = rng.random() < 0.35
        f.cipher_intersection_anomaly = rng.random() < 0.3
        f.certificate_substitution = rng.random() < 0.15
    else:
        # A small background rate keeps these from being perfectly predictive
        # of the compromised archetype, which would make the model lazy.
        f.downgrade_sentinel_present = rng.random() < 0.01
        f.cipher_intersection_anomaly = rng.random() < 0.015

    # -- fleet-relative, filled properly at S9 ------------------------------
    f.ja3_rarity = round(rng.betavariate(2, 8), 3)
    f.ja3s_rarity = round(rng.betavariate(2, 8), 3)

    return f


def generate(n: int = 10_000, seed: int = 20260923) -> list[Sample]:
    """Build the labelled corpus."""
    rng = random.Random(seed)
    samples: list[Sample] = []
    for _ in range(n):
        archetype = _weighted(rng, ARCHETYPES)
        port, role, implicit = _pick_port(rng)
        features = sample_features(rng, archetype, port, role, implicit)
        ctx = RuleContext(features, host=None, port=port, port_role=role)
        samples.append(Sample(features, port, role, archetype, oracle_label(ctx)))
    return samples


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #


def write_csv(samples: list[Sample], path: str | Path) -> Path:
    """Write the corpus so the model can be trained anywhere, including Colab.

    Keeping the corpus as a CSV means the training step needs neither this
    package nor a PCAP -- useful when the only machine with a working scikit-learn
    is not the machine with the repo on it.
    """
    from ..ml.classifier import baseline_score  # noqa: PLC0415 - avoids a cycle
    from ..rules.pack import evaluate  # noqa: PLC0415

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = FeatureVector.field_names()
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([*columns, "port", "port_role", "archetype",
                         "label", "target", "baseline_risk"])
        for s in samples:
            ctx = RuleContext(s.features, port=s.port, port_role=s.port_role)
            # Precomputed so a training run elsewhere - Colab, a teammate's
            # laptop - can compare the model against the rule-derived baseline
            # without needing this package at all. The CSV is self-sufficient.
            risk, _ = baseline_score(evaluate(ctx))
            writer.writerow([
                *s.features.as_row(), s.port, s.port_role.value,
                s.archetype, s.label.value, s.target, risk,
            ])
    return path


def describe(samples: list[Sample]) -> dict[str, object]:
    """Summary statistics, printed after generation as a sanity check.

    Worth reading every time: if 'critical' is 40% of the corpus, the sampler
    has drifted and the model will learn that catastrophe is routine.
    """
    labels: dict[str, int] = {}
    archetypes: dict[str, int] = {}
    roles: dict[str, int] = {}
    for s in samples:
        labels[s.label.value] = labels.get(s.label.value, 0) + 1
        archetypes[s.archetype] = archetypes.get(s.archetype, 0) + 1
        roles[s.port_role.value] = roles.get(s.port_role.value, 0) + 1
    n = len(samples) or 1
    return {
        "count": len(samples),
        "labels": {k: f"{v} ({v / n:.1%})" for k, v in
                   sorted(labels.items(), key=lambda kv: -kv[1])},
        "archetypes": {k: f"{v / n:.1%}" for k, v in
                       sorted(archetypes.items(), key=lambda kv: -kv[1])},
        "port_roles": {k: f"{v / n:.1%}" for k, v in
                       sorted(roles.items(), key=lambda kv: -kv[1])},
        "mean_target": round(sum(s.target for s in samples) / n, 4),
    }


def main() -> int:
    """`python -m securemailscope.ml.corpus`

    This entry point did not exist, so the documented command imported the
    module, did nothing and exited 0. `run.sh` then reported "training corpus
    generated", the trainer found no corpus, and the launcher announced that
    the *model had lost to the baseline* — a reassuring sentence about a
    completely different failure. A fresh clone therefore came up with no
    trained model and nobody would have known why.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Generate the training corpus.")
    parser.add_argument("--rows", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20260923)
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).resolve().parents[2] / "data" / "corpus.csv")
    args = parser.parse_args()

    samples = generate(args.rows, args.seed)
    path = write_csv(samples, args.out)
    stats = describe(samples)
    print(f"wrote {path}  ({path.stat().st_size / 1024:.0f} KB)")
    print(f"  rows        {stats['count']:,}")
    print(f"  labels      {stats['labels']}")
    print(f"  mean target {stats['mean_target']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
