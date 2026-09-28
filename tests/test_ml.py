"""Tests for the rule pack (S6) and the AI layer (S8).

Everything here runs with zero dependencies, which is the point of ADR-0009 and
of the baseline scorer: the analysis chain is testable before anyone has a
working scikit-learn.

Run:  python tests/test_ml.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from schema import (  # noqa: E402
    FeatureVector,
    Finding,
    FindingCategory,
    MailSession,
    PortRole,
    SessionAssessment,
    Severity,
)
from securemailscope.ml import anomaly, corpus, priority  # noqa: E402
from securemailscope.ml.classifier import RiskModel, baseline_score, humanise  # noqa: E402
from securemailscope.rules import pack  # noqa: E402


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def healthy() -> FeatureVector:
    return FeatureVector(
        tls_version_num=1.3, cipher_strength_bits=256, cipher_is_aead=True,
        kex_is_ephemeral=True, has_forward_secrecy=True, kex_group_bits=256,
        pq_hybrid_offered=True, pq_hybrid_negotiated=True,
        cert_present=True, cert_days_to_expiry=90, cert_key_bits=256,
        cert_chain_length=2, cert_chain_complete=True, cert_hostname_match=True,
        port_role_is_access=True, tls_mode_is_implicit=True,
        sni_present=True, renegotiation_info_present=True,
    )


def terrible() -> FeatureVector:
    return FeatureVector(
        tls_version_num=1.0, is_deprecated_version=True,
        cipher_strength_bits=128, cipher_is_rc4=True, cipher_is_cbc=True,
        kex_is_ephemeral=False, has_forward_secrecy=False,
        cert_present=True, cert_is_expired=True, cert_is_self_signed=True,
        cert_days_to_expiry=-47, cert_key_is_rsa=True, cert_key_bits=1024,
        cert_sig_is_weak=True, cert_chain_complete=False, cert_hostname_match=False,
        port_role_is_access=True, tls_mode_is_implicit=True, sni_present=True,
    )


def ctx_for(f: FeatureVector, port: int = 993,
            role: PortRole = PortRole.MAIL_ACCESS) -> pack.RuleContext:
    return pack.RuleContext(f, host="mail-test", port=port, port_role=role)


# --------------------------------------------------------------------------- #
# Rule pack
# --------------------------------------------------------------------------- #


def test_healthy_session_produces_no_findings():
    assert pack.evaluate(ctx_for(healthy())) == []


def test_terrible_session_fires_many_rules():
    findings = pack.evaluate(ctx_for(terrible()))
    ids = {f.rule_id for f in findings}
    for expected in ("TLS-DEPRECATED-VERSION", "TLS-WEAK-CIPHER-RC4",
                     "TLS-NO-FORWARD-SECRECY", "CERT-EXPIRED-SELF-SIGNED",
                     "CERT-WEAK-KEY", "CERT-WEAK-SIGNATURE"):
        assert expected in ids, expected


def test_every_rule_carries_standards_and_remediation():
    """USP-08 and objective O02 are free only if the fields are filled in."""
    for rule in pack.REGISTRY:
        assert rule.standards, f"{rule.rule_id} has no standards citation"
        assert rule.remediation is not None, f"{rule.rule_id} has no remediation"
        assert rule.remediation.summary, f"{rule.rule_id} remediation has no summary"
        assert rule.description, f"{rule.rule_id} has no description"


def test_rule_ids_are_unique():
    ids = [r.rule_id for r in pack.REGISTRY]
    assert len(ids) == len(set(ids))


def test_oracle_label_is_worst_severity():
    ctx = ctx_for(terrible())
    findings = pack.evaluate(ctx)
    assert pack.oracle_label(ctx).rank == max(f.severity.rank for f in findings)


def test_risk_target_is_normalised():
    assert pack.risk_target(ctx_for(healthy())) == 0.0
    assert pack.risk_target(ctx_for(terrible())) == 1.0


def test_pq_rule_does_not_fire_on_cleartext():
    """A cleartext session has no ClientHello, so it has no groups to offer."""
    f = FeatureVector(tls_mode_is_cleartext=True, port_role_is_relay=True)
    ids = {x.rule_id for x in pack.evaluate(ctx_for(f, 25, PortRole.MTA_RELAY))}
    assert "PQ-NOT-READY" not in ids


def test_tls13_opaque_certificate_is_not_a_hostname_mismatch():
    """Regression guard: TLS 1.3 encrypts the Certificate message.

    Reporting a hostname mismatch when we simply cannot see the certificate
    would be a false positive on the most secure sessions in the capture.
    """
    f = FeatureVector(
        tls_version_num=1.3, cipher_is_aead=True, cipher_strength_bits=256,
        kex_is_ephemeral=True, has_forward_secrecy=True, kex_group_bits=256,
        pq_hybrid_offered=True, cert_present=False, cert_opaque_tls13=True,
        sni_present=True, renegotiation_info_present=True,
        port_role_is_access=True, tls_mode_is_implicit=True,
    )
    ids = {x.rule_id for x in pack.evaluate(ctx_for(f))}
    assert "CERT-HOSTNAME-MISMATCH" not in ids
    assert not any(i.startswith("CERT-") for i in ids), ids


def test_relay_cleartext_is_not_critical():
    """USP-01 negative control. A tool that screams here gets ignored."""
    f = FeatureVector(tls_mode_is_cleartext=True, port_role_is_relay=True)
    findings = pack.evaluate(ctx_for(f, 25, PortRole.MTA_RELAY))
    assert findings, "should still report something"
    assert max(x.severity.rank for x in findings) <= Severity.LOW.rank


def test_credentials_in_cleartext_is_always_critical():
    f = FeatureVector(tls_mode_is_cleartext=True, credentials_in_cleartext=True,
                      auth_before_tls=True, port_role_is_submission=True)
    findings = pack.evaluate(ctx_for(f, 587, PortRole.SUBMISSION))
    creds = next(x for x in findings if x.rule_id == "ATTACK-CLEARTEXT-CREDENTIALS")
    assert creds.severity is Severity.CRITICAL


def test_compliance_excludes_context_only_citations():
    """RFC 7435 justifies the relay downgrade; it is never 'failed'."""
    report = pack.compliance_report(pack.evaluate(ctx_for(terrible())))
    assert report["RFC 7435"] == "pass"
    assert report["RFC 8996"] == "fail"


# --------------------------------------------------------------------------- #
# Corpus
# --------------------------------------------------------------------------- #


def test_corpus_is_deterministic():
    a = corpus.generate(200, seed=7)
    b = corpus.generate(200, seed=7)
    assert [s.label for s in a] == [s.label for s in b]


def test_corpus_covers_every_severity():
    labels = {s.label for s in corpus.generate(1500, seed=1)}
    assert labels == set(Severity)


def test_corpus_is_not_mostly_catastrophic():
    """A corpus that is half critical teaches the model that critical is normal."""
    samples = corpus.generate(2000, seed=2)
    critical = sum(1 for s in samples if s.label is Severity.CRITICAL)
    assert 0.02 < critical / len(samples) < 0.30, critical / len(samples)


def test_corpus_has_no_impossible_combinations():
    """Cleartext sessions must not carry handshake attributes."""
    for s in corpus.generate(2000, seed=3):
        f = s.features
        if f.tls_mode_is_cleartext:
            assert f.tls_version_num == 0.0, s.archetype
            assert not f.cipher_is_aead
            assert not f.has_forward_secrecy
            assert not f.cert_present
        if f.tls_version_num >= 1.3:
            assert f.kex_is_ephemeral, "TLS 1.3 is always ephemeral"
            assert f.has_forward_secrecy


def test_corpus_rows_are_numeric_and_aligned():
    s = corpus.generate(10, seed=4)[0]
    assert len(s.features.as_row()) == len(FeatureVector.field_names())


# --------------------------------------------------------------------------- #
# Baseline scorer (D16 without any dependency)
# --------------------------------------------------------------------------- #


def test_baseline_orders_sessions_sensibly():
    good = baseline_score(pack.evaluate(ctx_for(healthy())))[0]
    bad = baseline_score(pack.evaluate(ctx_for(terrible())))[0]
    assert good == 0.0
    assert bad > 0.9
    assert good < bad


def test_baseline_contributions_sum_to_the_score():
    risk, contributions = baseline_score(pack.evaluate(ctx_for(terrible())))
    assert abs(sum(c.contribution for c in contributions) - risk) < 0.01


def test_baseline_contributions_are_readable():
    _, contributions = baseline_score(pack.evaluate(ctx_for(terrible())))
    assert contributions
    for c in contributions:
        assert c.human_readable
        assert not c.human_readable.islower(), c.human_readable


def test_model_falls_back_cleanly_when_untrained():
    model = RiskModel.load("models-that-do-not-exist")
    assert model.backend == "rule_baseline"
    assessment = model.assess(ctx_for(terrible()))
    assert isinstance(assessment, SessionAssessment)
    assert assessment.risk_score > 0.9
    assert assessment.risk_label is Severity.CRITICAL
    assert assessment.shap_contributions


def test_blast_radius_ranks_credential_ports_above_relay():
    model = RiskModel.load("models-that-do-not-exist")
    access = model.assess(ctx_for(terrible(), 993, PortRole.MAIL_ACCESS))
    relay_f = terrible()
    relay_f.port_role_is_access = False
    relay_f.port_role_is_relay = True
    relay = model.assess(ctx_for(relay_f, 25, PortRole.MTA_RELAY))
    assert access.blast_radius > relay.blast_radius


def test_humanise_produces_sentences_not_field_names():
    assert humanise("cipher_is_rc4", 1.0) == "RC4 cipher suite negotiated"
    assert "expired 47 days ago" in humanise("cert_days_to_expiry", -47)
    assert "TLS 1.3" in humanise("tls_version_num", 1.3)


# --------------------------------------------------------------------------- #
# Anomaly detection (D17)
# --------------------------------------------------------------------------- #


def _fleet(n: int = 20) -> list[tuple[FeatureVector, str, str]]:
    return [(healthy(), "aaaa", "bbbb") for _ in range(n)]


def test_unique_fingerprint_is_rare():
    base = anomaly.FleetBaseline.build(_fleet() + [(healthy(), "zzzz", "yyyy")])
    assert base.rarity("zzzz") == 1.0
    assert base.rarity("aaaa") < 0.2


def test_odd_session_out_scores_as_anomalous():
    fleet = _fleet(30)
    odd = terrible()
    base = anomaly.FleetBaseline.build(fleet + [(odd, "zzzz", "yyyy")])
    result = anomaly.detect(odd, base, ja3="zzzz", ja3s="yyyy")
    assert result.is_anomalous
    assert result.reasons
    assert result.backend == "peer_deviation"


def test_conforming_session_is_not_anomalous():
    fleet = _fleet(30)
    base = anomaly.FleetBaseline.build(fleet)
    result = anomaly.detect(healthy(), base, ja3="aaaa", ja3s="bbbb")
    assert not result.is_anomalous
    assert result.score < 0.3


def test_baseline_excludes_contaminated_sessions():
    """The bug this guards against inverts the detector.

    If a majority of the fleet is compromised and every session helps define
    "normal", the attack becomes the norm and the healthy hosts are what look
    anomalous. The more hosts are compromised, the less compromise stands out.
    """
    attacks = [(terrible(), f"bad{i}", f"bads{i}") for i in range(10)]
    good = [(healthy(), f"ok{i}", f"oks{i}") for i in range(4)]
    fleet = attacks + good
    flags = [True] * len(attacks) + [False] * len(good)

    poisoned = anomaly.FleetBaseline.build(fleet)
    cleaned = anomaly.FleetBaseline.build(fleet, contaminated=flags)

    assert cleaned.clean_count == 4
    assert cleaned.contaminated_count == 10
    assert poisoned.contaminated_count == 0

    attack_on_poisoned, _ = anomaly.peer_deviation(terrible(), poisoned)
    attack_on_cleaned, _ = anomaly.peer_deviation(terrible(), cleaned)
    healthy_on_poisoned, _ = anomaly.peer_deviation(healthy(), poisoned)

    # Poisoned: the attack looks normal and the healthy host looks odd.
    assert attack_on_poisoned < healthy_on_poisoned
    # Cleaned: the attack is the outlier again.
    assert attack_on_cleaned > attack_on_poisoned


def test_rarity_still_counts_every_session():
    """Rarity is a property of the observed population, so contaminated
    sessions must stay in its denominator - excluding an attacker's fingerprint
    from its own count would hide exactly what we want to surface."""
    fleet = [(healthy(), "common", "s")] * 9 + [(terrible(), "unique", "s2")]
    base = anomaly.FleetBaseline.build(fleet, contaminated=[False] * 9 + [True])
    assert base.session_count == 10, "all sessions counted for rarity"
    assert base.clean_count == 9
    assert base.rarity("unique") == 1.0


def test_baseline_falls_back_when_nothing_is_clean():
    """A baseline built on one session is worse than none. Use everything and
    record that we did, rather than inventing a normal from noise."""
    fleet = [(terrible(), f"a{i}", f"b{i}") for i in range(6)]
    base = anomaly.FleetBaseline.build(fleet, contaminated=[True] * 6)
    assert base.clean_count == 6, "fell back to the full population"
    assert base.contaminated_count == 0, "and said so"


def test_baseline_needs_enough_sessions_to_judge():
    base = anomaly.FleetBaseline.build(_fleet(2))
    score, reasons = anomaly.peer_deviation(terrible(), base)
    assert score == 0.0 and reasons == []


# --------------------------------------------------------------------------- #
# Prioritisation (D18)
# --------------------------------------------------------------------------- #


def _finding(rule_id: str, severity: Severity, category: FindingCategory,
             host: str, port: int, attacks: tuple[str, ...] = ()) -> Finding:
    return Finding(rule_id=rule_id, title=rule_id, category=category,
                   base_severity=severity, severity=severity,
                   affected_host=host, affected_port=port,
                   related_attacks=list(attacks))


def _session(host: str, port: int, exploitability: float, blast: float) -> MailSession:
    return MailSession(session_id=f"{host}:{port}", server_host=host, server_port=port,
                       assessment=SessionAssessment(exploitability=exploitability,
                                                    blast_radius=blast))


def test_severity_still_leads_the_queue():
    findings = [
        _finding("LOW-ONE", Severity.LOW, FindingCategory.CONFIGURATION, "a", 25),
        _finding("CRIT-ONE", Severity.CRITICAL, FindingCategory.ATTACK_EVIDENCE, "b", 587),
    ]
    sessions = [_session("a", 25, 0.9, 0.9), _session("b", 587, 0.2, 0.2)]
    ordered, _ = priority.prioritise(findings, sessions)
    assert ordered[0].rule_id == "CRIT-ONE"


def test_evidenced_attack_outranks_equal_severity_config_issue():
    """Within a severity band, what is already happening comes first."""
    findings = [
        _finding("CONFIG", Severity.HIGH, FindingCategory.CONFIGURATION, "a", 25),
        _finding("EVIDENCE", Severity.HIGH, FindingCategory.ATTACK_EVIDENCE, "b", 587,
                 ("Credential theft",)),
    ]
    sessions = [_session("a", 25, 0.2, 0.4), _session("b", 587, 1.0, 1.0)]
    ordered, workings = priority.prioritise(findings, sessions)
    assert ordered[0].rule_id == "EVIDENCE"
    assert "evidenced" in workings["EVIDENCE@b:587"].rationale


def test_breadth_promotes_a_fleet_wide_fix():
    findings = [
        _finding("NARROW", Severity.MEDIUM, FindingCategory.CIPHER, "a", 993),
        *[_finding("WIDE", Severity.MEDIUM, FindingCategory.CIPHER, h, 993)
          for h in ("b", "c", "d", "e", "f")],
    ]
    sessions = [_session(h, 993, 0.3, 0.5) for h in "abcdef"]
    ordered, workings = priority.prioritise(findings, sessions)
    assert ordered[0].rule_id == "WIDE"
    assert workings["WIDE@b:993"].affected_hosts == 5


def test_every_finding_gets_a_rationale():
    findings = [_finding("X", Severity.HIGH, FindingCategory.CIPHER, "a", 993)]
    _, workings = priority.prioritise(findings, [_session("a", 993, 0.5, 0.5)])
    assert all(w.rationale for w in workings.values())


def test_remediation_batches_group_by_rule():
    findings = [_finding("WIDE", Severity.HIGH, FindingCategory.CIPHER, h, 993)
                for h in ("a", "b", "c")]
    ordered, _ = priority.prioritise(findings, [_session(h, 993, 0.5, 0.5) for h in "abc"])
    batches = priority.remediation_batches(ordered)
    assert len(batches) == 1
    assert batches[0]["host_count"] == 3


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
