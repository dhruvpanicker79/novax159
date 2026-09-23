"""Tests for the frozen data contract (ADR-0005).

These are the guard rails on the one thing all six people share. If a test here
fails, someone changed the schema without telling the team.

Run:  python -m pytest -q      (or: python tests/test_contract.py)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from schema import (  # noqa: E402
    Certificate,
    Evidence,
    FeatureVector,
    Finding,
    FindingCategory,
    KeyExchange,
    MailProtocol,
    MailSession,
    PortRole,
    Report,
    Severity,
    TlsVersion,
)
from schema.models import PORT_TABLE  # noqa: E402
from securemailscope.proto import roles  # noqa: E402
from securemailscope.rules import severity as sev  # noqa: E402


# --------------------------------------------------------------------------- #
# Round-tripping
# --------------------------------------------------------------------------- #


def test_session_roundtrips_through_json():
    original = MailSession(
        session_id="t1",
        protocol=MailProtocol.IMAP,
        port_role=PortRole.MAIL_ACCESS,
        server_port=993,
    )
    restored = MailSession.from_json(original.to_json())
    assert restored.protocol is MailProtocol.IMAP
    assert restored.port_role is PortRole.MAIL_ACCESS
    assert restored.server_port == 993


def test_unknown_keys_are_ignored():
    """An older consumer must be able to read a newer report."""
    data = {"session_id": "t2", "protocol": "smtp", "a_field_from_the_future": 42}
    restored = MailSession.from_dict(data)
    assert restored.session_id == "t2"
    assert restored.protocol is MailProtocol.SMTP


def test_nested_objects_survive_roundtrip():
    finding = Finding(
        rule_id="X", category=FindingCategory.CERTIFICATE,
        base_severity=Severity.HIGH, severity=Severity.CRITICAL,
        evidence=Evidence(capture_sha256="ab" * 32, stream_id=3,
                          frame_numbers=[10, 11], byte_range=[0, 40]),
    )
    restored = Finding.from_json(finding.to_json())
    assert restored.evidence.stream_id == 3
    assert restored.evidence.frame_numbers == [10, 11]
    assert restored.severity is Severity.CRITICAL


# --------------------------------------------------------------------------- #
# Enum semantics the rules depend on
# --------------------------------------------------------------------------- #


def test_rfc8996_deprecated_versions():
    for version in (TlsVersion.SSL2, TlsVersion.SSL3, TlsVersion.TLS1_0, TlsVersion.TLS1_1):
        assert version.is_deprecated, version
    for version in (TlsVersion.TLS1_2, TlsVersion.TLS1_3):
        assert not version.is_deprecated, version


def test_version_ordering_is_monotonic():
    ordered = [TlsVersion.SSL3, TlsVersion.TLS1_0, TlsVersion.TLS1_1,
               TlsVersion.TLS1_2, TlsVersion.TLS1_3]
    numbers = [v.numeric for v in ordered]
    assert numbers == sorted(numbers)


def test_forward_secrecy_only_for_ephemeral():
    assert KeyExchange.ECDHE.has_forward_secrecy
    assert KeyExchange.DHE.has_forward_secrecy
    assert KeyExchange.TLS13_EPHEMERAL.has_forward_secrecy
    assert not KeyExchange.RSA.has_forward_secrecy
    assert not KeyExchange.ECDH.has_forward_secrecy


# --------------------------------------------------------------------------- #
# Port roles (USP-01 foundation)
# --------------------------------------------------------------------------- #


def test_all_seven_mail_ports_are_mapped():
    assert set(PORT_TABLE) == {25, 110, 143, 465, 587, 993, 995}


def test_port_25_is_opportunistic_relay():
    protocol, role, implicit = roles.classify_port(25)
    assert protocol is MailProtocol.SMTP
    assert role is PortRole.MTA_RELAY
    assert implicit is False
    assert not roles.requires_validated_certificate(role)
    assert not roles.carries_credentials(role)


def test_implicit_tls_ports_flagged_correctly():
    """The PS dataset guidance names exactly these three."""
    for port in (465, 993, 995):
        assert roles.classify_port(port)[2] is True, port
    for port in (25, 587, 143, 110):
        assert roles.classify_port(port)[2] is False, port


def test_credential_bearing_ports_require_validation():
    for port in (587, 465, 143, 993, 110, 995):
        _, role, _ = roles.classify_port(port)
        assert roles.requires_validated_certificate(role), port
        assert roles.carries_credentials(role), port


def test_nonstandard_smtp_port_assumed_submission():
    assert roles.infer_role_from_protocol(MailProtocol.SMTP, 2587) is PortRole.SUBMISSION


# --------------------------------------------------------------------------- #
# USP-01: the same fact, two verdicts
# --------------------------------------------------------------------------- #


def _cert_finding(role: PortRole, port: int) -> Finding:
    return Finding(
        rule_id="CERT-EXPIRED-SELF-SIGNED",
        category=FindingCategory.CERTIFICATE,
        base_severity=Severity.HIGH,
        port_role=role, affected_port=port,
    )


def test_identical_certificate_fault_scores_differently_by_role():
    """The demo moment, asserted. Same defect, opposite verdicts."""
    relay = sev.adjust(_cert_finding(PortRole.MTA_RELAY, 25))
    access = sev.adjust(_cert_finding(PortRole.MAIL_ACCESS, 993))

    assert relay.base_severity is Severity.HIGH
    assert access.base_severity is Severity.HIGH

    assert relay.severity is Severity.INFO
    assert access.severity is Severity.CRITICAL

    assert "RFC 7435" in (relay.severity_adjustment_reason or "")
    assert "RFC 8314" in (access.severity_adjustment_reason or "")


def test_adjustment_is_always_explained():
    for role in (PortRole.MTA_RELAY, PortRole.SUBMISSION, PortRole.MAIL_ACCESS):
        f = sev.adjust(_cert_finding(role, 0))
        if f.was_adjusted:
            assert f.severity_adjustment_reason, role


def test_broken_crypto_is_never_excused_by_role():
    """RC4 on port 25 is still RC4. Only trust-dependent categories move."""
    for category in sev.NEVER_ADJUSTED:
        for role in PortRole:
            f = Finding(category=category, base_severity=Severity.HIGH, port_role=role)
            adjusted = sev.adjust(f)
            assert adjusted.severity is Severity.HIGH, (category, role)
            assert adjusted.severity_adjustment_reason is None


def test_severity_shift_clamps_at_both_ends():
    low = sev.adjust(Finding(category=FindingCategory.CERTIFICATE,
                             base_severity=Severity.INFO, port_role=PortRole.MTA_RELAY))
    assert low.severity is Severity.INFO
    high = sev.adjust(Finding(category=FindingCategory.CERTIFICATE,
                              base_severity=Severity.CRITICAL,
                              port_role=PortRole.MAIL_ACCESS))
    assert high.severity is Severity.CRITICAL


# --------------------------------------------------------------------------- #
# Feature vector
# --------------------------------------------------------------------------- #


def test_feature_row_matches_field_names():
    fv = FeatureVector()
    assert len(fv.as_row()) == len(FeatureVector.field_names())


def test_feature_row_is_all_numeric():
    fv = FeatureVector(cipher_is_rc4=True, tls_version_num=1.0, cipher_strength_bits=128)
    assert all(isinstance(v, float) for v in fv.as_row())


# --------------------------------------------------------------------------- #
# Certificate maths
# --------------------------------------------------------------------------- #


def test_expired_certificate_reports_negative_days():
    from datetime import datetime, timedelta, timezone
    now = datetime(2026, 9, 23, tzinfo=timezone.utc)
    cert = Certificate(not_after=now - timedelta(days=47))
    assert cert.days_to_expiry(now) == -47


# --------------------------------------------------------------------------- #
# The fixture everyone builds against
# --------------------------------------------------------------------------- #


def test_sample_report_loads():
    path = ROOT / "fixtures" / "report.sample.json"
    assert path.exists(), "run: python scripts/make_fixtures.py"
    report = Report.from_json(path.read_text(encoding="utf-8"))
    assert len(report.sessions) >= 10
    assert report.fleet is not None
    assert report.prioritised_findings


def test_every_fixture_object_carries_evidence():
    """ADR-0004: provenance is born with the data, not bolted on later."""
    path = ROOT / "fixtures" / "report.sample.json"
    report = Report.from_json(path.read_text(encoding="utf-8"))
    for session in report.sessions:
        assert session.evidence.is_populated, session.session_id
        for finding in session.findings:
            assert finding.evidence.is_populated, finding.rule_id


def test_triage_queue_is_ordered_by_severity():
    path = ROOT / "fixtures" / "report.sample.json"
    report = Report.from_json(path.read_text(encoding="utf-8"))
    ranks = [f.severity.rank for f in report.prioritised_findings]
    assert ranks == sorted(ranks, reverse=True)


def test_generated_json_schema_is_current():
    """Regenerate with: python -m schema.jsonschema"""
    from schema.jsonschema import json_schema
    generated = ROOT / "schema" / "generated" / "Report.schema.json"
    assert generated.exists(), "run: python -m schema.jsonschema"
    on_disk = json.loads(generated.read_text(encoding="utf-8"))
    assert on_disk == json_schema(Report), "schema changed but generated files were not refreshed"


if __name__ == "__main__":
    # Lets the tests run without pytest installed, which matters on day one
    # before anyone has set up an environment.
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
