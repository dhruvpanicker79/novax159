"""Tests for the platform layer: jobs, dispositions, audit, snapshots, SIEM.

These cover the boxes in the user-flow diagram that carry *state* rather than
facts — everything the analysis pipeline does not.

Run:  python tests/test_platform.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "testbed"))

from schema import Report, Severity  # noqa: E402
from schema.platform import (  # noqa: E402
    AuditAction,
    DispositionState,
    JobState,
    PostureSnapshot,
)
from securemailscope import siem  # noqa: E402
from securemailscope.store import Store, finding_key  # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="sms-platform-"))
_CACHE: dict = {}


def store() -> Store:
    return Store(_TMP / f"s{len(list(_TMP.glob('*.db')))}.db")


def report() -> Report:
    if "r" not in _CACHE:
        _CACHE["r"] = Report.from_json(
            (ROOT / "fixtures" / "report.sample.json").read_text(encoding="utf-8"))
    return _CACHE["r"]


# --------------------------------------------------------------------------- #
# Jobs — QUEUE FOR INGESTION / ABORT-ERROR LOG
# --------------------------------------------------------------------------- #


def test_job_starts_queued_and_is_audited():
    s = store()
    job = s.create_job("capture.pcap", 4096, "asha")
    assert job.state is JobState.QUEUED
    events = s.audit_events()
    assert events[0].action is AuditAction.JOB_SUBMITTED
    assert events[0].actor == "asha"


def test_job_round_trips_through_the_store():
    s = store()
    job = s.create_job("c.pcap", 10, "a")
    job.state = JobState.RUNNING
    job.current_stage = "S4 tls handshake"
    job.progress = 0.6
    s.update_job(job)

    reloaded = s.get_job(job.job_id)
    assert reloaded.state is JobState.RUNNING
    assert reloaded.progress == 0.6
    assert reloaded.current_stage == "S4 tls handshake"


def test_rejected_is_distinct_from_failed():
    """Rejected means we refused the input; failed means we broke. Conflating
    them hides our own bugs behind 'bad file'."""
    assert JobState.REJECTED.is_terminal and JobState.FAILED.is_terminal
    assert not JobState.RUNNING.is_terminal
    s = store()
    job = s.create_job("notacapture.txt", 12, "a")
    job.state = JobState.REJECTED
    job.reject_reason = "does not look like a capture file"
    s.update_job(job)
    assert s.get_job(job.job_id).reject_reason


# --------------------------------------------------------------------------- #
# Dispositions — TRIAGE ALERT / INCIDENT CLOSED
# --------------------------------------------------------------------------- #


def test_untouched_finding_reads_as_new():
    """A missing row is not a missing record - it means nobody has looked."""
    assert store().get_disposition("X@h:993").state is DispositionState.NEW


def test_triage_flow():
    s = store()
    key = "TLS-WEAK-CIPHER-RC4@mail-06:993"
    s.set_disposition(key, DispositionState.ACKNOWLEDGED, "asha")
    s.set_disposition(key, DispositionState.IN_PROGRESS, "asha")
    final = s.set_disposition(key, DispositionState.RESOLVED, "asha", note="cipher list fixed")
    assert final.state is DispositionState.RESOLVED
    assert s.get_disposition(key).note == "cipher list fixed"


def test_illegal_transition_is_refused():
    """Straight from new to resolved would mean nobody looked."""
    s = store()
    key = "R@h:1"
    try:
        s.set_disposition(key, DispositionState.RESOLVED, "a")
    except ValueError as exc:
        assert "cannot move" in str(exc)
    else:
        raise AssertionError("should have refused new -> resolved")


def test_accepting_risk_requires_a_justification():
    """An unexplained acceptance is indistinguishable from an unread alert."""
    s = store()
    key = "R@h:2"
    s.set_disposition(key, DispositionState.ACKNOWLEDGED, "a")
    try:
        s.set_disposition(key, DispositionState.ACCEPTED_RISK, "a")
    except ValueError as exc:
        assert "justification" in str(exc)
    else:
        raise AssertionError("should have required a justification")

    ok = s.set_disposition(key, DispositionState.ACCEPTED_RISK, "a",
                           justification="legacy scanner, retires in March")
    assert ok.state is DispositionState.ACCEPTED_RISK


def test_false_positive_is_reachable_immediately():
    """An analyst who spots a false positive should not have to acknowledge it
    first - that is friction on the path we most want used."""
    s = store()
    d = s.set_disposition("R@h:3", DispositionState.FALSE_POSITIVE, "a")
    assert d.state is DispositionState.FALSE_POSITIVE


def test_terminal_dispositions_can_be_reopened():
    s = store()
    key = "R@h:4"
    s.set_disposition(key, DispositionState.FALSE_POSITIVE, "a")
    reopened = s.set_disposition(key, DispositionState.ACKNOWLEDGED, "b")
    assert reopened.state is DispositionState.ACKNOWLEDGED


def test_disposition_changes_are_audited_with_before_and_after():
    s = store()
    key = "R@h:5"
    s.set_disposition(key, DispositionState.ACKNOWLEDGED, "asha")
    event = s.audit_events()[0]
    assert event.action is AuditAction.DISPOSITION_CHANGED
    assert event.before == "new" and event.after == "acknowledged"


def test_finding_key_is_stable_across_runs():
    """Keyed on rule+host+port, not a per-run id: a decision must survive
    re-analysing the same infrastructure."""
    assert finding_key("CERT-EXPIRED", "mail-01", 993) == "CERT-EXPIRED@mail-01:993"
    assert finding_key("R", None, None) == "R@unknown:0"


def test_analyst_decisions_become_training_signal():
    """The feedback loop: false positives and resolutions are labels."""
    s = store()
    s.set_disposition("A@h:1", DispositionState.FALSE_POSITIVE, "a")
    s.set_disposition("B@h:2", DispositionState.ACKNOWLEDGED, "a")
    signal = dict(s.training_signal())
    assert signal.get("A@h:1") == "false_positive"
    assert "B@h:2" not in signal, "an acknowledgement is not yet a label"


# --------------------------------------------------------------------------- #
# Audit — LOG AUDIT DATA
# --------------------------------------------------------------------------- #


def test_audit_is_append_only_and_ordered_newest_first():
    s = store()
    for i in range(5):
        s.record("a", AuditAction.REPORT_EXPORTED, "report", f"r{i}")
    events = s.audit_events()
    assert len(events) >= 5
    assert events[0].object_id == "r4"
    assert [e.event_id for e in events] == sorted(
        (e.event_id for e in events), reverse=True)


# --------------------------------------------------------------------------- #
# Snapshots — REPORT ARCHIVED / POSTURE FINALIZED
# --------------------------------------------------------------------------- #


def test_snapshot_finalisation_is_one_way_and_audited():
    s = store()
    snap = s.save_snapshot(PostureSnapshot(
        job_id="j1", fleet_score=56.2, fleet_grade="D",
        host_count=9, session_count=13, compliance={"RFC 8996": "fail"}))
    assert not snap.is_final

    final = s.finalise_snapshot(snap.snapshot_id, "asha")
    assert final.is_final and final.finalised_by == "asha"
    assert s.audit_events()[0].action is AuditAction.POSTURE_FINALISED

    stamp = final.finalised_at
    again = s.finalise_snapshot(snap.snapshot_id, "someone-else")
    assert again.finalised_at == stamp, "finalisation must not be overwritten"


def test_two_snapshots_support_a_drift_diff():
    """USP-10 falls out of the archive for free."""
    s = store()
    a = s.save_snapshot(PostureSnapshot(job_id="j1", fleet_score=82.0, fleet_grade="B"))
    b = s.save_snapshot(PostureSnapshot(job_id="j2", fleet_score=56.2, fleet_grade="D"))
    assert len(s.list_snapshots()) == 2
    assert abs((a.fleet_score - b.fleet_score) - 25.8) < 1e-9


# --------------------------------------------------------------------------- #
# SIEM export
# --------------------------------------------------------------------------- #


def test_cef_header_is_well_formed():
    finding = report().prioritised_findings[0]
    line = siem.to_cef(finding, "abc123")
    head = line.split("|")
    assert head[0] == "CEF:0"
    assert head[1] == "SecureMailScope"
    assert 0 <= int(head[6]) <= 10, "CEF severity is 0-10"


def test_cef_escapes_pipes_in_the_header():
    """An unescaped pipe in a rule title would shift every field right."""
    from schema import Finding, FindingCategory
    f = Finding(rule_id="A|B", title="weak | cipher", category=FindingCategory.CIPHER,
                base_severity=Severity.HIGH, severity=Severity.HIGH)
    head = siem.to_cef(f).split("|")
    assert head[4] == "A\\", "the pipe was escaped, not treated as a separator"
    assert len(head) >= 8


def test_ecs_is_valid_json_with_required_fields():
    doc = siem.to_ecs(report().prioritised_findings[0], "abc123")
    json.dumps(doc)
    assert "@timestamp" in doc
    assert doc["event"]["kind"] == "alert"
    assert 0 <= doc["event"]["severity"] <= 100


def test_export_filters_by_severity_floor():
    """Forwarding every informational finding is how a SIEM feed gets muted."""
    everything = siem.export(report(), "cef", Severity.INFO).splitlines()
    serious = siem.export(report(), "cef", Severity.HIGH).splitlines()
    assert len(serious) < len(everything)
    assert all("|7|" in l or "|9|" in l for l in serious)


def test_export_carries_evidence_for_verification():
    """A SIEM alert nobody can check against the capture is just noise."""
    line = siem.export(report(), "cef", Severity.CRITICAL).splitlines()[0]
    assert "firstFrame" in line and "streamId" in line


def test_unknown_format_is_refused():
    try:
        siem.export(report(), "xml")
    except ValueError as exc:
        assert "xml" in str(exc)
    else:
        raise AssertionError("should have refused an unknown format")


# --------------------------------------------------------------------------- #
# End to end through the HTTP API
# --------------------------------------------------------------------------- #


def _client():
    from securemailscope.api import create_app
    app = create_app(_TMP / "api.db")
    app.config["TESTING"] = True
    return app.test_client()


def test_api_rejects_a_non_capture_with_a_reason():
    """The ABORT/ERROR LOG box, end to end."""
    import io
    client = _client()
    resp = client.post("/api/jobs", data={"file": (io.BytesIO(b"not a pcap"), "x.txt")},
                       content_type="multipart/form-data")
    assert resp.status_code == 202
    job_id = resp.get_json()["job_id"]

    for _ in range(50):
        state = client.get(f"/api/jobs/{job_id}").get_json()
        if state["state"] in ("rejected", "failed", "completed"):
            break
        time.sleep(0.1)
    assert state["state"] == "rejected", state
    assert state["reject_reason"]


def test_api_analyses_a_sample_end_to_end():
    """Upload -> queue -> run -> report -> SIEM, the whole spine."""
    sample = ROOT / "testbed" / "out" / "fleet.pcap"
    if not sample.exists():
        import synth
        synth.build_all(ROOT / "testbed" / "out")

    client = _client()
    resp = client.post("/api/samples/fleet.pcap/analyse")
    assert resp.status_code == 202
    job_id = resp.get_json()["job_id"]

    for _ in range(300):
        state = client.get(f"/api/jobs/{job_id}").get_json()
        if state["state"] in ("completed", "failed", "rejected"):
            break
        time.sleep(0.1)
    assert state["state"] == "completed", state
    assert state["session_count"] > 0 and state["finding_count"] > 0

    assert client.get(f"/api/reports/{job_id}").get_json()["sessions"]
    assert b"<!doctype html>" in client.get(f"/api/reports/{job_id}/html").data[:40].lower()

    cef = client.get(f"/api/reports/{job_id}/siem?fmt=cef").get_data(as_text=True)
    assert cef.startswith("CEF:0|SecureMailScope")

    # The run archived a posture snapshot.
    assert client.get("/api/snapshots").get_json()

    # And every step of it is in the audit log.
    actions = {e["action"] for e in client.get("/api/audit").get_json()}
    assert "job.submitted" in actions and "job.completed" in actions


def test_api_disposition_refuses_an_illegal_transition():
    client = _client()
    resp = client.post("/api/findings/R@h:9/disposition", json={"state": "resolved"})
    assert resp.status_code == 409, "well-formed request, refused by the state machine"


def test_api_samples_endpoint_backs_the_demo():
    """A live upload failing in front of judges is only recoverable if a
    pre-loaded capture is one click away."""
    assert "fleet.pcap" in _client().get("/api/samples").get_json()


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
