"""Temporal posture drift. USP-10.

The corpus for this is `fleet.pcap` and `fleet_later.pcap` — the same eleven
hosts a fortnight apart, with exactly two changed: `10.20.1.16` was remediated
and `10.20.1.11` was redeployed with a legacy TLS profile. Everything else is
held constant, so a diff that reports anything other than those two is wrong in
a way the test can name.

The property tested hardest is not the diff. It is the **refusal**: two
captures are drift only when they cover the same estate, and comparing
unrelated files produces a number that is arithmetically correct and
operationally meaningless. A confident wrong trend is worse than a blank panel.

    python tests/test_drift.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "testbed"))

from schema import Report  # noqa: E402
from securemailscope.drift import OVERLAP_FLOOR, compare  # noqa: E402
from securemailscope.pipeline import analyse  # noqa: E402

OUT = ROOT / "testbed" / "out"
TRUST = [str(ROOT / "testbed" / "certs" / "_ca.der")]
_CACHE: dict[str, Report] = {}

#: The two hosts synth.py deliberately changes between the pair.
REMEDIATED, REGRESSED = "10.20.1.16", "10.20.1.11"


def _report(name: str) -> Report:
    if name not in _CACHE:
        if not (OUT / name).exists():
            import synth
            synth.build_all(OUT)
        _CACHE[name] = analyse(OUT / name, trust_store_paths=TRUST)
    return _CACHE[name]


def _pair():
    return _report("fleet.pcap"), _report("fleet_later.pcap")


# --------------------------------------------------------------------------- #
# The refusal — the property that makes the rest trustworthy
# --------------------------------------------------------------------------- #

def test_unrelated_captures_are_refused_not_diffed():
    """Grade A+ to grade D across two unrelated files is not a regression, it
    is two different networks. Reporting it as drift would be a confident lie."""
    drift = compare(_report("smtp_relay_cleartext.pcap"), _report("imaps_downgrade.pcap"))
    assert not drift.comparable
    assert drift.host_overlap == 0.0
    assert "overlap" in drift.incomparable_reason
    assert not drift.appeared and not drift.resolved, (
        "findings were diffed for captures that are not the same estate")
    assert "meaningless" in drift.summary or "not the same estate" in drift.summary


def test_a_capture_against_itself_is_refused():
    report = _report("fleet.pcap")
    drift = compare(report, report)
    assert not drift.comparable
    assert "same capture file" in drift.incomparable_reason


def test_a_subset_capture_is_refused():
    """One host against a whole fleet is not a time series."""
    drift = compare(_report("imaps_downgrade.pcap"), _report("fleet.pcap"))
    assert not drift.comparable
    assert drift.host_overlap < OVERLAP_FLOOR


def test_the_overlap_floor_is_enforced_at_the_boundary():
    before, after = _pair()
    assert compare(before, after, overlap_floor=1.0).comparable, (
        "100% overlap should pass a 100% floor")
    assert not compare(before, after, overlap_floor=1.01).comparable


# --------------------------------------------------------------------------- #
# The diff
# --------------------------------------------------------------------------- #

def test_the_pair_is_the_same_estate():
    drift = compare(*_pair())
    assert drift.comparable
    assert drift.host_overlap == 1.0, (
        f"fleet_later.pcap should cover every host in fleet.pcap, got "
        f"{drift.host_overlap:.0%}")


def test_exactly_the_two_intended_hosts_moved():
    drift = compare(*_pair())
    moved = {h.host: h.status for h in drift.hosts if h.status != "unchanged"}
    assert set(moved) == {REMEDIATED, REGRESSED}, (
        f"expected only {REMEDIATED} and {REGRESSED} to move, got {moved}")
    assert moved[REMEDIATED] == "improved"
    assert moved[REGRESSED] == "regressed"


def test_the_regression_names_its_cause():
    """"Grade fell" without a reason is not actionable. USP-10's whole pitch is
    the second half of the sentence."""
    drift = compare(*_pair())
    host = next(h for h in drift.hosts if h.host == REGRESSED)
    assert host.appeared, "the regressed host lists no new findings"
    assert "TLS-WEAK-CIPHER-RC4" in host.appeared or \
           "TLS-DEPRECATED-VERSION" in host.appeared
    assert REGRESSED in drift.summary
    assert host.delta < -50, f"expected a large drop, got {host.delta}"


def test_the_remediation_is_reported_as_an_improvement():
    drift = compare(*_pair())
    host = next(h for h in drift.hosts if h.host == REMEDIATED)
    assert host.resolved, "the remediated host lists nothing resolved"
    assert host.delta > 50, f"expected a large rise, got {host.delta}"
    assert not host.appeared or host.after_grade in ("A+", "A")


def test_findings_partition_into_appeared_resolved_and_persisted():
    """The partition is over *keys*, not raw findings.

    `rule_id@host:port` is intentionally not unique within one report: two
    sessions to the same endpoint each produce their own finding, and
    `PQ-NOT-READY@10.20.1.23:993` legitimately appears twice in the corpus. The
    key identifies *a condition on an endpoint*, which is what a disposition
    should survive re-analysis on (ADR-0022) and what drift should track.
    """
    from securemailscope.drift import _key
    before, after = _pair()
    drift = compare(before, after)

    before_keys = {_key(f) for f in before.prioritised_findings}
    after_keys = {_key(f) for f in after.prioritised_findings}

    assert len(drift.appeared) + drift.persisted_count == len(after_keys)
    assert len(drift.resolved) + drift.persisted_count == len(before_keys)
    assert drift.persisted_count == len(before_keys & after_keys)


def test_the_finding_key_is_the_same_one_dispositions_use():
    """If these ever diverge, an analyst's decision and a drift entry stop
    referring to the same thing."""
    from securemailscope.drift import _key
    from securemailscope.store import finding_key
    for finding in _report("fleet.pcap").prioritised_findings[:5]:
        assert _key(finding) == finding_key(
            finding.rule_id, finding.affected_host, finding.affected_port)


def test_direction_is_symmetric():
    before, after = _pair()
    forward = compare(before, after)
    backward = compare(after, before)
    assert forward.appeared and backward.resolved
    assert len(forward.appeared) == len(backward.resolved)
    assert len(forward.resolved) == len(backward.appeared)


def test_a_host_whose_score_held_but_findings_changed_is_not_unchanged():
    """Two findings swapping out at equal weight is a change, and calling it
    'unchanged' is how a monitoring tool misses a redeployment."""
    before, after = _pair()
    drift = compare(before, after)
    for host in drift.hosts:
        if host.appeared or host.resolved:
            assert host.status != "unchanged", (
                f"{host.host} changed findings but reads as unchanged")


def test_drift_survives_the_json_round_trip():
    from schema import PostureDrift
    drift = compare(*_pair())
    back = PostureDrift.from_dict(drift.to_dict())
    assert back.comparable == drift.comparable
    assert back.summary == drift.summary
    assert len(back.hosts) == len(drift.hosts)
    assert len(back.appeared) == len(drift.appeared)


def test_summary_is_ascii_printable_on_a_windows_console():
    """A cp1252 console cannot print U+2192, and scripts print summaries. This
    crashed once."""
    drift = compare(*_pair())
    for text in (drift.summary, drift.incomparable_reason):
        text.encode("cp1252")


# --------------------------------------------------------------------------- #
# Over HTTP
# --------------------------------------------------------------------------- #

def test_the_api_refuses_before_there_are_two_snapshots():
    import tempfile
    from securemailscope.api import create_app
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(Path(tmp) / "drift.db")
        app.config["TESTING"] = True
        response = app.test_client().get("/api/drift")
        assert response.status_code == 409
        assert "two completed analyses" in response.get_json()["error"]


def test_the_api_diffs_the_two_most_recent_by_default():
    import tempfile
    import time
    from securemailscope.api import create_app
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(Path(tmp) / "drift.db")
        app.config["TESTING"] = True
        client = app.test_client()
        for name in ("fleet.pcap", "fleet_later.pcap"):
            job = client.post(f"/api/samples/{name}/analyse").get_json()["job_id"]
            for _ in range(900):
                state = client.get(f"/api/jobs/{job}").get_json()
                if state["state"] in ("completed", "failed", "rejected"):
                    break
                time.sleep(0.1)
            assert state["state"] == "completed", state

        payload = client.get("/api/drift").get_json()
        assert payload["comparable"] is True
        assert payload["host_overlap"] == 1.0
        moved = {h["host"] for h in payload["hosts"] if h["status"] != "unchanged"}
        assert moved == {REMEDIATED, REGRESSED}


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
