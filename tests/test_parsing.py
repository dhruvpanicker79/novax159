"""Tests for S0-S3 and the end-to-end pipeline.

These run against PCAPs crafted by `testbed/synth.py`, so they need no Docker,
no mail servers and no WSL - only `dpkt`, which is pure Python and therefore
not blocked by Smart App Control (ADR-0012).

Run:  python tests/test_parsing.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from schema import Confidence, MailProtocol, PortRole, TlsMode  # noqa: E402
from securemailscope.capture.ingest import detect_format, load_capture, sha256_of  # noqa: E402
from securemailscope.capture.reassemble import DirectionStream, reassemble  # noqa: E402
from securemailscope.proto import detect, starttls  # noqa: E402

sys.path.insert(0, str(ROOT / "testbed"))
import synth  # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="sms-tests-"))


def _capture(*scenarios: str) -> Path:
    name = "_".join(scenarios) or "fleet"
    path = _TMP / f"{name}.pcap"
    if not path.exists():
        scripts = ([synth.SCENARIOS[s]() for s in scenarios] if scenarios
                   else [f() for f in synth.SCENARIOS.values()])
        synth.write_pcap(path, scripts)
    return path


def _sessions(*scenarios: str):
    capture = load_capture(_capture(*scenarios))
    out = []
    for flow in reassemble(capture):
        session = detect.identify(flow)
        if session is not None:
            starttls.attach(session, flow)
            out.append((session, flow))
    return out


# --------------------------------------------------------------------------- #
# S1 reassembly, tested directly
# --------------------------------------------------------------------------- #


def test_in_order_segments_concatenate():
    s = DirectionStream()
    s.add(100, b"hello ", 1)
    s.add(106, b"world", 2)
    s.finish()
    assert bytes(s.data) == b"hello world"
    assert s.retransmissions == 0


def test_out_of_order_segments_are_reordered():
    s = DirectionStream()
    s.add(100, b"aaa", 1)
    s.add(106, b"ccc", 3)      # arrives early
    s.add(103, b"bbb", 2)
    s.finish()
    assert bytes(s.data) == b"aaabbbccc"


def test_retransmission_keeps_the_first_copy():
    s = DirectionStream()
    s.add(100, b"abc", 1)
    s.add(100, b"abc", 2)      # duplicate
    s.finish()
    assert bytes(s.data) == b"abc"
    assert s.retransmissions == 1


def test_partial_overlap_keeps_only_new_bytes():
    s = DirectionStream()
    s.add(100, b"abcd", 1)
    s.add(102, b"cdef", 2)     # overlaps by two
    s.finish()
    assert bytes(s.data) == b"abcdef"


def test_offsets_map_back_to_frames():
    """USP-03: the provenance claim has to survive reassembly."""
    s = DirectionStream()
    s.add(100, b"first", 11)
    s.add(105, b"second", 22)
    s.finish()
    assert s.frame_for_offset(0) == 11
    assert s.frame_for_offset(4) == 11
    assert s.frame_for_offset(5) == 22
    assert s.frames_for_range(0, 11) == [11, 22]
    assert s.frames_for_range(6, 8) == [22]


def test_gap_is_recorded_not_faked():
    """We concatenate what we have; we never invent bytes to fill a hole."""
    s = DirectionStream()
    s.add(100, b"aaa", 1)
    for i in range(70):        # push past MAX_PENDING_SEGMENTS
        s.add(1000 + i * 10, b"x" * 10, 10 + i)
    s.finish()
    assert s.gaps, "a gap should have been recorded"
    assert b"\x00" not in bytes(s.data), "no filler bytes may be inserted"


# --------------------------------------------------------------------------- #
# S0 ingest
# --------------------------------------------------------------------------- #


def test_format_detected_from_magic_not_extension():
    path = _capture("smtp_starttls_healthy")
    renamed = _TMP / "actually_a_pcap.bin"
    renamed.write_bytes(path.read_bytes())
    assert detect_format(renamed) == "pcap"


def test_capture_metadata_is_populated():
    capture = load_capture(_capture("smtp_starttls_healthy"))
    assert capture.packet_count > 10
    assert len(capture.sha256) == 64
    assert capture.first_packet_at is not None
    assert capture.last_packet_at >= capture.first_packet_at


def test_hash_is_stable():
    path = _capture("smtp_starttls_healthy")
    assert sha256_of(path) == sha256_of(path)


def test_non_capture_file_is_rejected():
    junk = _TMP / "not-a-capture.txt"
    junk.write_text("hello")
    try:
        detect_format(junk)
    except ValueError as exc:
        assert "capture" in str(exc)
    else:
        raise AssertionError("should have refused a non-capture file")


# --------------------------------------------------------------------------- #
# S2 protocol identification (D01)
# --------------------------------------------------------------------------- #


def test_banner_identifies_each_protocol():
    assert detect.banner_protocol(b"220 mail ESMTP Postfix\r\n")[0] is MailProtocol.SMTP
    assert detect.banner_protocol(b"* OK [CAPABILITY IMAP4rev1] ready\r\n")[0] is MailProtocol.IMAP
    assert detect.banner_protocol(b"+OK POP3 ready\r\n")[0] is MailProtocol.POP3
    assert detect.banner_protocol(b"GET / HTTP/1.1\r\n")[0] is MailProtocol.UNKNOWN


def test_all_three_protocols_identified_from_capture():
    found = {s.protocol for s, _ in _sessions()}
    assert {MailProtocol.SMTP, MailProtocol.IMAP, MailProtocol.POP3} <= found


def test_banner_and_port_agreement_gives_confirmed():
    session, _ = _sessions("smtp_starttls_healthy")[0]
    assert session.protocol_confidence is Confidence.CONFIRMED


def test_implicit_tls_has_no_banner_but_is_still_identified():
    """On 993 the first byte is a ClientHello, so there is nothing to read."""
    session, _ = _sessions("imaps_implicit_weak")[0]
    assert session.protocol is MailProtocol.IMAP
    assert session.tls_mode is TlsMode.IMPLICIT
    assert session.banner is None


def test_port_roles_assigned_correctly():
    roles = {s.server_port: s.port_role for s, _ in _sessions()}
    assert roles[25] is PortRole.MTA_RELAY
    assert roles[587] is PortRole.SUBMISSION
    assert roles[993] is PortRole.MAIL_ACCESS


def test_starttls_upgrade_is_not_reported_as_cleartext():
    """Regression: an anchored regex used with .search() made every upgraded
    session look like cleartext."""
    session, _ = _sessions("smtp_starttls_healthy")[0]
    assert session.tls_mode is TlsMode.STARTTLS


# --------------------------------------------------------------------------- #
# S3 STARTTLS validation (D02)
# --------------------------------------------------------------------------- #


def test_healthy_upgrade_passes_every_observable_check():
    session, _ = _sessions("smtp_starttls_healthy")[0]
    v = session.starttls
    assert v.v1_advertised and v.v3_client_issued and v.v4_server_accepted
    assert v.v5_clienthello_followed and v.v6_handshake_completed
    assert v.upgrade_succeeded
    assert v.failed_checks == []


def test_v7_is_none_when_not_observable():
    """After a successful upgrade the re-issued EHLO is inside the encrypted
    channel. Claiming a verdict would be fabricating a finding."""
    session, _ = _sessions("smtp_starttls_healthy")[0]
    assert session.starttls.v6_handshake_completed is True
    assert session.starttls.v7_ehlo_reissued is None


def test_stripping_detected_and_credentials_recovered():
    session, _ = _sessions("smtp_starttls_stripped")[0]
    v = session.starttls
    assert v.v2_capability_mangled is True
    assert v.observed_capability_line == "250-XXXXXXXA"
    assert v.v9_credentials_before_tls is True
    assert not v.upgrade_succeeded

    exposure = session.attack_evidence.credential_exposure[0]
    assert exposure.username == "r.sharma@dept.gov.in"
    assert exposure.password_length == 14
    assert "*" in exposure.password_redacted
    assert "MonsoonRain" not in (exposure.password_redacted or "")


def test_well_formed_capability_is_not_flagged_as_mangled():
    """The false-positive guard: a healthy 250-STARTTLS must stay clean."""
    for name in ("smtp_starttls_healthy", "smtp_relay_cleartext"):
        session, _ = _sessions(name)[0]
        assert session.starttls.v2_capability_mangled is False, name


def test_imap_plaintext_login_is_recovered():
    session, _ = _sessions("imap_advertised_not_used")[0]
    assert session.starttls.v1_advertised is True
    assert session.starttls.v3_client_issued is False
    exposure = session.attack_evidence.credential_exposure[0]
    assert exposure.mechanism == "IMAP LOGIN"
    assert exposure.username == "r.sharma@dept.gov.in"


def test_phases_split_correctly():
    session, _ = _sessions("smtp_starttls_healthy")[0]
    kinds = [p.kind.value for p in session.phases]
    assert kinds == ["plaintext", "starttls_negotiation", "encrypted"]

    implicit, _ = _sessions("imaps_implicit_weak")[0]
    assert [p.kind.value for p in implicit.phases] == ["encrypted"]


def test_implicit_tls_leaves_starttls_checks_not_applicable():
    session, _ = _sessions("imaps_implicit_weak")[0]
    v = session.starttls
    assert v.v1_advertised is None and v.v3_client_issued is None


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #


def test_pipeline_produces_a_report_from_a_pcap():
    from securemailscope.pipeline import analyse

    report = analyse(_capture())
    assert report.capture.packet_count > 50
    assert len(report.sessions) >= 6
    assert report.fleet is not None
    assert report.prioritised_findings
    assert report.to_json()


def test_credential_exposure_caps_the_host_grade():
    """An average that hides a catastrophe is worse than no score."""
    from securemailscope.pipeline import analyse

    report = analyse(_capture())
    leaking = [h for h in report.hosts
               if any(f.rule_id == "ATTACK-CLEARTEXT-CREDENTIALS"
                      for f in h.top_findings)]
    assert leaking, "expected at least one leaking host"
    assert all(h.grade.value == "F" for h in leaking)


def test_mid_session_capture_is_encrypted_not_cleartext():
    """A capture that began after the handshake has no ClientHello to read.

    Reporting it as cleartext would be a serious misread of a normal forensic
    situation; reporting it as clean would be worse.
    """
    from schema import TlsMode
    from securemailscope.pipeline import analyse

    report = analyse(_capture("imaps_mid_session"))
    session = report.sessions[0]
    assert session.tls_mode is TlsMode.IMPLICIT
    assert session.handshake is None, "there is no handshake to parse"


def test_unparsed_handshake_is_reported_not_scored_as_clean():
    """A host must never look perfect because we could not inspect it."""
    from securemailscope.pipeline import analyse

    report = analyse(_capture("imaps_mid_session"))
    ids = {f.rule_id for f in report.prioritised_findings}
    assert "ANALYSIS-INCOMPLETE-HANDSHAKE" in ids
    assert "Coverage is partial" in report.fleet.summary
    assert report.hosts[0].grade.value == "?", report.hosts[0].grade.value


def test_relay_does_not_collect_false_high_severity():
    """USP-01 applied to our own rule pack: the relay is not the client's fault."""
    from securemailscope.pipeline import analyse

    report = analyse(_capture())
    relay = [f for f in report.prioritised_findings
             if f.port_role is PortRole.MTA_RELAY]
    assert relay, "expected relay findings"
    assert all(f.severity.rank <= 1 for f in relay), \
        [(f.rule_id, f.severity.value) for f in relay]


def test_every_pipeline_finding_carries_usable_evidence():
    from securemailscope.pipeline import analyse

    report = analyse(_capture())
    for finding in report.prioritised_findings:
        assert finding.evidence.is_populated, finding.rule_id
        assert finding.evidence.frame_numbers, finding.rule_id


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
