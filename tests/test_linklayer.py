"""Link-layer coverage. Stage S0/S1.

The claim under test is **invariance**: how a packet reached the wire must not
change a single finding. The corpus for it is built by re-wrapping `fleet.pcap`
(`testbed/relink.py`), so the TCP payloads are byte-identical across every file
and any difference in output is a link-layer bug and nothing else.

Before this existed, five of the seven encapsulations below lost *every frame*
and produced an empty report that read exactly like a healthy estate — which is
why the last test here matters more than the rest.

    python tests/test_linklayer.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "testbed"))

import dpkt  # noqa: E402

from securemailscope.capture.ingest import datalink_of, load_capture  # noqa: E402
from securemailscope.capture.linklayer import (  # noqa: E402
    LINK_TYPES, DecodeStats, decode, link_name)
from securemailscope.capture.reassemble import reassemble  # noqa: E402
from securemailscope.pipeline import analyse  # noqa: E402

OUT = ROOT / "testbed" / "out"
TRUST = [str(ROOT / "testbed" / "certs" / "_ca.der")]
BASE = OUT / "fleet.pcap"

#: Every re-wrapping of fleet.pcap, and whether addresses were rewritten too.
VARIANTS = [
    ("fleet_sll.pcap", "linux_sll", False),
    ("fleet_sll2.pcap", "linux_sll2", False),
    ("fleet_raw.pcap", "raw_ip", False),
    ("fleet_vlan.pcap", "ethernet", False),
    ("fleet_qinq.pcap", "ethernet", False),
    ("fleet_loopback.pcap", "null", False),
    ("fleet_ipv6.pcap", "ethernet", True),
]


def _ensure_corpus() -> None:
    if not BASE.exists():
        import synth
        synth.build_all(OUT)
    if not (OUT / "fleet_sll.pcap").exists():
        import relink
        relink.build(BASE)


def _fingerprint(report, drop_host: bool = False):
    """The findings, as a comparable set. Host is dropped for the IPv6 variant
    because its addresses were deliberately rewritten."""
    return sorted(
        (f.rule_id, f.severity.value, None if drop_host else f.affected_host,
         f.affected_port)
        for f in report.prioritised_findings)


# --------------------------------------------------------------------------- #
# The decoder itself
# --------------------------------------------------------------------------- #

def test_every_supported_link_type_has_a_name():
    for dlt in LINK_TYPES:
        assert not link_name(dlt).startswith("unsupported"), dlt
    assert link_name(105).startswith("unsupported"), "802.11 is not supported"


def test_decoder_never_raises_on_rubbish():
    """A malformed frame is data, not an exception. One bad packet in a large
    capture must not end the run."""
    stats = DecodeStats()
    for payload in (b"", b"\x00", b"\xff" * 3, bytes(range(60)), b"\x45" + b"\x00" * 3):
        for dlt in (*LINK_TYPES, 105):
            assert decode(payload, dlt, stats) is None or True   # must not raise
    assert stats.frames > 0


def test_link_type_is_read_from_the_file():
    """It used to be hard-coded to 'ethernet', which is how a `tcpdump -i any`
    capture analysed cleanly and reported nothing."""
    _ensure_corpus()
    assert load_capture(BASE).link_type == "ethernet"
    for name, expected, _ in VARIANTS:
        assert load_capture(OUT / name).link_type == expected, name


def test_datalink_of_falls_back_rather_than_raising():
    capture = load_capture(BASE)
    capture.path = str(OUT / "does_not_exist.pcap")
    assert datalink_of(capture) == 1


# --------------------------------------------------------------------------- #
# Invariance: the whole point
# --------------------------------------------------------------------------- #

def test_every_frame_is_decoded_in_every_encapsulation():
    _ensure_corpus()
    base = load_capture(BASE)
    list(reassemble(base))
    assert base.decoded_frame_count == base.packet_count

    for name, _, _ in VARIANTS:
        capture = load_capture(OUT / name)
        list(reassemble(capture))
        assert capture.decoded_frame_count == capture.packet_count, (
            f"{name}: only {capture.decoded_frame_count} of "
            f"{capture.packet_count} frames decoded")


def test_same_flows_regardless_of_encapsulation():
    _ensure_corpus()
    want = len(list(reassemble(load_capture(BASE))))
    assert want > 0
    for name, _, _ in VARIANTS:
        got = len(list(reassemble(load_capture(OUT / name))))
        assert got == want, f"{name}: {got} flows, expected {want}"


def test_findings_are_identical_regardless_of_encapsulation():
    """The headline claim. Same payloads in, same findings out."""
    _ensure_corpus()
    base = analyse(BASE, trust_store_paths=TRUST)
    for name, _, rewrote_addresses in VARIANTS:
        report = analyse(OUT / name, trust_store_paths=TRUST)
        assert _fingerprint(report, rewrote_addresses) == \
               _fingerprint(base, rewrote_addresses), name
        assert report.fleet.grade == base.fleet.grade, name
        assert len(report.sessions) == len(base.sessions), name


def test_ipv6_addresses_survive_into_the_report():
    """IPv4 formatting is `inet_ntoa`, which is 4-byte only. If IPv6 were being
    mangled rather than decoded, this is where it would show."""
    _ensure_corpus()
    report = analyse(OUT / "fleet_ipv6.pcap", trust_store_paths=TRUST)
    hosts = {s.server_host for s in report.sessions}
    assert hosts, "no sessions at all"
    assert all(":" in h for h in hosts), f"not IPv6 addresses: {sorted(hosts)[:3]}"
    assert all(h.startswith("2001:db8:") for h in hosts), sorted(hosts)[:3]


# --------------------------------------------------------------------------- #
# The failure that matters most
# --------------------------------------------------------------------------- #

def _write_with_linktype(target: Path, linktype: int) -> Path:
    with BASE.open("rb") as fh, target.open("wb") as out:
        writer = dpkt.pcap.Writer(out, linktype=linktype)
        for ts, buf in dpkt.pcap.Reader(fh):
            writer.writepkt(bytes(buf), ts=ts)
    return target


def test_an_unreadable_capture_never_reads_as_clean():
    """A capture we cannot decode yields no sessions and therefore no findings,
    which scores 100/100 and grades A+ unless something stops it. That is the
    single worst failure this tool can have: indistinguishable from a healthy
    estate. Same rule as ADR-0014, one layer down.
    """
    _ensure_corpus()
    bad = _write_with_linktype(OUT / "_unsupported_linktype.pcap", 105)
    try:
        report = analyse(bad, trust_store_paths=TRUST)
        assert report.capture.link_type.startswith("unsupported")
        assert not report.sessions

        ids = [f.rule_id for f in report.prioritised_findings]
        assert "ANALYSIS-CAPTURE-NOT-READABLE" in ids, ids

        assert report.fleet.grade.value == "?", (
            f"graded {report.fleet.grade.value} on a capture that could not be read")
        assert report.fleet.score == 0.0

        finding = next(f for f in report.prioritised_findings
                       if f.rule_id == "ANALYSIS-CAPTURE-NOT-READABLE")
        assert finding.severity.rank >= 3, "an unreadable capture is not an INFO"
        assert finding.remediation and "tcpdump" in finding.remediation.summary
    finally:
        bad.unlink(missing_ok=True)


def test_a_readable_capture_with_no_mail_is_not_flagged():
    """The opposite error: a perfectly good capture of something that is not
    mail is an answer, not a coverage failure."""
    target = OUT / "_arp_only.pcap"
    with target.open("wb") as fh:
        writer = dpkt.pcap.Writer(fh, linktype=1)
        arp = dpkt.arp.ARP(sha=b"\x00" * 6, spa=b"\x0a\x14\x01\x01",
                           tha=b"\x00" * 6, tpa=b"\x0a\x14\x01\x02")
        frame = dpkt.ethernet.Ethernet(
            src=b"\x00" * 6, dst=b"\xff" * 6,
            type=dpkt.ethernet.ETH_TYPE_ARP, data=arp)
        for i in range(10):
            writer.writepkt(bytes(frame), ts=1758000000.0 + i)
    try:
        report = analyse(target, trust_store_paths=TRUST)
        assert not report.sessions
        ids = [f.rule_id for f in report.prioritised_findings]
        assert "ANALYSIS-CAPTURE-NOT-READABLE" not in ids, (
            "a decodable non-mail capture was reported as unreadable")
    finally:
        target.unlink(missing_ok=True)


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
