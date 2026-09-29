"""Re-wrap an existing capture in a different link layer. Test-corpus tool.

The analysis above S1 should not be able to tell how a packet reached the wire.
The way to prove that is to take a capture whose expected findings are already
known, re-encapsulate every frame, and assert the analyser produces *exactly
the same result*. If it does not, the difference is a link-layer bug and
nothing else, because the TCP payloads are byte-identical.

    python testbed/relink.py                 # writes into testbed/out/

Produces, from `fleet.pcap`:

    fleet_sll.pcap     Linux cooked capture   `tcpdump -i any`
    fleet_sll2.pcap    Linux cooked v2        newer tcpdump
    fleet_raw.pcap     raw IP, no link header  VPN / tunnel interfaces
    fleet_vlan.pcap    802.1Q tagged           trunk port
    fleet_qinq.pcap    stacked 802.1Q          carrier / provider bridge
    fleet_ipv6.pcap    IPv6 over Ethernet      addresses mapped deterministically
    fleet_loopback.pcap BSD/macOS loopback     4-byte address family

`fleet_ipv6.pcap` is the only one that rewrites more than the encapsulation:
IPv4 addresses are mapped into the 2001:db8::/32 documentation prefix, which
RFC 3849 reserves for exactly this. Ports, sequence numbers and payloads are
untouched, so the reconstructed conversations must be identical.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import dpkt

OUT = Path(__file__).resolve().parent / "out"

#: Link types we emit. See `securemailscope/capture/linklayer.LINK_TYPES`.
DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_LINUX_SLL, DLT_LINUX_SLL2 = 0, 1, 101, 113, 276


def _frames(path: Path):
    """Yield `(timestamp, ethernet_frame)` from an Ethernet capture."""
    with path.open("rb") as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            try:
                eth = dpkt.ethernet.Ethernet(bytes(buf))
            except Exception:  # noqa: BLE001
                continue
            if isinstance(eth.data, dpkt.ip.IP):
                yield ts, eth


def _write(name: str, linktype: int, records) -> Path:
    target = OUT / name
    with target.open("wb") as fh:
        writer = dpkt.pcap.Writer(fh, linktype=linktype)
        n = 0
        for ts, payload in records:
            writer.writepkt(payload, ts=ts)
            n += 1
    print(f"  {name:24} linktype {linktype:<4} {n} frames")
    return target


def _map_v6(v4: bytes) -> bytes:
    """10.20.1.23 -> 2001:db8:1::17, deterministically and reversibly.

    RFC 3849 reserves 2001:db8::/32 for documentation, which is what a test
    corpus is. Keeping the last two octets means the addresses stay readable
    against the IPv4 originals when a finding is checked by hand.
    """
    a, b, c, d = v4
    return struct.pack(">8H", 0x2001, 0x0DB8, c, 0, 0, 0, a, (b << 8) | d)


def build(source: Path) -> list[Path]:
    if not source.exists():
        raise SystemExit(f"{source} not found — run `python testbed/synth.py` first")
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"re-wrapping {source.name}:")
    written = []

    # ── Linux cooked capture (SLL): 16-byte header, no MAC framing ──────── #
    def sll():
        for ts, eth in _frames(source):
            hdr = struct.pack(">HHH8sH", 0, 1, 6, bytes(eth.src).ljust(8, b"\0"), 0x0800)
            yield ts, hdr + bytes(eth.data)
    written.append(_write("fleet_sll.pcap", DLT_LINUX_SLL, sll()))

    # ── SLL2: 20-byte header, protocol first, interface index added ─────── #
    def sll2():
        for ts, eth in _frames(source):
            hdr = struct.pack(">HHIHBB8s", 0x0800, 0, 1, 1, 0, 6,
                              bytes(eth.src).ljust(8, b"\0"))
            yield ts, hdr + bytes(eth.data)
    written.append(_write("fleet_sll2.pcap", DLT_LINUX_SLL2, sll2()))

    # ── raw IP: no link header at all ───────────────────────────────────── #
    written.append(_write("fleet_raw.pcap", DLT_RAW,
                          ((ts, bytes(eth.data)) for ts, eth in _frames(source))))

    # ── 802.1Q, and stacked 802.1Q ──────────────────────────────────────── #
    def tagged(tags: list[int]):
        """dst | src | (0x8100 vid)* | 0x0800 | ip — outermost tag first."""
        for ts, eth in _frames(source):
            frame = bytes(eth.dst) + bytes(eth.src)
            for vid in tags:
                frame += struct.pack(">HH", 0x8100, vid)
            frame += struct.pack(">H", 0x0800) + bytes(eth.data)
            yield ts, frame
    written.append(_write("fleet_vlan.pcap", DLT_EN10MB, tagged([110])))
    written.append(_write("fleet_qinq.pcap", DLT_EN10MB, tagged([200, 110])))

    # ── BSD loopback: 4-byte address family, host byte order ────────────── #
    def loopback():
        for ts, eth in _frames(source):
            yield ts, struct.pack("<I", 2) + bytes(eth.data)   # AF_INET
    written.append(_write("fleet_loopback.pcap", DLT_NULL, loopback()))

    # ── IPv6 over Ethernet ──────────────────────────────────────────────── #
    def v6():
        for ts, eth in _frames(source):
            ip4 = eth.data
            tcp = ip4.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            tcp = dpkt.tcp.TCP(bytes(tcp))
            tcp.sum = 0                       # dpkt recomputes over the v6 pseudo-header
            ip6 = dpkt.ip6.IP6(
                src=_map_v6(bytes(ip4.src)), dst=_map_v6(bytes(ip4.dst)),
                nxt=dpkt.ip.IP_PROTO_TCP, hlim=64, data=tcp)
            ip6.plen = len(bytes(tcp))
            frame = dpkt.ethernet.Ethernet(
                src=bytes(eth.src), dst=bytes(eth.dst),
                type=dpkt.ethernet.ETH_TYPE_IP6, data=ip6)
            yield ts, bytes(frame)
    written.append(_write("fleet_ipv6.pcap", DLT_EN10MB, v6()))

    return written


if __name__ == "__main__":
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT / "fleet.pcap"
    build(src)
