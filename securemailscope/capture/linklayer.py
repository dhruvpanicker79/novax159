"""Link-layer decoding. Stage S0/S1.

Everything above this module assumes it is handed an IP layer and a TCP
segment. Getting there from a raw captured frame is the job here, and it is
more varied than "strip 14 bytes of Ethernet":

* a capture taken with ``tcpdump -i any`` on Linux is **Linux cooked capture**
  (SLL or SLL2), not Ethernet;
* a capture from a router, a VPN or a tunnel interface is often **raw IP**,
  with no link header at all;
* a capture from a loopback interface carries a **4-byte address family**;
* a trunk port gives **802.1Q VLAN** tags, sometimes two of them (QinQ);
* and any of those can carry **IPv6**, whose extension-header chain has to be
  walked before the TCP segment appears.

Handing an Ethernet parser a cooked-capture frame does not raise — it decodes
the first 14 bytes as a MAC header and produces garbage, which then fails the
``isinstance(ip, IP)`` check and is silently dropped. The capture analyses
cleanly and reports **no mail sessions found**, which is the single worst
failure mode this tool has: indistinguishable from a healthy estate.

So this module reports what it could *not* decode as well as what it could,
and `securemailscope.rules` turns a low decode rate into a finding. Same
principle as ADR-0014: never let unanalysed read as clean.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

#: libpcap link types we can decode, mapped to the name we record on `Capture`.
#: The numbers are from tcpdump's `pcap/dlt.h` and are stable.
LINK_TYPES: dict[int, str] = {
    0: "null",              # BSD loopback: 4-byte address family
    1: "ethernet",          # DLT_EN10MB, including 802.1Q and QinQ
    12: "raw_ip",           # DLT_RAW on Linux: no link header at all
    14: "raw_ip",           # DLT_RAW on some BSDs
    101: "raw_ip",          # DLT_RAW as libpcap once numbered it
    108: "loopback",        # DLT_LOOP: 4-byte address family, big endian
    113: "linux_sll",       # `tcpdump -i any`
    228: "raw_ipv4",
    229: "raw_ipv6",
    276: "linux_sll2",      # newer `tcpdump -i any`
}

#: EtherType/protocol numbers we care about.
_ETH_IP4, _ETH_IP6 = 0x0800, 0x86DD


@dataclass
class DecodeStats:
    """What the decoder managed, for honest coverage reporting."""

    link_type: int = 1
    link_name: str = "ethernet"
    frames: int = 0
    decoded: int = 0            #: yielded an IP layer, whatever the protocol
    tcp: int = 0                #: yielded a TCP segment
    undecodable: int = 0        #: link layer could not be parsed at all
    non_ip: int = 0             #: decoded, but ARP/STP/LLDP and the like
    ipv6: int = 0
    vlan: int = 0
    reasons: set[str] = field(default_factory=set)

    @property
    def supported(self) -> bool:
        return self.link_type in LINK_TYPES

    @property
    def decode_rate(self) -> float:
        """Fraction of frames we got an IP layer out of. Non-IP frames count
        as decoded — ARP on a mail network is normal, not a parser failure."""
        return (self.decoded + self.non_ip) / self.frames if self.frames else 0.0

    def summary(self) -> str:
        if not self.frames:
            return "empty capture"
        if not self.supported:
            return (f"link type {self.link_type} is not supported; "
                    f"0 of {self.frames} frames could be decoded")
        bits = [f"{self.link_name}", f"{self.decoded}/{self.frames} frames decoded",
                f"{self.tcp} TCP"]
        if self.ipv6:
            bits.append(f"{self.ipv6} IPv6")
        if self.vlan:
            bits.append(f"{self.vlan} VLAN-tagged")
        if self.undecodable:
            bits.append(f"{self.undecodable} undecodable")
        return ", ".join(bits)


def link_name(datalink: int) -> str:
    return LINK_TYPES.get(datalink, f"unsupported({datalink})")


def _ip_from_raw(buf: bytes):
    """Raw IP with no link header: the version nibble tells us which."""
    import dpkt  # noqa: PLC0415

    if not buf:
        return None
    version = buf[0] >> 4
    if version == 4:
        return dpkt.ip.IP(buf)
    if version == 6:
        return dpkt.ip6.IP6(buf)
    return None


def _unwrap(layer, stats: DecodeStats):
    """Walk down from a link layer to an IP layer.

    dpkt strips 802.1Q tags into ``vlan_tags`` and leaves the inner protocol in
    ``data``, so VLAN and QinQ need no special handling beyond noting them.
    """
    import dpkt  # noqa: PLC0415

    if getattr(layer, "vlan_tags", None):
        stats.vlan += 1

    inner = getattr(layer, "data", None)
    if isinstance(inner, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return inner
    # Some SLL captures hand back bytes when the protocol is unfamiliar; if the
    # EtherType says IP, parse it ourselves rather than dropping the frame.
    etype = getattr(layer, "ethertype", None) or getattr(layer, "type", None)
    if isinstance(inner, (bytes, bytearray)) and etype in (_ETH_IP4, _ETH_IP6):
        return dpkt.ip.IP(inner) if etype == _ETH_IP4 else dpkt.ip6.IP6(inner)
    return None


def _tcp_of(ip, stats: DecodeStats):
    """Return the TCP segment carried by an IP layer, or None.

    dpkt walks the IPv6 extension-header chain during unpack, but a chain it
    does not recognise leaves an extension header in ``data``, so follow it.
    """
    import dpkt  # noqa: PLC0415

    layer = getattr(ip, "data", None)
    for _ in range(8):                      # a chain longer than this is hostile
        if isinstance(layer, dpkt.tcp.TCP):
            return layer
        nxt = getattr(layer, "data", None)
        if nxt is None or isinstance(nxt, (bytes, bytearray)):
            return None
        layer = nxt
    stats.reasons.add("IPv6 extension-header chain too long")
    return None


def decode(buf: bytes, datalink: int, stats: DecodeStats):
    """Decode one frame to ``(ip_layer, tcp_segment)``, or ``None``.

    Never raises: one malformed frame in a million-packet capture must not end
    the run. It is counted instead, which is what makes the count meaningful.
    """
    import dpkt  # noqa: PLC0415

    stats.frames += 1
    try:
        if datalink == 1:
            ip = _unwrap(dpkt.ethernet.Ethernet(buf), stats)
        elif datalink == 113:
            ip = _unwrap(dpkt.sll.SLL(buf), stats)
        elif datalink == 276:
            ip = _unwrap(dpkt.sll2.SLL2(buf), stats)
        elif datalink in (0, 108):
            ip = _unwrap(dpkt.loopback.Loopback(buf), stats)
        elif datalink in (12, 14, 101):
            ip = _ip_from_raw(buf)
        elif datalink == 228:
            ip = dpkt.ip.IP(buf)
        elif datalink == 229:
            ip = dpkt.ip6.IP6(buf)
        else:
            stats.undecodable += 1
            stats.reasons.add(f"unsupported link type {datalink}")
            return None
    except Exception:  # noqa: BLE001 — a bad frame is data, not an exception
        stats.undecodable += 1
        stats.reasons.add("malformed link-layer header")
        return None

    if ip is None:
        stats.non_ip += 1
        return None

    if isinstance(ip, dpkt.ip6.IP6):
        stats.ipv6 += 1
    stats.decoded += 1

    segment = _tcp_of(ip, stats)
    if segment is None:
        return None
    stats.tcp += 1
    return ip, segment


def addresses(ip) -> tuple[str, str]:
    """Printable source and destination, IPv4 or IPv6.

    `socket.inet_ntoa` is 4-byte only, so IPv6 needs `inet_ntop`; getting this
    wrong raises rather than mis-formatting, which is the good failure.
    """
    family = socket.AF_INET6 if len(ip.src) == 16 else socket.AF_INET
    return (socket.inet_ntop(family, ip.src), socket.inet_ntop(family, ip.dst))
