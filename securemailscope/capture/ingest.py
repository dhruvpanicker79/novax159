"""S0 - open a capture and describe it.

Everything downstream quotes `Capture.sha256` as the root of the chain of
custody (USP-03), so the hash is computed in one streaming pass: a real
enterprise capture can be gigabytes and must never be read into memory whole.

PCAP and PCAPNG are both accepted, detected from the magic number rather than
the file extension - a file named `.pcap` that is actually pcapng is common
enough to be worth handling silently.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from schema import Capture

from .linklayer import link_name

_CHUNK = 1 << 20

#: pcap (both endiannesses, plus the nanosecond variants) and pcapng.
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "pcap",
    b"\xa1\xb2\xc3\xd4": "pcap",
    b"\x4d\x3c\xb2\xa1": "pcap",
    b"\xa1\xb2\x3c\x4d": "pcap",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}


def detect_format(path: Path) -> str:
    with path.open("rb") as fh:
        magic = fh.read(4)
    fmt = _MAGICS.get(magic)
    if fmt is None:
        raise ValueError(
            f"{path.name} does not look like a capture file "
            f"(magic {magic.hex()}). Expected pcap or pcapng."
        )
    return fmt


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _reader(fh, fmt: str):
    import dpkt  # noqa: PLC0415 - optional dependency, only needed here

    return dpkt.pcapng.Reader(fh) if fmt == "pcapng" else dpkt.pcap.Reader(fh)


def load_capture(path: str | Path) -> Capture:
    """Open a capture and return its metadata.

    One pass for the hash, one for the packet count and time range. Both are
    streaming, so memory stays flat regardless of file size.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)

    fmt = detect_format(path)
    capture = Capture(
        path=str(path),
        filename=path.name,
        sha256=sha256_of(path),
        size_bytes=path.stat().st_size,
        analysed_at=datetime.now(tz=timezone.utc),
    )

    first: float | None = None
    last: float | None = None
    count = 0
    with path.open("rb") as fh:
        reader = _reader(fh, fmt)
        # Ask the file what link layer it holds. This used to be hard-coded to
        # "ethernet", which is how a Linux `tcpdump -i any` capture analysed
        # cleanly and reported nothing at all.
        try:
            capture.link_type = link_name(reader.datalink())
        except Exception:  # noqa: BLE001 - a reader without datalink() is old
            capture.link_type = "ethernet"
        for ts, _ in reader:
            count += 1
            if first is None:
                first = ts
            last = ts

    capture.packet_count = count
    if first is not None:
        capture.first_packet_at = datetime.fromtimestamp(first, tz=timezone.utc)
    if last is not None:
        capture.last_packet_at = datetime.fromtimestamp(last, tz=timezone.utc)
    return capture


def datalink_of(capture: Capture) -> int:
    """The capture's libpcap link type, as a number.

    Read from the file rather than remembered from `load_capture`, so callers
    that build a `Capture` by hand still get the right answer. Defaults to
    Ethernet only when the reader cannot say.
    """
    path = Path(capture.path)
    try:
        with path.open("rb") as fh:
            return int(_reader(fh, detect_format(path)).datalink())
    except Exception:  # noqa: BLE001
        return 1


def iter_packets(capture: Capture) -> Iterator[tuple[int, float, bytes]]:
    """Yield `(frame_number, timestamp, raw_frame)` in file order.

    frame_number is **1-based**, matching what Wireshark shows. That is not
    cosmetic: `Evidence.frame_numbers` has to be something an analyst can type
    into a display filter to check our work, which is the whole point of USP-03.
    """
    path = Path(capture.path)
    fmt = detect_format(path)
    with path.open("rb") as fh:
        for index, (ts, buf) in enumerate(_reader(fh, fmt), start=1):
            yield index, ts, bytes(buf)
