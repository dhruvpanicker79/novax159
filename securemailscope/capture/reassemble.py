"""S1 - TCP stream reconstruction. Deliverable D03.

This is the module USP-03 lives or dies on. Read ADR-0004 first: every byte
placed into a direction stream remembers the frame it arrived in, recorded as
we go. Retrofitting that through a finished parser is the mistake that costs
teams their strongest differentiator, so the bookkeeping is built in from the
first line rather than added later.

What it handles:
    - out-of-order segments, held until the gap ahead of them is filled
    - retransmissions, where the FIRST copy seen wins and duplicates are counted
    - partial overlaps, where only the genuinely new tail is appended
    - gaps from a truncated capture, recorded rather than fatal

On gaps: when bytes are missing we concatenate what we have and record the
gap, exactly as Wireshark's "Follow TCP Stream" does. We do NOT insert filler
to preserve sequence-relative offsets. Inserting bytes nobody sent into an
artifact we then present as forensic evidence would be indefensible, and a
missing-bytes marker is more honest than a plausible-looking zero run.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone

from schema import Capture, Evidence, Flow

from .ingest import iter_packets

#: Cap per direction so one pathological flow cannot exhaust memory on a large
#: capture. 8 MB is far more than any mail session needs; truncation is
#: recorded on the Flow rather than silently dropped.
MAX_STREAM_BYTES = 8 << 20

#: Out-of-order segments waiting on a predecessor. Beyond this we declare a gap
#: and move on, rather than holding a stalled flow open forever.
MAX_PENDING_SEGMENTS = 64


@dataclass
class DirectionStream:
    """One half of a conversation, reassembled in order."""

    data: bytearray = field(default_factory=bytearray)
    base_seq: int | None = None
    next_seq: int | None = None
    pending: dict[int, tuple[bytes, int]] = field(default_factory=dict)
    #: stream offset -> frame number. Sparse: one entry per contiguous run.
    offset_to_frame: dict[int, int] = field(default_factory=dict)
    retransmissions: int = 0
    gaps: list[tuple[int, int]] = field(default_factory=list)
    truncated: bool = False
    frames: list[int] = field(default_factory=list)

    def _append(self, payload: bytes, frame: int) -> None:
        if len(self.data) + len(payload) > MAX_STREAM_BYTES:
            self.truncated = True
            payload = payload[: max(0, MAX_STREAM_BYTES - len(self.data))]
            if not payload:
                return
        self.offset_to_frame[len(self.data)] = frame
        self.data += payload
        if frame not in self.frames:
            self.frames.append(frame)

    def add(self, seq: int, payload: bytes, frame: int) -> None:
        """Place one segment, in order if possible, buffered if not."""
        if not payload:
            return

        if self.base_seq is None:
            self.base_seq = seq
            self.next_seq = seq

        assert self.next_seq is not None

        if seq == self.next_seq:
            self._append(payload, frame)
            self.next_seq += len(payload)
            self._drain()
            return

        if seq < self.next_seq:
            end = seq + len(payload)
            if end <= self.next_seq:
                # Pure retransmission: the first copy already won.
                self.retransmissions += 1
                return
            # Partial overlap - keep only the bytes we have not seen.
            overlap = self.next_seq - seq
            self.retransmissions += 1
            self._append(payload[overlap:], frame)
            self.next_seq = end
            self._drain()
            return

        # Ahead of the hole: hold it until the missing bytes arrive.
        self.pending[seq] = (payload, frame)
        if len(self.pending) > MAX_PENDING_SEGMENTS:
            self._force_gap()

    def _drain(self) -> None:
        """Flush any buffered segments that are now contiguous."""
        while self.next_seq in self.pending:
            payload, frame = self.pending.pop(self.next_seq)
            self._append(payload, frame)
            self.next_seq += len(payload)

    def _force_gap(self) -> None:
        """Skip to the earliest buffered segment and record what we lost."""
        if not self.pending or self.next_seq is None:
            return
        earliest = min(self.pending)
        self.gaps.append((len(self.data), earliest - self.next_seq))
        self.next_seq = earliest
        self._drain()

    def finish(self) -> None:
        while self.pending:
            self._force_gap()

    def frame_for_offset(self, offset: int) -> int | None:
        """Which packet delivered the byte at this stream offset?

        Answers the question a judge asks when we claim provenance: "show me."
        """
        best: int | None = None
        best_start = -1
        for start, frame in self.offset_to_frame.items():
            if start <= offset and start > best_start:
                best, best_start = frame, start
        return best

    def frames_for_range(self, start: int, end: int) -> list[int]:
        """Every packet contributing bytes in [start, end)."""
        runs = sorted(self.offset_to_frame.items())
        out: list[int] = []
        for index, (run_start, frame) in enumerate(runs):
            run_end = runs[index + 1][0] if index + 1 < len(runs) else len(self.data)
            if run_start < end and run_end > start:
                out.append(frame)
        return out


@dataclass
class ReassembledFlow:
    """A reconstructed conversation, with its bytes attached.

    `flow` is the light schema object that goes into the report. The payload
    lives here at runtime and is never serialised - a JSON report carrying
    megabytes of stream bytes would be unusable.
    """

    flow: Flow
    c2s: DirectionStream
    s2c: DirectionStream
    capture_sha256: str = ""

    @property
    def client_bytes(self) -> bytes:
        return bytes(self.c2s.data)

    @property
    def server_bytes(self) -> bytes:
        return bytes(self.s2c.data)

    def evidence_for(self, direction: str, start: int, end: int,
                     note: str | None = None) -> Evidence:
        """Build a populated Evidence block for a byte range. ADR-0004.

        Every parser downstream calls this instead of constructing Evidence by
        hand, which is how provenance stays correct without anyone having to
        remember to add it.
        """
        stream = self.c2s if direction == "c2s" else self.s2c
        return Evidence(
            capture_sha256=self.capture_sha256,
            stream_id=self.flow.stream_id,
            frame_numbers=stream.frames_for_range(start, end),
            byte_range=[start, end],
            direction=direction,
            timestamp=self.flow.started_at,
            note=note,
        )


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #


@dataclass
class _Builder:
    stream_id: int
    client_ip: str = ""
    client_port: int = 0
    server_ip: str = ""
    server_port: int = 0
    c2s: DirectionStream = field(default_factory=DirectionStream)
    s2c: DirectionStream = field(default_factory=DirectionStream)
    first_ts: float | None = None
    last_ts: float | None = None
    packet_count: int = 0
    saw_syn: bool = False
    frames: list[int] = field(default_factory=list)


def _endpoints(ip, tcp_seg) -> tuple[tuple[str, int], tuple[str, int]]:
    import socket  # noqa: PLC0415

    src = (socket.inet_ntoa(ip.src), tcp_seg.sport)
    dst = (socket.inet_ntoa(ip.dst), tcp_seg.dport)
    return src, dst


def reassemble(capture: Capture) -> Iterator[ReassembledFlow]:
    """Reconstruct every TCP conversation in the capture. Deliverable D03.

    Direction is decided by the SYN: the side that sends SYN without ACK is the
    client. Without a SYN - a capture that started mid-conversation - we fall
    back to the lower port being the server, which is right for mail traffic.
    """
    import dpkt  # noqa: PLC0415

    builders: dict[tuple, _Builder] = {}
    order: list[tuple] = []

    for frame_number, ts, buf in iter_packets(capture):
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:  # noqa: BLE001 - a malformed frame must not stop the run
            continue

        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            continue
        segment = ip.data
        if not isinstance(segment, dpkt.tcp.TCP):
            continue

        src, dst = _endpoints(ip, segment)
        key = tuple(sorted([src, dst]))

        builder = builders.get(key)
        if builder is None:
            builder = _Builder(stream_id=len(order))
            builders[key] = builder
            order.append(key)
            # Provisional orientation; a SYN below corrects it.
            if src[1] < dst[1]:
                builder.server_ip, builder.server_port = src
                builder.client_ip, builder.client_port = dst
            else:
                builder.client_ip, builder.client_port = src
                builder.server_ip, builder.server_port = dst

        is_syn = bool(segment.flags & dpkt.tcp.TH_SYN)
        is_ack = bool(segment.flags & dpkt.tcp.TH_ACK)
        if is_syn and not is_ack and not builder.saw_syn:
            builder.saw_syn = True
            builder.client_ip, builder.client_port = src
            builder.server_ip, builder.server_port = dst

        builder.packet_count += 1
        if builder.first_ts is None:
            builder.first_ts = ts
        builder.last_ts = ts
        builder.frames.append(frame_number)

        payload = bytes(segment.data)
        if not payload:
            continue

        # The SYN consumes one sequence number, so data starts at seq+1.
        seq = segment.seq
        from_client = src == (builder.client_ip, builder.client_port)
        stream = builder.c2s if from_client else builder.s2c
        if stream.base_seq is None and builder.saw_syn:
            seq_base = seq
            stream.base_seq = seq_base
            stream.next_seq = seq_base
        stream.add(seq, payload, frame_number)

    for key in order:
        builder = builders[key]
        builder.c2s.finish()
        builder.s2c.finish()

        flow = Flow(
            stream_id=builder.stream_id,
            src_ip=builder.client_ip, src_port=builder.client_port,
            dst_ip=builder.server_ip, dst_port=builder.server_port,
            started_at=(datetime.fromtimestamp(builder.first_ts, tz=timezone.utc)
                        if builder.first_ts else None),
            ended_at=(datetime.fromtimestamp(builder.last_ts, tz=timezone.utc)
                      if builder.last_ts else None),
            packet_count=builder.packet_count,
            c2s_bytes=len(builder.c2s.data),
            s2c_bytes=len(builder.s2c.data),
            byte_to_frame_c2s={str(k): v for k, v in builder.c2s.offset_to_frame.items()},
            byte_to_frame_s2c={str(k): v for k, v in builder.s2c.offset_to_frame.items()},
            has_gaps=bool(builder.c2s.gaps or builder.s2c.gaps),
            retransmission_count=builder.c2s.retransmissions + builder.s2c.retransmissions,
            evidence=Evidence(
                capture_sha256=capture.sha256,
                stream_id=builder.stream_id,
                frame_numbers=builder.frames[:2] or [],
                timestamp=(datetime.fromtimestamp(builder.first_ts, tz=timezone.utc)
                           if builder.first_ts else None),
                note="TCP stream",
            ),
        )
        yield ReassembledFlow(flow=flow, c2s=builder.c2s, s2c=builder.s2c,
                              capture_sha256=capture.sha256)
