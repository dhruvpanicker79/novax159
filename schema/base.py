"""Serialisation machinery for the SecureMailScope contract.

Deliberately stdlib-only (ADR-0009). Every module in the project imports the
schema, so the schema must never be the thing that fails to install.

Provides:
    - `Evidence`, the forensic provenance block carried by every object (USP-03)
    - `to_dict` / `from_dict`, recursive dataclass <-> plain-JSON conversion
    - `JsonModel`, a mixin giving every model `.to_dict()`, `.to_json()`,
      `.from_dict()` and `.from_json()`
"""

from __future__ import annotations

import json
import types
import typing
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TypeVar

T = TypeVar("T")

_NONE_TYPE = type(None)


# --------------------------------------------------------------------------- #
# Forensic provenance
# --------------------------------------------------------------------------- #


@dataclass
class Evidence:
    """Where in the capture this fact came from.

    This is USP-03 and ADR-0004. Every object in the model carries one of these,
    populated at construction time by the stage that produced the object. It is
    what lets the UI jump from a finding to the exact highlighted bytes, and
    what lets a third party re-open the PCAP in Wireshark and check our work.

    Retrofitting this after the parsers are written is painful, which is exactly
    why competing teams will not have it. Populate it as you go.

    Attributes:
        capture_sha256: Integrity hash of the source PCAP.
        stream_id: Index of the reconstructed TCP stream (stage S1).
        frame_numbers: Originating packet numbers, 1-based as Wireshark shows.
        byte_range: [start, end) offset within the reassembled direction stream.
        direction: "c2s" or "s2c"; which half of the conversation.
        timestamp: Wire time of the first contributing frame.
        note: Optional human-readable pointer, e.g. "ServerHello.random[24:32]".
    """

    capture_sha256: str = ""
    stream_id: int | None = None
    frame_numbers: list[int] = field(default_factory=list)
    byte_range: list[int] | None = None
    direction: str | None = None
    timestamp: datetime | None = None
    note: str | None = None

    @property
    def is_populated(self) -> bool:
        """True if this evidence can actually be used to find something."""
        return bool(self.capture_sha256) and bool(self.frame_numbers)

    def describe(self) -> str:
        """One-line human form, e.g. 'stream 14, frames 812-813, bytes 3480-3712'."""
        parts: list[str] = []
        if self.stream_id is not None:
            parts.append(f"stream {self.stream_id}")
        if self.frame_numbers:
            frames = sorted(self.frame_numbers)
            if len(frames) == 1:
                parts.append(f"frame {frames[0]}")
            elif frames == list(range(frames[0], frames[-1] + 1)):
                parts.append(f"frames {frames[0]}-{frames[-1]}")
            else:
                # Non-contiguous: list them. Printing "frames 4-8" for [4, 8]
                # would send an analyst looking at packets that are not ours.
                shown = ", ".join(str(f) for f in frames[:6])
                suffix = f" (+{len(frames) - 6} more)" if len(frames) > 6 else ""
                parts.append(f"frames {shown}{suffix}")
        if self.byte_range:
            parts.append(f"bytes {self.byte_range[0]}-{self.byte_range[1]}")
        if self.direction:
            parts.append(self.direction)
        return ", ".join(parts) if parts else "no evidence recorded"


# --------------------------------------------------------------------------- #
# Recursive conversion
# --------------------------------------------------------------------------- #


def to_dict(value: Any) -> Any:
    """Convert dataclasses, enums and datetimes into JSON-safe plain data.

    Keys with a `None` value are kept, so the JSON shape is stable and the
    frontend can rely on every documented field existing.
    """
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_dict(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return [to_dict(v) for v in value]
    if isinstance(value, dict):
        return {str(k): to_dict(v) for k, v in value.items()}
    return value


def _unwrap_optional(annotation: Any) -> tuple[Any, bool]:
    """Return (inner_type, was_optional) for `X | None` and `Optional[X]`."""
    origin = typing.get_origin(annotation)
    if origin is typing.Union or origin is types.UnionType:
        args = [a for a in typing.get_args(annotation) if a is not _NONE_TYPE]
        if len(args) == 1:
            return args[0], True
        # Genuine multi-type union: fall back to passthrough.
        return Any, True
    return annotation, False


def _coerce(annotation: Any, raw: Any) -> Any:
    """Convert one raw JSON value into the type its annotation asks for."""
    annotation, _ = _unwrap_optional(annotation)

    if raw is None or annotation is Any:
        return raw

    origin = typing.get_origin(annotation)

    if origin in (list, tuple):
        (item_type,) = typing.get_args(annotation) or (Any,)
        return [_coerce(item_type, item) for item in raw]

    if origin is dict:
        args = typing.get_args(annotation)
        value_type = args[1] if len(args) == 2 else Any
        return {k: _coerce(value_type, v) for k, v in raw.items()}

    if isinstance(annotation, type):
        if is_dataclass(annotation):
            return from_dict(annotation, raw)
        if issubclass(annotation, Enum):
            return annotation(raw)
        if annotation is datetime:
            return datetime.fromisoformat(raw)

    return raw


def from_dict(cls: type[T], data: dict[str, Any]) -> T:
    """Rebuild a dataclass from plain JSON data.

    Unknown keys are ignored rather than raising, so an older consumer can read
    a newer report. Missing keys fall back to the field's default.
    """
    if not is_dataclass(cls):
        raise TypeError(f"{cls!r} is not a dataclass")

    hints = typing.get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for f in fields(cls):
        if f.name not in data:
            continue
        kwargs[f.name] = _coerce(hints.get(f.name, Any), data[f.name])
    return cls(**kwargs)  # type: ignore[return-value]


# --------------------------------------------------------------------------- #
# Mixin
# --------------------------------------------------------------------------- #


class JsonModel:
    """Give a dataclass symmetrical JSON conversion.

    Usage:
        @dataclass
        class Thing(JsonModel):
            name: str = ""
    """

    def to_dict(self) -> dict[str, Any]:
        return to_dict(self)

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        return from_dict(cls, data)

    @classmethod
    def from_json(cls: type[T], text: str) -> T:
        return from_dict(cls, json.loads(text))
