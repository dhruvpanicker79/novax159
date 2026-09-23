"""A minimal DER reader, stdlib only.

`cryptography` would normally do this, but Smart App Control blocks its Rust
extension on the team's machines and `openssl` is blocked too (ADR-0012), so
S5 needs a path that does not depend on either. This is that path: enough
ASN.1 to read an X.509 certificate, and no more.

Scope, stated plainly: DER only, definite-length only, no BER, no streaming.
That is exactly what certificates on the wire use, so the restriction costs us
nothing and keeps the parser small enough to audit.

Everything is bounds-checked. A truncated certificate - common in a capture
that stopped mid-transfer - yields what could be read rather than raising.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

# Universal tags
BOOLEAN = 0x01
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OBJECT_IDENTIFIER = 0x06
UTF8_STRING = 0x0C
PRINTABLE_STRING = 0x13
IA5_STRING = 0x16
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18
SEQUENCE = 0x30
SET = 0x31

_STRING_TAGS = {UTF8_STRING, PRINTABLE_STRING, IA5_STRING, 0x14, 0x1E, 0x1A}

#: Certificates larger than this are not certificates. Guards a malformed
#: length field from causing a huge allocation.
MAX_ELEMENT = 1 << 20


class DerError(ValueError):
    """Malformed DER. Callers are expected to catch and degrade."""


@dataclass(frozen=True)
class Element:
    """One TLV, with its position so evidence can point at it."""

    tag: int
    value: bytes
    offset: int          #: start of the tag byte
    header_length: int
    declared_length: int = -1   #: what the length field said, before clipping

    def __post_init__(self) -> None:
        if self.declared_length < 0:
            object.__setattr__(self, "declared_length", len(self.value))

    @property
    def truncated(self) -> bool:
        """The element declared more bytes than the buffer actually held.

        Worth surfacing rather than swallowing: a certificate cut short by a
        capture that stopped mid-transfer will parse into something that looks
        empty, and "no subjectAltName" reads very differently from "we only
        received half of this certificate".
        """
        return len(self.value) < self.declared_length

    @property
    def is_constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def total_length(self) -> int:
        return self.header_length + len(self.value)

    @property
    def children(self) -> list[Element]:
        """Sub-elements, for a constructed type. Empty for primitives."""
        if not self.is_constructed:
            return []
        return parse_all(self.value, base_offset=self.offset + self.header_length)

    def child(self, index: int) -> Element | None:
        kids = self.children
        return kids[index] if index < len(kids) else None


def parse(data: bytes, offset: int = 0, base_offset: int = 0) -> Element:
    """Read one element starting at `offset`."""
    if offset + 2 > len(data):
        raise DerError("truncated element header")

    tag = data[offset]
    length_byte = data[offset + 1]
    cursor = offset + 2

    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0:
            raise DerError("indefinite length is not valid DER")
        if cursor + count > len(data):
            raise DerError("truncated length field")
        length = int.from_bytes(data[cursor: cursor + count], "big")
        cursor += count
    else:
        length = length_byte

    if length > MAX_ELEMENT:
        raise DerError(f"implausible element length {length}")

    value = data[cursor: cursor + length]
    return Element(tag=tag, value=value, offset=base_offset + offset,
                   header_length=cursor - offset, declared_length=length)


def parse_all(data: bytes, base_offset: int = 0) -> list[Element]:
    """Read every element in a buffer, stopping cleanly at damage."""
    out: list[Element] = []
    offset = 0
    while offset < len(data):
        try:
            element = parse(data, offset, base_offset)
        except DerError:
            break
        if element.truncated:
            # Nothing useful follows a short element: the buffer ended inside
            # it, so any bytes after would be a misread. Stop, and let the
            # caller see the truncation on the element it did get.
            out.append(element)
            break
        out.append(element)
        step = element.total_length
        if step <= 0:
            break
        offset += step
    return out


# --------------------------------------------------------------------------- #
# Value decoding
# --------------------------------------------------------------------------- #


def decode_oid(value: bytes) -> str:
    """Dotted-decimal form of an OBJECT IDENTIFIER."""
    if not value:
        return ""
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    current = 0
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(current))
            current = 0
    return ".".join(parts)


def decode_integer(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=True) if value else 0


def decode_string(element: Element) -> str:
    return element.value.decode("utf-8", errors="replace")


def decode_time(element: Element) -> datetime | None:
    """UTCTime or GeneralizedTime.

    UTCTime carries a two-digit year, so RFC 5280 says 50-99 means 19xx and
    00-49 means 20xx. A certificate issued in 2049 and one in 1951 are only
    distinguishable by that rule.
    """
    text = element.value.decode("ascii", errors="replace").strip()
    try:
        if element.tag == UTC_TIME:
            if not text.endswith("Z") or len(text) < 11:
                return None
            body = text[:-1]
            year = int(body[0:2])
            year += 1900 if year >= 50 else 2000
            rest = body[2:]
            month, day, hour, minute = (int(rest[0:2]), int(rest[2:4]),
                                        int(rest[4:6]), int(rest[6:8]))
            second = int(rest[8:10]) if len(rest) >= 10 else 0
        else:
            body = text[:-1] if text.endswith("Z") else text
            year, month, day = int(body[0:4]), int(body[4:6]), int(body[6:8])
            hour, minute = int(body[8:10]), int(body[10:12])
            second = int(body[12:14]) if len(body) >= 14 else 0
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None


def decode_bitstring(value: bytes) -> bytes:
    """Strip the leading unused-bits count. Certificates always use 0 here."""
    return value[1:] if value else b""


# --------------------------------------------------------------------------- #
# Distinguished names
# --------------------------------------------------------------------------- #

ATTRIBUTE_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC",
}


@dataclass
class DistinguishedName:
    """A parsed Name, with the attributes we care about pulled out."""

    attributes: list[tuple[str, str]] = field(default_factory=list)

    @property
    def common_name(self) -> str | None:
        for key, value in self.attributes:
            if key == "CN":
                return value
        return None

    def rfc4514(self) -> str:
        """Conventional display order: most specific first."""
        return ", ".join(f"{key}={value}" for key, value in reversed(self.attributes))

    def __str__(self) -> str:
        return self.rfc4514()

    def __eq__(self, other: object) -> bool:
        """Compare by attribute content, which is how chain linking works."""
        if not isinstance(other, DistinguishedName):
            return NotImplemented
        return self._normalised() == other._normalised()

    def __hash__(self) -> int:
        return hash(self._normalised())

    def _normalised(self) -> tuple:
        # Case-insensitive, whitespace-collapsed, per RFC 5280 name matching.
        return tuple(sorted((k, " ".join(v.split()).lower())
                            for k, v in self.attributes))


def parse_name(element: Element) -> DistinguishedName:
    """Name ::= SEQUENCE OF RelativeDistinguishedName."""
    name = DistinguishedName()
    for rdn in element.children:
        for attribute in rdn.children:
            kids = attribute.children
            if len(kids) < 2:
                continue
            oid = decode_oid(kids[0].value)
            label = ATTRIBUTE_NAMES.get(oid, oid)
            name.attributes.append((label, decode_string(kids[1])))
    return name
