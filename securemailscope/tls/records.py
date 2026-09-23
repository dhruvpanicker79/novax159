"""S4 - the TLS record layer.

Records do not align with TCP segments, which is exactly why S1 hands us a
reassembled stream rather than packets. A single handshake message can span
several records, and several messages can share one record - both happen in
the wild and both are handled here.

Every yielded item carries its offset within the reassembled stream, so the
caller can turn it into an `Evidence` byte range (ADR-0004). That is the whole
reason this returns offsets rather than just bytes.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass

CONTENT_CHANGE_CIPHER_SPEC = 0x14
CONTENT_ALERT = 0x15
CONTENT_HANDSHAKE = 0x16
CONTENT_APPLICATION_DATA = 0x17

HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_NEW_SESSION_TICKET = 0x04
HS_ENCRYPTED_EXTENSIONS = 0x08
HS_CERTIFICATE = 0x0B
HS_SERVER_KEY_EXCHANGE = 0x0C
HS_CERTIFICATE_REQUEST = 0x0D
HS_SERVER_HELLO_DONE = 0x0E
HS_CERTIFICATE_VERIFY = 0x0F
HS_CLIENT_KEY_EXCHANGE = 0x10
HS_FINISHED = 0x14

HANDSHAKE_NAMES = {
    HS_CLIENT_HELLO: "ClientHello",
    HS_SERVER_HELLO: "ServerHello",
    HS_NEW_SESSION_TICKET: "NewSessionTicket",
    HS_ENCRYPTED_EXTENSIONS: "EncryptedExtensions",
    HS_CERTIFICATE: "Certificate",
    HS_SERVER_KEY_EXCHANGE: "ServerKeyExchange",
    HS_CERTIFICATE_REQUEST: "CertificateRequest",
    HS_SERVER_HELLO_DONE: "ServerHelloDone",
    HS_CERTIFICATE_VERIFY: "CertificateVerify",
    HS_CLIENT_KEY_EXCHANGE: "ClientKeyExchange",
    HS_FINISHED: "Finished",
}

ALERT_LEVELS = {1: "warning", 2: "fatal"}
ALERT_DESCRIPTIONS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
    47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied",
    50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
    90: "user_canceled", 109: "missing_extension", 112: "unrecognized_name",
    116: "certificate_required", 120: "no_application_protocol",
}

#: A record body larger than this is not a real TLS record; it is a text stream
#: that happens to start with 0x16. Guards against runaway allocation.
MAX_RECORD_LENGTH = 1 << 14 | 2048


@dataclass(frozen=True)
class Record:
    content_type: int
    legacy_version: int
    fragment: bytes
    offset: int          #: start of the record header within the stream

    @property
    def is_handshake(self) -> bool:
        return self.content_type == CONTENT_HANDSHAKE


@dataclass(frozen=True)
class HandshakeMessage:
    msg_type: int
    body: bytes
    offset: int          #: start of the message within the stream

    @property
    def name(self) -> str:
        return HANDSHAKE_NAMES.get(self.msg_type, f"Unknown(0x{self.msg_type:02X})")


def looks_like_record(data: bytes, at: int = 0) -> bool:
    """Plausibility check: known content type and a sane legacy version."""
    if len(data) < at + 5:
        return False
    content_type = data[at]
    if content_type not in (CONTENT_CHANGE_CIPHER_SPEC, CONTENT_ALERT,
                            CONTENT_HANDSHAKE, CONTENT_APPLICATION_DATA):
        return False
    major, minor = data[at + 1], data[at + 2]
    return major == 0x03 and minor <= 0x04


def iter_records(stream: bytes, start: int = 0) -> Iterator[Record]:
    """Walk the record layer from `start`.

    Stops at the first thing that is not a plausible record rather than trying
    to resynchronise: once the stream is encrypted the bytes are opaque, and
    guessing at structure there would invent findings.
    """
    offset = start
    end = len(stream)
    while offset + 5 <= end:
        if not looks_like_record(stream, offset):
            return
        content_type, legacy_version, length = struct.unpack_from(">BHH", stream, offset)
        if length > MAX_RECORD_LENGTH:
            return
        body_start = offset + 5
        fragment = stream[body_start: body_start + length]
        yield Record(content_type, legacy_version, fragment, offset)
        if len(fragment) < length:
            return                      # truncated capture; stop cleanly
        offset = body_start + length


def iter_handshake_messages(stream: bytes,
                            start: int = 0) -> Iterator[HandshakeMessage]:
    """Yield handshake messages, re-joining records where a message spans them.

    Only unencrypted handshake records are readable. In TLS 1.3 everything from
    EncryptedExtensions onward is protected, so this naturally stops after
    ServerHello - which is correct, not a failure.
    """
    buffer = bytearray()
    #: buffer offset -> stream offset, so a message that spans records still
    #: reports where it really began.
    origins: list[tuple[int, int]] = []

    for record in iter_records(stream, start):
        if not record.is_handshake:
            if record.content_type in (CONTENT_CHANGE_CIPHER_SPEC,
                                       CONTENT_APPLICATION_DATA):
                break
            continue
        origins.append((len(buffer), record.offset + 5))
        buffer += record.fragment

        while len(buffer) >= 4:
            msg_type = buffer[0]
            length = int.from_bytes(buffer[1:4], "big")
            if len(buffer) < 4 + length:
                break                   # wait for the next record
            body = bytes(buffer[4: 4 + length])
            stream_offset = _origin_for(origins, 0)
            yield HandshakeMessage(msg_type, body, stream_offset)
            consumed = 4 + length
            del buffer[:consumed]
            origins = [(pos - consumed, src) for pos, src in origins if pos - consumed >= 0] \
                or [(0, stream_offset + consumed)]


def _origin_for(origins: list[tuple[int, int]], buffer_pos: int) -> int:
    """Translate a buffer position back to its offset in the stream."""
    best = 0
    for pos, src in origins:
        if pos <= buffer_pos:
            best = src + (buffer_pos - pos)
    return best


def find_alerts(stream: bytes, start: int = 0) -> list[str]:
    """Readable alerts. Only the unencrypted ones - the rest are opaque."""
    alerts: list[str] = []
    for record in iter_records(stream, start):
        if record.content_type == CONTENT_ALERT and len(record.fragment) >= 2:
            level = ALERT_LEVELS.get(record.fragment[0], str(record.fragment[0]))
            description = ALERT_DESCRIPTIONS.get(
                record.fragment[1], f"unknown({record.fragment[1]})")
            alerts.append(f"{level}: {description}")
    return alerts


def handshake_completed(client_stream: bytes, server_stream: bytes,
                        client_start: int = 0, server_start: int = 0) -> bool:
    """Did keys actually get agreed?

    ChangeCipherSpec or application data after the handshake is the passive
    proof. We cannot read the Finished message - it is encrypted - but we can
    see that protected records started flowing.
    """
    for stream, start in ((client_stream, client_start), (server_stream, server_start)):
        for record in iter_records(stream, start):
            if record.content_type in (CONTENT_CHANGE_CIPHER_SPEC,
                                       CONTENT_APPLICATION_DATA):
                return True
    return False
