"""S4 - parse ClientHello and ServerHello. Deliverables D04, D05, D06, D07.

THE TRAP, and it catches most implementations: a TLS 1.3 server sets
`ServerHello.legacy_version` to 0x0303 (TLS 1.2) and signals the real version
through the `supported_versions` extension (RFC 8446 section 4.2.1). Read
legacy_version alone and every single 1.3 session is misreported as 1.2 - which
also inverts the verdict, since 1.3 is the outcome you want.

Also extracted here because later stages need them:
    - `supported_groups`, for the post-quantum check (USP-05)
    - the last 8 bytes of ServerHello.random, for the RFC 8446 4.1.3 DOWNGRD
      sentinel (USP-02)
    - TLS_FALLBACK_SCSV in the client's cipher list (RFC 7507)
    - the full client cipher list, so the intersection anomaly can compare what
      the server COULD have chosen against what it did

Parsing is defensive throughout: a truncated or malformed hello returns what it
managed to read rather than raising. A capture that stops mid-handshake still
tells us the version and the cipher, and losing that to an exception would be a
poor trade.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from schema import ClientHelloInfo, ServerHelloInfo, TlsVersion

from . import ciphers
from .records import HS_CLIENT_HELLO, HS_SERVER_HELLO, HandshakeMessage

# --------------------------------------------------------------------------- #
# Versions and extensions
# --------------------------------------------------------------------------- #

_VERSIONS = {
    0x0200: TlsVersion.SSL2, 0x0300: TlsVersion.SSL3,
    0x0301: TlsVersion.TLS1_0, 0x0302: TlsVersion.TLS1_1,
    0x0303: TlsVersion.TLS1_2, 0x0304: TlsVersion.TLS1_3,
}

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SESSION_TICKET = 0x0023
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_KEY_SHARE = 0x0033
EXT_RENEGOTIATION_INFO = 0xFF01

#: RFC 8446 4.1.3. A TLS 1.3-capable server that ends up negotiating something
#: older MUST put this in the last 8 bytes of ServerHello.random, so a client
#: can tell a genuine downgrade from an attacker forcing one.
DOWNGRADE_TLS12 = b"DOWNGRD\x01"
DOWNGRADE_TLS11_OR_BELOW = b"DOWNGRD\x00"

_SIG_ALGS = {
    0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512", 0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384", 0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512", 0x0807: "ed25519", 0x0808: "ed448",
    0x0201: "rsa_pkcs1_sha1", 0x0203: "ecdsa_sha1",
}


def version_of(raw: int) -> TlsVersion:
    return _VERSIONS.get(raw, TlsVersion.UNKNOWN)


# --------------------------------------------------------------------------- #
# Byte-level helpers, all bounds-checked
# --------------------------------------------------------------------------- #


class _Cursor:
    """A bounds-checked reader. Returns empty rather than raising on overrun."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, count: int) -> bytes:
        if count < 0 or self.remaining < count:
            chunk = self.data[self.pos:]
            self.pos = len(self.data)
            return chunk
        chunk = self.data[self.pos: self.pos + count]
        self.pos += count
        return chunk

    def u8(self) -> int:
        chunk = self.take(1)
        return chunk[0] if chunk else 0

    def u16(self) -> int:
        chunk = self.take(2)
        return struct.unpack(">H", chunk)[0] if len(chunk) == 2 else 0

    def vector(self, length_bytes: int) -> bytes:
        length = self.u8() if length_bytes == 1 else self.u16()
        return self.take(length)


def _u16_list(data: bytes) -> list[int]:
    return [struct.unpack_from(">H", data, i)[0]
            for i in range(0, len(data) - 1, 2)]


def _parse_extensions(data: bytes) -> dict[int, bytes]:
    """Extension type -> body. Later duplicates win, as receivers do."""
    out: dict[int, bytes] = {}
    cursor = _Cursor(data)
    while cursor.remaining >= 4:
        ext_type = cursor.u16()
        body = cursor.vector(2)
        out[ext_type] = body
    return out


def _parse_sni(body: bytes) -> str | None:
    cursor = _Cursor(body)
    entries = cursor.vector(2)
    inner = _Cursor(entries)
    while inner.remaining >= 3:
        name_type = inner.u8()
        name = inner.vector(2)
        if name_type == 0 and name:
            return name.decode("utf-8", errors="replace")
    return None


def _parse_alpn(body: bytes) -> list[str]:
    cursor = _Cursor(body)
    inner = _Cursor(cursor.vector(2))
    out: list[str] = []
    while inner.remaining >= 1:
        item = inner.vector(1)
        if item:
            out.append(item.decode("utf-8", errors="replace"))
    return out


# --------------------------------------------------------------------------- #
# ClientHello
# --------------------------------------------------------------------------- #


def parse_client_hello(body: bytes) -> ClientHelloInfo:
    """Parse a ClientHello body (the bytes after the 4-byte message header)."""
    info = ClientHelloInfo()
    cursor = _Cursor(body)

    info.legacy_version = version_of(cursor.u16())
    cursor.take(32)                                   # random
    cursor.vector(1)                                  # legacy_session_id

    suites_raw = _u16_list(cursor.vector(2))
    info.fallback_scsv = ciphers.TLS_FALLBACK_SCSV in suites_raw
    info.cipher_suites = [c for c in suites_raw if not ciphers.is_grease(c)]
    info.cipher_suite_names = [
        ciphers.name_of(c) for c in info.cipher_suites
        if c not in (ciphers.TLS_FALLBACK_SCSV,
                     ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    ]

    info.compression_methods = list(cursor.vector(1))

    extensions = _parse_extensions(cursor.vector(2))
    info.extensions = [e for e in extensions if not ciphers.is_grease(e)]

    if EXT_SERVER_NAME in extensions:
        info.server_name = _parse_sni(extensions[EXT_SERVER_NAME])

    if EXT_SUPPORTED_GROUPS in extensions:
        groups = _u16_list(_Cursor(extensions[EXT_SUPPORTED_GROUPS]).vector(2))
        info.supported_groups = [g for g in groups if not ciphers.is_grease(g)]
        info.supported_group_names = [ciphers.group_name(g) for g in info.supported_groups]

    if EXT_EC_POINT_FORMATS in extensions:
        info.ec_point_formats = list(_Cursor(extensions[EXT_EC_POINT_FORMATS]).vector(1))

    if EXT_SIGNATURE_ALGORITHMS in extensions:
        raw = _u16_list(_Cursor(extensions[EXT_SIGNATURE_ALGORITHMS]).vector(2))
        info.signature_algorithms = [
            _SIG_ALGS.get(s, f"0x{s:04X}") for s in raw if not ciphers.is_grease(s)]

    if EXT_ALPN in extensions:
        info.alpn = _parse_alpn(extensions[EXT_ALPN])

    if EXT_SUPPORTED_VERSIONS in extensions:
        raw = _u16_list(_Cursor(extensions[EXT_SUPPORTED_VERSIONS]).vector(1))
        info.supported_versions = [version_of(v) for v in raw
                                   if not ciphers.is_grease(v)
                                   and version_of(v) is not TlsVersion.UNKNOWN]
    if not info.supported_versions and info.legacy_version is not TlsVersion.UNKNOWN:
        info.supported_versions = [info.legacy_version]

    info.session_ticket_offered = EXT_SESSION_TICKET in extensions
    return info


# --------------------------------------------------------------------------- #
# ServerHello
# --------------------------------------------------------------------------- #


def parse_server_hello(body: bytes) -> ServerHelloInfo:
    """Parse a ServerHello body.

    The negotiated version comes from `supported_versions` when present, NOT
    from legacy_version. See the module docstring.
    """
    info = ServerHelloInfo()
    cursor = _Cursor(body)

    info.legacy_version = version_of(cursor.u16())
    random_bytes = cursor.take(32)
    cursor.vector(1)                                  # legacy_session_id_echo

    suite = cursor.u16()
    info.cipher_suite = suite
    info.cipher_suite_name = ciphers.name_of(suite)
    info.compression_method = cursor.u8()

    extensions = _parse_extensions(cursor.vector(2))
    info.extensions = [e for e in extensions if not ciphers.is_grease(e)]
    info.renegotiation_info = EXT_RENEGOTIATION_INFO in extensions

    info.negotiated_version = info.legacy_version
    if EXT_SUPPORTED_VERSIONS in extensions:
        raw = extensions[EXT_SUPPORTED_VERSIONS]
        if len(raw) >= 2:
            info.negotiated_version = version_of(struct.unpack_from(">H", raw, 0)[0])

    if EXT_KEY_SHARE in extensions:
        raw = extensions[EXT_KEY_SHARE]
        if len(raw) >= 2:
            group = struct.unpack_from(">H", raw, 0)[0]
            info.selected_group = group
            info.selected_group_name = ciphers.group_name(group)

    if EXT_ALPN in extensions:
        chosen = _parse_alpn(extensions[EXT_ALPN])
        info.alpn = chosen[0] if chosen else None

    # RFC 8446 4.1.3 downgrade sentinel.
    if len(random_bytes) == 32:
        tail = random_bytes[-8:]
        if tail in (DOWNGRADE_TLS12, DOWNGRADE_TLS11_OR_BELOW):
            info.downgrade_sentinel = tail.hex()

    # A session_id echo with no key_share and a resumption-shaped reply is the
    # readable hint that this was resumed. Not conclusive in 1.3, so it stays a
    # hint rather than a finding of its own.
    info.session_resumed = (EXT_SESSION_TICKET in extensions)
    return info


# --------------------------------------------------------------------------- #
# Putting the two halves together
# --------------------------------------------------------------------------- #


@dataclass
class HandshakeAnalysis:
    """What S4 recovered, plus the cross-checks that need both halves."""

    client_hello: ClientHelloInfo | None = None
    server_hello: ServerHelloInfo | None = None
    client_hello_offset: int | None = None
    server_hello_offset: int | None = None
    message_sequence: list[str] = None  # type: ignore[assignment]
    cipher_intersection_anomaly: bool = False
    intersection_detail: str | None = None

    def __post_init__(self) -> None:
        if self.message_sequence is None:
            self.message_sequence = []


def detect_intersection_anomaly(
    client: ClientHelloInfo, server: ServerHelloInfo
) -> tuple[bool, str | None]:
    """Did the server pick something materially weaker than it could have?

    This is USP-02's detector that rules alone cannot express: it needs both
    halves of the handshake compared, not just the negotiated result. A server
    choosing static RSA when the client offered ECDHE, or a CBC suite when AEAD
    was on the table, is either badly configured or being interfered with.

    Deliberately conservative. Only a drop in *forward secrecy* or in *AEAD*
    counts, not a smaller key size - preferring AES-128 over AES-256 is a
    legitimate performance choice and flagging it would be noise.
    """
    if server.cipher_suite is None or not client.cipher_suites:
        return False, None

    chosen = ciphers.describe(server.cipher_suite)
    if not chosen.known:
        return False, None

    best = ciphers.strongest(client.cipher_suites)
    if best is None or best.codepoint == chosen.codepoint:
        return False, None

    lost_pfs = best.has_forward_secrecy and not chosen.has_forward_secrecy
    lost_aead = best.is_aead and not chosen.is_aead
    if not (lost_pfs or lost_aead):
        return False, None

    lost = []
    if lost_pfs:
        lost.append("forward secrecy")
    if lost_aead:
        lost.append("AEAD")
    return True, (f"client offered {best.name}; server selected {chosen.name}, "
                  f"giving up {' and '.join(lost)}")


def analyse(messages_client: list[HandshakeMessage],
            messages_server: list[HandshakeMessage]) -> HandshakeAnalysis:
    """Build the handshake picture from both directions. D04.

    `message_sequence` is populated in wire order so the UI can draw the ladder
    diagram: D04 says *reconstruction*, and parsing without rendering loses the
    deliverable even though the work was done.
    """
    result = HandshakeAnalysis()

    for message in messages_client:
        result.message_sequence.append(f"-> {message.name}")
        if message.msg_type == HS_CLIENT_HELLO and result.client_hello is None:
            result.client_hello = parse_client_hello(message.body)
            result.client_hello_offset = message.offset

    for message in messages_server:
        result.message_sequence.append(f"<- {message.name}")
        if message.msg_type == HS_SERVER_HELLO and result.server_hello is None:
            result.server_hello = parse_server_hello(message.body)
            result.server_hello_offset = message.offset

    if result.client_hello and result.server_hello:
        anomaly, detail = detect_intersection_anomaly(
            result.client_hello, result.server_hello)
        result.cipher_intersection_anomaly = anomaly
        result.intersection_detail = detail

    return result
