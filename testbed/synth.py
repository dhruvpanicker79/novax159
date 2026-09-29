"""Craft PCAP files byte by byte, with no dependencies and no servers.

Why this exists. The Docker testbed produces the most realistic captures, but
it needs WSL2, Docker and old OpenSSL builds, and modern OpenSSL refuses to
negotiate exactly the suites we most want to test. This module writes the
packets directly instead, which buys three things:

    1. Test data for S0-S4 today, before the environment is sorted out.
    2. Total control over the bytes - RC4, SSLv3, a mangled STARTTLS
       capability, a DOWNGRD sentinel - none of which a current OpenSSL will
       emit for us.
    3. The insurance policy. If a live capture misbehaves twenty minutes
       before the demo, one command regenerates the whole corpus.

It is not a replacement for the Docker testbed. Real captures catch things
hand-written ones cannot, so `testbed/manifest.json` remains the ground truth
and this is the fast path to it.

    python testbed/synth.py --out testbed/out

Checksums are computed properly so the files open cleanly in Wireshark. That
matters: the provenance claim in USP-03 is only convincing if a judge can open
the capture themselves and land on the frame we cited.
"""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- #
# PCAP container
# --------------------------------------------------------------------------- #

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1


def pcap_global_header() -> bytes:
    return struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)


def pcap_packet(ts: float, data: bytes) -> bytes:
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    return struct.pack("<IIII", sec, usec, len(data), len(data)) + data


# --------------------------------------------------------------------------- #
# Ethernet / IP / TCP
# --------------------------------------------------------------------------- #


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip_to_bytes(addr: str) -> bytes:
    return bytes(int(part) for part in addr.split("."))


def ethernet(src_mac: bytes, dst_mac: bytes, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", 0x0800) + payload


def ipv4(src: str, dst: str, payload: bytes, ident: int) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0x00, total_length, ident, 0x4000, 64, 6, 0,
        _ip_to_bytes(src), _ip_to_bytes(dst),
    )
    checksum = _checksum(header)
    header = header[:10] + struct.pack(">H", checksum) + header[12:]
    return header + payload


def tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    header = struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port, seq, ack, 0x50, flags, 64240, 0, 0,
    )
    pseudo = (_ip_to_bytes(src_ip) + _ip_to_bytes(dst_ip)
              + struct.pack(">BBH", 0, 6, len(header) + len(payload)))
    checksum = _checksum(pseudo + header + payload)
    header = header[:16] + struct.pack(">H", checksum) + header[18:]
    return header + payload


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

CLIENT_MAC = bytes.fromhex("0a0027000001")
SERVER_MAC = bytes.fromhex("0a0027000002")


# --------------------------------------------------------------------------- #
# TLS message construction
# --------------------------------------------------------------------------- #

def _u8(values: list[int]) -> bytes:
    return bytes(values)


def _u16_list(values: list[int]) -> bytes:
    return b"".join(struct.pack(">H", v) for v in values)


def _vector(data: bytes, length_bytes: int) -> bytes:
    if length_bytes == 1:
        return struct.pack(">B", len(data)) + data
    if length_bytes == 2:
        return struct.pack(">H", len(data)) + data
    return struct.pack(">I", len(data))[1:] + data


def _extension(ext_type: int, body: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(body)) + body


def _record(content_type: int, version: int, fragment: bytes) -> bytes:
    return struct.pack(">BHH", content_type, version, len(fragment)) + fragment


#: IANA supported-group codepoints we emit. The hybrid post-quantum group is
#: included so S4's USP-05 check has something to find. VERIFY the codepoint
#: against the IANA TLS Supported Groups registry before relying on it in a
#: claim - it is here to exercise the parser, not as an authority.
GROUP_X25519 = 0x001D
GROUP_SECP256R1 = 0x0017
GROUP_FFDHE2048 = 0x0100
GROUP_X25519_MLKEM768 = 0x11EC

TLS_FALLBACK_SCSV = 0x5600
DOWNGRADE_SENTINEL_12 = b"DOWNGRD\x01"


def client_hello(server_name: str, cipher_suites: list[int],
                 versions: list[int], groups: list[int],
                 fallback_scsv: bool = False,
                 record_version: int = 0x0301) -> bytes:
    """Build a complete ClientHello record."""
    suites = list(cipher_suites)
    if fallback_scsv:
        suites.append(TLS_FALLBACK_SCSV)

    sni_entry = b"\x00" + _vector(server_name.encode(), 2)
    extensions = b"".join([
        _extension(0x0000, _vector(sni_entry, 2)),                      # SNI
        _extension(0x000A, _vector(_u16_list(groups), 2)),              # supported_groups
        _extension(0x000B, _vector(_u8([0]), 1)),                       # ec_point_formats
        _extension(0x000D, _vector(_u16_list([0x0403, 0x0804, 0x0401]), 2)),
        _extension(0x002B, _vector(_u16_list(versions), 1)),            # supported_versions
    ])

    body = b"".join([
        struct.pack(">H", 0x0303),
        bytes(range(32)),                       # random, deterministic on purpose
        _vector(b"", 1),                        # session_id
        _vector(_u16_list(suites), 2),
        _vector(_u8([0]), 1),                   # compression: null
        _vector(extensions, 2),
    ])
    handshake = b"\x01" + _vector(body, 3)
    return _record(0x16, record_version, handshake)


def server_hello(cipher_suite: int, version: int,
                 negotiated_version: int | None = None,
                 downgrade_sentinel: bool = False,
                 renegotiation_info: bool = True,
                 selected_group: int | None = None) -> bytes:
    """Build a ServerHello record.

    `version` goes in legacy_version. For TLS 1.3, `negotiated_version` is
    signalled through the supported_versions extension instead - which is the
    trap S4 has to get right, so the synthetic corpus must contain it.
    """
    random_bytes = bytes(range(32, 64))
    if downgrade_sentinel:
        random_bytes = random_bytes[:24] + DOWNGRADE_SENTINEL_12

    extensions = b""
    if renegotiation_info:
        extensions += _extension(0xFF01, _vector(b"", 1))
    if negotiated_version is not None:
        extensions += _extension(0x002B, struct.pack(">H", negotiated_version))
    if selected_group is not None:
        extensions += _extension(0x0033, struct.pack(">H", selected_group) + _vector(b"\x04" * 32, 2))

    body = b"".join([
        struct.pack(">H", version),
        random_bytes,
        _vector(b"", 1),
        struct.pack(">H", cipher_suite),
        b"\x00",
        _vector(extensions, 2),
    ])
    handshake = b"\x02" + _vector(body, 3)
    return _record(0x16, 0x0303, handshake)


def certificate_message(der_blobs: list[bytes]) -> bytes:
    chain = b"".join(_vector(blob, 3) for blob in der_blobs)
    handshake = b"\x0b" + _vector(_vector(chain, 3), 3)
    return _record(0x16, 0x0303, handshake)


def load_cert_chain(name: str) -> list[bytes]:
    """Load a generated certificate chain, leaf first.

    Falls back to a single opaque blob when `testbed/certgen.py` has not been
    run, so the scenarios still produce a structurally valid capture - S5 will
    simply report the certificate as unparseable, which is itself the correct
    behaviour for garbage on the wire.
    """
    certs_dir = Path(__file__).resolve().parent / "certs"
    chain: list[bytes] = []
    for suffix in ("", ".1", ".2"):
        path = certs_dir / f"{name}{suffix}.der"
        if path.exists():
            chain.append(path.read_bytes())
    return chain or [b"\x30\x82\x01\x0a" + b"\xAB" * 260]


def change_cipher_spec() -> bytes:
    return _record(0x14, 0x0303, b"\x01")


def encrypted_application_data(size: int = 256) -> bytes:
    return _record(0x17, 0x0303, bytes((i * 7 + 13) % 256 for i in range(size)))


# --------------------------------------------------------------------------- #
# Session scripting
# --------------------------------------------------------------------------- #


@dataclass
class Turn:
    """One side sending some bytes."""

    from_client: bool
    data: bytes


@dataclass
class SessionScript:
    """A full TCP conversation, described as an ordered list of turns."""

    name: str
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    turns: list[Turn] = field(default_factory=list)
    start_time: float = 1_790_000_000.0

    def client(self, data: bytes | str) -> SessionScript:
        self.turns.append(Turn(True, data.encode() if isinstance(data, str) else data))
        return self

    def server(self, data: bytes | str) -> SessionScript:
        self.turns.append(Turn(False, data.encode() if isinstance(data, str) else data))
        return self


def render(script: SessionScript, ident_start: int = 1) -> list[bytes]:
    """Turn a script into Ethernet frames: handshake, data, teardown."""
    frames: list[bytes] = []
    ident = ident_start
    c_seq, s_seq = 1_000_000, 2_000_000

    def emit(from_client: bool, flags: int, payload: bytes) -> None:
        nonlocal ident, c_seq, s_seq
        if from_client:
            segment = tcp(script.client_ip, script.server_ip,
                          script.client_port, script.server_port,
                          c_seq, s_seq, flags, payload)
            packet = ipv4(script.client_ip, script.server_ip, segment, ident)
            frames.append(ethernet(CLIENT_MAC, SERVER_MAC, packet))
            c_seq += len(payload) or (1 if flags & (SYN | FIN) else 0)
        else:
            segment = tcp(script.server_ip, script.client_ip,
                          script.server_port, script.client_port,
                          s_seq, c_seq, flags, payload)
            packet = ipv4(script.server_ip, script.client_ip, segment, ident)
            frames.append(ethernet(SERVER_MAC, CLIENT_MAC, packet))
            s_seq += len(payload) or (1 if flags & (SYN | FIN) else 0)
        ident += 1

    emit(True, SYN, b"")
    emit(False, SYN | ACK, b"")
    emit(True, ACK, b"")

    for turn in script.turns:
        # Split large payloads across segments, so the reassembler is actually
        # exercised rather than always seeing one record per packet.
        data = turn.data
        while data:
            chunk, data = data[:1400], data[1400:]
            emit(turn.from_client, PSH | ACK, chunk)
        emit(not turn.from_client, ACK, b"")

    emit(True, FIN | ACK, b"")
    emit(False, FIN | ACK, b"")
    emit(True, ACK, b"")
    return frames


def write_pcap(path: Path, scripts: list[SessionScript]) -> Path:
    """Write one or more sessions into a single capture file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    out = bytearray(pcap_global_header())
    ident = 1
    for index, script in enumerate(scripts):
        ts = script.start_time + index * 5.0
        for offset, frame in enumerate(render(script, ident)):
            out += pcap_packet(ts + offset * 0.002, frame)
        ident += 2000
    path.write_bytes(bytes(out))
    return path


# --------------------------------------------------------------------------- #
# Scenario library
# --------------------------------------------------------------------------- #

MODERN_SUITES = [0x1302, 0x1301, 0xC030, 0xC02F]
RC4_SUITES = [0x0005, 0x0004]
TRIPLE_DES_SUITES = [0x000A]


def smtp_starttls_healthy(port: int = 587) -> SessionScript:
    s = SessionScript("smtp_starttls_healthy", "10.20.4.17", "10.20.1.11", 49201, port)
    s.server("220 mail-01.dept.gov.in ESMTP Postfix\r\n")
    s.client("EHLO client.dept.gov.in\r\n")
    s.server("250-mail-01.dept.gov.in\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n"
             "250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n250 CHUNKING\r\n")
    s.client("STARTTLS\r\n")
    s.server("220 2.0.0 Ready to start TLS\r\n")
    s.client(client_hello("mail-01.dept.gov.in", MODERN_SUITES,
                          [0x0304, 0x0303], [GROUP_X25519_MLKEM768, GROUP_X25519]))
    s.server(server_hello(0x1302, 0x0303, negotiated_version=0x0304,
                          selected_group=GROUP_X25519))
    # TLS 1.3 encrypts the Certificate message, so a passive observer sees
    # nothing here. That absence is the correct observation, not a gap.
    s.server(encrypted_application_data(320))
    s.client(encrypted_application_data(180))
    return s


def smtp_starttls_stripped(port: int = 587) -> SessionScript:
    """The demo's emotional peak.

    The capability keyword is overwritten in place with a same-length
    placeholder so TCP sequence numbers stay valid, the client gives up on the
    upgrade, and then authenticates in the clear.

    Base64 below decodes to r.sharma@dept.gov.in / MonsoonRain#24 - a made-up
    account for the test corpus.
    """
    s = SessionScript("smtp_starttls_stripped", "10.20.4.17", "10.20.1.15", 49202, port)
    s.server("220 mail-05.dept.gov.in ESMTP Postfix\r\n")
    s.client("EHLO client.dept.gov.in\r\n")
    s.server("250-mail-05.dept.gov.in\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n"
             "250-XXXXXXXA\r\n250-AUTH LOGIN PLAIN\r\n250 CHUNKING\r\n")
    s.client("AUTH LOGIN\r\n")
    s.server("334 VXNlcm5hbWU6\r\n")
    s.client("ci5zaGFybWFAZGVwdC5nb3YuaW4=\r\n")
    s.server("334 UGFzc3dvcmQ6\r\n")
    s.client("TW9uc29vblJhaW4jMjQ=\r\n")
    s.server("235 2.7.0 Authentication successful\r\n")
    s.client("MAIL FROM:<r.sharma@dept.gov.in>\r\n")
    s.server("250 2.1.0 Ok\r\n")
    return s


def imaps_implicit_weak(port: int = 993) -> SessionScript:
    """Implicit TLS with TLS 1.0 and RC4 - no cleartext phase at all."""
    s = SessionScript("imaps_implicit_weak", "10.20.4.17", "10.20.1.16", 49203, port)
    s.client(client_hello("mail-compromised.test", RC4_SUITES + MODERN_SUITES,
                          [0x0303, 0x0301], [GROUP_SECP256R1]))
    s.server(server_hello(0x0005, 0x0301, renegotiation_info=False))
    s.server(certificate_message(load_cert_chain("expired_selfsigned")))
    s.server(change_cipher_spec())
    s.server(encrypted_application_data(200))
    return s


def imaps_downgrade(port: int = 993) -> SessionScript:
    """A 1.3-capable server negotiating 1.2 and setting the DOWNGRD sentinel."""
    s = SessionScript("imaps_downgrade", "10.20.4.17", "10.20.1.17", 49204, port)
    s.client(client_hello("mail-healthy.test", MODERN_SUITES,
                          [0x0304, 0x0303], [GROUP_X25519, GROUP_FFDHE2048],
                          fallback_scsv=True))
    # The server picks TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009D): static RSA key
    # exchange, so the session loses forward secrecy even though the client
    # offered ECDHE and TLS 1.3. That is what the intersection anomaly detects -
    # a weaker choice than both sides supported, invisible to any rule that only
    # looks at the negotiated suite.
    s.server(server_hello(0x009D, 0x0303, downgrade_sentinel=True,
                          selected_group=GROUP_FFDHE2048))
    s.server(certificate_message(load_cert_chain("valid")))
    s.server(encrypted_application_data(256))
    return s


def imap_advertised_not_used(port: int = 143) -> SessionScript:
    s = SessionScript("imap_advertised_not_used", "10.20.4.17", "10.20.1.15", 49205, port)
    s.server("* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] mail-05 ready\r\n")
    s.client("a001 CAPABILITY\r\n")
    s.server("* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n"
             "a001 OK CAPABILITY completed\r\n")
    s.client("a002 LOGIN r.sharma@dept.gov.in MonsoonRain#24\r\n")
    s.server("a002 OK LOGIN completed\r\n")
    return s


def pop3_starttls_healthy(port: int = 110) -> SessionScript:
    s = SessionScript("pop3_starttls_healthy", "10.20.4.17", "10.20.1.18", 49206, port)
    s.server("+OK mail-08.dept.gov.in POP3 ready\r\n")
    s.client("CAPA\r\n")
    s.server("+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n")
    s.client("STLS\r\n")
    s.server("+OK Begin TLS negotiation\r\n")
    s.client(client_hello("mail-08.dept.gov.in", MODERN_SUITES,
                          [0x0304, 0x0303], [GROUP_X25519]))
    s.server(server_hello(0x1301, 0x0303, negotiated_version=0x0304))
    s.server(encrypted_application_data(160))
    return s


def imaps_tls12_valid_chain(port: int = 993) -> SessionScript:
    """TLS 1.2 with a complete, valid, properly signed chain.

    The S5 happy path: unlike TLS 1.3, the Certificate message is in the clear,
    so the full chain is observable and verifiable.
    """
    s = SessionScript("imaps_tls12_valid_chain", "10.20.4.17", "10.20.1.20", 49208, port)
    s.client(client_hello("mail-healthy.test", MODERN_SUITES,
                          [0x0303], [GROUP_X25519, GROUP_SECP256R1]))
    s.server(server_hello(0xC030, 0x0303))
    s.server(certificate_message(load_cert_chain("valid")))
    s.server(change_cipher_spec())
    s.server(encrypted_application_data(220))
    return s


def imaps_expiring_cert(port: int = 993) -> SessionScript:
    """1024-bit RSA key, SHA-1 signature, nine days of validity left."""
    s = SessionScript("imaps_expiring_cert", "10.20.4.17", "10.20.1.21", 49209, port)
    s.client(client_hello("mail-degraded.test", MODERN_SUITES,
                          [0x0303], [GROUP_X25519]))
    s.server(server_hello(0xC027, 0x0303))
    s.server(certificate_message(load_cert_chain("expiring")))
    s.server(encrypted_application_data(200))
    return s


def smtp_relay_expired_cert(port: int = 25) -> SessionScript:
    """The other half of the USP-01 side-by-side.

    This presents the EXACT SAME expired self-signed certificate as
    `imaps_implicit_weak` on port 993. On a mail-access port that certificate
    is critical - credentials cross the session and RFC 8314 requires a
    validated certificate. Here on port 25 it is informational, because
    MTA-to-MTA TLS is opportunistic (RFC 7435) and the sender has no trust
    anchor for the receiver.

    Same bytes, opposite verdicts. Do not change one scenario without the
    other: `scripts/audit.py` checks that a rule still produces two different
    severities, and the dashboard's USP-01 panel builds itself from that.
    """
    s = SessionScript("smtp_relay_expired_cert", "203.0.113.9", "10.20.1.22", 51001, port)
    s.server("220 mail-compromised.test ESMTP Postfix\r\n")
    s.client("EHLO relay.partner.example\r\n")
    s.server("250-mail-compromised.test\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 CHUNKING\r\n")
    s.client("STARTTLS\r\n")
    s.server("220 2.0.0 Ready to start TLS\r\n")
    s.client(client_hello("mail-compromised.test", MODERN_SUITES,
                          [0x0303], [GROUP_X25519]))
    s.server(server_hello(0xC02F, 0x0303))
    s.server(certificate_message(load_cert_chain("expired_selfsigned")))
    s.server(change_cipher_spec())
    s.server(encrypted_application_data(180))
    return s


def imaps_cert_substitution_a(port: int = 993) -> SessionScript:
    """First of a pair: the same host presenting two different certificates.

    Within one capture, one server identity offering two distinct leaf
    certificates is either an unmanaged rotation nobody approved or active
    interception. Detecting it needs cross-session memory, which no
    single-session rule can have (USP-02).
    """
    s = SessionScript("imaps_cert_substitution_a", "10.20.4.17", "10.20.1.23", 49210, port)
    s.client(client_hello("mail-healthy.test", MODERN_SUITES, [0x0303], [GROUP_X25519]))
    s.server(server_hello(0xC030, 0x0303))
    s.server(certificate_message(load_cert_chain("valid")))
    s.server(encrypted_application_data(160))
    return s


def imaps_cert_substitution_b(port: int = 993) -> SessionScript:
    """Second of the pair: same host and port, a different certificate."""
    s = SessionScript("imaps_cert_substitution_b", "10.20.4.18", "10.20.1.23", 49211, port)
    s.client(client_hello("mail-healthy.test", MODERN_SUITES, [0x0303], [GROUP_X25519]))
    s.server(server_hello(0xC030, 0x0303))
    s.server(certificate_message(load_cert_chain("missing_intermediate")))
    s.server(encrypted_application_data(160))
    return s


def smtp_relay_cleartext(port: int = 25) -> SessionScript:
    """Opportunistic relay with no upgrade. The USP-01 negative control."""
    s = SessionScript("smtp_relay_cleartext", "203.0.113.9", "10.20.1.12", 51000, port)
    s.server("220 mail-02.dept.gov.in ESMTP Postfix\r\n")
    s.client("EHLO relay.partner.example\r\n")
    s.server("250-mail-02.dept.gov.in\r\n250-STARTTLS\r\n250 CHUNKING\r\n")
    s.client("MAIL FROM:<sender@partner.example>\r\n")
    s.server("250 2.1.0 Ok\r\n")
    s.client("RCPT TO:<r.sharma@dept.gov.in>\r\n")
    s.server("250 2.1.5 Ok\r\n")
    return s


def imaps_mid_session(port: int = 993) -> SessionScript:
    """A capture that began AFTER the handshake completed.

    Common in real forensics: recording starts on an already-established
    session, so the first bytes are protected application data and there is no
    handshake to parse. The right answer is "encrypted, uninspectable" - never
    "cleartext", and never a clean bill of health.
    """
    s = SessionScript("imaps_mid_session", "10.20.4.17", "10.20.1.19", 49207, port)
    s.server(encrypted_application_data(512))
    s.client(encrypted_application_data(128))
    s.server(encrypted_application_data(384))
    return s


# ── the "same estate, later" pair (USP-10) ────────────────────────────────── #
# These are deliberately NOT in SCENARIOS: adding them would change fleet.pcap
# and invalidate the hand-authored ground truth in manifest.json. They exist
# only to build fleet_later.pcap, which shares every host with fleet.pcap and
# differs on exactly two of them — one fixed, one regressed. That is what makes
# a drift diff testable rather than anecdotal.


def imaps_16_remediated(port: int = 993) -> SessionScript:
    """10.20.1.16, after someone did the work.

    Was TLS 1.0 + RC4 with an expired self-signed certificate. Now TLS 1.3, so
    the certificate is encrypted and correctly unobservable.
    """
    s = SessionScript("imaps_16_remediated", "10.20.4.17", "10.20.1.16", 49203, port)
    s.client(client_hello("mail-compromised.test", MODERN_SUITES,
                          [0x0304, 0x0303], [GROUP_X25519_MLKEM768, GROUP_X25519]))
    s.server(server_hello(0x1302, 0x0303, negotiated_version=0x0304,
                          selected_group=GROUP_X25519))
    s.server(encrypted_application_data(280))
    s.client(encrypted_application_data(160))
    return s


def smtp_11_regressed(port: int = 587) -> SessionScript:
    """10.20.1.11, after a redeployment put a legacy TLS profile back.

    Was TLS 1.3 with a hybrid post-quantum group. Now negotiates TLS 1.0 with
    RC4 and presents the expired self-signed certificate. This is the regression
    a monitoring tool exists to catch: nothing was attacked, someone shipped a
    bad config.
    """
    s = SessionScript("smtp_11_regressed", "10.20.4.17", "10.20.1.11", 49201, port)
    s.server("220 mail-01.dept.gov.in ESMTP Postfix\r\n")
    s.client("EHLO client.dept.gov.in\r\n")
    s.server("250-mail-01.dept.gov.in\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n"
             "250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n250 CHUNKING\r\n")
    s.client("STARTTLS\r\n")
    s.server("220 2.0.0 Ready to start TLS\r\n")
    s.client(client_hello("mail-01.dept.gov.in", RC4_SUITES + MODERN_SUITES,
                          [0x0303, 0x0301], [GROUP_SECP256R1]))
    s.server(server_hello(0x0005, 0x0301, renegotiation_info=False))
    s.server(certificate_message(load_cert_chain("expired_selfsigned")))
    s.server(change_cipher_spec())
    s.server(encrypted_application_data(220))
    return s


SCENARIOS = {
    "smtp_starttls_healthy": smtp_starttls_healthy,
    "smtp_starttls_stripped": smtp_starttls_stripped,
    "imaps_implicit_weak": imaps_implicit_weak,
    "imaps_downgrade": imaps_downgrade,
    "imap_advertised_not_used": imap_advertised_not_used,
    "pop3_starttls_healthy": pop3_starttls_healthy,
    "smtp_relay_cleartext": smtp_relay_cleartext,
    "imaps_mid_session": imaps_mid_session,
    "imaps_tls12_valid_chain": imaps_tls12_valid_chain,
    "imaps_expiring_cert": imaps_expiring_cert,
    "smtp_relay_expired_cert": smtp_relay_expired_cert,
    "imaps_cert_substitution_a": imaps_cert_substitution_a,
    "imaps_cert_substitution_b": imaps_cert_substitution_b,
}


def build_all(out_dir: Path) -> list[Path]:
    """One PCAP per scenario, plus a combined fleet capture for the demo."""
    written = []
    for name, factory in SCENARIOS.items():
        written.append(write_pcap(out_dir / f"{name}.pcap", [factory()]))
    written.append(write_pcap(out_dir / "fleet.pcap",
                              [factory() for factory in SCENARIOS.values()]))

    # The same estate a fortnight later: every host is still here, one was
    # fixed and one regressed. Two captures of one network is USP-10.
    later = {name: factory for name, factory in SCENARIOS.items()
             if name not in ("imaps_implicit_weak", "smtp_starttls_healthy")}
    later["imaps_16_remediated"] = imaps_16_remediated
    later["smtp_11_regressed"] = smtp_11_regressed
    written.append(write_pcap(out_dir / "fleet_later.pcap",
                              [factory() for factory in later.values()]))
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("testbed/out"))
    args = parser.parse_args()
    for path in build_all(args.out):
        print(f"  {path}  ({path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
