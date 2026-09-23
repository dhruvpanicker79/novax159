"""S3 - the STARTTLS state machine and cleartext-phase analysis. Deliverable D02.

"Detection AND validation" is two verbs. Detection is seeing the keyword;
validation is the checks V1-V10 on `schema.StarttlsValidation`.

A CORRECTION TO THE ORIGINAL SPEC, worth stating plainly because it changes
what we can claim:

    V7 - "did the client re-issue EHLO after the TLS upgrade, as RFC 3207
    requires" - is NOT passively observable when the upgrade succeeds. Once the
    handshake completes, the re-issued EHLO travels inside the encrypted
    channel and we cannot see it. We only get to check V7 when the upgrade
    failed and the conversation continued in cleartext.

    So V7 is left as None (not applicable) whenever the handshake completed,
    and the feature flag defaults to "reissued" so the rule cannot fire on
    something we did not observe. Reporting a violation we cannot see would be
    a fabricated finding, which is worse than a missing one.

Knowing which of our own checks are observable is a strength, not an
embarrassment. It is the same class of honesty as reporting TLS 1.3
certificates as opaque rather than absent.

V2 - capability mangling - is the highest-value check in the project. The
classic on-path attack rewrites the keyword in place with a same-length
placeholder so TCP sequence numbers stay valid:

    250-STARTTLS   ->   250-XXXXXXXA
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from schema import (
    CredentialExposure,
    MailProtocol,
    MailSession,
    Phase,
    PhaseKind,
    PortRole,
    StarttlsValidation,
)

from ..capture.reassemble import ReassembledFlow

_TLS_RECORD_START = re.compile(rb"\x16\x03[\x00-\x04]..", re.DOTALL)

#: The upgrade keyword per protocol, and the success response we expect.
_KEYWORDS = {
    MailProtocol.SMTP: (b"STARTTLS", re.compile(rb"^220[ -]", re.MULTILINE)),
    MailProtocol.IMAP: (b"STARTTLS", re.compile(rb"^\S+\s+OK", re.MULTILINE | re.IGNORECASE)),
    MailProtocol.POP3: (b"STLS", re.compile(rb"^\+OK", re.MULTILINE)),
}

#: Capability keywords we expect to see advertised, used to spot a line that
#: has the shape of a capability but a keyword nobody has ever defined.
_KNOWN_CAPABILITIES = {
    b"PIPELINING", b"SIZE", b"ETRN", b"STARTTLS", b"AUTH", b"ENHANCEDSTATUSCODES",
    b"8BITMIME", b"DSN", b"SMTPUTF8", b"CHUNKING", b"VRFY", b"HELP", b"BINARYMIME",
    b"STLS", b"USER", b"UIDL", b"TOP", b"RESP-CODES", b"SASL", b"EXPIRE",
    b"IMAP4REV1", b"LOGINDISABLED", b"IDLE", b"NAMESPACE", b"LITERAL+", b"ID",
    b"UNSELECT", b"CHILDREN", b"SORT", b"THREAD", b"MOVE", b"QUOTA", b"ACL",
}


@dataclass
class CleartextAnalysis:
    """Everything S3 recovered from the unencrypted part of the session."""

    phases: list[Phase]
    validation: StarttlsValidation
    credentials: list[CredentialExposure]
    capability_mangled_line: str | None = None


# --------------------------------------------------------------------------- #
# Phase splitting
# --------------------------------------------------------------------------- #


def find_tls_start(data: bytes) -> int | None:
    """Offset of the first TLS record in a direction stream, if any."""
    match = _TLS_RECORD_START.search(data)
    return match.start() if match else None


def split_phases(session: MailSession, flow: ReassembledFlow) -> list[Phase]:
    """Break the session into plaintext / negotiation / encrypted. D02, D03."""
    client, server = flow.client_bytes, flow.server_bytes
    c_tls = find_tls_start(client)
    s_tls = find_tls_start(server)

    phases: list[Phase] = []

    if c_tls == 0 and s_tls == 0:
        phases.append(Phase(
            kind=PhaseKind.ENCRYPTED, started_at=session.flow.started_at,
            byte_range_c2s=[0, len(client)], byte_range_s2c=[0, len(server)],
            evidence=flow.evidence_for("s2c", 0, min(len(server), 64),
                                       note="implicit TLS from first byte"),
        ))
        return phases

    plaintext_end_c = c_tls if c_tls is not None else len(client)
    plaintext_end_s = s_tls if s_tls is not None else len(server)

    commands = _readable_lines(client[:plaintext_end_c]) + \
        _readable_lines(server[:plaintext_end_s])
    phases.append(Phase(
        kind=PhaseKind.PLAINTEXT, started_at=session.flow.started_at,
        byte_range_c2s=[0, plaintext_end_c], byte_range_s2c=[0, plaintext_end_s],
        commands=commands[:40],
        evidence=flow.evidence_for("s2c", 0, plaintext_end_s, note="cleartext phase"),
    ))

    if c_tls is not None:
        keyword = _KEYWORDS.get(session.protocol, (b"STARTTLS", None))[0]
        cmd_at = client.rfind(keyword, 0, c_tls)
        if cmd_at != -1:
            phases.append(Phase(
                kind=PhaseKind.STARTTLS_NEGOTIATION,
                started_at=session.flow.started_at,
                byte_range_c2s=[cmd_at, c_tls],
                evidence=flow.evidence_for("c2s", cmd_at, c_tls,
                                           note="STARTTLS command exchange"),
            ))
        phases.append(Phase(
            kind=PhaseKind.ENCRYPTED, started_at=session.flow.started_at,
            byte_range_c2s=[c_tls, len(client)],
            byte_range_s2c=[s_tls if s_tls is not None else len(server), len(server)],
            evidence=flow.evidence_for("c2s", c_tls, len(client),
                                       note="encrypted phase"),
        ))
    return phases


def _readable_lines(data: bytes, limit: int = 40) -> list[str]:
    out: list[str] = []
    for raw in data.split(b"\r\n"):
        if not raw:
            continue
        out.append(raw[:160].decode("utf-8", errors="replace"))
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------- #
# Capability mangling (V2) - the highest-value check
# --------------------------------------------------------------------------- #


def detect_mangled_capability(server_data: bytes,
                              protocol: MailProtocol) -> tuple[bool, str | None]:
    """Spot a capability keyword overwritten in place by something on the path.

    The tell is a line that has the exact shape of a capability advertisement
    but whose keyword is not a word anyone has ever defined. Attackers preserve
    the length so sequence numbers stay valid, which is precisely what makes it
    recognisable: a same-length nonsense token where a keyword belongs.

    Returns (suspected, the offending line).
    """
    prefix = b"250-" if protocol is MailProtocol.SMTP else b""
    for raw in server_data.split(b"\r\n"):
        if protocol is MailProtocol.SMTP:
            if not raw.startswith((b"250-", b"250 ")):
                continue
            token = raw[4:].split(b" ")[0].strip().upper()
        else:
            token = raw.split(b" ")[0].strip().upper()
        if not token or len(token) < 4:
            continue
        if token in _KNOWN_CAPABILITIES:
            continue
        if not token.isalnum():
            continue
        # A run of a single repeated character is the classic signature
        # (XXXXXXXA). Unknown-but-plausible vendor extensions usually are not.
        body = token[:-1]
        if len(set(body)) == 1 and len(body) >= 4:
            return True, raw.decode("utf-8", errors="replace")
    return False, None


# --------------------------------------------------------------------------- #
# Credential recovery (V9, and the demo's peak)
# --------------------------------------------------------------------------- #


def _redact(secret: str) -> str:
    if len(secret) <= 4:
        return "*" * len(secret)
    return f"{secret[:2]}{'*' * (len(secret) - 4)}{secret[-2:]}"


def _decode_b64(raw: bytes) -> str | None:
    try:
        text = base64.b64decode(raw, validate=True).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None
    return text if text.isprintable() or "\x00" in text else None


def find_cleartext_credentials(session: MailSession,
                               flow: ReassembledFlow) -> list[CredentialExposure]:
    """Recover authentication material sent before encryption. USP-02.

    Passwords are stored REDACTED. The raw base64 goes into `raw_b64` for the
    forensic export only - an incident responder needs to prove what crossed
    the wire, but a dashboard left open on a desk should not display it.
    """
    client = flow.client_bytes
    tls_at = find_tls_start(client)
    window = client[:tls_at] if tls_at is not None else client
    if not window:
        return []

    found: list[CredentialExposure] = []
    lines = window.split(b"\r\n")

    # -- SMTP AUTH LOGIN: two base64 lines answering 334 challenges ---------
    for index, line in enumerate(lines):
        upper = line.upper()

        if upper.startswith(b"AUTH LOGIN"):
            payloads = [ln for ln in lines[index + 1: index + 4] if ln]
            username = _decode_b64(payloads[0]) if payloads else None
            password = _decode_b64(payloads[1]) if len(payloads) > 1 else None
            found.append(CredentialExposure(
                mechanism="LOGIN",
                username=username,
                password_redacted=_redact(password) if password else None,
                password_length=len(password) if password else None,
                raw_b64=payloads[1].decode() if len(payloads) > 1 else None,
                evidence=flow.evidence_for(
                    "c2s", window.find(line), window.find(line) + len(line),
                    note="AUTH LOGIN exchange"),
            ))

        elif upper.startswith(b"AUTH PLAIN"):
            blob = line[len(b"AUTH PLAIN"):].strip()
            if not blob and index + 1 < len(lines):
                blob = lines[index + 1].strip()
            decoded = _decode_b64(blob) if blob else None
            if decoded and "\x00" in decoded:
                parts = decoded.split("\x00")
                username = parts[1] if len(parts) > 2 else None
                password = parts[2] if len(parts) > 2 else None
                found.append(CredentialExposure(
                    mechanism="PLAIN", username=username,
                    password_redacted=_redact(password) if password else None,
                    password_length=len(password) if password else None,
                    raw_b64=blob.decode(),
                    evidence=flow.evidence_for(
                        "c2s", window.find(line), window.find(line) + len(line),
                        note="AUTH PLAIN payload"),
                ))

        # -- IMAP LOGIN: username and password entirely in the clear --------
        elif session.protocol is MailProtocol.IMAP and b" LOGIN " in upper:
            parts = line.split()
            if len(parts) >= 4:
                password = parts[3].decode("utf-8", errors="replace").strip('"')
                found.append(CredentialExposure(
                    mechanism="IMAP LOGIN",
                    username=parts[2].decode("utf-8", errors="replace").strip('"'),
                    password_redacted=_redact(password),
                    password_length=len(password),
                    evidence=flow.evidence_for(
                        "c2s", window.find(line), window.find(line) + len(line),
                        note="IMAP LOGIN command"),
                ))

        # -- POP3 USER / PASS ------------------------------------------------
        elif session.protocol is MailProtocol.POP3 and upper.startswith(b"PASS "):
            password = line[5:].decode("utf-8", errors="replace")
            username = None
            for earlier in lines[:index]:
                if earlier.upper().startswith(b"USER "):
                    username = earlier[5:].decode("utf-8", errors="replace")
            found.append(CredentialExposure(
                mechanism="POP3 USER/PASS", username=username,
                password_redacted=_redact(password), password_length=len(password),
                evidence=flow.evidence_for(
                    "c2s", window.find(line), window.find(line) + len(line),
                    note="POP3 PASS command"),
            ))

    return found


# --------------------------------------------------------------------------- #
# The ten checks
# --------------------------------------------------------------------------- #


def validate(session: MailSession, flow: ReassembledFlow) -> StarttlsValidation:
    """Run V1-V10. Deliverable D02."""
    client, server = flow.client_bytes, flow.server_bytes
    keyword, success = _KEYWORDS.get(
        session.protocol, (b"STARTTLS", re.compile(rb"^220[ -]", re.MULTILINE)))

    c_tls = find_tls_start(client)
    s_tls = find_tls_start(server)
    cleartext_server = server[:s_tls] if s_tls is not None else server
    cleartext_client = client[:c_tls] if c_tls is not None else client

    v = StarttlsValidation(evidence=flow.evidence_for(
        "s2c", 0, len(cleartext_server), note="cleartext capability exchange"))

    # Implicit TLS: none of this applies, and saying so is the right answer.
    if c_tls == 0:
        v.observed_capability_line = None
        return v

    # V1 - advertised?
    v.v1_advertised = keyword in cleartext_server.upper()
    if v.v1_advertised:
        for raw in cleartext_server.split(b"\r\n"):
            if keyword in raw.upper():
                v.observed_capability_line = raw.decode("utf-8", errors="replace")
                break

    # V2 - mangled in transit?
    mangled, line = detect_mangled_capability(cleartext_server, session.protocol)
    v.v2_capability_mangled = mangled
    if mangled:
        v.observed_capability_line = line

    # V3 - did the client ask?
    v.v3_client_issued = bool(
        re.search(rb"^" + keyword + rb"\s*$", cleartext_client,
                  re.MULTILINE | re.IGNORECASE))

    # V4 - did the server agree? Look after the command, not before.
    if v.v3_client_issued:
        cmd_at = cleartext_client.upper().rfind(keyword)
        tail = cleartext_server[-len(cleartext_server) // 2:] if cmd_at else cleartext_server
        v.v4_server_accepted = bool(success.search(tail))

    # V5 - did a real handshake begin?
    v.v5_clienthello_followed = c_tls is not None

    # V6 - did it complete? ChangeCipherSpec (0x14) or application data (0x17)
    # after the handshake is the passive proof that keys were agreed.
    if c_tls is not None:
        after = server[s_tls:] if s_tls is not None else b""
        v.v6_handshake_completed = bool(
            re.search(rb"\x14\x03[\x00-\x04]", after) or
            re.search(rb"\x17\x03[\x00-\x04]", after) or
            re.search(rb"\x17\x03[\x00-\x04]", client[c_tls:]))

    # V7 - EHLO re-issued after TLS.
    # NOT OBSERVABLE once the upgrade succeeds: the re-issued EHLO is inside
    # the encrypted channel. Leave it as None rather than inventing a verdict.
    if v.v6_handshake_completed:
        v.v7_ehlo_reissued = None
    elif v.v4_server_accepted:
        # The server said go ahead and the session stayed readable, so we can
        # genuinely check - and the absence of a fresh EHLO is a real finding.
        v.v7_ehlo_reissued = b"EHLO" in cleartext_client.upper().split(keyword)[-1]

    # V8 - plaintext AUTH offered before TLS (RFC 4954)
    offers_plaintext_sasl = bool(
        re.search(rb"AUTH[= ]+(LOGIN|PLAIN)", cleartext_server, re.IGNORECASE))
    # LOGINDISABLED is IMAP saying "do not send me a plaintext LOGIN yet",
    # which is the correct behaviour and cancels the finding.
    imap_guards_login = (session.protocol is MailProtocol.IMAP
                         and b"LOGINDISABLED" in cleartext_server.upper())
    v.v8_auth_offered_before_tls = offers_plaintext_sasl and not imap_guards_login

    # V9 - credentials actually exposed
    v.v9_credentials_before_tls = bool(find_cleartext_credentials(session, flow))

    # V10 - commands pipelined across the TLS boundary (CVE-2011-0411).
    # Anything the client sent between the upgrade command and the ClientHello
    # would be buffered by a vulnerable server and replayed as if it had
    # arrived inside the protected session.
    if v.v3_client_issued and c_tls is not None:
        cmd_at = cleartext_client.upper().rfind(keyword)
        between = client[cmd_at + len(keyword): c_tls]
        v.v10_command_injection = len(between.strip(b"\r\n \t")) > 0

    return v


def analyse(session: MailSession, flow: ReassembledFlow) -> CleartextAnalysis:
    """Full S3 pass: phases, the ten checks, and any exposed credentials."""
    phases = split_phases(session, flow)
    validation = validate(session, flow)
    credentials = find_cleartext_credentials(session, flow)
    return CleartextAnalysis(
        phases=phases,
        validation=validation,
        credentials=credentials,
        capability_mangled_line=(validation.observed_capability_line
                                 if validation.v2_capability_mangled else None),
    )


def attach(session: MailSession, flow: ReassembledFlow) -> MailSession:
    """Run S3 and write the results onto the session."""
    analysis = analyse(session, flow)
    session.phases = analysis.phases
    session.starttls = analysis.validation
    if analysis.credentials:
        from schema import AttackEvidence, Confidence  # noqa: PLC0415

        session.attack_evidence = session.attack_evidence or AttackEvidence()
        session.attack_evidence.credential_exposure = analysis.credentials
        session.attack_evidence.confidence = Confidence.CONFIRMED
    if analysis.validation.v2_capability_mangled:
        from schema import AttackEvidence, Confidence  # noqa: PLC0415

        session.attack_evidence = session.attack_evidence or AttackEvidence()
        session.attack_evidence.starttls_stripping_suspected = True
        session.attack_evidence.confidence = Confidence.HIGH
        session.attack_evidence.corroborating_signals.append(
            f"capability line observed as {analysis.capability_mangled_line!r}")
        if analysis.credentials:
            session.attack_evidence.corroborating_signals.append(
                "cleartext authentication followed in the same session")
    return session
