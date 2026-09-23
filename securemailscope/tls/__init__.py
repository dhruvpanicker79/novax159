"""S4 - TLS record and handshake parsing. Deliverables D04-D07, D15, USP-05.

Owner: person B.

    records.py      the record layer, with stream offsets for provenance
    handshake.py    ClientHello / ServerHello, and the cross-half checks
    ciphers.py      suite and named-group tables, properties derived from names
    fingerprint.py  JA3 / JA3S

`attach()` below is the stage entry point the pipeline calls.
"""

from __future__ import annotations

from schema import AttackEvidence, Confidence, KeyExchange, MailSession, TlsHandshake, TlsVersion

from ..capture.reassemble import ReassembledFlow
from . import ciphers, fingerprint, records
from .handshake import analyse as analyse_handshake


def _tls_offset(data: bytes) -> int | None:
    """Where does the TLS record layer begin in this direction?"""
    for index in range(0, min(len(data), 1 << 16)):
        if records.looks_like_record(data, index):
            return index
    return None


def attach(session: MailSession, flow: ReassembledFlow) -> MailSession:
    """Parse the handshake and write the results onto the session.

    Returns the session unchanged when there is no readable handshake - a
    cleartext session, or a capture that stops before the hellos. Producing a
    partly-filled `TlsHandshake` in that case would let downstream rules draw
    conclusions from data we never saw (ADR-0014).
    """
    client, server = flow.client_bytes, flow.server_bytes
    client_start = _tls_offset(client)
    server_start = _tls_offset(server)
    if client_start is None and server_start is None:
        return session

    client_messages = (list(records.iter_handshake_messages(client, client_start))
                       if client_start is not None else [])
    server_messages = (list(records.iter_handshake_messages(server, server_start))
                       if server_start is not None else [])
    if not client_messages and not server_messages:
        return session

    analysis = analyse_handshake(client_messages, server_messages)
    client_hello = analysis.client_hello
    server_hello = analysis.server_hello

    handshake = TlsHandshake(
        client_hello=client_hello,
        server_hello=server_hello,
        message_sequence=analysis.message_sequence,
        alerts=(records.find_alerts(server, server_start or 0)
                + records.find_alerts(client, client_start or 0)),
        completed=records.handshake_completed(
            client, server, client_start or 0, server_start or 0),
        evidence=flow.evidence_for(
            "c2s", client_start or 0, len(client), note="TLS handshake"),
    )

    # -- evidence for each hello, so the ladder diagram is clickable --------
    if client_hello is not None and analysis.client_hello_offset is not None:
        client_hello.evidence = flow.evidence_for(
            "c2s", analysis.client_hello_offset,
            analysis.client_hello_offset + 64, note="ClientHello")
        client_hello.ja3, client_hello.ja3_string = fingerprint.ja3(client_hello)

    if server_hello is not None and analysis.server_hello_offset is not None:
        server_hello.evidence = flow.evidence_for(
            "s2c", analysis.server_hello_offset,
            analysis.server_hello_offset + 64, note="ServerHello")
        server_hello.ja3s, server_hello.ja3s_string = fingerprint.ja3s(server_hello)

    # -- negotiated parameters (D05, D06, D07, D15) ------------------------
    if server_hello is not None:
        handshake.negotiated_version = server_hello.negotiated_version
        handshake.cipher_suite_name = server_hello.cipher_suite_name
        if server_hello.cipher_suite is not None:
            suite = ciphers.describe(server_hello.cipher_suite)
            handshake.key_exchange = suite.key_exchange
            handshake.cipher_bits = suite.strength_bits
            handshake.is_aead = suite.is_aead
            handshake.has_forward_secrecy = suite.has_forward_secrecy
        # TLS 1.3 is ephemeral by construction, whatever the suite name says.
        if handshake.negotiated_version is TlsVersion.TLS1_3:
            handshake.key_exchange = KeyExchange.TLS13_EPHEMERAL
            handshake.has_forward_secrecy = True
        if server_hello.selected_group is not None:
            handshake.key_exchange_bits = ciphers.group_bits(server_hello.selected_group)

    # -- post-quantum readiness (USP-05) -----------------------------------
    if client_hello is not None:
        handshake.pq_groups_offered = [
            ciphers.group_name(g) for g in client_hello.supported_groups
            if ciphers.is_post_quantum(g)]
    if (server_hello is not None and server_hello.selected_group is not None
            and ciphers.is_post_quantum(server_hello.selected_group)):
        handshake.pq_group_negotiated = ciphers.group_name(server_hello.selected_group)

    # -- key exchange group strength, for the Logjam check -----------------
    if (handshake.key_exchange_bits is None and client_hello is not None
            and client_hello.supported_groups):
        finite = [g for g in client_hello.supported_groups if ciphers.is_finite_field(g)]
        if finite and handshake.key_exchange is KeyExchange.DHE:
            handshake.key_exchange_bits = min(ciphers.group_bits(g) for g in finite)

    session.handshake = handshake

    # -- attack evidence that needs both halves (USP-02) -------------------
    downgrade = bool(server_hello and server_hello.downgrade_sentinel)
    fallback = bool(client_hello and client_hello.fallback_scsv)
    if downgrade or fallback or analysis.cipher_intersection_anomaly:
        evidence = session.attack_evidence or AttackEvidence()
        evidence.downgrade_sentinel_present = downgrade
        evidence.fallback_scsv_present = fallback
        evidence.cipher_intersection_anomaly = analysis.cipher_intersection_anomaly
        evidence.weakest_selected_over_available = analysis.intersection_detail
        if downgrade:
            evidence.corroborating_signals.append(
                "RFC 8446 downgrade sentinel present in ServerHello.random")
        if fallback:
            evidence.corroborating_signals.append(
                "client sent TLS_FALLBACK_SCSV, indicating a previous handshake failed")
        if analysis.intersection_detail:
            evidence.corroborating_signals.append(analysis.intersection_detail)
        # A sentinel is the server stating a fact; an intersection anomaly is
        # an inference. Confidence reflects which we actually have.
        evidence.confidence = Confidence.HIGH if downgrade else Confidence.MEDIUM
        evidence.evidence = flow.evidence_for(
            "s2c", analysis.server_hello_offset or 0,
            (analysis.server_hello_offset or 0) + 64,
            note="ServerHello.random / cipher selection")
        session.attack_evidence = evidence

    return session
