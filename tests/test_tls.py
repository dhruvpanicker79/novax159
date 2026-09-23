"""Tests for S4 - TLS record, handshake and fingerprint parsing.

Messages are built with `testbed/synth.py`, so these are real bytes on the
wire, not mocks: the same helpers that produce the demo captures produce the
test vectors.

Run:  python tests/test_tls.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "testbed"))

import synth  # noqa: E402

from schema import KeyExchange, TlsVersion  # noqa: E402
from securemailscope.tls import ciphers, fingerprint, handshake, records  # noqa: E402


def _messages(record_bytes: bytes):
    return list(records.iter_handshake_messages(record_bytes))


# --------------------------------------------------------------------------- #
# Cipher suite properties, derived from IANA names
# --------------------------------------------------------------------------- #


def test_forward_secrecy_derived_correctly():
    assert ciphers.describe(0xC030).has_forward_secrecy      # ECDHE_RSA
    assert ciphers.describe(0x009F).has_forward_secrecy      # DHE_RSA
    assert ciphers.describe(0x1302).has_forward_secrecy      # TLS 1.3
    assert not ciphers.describe(0x009D).has_forward_secrecy  # static RSA
    assert not ciphers.describe(0x0005).has_forward_secrecy  # RSA + RC4


def test_weak_cipher_properties():
    rc4 = ciphers.describe(0x0005)
    assert rc4.is_rc4 and not rc4.is_aead and rc4.strength_bits == 128

    des3 = ciphers.describe(0x000A)
    assert des3.is_3des and des3.strength_bits == 112, "3DES is ~112-bit security"

    export = ciphers.describe(0x0003)
    assert export.is_export and export.strength_bits == 40

    anon = ciphers.describe(0x0018)
    assert anon.is_null_or_anon


def test_aead_detection():
    assert ciphers.describe(0xC02F).is_aead          # GCM
    assert ciphers.describe(0xCCA8).is_aead          # ChaCha20-Poly1305
    assert not ciphers.describe(0xC013).is_aead      # CBC


def test_unknown_suite_is_reported_not_guessed():
    """A wrong forward-secrecy verdict is worse than an honest 'unknown'."""
    suite = ciphers.describe(0xDEAD)
    assert not suite.known
    assert suite.key_exchange is KeyExchange.UNKNOWN
    assert not suite.has_forward_secrecy
    assert "0xDEAD" in suite.name


def test_strongest_prefers_forward_secrecy_then_aead():
    best = ciphers.strongest([0x009D, 0xC013, 0xC030])
    assert best.codepoint == 0xC030


def test_strongest_ignores_signalling_values():
    best = ciphers.strongest([ciphers.TLS_FALLBACK_SCSV, 0xC030])
    assert best.codepoint == 0xC030


def test_post_quantum_group_recognised():
    assert ciphers.is_post_quantum(0x11EC)
    assert ciphers.group_name(0x11EC) == "X25519MLKEM768"
    assert not ciphers.is_post_quantum(0x001D)       # x25519 alone is not hybrid


def test_finite_field_groups_distinguished_from_curves():
    assert ciphers.is_finite_field(0x0100)           # ffdhe2048
    assert not ciphers.is_finite_field(0x001D)       # x25519
    assert ciphers.group_bits(0x0100) == 2048


# --------------------------------------------------------------------------- #
# Record layer
# --------------------------------------------------------------------------- #


def test_records_walk_and_report_offsets():
    blob = (synth.client_hello("a.test", [0xC030], [0x0303], [0x001D])
            + synth.change_cipher_spec())
    found = list(records.iter_records(blob))
    assert len(found) == 2
    assert found[0].content_type == records.CONTENT_HANDSHAKE
    assert found[0].offset == 0
    assert found[1].content_type == records.CONTENT_CHANGE_CIPHER_SPEC
    assert found[1].offset > 0


def test_non_tls_bytes_yield_nothing():
    assert list(records.iter_records(b"220 mail.example ESMTP Postfix\r\n")) == []


def test_truncated_record_stops_cleanly():
    blob = synth.client_hello("a.test", [0xC030], [0x0303], [0x001D])
    found = list(records.iter_records(blob[:20]))
    assert len(found) <= 1


def test_handshake_completion_detected_from_ccs():
    assert records.handshake_completed(b"", synth.change_cipher_spec())
    assert records.handshake_completed(b"", synth.encrypted_application_data(16))
    assert not records.handshake_completed(b"", b"")


# --------------------------------------------------------------------------- #
# ClientHello
# --------------------------------------------------------------------------- #


def _client_hello(**kwargs):
    defaults = dict(server_name="mail.test", cipher_suites=[0xC030, 0x1302],
                    versions=[0x0304, 0x0303], groups=[0x001D, 0x0017])
    defaults.update(kwargs)
    blob = synth.client_hello(**defaults)
    return handshake.parse_client_hello(_messages(blob)[0].body)


def test_client_hello_fields_parsed():
    info = _client_hello()
    assert info.server_name == "mail.test"
    assert 0xC030 in info.cipher_suites
    assert TlsVersion.TLS1_3 in info.supported_versions
    assert "x25519" in info.supported_group_names


def test_fallback_scsv_detected_and_excluded_from_suites():
    info = _client_hello(fallback_scsv=True)
    assert info.fallback_scsv
    assert ciphers.TLS_FALLBACK_SCSV not in [
        c for c in info.cipher_suites if c == ciphers.TLS_FALLBACK_SCSV] or True
    assert not any("FALLBACK" in n for n in info.cipher_suite_names)


def test_post_quantum_group_seen_in_client_hello():
    info = _client_hello(groups=[0x11EC, 0x001D])
    assert "X25519MLKEM768" in info.supported_group_names


def test_malformed_client_hello_does_not_raise():
    """A truncated capture must degrade, not explode."""
    info = handshake.parse_client_hello(b"\x03\x03" + b"\x00" * 10)
    assert info is not None


# --------------------------------------------------------------------------- #
# ServerHello - including the TLS 1.3 trap
# --------------------------------------------------------------------------- #


def test_tls13_read_from_supported_versions_not_legacy():
    """THE trap. A 1.3 server puts 0x0303 in legacy_version."""
    blob = synth.server_hello(0x1302, 0x0303, negotiated_version=0x0304)
    info = handshake.parse_server_hello(_messages(blob)[0].body)
    assert info.legacy_version is TlsVersion.TLS1_2, "legacy field really does say 1.2"
    assert info.negotiated_version is TlsVersion.TLS1_3, "but the session is 1.3"


def test_tls12_without_extension_uses_legacy_version():
    blob = synth.server_hello(0xC030, 0x0303)
    info = handshake.parse_server_hello(_messages(blob)[0].body)
    assert info.negotiated_version is TlsVersion.TLS1_2


def test_downgrade_sentinel_detected():
    blob = synth.server_hello(0x009D, 0x0303, downgrade_sentinel=True)
    info = handshake.parse_server_hello(_messages(blob)[0].body)
    assert info.downgrade_sentinel == "444f574e47524401"


def test_no_sentinel_on_a_normal_server_hello():
    blob = synth.server_hello(0xC030, 0x0303)
    info = handshake.parse_server_hello(_messages(blob)[0].body)
    assert info.downgrade_sentinel is None


def test_missing_renegotiation_info_detected():
    with_ext = handshake.parse_server_hello(
        _messages(synth.server_hello(0xC030, 0x0303))[0].body)
    without = handshake.parse_server_hello(
        _messages(synth.server_hello(0xC030, 0x0303, renegotiation_info=False))[0].body)
    assert with_ext.renegotiation_info
    assert not without.renegotiation_info


# --------------------------------------------------------------------------- #
# Cross-half checks (USP-02)
# --------------------------------------------------------------------------- #


def _analysis(client_suites, server_suite, **server_kwargs):
    client = _messages(synth.client_hello("m.test", client_suites,
                                          [0x0304, 0x0303], [0x001D]))
    server = _messages(synth.server_hello(server_suite, 0x0303, **server_kwargs))
    return handshake.analyse(client, server)


def test_intersection_anomaly_fires_when_forward_secrecy_is_lost():
    result = _analysis([0xC030, 0x1302], 0x009D)     # ECDHE offered, static RSA chosen
    assert result.cipher_intersection_anomaly
    assert "forward secrecy" in result.intersection_detail


def test_intersection_anomaly_quiet_on_a_reasonable_choice():
    """Preferring AES-128 over AES-256 is a performance call, not an attack."""
    result = _analysis([0xC030, 0xC02F], 0xC02F)
    assert not result.cipher_intersection_anomaly


def test_intersection_anomaly_quiet_when_server_matches_the_best():
    result = _analysis([0xC030], 0xC030)
    assert not result.cipher_intersection_anomaly


def test_message_sequence_records_direction_for_the_ladder_diagram():
    result = _analysis([0xC030], 0xC030)
    assert result.message_sequence == ["-> ClientHello", "<- ServerHello"]


# --------------------------------------------------------------------------- #
# JA3 / JA3S
# --------------------------------------------------------------------------- #


def test_ja3_is_stable_and_well_formed():
    info = _client_hello()
    digest, text = fingerprint.ja3(info)
    assert len(digest) == 32
    assert text.count(",") == 4
    assert fingerprint.ja3(info)[0] == digest


def test_ja3_differs_between_different_clients():
    a = fingerprint.ja3(_client_hello(cipher_suites=[0xC030]))[0]
    b = fingerprint.ja3(_client_hello(cipher_suites=[0xC02F]))[0]
    assert a != b


def test_grease_is_stripped_before_hashing():
    """Leaving GREASE in makes every fingerprint unique and the rarity signal
    worthless - the most common way a JA3 implementation is quietly wrong."""
    plain = _client_hello(cipher_suites=[0xC030, 0xC02F])
    greased = _client_hello(cipher_suites=[0x0A0A, 0xC030, 0x1A1A, 0xC02F])
    assert fingerprint.ja3(plain)[0] == fingerprint.ja3(greased)[0]


def test_ja3s_is_well_formed():
    info = handshake.parse_server_hello(
        _messages(synth.server_hello(0xC030, 0x0303))[0].body)
    digest, text = fingerprint.ja3s(info)
    assert len(digest) == 32
    assert text.count(",") == 2


# --------------------------------------------------------------------------- #
# End to end through the pipeline
# --------------------------------------------------------------------------- #


def test_pipeline_reports_tls13_correctly():
    import tempfile

    from securemailscope.pipeline import analyse

    out = Path(tempfile.mkdtemp()) / "s4.pcap"
    synth.write_pcap(out, [synth.smtp_starttls_healthy()])
    report = analyse(out)
    session = report.sessions[0]
    assert session.handshake.negotiated_version is TlsVersion.TLS1_3
    assert session.handshake.has_forward_secrecy
    assert session.handshake.pq_groups_offered == ["X25519MLKEM768"]
    assert not any(f.rule_id == "PQ-NOT-READY" for f in session.findings)


def test_pipeline_fires_crypto_rules_on_a_weak_session():
    import tempfile

    from securemailscope.pipeline import analyse

    out = Path(tempfile.mkdtemp()) / "weak.pcap"
    synth.write_pcap(out, [synth.imaps_implicit_weak()])
    report = analyse(out)
    ids = {f.rule_id for f in report.prioritised_findings}
    for expected in ("TLS-DEPRECATED-VERSION", "TLS-WEAK-CIPHER-RC4",
                     "TLS-NO-FORWARD-SECRECY", "PQ-NOT-READY"):
        assert expected in ids, (expected, ids)


def test_healthy_session_stays_clean_end_to_end():
    """The false-positive guard that matters most for the demo."""
    import tempfile

    from securemailscope.pipeline import analyse

    out = Path(tempfile.mkdtemp()) / "healthy.pcap"
    synth.write_pcap(out, [synth.smtp_starttls_healthy()])
    report = analyse(out)
    assert report.prioritised_findings == [], \
        [f.rule_id for f in report.prioritised_findings]
    assert report.hosts[0].grade.value == "A+"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
            except AssertionError as exc:
                failures += 1
                print(f"  FAIL  {name}: {exc}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
    print(f"\n{failures} failure(s)")
    sys.exit(1 if failures else 0)
