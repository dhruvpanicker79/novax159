"""Tests for S5 - DER parsing, X.509 extraction and chain validation.

Certificates come from `testbed/certgen.py`, which builds genuinely signed
DER in pure Python. So the signature verification path is exercised against
real signatures, not stubs.

Run:  python tests/test_certs.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "testbed"))

import certgen  # noqa: E402

from schema import ChainStatus, PubKeyAlgorithm, SignatureAlgorithm  # noqa: E402
from securemailscope.certs import chain as chain_mod  # noqa: E402
from securemailscope.certs import der, parse_certificate_message  # noqa: E402
from securemailscope.certs.extract import parse_certificate  # noqa: E402

CERTS = ROOT / "testbed" / "certs"
NOW = datetime(2026, 9, 23, 10, 0, tzinfo=timezone.utc)


def _load(name: str):
    return parse_certificate(( CERTS / f"{name}.der").read_bytes())


def _chain(*names: str):
    return [parse_certificate((CERTS / f"{n}.der").read_bytes(), i)
            for i, n in enumerate(names)]


def _trust():
    return chain_mod.load_trust_store([str(CERTS / "_ca.der")])


# --------------------------------------------------------------------------- #
# DER primitives
# --------------------------------------------------------------------------- #


def test_oid_decoding():
    assert der.decode_oid(bytes.fromhex("2a864886f70d01010b")) == "1.2.840.113549.1.1.11"
    assert der.decode_oid(bytes.fromhex("550403")) == "2.5.4.3"


def test_utctime_pivots_on_year_fifty():
    """RFC 5280: 50-99 means 19xx, 00-49 means 20xx."""
    early = der.Element(der.UTC_TIME, b"260923100000Z", 0, 2)
    late = der.Element(der.UTC_TIME, b"960923100000Z", 0, 2)
    assert der.decode_time(early).year == 2026
    assert der.decode_time(late).year == 1996


def test_truncated_element_is_flagged_not_silently_empty():
    """A certificate cut short by a capture that stopped mid-transfer must not
    read as a certificate that simply has no extensions."""
    elements = der.parse_all(b"\x30\x82\xff\xff")
    assert len(elements) == 1
    assert elements[0].truncated
    assert elements[0].declared_length == 0xFFFF
    assert elements[0].value == b""


def test_truncated_header_is_refused():
    try:
        der.parse(b"\x30")
    except der.DerError:
        pass
    else:
        raise AssertionError("should have refused a truncated header")


def test_indefinite_length_rejected():
    """Valid BER, invalid DER. Certificates never use it."""
    try:
        der.parse(b"\x30\x80\x00\x00")
    except der.DerError as exc:
        assert "indefinite" in str(exc)
    else:
        raise AssertionError("indefinite length should be refused")


def test_implausible_length_rejected():
    try:
        der.parse(b"\x30\x84\x7f\xff\xff\xff")
    except der.DerError as exc:
        assert "implausible" in str(exc)
    else:
        raise AssertionError("huge length should be refused")


def test_distinguished_names_compare_case_insensitively():
    a = der.DistinguishedName([("CN", "Mail.Example.COM")])
    b = der.DistinguishedName([("CN", "mail.example.com")])
    assert a == b
    assert hash(a) == hash(b)


# --------------------------------------------------------------------------- #
# Certificate extraction (D08, D10, D11, D12)
# --------------------------------------------------------------------------- #


def test_healthy_certificate_fields():
    parsed = _load("valid")
    cert = parsed.certificate
    assert cert.subject_cn == "mail-healthy.test"
    assert cert.issuer_cn == "SecureMailScope Test Root CA"
    assert cert.public_key_algorithm is PubKeyAlgorithm.RSA
    assert cert.public_key_bits == 2048
    assert cert.signature_algorithm is SignatureAlgorithm.SHA256_RSA
    assert cert.subject_alt_names == ["mail-healthy.test"]
    assert not cert.is_self_signed
    assert not cert.is_ca
    assert parsed.parse_errors == []


def test_weak_key_and_signature_detected():
    cert = _load("expiring").certificate
    assert cert.public_key_bits == 1024, "D11: below the NIST 2048-bit minimum"
    assert cert.signature_algorithm is SignatureAlgorithm.SHA1_RSA
    assert cert.signature_algorithm.is_weak


def test_self_signed_detected_by_name_equality():
    cert = _load("expired_selfsigned").certificate
    assert cert.is_self_signed
    assert cert.subject_cn == cert.issuer_cn


def test_ca_flag_read_from_basic_constraints():
    assert _load("_ca").certificate.is_ca
    assert not _load("valid").certificate.is_ca


def test_expiry_arithmetic():
    cert = _load("expired_selfsigned").certificate
    assert cert.days_to_expiry(NOW) == -47
    assert _load("expiring").certificate.days_to_expiry(NOW) == 9


def test_fingerprints_are_distinct_and_stable():
    a = _load("valid").certificate.sha256_fingerprint
    b = _load("expiring").certificate.sha256_fingerprint
    assert len(a) == 64 and a != b
    assert _load("valid").certificate.sha256_fingerprint == a


def test_garbage_is_not_a_certificate():
    assert parse_certificate(b"not a certificate at all") is None
    assert parse_certificate(b"") is None


# --------------------------------------------------------------------------- #
# RSA signature verification
# --------------------------------------------------------------------------- #


def test_real_signature_verifies():
    leaf, ca = _chain("valid", "valid.1")
    assert chain_mod.verify_rsa_signature(
        leaf.tbs_bytes, leaf.signature, ca.rsa_modulus, ca.rsa_exponent,
        leaf.certificate.signature_algorithm) is True


def test_tampered_certificate_fails_verification():
    leaf, ca = _chain("valid", "valid.1")
    tampered = bytearray(leaf.tbs_bytes)
    tampered[-1] ^= 0xFF
    assert chain_mod.verify_rsa_signature(
        bytes(tampered), leaf.signature, ca.rsa_modulus, ca.rsa_exponent,
        leaf.certificate.signature_algorithm) is False


def test_wrong_issuer_key_fails_verification():
    leaf, _ = _chain("valid", "valid.1")
    other = _load("expired_selfsigned")
    assert chain_mod.verify_rsa_signature(
        leaf.tbs_bytes, leaf.signature, other.rsa_modulus, other.rsa_exponent,
        leaf.certificate.signature_algorithm) is False


def test_padding_is_checked_in_full():
    """A verifier that just looks for the digest somewhere in the recovered
    block accepts forgeries - the Bleichenbacher '06 class of bug."""
    leaf, ca = _chain("valid", "valid.1")
    size = (ca.rsa_modulus.bit_length() + 7) // 8
    forged = (1).to_bytes(size, "big")
    assert chain_mod.verify_rsa_signature(
        leaf.tbs_bytes, forged, ca.rsa_modulus, ca.rsa_exponent,
        leaf.certificate.signature_algorithm) is False


def test_unverifiable_algorithm_returns_none_not_false():
    """None means 'we did not check'. False would claim we found a forgery."""
    leaf, ca = _chain("valid", "valid.1")
    assert chain_mod.verify_rsa_signature(
        leaf.tbs_bytes, leaf.signature, ca.rsa_modulus, ca.rsa_exponent,
        SignatureAlgorithm.SHA256_ECDSA) is None


# --------------------------------------------------------------------------- #
# Hostname matching (RFC 6125)
# --------------------------------------------------------------------------- #


def test_wildcard_covers_exactly_one_label():
    assert chain_mod.hostname_matches("mail.example.com", ["*.example.com"])
    assert not chain_mod.hostname_matches("example.com", ["*.example.com"])
    assert not chain_mod.hostname_matches("a.b.example.com", ["*.example.com"])


def test_hostname_matching_is_case_insensitive():
    assert chain_mod.hostname_matches("MAIL.Example.COM", ["mail.example.com"])


def test_bare_wildcard_is_refused():
    """`*.com` must never match - it would validate the entire TLD."""
    assert not chain_mod.hostname_matches("example.com", ["*.com"])


# --------------------------------------------------------------------------- #
# Chain validation (D09)
# --------------------------------------------------------------------------- #


def test_complete_valid_chain():
    v = chain_mod.validate(_chain("valid", "valid.1"), "mail-healthy.test",
                           NOW, _trust())
    assert v.result.status is ChainStatus.VALID
    assert v.result.complete
    assert v.result.hostname_matched
    assert v.result.root_in_trust_store
    assert v.signature_verified is True


def test_expired_chain_reports_expiry():
    v = chain_mod.validate(_chain("expired_selfsigned"), "mail-compromised.test",
                           NOW, _trust())
    assert v.result.status is ChainStatus.EXPIRED
    assert any("expired" in issue for issue in v.result.issues)


def test_missing_intermediate_is_a_finding_not_a_pass():
    """Browsers can fetch it over AIA; many mail clients cannot. The finding
    is that some clients will fail where others succeed."""
    v = chain_mod.validate(_chain("missing_intermediate"), "mail-partial.test",
                           NOW, _trust())
    assert v.result.status is ChainStatus.INCOMPLETE
    assert not v.result.complete


def test_hostname_mismatch_detected():
    v = chain_mod.validate(_chain("valid", "valid.1"), "attacker.test",
                           NOW, _trust())
    assert v.result.status is ChainStatus.NAME_MISMATCH
    assert v.result.hostname_matched is False


def test_no_trust_store_means_unchecked_not_untrusted():
    """None is honest; False would claim we checked and it failed."""
    v = chain_mod.validate(_chain("valid", "valid.1"), "mail-healthy.test", NOW)
    assert v.result.root_in_trust_store is None


def test_empty_chain_is_absent():
    v = chain_mod.validate([], "x.test", NOW)
    assert v.result.status is ChainStatus.ABSENT


# --------------------------------------------------------------------------- #
# Certificate message framing
# --------------------------------------------------------------------------- #


def test_certificate_message_splits_a_chain():
    leaf = (CERTS / "valid.der").read_bytes()
    ca = (CERTS / "valid.1.der").read_bytes()
    inner = b"".join(len(c).to_bytes(3, "big") + c for c in (leaf, ca))
    body = len(inner).to_bytes(3, "big") + inner
    assert parse_certificate_message(body) == [leaf, ca]


def test_truncated_certificate_message_returns_what_it_can():
    leaf = (CERTS / "valid.der").read_bytes()
    inner = len(leaf).to_bytes(3, "big") + leaf
    body = (len(inner) + 500).to_bytes(3, "big") + inner
    assert parse_certificate_message(body) == [leaf]


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #


def _analyse(scenario: str):
    import tempfile

    import synth

    from securemailscope.pipeline import analyse

    out = Path(tempfile.mkdtemp()) / f"{scenario}.pcap"
    synth.write_pcap(out, [synth.SCENARIOS[scenario]()])
    return analyse(out, trust_store_paths=[str(CERTS / "_ca.der")])


def test_pipeline_extracts_a_certificate_from_a_pcap():
    report = _analyse("imaps_tls12_valid_chain")
    session = report.sessions[0]
    assert len(session.certificates) == 2
    assert session.certificates[0].subject_cn == "mail-healthy.test"
    assert session.chain.status is ChainStatus.VALID


def test_tls13_certificate_reported_opaque_not_missing():
    """The limitation most teams will get wrong: an empty panel reads as
    'no certificate', which is a completely different finding."""
    report = _analyse("smtp_starttls_healthy")
    session = report.sessions[0]
    assert session.chain.status is ChainStatus.OPAQUE_TLS13
    assert session.certificates == []
    assert not any(f.rule_id.startswith("CERT-") for f in session.findings)


def test_weak_certificate_fires_the_right_rules():
    report = _analyse("imaps_expiring_cert")
    ids = {f.rule_id for f in report.prioritised_findings}
    for expected in ("CERT-WEAK-KEY", "CERT-WEAK-SIGNATURE", "CERT-EXPIRING-SOON"):
        assert expected in ids, (expected, ids)


def test_expired_self_signed_is_critical_on_a_credential_port():
    """USP-01 end to end, from PCAP bytes to an adjusted severity."""
    report = _analyse("imaps_implicit_weak")
    finding = next(f for f in report.prioritised_findings
                   if f.rule_id == "CERT-EXPIRED-SELF-SIGNED")
    assert finding.base_severity.value == "high"
    assert finding.severity.value == "critical"
    assert "RFC 8314" in (finding.severity_adjustment_reason or "")


# --------------------------------------------------------------------------- #
# certgen is a test fixture, not a security tool
# --------------------------------------------------------------------------- #


def test_generated_keys_are_usable():
    key = certgen.generate_rsa(512, seed=99)
    assert key.n.bit_length() == 512
    signature = key.sign(b"hello", "sha256")
    assert chain_mod.verify_rsa_signature(
        b"hello", signature, key.n, key.e, SignatureAlgorithm.SHA256_RSA) is True


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
