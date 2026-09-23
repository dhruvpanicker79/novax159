"""Generate a realistic sample report so everyone can build in parallel.

This is ADR-0005 in practice: the frontend (E, F), the reporting layer (D) and
the ML layer (C) all build against `fixtures/report.sample.json` from minute
one, and never wait for the PCAP parser to exist.

    python scripts/make_fixtures.py

The fixture covers every USP so the dashboard has something real to render:

    USP-01  the same expired self-signed certificate appears on an MTA relay
            (downgraded to informational) and on a mail-access port (critical)
    USP-02  a stripped STARTTLS session with credentials in the clear
    USP-03  every object carries populated evidence
    USP-04  SHAP contributions and anomaly scores
    USP-05  post-quantum readiness, mostly absent
    USP-07  evaluation metrics from the ground-truth testbed
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from schema import (  # noqa: E402
    AttackEvidence,
    Capture,
    CategoryScore,
    Certificate,
    ChainResult,
    ChainStatus,
    ClientHelloInfo,
    Confidence,
    CredentialExposure,
    Evidence,
    FeatureVector,
    Finding,
    FindingCategory,
    FleetPosture,
    Flow,
    Grade,
    HostPosture,
    KeyExchange,
    MailProtocol,
    MailSession,
    Phase,
    PhaseKind,
    PortRole,
    PubKeyAlgorithm,
    Remediation,
    Report,
    ServerHelloInfo,
    SessionAssessment,
    Severity,
    ShapContribution,
    SignatureAlgorithm,
    StandardRef,
    StarttlsValidation,
    TlsHandshake,
    TlsMode,
    TlsVersion,
)
from securemailscope.rules import severity as sev  # noqa: E402

NOW = datetime(2026, 9, 23, 10, 0, tzinfo=timezone.utc)
CAPTURE_SHA = hashlib.sha256(b"securemailscope-sample-capture").hexdigest()

_frame = [100]


def ev(stream: int, count: int = 2, note: str | None = None, direction: str = "s2c") -> Evidence:
    """Produce a populated Evidence block. USP-03: never leave these empty."""
    start = _frame[0]
    _frame[0] += count + 3
    return Evidence(
        capture_sha256=CAPTURE_SHA,
        stream_id=stream,
        frame_numbers=list(range(start, start + count)),
        byte_range=[start * 40, start * 40 + 232],
        direction=direction,
        timestamp=NOW + timedelta(seconds=stream * 7),
        note=note,
    )


# --------------------------------------------------------------------------- #
# Standards, reused across findings (USP-08 aggregates this field)
# --------------------------------------------------------------------------- #

RFC8996 = StandardRef(
    body="RFC", identifier="8996", clause="Section 3",
    requirement="TLS 1.0 and TLS 1.1 MUST NOT be used",
    url="https://www.rfc-editor.org/rfc/rfc8996",
)
RFC9325 = StandardRef(
    body="RFC", identifier="9325", clause="Section 4.2",
    requirement="Implementations MUST NOT negotiate cipher suites offering less than 112 bits of security",
    url="https://www.rfc-editor.org/rfc/rfc9325",
)
RFC8314 = StandardRef(
    body="RFC", identifier="8314", clause="Section 3",
    requirement="Mail submission and access MUST use TLS with certificate validation",
    url="https://www.rfc-editor.org/rfc/rfc8314",
)
RFC7435 = StandardRef(
    body="RFC", identifier="7435", clause="Section 3",
    requirement="Opportunistic security: unauthenticated encryption is acceptable where authentication is impossible",
    url="https://www.rfc-editor.org/rfc/rfc7435",
)
RFC7465 = StandardRef(
    body="RFC", identifier="7465",
    requirement="RC4 cipher suites MUST NOT be used",
    url="https://www.rfc-editor.org/rfc/rfc7465",
)
RFC4954 = StandardRef(
    body="RFC", identifier="4954", clause="Section 4",
    requirement="A server MUST NOT advertise plaintext AUTH mechanisms before TLS",
    url="https://www.rfc-editor.org/rfc/rfc4954",
)
NIST80052 = StandardRef(
    body="NIST", identifier="SP 800-52 Rev 2", clause="Section 3.1",
    requirement="Servers shall be configured to support TLS 1.2 and should support TLS 1.3",
)
CERTIN = StandardRef(
    body="CERT-In", identifier="Cryptographic Controls Advisory",
    requirement="Deprecated TLS versions and weak ciphers must be disabled on government infrastructure",
)


# --------------------------------------------------------------------------- #
# Finding builders
# --------------------------------------------------------------------------- #


def f_deprecated_version(host: str, port: int, role: PortRole, version: str, stream: int) -> Finding:
    return Finding(
        rule_id="TLS-DEPRECATED-VERSION",
        title=f"Deprecated protocol version negotiated ({version})",
        description=(
            f"The session negotiated {version}, which RFC 8996 formally deprecates. "
            "It lacks AEAD cipher suites and modern signature algorithms, and is "
            "vulnerable to BEAST and Lucky13 when CBC suites are in use."
        ),
        category=FindingCategory.PROTOCOL,
        base_severity=Severity.HIGH, severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        affected_host=host, affected_port=port, port_role=role,
        standards=[RFC8996, NIST80052, CERTIN],
        related_attacks=["BEAST", "Lucky13"],
        remediation=Remediation(
            summary="Disable TLS 1.0 and 1.1; require TLS 1.2 as a minimum.",
            postfix="smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1\n"
                    "smtpd_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1",
            dovecot="ssl_min_protocol = TLSv1.2",
            exchange="Disable TLS 1.0/1.1 via the SCHANNEL registry keys, then reboot.",
            effort="low", risk_of_change="May break clients older than roughly 2015.",
        ),
        evidence=ev(stream, note="ServerHello.legacy_version"),
    )


def f_weak_cipher(host: str, port: int, role: PortRole, cipher: str, attacks: list[str], stream: int) -> Finding:
    return Finding(
        rule_id="TLS-WEAK-CIPHER",
        title=f"Weak cipher suite negotiated ({cipher})",
        description=f"{cipher} does not meet the minimum strength required by RFC 9325.",
        category=FindingCategory.CIPHER,
        base_severity=Severity.HIGH, severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        affected_host=host, affected_port=port, port_role=role,
        standards=[RFC9325, RFC7465] if "RC4" in cipher else [RFC9325],
        related_attacks=attacks,
        remediation=Remediation(
            summary="Restrict the cipher list to AEAD suites with forward secrecy.",
            postfix="smtpd_tls_mandatory_ciphers = high\n"
                    "tls_high_cipherlist = ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!RC4:!3DES",
            dovecot="ssl_cipher_list = ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!RC4:!3DES\n"
                    "ssl_prefer_server_ciphers = yes",
            effort="low", risk_of_change="Low. Modern clients all support AEAD suites.",
        ),
        evidence=ev(stream, note="ServerHello.cipher_suite"),
    )


def f_expired_selfsigned(host: str, port: int, role: PortRole, stream: int) -> Finding:
    """The USP-01 demonstration finding.

    Identical certificate problem, two port roles, two very different verdicts.
    """
    relay = role is PortRole.MTA_RELAY
    return Finding(
        rule_id="CERT-EXPIRED-SELF-SIGNED",
        title="Expired self-signed certificate presented",
        description=(
            "The server presented a self-signed certificate whose validity period "
            "ended 47 days ago."
        ),
        # Severity is deliberately NOT set here. The real role-aware engine in
        # securemailscope.rules.severity assigns it, so the fixture exercises
        # the same code path the pipeline will -- no hand-tuned demo numbers.
        category=FindingCategory.CERTIFICATE,
        base_severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        affected_host=host, affected_port=port, port_role=role,
        standards=[RFC7435] if relay else [RFC8314],
        related_attacks=[] if relay else ["Man-in-the-middle", "Credential theft"],
        remediation=Remediation(
            summary=("No action required for opportunistic relay, though a valid "
                     "certificate would enable DANE or MTA-STS."
                     if relay else
                     "Install a certificate from a publicly trusted CA and automate renewal."),
            postfix="smtpd_tls_cert_file = /etc/letsencrypt/live/HOST/fullchain.pem\n"
                    "smtpd_tls_key_file  = /etc/letsencrypt/live/HOST/privkey.pem",
            dovecot="ssl_cert = </etc/letsencrypt/live/HOST/fullchain.pem\n"
                    "ssl_key  = </etc/letsencrypt/live/HOST/privkey.pem",
            effort="trivial" if relay else "low",
            risk_of_change="None.",
        ),
        evidence=ev(stream, note="Certificate message, leaf notAfter"),
    )


def f_starttls_stripped(host: str, port: int, stream: int) -> Finding:
    return Finding(
        rule_id="ATTACK-STARTTLS-STRIPPED",
        title="STARTTLS capability stripped in transit",
        description=(
            "The server's EHLO response advertised STARTTLS as '250-XXXXXXXA' — the "
            "capability keyword overwritten in place with a same-length placeholder. "
            "This is the signature of an on-path attacker removing the upgrade option. "
            "The client then proceeded in cleartext and authenticated."
        ),
        category=FindingCategory.ATTACK_EVIDENCE,
        base_severity=Severity.CRITICAL, severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        affected_host=host, affected_port=port, port_role=PortRole.SUBMISSION,
        standards=[RFC8314, RFC4954],
        related_attacks=["STARTTLS stripping", "Credential theft", "Passive interception"],
        remediation=Remediation(
            summary="Require TLS on submission; move users to implicit TLS on port 465; "
                    "rotate every credential observed in this capture.",
            postfix="smtpd_tls_security_level = encrypt\nsmtpd_tls_auth_only = yes",
            dovecot="ssl = required\ndisable_plaintext_auth = yes",
            effort="low",
            risk_of_change="Clients that cannot do TLS will stop working, which is the point.",
        ),
        evidence=ev(stream, count=3, note="EHLO response, capability line", direction="s2c"),
    )


def f_credentials_cleartext(host: str, port: int, stream: int) -> Finding:
    return Finding(
        rule_id="ATTACK-CLEARTEXT-CREDENTIALS",
        title="Account credentials transmitted in cleartext",
        description=(
            "An AUTH LOGIN exchange completed before any TLS handshake. The username "
            "and password were recoverable by any observer on the path, including us."
        ),
        category=FindingCategory.ATTACK_EVIDENCE,
        base_severity=Severity.CRITICAL, severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        affected_host=host, affected_port=port, port_role=PortRole.SUBMISSION,
        standards=[RFC8314, RFC4954],
        related_attacks=["Credential theft", "Account takeover"],
        remediation=Remediation(
            summary="Treat the exposed accounts as compromised and rotate immediately. "
                    "Then enforce TLS before AUTH.",
            postfix="smtpd_tls_auth_only = yes",
            dovecot="disable_plaintext_auth = yes",
            effort="trivial", risk_of_change="None.",
        ),
        evidence=ev(stream, count=2, note="AUTH LOGIN base64 payload", direction="c2s"),
    )


def f_no_pfs(host: str, port: int, role: PortRole, stream: int) -> Finding:
    return Finding(
        rule_id="TLS-NO-FORWARD-SECRECY",
        title="Session negotiated without forward secrecy",
        description=(
            "Static RSA key exchange was used. Anyone who records this traffic and "
            "later obtains the server's private key can decrypt it retroactively."
        ),
        category=FindingCategory.KEY_EXCHANGE,
        base_severity=Severity.MEDIUM, severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        affected_host=host, affected_port=port, port_role=role,
        standards=[RFC9325],
        related_attacks=["Retrospective decryption"],
        remediation=Remediation(
            summary="Prefer ECDHE key exchange; disable static RSA suites.",
            postfix="tls_preempt_cipherlist = yes\ntls_eecdh_strong_curve = prime256v1",
            dovecot="ssl_prefer_server_ciphers = yes",
            effort="low", risk_of_change="Low.",
        ),
        evidence=ev(stream, note="ServerHello.cipher_suite key exchange component"),
    )


def f_no_pq(host: str, port: int, role: PortRole, stream: int) -> Finding:
    return Finding(
        rule_id="PQ-NOT-READY",
        title="No post-quantum key exchange offered",
        description=(
            "The ClientHello offered no hybrid post-quantum group. Traffic captured "
            "today can be stored and decrypted once a cryptographically relevant "
            "quantum computer exists — a live concern for mail, which organisations "
            "retain for years."
        ),
        category=FindingCategory.POST_QUANTUM,
        base_severity=Severity.LOW, severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        affected_host=host, affected_port=port, port_role=role,
        standards=[StandardRef(body="NIST", identifier="FIPS 203",
                               requirement="ML-KEM standardised for key encapsulation")],
        related_attacks=["Harvest now, decrypt later"],
        remediation=Remediation(
            summary="Plan migration to hybrid key exchange (X25519MLKEM768) as your TLS "
                    "library adds support.",
            generic="Track OpenSSL 3.5+ / BoringSSL hybrid group support and enable it "
                    "once available in your MTA build.",
            effort="high", risk_of_change="Requires a library upgrade.",
        ),
        evidence=ev(stream, note="ClientHello.supported_groups"),
    )


# --------------------------------------------------------------------------- #
# Session builder
# --------------------------------------------------------------------------- #


def make_session(
    sid: str, stream: int, host: str, port: int,
    protocol: MailProtocol, role: PortRole, mode: TlsMode,
    version: TlsVersion, cipher: str, kex: KeyExchange,
    cipher_bits: int, aead: bool,
    cert: Certificate | None, chain_status: ChainStatus,
    findings: list[Finding],
    risk: float, anomaly: float, shap: list[ShapContribution],
    pq_offered: list[str] | None = None,
    starttls: StarttlsValidation | None = None,
    attack: AttackEvidence | None = None,
    anomaly_reasons: list[str] | None = None,
) -> MailSession:
    pq_offered = pq_offered or []
    client_hello = ClientHelloInfo(
        legacy_version=TlsVersion.TLS1_2,
        supported_versions=[TlsVersion.TLS1_3, TlsVersion.TLS1_2],
        cipher_suite_names=[cipher, "TLS_AES_128_GCM_SHA256"],
        supported_group_names=["x25519", "secp256r1"] + pq_offered,
        server_name=host,
        alpn=[],
        fallback_scsv=bool(attack and attack.fallback_scsv_present),
        ja3=f"{abs(hash(sid)) % (10 ** 32):032x}",
        evidence=ev(stream, note="ClientHello", direction="c2s"),
    )
    server_hello = ServerHelloInfo(
        legacy_version=TlsVersion.TLS1_2 if version is TlsVersion.TLS1_3 else version,
        negotiated_version=version,
        cipher_suite_name=cipher,
        renegotiation_info=version is not TlsVersion.TLS1_0,
        downgrade_sentinel="444f574e47524401" if (attack and attack.downgrade_sentinel_present) else None,
        ja3s=f"{abs(hash(sid + 's')) % (10 ** 32):032x}",
        evidence=ev(stream, note="ServerHello"),
    )
    handshake = None
    if mode is not TlsMode.CLEARTEXT:
        handshake = TlsHandshake(
            client_hello=client_hello, server_hello=server_hello,
            negotiated_version=version, cipher_suite_name=cipher,
            key_exchange=kex, key_exchange_bits=256 if kex is KeyExchange.ECDHE else 2048,
            cipher_bits=cipher_bits, is_aead=aead,
            has_forward_secrecy=kex.has_forward_secrecy,
            message_sequence=["ClientHello", "ServerHello", "Certificate",
                              "ServerKeyExchange", "ServerHelloDone",
                              "ClientKeyExchange", "ChangeCipherSpec", "Finished"],
            completed=True,
            pq_groups_offered=pq_offered,
            pq_group_negotiated=pq_offered[0] if pq_offered else None,
            evidence=ev(stream, count=8, note="full handshake"),
        )

    phases = []
    if mode in (TlsMode.STARTTLS, TlsMode.CLEARTEXT):
        phases.append(Phase(kind=PhaseKind.PLAINTEXT, started_at=NOW,
                            commands=["EHLO client.example", "250-STARTTLS" if mode is TlsMode.STARTTLS else "250-SIZE"],
                            evidence=ev(stream, direction="c2s")))
    if mode is TlsMode.STARTTLS:
        phases.append(Phase(kind=PhaseKind.STARTTLS_NEGOTIATION, started_at=NOW,
                            commands=["STARTTLS", "220 2.0.0 Ready to start TLS"],
                            evidence=ev(stream)))
    if mode is not TlsMode.CLEARTEXT:
        phases.append(Phase(kind=PhaseKind.ENCRYPTED, started_at=NOW, evidence=ev(stream)))

    return MailSession(
        session_id=sid,
        flow=Flow(stream_id=stream, src_ip="10.20.4.17", src_port=49000 + stream,
                  dst_ip="10.20.1." + str(10 + stream), dst_port=port,
                  started_at=NOW, packet_count=48 + stream,
                  c2s_bytes=2100, s2c_bytes=8400,
                  evidence=ev(stream)),
        protocol=protocol, protocol_confidence=Confidence.CONFIRMED,
        port_role=role, tls_mode=mode,
        server_host=host, server_port=port, client_host="10.20.4.17",
        banner={"smtp": "220 %s ESMTP Postfix" % host,
                "imap": "* OK [CAPABILITY IMAP4rev1] %s ready" % host,
                "pop3": "+OK %s POP3 ready" % host}.get(protocol.value),
        phases=phases,
        starttls=starttls,
        handshake=handshake,
        certificates=[cert] if cert else [],
        chain=ChainResult(status=chain_status, chain_length=1 if cert else 0,
                          complete=chain_status is ChainStatus.VALID,
                          hostname_matched=chain_status is ChainStatus.VALID,
                          matched_against=host, evidence=ev(stream)),
        attack_evidence=attack,
        features=FeatureVector(
            tls_version_num=version.numeric,
            is_deprecated_version=version.is_deprecated,
            cipher_strength_bits=cipher_bits,
            cipher_is_aead=aead,
            cipher_is_cbc=("CBC" in cipher or "SHA" == cipher.split("_")[-1]),
            cipher_is_rc4="RC4" in cipher,
            cipher_is_3des="3DES" in cipher,
            kex_is_ephemeral=kex.has_forward_secrecy,
            has_forward_secrecy=kex.has_forward_secrecy,
            kex_group_bits=256 if kex is KeyExchange.ECDHE else 2048,
            pq_hybrid_offered=bool(pq_offered),
            pq_hybrid_negotiated=bool(pq_offered),
            cert_present=cert is not None,
            cert_days_to_expiry=cert.days_to_expiry(NOW) if cert else 0,
            cert_is_expired=bool(cert and (cert.days_to_expiry(NOW) or 0) < 0),
            cert_is_self_signed=bool(cert and cert.is_self_signed),
            cert_key_bits=cert.public_key_bits or 0 if cert else 0,
            cert_key_is_rsa=bool(cert and cert.public_key_algorithm is PubKeyAlgorithm.RSA),
            cert_sig_is_weak=bool(cert and cert.signature_algorithm.is_weak),
            cert_chain_complete=chain_status is ChainStatus.VALID,
            cert_hostname_match=chain_status is ChainStatus.VALID,
            port_role_is_relay=role is PortRole.MTA_RELAY,
            port_role_is_submission=role is PortRole.SUBMISSION,
            port_role_is_access=role is PortRole.MAIL_ACCESS,
            tls_mode_is_implicit=mode is TlsMode.IMPLICIT,
            tls_mode_is_starttls=mode is TlsMode.STARTTLS,
            tls_mode_is_cleartext=mode is TlsMode.CLEARTEXT,
            starttls_advertised=bool(starttls and starttls.v1_advertised),
            starttls_completed=bool(starttls and starttls.upgrade_succeeded),
            starttls_stripped_suspected=bool(attack and attack.starttls_stripping_suspected),
            credentials_in_cleartext=bool(attack and attack.credential_exposure),
            downgrade_sentinel_present=bool(attack and attack.downgrade_sentinel_present),
            cipher_intersection_anomaly=bool(attack and attack.cipher_intersection_anomaly),
            renegotiation_info_present=server_hello.renegotiation_info,
            sni_present=True,
            ja3_rarity=anomaly,
        ),
        assessment=SessionAssessment(
            risk_score=risk,
            risk_label=(Severity.CRITICAL if risk >= 0.85 else Severity.HIGH if risk >= 0.6
                        else Severity.MEDIUM if risk >= 0.35 else Severity.LOW if risk >= 0.15
                        else Severity.INFO),
            shap_contributions=shap,
            anomaly_score=anomaly,
            is_anomalous=anomaly > 0.6,
            anomaly_reasons=anomaly_reasons or [],
            exploitability=min(1.0, risk * 1.1),
            blast_radius=0.9 if role is not PortRole.MTA_RELAY else 0.4,
        ),
        findings=findings,
        evidence=ev(stream),
    )


def cert_good(cn: str) -> Certificate:
    return Certificate(
        chain_position=0, subject=f"CN={cn}", subject_cn=cn,
        issuer="CN=Example Root CA, O=Example Trust Services", issuer_cn="Example Root CA",
        serial_number="0a:1b:2c:3d:4e:5f",
        not_before=NOW - timedelta(days=30), not_after=NOW + timedelta(days=60),
        sha256_fingerprint=hashlib.sha256(cn.encode()).hexdigest(),
        public_key_algorithm=PubKeyAlgorithm.ECDSA, public_key_bits=256,
        signature_algorithm=SignatureAlgorithm.SHA256_ECDSA,
        subject_alt_names=[cn], is_self_signed=False,
        evidence=ev(1, note="Certificate message, leaf"),
    )


def cert_expiring(cn: str) -> Certificate:
    return Certificate(
        chain_position=0, subject=f"CN={cn}", subject_cn=cn,
        issuer="CN=Example Root CA", issuer_cn="Example Root CA",
        serial_number="11:22:33:44",
        not_before=NOW - timedelta(days=356), not_after=NOW + timedelta(days=9),
        sha256_fingerprint=hashlib.sha256((cn + "exp").encode()).hexdigest(),
        public_key_algorithm=PubKeyAlgorithm.RSA, public_key_bits=1024,
        signature_algorithm=SignatureAlgorithm.SHA1_RSA,
        subject_alt_names=[cn], is_self_signed=False,
        evidence=ev(2, note="Certificate message, leaf"),
    )


def cert_expired_selfsigned(cn: str) -> Certificate:
    """Deliberately the SAME certificate on two different port roles (USP-01)."""
    return Certificate(
        chain_position=0, subject=f"CN={cn}", subject_cn=cn,
        issuer=f"CN={cn}", issuer_cn=cn,
        serial_number="de:ad:be:ef",
        not_before=NOW - timedelta(days=412), not_after=NOW - timedelta(days=47),
        sha256_fingerprint=hashlib.sha256(b"self-signed-shared").hexdigest(),
        public_key_algorithm=PubKeyAlgorithm.RSA, public_key_bits=2048,
        signature_algorithm=SignatureAlgorithm.SHA256_RSA,
        subject_alt_names=[cn], is_self_signed=True,
        evidence=ev(3, note="Certificate message, self-signed leaf"),
    )


def shap(*pairs: tuple[str, float, str]) -> list[ShapContribution]:
    return [ShapContribution(feature=f, value=1.0, contribution=c, human_readable=h)
            for f, c, h in pairs]


def build_sessions() -> list[MailSession]:
    s: list[MailSession] = []

    # --- healthy tier ------------------------------------------------------
    s.append(make_session(
        "s01", 1, "mail-01.dept.gov.in", 993, MailProtocol.IMAP, PortRole.MAIL_ACCESS,
        TlsMode.IMPLICIT, TlsVersion.TLS1_3, "TLS_AES_256_GCM_SHA384",
        KeyExchange.TLS13_EPHEMERAL, 256, True,
        cert_good("mail-01.dept.gov.in"), ChainStatus.VALID, [],
        risk=0.04, anomaly=0.08,
        shap=shap(("tls_version_num", -0.22, "TLS 1.3 negotiated"),
                  ("has_forward_secrecy", -0.18, "Forward secrecy present"),
                  ("pq_hybrid_offered", -0.06, "Hybrid post-quantum group offered")),
        pq_offered=["X25519MLKEM768"],
    ))
    s.append(make_session(
        "s02", 2, "mail-01.dept.gov.in", 465, MailProtocol.SMTP, PortRole.SUBMISSION,
        TlsMode.IMPLICIT, TlsVersion.TLS1_3, "TLS_AES_128_GCM_SHA256",
        KeyExchange.TLS13_EPHEMERAL, 128, True,
        cert_good("mail-01.dept.gov.in"), ChainStatus.VALID,
        [f_no_pq("mail-01.dept.gov.in", 465, PortRole.SUBMISSION, 2)],
        risk=0.09, anomaly=0.10,
        shap=shap(("tls_version_num", -0.20, "TLS 1.3 negotiated"),
                  ("pq_hybrid_offered", 0.05, "No post-quantum group offered")),
    ))
    s.append(make_session(
        "s03", 3, "mail-02.dept.gov.in", 587, MailProtocol.SMTP, PortRole.SUBMISSION,
        TlsMode.STARTTLS, TlsVersion.TLS1_2, "ECDHE-RSA-AES256-GCM-SHA384",
        KeyExchange.ECDHE, 256, True,
        cert_good("mail-02.dept.gov.in"), ChainStatus.VALID,
        [f_no_pq("mail-02.dept.gov.in", 587, PortRole.SUBMISSION, 3)],
        risk=0.13, anomaly=0.12,
        shap=shap(("has_forward_secrecy", -0.19, "ECDHE forward secrecy"),
                  ("cipher_is_aead", -0.14, "AEAD cipher suite"),
                  ("tls_version_num", 0.06, "TLS 1.2 rather than 1.3")),
        starttls=StarttlsValidation(
            v1_advertised=True, v2_capability_mangled=False, v3_client_issued=True,
            v4_server_accepted=True, v5_clienthello_followed=True,
            v6_handshake_completed=True, v7_ehlo_reissued=True,
            v8_auth_offered_before_tls=False, v9_credentials_before_tls=False,
            v10_command_injection=False,
            observed_capability_line="250-STARTTLS", evidence=ev(3)),
    ))

    # --- degraded tier -----------------------------------------------------
    s.append(make_session(
        "s04", 4, "mail-03.dept.gov.in", 993, MailProtocol.IMAP, PortRole.MAIL_ACCESS,
        TlsMode.IMPLICIT, TlsVersion.TLS1_2, "ECDHE-RSA-AES128-SHA",
        KeyExchange.ECDHE, 128, False,
        cert_expiring("mail-03.dept.gov.in"), ChainStatus.VALID,
        [Finding(
            rule_id="CERT-WEAK-KEY", title="Certificate uses a 1024-bit RSA key",
            description="1024-bit RSA is below the 2048-bit minimum required by NIST SP 800-52 Rev 2.",
            category=FindingCategory.CERTIFICATE_STRENGTH,
            base_severity=Severity.HIGH, severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            affected_host="mail-03.dept.gov.in", affected_port=993,
            port_role=PortRole.MAIL_ACCESS, standards=[NIST80052, RFC9325],
            related_attacks=["Factorisation"],
            remediation=Remediation(summary="Reissue with a 2048-bit RSA or P-256 ECDSA key.",
                                    effort="low", risk_of_change="None."),
            evidence=ev(4, note="Certificate SubjectPublicKeyInfo")),
         Finding(
            rule_id="CERT-EXPIRING-SOON", title="Certificate expires in 9 days",
            description="Renewal has not occurred. Mail delivery will fail on expiry.",
            category=FindingCategory.CERTIFICATE,
            base_severity=Severity.MEDIUM, severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            affected_host="mail-03.dept.gov.in", affected_port=993,
            port_role=PortRole.MAIL_ACCESS, standards=[],
            remediation=Remediation(summary="Renew now and automate renewal.",
                                    effort="trivial", risk_of_change="None."),
            evidence=ev(4, note="leaf notAfter")),
         Finding(
            rule_id="CERT-WEAK-SIGNATURE", title="Certificate signed with SHA-1",
            description="SHA-1 signatures are collision-broken and rejected by modern clients.",
            category=FindingCategory.CERTIFICATE_STRENGTH,
            base_severity=Severity.HIGH, severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            affected_host="mail-03.dept.gov.in", affected_port=993,
            port_role=PortRole.MAIL_ACCESS, standards=[RFC9325, CERTIN],
            related_attacks=["Chosen-prefix collision"],
            remediation=Remediation(summary="Reissue with SHA-256.", effort="low",
                                    risk_of_change="None."),
            evidence=ev(4, note="Certificate signatureAlgorithm"))],
        risk=0.62, anomaly=0.31,
        shap=shap(("cert_key_bits", 0.24, "1024-bit RSA certificate key"),
                  ("cert_sig_is_weak", 0.21, "SHA-1 certificate signature"),
                  ("cipher_is_cbc", 0.11, "CBC cipher without AEAD"),
                  ("cert_days_to_expiry", 0.08, "Certificate expires in 9 days"),
                  ("has_forward_secrecy", -0.15, "ECDHE forward secrecy")),
    ))
    s.append(make_session(
        "s05", 5, "mail-03.dept.gov.in", 110, MailProtocol.POP3, PortRole.MAIL_ACCESS,
        TlsMode.STARTTLS, TlsVersion.TLS1_1, "ECDHE-RSA-AES128-SHA",
        KeyExchange.ECDHE, 128, False,
        cert_expiring("mail-03.dept.gov.in"), ChainStatus.VALID,
        [f_deprecated_version("mail-03.dept.gov.in", 110, PortRole.MAIL_ACCESS, "TLS 1.1", 5)],
        risk=0.68, anomaly=0.44,
        shap=shap(("is_deprecated_version", 0.34, "TLS 1.1 is deprecated by RFC 8996"),
                  ("cipher_is_cbc", 0.12, "CBC cipher without AEAD"),
                  ("port_role_is_access", 0.09, "Mail access port carries credentials")),
        starttls=StarttlsValidation(
            v1_advertised=True, v2_capability_mangled=False, v3_client_issued=True,
            v4_server_accepted=True, v5_clienthello_followed=True,
            v6_handshake_completed=True, v7_ehlo_reissued=True,
            v8_auth_offered_before_tls=False, v9_credentials_before_tls=False,
            v10_command_injection=False, observed_capability_line="STLS", evidence=ev(5)),
    ))

    # --- USP-01 side by side: identical certificate, opposite verdicts -----
    s.append(make_session(
        "s06", 6, "mail-04.dept.gov.in", 25, MailProtocol.SMTP, PortRole.MTA_RELAY,
        TlsMode.STARTTLS, TlsVersion.TLS1_2, "ECDHE-RSA-AES128-GCM-SHA256",
        KeyExchange.ECDHE, 128, True,
        cert_expired_selfsigned("mail-04.dept.gov.in"), ChainStatus.SELF_SIGNED,
        [f_expired_selfsigned("mail-04.dept.gov.in", 25, PortRole.MTA_RELAY, 6)],
        risk=0.18, anomaly=0.22,
        shap=shap(("cert_is_expired", 0.19, "Certificate expired 47 days ago"),
                  ("cert_is_self_signed", 0.14, "Self-signed certificate"),
                  ("port_role_is_relay", -0.26, "MTA relay: opportunistic TLS per RFC 7435"),
                  ("has_forward_secrecy", -0.12, "ECDHE forward secrecy")),
        starttls=StarttlsValidation(
            v1_advertised=True, v2_capability_mangled=False, v3_client_issued=True,
            v4_server_accepted=True, v5_clienthello_followed=True,
            v6_handshake_completed=True, v7_ehlo_reissued=True,
            v8_auth_offered_before_tls=False, v9_credentials_before_tls=False,
            v10_command_injection=False, observed_capability_line="250-STARTTLS", evidence=ev(6)),
    ))
    s.append(make_session(
        "s07", 7, "mail-06.dept.gov.in", 993, MailProtocol.IMAP, PortRole.MAIL_ACCESS,
        TlsMode.IMPLICIT, TlsVersion.TLS1_0, "RC4-SHA",
        KeyExchange.RSA, 128, False,
        cert_expired_selfsigned("mail-06.dept.gov.in"), ChainStatus.SELF_SIGNED,
        [f_expired_selfsigned("mail-06.dept.gov.in", 993, PortRole.MAIL_ACCESS, 7),
         f_deprecated_version("mail-06.dept.gov.in", 993, PortRole.MAIL_ACCESS, "TLS 1.0", 7),
         f_weak_cipher("mail-06.dept.gov.in", 993, PortRole.MAIL_ACCESS, "RC4-SHA",
                       ["RC4 keystream biases", "BEAST"], 7),
         f_no_pfs("mail-06.dept.gov.in", 993, PortRole.MAIL_ACCESS, 7)],
        risk=0.93, anomaly=0.71,
        shap=shap(("cipher_is_rc4", 0.31, "RC4 cipher suite negotiated"),
                  ("is_deprecated_version", 0.26, "TLS 1.0 negotiated"),
                  ("cert_is_expired", 0.17, "Certificate expired 47 days ago"),
                  ("has_forward_secrecy", 0.14, "Static RSA: no forward secrecy"),
                  ("port_role_is_access", 0.09, "Mail access port carries credentials")),
        anomaly_reasons=["Only host in the capture negotiating RC4",
                         "JA3S fingerprint unique across 40 sessions"],
    ))

    # --- compromised tier: the demo's emotional peak (USP-02) --------------
    stripped_attack = AttackEvidence(
        starttls_stripping_suspected=True,
        credential_exposure=[CredentialExposure(
            mechanism="LOGIN", username="r.sharma@dept.gov.in",
            password_redacted="Mo**********24", password_length=14,
            raw_b64="ci5zaGFybWFAZGVwdC5nb3YuaW4=",
            evidence=ev(8, count=2, note="AUTH LOGIN payload", direction="c2s"))],
        corroborating_signals=[
            "Capability line length preserved but keyword overwritten",
            "Same server advertised a well-formed STARTTLS on stream 3",
            "Cleartext AUTH followed 40 ms later",
        ],
        confidence=Confidence.HIGH,
        evidence=ev(8, count=3, note="EHLO response"),
    )
    s.append(make_session(
        "s08", 8, "mail-05.dept.gov.in", 587, MailProtocol.SMTP, PortRole.SUBMISSION,
        TlsMode.CLEARTEXT, TlsVersion.UNKNOWN, "none", KeyExchange.UNKNOWN, 0, False,
        None, ChainStatus.ABSENT,
        [f_starttls_stripped("mail-05.dept.gov.in", 587, 8),
         f_credentials_cleartext("mail-05.dept.gov.in", 587, 8)],
        risk=0.98, anomaly=0.88,
        shap=shap(("credentials_in_cleartext", 0.38, "Credentials sent without encryption"),
                  ("starttls_stripped_suspected", 0.29, "STARTTLS capability mangled in transit"),
                  ("tls_mode_is_cleartext", 0.21, "Session never encrypted"),
                  ("port_role_is_submission", 0.07, "Submission port requires TLS")),
        starttls=StarttlsValidation(
            v1_advertised=False, v2_capability_mangled=True, v3_client_issued=False,
            v4_server_accepted=None, v5_clienthello_followed=False,
            v6_handshake_completed=False, v7_ehlo_reissued=None,
            v8_auth_offered_before_tls=True, v9_credentials_before_tls=True,
            v10_command_injection=False,
            observed_capability_line="250-XXXXXXXA", evidence=ev(8, count=2)),
        attack=stripped_attack,
        anomaly_reasons=["Only cleartext authentication in the capture",
                         "Capability line does not match this host's other sessions"],
    ))
    s.append(make_session(
        "s09", 9, "mail-05.dept.gov.in", 143, MailProtocol.IMAP, PortRole.MAIL_ACCESS,
        TlsMode.CLEARTEXT, TlsVersion.UNKNOWN, "none", KeyExchange.UNKNOWN, 0, False,
        None, ChainStatus.ABSENT,
        [Finding(
            rule_id="STARTTLS-ADVERTISED-NOT-USED",
            title="STARTTLS advertised but never used",
            description="The server offered STARTTLS and the client ignored it, then "
                        "authenticated over the cleartext channel.",
            category=FindingCategory.STARTTLS,
            base_severity=Severity.HIGH, severity=Severity.CRITICAL,
            severity_adjustment_reason="Raised to CRITICAL: mail-access port with "
                                       "credentials observed in the plaintext phase.",
            confidence=Confidence.CONFIRMED,
            affected_host="mail-05.dept.gov.in", affected_port=143,
            port_role=PortRole.MAIL_ACCESS, standards=[RFC8314, RFC4954],
            related_attacks=["Passive interception", "Credential theft"],
            remediation=Remediation(
                summary="Set the client to require TLS, and refuse plaintext AUTH server-side.",
                dovecot="disable_plaintext_auth = yes\nssl = required",
                effort="trivial", risk_of_change="Legacy clients will need reconfiguring."),
            evidence=ev(9, count=2, note="CAPABILITY response"))],
        risk=0.89, anomaly=0.52,
        shap=shap(("credentials_in_cleartext", 0.36, "Credentials sent without encryption"),
                  ("starttls_advertised", 0.18, "Upgrade available but unused"),
                  ("tls_mode_is_cleartext", 0.20, "Session never encrypted")),
        starttls=StarttlsValidation(
            v1_advertised=True, v2_capability_mangled=False, v3_client_issued=False,
            v4_server_accepted=None, v5_clienthello_followed=False,
            v6_handshake_completed=False, v7_ehlo_reissued=None,
            v8_auth_offered_before_tls=True, v9_credentials_before_tls=True,
            v10_command_injection=False,
            observed_capability_line="* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED",
            evidence=ev(9)),
    ))

    # --- anomalous but not rule-violating (the USP-04 layer-2 demo) --------
    s.append(make_session(
        "s10", 10, "mail-07.dept.gov.in", 993, MailProtocol.IMAP, PortRole.MAIL_ACCESS,
        TlsMode.IMPLICIT, TlsVersion.TLS1_2, "DHE-RSA-AES256-GCM-SHA384",
        KeyExchange.DHE, 256, True,
        cert_good("mail-07.dept.gov.in"), ChainStatus.VALID,
        [Finding(
            rule_id="ATTACK-CIPHER-INTERSECTION-ANOMALY",
            title="Server selected a weaker suite than both parties supported",
            description="The client offered TLS 1.3 with AES-256-GCM; the server chose "
                        "TLS 1.2 with a 2048-bit DHE group despite advertising 1.3 "
                        "support elsewhere in the capture. Consistent with a downgrade.",
            category=FindingCategory.ATTACK_EVIDENCE,
            base_severity=Severity.MEDIUM, severity=Severity.HIGH,
            severity_adjustment_reason="Raised: mail-access port, and the DOWNGRD "
                                       "sentinel is present in ServerHello.random.",
            confidence=Confidence.MEDIUM,
            affected_host="mail-07.dept.gov.in", affected_port=993,
            port_role=PortRole.MAIL_ACCESS, standards=[RFC9325],
            related_attacks=["Protocol downgrade", "Man-in-the-middle"],
            remediation=Remediation(
                summary="Verify the server's protocol configuration and inspect the "
                        "path for an intercepting middlebox.",
                effort="medium", risk_of_change="Investigation only."),
            evidence=ev(10, count=3, note="ServerHello.random[24:32]"))],
        risk=0.47, anomaly=0.79,
        shap=shap(("downgrade_sentinel_present", 0.22, "DOWNGRD sentinel in ServerHello.random"),
                  ("cipher_intersection_anomaly", 0.19, "Weaker suite than mutually supported"),
                  ("has_forward_secrecy", -0.14, "DHE forward secrecy present")),
        attack=AttackEvidence(
            downgrade_sentinel_present=True, fallback_scsv_present=True,
            cipher_intersection_anomaly=True,
            weakest_selected_over_available="TLS_AES_256_GCM_SHA384 offered, DHE-RSA-AES256-GCM-SHA384 selected",
            corroborating_signals=["Host negotiated TLS 1.3 on stream 12 for the same service"],
            confidence=Confidence.MEDIUM, evidence=ev(10, count=2)),
        anomaly_reasons=["DHE key exchange used by no other host in the fleet",
                         "JA3S fingerprint seen once in 40 sessions",
                         "Negotiated version inconsistent with this host's other sessions"],
    ))

    # --- opportunistic relay with no TLS at all (correctly low severity) ---
    s.append(make_session(
        "s11", 11, "mail-02.dept.gov.in", 25, MailProtocol.SMTP, PortRole.MTA_RELAY,
        TlsMode.CLEARTEXT, TlsVersion.UNKNOWN, "none", KeyExchange.UNKNOWN, 0, False,
        None, ChainStatus.ABSENT,
        [Finding(
            rule_id="SMTP-RELAY-NO-TLS",
            title="Inbound relay session not encrypted",
            description="A peer MTA delivered mail without attempting STARTTLS. The "
                        "remote sender controls this, not us; the local server did "
                        "advertise STARTTLS correctly.",
            category=FindingCategory.CONFIGURATION,
            base_severity=Severity.MEDIUM, severity=Severity.LOW,
            severity_adjustment_reason="Downgraded: port 25 relay, and the failure is "
                                       "on the remote peer. Consider publishing "
                                       "MTA-STS or DANE to require TLS from senders.",
            confidence=Confidence.CONFIRMED,
            affected_host="mail-02.dept.gov.in", affected_port=25,
            port_role=PortRole.MTA_RELAY, standards=[RFC7435],
            remediation=Remediation(
                summary="Publish an MTA-STS policy (RFC 8461) and a TLSA record "
                        "(RFC 7672) so compliant senders are required to use TLS.",
                effort="medium", risk_of_change="Misconfigured MTA-STS can defer mail."),
            evidence=ev(11, count=2, note="EHLO exchange"))],
        risk=0.22, anomaly=0.18,
        shap=shap(("tls_mode_is_cleartext", 0.26, "Session never encrypted"),
                  ("port_role_is_relay", -0.24, "MTA relay: opportunistic TLS per RFC 7435")),
    ))

    s.append(make_session(
        "s12", 12, "mail-08.dept.gov.in", 995, MailProtocol.POP3, PortRole.MAIL_ACCESS,
        TlsMode.IMPLICIT, TlsVersion.TLS1_2, "ECDHE-RSA-CHACHA20-POLY1305",
        KeyExchange.ECDHE, 256, True,
        cert_good("mail-08.dept.gov.in"), ChainStatus.VALID,
        [f_no_pq("mail-08.dept.gov.in", 995, PortRole.MAIL_ACCESS, 12)],
        risk=0.14, anomaly=0.15,
        shap=shap(("cipher_is_aead", -0.17, "ChaCha20-Poly1305 AEAD suite"),
                  ("has_forward_secrecy", -0.16, "ECDHE forward secrecy"),
                  ("pq_hybrid_offered", 0.05, "No post-quantum group offered")),
    ))

    return s


def build_report() -> Report:
    sessions = build_sessions()

    # Run the real role-aware severity engine over every finding (USP-01), so
    # the fixture reflects the shipping policy rather than hand-picked numbers.
    # If the policy changes, regenerating the fixture shows it immediately.
    all_findings = [f for s in sessions for f in s.findings]
    sev.adjust_all(all_findings)

    # D18 is not D16. Severity alone does not order a remediation queue, so the
    # rank folds in the model's exploitability and blast radius for the session
    # the finding came from, then the number of attacks it enables.
    def session_for(f: Finding) -> MailSession | None:
        return next((s for s in sessions
                     if s.server_host == f.affected_host
                     and s.server_port == f.affected_port), None)

    def priority_key(f: Finding) -> tuple[float, float, float]:
        s = session_for(f)
        a = s.assessment if s and s.assessment else None
        exposure = (a.exploitability * a.blast_radius) if a else 0.0
        return (-f.severity.rank, -exposure, -len(f.related_attacks))

    prioritised = sorted(all_findings, key=priority_key)
    for f in prioritised:
        f.session_ids = [s.session_id for s in sessions
                         if s.server_host == f.affected_host and s.server_port == f.affected_port]

    hosts: dict[str, HostPosture] = {}
    for s in sessions:
        host = s.server_host or "unknown"
        hp = hosts.setdefault(host, HostPosture(host=host))
        hp.ports.append(s.server_port)
        if s.protocol not in hp.protocols:
            hp.protocols.append(s.protocol)
        hp.session_count += 1
        if s.handshake and s.handshake.pq_ready:
            hp.pq_ready = True
        for f in s.findings:
            hp.finding_counts[f.severity.value] = hp.finding_counts.get(f.severity.value, 0) + 1

    for host, hp in hosts.items():
        sess = [s for s in sessions if s.server_host == host]
        worst_risk = max((s.assessment.risk_score for s in sess if s.assessment), default=0.0)
        hp.score = round(max(0.0, 100.0 - worst_risk * 100), 1)
        hp.grade = (Grade.A_PLUS if hp.score >= 95 else Grade.A if hp.score >= 85
                    else Grade.B if hp.score >= 75 else Grade.C if hp.score >= 60
                    else Grade.D if hp.score >= 45 else Grade.E if hp.score >= 25 else Grade.F)
        pfs = [s for s in sess if s.handshake and s.handshake.has_forward_secrecy]
        encrypted = [s for s in sess if s.tls_mode is not TlsMode.CLEARTEXT]
        hp.forward_secrecy_ratio = round(len(pfs) / len(encrypted), 2) if encrypted else 0.0
        versions = [s.handshake.negotiated_version for s in sess if s.handshake]
        hp.worst_tls_version = min(versions, key=lambda v: v.numeric) if versions else TlsVersion.UNKNOWN
        hp.top_findings = sorted((f for s in sess for f in s.findings),
                                 key=lambda f: -f.severity.rank)[:3]

    encrypted_sessions = [s for s in sessions if s.tls_mode is not TlsMode.CLEARTEXT]
    pfs_sessions = [s for s in encrypted_sessions if s.handshake and s.handshake.has_forward_secrecy]
    fleet_score = round(sum(h.score for h in hosts.values()) / len(hosts), 1)

    fleet = FleetPosture(
        score=fleet_score,
        grade=(Grade.A if fleet_score >= 85 else Grade.B if fleet_score >= 75
               else Grade.C if fleet_score >= 60 else Grade.D if fleet_score >= 45
               else Grade.E if fleet_score >= 25 else Grade.F),
        host_count=len(hosts), session_count=len(sessions),
        category_scores=[
            CategoryScore(category=FindingCategory.PROTOCOL, score=62.0, finding_count=2,
                          worst_severity=Severity.HIGH),
            CategoryScore(category=FindingCategory.CIPHER, score=71.0, finding_count=1,
                          worst_severity=Severity.HIGH),
            CategoryScore(category=FindingCategory.KEY_EXCHANGE, score=84.0, finding_count=1,
                          worst_severity=Severity.MEDIUM),
            CategoryScore(category=FindingCategory.CERTIFICATE, score=55.0, finding_count=5,
                          worst_severity=Severity.CRITICAL),
            CategoryScore(category=FindingCategory.STARTTLS, score=48.0, finding_count=1,
                          worst_severity=Severity.CRITICAL),
            CategoryScore(category=FindingCategory.ATTACK_EVIDENCE, score=21.0, finding_count=3,
                          worst_severity=Severity.CRITICAL),
            CategoryScore(category=FindingCategory.POST_QUANTUM, score=10.0, finding_count=3,
                          worst_severity=Severity.LOW),
        ],
        forward_secrecy_ratio=round(len(pfs_sessions) / len(encrypted_sessions), 2),
        pq_ready_hosts=sum(1 for h in hosts.values() if h.pq_ready),
        deprecated_version_sessions=sum(
            1 for s in sessions if s.handshake and s.handshake.negotiated_version.is_deprecated),
        cleartext_credential_sessions=sum(
            1 for s in sessions if s.features and s.features.credentials_in_cleartext),
        compliance={
            "RFC 8996": "fail",
            "RFC 9325": "fail",
            "RFC 8314": "fail",
            "RFC 7435": "pass",
            "NIST SP 800-52 Rev 2": "partial",
            "CERT-In Cryptographic Controls": "fail",
            "PCI-DSS 4.0 (4.2.1)": "fail",
        },
        summary=(
            "Two of eight mail servers are in an actively unsafe state. mail-05 "
            "authenticated users over an unencrypted channel after its STARTTLS "
            "capability was stripped in transit, and mail-06 negotiated TLS 1.0 with "
            "RC4 while presenting an expired self-signed certificate on a mail-access "
            "port. Neither is a theoretical weakness: credentials from this capture "
            "should be treated as compromised. No server in the fleet offers "
            "post-quantum key exchange."
        ),
    )

    return Report(
        capture=Capture(
            path="captures/enterprise_mail_2026-09-23.pcap",
            filename="enterprise_mail_2026-09-23.pcap",
            sha256=CAPTURE_SHA, size_bytes=48_210_944, packet_count=284_118,
            first_packet_at=NOW, last_packet_at=NOW + timedelta(minutes=37),
            analysed_at=NOW + timedelta(hours=1),
        ),
        sessions=sessions,
        hosts=sorted(hosts.values(), key=lambda h: h.score),
        fleet=fleet,
        prioritised_findings=prioritised,
        executive_summary=fleet.summary,
        generated_at=NOW + timedelta(hours=1),
        evaluation_metrics={
            "rule_precision": 0.97,
            "rule_recall": 0.94,
            "protocol_id_accuracy": 1.00,
            "classifier_roc_auc": 0.982,
            "anomaly_detection_precision_at_10": 0.80,
            "throughput_mb_per_second": 14.2,
        },
    )


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    out_dir = root / "fixtures"
    out_dir.mkdir(exist_ok=True)

    report = build_report()
    target = out_dir / "report.sample.json"
    target.write_text(report.to_json(), encoding="utf-8")

    # Also emit each session on its own, for focused component development.
    sessions_dir = out_dir / "sessions"
    sessions_dir.mkdir(exist_ok=True)
    for s in report.sessions:
        (sessions_dir / f"{s.session_id}.json").write_text(s.to_json(), encoding="utf-8")

    size_kb = target.stat().st_size / 1024
    print(f"wrote {target.relative_to(root)}  ({size_kb:.0f} KB)")
    print(f"wrote {len(report.sessions)} session fixtures to {sessions_dir.relative_to(root)}")
    print(f"  hosts: {len(report.hosts)}  findings: {len(report.prioritised_findings)}")
    print(f"  fleet grade: {report.fleet.grade.value}  score: {report.fleet.score}")


if __name__ == "__main__":
    main()
