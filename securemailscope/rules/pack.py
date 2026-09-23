"""S6 - the detection rule pack. Deliverables D13, D14, D15, and objective O02.

Every rule is a predicate over a `FeatureVector` plus the minimum session
context (host, port, role). That is a deliberate design choice, not an
accident: the SAME rules run over real parsed sessions and over the synthetic
feature vectors that train the classifier (ADR-0003). One implementation, so
the model's labelling oracle can never drift from the shipping detector.

Every rule carries its `standards` and `remediation` inline. Those two fields
give us objective O02 and the compliance report card (USP-08) for free, but
only because they are written at authoring time.

Severity emitted here is the BASE severity. `rules/severity.py` then applies
the role-aware adjustment (USP-01) and records the reasoning.

Pure stdlib: this module must import and run with nothing installed, because it
is what generates the ML training labels.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace

from schema import (
    Evidence,
    FeatureVector,
    Finding,
    FindingCategory,
    PortRole,
    Remediation,
    Severity,
    StandardRef,
)

from . import standards as std
from .severity import adjust

# --------------------------------------------------------------------------- #
# Context
# --------------------------------------------------------------------------- #


@dataclass
class RuleContext:
    """Everything a rule is allowed to look at.

    Keeping this narrow is what lets the synthetic corpus generator produce
    valid inputs without constructing a whole parsed session.
    """

    features: FeatureVector
    host: str | None = None
    port: int = 0
    port_role: PortRole = PortRole.UNKNOWN
    evidence: Evidence = field(default_factory=Evidence)

    @property
    def f(self) -> FeatureVector:
        return self.features

    @property
    def is_encrypted(self) -> bool:
        return not self.features.tls_mode_is_cleartext and self.features.tls_version_num > 0


# --------------------------------------------------------------------------- #
# Rule definition
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rule:
    """One detection rule."""

    rule_id: str
    title: str
    category: FindingCategory
    base_severity: Severity
    predicate: Callable[[RuleContext], bool]
    description: str
    standards: tuple[StandardRef, ...] = ()
    attacks: tuple[str, ...] = ()
    remediation: Remediation | None = None
    evidence_note: str = ""

    def fires(self, ctx: RuleContext) -> bool:
        try:
            return bool(self.predicate(ctx))
        except Exception:  # noqa: BLE001 - a broken rule must not kill the run
            return False

    def to_finding(self, ctx: RuleContext) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            description=self.description,
            category=self.category,
            base_severity=self.base_severity,
            severity=self.base_severity,  # severity.adjust() refines this
            affected_host=ctx.host,
            affected_port=ctx.port,
            port_role=ctx.port_role,
            standards=list(self.standards),
            related_attacks=list(self.attacks),
            remediation=self.remediation,
            evidence=replace(ctx.evidence, note=self.evidence_note or ctx.evidence.note),
        )


# --------------------------------------------------------------------------- #
# Reusable remediation blocks
# --------------------------------------------------------------------------- #

FIX_PROTOCOL = Remediation(
    summary="Disable SSL and TLS 1.0/1.1; require TLS 1.2 as a minimum and prefer 1.3.",
    postfix="smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1\n"
            "smtpd_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1\n"
            "smtp_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1",
    dovecot="ssl_min_protocol = TLSv1.2",
    exchange="Disable TLS 1.0/1.1 under the SCHANNEL registry keys, then reboot.",
    effort="low",
    risk_of_change="May break clients older than roughly 2015. Check logs for "
                   "legacy user agents before enforcing.",
)

FIX_CIPHER = Remediation(
    summary="Restrict the cipher list to AEAD suites with forward secrecy.",
    postfix="smtpd_tls_mandatory_ciphers = high\n"
            "tls_high_cipherlist = ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!RC4:!3DES:!EXPORT",
    dovecot="ssl_cipher_list = ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!RC4:!3DES:!EXPORT\n"
            "ssl_prefer_server_ciphers = yes",
    effort="low",
    risk_of_change="Low. Every client from the last decade supports AEAD suites.",
)

FIX_PFS = Remediation(
    summary="Prefer ECDHE key exchange and disable static RSA suites.",
    postfix="tls_preempt_cipherlist = yes\ntls_eecdh_strong_curve = prime256v1",
    dovecot="ssl_prefer_server_ciphers = yes\nssl_cipher_list = ECDHE+AESGCM:ECDHE+CHACHA20",
    effort="low", risk_of_change="Low.",
)

FIX_CERT = Remediation(
    summary="Install a certificate from a publicly trusted CA and automate renewal.",
    postfix="smtpd_tls_cert_file = /etc/letsencrypt/live/HOST/fullchain.pem\n"
            "smtpd_tls_key_file  = /etc/letsencrypt/live/HOST/privkey.pem",
    dovecot="ssl_cert = </etc/letsencrypt/live/HOST/fullchain.pem\n"
            "ssl_key  = </etc/letsencrypt/live/HOST/privkey.pem",
    effort="low", risk_of_change="None.",
)

FIX_REQUIRE_TLS = Remediation(
    summary="Require TLS before authentication, and prefer implicit TLS on 465/993/995.",
    postfix="smtpd_tls_security_level = encrypt\nsmtpd_tls_auth_only = yes",
    dovecot="ssl = required\ndisable_plaintext_auth = yes",
    effort="low",
    risk_of_change="Clients that cannot do TLS will stop working, which is the point.",
)

FIX_ROTATE_CREDS = Remediation(
    summary="Treat every account seen in this capture as compromised and rotate "
            "immediately, then enforce TLS before AUTH.",
    postfix="smtpd_tls_auth_only = yes",
    dovecot="disable_plaintext_auth = yes",
    effort="trivial", risk_of_change="None. Do this first.",
)

FIX_MTA_STS = Remediation(
    summary="Publish an MTA-STS policy (RFC 8461) and a DANE TLSA record (RFC 7672) "
            "so compliant senders are required to use authenticated TLS.",
    generic="_mta-sts.<domain> TXT  \"v=STSv1; id=...\"\n"
            "https://mta-sts.<domain>/.well-known/mta-sts.txt  mode: enforce",
    effort="medium",
    risk_of_change="A misconfigured MTA-STS policy can defer inbound mail. Start in "
                   "testing mode and watch TLS-RPT reports.",
)

FIX_PQ = Remediation(
    summary="Plan migration to hybrid post-quantum key exchange (X25519MLKEM768) "
            "as your TLS library gains support.",
    generic="Track OpenSSL 3.5+ hybrid group support and enable it in the MTA build "
            "once available. Prioritise systems with long mail retention.",
    effort="high", risk_of_change="Requires a TLS library upgrade.",
)


# --------------------------------------------------------------------------- #
# The rule pack
# --------------------------------------------------------------------------- #

REGISTRY: list[Rule] = [

    # -- protocol version (D13) --------------------------------------------
    Rule(
        "TLS-SSL-PROHIBITED", "SSL 2.0 or 3.0 negotiated",
        FindingCategory.PROTOCOL, Severity.CRITICAL,
        lambda c: 0 < c.f.tls_version_num < 1.0,
        "SSL 2.0 and 3.0 are prohibited. Both are structurally broken; SSL 3.0 is "
        "trivially exploitable via POODLE.",
        (std.RFC8996_SSL, std.NIST_80052, std.CERT_IN, std.PCI_DSS),
        ("POODLE", "DROWN"), FIX_PROTOCOL, "ServerHello.legacy_version",
    ),
    Rule(
        "TLS-DEPRECATED-VERSION", "Deprecated protocol version negotiated",
        FindingCategory.PROTOCOL, Severity.HIGH,
        lambda c: 1.0 <= c.f.tls_version_num <= 1.1,
        "The session negotiated TLS 1.0 or 1.1, which RFC 8996 formally deprecates. "
        "Neither offers AEAD cipher suites or modern signature algorithms, and both "
        "are exposed to BEAST and Lucky13 when CBC suites are in use.",
        (std.RFC8996, std.NIST_80052, std.CIS_TLS, std.CERT_IN, std.PCI_DSS),
        ("BEAST", "Lucky13"), FIX_PROTOCOL, "ServerHello.legacy_version",
    ),

    # -- cipher suite (D13) -------------------------------------------------
    Rule(
        "TLS-WEAK-CIPHER-RC4", "RC4 cipher suite negotiated",
        FindingCategory.CIPHER, Severity.HIGH,
        lambda c: c.f.cipher_is_rc4,
        "RC4 has statistical biases in its keystream that allow plaintext recovery "
        "from repeated encryptions. RFC 7465 prohibits it outright.",
        (std.RFC7465, std.RFC9325, std.CERT_IN), ("RC4 keystream biases",),
        FIX_CIPHER, "ServerHello.cipher_suite",
    ),
    Rule(
        "TLS-WEAK-CIPHER-3DES", "3DES cipher suite negotiated",
        FindingCategory.CIPHER, Severity.HIGH,
        lambda c: c.f.cipher_is_3des,
        "3DES has a 64-bit block size, making it vulnerable to the Sweet32 birthday "
        "attack on long-lived connections - which mail sessions frequently are.",
        (std.RFC9325, std.CIS_TLS), ("Sweet32",), FIX_CIPHER, "ServerHello.cipher_suite",
    ),
    Rule(
        "TLS-NULL-OR-ANON-CIPHER", "NULL or anonymous cipher suite negotiated",
        FindingCategory.CIPHER, Severity.CRITICAL,
        lambda c: c.f.cipher_is_null_or_anon,
        "The negotiated suite provides no encryption or no authentication. Traffic is "
        "readable, or the peer is unauthenticated and trivially impersonated.",
        (std.RFC9325, std.PCI_DSS), ("Passive interception", "Man-in-the-middle"),
        FIX_CIPHER, "ServerHello.cipher_suite",
    ),
    Rule(
        "TLS-EXPORT-CIPHER", "Export-grade cipher suite negotiated",
        FindingCategory.CIPHER, Severity.CRITICAL,
        lambda c: c.f.cipher_is_export,
        "Export-grade suites are deliberately weakened to 40 or 56 bits and are "
        "breakable with commodity hardware.",
        (std.RFC9325, std.CERT_IN), ("FREAK", "Logjam"), FIX_CIPHER,
        "ServerHello.cipher_suite",
    ),
    Rule(
        "TLS-WEAK-CIPHER-BITS", "Cipher provides less than 128-bit security",
        FindingCategory.CIPHER, Severity.HIGH,
        lambda c: c.is_encrypted and 0 < c.f.cipher_strength_bits < 128,
        "RFC 9325 requires at least 112 bits of security; anything under 128 bits is "
        "below current practice.",
        (std.RFC9325, std.NIST_80052), (), FIX_CIPHER, "ServerHello.cipher_suite",
    ),
    Rule(
        "TLS-CBC-CIPHER", "Non-AEAD (CBC) cipher suite negotiated",
        FindingCategory.CIPHER, Severity.MEDIUM,
        lambda c: c.is_encrypted and c.f.cipher_is_cbc and not c.f.cipher_is_aead,
        "CBC construction with HMAC has a long history of padding-oracle and timing "
        "attacks. RFC 9325 recommends AEAD suites.",
        (std.RFC9325,), ("Lucky13", "BEAST"), FIX_CIPHER, "ServerHello.cipher_suite",
    ),

    # -- key exchange and forward secrecy (D07, D15) ------------------------
    Rule(
        "TLS-NO-FORWARD-SECRECY", "Session negotiated without forward secrecy",
        FindingCategory.KEY_EXCHANGE, Severity.MEDIUM,
        lambda c: c.is_encrypted and not c.f.has_forward_secrecy and not c.f.kex_is_anon,
        "Static key exchange was used. Anyone recording this traffic who later obtains "
        "the server's private key can decrypt it retroactively - the central risk for "
        "archived mail.",
        (std.RFC9325_PFS, std.NIST_80052), ("Retrospective decryption",),
        FIX_PFS, "ServerHello.cipher_suite key exchange component",
    ),
    Rule(
        "TLS-ANON-KEY-EXCHANGE", "Anonymous key exchange negotiated",
        FindingCategory.KEY_EXCHANGE, Severity.CRITICAL,
        lambda c: c.f.kex_is_anon,
        "An anonymous key exchange authenticates neither party, so the session is "
        "encrypted but trivially interceptable.",
        (std.RFC9325,), ("Man-in-the-middle",), FIX_CIPHER, "ServerHello.cipher_suite",
    ),
    Rule(
        "TLS-WEAK-DH-GROUP", "Diffie-Hellman group smaller than 2048 bits",
        FindingCategory.KEY_EXCHANGE, Severity.HIGH,
        # A group size above 256 bits means finite-field DH rather than an
        # elliptic curve, where 256 bits is already strong. Only FFDHE groups
        # are measured against the 2048-bit floor.
        lambda c: c.f.kex_is_ephemeral and 256 < c.f.kex_group_bits < 2048,
        "The finite-field Diffie-Hellman group is under 2048 bits. Precomputation "
        "against common groups makes this breakable, which is the Logjam attack.",
        (std.RFC9325, std.NIST_80052_KEY), ("Logjam",), FIX_PFS,
        "ServerKeyExchange DH parameters",
    ),

    # -- certificate TRUST (D09, D10) - role-adjusted -----------------------
    Rule(
        "CERT-EXPIRED", "Expired certificate presented",
        FindingCategory.CERTIFICATE, Severity.HIGH,
        lambda c: c.f.cert_present and c.f.cert_is_expired and not c.f.cert_is_self_signed,
        "The server presented a certificate whose validity period has ended. Clients "
        "that validate will refuse the connection or warn the user.",
        (std.RFC8314,), ("Man-in-the-middle",), FIX_CERT, "leaf certificate notAfter",
    ),
    Rule(
        "CERT-EXPIRED-SELF-SIGNED", "Expired self-signed certificate presented",
        FindingCategory.CERTIFICATE, Severity.HIGH,
        lambda c: c.f.cert_present and c.f.cert_is_expired and c.f.cert_is_self_signed,
        "The server presented a self-signed certificate that has also expired. There "
        "is no trust path and no validity, so a client cannot distinguish this server "
        "from an impostor.",
        (std.RFC8314, std.RFC7435), ("Man-in-the-middle", "Credential theft"),
        FIX_CERT, "leaf certificate, self-signed and expired",
    ),
    Rule(
        "CERT-EXPIRING-SOON", "Certificate expires within 30 days",
        FindingCategory.CERTIFICATE, Severity.MEDIUM,
        lambda c: c.f.cert_present and not c.f.cert_is_expired
                  and 0 <= c.f.cert_days_to_expiry <= 30,
        "Renewal has not yet happened. On expiry, validating clients will stop "
        "connecting and mail flow will break.",
        (std.RFC8314,), (),
        Remediation(summary="Renew now and automate renewal so this cannot recur.",
                    generic="certbot renew --deploy-hook 'systemctl reload postfix dovecot'",
                    effort="trivial", risk_of_change="None."),
        "leaf certificate notAfter",
    ),
    Rule(
        "CERT-SELF-SIGNED", "Self-signed certificate presented",
        FindingCategory.CERTIFICATE, Severity.MEDIUM,
        lambda c: c.f.cert_present and c.f.cert_is_self_signed and not c.f.cert_is_expired,
        "The certificate is its own issuer, so there is no trust path a client can "
        "validate.",
        (std.RFC8314, std.RFC7435), ("Man-in-the-middle",), FIX_CERT,
        "leaf certificate issuer equals subject",
    ),
    Rule(
        "CERT-CHAIN-INCOMPLETE", "Certificate chain is missing an intermediate",
        FindingCategory.CERTIFICATE, Severity.MEDIUM,
        lambda c: c.f.cert_present and not c.f.cert_chain_complete
                  and not c.f.cert_is_self_signed,
        "The server did not send the full chain. Clients that cannot fetch the missing "
        "intermediate will fail validation even though the certificate itself is fine - "
        "a classic intermittent mail-delivery failure.",
        (std.RFC8314,), (),
        Remediation(summary="Serve the full chain: concatenate leaf and intermediates.",
                    postfix="smtpd_tls_cert_file = /path/fullchain.pem",
                    dovecot="ssl_cert = </path/fullchain.pem",
                    effort="trivial", risk_of_change="None."),
        "Certificate message chain",
    ),
    Rule(
        "CERT-HOSTNAME-MISMATCH", "Certificate does not match the requested hostname",
        FindingCategory.CERTIFICATE, Severity.HIGH,
        lambda c: c.f.cert_present and not c.f.cert_hostname_match
                  and c.f.sni_present and not c.f.cert_opaque_tls13,
        "No subjectAltName matches the name the client asked for, so a validating "
        "client cannot confirm it reached the right server.",
        (std.RFC8314,), ("Man-in-the-middle",), FIX_CERT,
        "certificate subjectAltName versus ClientHello SNI",
    ),

    # -- certificate STRENGTH (D11, D12) - NEVER role-adjusted, see ADR-0010
    Rule(
        "CERT-WEAK-KEY", "Certificate public key is below 2048 bits",
        FindingCategory.CERTIFICATE_STRENGTH, Severity.HIGH,
        lambda c: c.f.cert_present and c.f.cert_key_is_rsa and 0 < c.f.cert_key_bits < 2048,
        "RSA keys under 2048 bits are below the NIST minimum and within reach of "
        "factorisation by a well-resourced adversary.",
        (std.NIST_80052_KEY, std.RFC9325, std.CERT_IN), ("Factorisation",),
        Remediation(summary="Reissue with a 2048-bit RSA key or a P-256 ECDSA key.",
                    effort="low", risk_of_change="None."),
        "certificate SubjectPublicKeyInfo",
    ),
    Rule(
        "CERT-WEAK-SIGNATURE", "Certificate signed with a broken hash algorithm",
        FindingCategory.CERTIFICATE_STRENGTH, Severity.HIGH,
        lambda c: c.f.cert_present and c.f.cert_sig_is_weak,
        "MD5 and SHA-1 signatures are collision-broken. A chosen-prefix collision can "
        "produce a second certificate with the same signature.",
        (std.RFC9325, std.NIST_80052, std.CERT_IN), ("Chosen-prefix collision",),
        Remediation(summary="Reissue with a SHA-256 or stronger signature.",
                    effort="low", risk_of_change="None."),
        "certificate signatureAlgorithm",
    ),

    # -- STARTTLS behaviour (D02) ------------------------------------------
    Rule(
        "STARTTLS-ADVERTISED-NOT-USED", "STARTTLS advertised but never used",
        FindingCategory.STARTTLS, Severity.HIGH,
        # Not on port 25. There the client is a remote peer MTA outside this
        # organisation's control, SMTP-RELAY-NO-TLS already covers it, and
        # raising a HIGH would be exactly the false positive USP-01 exists to
        # prevent - in our own rule pack.
        lambda c: c.f.starttls_advertised and not c.f.starttls_completed
                  and c.f.tls_mode_is_cleartext and not c.f.starttls_stripped_suspected
                  and c.port_role is not PortRole.MTA_RELAY,
        "The server offered the upgrade and the client ignored it, continuing in "
        "cleartext. This is a client-side policy failure and is entirely preventable.",
        (std.RFC8314, std.RFC4954), ("Passive interception",), FIX_REQUIRE_TLS,
        "EHLO / CAPABILITY response",
    ),
    Rule(
        "STARTTLS-NOT-OFFERED", "Server does not offer STARTTLS",
        FindingCategory.STARTTLS, Severity.HIGH,
        lambda c: c.f.tls_mode_is_cleartext and not c.f.starttls_advertised
                  and not c.f.starttls_stripped_suspected
                  and c.port_role is not PortRole.MTA_RELAY,
        "The server advertises no way to upgrade the connection, so every session to "
        "it is unencrypted by design.",
        (std.RFC8314,), ("Passive interception", "Credential theft"), FIX_REQUIRE_TLS,
        "EHLO / CAPABILITY response",
    ),
    Rule(
        "STARTTLS-EHLO-NOT-REISSUED", "EHLO not re-issued after the TLS upgrade",
        FindingCategory.CONFIGURATION, Severity.LOW,
        lambda c: c.f.tls_mode_is_starttls and c.f.starttls_completed
                  and not c.f.starttls_ehlo_reissued,
        "RFC 3207 requires the client to discard cached capabilities and re-issue EHLO "
        "after the handshake. Skipping it risks acting on capabilities that were "
        "observed in the cleartext phase and may have been tampered with.",
        (std.RFC3207,), ("Capability confusion",),
        Remediation(summary="Update the client or MTA to re-issue EHLO after STARTTLS.",
                    effort="low", risk_of_change="None."),
        "post-handshake application data",
    ),

    # -- attack evidence (USP-02) ------------------------------------------
    Rule(
        "ATTACK-STARTTLS-STRIPPED", "STARTTLS capability stripped in transit",
        FindingCategory.ATTACK_EVIDENCE, Severity.CRITICAL,
        lambda c: c.f.starttls_stripped_suspected,
        "The capability keyword was overwritten in place with a same-length "
        "placeholder, preserving TCP sequence numbers. This is the signature of an "
        "on-path attacker removing the client's option to upgrade.",
        (std.RFC8314, std.RFC4954, std.RFC8461),
        ("STARTTLS stripping", "Credential theft", "Passive interception"),
        FIX_REQUIRE_TLS, "EHLO response capability line",
    ),
    Rule(
        "ATTACK-CLEARTEXT-CREDENTIALS", "Account credentials transmitted in cleartext",
        FindingCategory.ATTACK_EVIDENCE, Severity.CRITICAL,
        lambda c: c.f.credentials_in_cleartext,
        "An authentication exchange completed before any TLS handshake. The username "
        "and password were recoverable by any observer on the path, including this tool.",
        (std.RFC8314, std.RFC4954, std.PCI_DSS),
        ("Credential theft", "Account takeover"), FIX_ROTATE_CREDS,
        "AUTH command payload",
    ),
    Rule(
        "ATTACK-AUTH-BEFORE-TLS", "Plaintext AUTH advertised before TLS",
        FindingCategory.CONFIGURATION, Severity.HIGH,
        lambda c: c.f.auth_before_tls and not c.f.credentials_in_cleartext,
        "The server advertised plaintext authentication mechanisms before the session "
        "was encrypted, which RFC 4954 forbids. No credentials were observed, but the "
        "configuration invites the exposure.",
        (std.RFC4954, std.RFC8314), ("Credential theft",), FIX_REQUIRE_TLS,
        "EHLO / CAPABILITY response",
    ),
    Rule(
        "ATTACK-DOWNGRADE-SENTINEL", "TLS downgrade sentinel present in ServerHello",
        FindingCategory.ATTACK_EVIDENCE, Severity.HIGH,
        lambda c: c.f.downgrade_sentinel_present,
        "A TLS 1.3-capable server negotiated an older version and set the RFC 8446 "
        "downgrade marker in ServerHello.random. Something on the path forced the "
        "version down, or the server is misconfigured.",
        (std.RFC8446_DOWNGRADE, std.RFC9325), ("Protocol downgrade", "Man-in-the-middle"),
        Remediation(summary="Verify the server's protocol configuration and inspect the "
                            "path for an intercepting middlebox.",
                    effort="medium", risk_of_change="Investigation only."),
        "ServerHello.random last 8 bytes",
    ),
    Rule(
        "ATTACK-CIPHER-INTERSECTION-ANOMALY",
        "Server selected a weaker suite than both parties supported",
        FindingCategory.ATTACK_EVIDENCE, Severity.MEDIUM,
        lambda c: c.f.cipher_intersection_anomaly,
        "The server chose a materially weaker cipher suite than the strongest one both "
        "sides advertised. A rule looking only at the negotiated suite cannot see this; "
        "it requires comparing both halves of the handshake.",
        (std.RFC9325,), ("Protocol downgrade", "Man-in-the-middle"),
        Remediation(summary="Check server cipher preference order and look for an "
                            "intercepting proxy.",
                    postfix="tls_preempt_cipherlist = yes",
                    effort="medium", risk_of_change="Investigation only."),
        "ClientHello versus ServerHello cipher lists",
    ),
    Rule(
        "ATTACK-CERT-SUBSTITUTION", "Server presented differing certificates",
        FindingCategory.ATTACK_EVIDENCE, Severity.HIGH,
        lambda c: c.f.certificate_substitution,
        "The same server identity presented certificates with different fingerprints "
        "within a single capture. That is either an unmanaged rotation nobody approved, "
        "or interception.",
        (std.RFC8314,), ("Man-in-the-middle",),
        Remediation(summary="Confirm which certificate is authoritative and investigate "
                            "the path for the other.",
                    effort="medium", risk_of_change="Investigation only."),
        "Certificate message fingerprints across sessions",
    ),

    # -- configuration hygiene (D14) ---------------------------------------
    Rule(
        "CONFIG-NO-RENEGOTIATION-INFO", "Secure renegotiation not supported",
        FindingCategory.CONFIGURATION, Severity.MEDIUM,
        lambda c: c.is_encrypted and c.f.tls_version_num < 1.3
                  and not c.f.renegotiation_info_present,
        "The renegotiation_info extension is absent, leaving the session exposed to the "
        "CVE-2009-3555 prefix-injection attack.",
        (std.RFC5746,), ("Renegotiation prefix injection",),
        Remediation(summary="Upgrade the TLS library; every current version supports this.",
                    effort="medium", risk_of_change="Requires a service restart."),
        "ServerHello extensions",
    ),
    Rule(
        "CONFIG-COMPRESSION-ENABLED", "TLS compression enabled",
        FindingCategory.CONFIGURATION, Severity.MEDIUM,
        lambda c: c.f.compression_enabled,
        "TLS-level compression enables the CRIME attack, which recovers secrets by "
        "observing compressed lengths.",
        (std.RFC9325,), ("CRIME",),
        Remediation(summary="Disable TLS compression.", effort="low",
                    risk_of_change="None."),
        "ServerHello.compression_method",
    ),
    Rule(
        "CONFIG-NO-SNI", "Client did not send Server Name Indication",
        FindingCategory.CONFIGURATION, Severity.LOW,
        lambda c: c.is_encrypted and not c.f.sni_present,
        "Without SNI the server cannot select the correct certificate for a virtual "
        "host, and we cannot verify the hostname the client intended to reach.",
        (std.RFC9325,), (),
        Remediation(summary="Configure the client to send SNI.", effort="low",
                    risk_of_change="None."),
        "ClientHello extensions",
    ),
    Rule(
        "SMTP-RELAY-NO-TLS", "Inbound relay session not encrypted",
        FindingCategory.CONFIGURATION, Severity.MEDIUM,
        lambda c: c.f.tls_mode_is_cleartext and c.port_role is PortRole.MTA_RELAY,
        "A peer MTA delivered mail without attempting STARTTLS. The remote sender "
        "controls this, not the local server - but publishing MTA-STS or DANE would "
        "require compliant senders to encrypt.",
        (std.RFC7435, std.RFC8461, std.RFC7672), ("Passive interception",),
        FIX_MTA_STS, "EHLO exchange",
    ),

    # -- analysis coverage --------------------------------------------------
    Rule(
        "ANALYSIS-INCOMPLETE-HANDSHAKE", "Encrypted session not fully analysed",
        FindingCategory.CONFIGURATION, Severity.INFO,
        lambda c: (c.f.tls_mode_is_implicit or c.f.tls_mode_is_starttls)
                  and c.f.tls_version_num == 0.0,
        "The session reached TLS but the handshake was not parsed, so no "
        "conclusion can be drawn about its version, cipher suite, key exchange "
        "or certificate. This is a gap in coverage, not a clean result.",
        (std.NIST_80052,), (),
        Remediation(
            summary="No server-side action. Re-run once handshake parsing (S4) is "
                    "available, or check whether the capture truncated the handshake.",
            effort="trivial", risk_of_change="None."),
        "TLS records present but unparsed",
    ),

    # -- post-quantum (USP-05) ---------------------------------------------
    Rule(
        "PQ-NOT-READY", "No post-quantum key exchange offered",
        FindingCategory.POST_QUANTUM, Severity.LOW,
        lambda c: c.is_encrypted and not c.f.pq_hybrid_offered,
        "The ClientHello offered no hybrid post-quantum group. Traffic captured today "
        "can be stored and decrypted once a cryptographically relevant quantum computer "
        "exists - a present-tense concern for mail, which organisations retain for years.",
        (std.NIST_FIPS203,), ("Harvest now, decrypt later",), FIX_PQ,
        "ClientHello.supported_groups",
    ),
]

#: Fast lookup for tests and for the evaluation harness.
BY_ID: dict[str, Rule] = {r.rule_id: r for r in REGISTRY}


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #


def evaluate(ctx: RuleContext, apply_role_policy: bool = True) -> list[Finding]:
    """Run every rule over one context and return the findings that fired.

    With `apply_role_policy` the USP-01 adjustment runs too, which is what the
    pipeline wants. Tests that want to inspect raw base severities pass False.
    """
    findings = [rule.to_finding(ctx) for rule in REGISTRY if rule.fires(ctx)]
    if apply_role_policy:
        findings = [adjust(f) for f in findings]
    return sorted(findings, key=lambda f: (-f.severity.rank, f.rule_id))


def oracle_label(ctx: RuleContext) -> Severity:
    """The training label for one feature vector. ADR-0003.

    Defined as the worst role-adjusted severity produced by the rule pack, so
    the classifier learns the *shipping* policy - including the role-aware
    adjustment - rather than a parallel definition that could drift from it.
    """
    findings = evaluate(ctx)
    if not findings:
        return Severity.INFO
    return max((f.severity for f in findings), key=lambda s: s.rank)


def risk_target(ctx: RuleContext) -> float:
    """Continuous 0.0-1.0 regression target derived from the oracle label."""
    return oracle_label(ctx).rank / 4.0


def compliance_report(findings: list[Finding]) -> dict[str, str]:
    """Per-standard pass/fail scorecard. USP-08.

    A standard is 'fail' when a finding cites it as VIOLATED, 'pass' otherwise.
    Citations marked relation="context" are excluded: RFC 7435 is quoted to
    justify the opportunistic-relay downgrade, so counting it as a failure would
    be exactly backwards.
    """
    cited = {
        std.standard_key(ref)
        for f in findings
        for ref in f.standards
        if ref.relation == "violates"
    }
    return {
        std.standard_key(ref): ("fail" if std.standard_key(ref) in cited else "pass")
        for ref in std.ALL_STANDARDS
    }
