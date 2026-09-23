"""S7 - cryptographic feature extraction. Objective O01.

The PS lists feature extraction as its own capability, so `FeatureVector` is a
documented, inspectable artifact with a panel in the UI, not an anonymous array
hidden inside a `predict()` call.

One principle runs through this module: **absent is not false.** When a stage
has not run, or when something is genuinely unobservable - certificates in TLS
1.3, an EHLO re-issue inside an encrypted channel - the feature is set to the
value that makes the corresponding rule *not* fire. Inventing a finding out of
missing data would be worse than missing one, and a demo full of false
positives is how a tool loses a judge's trust.
"""

from __future__ import annotations

from schema import FeatureVector, MailSession, PortRole, TlsMode

#: Cipher-suite name fragments that imply a property. Used until S4 supplies a
#: parsed suite; the names come from the IANA registry spellings.
_WEAK_MARKERS = {
    "rc4": "cipher_is_rc4",
    "3des": "cipher_is_3des",
    "des-cbc3": "cipher_is_3des",
    "null": "cipher_is_null_or_anon",
    "anon": "cipher_is_null_or_anon",
    "export": "cipher_is_export",
}


def _cipher_flags(name: str | None) -> dict[str, bool]:
    flags = {
        "cipher_is_rc4": False, "cipher_is_3des": False,
        "cipher_is_null_or_anon": False, "cipher_is_export": False,
        "cipher_is_aead": False, "cipher_is_cbc": False,
    }
    if not name:
        return flags
    lowered = name.lower()
    for marker, field in _WEAK_MARKERS.items():
        if marker in lowered:
            flags[field] = True
    flags["cipher_is_aead"] = any(
        token in lowered for token in ("gcm", "chacha20", "poly1305", "ccm"))
    flags["cipher_is_cbc"] = "cbc" in lowered or (
        not flags["cipher_is_aead"] and lowered.endswith(("-sha", "-sha256", "-sha384")))
    return flags


def extract(session: MailSession, fleet_context: dict | None = None) -> FeatureVector:
    """Build the model input for one session. Objective O01.

    `fleet_context` supplies capture-wide counts so the JA3 rarity features can
    be filled in; pass None in unit tests or when scoring a session alone.
    """
    f = FeatureVector()
    fleet_context = fleet_context or {}

    # -- session context (USP-01) ------------------------------------------
    f.port_role_is_relay = session.port_role is PortRole.MTA_RELAY
    f.port_role_is_submission = session.port_role is PortRole.SUBMISSION
    f.port_role_is_access = session.port_role is PortRole.MAIL_ACCESS
    f.tls_mode_is_implicit = session.tls_mode is TlsMode.IMPLICIT
    f.tls_mode_is_starttls = session.tls_mode is TlsMode.STARTTLS
    f.tls_mode_is_cleartext = session.tls_mode is TlsMode.CLEARTEXT

    # -- STARTTLS behaviour (D02) ------------------------------------------
    v = session.starttls
    if v is not None:
        f.starttls_advertised = bool(v.v1_advertised)
        f.starttls_completed = bool(v.upgrade_succeeded)
        f.auth_before_tls = bool(v.v8_auth_offered_before_tls)
        f.credentials_in_cleartext = bool(v.v9_credentials_before_tls)
        f.starttls_stripped_suspected = bool(v.v2_capability_mangled)
        # None means "we could not observe it" - see the note in proto/starttls.
        # Defaulting to True keeps STARTTLS-EHLO-NOT-REISSUED from firing on
        # something that happened inside the encrypted channel.
        f.starttls_ehlo_reissued = v.v7_ehlo_reissued is not False

    # -- attack evidence (USP-02) ------------------------------------------
    a = session.attack_evidence
    if a is not None:
        f.starttls_stripped_suspected = (
            f.starttls_stripped_suspected or a.starttls_stripping_suspected)
        f.credentials_in_cleartext = (
            f.credentials_in_cleartext or bool(a.credential_exposure))
        f.downgrade_sentinel_present = a.downgrade_sentinel_present
        f.fallback_scsv_present = a.fallback_scsv_present
        f.cipher_intersection_anomaly = a.cipher_intersection_anomaly
        f.certificate_substitution = a.certificate_substitution

    # -- handshake (D05-D07, D15, USP-05) ----------------------------------
    h = session.handshake
    if h is not None:
        f.tls_version_num = h.negotiated_version.numeric
        f.is_deprecated_version = h.negotiated_version.is_deprecated
        f.cipher_strength_bits = h.cipher_bits or 0
        flags = _cipher_flags(h.cipher_suite_name)
        for name, value in flags.items():
            setattr(f, name, value)
        if h.is_aead:
            f.cipher_is_aead = True
            f.cipher_is_cbc = False
        f.kex_is_ephemeral = h.key_exchange.has_forward_secrecy
        f.has_forward_secrecy = h.has_forward_secrecy
        f.kex_group_bits = h.key_exchange_bits or 0
        f.kex_is_anon = "anon" in (h.cipher_suite_name or "").lower()
        f.pq_hybrid_offered = bool(h.pq_groups_offered)
        f.pq_hybrid_negotiated = bool(h.pq_group_negotiated)
        f.handshake_alert_count = len(h.alerts)
        if h.client_hello is not None:
            f.sni_present = bool(h.client_hello.server_name)
            f.alpn_present = bool(h.client_hello.alpn)
            f.fallback_scsv_present = (
                f.fallback_scsv_present or h.client_hello.fallback_scsv)
        if h.server_hello is not None:
            f.renegotiation_info_present = h.server_hello.renegotiation_info
            f.compression_enabled = bool(h.server_hello.compression_method)
            f.session_resumed = h.server_hello.session_resumed
            f.downgrade_sentinel_present = (
                f.downgrade_sentinel_present or bool(h.server_hello.downgrade_sentinel))
            # TLS 1.3 always provides secure renegotiation semantics; the
            # extension is simply not used, so its absence is not a finding.
            if h.negotiated_version.numeric >= 1.3:
                f.renegotiation_info_present = True

    # -- certificates (D09-D12) --------------------------------------------
    chain = session.chain
    leaf = next((c for c in session.certificates if c.chain_position == 0), None)
    if chain is not None and chain.status.value == "opaque_tls13":
        # Encrypted Certificate message. Report it as opaque and set every
        # certificate feature to its benign value so no CERT-* rule fires on
        # data we were never able to see.
        f.cert_opaque_tls13 = True
        f.cert_present = False
        f.cert_chain_complete = True
        f.cert_hostname_match = True
    elif leaf is not None:
        f.cert_present = True
        days = leaf.days_to_expiry(session.flow.started_at if session.flow else None)
        f.cert_days_to_expiry = days if days is not None else 0
        f.cert_is_expired = f.cert_days_to_expiry < 0
        f.cert_is_self_signed = leaf.is_self_signed
        f.cert_key_bits = leaf.public_key_bits or 0
        f.cert_key_is_rsa = leaf.public_key_algorithm.value == "rsa"
        f.cert_sig_is_weak = leaf.signature_algorithm.is_weak
        f.cert_chain_length = len(session.certificates)
        if chain is not None:
            f.cert_chain_complete = chain.complete
            f.cert_hostname_match = bool(chain.hostname_matched)
    else:
        # No certificate stage has run, or the session never reached TLS.
        # Benign defaults, for the same reason as the TLS 1.3 case above.
        f.cert_chain_complete = True
        f.cert_hostname_match = True

    # -- fleet-relative (filled at S9) -------------------------------------
    f.ja3_rarity = float(fleet_context.get("ja3_rarity", 0.0))
    f.ja3s_rarity = float(fleet_context.get("ja3s_rarity", 0.0))
    return f
