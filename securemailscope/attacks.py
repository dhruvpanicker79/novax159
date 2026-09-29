"""Attack feasibility matrix. USP-09.

A finding says *"RC4 was negotiated."* An administrator already knows that is
bad. What they cannot get from a scanner is the next sentence: **which named
attack actually works against this estate, and which ones do not.**

So every attack here is judged against what the capture showed, and the
verdicts that read `NOT APPLICABLE` carry as much weight as the ones that read
`FEASIBLE`. A report listing only what is broken is indistinguishable from a
report by a tool that did not look — stating *"POODLE: not applicable, no SSLv3
was negotiated in any of the 13 sessions"* is a claim, and it is checkable.

Three verdicts, not two. `NOT_OBSERVABLE` exists because TLS 1.3 encrypts the
certificate, an unparsed handshake hides everything, and a capture that never
contained a heartbeat message cannot rule out Heartbleed. Collapsing that into
"not applicable" would be claiming safety we never established, which is the
failure ADR-0014 exists to prevent.

Each test returns:

    True   this session is vulnerable
    False  this session was checked and is not
    None   this session could not be judged either way

and the fleet verdict is: **feasible** if any session returned True,
**not applicable** if at least one returned False and none returned True, and
**not observable** if nothing could be judged.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from schema import (AttackAssessment, AttackVerdict, MailSession, Report,
                    Severity, TlsVersion)


@dataclass(frozen=True)
class Attack:
    """One named attack and the condition that makes it work."""

    attack_id: str
    name: str
    reference: str
    year: int
    severity: Severity
    precondition: str
    test: Callable[[MailSession], bool | None]
    rules: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# Helpers. Each returns None when the session cannot be judged at all.
# --------------------------------------------------------------------------- #

def _tls(session: MailSession):
    """The handshake, or None when there is nothing to judge."""
    return session.handshake if session.handshake else None


def _suite(session: MailSession) -> str:
    h = _tls(session)
    return (h.cipher_suite_name or "").upper() if h else ""


def _version(session: MailSession) -> float:
    f = session.features
    return f.tls_version_num if f else 0.0


def _needs_handshake(fn):
    """Wrap a test so a session with no parsed handshake reports None rather
    than False. Answering "not vulnerable" about a session we could not read is
    the whole class of bug this project keeps finding."""
    def wrapper(session: MailSession):
        if _tls(session) is None or _version(session) == 0.0:
            return None
        return fn(session)
    return wrapper


@_needs_handshake
def _poodle(s):          # SSLv3 with a CBC suite
    # Compare the enum, not `tls_version_num`. TLS 1.0 is 1.00 on that scale,
    # so `<= 3.0` matched every session in the corpus and reported POODLE
    # feasible against TLS 1.2. Caught by reading the generated table.
    h = _tls(s)
    return (h.negotiated_version in (TlsVersion.SSL3, TlsVersion.SSL2)
            and bool(s.features and s.features.cipher_is_cbc))


@_needs_handshake
def _beast(s):           # TLS 1.0 CBC, predictable IV
    h = _tls(s)
    return (h.negotiated_version is TlsVersion.TLS1_0
            and bool(s.features and s.features.cipher_is_cbc))


@_needs_handshake
def _lucky13(s):         # MAC-then-encrypt CBC, any TLS below 1.3
    return bool(s.features and s.features.cipher_is_cbc) and _version(s) < 1.3


@_needs_handshake
def _sweet32(s):         # 64-bit block cipher: 3DES or Blowfish
    suite = _suite(s)
    return "3DES" in suite or "DES_CBC3" in suite or "IDEA" in suite


@_needs_handshake
def _freak(s):           # export-grade RSA
    f = s.features
    return bool(f and f.cipher_is_export) or "EXPORT" in _suite(s)


@_needs_handshake
def _logjam(s):          # DH group at or below 1024 bits
    f = s.features
    if not f:
        return None
    if "DHE" not in _suite(s) or "ECDHE" in _suite(s):
        return False
    return 0 < f.kex_group_bits <= 1024


@_needs_handshake
def _rc4(s):
    return "RC4" in _suite(s)


@_needs_handshake
def _crime(s):           # TLS-level compression
    return bool(s.features and s.features.compression_enabled)


@_needs_handshake
def _robot(s):           # static RSA key exchange -> Bleichenbacher oracle
    f = s.features
    if not f:
        return None
    return not f.kex_is_ephemeral and "TLS_RSA" in _suite(s)


@_needs_handshake
def _renegotiation(s):
    return not bool(s.features and s.features.renegotiation_info_present)


@_needs_handshake
def _retrospective(s):   # recorded now, read once the server key leaks
    return not bool(s.features and s.features.has_forward_secrecy)


@_needs_handshake
def _harvest(s):         # recorded now, read once a quantum computer exists
    return not bool(s.features and s.features.pq_hybrid_negotiated)


def _heartbleed(s):
    """CVE-2014-0160 needs the heartbeat extension *and* a vulnerable OpenSSL
    build on the **server**.

    Always `None`. The first version returned False when the ClientHello did
    not offer heartbeat, which reads as "ruled out" - but that only says this
    *client* did not ask for it, and says nothing about the server, whose
    OpenSSL build a passive observer never sees. Clearing a server of
    Heartbleed on that basis is exactly the false reassurance this project
    refuses to give anywhere else.
    """
    return None


def _starttls_stripping(s):
    f = s.features
    if f is None:
        return None
    if f.tls_mode_is_implicit:
        return False                                   # no cleartext phase to strip
    if f.starttls_stripped_suspected:
        return True
    if f.tls_mode_is_cleartext and f.starttls_advertised:
        return True
    return False


def _credential_theft(s):
    f = s.features
    if f is None:
        return None
    return bool(f.credentials_in_cleartext or f.auth_before_tls)


def _impersonation(s):
    """A client cannot tell this server from an impostor."""
    f = s.features
    if f is None:
        return None
    if not f.cert_present:
        return None                                    # TLS 1.3 hid it, or none seen
    return bool(f.cert_is_expired or f.cert_is_self_signed or not f.cert_hostname_match)


# --------------------------------------------------------------------------- #
# The registry
# --------------------------------------------------------------------------- #

REGISTRY: tuple[Attack, ...] = (
    Attack("starttls-stripping", "STARTTLS stripping", "RFC 3207 / IMC 2015", 2015,
           Severity.CRITICAL,
           "A cleartext phase exists and the STARTTLS capability can be removed "
           "or the upgrade skipped",
           _starttls_stripping,
           ("ATTACK-STARTTLS-STRIPPED", "STARTTLS-ADVERTISED-NOT-USED")),

    Attack("credential-theft", "Credential interception", "RFC 4954 §5", 0,
           Severity.CRITICAL,
           "Authentication occurs before, or without, an encrypted channel",
           _credential_theft, ("ATTACK-CLEARTEXT-CREDENTIALS",)),

    Attack("impersonation", "Server impersonation", "RFC 6125 / RFC 8314", 0,
           Severity.CRITICAL,
           "The presented certificate is expired, self-signed, or does not match "
           "the requested name, so a client cannot distinguish the real server",
           _impersonation,
           ("CERT-EXPIRED-SELF-SIGNED", "CERT-HOSTNAME-MISMATCH")),

    Attack("rc4-biases", "RC4 keystream biases", "CVE-2013-2566 / RFC 7465", 2013,
           Severity.HIGH,
           "RC4 is the negotiated cipher",
           _rc4, ("TLS-WEAK-CIPHER-RC4",)),

    Attack("sweet32", "Sweet32 birthday attack", "CVE-2016-2183", 2016,
           Severity.HIGH,
           "A 64-bit block cipher (3DES, Blowfish, IDEA) over a long-lived connection",
           _sweet32, ("TLS-WEAK-CIPHER",)),

    Attack("freak", "FREAK", "CVE-2015-0204", 2015,
           Severity.HIGH,
           "Export-grade RSA key exchange is offered or negotiated",
           _freak, ("TLS-EXPORT-CIPHER",)),

    Attack("logjam", "Logjam", "CVE-2015-4000", 2015,
           Severity.HIGH,
           "Finite-field Diffie-Hellman with a group of 1024 bits or fewer",
           _logjam, ("TLS-WEAK-KEY-EXCHANGE",)),

    Attack("robot", "ROBOT / Bleichenbacher oracle", "CVE-2017-13099", 2017,
           Severity.HIGH,
           "Static RSA key exchange, which exposes a padding oracle and has no "
           "forward secrecy",
           _robot, ("TLS-NO-FORWARD-SECRECY",)),

    Attack("poodle", "POODLE", "CVE-2014-3566", 2014,
           Severity.HIGH,
           "SSL 3.0 with a CBC cipher suite",
           _poodle, ("TLS-DEPRECATED-VERSION",)),

    Attack("beast", "BEAST", "CVE-2011-3389", 2011,
           Severity.MEDIUM,
           "TLS 1.0 with a CBC cipher suite and a predictable IV",
           _beast, ("TLS-CBC-CIPHER", "TLS-DEPRECATED-VERSION")),

    Attack("lucky13", "Lucky 13", "CVE-2013-0169", 2013,
           Severity.MEDIUM,
           "A MAC-then-encrypt CBC suite below TLS 1.3, timing-observable",
           _lucky13, ("TLS-CBC-CIPHER",)),

    Attack("crime", "CRIME", "CVE-2012-4929", 2012,
           Severity.MEDIUM,
           "TLS-level compression is enabled",
           _crime, ("CONFIG-COMPRESSION",)),

    Attack("renegotiation", "Renegotiation prefix injection", "CVE-2009-3555", 2009,
           Severity.MEDIUM,
           "The renegotiation_info extension is absent, so a renegotiation cannot "
           "be bound to the original handshake",
           _renegotiation, ("CONFIG-NO-RENEGOTIATION-INFO",)),

    Attack("retrospective", "Retrospective decryption", "RFC 9325 §4.1", 0,
           Severity.MEDIUM,
           "No forward secrecy: a recorded session becomes readable the day the "
           "server's private key is obtained",
           _retrospective, ("TLS-NO-FORWARD-SECRECY",)),

    Attack("harvest-now", "Harvest now, decrypt later", "NIST FIPS 203", 2024,
           Severity.LOW,
           "No hybrid post-quantum key exchange, so recorded traffic is readable "
           "once a cryptographically relevant quantum computer exists",
           _harvest, ("PQ-NOT-READY",)),

    Attack("heartbleed", "Heartbleed", "CVE-2014-0160", 2014,
           Severity.HIGH,
           "A vulnerable OpenSSL build with the heartbeat extension enabled",
           _heartbleed, ()),
)


# --------------------------------------------------------------------------- #
# Assessment
# --------------------------------------------------------------------------- #

def _endpoint(session: MailSession) -> str:
    return f"{session.server_host}:{session.server_port}"


def _rationale(attack: Attack, verdict: AttackVerdict, matching: list[str],
               evaluated: int, total: int) -> str:
    """Say what was observed, not just what was concluded."""
    if verdict is AttackVerdict.FEASIBLE:
        shown = ", ".join(matching[:3])
        more = f" and {len(matching) - 3} more" if len(matching) > 3 else ""
        return (f"{len(matching)} of {evaluated} evaluated sessions meet the "
                f"precondition: {shown}{more}.")

    if verdict is AttackVerdict.NOT_APPLICABLE:
        return (f"Checked {evaluated} of {total} sessions; none meet the "
                f"precondition. Ruled out for what this capture contained.")

    if attack.attack_id == "heartbleed":
        return ("The heartbeat extension and the server's OpenSSL build cannot both "
                "be established from a passive capture. Not assessed rather than "
                "cleared - absence of a heartbeat message is not absence of the bug.")

    return (f"No session could be judged: {total - evaluated} of {total} had no "
            f"parsed handshake, so the precondition is neither met nor ruled out.")


def assess(report: Report) -> list[AttackAssessment]:
    """Judge every attack in the registry against the report.

    Ordered feasible-first, then by severity, so the matrix reads as a threat
    model rather than an alphabetical list.
    """
    sessions = report.sessions
    total = len(sessions)
    results: list[AttackAssessment] = []

    for attack in REGISTRY:
        matching: list[str] = []
        evaluated = 0
        for session in sessions:
            outcome = attack.test(session)
            if outcome is None:
                continue
            evaluated += 1
            if outcome:
                matching.append(_endpoint(session))

        if matching:
            verdict = AttackVerdict.FEASIBLE
        elif evaluated:
            verdict = AttackVerdict.NOT_APPLICABLE
        else:
            verdict = AttackVerdict.NOT_OBSERVABLE

        results.append(AttackAssessment(
            attack_id=attack.attack_id,
            name=attack.name,
            reference=attack.reference,
            year=attack.year,
            verdict=verdict,
            severity=attack.severity,
            precondition=attack.precondition,
            rationale=_rationale(attack, verdict, sorted(set(matching)), evaluated, total),
            affected=sorted(set(matching)),
            sessions_evaluated=evaluated,
            sessions_matching=len(set(matching)),
            related_rules=list(attack.rules),
        ))

    order = {AttackVerdict.FEASIBLE: 0, AttackVerdict.NOT_OBSERVABLE: 1,
             AttackVerdict.NOT_APPLICABLE: 2}
    sev = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
           Severity.LOW: 3, Severity.INFO: 4}
    results.sort(key=lambda a: (order[a.verdict], sev.get(a.severity, 9), a.name))
    return results
