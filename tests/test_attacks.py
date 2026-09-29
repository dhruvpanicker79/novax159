"""Attack feasibility matrix. USP-09.

The claim is not "we list attacks". It is **"we judged each one against this
capture, and here is what we ruled out"** — which is only worth something if
the rulings are right. A matrix that says FEASIBLE about everything has not
demonstrated it checked anything; one that says NOT APPLICABLE about something
that *is* possible is worse than silence.

So the tests here are mostly about the two error directions:

* a verdict of NOT APPLICABLE must mean *checked and cannot happen*, never
  *could not be judged* — that is what NOT OBSERVABLE is for;
* a verdict of FEASIBLE must name endpoints that really do meet the
  precondition.

    python tests/test_attacks.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "testbed"))

from schema import AttackVerdict, Report, Severity, TlsVersion  # noqa: E402
from securemailscope.attacks import REGISTRY, assess  # noqa: E402
from securemailscope.pipeline import analyse  # noqa: E402

OUT = ROOT / "testbed" / "out"
TRUST = [str(ROOT / "testbed" / "certs" / "_ca.der")]
_CACHE: dict[str, Report] = {}


def _report(name: str = "fleet.pcap") -> Report:
    if name not in _CACHE:
        if not (OUT / name).exists():
            import synth
            synth.build_all(OUT)
        _CACHE[name] = analyse(OUT / name, trust_store_paths=TRUST)
    return _CACHE[name]


def _by_id(report: Report | None = None) -> dict:
    return {a.attack_id: a for a in (report or _report()).attack_matrix}


# --------------------------------------------------------------------------- #
# Registry hygiene
# --------------------------------------------------------------------------- #

def test_every_attack_is_uniquely_identified_and_cited():
    ids = [a.attack_id for a in REGISTRY]
    assert len(ids) == len(set(ids)), "duplicate attack_id"
    for attack in REGISTRY:
        assert attack.name and attack.precondition, attack.attack_id
        assert attack.reference, f"{attack.attack_id} has no CVE or standard reference"


def test_the_matrix_reaches_the_report_and_survives_json():
    report = _report()
    assert report.attack_matrix, "no matrix on the report"
    back = Report.from_json(report.to_json())
    assert len(back.attack_matrix) == len(REGISTRY)
    assert isinstance(back.attack_matrix[0].verdict, AttackVerdict)


def test_feasible_entries_sort_above_ruled_out_ones():
    verdicts = [a.verdict for a in _report().attack_matrix]
    order = {AttackVerdict.FEASIBLE: 0, AttackVerdict.NOT_OBSERVABLE: 1,
             AttackVerdict.NOT_APPLICABLE: 2}
    ranks = [order[v] for v in verdicts]
    assert ranks == sorted(ranks), "the matrix does not read worst-first"


# --------------------------------------------------------------------------- #
# The verdicts have to be right
# --------------------------------------------------------------------------- #

def test_the_corpus_produces_all_three_verdicts():
    """If the corpus cannot produce a NOT APPLICABLE, the deliverable is not
    demonstrated — ruling attacks out is half of USP-09."""
    verdicts = {a.verdict for a in _report().attack_matrix}
    assert verdicts == {AttackVerdict.FEASIBLE, AttackVerdict.NOT_APPLICABLE,
                        AttackVerdict.NOT_OBSERVABLE}, verdicts


def test_poodle_is_ruled_out_because_no_session_used_sslv3():
    """This was wrong once. The test compared `tls_version_num <= 3.0`, and TLS
    1.0 is 1.00 on that scale, so POODLE read FEASIBLE against TLS 1.2 — a
    false positive on the most recognisable CVE in the table."""
    report = _report()
    assert not any(s.handshake and s.handshake.negotiated_version
                   in (TlsVersion.SSL2, TlsVersion.SSL3) for s in report.sessions), \
        "corpus now contains SSLv3; this test needs rewriting"
    poodle = _by_id(report)["poodle"]
    assert poodle.verdict is AttackVerdict.NOT_APPLICABLE, poodle.rationale
    assert poodle.sessions_evaluated > 0, "ruled out without checking anything"


def test_beast_is_ruled_out_because_the_tls10_session_is_not_cbc():
    report = _report()
    beast = _by_id(report)["beast"]
    assert beast.verdict is AttackVerdict.NOT_APPLICABLE
    tls10 = [s for s in report.sessions
             if s.handshake and s.handshake.negotiated_version is TlsVersion.TLS1_0]
    assert tls10, "corpus no longer exercises TLS 1.0"
    assert not any(s.features.cipher_is_cbc for s in tls10 if s.features)


def test_heartbleed_is_never_ruled_out_from_a_passive_capture():
    """The one row whose whole purpose is honesty.

    An earlier version returned False when the ClientHello did not offer the
    heartbeat extension, which renders as "ruled out". That only says the
    *client* did not ask; the server's OpenSSL build is invisible to a passive
    observer. Clearing a server on that basis is false reassurance.
    """
    heartbleed = _by_id()["heartbleed"]
    assert heartbleed.verdict is AttackVerdict.NOT_OBSERVABLE
    assert heartbleed.sessions_evaluated == 0
    assert "not assessed" in heartbleed.rationale.lower() or \
           "cannot" in heartbleed.rationale.lower()


def test_rc4_is_feasible_and_names_the_right_host():
    report = _report()
    rc4 = _by_id(report)["rc4-biases"]
    assert rc4.verdict is AttackVerdict.FEASIBLE
    for endpoint in rc4.affected:
        host, port = endpoint.rsplit(":", 1)
        session = next(s for s in report.sessions
                       if s.server_host == host and s.server_port == int(port))
        assert "RC4" in (session.handshake.cipher_suite_name or "").upper()


def test_credential_theft_matches_the_cleartext_sessions():
    report = _report()
    entry = _by_id(report)["credential-theft"]
    assert entry.verdict is AttackVerdict.FEASIBLE
    expected = {f"{s.server_host}:{s.server_port}" for s in report.sessions
                if s.features and (s.features.credentials_in_cleartext
                                   or s.features.auth_before_tls)}
    assert set(entry.affected) == expected


def test_every_feasible_entry_names_at_least_one_endpoint():
    for entry in _report().attack_matrix:
        if entry.verdict is AttackVerdict.FEASIBLE:
            assert entry.affected, f"{entry.attack_id} is feasible against nothing"
            assert entry.sessions_matching == len(entry.affected)


def test_not_applicable_always_means_something_was_actually_checked():
    """The distinction the whole design turns on. NOT APPLICABLE without an
    evaluated session is a guess wearing a verdict's clothes."""
    for entry in _report().attack_matrix:
        if entry.verdict is AttackVerdict.NOT_APPLICABLE:
            assert entry.sessions_evaluated > 0, entry.attack_id
            assert not entry.affected, entry.attack_id


def test_not_observable_never_claims_to_have_checked():
    for entry in _report().attack_matrix:
        if entry.verdict is AttackVerdict.NOT_OBSERVABLE:
            assert entry.sessions_matching == 0
            assert not entry.affected


def test_every_rationale_says_what_was_observed():
    for entry in _report().attack_matrix:
        assert entry.rationale, entry.attack_id
        assert any(ch.isdigit() for ch in entry.rationale) or \
            entry.verdict is AttackVerdict.NOT_OBSERVABLE, (
                f"{entry.attack_id} states a verdict without quoting an observation")


# --------------------------------------------------------------------------- #
# Degenerate inputs
# --------------------------------------------------------------------------- #

def test_a_capture_with_no_handshakes_judges_nothing_rather_than_clearing_it():
    """An unparsed estate must not come back as "no attacks apply"."""
    report = _report("smtp_relay_cleartext.pcap")
    matrix = {a.attack_id: a for a in report.attack_matrix}
    for attack_id in ("poodle", "beast", "rc4-biases", "sweet32", "logjam", "freak"):
        entry = matrix[attack_id]
        assert entry.verdict is AttackVerdict.NOT_OBSERVABLE, (
            f"{attack_id} was ruled out on a capture with no TLS handshake: "
            f"{entry.rationale}")


def test_an_empty_report_produces_a_full_matrix_of_unjudged_attacks():
    matrix = assess(Report())
    assert len(matrix) == len(REGISTRY)
    assert all(a.verdict is AttackVerdict.NOT_OBSERVABLE for a in matrix)
    assert all(not a.affected for a in matrix)


def test_severities_are_real_enum_members():
    for entry in _report().attack_matrix:
        assert isinstance(entry.severity, Severity)


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
