"""Grounded narrative generation. S8 layer 3, objective O02, USP-04.

The layer's value depends entirely on two properties, so both are tested
harder than the prose itself:

* it **cannot invent** — generated text is checked against a closed vocabulary
  drawn from the report, and anything unverifiable is discarded whole;
* it **cannot analyse** — it is handed a finished report and may not add,
  remove or re-score a finding.

The deterministic template path is tested as the product it is, not as a
fallback, because it is what ships.

    python tests/test_llm.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "testbed"))

from schema import Report, Severity  # noqa: E402
from securemailscope.llm import grounding, narrate, render_prompt, templates, verify  # noqa: E402
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


# --------------------------------------------------------------------------- #
# Grounding
# --------------------------------------------------------------------------- #

def test_fact_sheet_never_carries_payload_bytes():
    """The model must not be able to see credentials, banners or payloads. If
    it cannot see them it cannot leak them, which is cheaper than redaction."""
    report = _report()
    blob = str(grounding.build(report).to_prompt_dict()).lower()
    for secret in ("monsoonrain", "password:", "auth plain", "dXNlcg",
                   "220 mail", "+ok", "* ok"):
        assert secret.lower() not in blob, f"fact sheet leaked {secret!r}"


def test_fact_sheet_hash_is_stable_and_sensitive():
    report = _report()
    a = grounding.build(report)
    b = grounding.build(report)
    assert a.sha256() == b.sha256(), "same report produced different hashes"

    mutated = grounding.build(report)
    mutated.issues[0]["severity"] = "info"
    assert mutated.sha256() != a.sha256(), "hash ignored a change to the facts"


def test_findings_are_grouped_by_rule_not_repeated():
    report = _report()
    sheet = grounding.build(report)
    rule_ids = [i["rule_id"] for i in sheet.issues]
    assert len(rule_ids) == len(set(rule_ids)), "a rule appears twice in the sheet"
    assert sum(i["occurrences"] for i in sheet.issues) == len(report.prioritised_findings)


def test_issues_are_ordered_worst_first():
    sheet = grounding.build(_report())
    rank = {s.value: i for i, s in enumerate(
        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])}
    ranks = [rank[i["severity"]] for i in sheet.issues]
    assert ranks == sorted(ranks), "issues are not severity-ordered"


# --------------------------------------------------------------------------- #
# The deterministic path — the product, not a fallback
# --------------------------------------------------------------------------- #

def test_template_narrative_is_deterministic():
    sheet = grounding.build(_report())
    a, b = templates.render(sheet), templates.render(sheet)
    assert a.executive_summary == b.executive_summary
    assert [x.title for x in a.action_plan] == [x.title for x in b.action_plan]


def test_plan_is_shorter_than_the_finding_list():
    """One action per distinct fix. Thirteen sessions with one weak cipher is
    one action; a plan that repeats itself is a plan nobody finishes."""
    report = _report()
    plan = narrate(report).action_plan
    assert plan, "no actions produced"
    assert len(plan) < len(report.prioritised_findings), (
        f"{len(plan)} actions for {len(report.prioritised_findings)} findings - "
        f"nothing was deduplicated")


def test_summary_agrees_with_the_plan_it_introduces():
    """The summary counts *actions*, not the rules that went into them. It said
    "20 actions below" above a list of 17 until this test existed."""
    import re
    narrative = narrate(_report())
    match = re.search(r"of the (\d+) actions below", narrative.executive_summary)
    if match:
        assert int(match.group(1)) == len(narrative.action_plan), (
            f"summary claims {match.group(1)} actions, plan has "
            f"{len(narrative.action_plan)}")


def test_every_action_traces_to_rules_that_actually_fired():
    """The layer may not invent work. Every action must close real findings."""
    report = _report()
    fired = {f.rule_id for f in report.prioritised_findings}
    for action in narrate(report).action_plan:
        assert action.rule_ids, f"action {action.order} closes nothing"
        for rule_id in action.rule_ids:
            assert rule_id in fired, f"action cites {rule_id}, which did not fire"


def test_plan_is_ordered_by_severity():
    plan = narrate(_report()).action_plan
    rank = {s.value: i for i, s in enumerate(
        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])}
    ranks = [rank[a.severity.value] for a in plan]
    assert ranks == sorted(ranks), "the plan is not worst-first"
    assert [a.order for a in plan] == list(range(1, len(plan) + 1))


def test_role_aware_reasoning_reaches_the_narrative():
    """USP-01 is the pitch. If the severity adjustment does not survive into the
    prose, the report cannot explain its own ranking."""
    report = _report()
    adjusted = [f for f in report.prioritised_findings if f.severity_adjustment_reason]
    assert adjusted, "corpus no longer exercises role-aware severity"
    prose = " ".join(a.rationale for a in narrate(report).action_plan)
    assert "Raised from" in prose or "Downgraded from" in prose, (
        "no severity adjustment reached the action plan")


def test_closing_note_always_states_the_passive_scope():
    for name in ("fleet.pcap", "smtp_starttls_healthy.pcap"):
        note = narrate(_report(name)).closing_note.lower()
        assert "passive" in note
        assert "decrypted" in note


def test_narrative_survives_the_json_round_trip():
    """The console reads JSON, so a narrative that does not serialise is not a
    feature."""
    report = _report()
    back = Report.from_json(report.to_json())
    assert back.narrative is not None
    assert back.narrative.executive_summary == report.narrative.executive_summary
    assert len(back.narrative.action_plan) == len(report.narrative.action_plan)
    assert back.narrative.grounding_sha256 == report.narrative.grounding_sha256


# --------------------------------------------------------------------------- #
# The guardrail
# --------------------------------------------------------------------------- #

def test_our_own_output_passes_verification():
    """A verifier that rejects correct text is a verifier nobody will keep on."""
    sheet = grounding.build(_report())
    ok, reason = verify.verdict(templates.render(sheet).executive_summary, sheet)
    assert ok, f"template output failed its own verifier: {reason}"


def test_verifier_rejects_every_kind_of_fabrication():
    sheet = grounding.build(_report())
    fabrications = {
        "invented IPv4 host": "Weaknesses were found on 192.168.44.9.",
        "invented hostname": "mail.corp.internal presented an expired certificate.",
        "invented rule id": "TLS-HEARTBLEED-EXPOSURE fired on two hosts.",
        "invented CVE": "The servers are vulnerable to CVE-2024-31497.",
        "invented RFC": "This breaches RFC 9999 on post-quantum certificates.",
        "plausible mixture": (
            "13 sessions were analysed. The relay at 10.20.1.11 failed RFC 8314 "
            "and mail.corp.internal presented an expired certificate."),
    }
    for label, text in fabrications.items():
        ok, reason = verify.verdict(text, sheet)
        assert not ok, f"verifier accepted a fabrication: {label}"
        assert reason.startswith("rejected:"), reason


def test_verifier_allows_a_faithful_paraphrase():
    sheet = grounding.build(_report())
    text = ("Two sessions authenticated over an unencrypted channel on 10.20.1.15. "
            "The estate grades D. RFC 8314 is breached.")
    ok, reason = verify.verdict(text, sheet)
    assert ok, f"faithful paraphrase rejected: {reason}"


def test_a_failing_backend_falls_back_rather_than_raising():
    """A demo cannot die on an API timeout."""
    report = _report()
    narrative = narrate(report, backend="definitely-not-a-real-backend")
    assert narrative.executive_summary, "no narrative produced at all"
    assert narrative.generated_by == "template"
    assert "template used" in narrative.verification


def test_prompt_states_the_rules_and_carries_no_payload():
    sheet = grounding.build(_report())
    prompt = render_prompt(sheet).lower()
    assert "use only the facts" in prompt
    assert "passive" in prompt
    for secret in ("monsoonrain", "auth plain", "220 mail"):
        assert secret not in prompt


# --------------------------------------------------------------------------- #
# The boundary that keeps the AI story defensible
# --------------------------------------------------------------------------- #

def test_the_layer_cannot_change_the_analysis():
    """It writes *about* the findings. It does not participate in producing
    them — that is what keeps every number traceable to a cited rule."""
    report = _report()
    before = [(f.rule_id, f.severity.value, f.affected_host)
              for f in report.prioritised_findings]
    grade, score = report.fleet.grade, report.fleet.score

    narrate(report)
    narrate(report, backend="definitely-not-a-real-backend")

    after = [(f.rule_id, f.severity.value, f.affected_host)
             for f in report.prioritised_findings]
    assert after == before, "the narrative layer mutated the findings"
    assert (report.fleet.grade, report.fleet.score) == (grade, score)


def test_an_unreadable_capture_gets_an_honest_narrative():
    """The one case where the summary must refuse to reassure."""
    import dpkt
    bad = OUT / "_llm_unreadable.pcap"
    with (OUT / "fleet.pcap").open("rb") as fh, bad.open("wb") as out:
        writer = dpkt.pcap.Writer(out, linktype=105)      # 802.11, unsupported
        for ts, buf in dpkt.pcap.Reader(fh):
            writer.writepkt(bytes(buf), ts=ts)
    try:
        narrative = analyse(bad, trust_store_paths=TRUST).narrative
        summary = narrative.executive_summary.lower()
        assert "could not be read" in summary
        assert "not a statement about" in summary or "only about the file" in summary
        for reassuring in ("no weaknesses were found", "secure", "clean"):
            assert reassuring not in summary, f"reassuring word {reassuring!r}"
    finally:
        bad.unlink(missing_ok=True)


def test_a_clean_capture_does_not_claim_more_than_it_saw():
    sheet = grounding.build(_report("smtp_starttls_healthy.pcap"))
    summary = templates.render(sheet).executive_summary.lower()
    if sheet.finding_count == 0:
        assert "not the same as a clean estate" in summary or "was not assessed" in summary


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
