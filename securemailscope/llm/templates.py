"""The deterministic narrative. Objective O02, USP-04 layer 3.

**This is the path that ships.** The LLM backend is an optional improvement on
top; it is not a dependency, and a demo with no network produces exactly this
output. Writing it second — as a fallback — is how projects end up with a
fallback nobody would want to read, so it was written first and the model is
judged against it.

Everything here is a pure function of the fact sheet. Same report in, same
words out, which also makes it testable in a way generated prose is not.
"""

from __future__ import annotations

from schema import ActionItem, Narrative, Severity

from .grounding import FactSheet

#: Plain-English stakes per category, for the "why this matters" clause. Keyed
#: on the rule-id prefix because that is stable across rule-pack edits.
_STAKES = {
    "ATTACK-CLEARTEXT-CREDENTIALS":
        "anyone with a port mirror between these hosts has the password",
    "ATTACK-STARTTLS-STRIPPED":
        "the encryption offer was removed in transit, so the client never knew "
        "it could have protected the session",
    "ATTACK-DOWNGRADE-SENTINEL":
        "the server itself signalled that it saw a downgrade attempt",
    "ATTACK-CERT-SUBSTITUTION":
        "two different certificates were presented for the same endpoint, which "
        "is what interception looks like from the wire",
    "ATTACK-CIPHER-INTERSECTION-ANOMALY":
        "the suite chosen was weaker than both sides supported",
    "CERT-EXPIRED-SELF-SIGNED":
        "clients cannot distinguish this server from an impostor",
    "CERT-HOSTNAME-MISMATCH":
        "the name on the certificate is not the name that was asked for",
    "STARTTLS-ADVERTISED-NOT-USED":
        "the protection was available and went unused",
    "SMTP-RELAY-NO-TLS":
        "mail crossed the network in the clear, though on a relay port the "
        "remote end's configuration is not yours to fix",
}

_EFFORT_WORDS = {
    "trivial": "a one-line change",
    "low": "a small change",
    "medium": "a planned change",
    "high": "a project",
    "unknown": "an unscoped change",
}


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def _executive_summary(sheet: FactSheet, plan: list[ActionItem]) -> str:
    """Five sentences at most. This is the paragraph a decision-maker reads,
    and the only one most of them will."""
    if sheet.unreadable:
        return (
            f"**{sheet.capture_name} could not be read.** Its link layer is not one "
            f"this tool decodes, so no mail sessions were reconstructed and no "
            f"posture was assessed. Nothing in this report is a statement about the "
            f"security of these hosts — only about the file. Re-capture in Ethernet, "
            f"Linux cooked or raw IP format and run it again.")

    if not sheet.finding_count:
        return (
            f"{_plural(sheet.session_count, 'mail session')} across "
            f"{_plural(sheet.host_count, 'host')} were reconstructed from "
            f"{sheet.capture_name} and no cryptographic weaknesses were found. "
            f"Grade **{sheet.grade}** ({sheet.score:.0f}/100). This reflects what was "
            f"observable in this capture, which is not the same as a clean estate: "
            f"anything the capture did not contain was not assessed.")

    counts = sheet.severity_counts
    critical, high = counts.get("critical", 0), counts.get("high", 0)

    # Lead with the worst true thing. Order matters more than completeness here.
    if sheet.cleartext_credential_sessions:
        lead = (
            f"**{_plural(sheet.cleartext_credential_sessions, 'session')} "
            f"authenticated over an unencrypted channel.** Treat every credential "
            f"in this capture as compromised and rotate them before doing anything "
            f"else on this list.")
    elif critical:
        top = next((i for i in sheet.issues if i["severity"] == "critical"), None)
        lead = (f"**{_plural(critical, 'critical finding')}**, the most urgent being "
                f"{top['title'].lower()} on "
                f"{_plural(len(top['endpoints']), 'endpoint')}.")
    elif high:
        lead = (f"No critical findings. **{_plural(high, 'high-severity finding')}** "
                f"require attention.")
    else:
        lead = "No critical or high-severity findings."

    scope = (
        f"{_plural(sheet.session_count, 'mail session')} across "
        f"{_plural(sheet.host_count, 'host')} were reconstructed from "
        f"{sheet.capture_name}, producing {_plural(sheet.finding_count, 'finding')}. "
        f"The estate grades **{sheet.grade}** ({sheet.score:.0f}/100).")

    transport = ""
    if sheet.cleartext_sessions:
        transport = (f" {_plural(sheet.cleartext_sessions, 'session')} carried no "
                     f"encryption at all.")
    elif sheet.encrypted_sessions and sheet.forward_secrecy_ratio < 1.0:
        pct = round(sheet.forward_secrecy_ratio * 100)
        transport = (f" {pct}% of encrypted sessions negotiated forward secrecy, so "
                     f"the rest are readable retrospectively by anyone who recorded "
                     f"them and later obtains the server key.")

    standards = ""
    if sheet.failed_standards:
        shown = ", ".join(sheet.failed_standards[:3])
        more = (f" and {len(sheet.failed_standards) - 3} more"
                if len(sheet.failed_standards) > 3 else "")
        standards = (f" {_plural(len(sheet.failed_standards), 'standard')} "
                     f"{'is' if len(sheet.failed_standards) == 1 else 'are'} "
                     f"breached: {shown}{more}.")

    effort_note = ""
    quick = [a for a in plan if a.effort in ("trivial", "low")]
    if quick:
        effort_note = (f" {len(quick)} of the {len(plan)} actions below "
                       f"{'is' if len(quick) == 1 else 'are'} a small configuration "
                       f"change.")

    return f"{scope} {lead}{transport}{standards}{effort_note}"


def _rationale(issue: dict, group: list[dict] | None = None,
               endpoints: list[str] | None = None) -> str:
    """Why this action, and why at this position in the list."""
    group = group or [issue]
    endpoints = endpoints if endpoints is not None else issue["endpoints"]
    occurrences = sum(i["occurrences"] for i in group)

    where = (f"{_plural(occurrences, 'session')} on "
             f"{_plural(len(endpoints), 'endpoint')}"
             if endpoints else _plural(occurrences, "session"))

    parts = [f"Affects {where}."]
    if len(group) > 1:
        parts.append(f"Closes {_plural(len(group), 'finding')}: "
                     f"{', '.join(sorted(i['rule_id'] for i in group))}.")
    stakes = [_STAKES[i["rule_id"]] for i in group if i["rule_id"] in _STAKES]
    if stakes:
        parts.append(f"Left alone, {stakes[0]}.")
    if issue["severity_adjusted"]:
        # USP-01 in the narrative: say why this is ranked where it is.
        parts.append(issue["severity_adjusted"])
    if issue["standards_violated"]:
        parts.append(f"Breaches {', '.join(issue['standards_violated'][:2])}.")
    parts.append(f"The fix is {_EFFORT_WORDS.get(issue['effort'], 'a change')}; "
                 f"risk of the change itself: {issue['risk_of_change'].rstrip('.')}.")
    return " ".join(parts)


def _merge_key(issue: dict) -> tuple[str, str]:
    """Two issues are the same *action* when the fix is the same edit.

    `STARTTLS-ADVERTISED-NOT-USED` and `ATTACK-STARTTLS-STRIPPED` are different
    findings with different evidence, and both are closed by setting
    `smtpd_tls_security_level = encrypt`. Listing that twice pads the plan and
    makes it read like a tool that cannot count.
    """
    return (issue["remediation"].strip(), issue["config"].strip())


def _action_plan(sheet: FactSheet) -> list[ActionItem]:
    """The plan: one action per distinct *fix*, ordered by the fact sheet.

    Thirteen sessions with the same weak cipher is one action, not thirteen,
    and two rules closed by one config line is one action, not two. A plan that
    repeats itself is a plan nobody finishes.
    """
    merged: dict[tuple[str, str], list[dict]] = {}
    for issue in sheet.issues:                      # already severity-ordered
        merged.setdefault(_merge_key(issue), []).append(issue)

    plan: list[ActionItem] = []
    for n, group in enumerate(merged.values(), start=1):
        lead = group[0]                             # worst, by the sheet's order
        endpoints = sorted({e for i in group for e in i["endpoints"]})
        standards = sorted({s for i in group for s in i["standards_violated"]})
        rationale = _rationale(lead, group, endpoints)
        plan.append(ActionItem(
            order=n,
            title=lead["remediation"].split(".")[0].strip() or lead["title"],
            rationale=rationale,
            severity=Severity(lead["severity"]),
            affected=endpoints,
            rule_ids=sorted(i["rule_id"] for i in group),
            effort=lead["effort"],
            risk_of_change=lead["risk_of_change"],
            platform=lead["platform"],
            config=lead["config"],
            standards=standards,
        ))
    return plan


def _closing_note(sheet: FactSheet) -> str:
    """The honest caveat. Every report carries it; it is not boilerplate."""
    base = (
        "This assessment is passive: nothing was decrypted, injected or modified, "
        "and every finding above can be checked against the capture in Wireshark "
        "using the frame numbers each one carries.")
    if sheet.unreadable:
        return base
    unseen = (
        " Conclusions are bounded by what the capture contained — a weakness on a "
        "host that did not appear in this file was not assessed, and absence of a "
        "finding is not evidence of absence.")
    pq = ""
    if sheet.pq_ready_hosts == 0 and sheet.encrypted_sessions:
        pq = (" No host offered a hybrid post-quantum key exchange; traffic recorded "
              "today remains decryptable later by anyone who keeps it.")
    return base + unseen + pq


def render(sheet: FactSheet) -> Narrative:
    """Build the narrative deterministically. No network, no model, no failure
    mode beyond a bug in this file."""
    plan = _action_plan(sheet)
    return Narrative(
        executive_summary=_executive_summary(sheet, plan),
        action_plan=plan,
        closing_note=_closing_note(sheet),
        generated_by="template",
        verification="not attempted",
        grounding_sha256=sheet.sha256(),
    )
