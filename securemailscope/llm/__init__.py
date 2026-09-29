"""S8 — grounded remediation generation. Objective O02, USP-04 layer 3.

Turns structured findings into an executive narrative and a prioritised action
plan with working config snippets for Postfix, Dovecot and Exchange.

Three hard rules, in the order they matter:

1. **GROUNDED.** The generator sees only `grounding.FactSheet` — counts, rule
   identifiers, severities and the remediation text the rule pack already
   wrote. Never capture bytes, credentials, banners or payloads. What is not in
   the fact sheet cannot be written about.

2. **VERIFIED.** Generated prose is untrusted input. Before it is used it is
   checked mechanically against the fact sheet's closed vocabulary — hosts,
   rule identifiers, standards, counts. Anything unverifiable and the whole
   narrative is **discarded**, not flagged. See `verify.py` and ADR-0028.

3. **FALLBACK.** `templates.py` produces the full narrative with no network,
   no model and no API key, and it is what ships. The model is an optional
   improvement judged against it, never a dependency. A demo cannot die on an
   API timeout because the default path never makes a call.

The layer may **never** introduce, remove or re-score a finding. It writes
about the rule engine's output; it does not participate in the analysis. That
boundary is what keeps the AI story defensible: every number in the narrative
traces to a deterministic rule with an RFC citation behind it.

    from securemailscope.llm import narrate
    report.narrative = narrate(report)
"""

from __future__ import annotations

import os

from schema import Narrative, Report

from . import grounding, templates, verify
from .grounding import FactSheet, build

__all__ = ["FactSheet", "build", "narrate", "render_prompt"]


def narrate(report: Report, *, backend: str | None = None) -> Narrative:
    """Produce the narrative for a finished report.

    `backend` defaults to the `SMS_LLM_BACKEND` environment variable, and to
    the deterministic template when that is unset — which is the shipping
    configuration. Any failure in a model backend, of any kind, falls back to
    the template rather than propagating: a report that renders is worth more
    than a report that explains why it did not.
    """
    sheet = grounding.build(report)
    baseline = templates.render(sheet)

    choice = backend if backend is not None else os.environ.get("SMS_LLM_BACKEND", "")
    if not choice or choice == "template":
        return baseline

    try:
        from .backend import generate            # imported lazily: optional path
        text, model = generate(sheet, choice)
    except Exception as exc:                     # noqa: BLE001 - never fatal
        baseline.verification = f"backend unavailable ({type(exc).__name__}); template used"
        return baseline

    ok, reason = verify.verdict(text, sheet)
    if not ok:
        # Discarded, not repaired. A partially hallucinated security report is
        # not a degraded report, it is an untrustworthy one.
        baseline.verification = f"{reason}; template used"
        return baseline

    # The model may rewrite the prose. It may not touch the plan, which is
    # built from the rule engine's own remediation text.
    baseline.executive_summary = text.strip()
    baseline.generated_by = f"llm:{model}"
    baseline.verification = reason
    return baseline


def render_prompt(sheet: FactSheet) -> str:
    """The exact prompt a backend is given. Public so it can be inspected in a
    test and shown to a judge who asks what the model actually sees."""
    import json

    facts = json.dumps(sheet.to_prompt_dict(), indent=2, sort_keys=True)
    return (
        "You are writing the executive summary of a passive cryptographic "
        "assessment of email infrastructure.\n\n"
        "RULES:\n"
        "- Use ONLY the facts below. Do not introduce hosts, rule identifiers, "
        "standards, CVEs or numbers that do not appear in them.\n"
        "- Do not recommend anything not present in the remediation fields.\n"
        "- Never claim traffic was decrypted. This assessment is passive.\n"
        "- Four to six sentences. Lead with the most serious true statement.\n"
        "- Plain English for a decision-maker, not a security specialist.\n\n"
        f"FACTS:\n{facts}\n"
    )
