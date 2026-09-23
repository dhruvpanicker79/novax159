"""S6 - role-aware severity adjustment. This IS USP-01.

A rule emits a `base_severity` describing how bad the cryptographic fact is in
the abstract. This module then decides how bad it is *here*, given what the
port is actually for, and records the reasoning in plain English so an analyst
can see why an expired certificate on port 25 was filed as informational.

We keep both values. Hiding the adjustment would make the tool less
trustworthy, not more: the point is that the judgement is explainable.

    expired self-signed cert on port 25   HIGH -> INFO
    expired self-signed cert on port 993  HIGH -> CRITICAL

Design rule: adjustments are driven by a declarative table, not by `if`
statements scattered through the rule pack, so the policy can be reviewed as a
single artifact and cited in the PPT.
"""

from __future__ import annotations

from dataclasses import dataclass

from schema import Finding, FindingCategory, PortRole, Severity

_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _shift(severity: Severity, steps: int) -> Severity:
    """Move a severity up or down the scale, clamped at both ends."""
    idx = _ORDER.index(severity)
    return _ORDER[max(0, min(len(_ORDER) - 1, idx + steps))]


@dataclass(frozen=True)
class Adjustment:
    """One row of the severity policy.

    `steps` shifts along the scale; `cap` and `floor` clamp the result. A cap is
    preferred over a large shift where the rule is categorical rather than
    proportional -- "certificate trust failures on an opportunistic relay are
    informational, full stop" is a clearer policy than "subtract three", and it
    is what RFC 7435 actually implies.
    """

    reason: str
    steps: int = 0
    cap: Severity | None = None
    floor: Severity | None = None


#: The policy. Keyed by (category, role).
#:
#: Rationale for the two that look surprising:
#:
#: CERTIFICATE (trust) on MTA_RELAY is capped at INFO because RFC 7435 defines
#: server-to-server SMTP as opportunistic security. The sender has no way to
#: know which certificate the receiver *should* present unless DANE or MTA-STS
#: is published, so a validation failure is the normal case, not an incident.
#: Paging a human for it is how a tool teaches its users to ignore it.
#:
#: CERTIFICATE on SUBMISSION / MAIL_ACCESS is pushed up one step because a
#: password is about to cross the session. RFC 8314 requires a validated
#: certificate precisely so that interception is distinguishable from normal
#: operation; without one, it is not.
POLICY: dict[tuple[FindingCategory, PortRole], Adjustment] = {
    (FindingCategory.CERTIFICATE, PortRole.MTA_RELAY): Adjustment(
        reason=(
            "port 25 is MTA-to-MTA relay, where TLS is opportunistic (RFC 7435) and "
            "the sender has no trust anchor for the receiver. Encrypting with an "
            "unvalidated certificate still beats cleartext."
        ),
        cap=Severity.INFO,
    ),
    (FindingCategory.CERTIFICATE, PortRole.SUBMISSION): Adjustment(
        reason=(
            "user credentials traverse this session, so RFC 8314 requires a validated "
            "certificate. Without one, interception is indistinguishable from normal "
            "operation."
        ),
        steps=+1,
    ),
    (FindingCategory.CERTIFICATE, PortRole.MAIL_ACCESS): Adjustment(
        reason=(
            "user credentials traverse this session, so RFC 8314 requires a validated "
            "certificate. Without one, interception is indistinguishable from normal "
            "operation."
        ),
        steps=+1,
    ),
    (FindingCategory.CONFIGURATION, PortRole.MTA_RELAY): Adjustment(
        reason=(
            "opportunistic relay: a remote peer's configuration is outside this "
            "organisation's control. Publish MTA-STS or DANE to require TLS from senders."
        ),
        steps=-1,
    ),
    (FindingCategory.STARTTLS, PortRole.SUBMISSION): Adjustment(
        reason="submission port: a failed or skipped upgrade exposes credentials.",
        steps=+1,
    ),
    (FindingCategory.STARTTLS, PortRole.MAIL_ACCESS): Adjustment(
        reason="mail access port: a failed or skipped upgrade exposes credentials.",
        steps=+1,
    ),
    (FindingCategory.ATTACK_EVIDENCE, PortRole.MAIL_ACCESS): Adjustment(
        reason="evidence of interception on a port that carries credentials.",
        steps=+1,
    ),
    (FindingCategory.ATTACK_EVIDENCE, PortRole.SUBMISSION): Adjustment(
        reason="evidence of interception on a port that carries credentials.",
        steps=+1,
    ),
}

#: Categories describing the cryptography itself rather than the trust
#: relationship. A broken cipher is broken everywhere, so these are never
#: adjusted by role: RC4 on port 25 is still RC4, and a 1024-bit certificate
#: key is weak wherever it is presented.
#:
#: CERTIFICATE_STRENGTH belongs here and CERTIFICATE does not. Keeping them
#: apart is what stops the opportunistic-relay exemption from quietly excusing
#: broken cryptography, which would be a real flaw in the USP-01 argument.
NEVER_ADJUSTED = {
    FindingCategory.PROTOCOL,
    FindingCategory.CIPHER,
    FindingCategory.KEY_EXCHANGE,
    FindingCategory.CERTIFICATE_STRENGTH,
    FindingCategory.POST_QUANTUM,
    FindingCategory.COMPLIANCE,
}


def adjust(finding: Finding) -> Finding:
    """Apply the role policy to one finding, in place, and return it.

    Sets `severity` and `severity_adjustment_reason`; leaves `base_severity`
    untouched so the UI can show both.
    """
    if finding.category in NEVER_ADJUSTED:
        finding.severity = finding.base_severity
        return finding

    rule = POLICY.get((finding.category, finding.port_role))
    if rule is None:
        finding.severity = finding.base_severity
        return finding

    adjusted = _shift(finding.base_severity, rule.steps)
    if rule.cap is not None and adjusted.rank > rule.cap.rank:
        adjusted = rule.cap
    if rule.floor is not None and adjusted.rank < rule.floor.rank:
        adjusted = rule.floor
    finding.severity = adjusted

    if adjusted is finding.base_severity:
        finding.severity_adjustment_reason = None
    else:
        direction = "Downgraded" if adjusted.rank < finding.base_severity.rank else "Raised"
        finding.severity_adjustment_reason = (
            f"{direction} from {finding.base_severity.value.upper()} to "
            f"{adjusted.value.upper()}: {rule.reason}"
        )
    return finding


def adjust_all(findings: list[Finding]) -> list[Finding]:
    """Apply the policy across a list of findings."""
    return [adjust(f) for f in findings]


def policy_table() -> list[dict[str, str]]:
    """The policy as rows, for the PPT slide and the compliance appendix."""
    rows: list[dict[str, str]] = []
    for (category, role), rule in POLICY.items():
        if rule.cap is not None:
            effect = f"cap at {rule.cap.value.upper()}"
        elif rule.floor is not None:
            effect = f"floor at {rule.floor.value.upper()}"
        else:
            effect = f"{rule.steps:+d} step"
        rows.append({
            "category": category.value,
            "port_role": role.value,
            "adjustment": effect,
            "rationale": rule.reason,
        })
    return sorted(rows, key=lambda r: (r["category"], r["port_role"]))
