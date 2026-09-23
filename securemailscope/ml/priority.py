"""S8 layer 3 - the triage queue. Deliverable D18.

D18 is a different ask from D16, and conflating them is the easy mistake. A
risk score says how bad one session is. A *priority* says what the analyst
should fix first, across the whole capture, which needs three more things:

    exploitability  is an attack practical, or theoretical? Evidence that it
                    already happened outranks everything.
    blast radius    does a compromise here cost one message or one account?
    breadth         a weak cipher on twelve hosts is a bigger job than the same
                    cipher on one, and worth batching.

Severity still leads -- an analyst scanning the queue expects CRITICAL at the
top -- but within a severity band the ordering is earned, not alphabetical.

Pure stdlib.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from schema import Finding, MailSession, Severity


@dataclass(frozen=True)
class PriorityScore:
    """Why a finding sits where it does. Shown in the UI on hover."""

    rank: int
    score: float
    severity: Severity
    exploitability: float
    blast_radius: float
    affected_hosts: int
    rationale: str


def _session_signals(sessions: list[MailSession]) -> dict[str, tuple[float, float]]:
    """(exploitability, blast_radius) keyed by 'host:port'."""
    out: dict[str, tuple[float, float]] = {}
    for s in sessions:
        if s.assessment is None:
            continue
        out[f"{s.server_host}:{s.server_port}"] = (
            s.assessment.exploitability, s.assessment.blast_radius)
    return out


def prioritise(findings: list[Finding],
               sessions: list[MailSession]) -> tuple[list[Finding], dict[str, PriorityScore]]:
    """Rank findings for remediation. Returns the ordered list and the workings.

    The workings matter: an analyst who cannot see why item 3 outranks item 4
    will not trust the ordering, and an unexplained queue gets ignored.
    """
    signals = _session_signals(sessions)

    # Breadth: how many distinct hosts does each rule affect? A single fix
    # applied fleet-wide is better value than a one-off.
    hosts_by_rule: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        if f.affected_host:
            hosts_by_rule[f.rule_id].add(f.affected_host)

    scored: list[tuple[float, Finding, PriorityScore]] = []
    for f in findings:
        exploitability, blast = signals.get(f"{f.affected_host}:{f.affected_port}", (0.3, 0.5))
        breadth = len(hosts_by_rule.get(f.rule_id, ()))
        breadth_factor = min(breadth / 5.0, 1.0)

        # Severity dominates the sort; the rest breaks ties within a band and
        # is scaled to stay below one severity step.
        within_band = (
            0.45 * exploitability
            + 0.35 * blast
            + 0.20 * breadth_factor
        )
        score = f.severity.rank + min(within_band, 0.99)

        bits = []
        if exploitability >= 0.95:
            bits.append("exploitation already evidenced")
        elif exploitability >= 0.5:
            bits.append("practical attack available")
        if blast >= 0.95:
            bits.append("credentials exposed")
        elif blast >= 0.8:
            bits.append("credential-bearing port")
        if breadth > 1:
            bits.append(f"affects {breadth} hosts - fix once, apply fleet-wide")
        rationale = "; ".join(bits) or "standard remediation"

        scored.append((score, f, PriorityScore(
            rank=0, score=round(score, 3), severity=f.severity,
            exploitability=exploitability, blast_radius=blast,
            affected_hosts=max(breadth, 1), rationale=rationale,
        )))

    scored.sort(key=lambda row: (-row[0], row[1].rule_id))

    ordered: list[Finding] = []
    workings: dict[str, PriorityScore] = {}
    for position, (_, finding, ps) in enumerate(scored, start=1):
        ordered.append(finding)
        key = f"{finding.rule_id}@{finding.affected_host}:{finding.affected_port}"
        workings[key] = PriorityScore(
            rank=position, score=ps.score, severity=ps.severity,
            exploitability=ps.exploitability, blast_radius=ps.blast_radius,
            affected_hosts=ps.affected_hosts, rationale=ps.rationale,
        )

    # Write the rank back onto the sessions' assessments so the dashboard can
    # show "this session holds your #1 priority" without a second lookup.
    rank_by_session: dict[str, int] = {}
    for position, finding in enumerate(ordered, start=1):
        for sid in finding.session_ids:
            rank_by_session.setdefault(sid, position)
    for s in sessions:
        if s.assessment is not None and s.session_id in rank_by_session:
            s.assessment.priority_rank = rank_by_session[s.session_id]

    return ordered, workings


def remediation_batches(ordered: list[Finding]) -> list[dict[str, object]]:
    """Group the queue by rule, for the administrator view (USP-06).

    An admin does not work finding by finding; they apply one configuration
    change across every host that needs it. This is that view of the same data.
    """
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in ordered:
        grouped[f.rule_id].append(f)

    batches = []
    for rule_id, group in grouped.items():
        first = group[0]
        batches.append({
            "rule_id": rule_id,
            "title": first.title,
            "severity": first.severity.value,
            "host_count": len({f.affected_host for f in group if f.affected_host}),
            "hosts": sorted({f.affected_host for f in group if f.affected_host}),
            "remediation": first.remediation.to_dict() if first.remediation else None,
            "effort": first.remediation.effort if first.remediation else "unknown",
        })
    batches.sort(key=lambda b: (-Severity(b["severity"]).rank, -int(b["host_count"])))
    return batches
