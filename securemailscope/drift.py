"""Temporal posture drift. USP-10.

Two captures of the same estate, taken at different times, are a diff: *"the
fleet fell from B to C, because mail-03 was redeployed with a 1024-bit key."*
That turns a one-shot analyser into a monitoring capability, and the store
already archives a `PostureSnapshot` for every completed job, so the data has
been sitting there since ADR-0022.

**The whole thing turns on one question: are these two captures of the same
estate?** If they are not, the arithmetic still works and the answer is
nonsense — "grade fell from A+ to D" reads as a catastrophe when it is really
two unrelated files. This module refuses rather than reports when the estates
do not overlap, because a confident wrong number is worse than a blank panel.
The console already learned that lesson once with its KPI deltas (ADR-0026);
this is the same rule enforced at the source.

Findings are identified across captures by `rule_id@host:port` — the same key
dispositions use (ADR-0022), so an analyst's decision and a drift entry refer
to exactly the same thing.
"""

from __future__ import annotations

from schema import Finding, HostDrift, PostureDrift, Report

#: Below this fraction of shared hosts, two captures are not the same estate.
#: 0.5 is a judgement call: half the hosts in common is a re-scoped capture of
#: one network, a quarter is two different networks that happen to share a
#: subnet convention.
OVERLAP_FLOOR = 0.5

_GRADE_ORDER = ["A+", "A", "B", "C", "D", "E", "F", "?"]


def _key(finding: Finding) -> str:
    """Stable identity across captures. Same scheme as dispositions."""
    return f"{finding.rule_id}@{finding.affected_host or 'unknown'}:" \
           f"{finding.affected_port or 0}"


def _hosts_of(report: Report) -> set[str]:
    return {s.server_host for s in report.sessions if s.server_host}


def _host_scores(report: Report) -> dict[str, tuple[str, float]]:
    return {h.host: (h.grade.value, h.score) for h in report.hosts}


def _direction(before: float, after: float) -> str:
    if abs(after - before) < 0.05:
        return "unchanged"
    return "improved" if after > before else "regressed"


def _worst(findings: list[Finding]) -> Finding | None:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return min(findings, key=lambda f: order.get(f.severity.value, 9), default=None)


def _summary(drift: PostureDrift) -> str:
    """The sentence a reader actually takes away. Names the cause where there
    is one, because "grade fell" without a reason is not actionable."""
    if not drift.comparable:
        return (f"These two captures are not the same estate "
                f"({drift.incomparable_reason}), so no drift was calculated. "
                f"Comparing them would produce a number that is arithmetically "
                f"correct and operationally meaningless.")

    if drift.direction == "unchanged" and not drift.appeared and not drift.resolved:
        return (f"No change. The estate held grade {drift.after_grade} across both "
                f"captures, with {drift.persisted_count} findings carried forward "
                f"and nothing new appearing.")

    parts: list[str] = []
    if drift.before_grade != drift.after_grade:
        verb = "rose" if drift.direction == "improved" else "fell"
        parts.append(f"The fleet grade {verb} from **{drift.before_grade}** to "
                     f"**{drift.after_grade}** "
                     f"({drift.before_score:.0f} -> {drift.after_score:.0f}).")
    elif drift.score_delta:
        parts.append(f"The fleet held grade **{drift.after_grade}**, with the score "
                     f"moving {drift.score_delta:+.1f} points.")
    else:
        parts.append(f"The fleet held grade **{drift.after_grade}**.")

    # Attribute the change to a host wherever the data allows it. This is the
    # difference between a dashboard and a monitoring tool.
    regressed = [h for h in drift.hosts if h.status == "regressed"]
    if regressed:
        worst_host = min(regressed, key=lambda h: h.delta)
        cause = worst_host.appeared[0] if worst_host.appeared else ""
        parts.append(f"The largest regression is **{worst_host.host}** "
                     f"({worst_host.before_grade} -> {worst_host.after_grade})"
                     + (f", which now reports {cause}." if cause else "."))

    if drift.appeared:
        worst = _worst(drift.appeared)
        parts.append(f"{len(drift.appeared)} new "
                     f"{'finding' if len(drift.appeared) == 1 else 'findings'}"
                     + (f", the most serious being {worst.title.lower()} "
                        f"on {worst.affected_host}." if worst else "."))
    if drift.resolved:
        parts.append(f"{len(drift.resolved)} "
                     f"{'finding was' if len(drift.resolved) == 1 else 'findings were'} "
                     f"resolved since the previous capture.")

    new_hosts = [h.host for h in drift.hosts if h.status == "new"]
    gone = [h.host for h in drift.hosts if h.status == "removed"]
    if new_hosts:
        parts.append(f"{len(new_hosts)} host"
                     f"{'' if len(new_hosts) == 1 else 's'} appeared that were not in "
                     f"the earlier capture ({', '.join(new_hosts[:3])}).")
    if gone:
        parts.append(f"{len(gone)} host{'' if len(gone) == 1 else 's'} present earlier "
                     f"were not seen this time ({', '.join(gone[:3])}); that may be "
                     f"decommissioning or simply capture coverage, and this tool "
                     f"cannot tell the difference.")

    return " ".join(parts)


def compare(before: Report, after: Report, *,
            overlap_floor: float = OVERLAP_FLOOR) -> PostureDrift:
    """Diff two reports. Order matters: `before` is the earlier capture.

    Always returns a `PostureDrift`. When the estates do not overlap enough to
    be the same infrastructure, `comparable` is False, the finding lists are
    left empty and `summary` explains why — rather than inventing a trend.
    """
    before_hosts, after_hosts = _hosts_of(before), _hosts_of(after)
    union = before_hosts | after_hosts
    shared = before_hosts & after_hosts
    overlap = len(shared) / len(union) if union else 0.0

    drift = PostureDrift(
        before_capture=before.capture.filename if before.capture else "",
        after_capture=after.capture.filename if after.capture else "",
        before_sha256=before.capture.sha256 if before.capture else "",
        after_sha256=after.capture.sha256 if after.capture else "",
        before_at=before.capture.first_packet_at if before.capture else None,
        after_at=after.capture.first_packet_at if after.capture else None,
        before_grade=before.fleet.grade.value if before.fleet else "?",
        after_grade=after.fleet.grade.value if after.fleet else "?",
        before_score=before.fleet.score if before.fleet else 0.0,
        after_score=after.fleet.score if after.fleet else 0.0,
        host_overlap=round(overlap, 2),
    )
    drift.direction = _direction(drift.before_score, drift.after_score)

    # -- the honesty gate -------------------------------------------------- #
    if before.capture and after.capture and \
            before.capture.sha256 == after.capture.sha256:
        drift.comparable = False
        drift.incomparable_reason = "both sides are the same capture file"
        drift.summary = _summary(drift)
        return drift

    if not union:
        drift.comparable = False
        drift.incomparable_reason = "neither capture contained a mail host"
        drift.summary = _summary(drift)
        return drift

    if overlap < overlap_floor:
        drift.comparable = False
        drift.incomparable_reason = (
            f"only {len(shared)} of {len(union)} hosts appear in both "
            f"({overlap:.0%} overlap, floor is {overlap_floor:.0%})")
        drift.summary = _summary(drift)
        return drift

    drift.comparable = True

    # -- findings ---------------------------------------------------------- #
    before_map = {_key(f): f for f in before.prioritised_findings}
    after_map = {_key(f): f for f in after.prioritised_findings}

    drift.appeared = [after_map[k] for k in after_map.keys() - before_map.keys()]
    drift.resolved = [before_map[k] for k in before_map.keys() - after_map.keys()]
    drift.persisted_count = len(before_map.keys() & after_map.keys())

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    drift.appeared.sort(key=lambda f: order.get(f.severity.value, 9))
    drift.resolved.sort(key=lambda f: order.get(f.severity.value, 9))

    # -- per host ---------------------------------------------------------- #
    before_scores, after_scores = _host_scores(before), _host_scores(after)
    by_host_before: dict[str, set[str]] = {}
    by_host_after: dict[str, set[str]] = {}
    for f in before.prioritised_findings:
        by_host_before.setdefault(f.affected_host or "", set()).add(f.rule_id)
    for f in after.prioritised_findings:
        by_host_after.setdefault(f.affected_host or "", set()).add(f.rule_id)

    for host in sorted(union):
        in_before, in_after = host in before_hosts, host in after_hosts
        bg, bs = before_scores.get(host, ("", 0.0))
        ag, as_ = after_scores.get(host, ("", 0.0))

        if not in_before:
            status = "new"
        elif not in_after:
            status = "removed"
        else:
            status = _direction(bs, as_)
            status = {"improved": "improved", "regressed": "regressed",
                      "unchanged": "unchanged"}[status]

        entry = HostDrift(
            host=host, status=status,
            before_grade=bg, after_grade=ag,
            before_score=bs, after_score=as_,
            appeared=sorted(by_host_after.get(host, set())
                            - by_host_before.get(host, set())),
            resolved=sorted(by_host_before.get(host, set())
                            - by_host_after.get(host, set())),
        )
        # A host whose score held but whose findings changed is not "unchanged".
        if status == "unchanged" and (entry.appeared or entry.resolved):
            entry.status = "changed"
        drift.hosts.append(entry)

    severity_rank = {"regressed": 0, "new": 1, "changed": 2, "removed": 3,
                     "improved": 4, "unchanged": 5}
    drift.hosts.sort(key=lambda h: (severity_rank.get(h.status, 9), h.delta))

    drift.summary = _summary(drift)
    return drift
