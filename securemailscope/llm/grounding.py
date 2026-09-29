"""The fact sheet. Objective O02, USP-04 layer 3.

Everything the narrative layer is allowed to know, extracted from the report
and nothing else. Two jobs:

1. **Bound the input.** A language model never sees capture bytes, credentials,
   banners or payloads — only counts, rule identifiers, severities and the
   remediation text the rule pack already wrote. What is not in here cannot be
   written about.

2. **Make the output checkable.** Because the fact sheet is a closed set of
   identifiers, any host, port, rule or standard appearing in generated prose
   that is *not* in the sheet is a fabrication, and can be detected
   mechanically rather than trusted. `verify.py` does exactly that.

The sheet is hashed, and the hash travels on the narrative. "This text
describes that report" then becomes something a reader can check instead of
something we assert.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from schema import Report, Severity

#: Remediation platforms we emit snippets for, in the order we prefer them.
PLATFORMS = ("postfix", "dovecot", "exchange", "generic")


@dataclass
class FactSheet:
    """A closed set of facts. Nothing outside this may appear in the output."""

    # -- scalars a narrative may quote ------------------------------------- #
    capture_name: str = ""
    capture_sha256: str = ""
    session_count: int = 0
    host_count: int = 0
    finding_count: int = 0
    grade: str = "?"
    score: float = 0.0
    cleartext_credential_sessions: int = 0
    deprecated_version_sessions: int = 0
    forward_secrecy_ratio: float = 0.0
    pq_ready_hosts: int = 0
    encrypted_sessions: int = 0
    cleartext_sessions: int = 0
    unreadable: bool = False

    severity_counts: dict[str, int] = field(default_factory=dict)
    failed_standards: list[str] = field(default_factory=list)

    #: One entry per distinct rule, with everything needed to write about it.
    issues: list[dict] = field(default_factory=list)

    # -- the closed vocabularies, for verification ------------------------- #
    allowed_hosts: set[str] = field(default_factory=set)
    allowed_ports: set[int] = field(default_factory=set)
    allowed_rules: set[str] = field(default_factory=set)
    allowed_standards: set[str] = field(default_factory=set)
    allowed_attacks: set[str] = field(default_factory=set)

    def to_prompt_dict(self) -> dict:
        """The JSON a model would be shown. Sets become sorted lists so the
        serialisation — and therefore the hash — is stable."""
        return {
            "capture": {"name": self.capture_name, "sha256": self.capture_sha256,
                        "readable": not self.unreadable},
            "posture": {"grade": self.grade, "score": self.score,
                        "sessions": self.session_count, "hosts": self.host_count,
                        "encrypted_sessions": self.encrypted_sessions,
                        "cleartext_sessions": self.cleartext_sessions,
                        "forward_secrecy_ratio": self.forward_secrecy_ratio,
                        "pq_ready_hosts": self.pq_ready_hosts,
                        "cleartext_credential_sessions":
                            self.cleartext_credential_sessions,
                        "deprecated_version_sessions":
                            self.deprecated_version_sessions},
            "severity_counts": self.severity_counts,
            "failed_standards": self.failed_standards,
            "issues": self.issues,
        }

    def sha256(self) -> str:
        blob = json.dumps(self.to_prompt_dict(), sort_keys=True,
                          separators=(",", ":")).encode()
        return hashlib.sha256(blob).hexdigest()


def _pick_config(remediation) -> tuple[str, str]:
    """The snippet to show, and which platform it is for.

    Preference order is deliberate: Postfix and Dovecot cover the overwhelming
    majority of self-hosted mail, and a generic directive helps nobody paste
    anything.
    """
    if remediation is None:
        return "generic", ""
    for platform in PLATFORMS:
        text = getattr(remediation, platform, None)
        if text:
            return platform, text
    return "generic", ""


def build(report: Report) -> FactSheet:
    """Extract the fact sheet from a finished report.

    Findings are **grouped by rule**, because that is the unit of work. An
    admin who fixes a weak cipher suite fixes it once, not once per session,
    and a plan that lists the same action thirteen times is a worse plan.
    """
    fleet = report.fleet
    sheet = FactSheet(
        capture_name=report.capture.filename if report.capture else "",
        capture_sha256=report.capture.sha256 if report.capture else "",
        session_count=len(report.sessions),
        host_count=fleet.host_count if fleet else 0,
        finding_count=len(report.prioritised_findings),
        grade=fleet.grade.value if fleet else "?",
        score=fleet.score if fleet else 0.0,
        cleartext_credential_sessions=fleet.cleartext_credential_sessions if fleet else 0,
        deprecated_version_sessions=fleet.deprecated_version_sessions if fleet else 0,
        forward_secrecy_ratio=fleet.forward_secrecy_ratio if fleet else 0.0,
        pq_ready_hosts=fleet.pq_ready_hosts if fleet else 0,
        encrypted_sessions=sum(1 for s in report.sessions
                               if s.tls_mode.value != "cleartext"),
        cleartext_sessions=sum(1 for s in report.sessions
                               if s.tls_mode.value == "cleartext"),
        unreadable=any(f.rule_id == "ANALYSIS-CAPTURE-NOT-READABLE"
                       for f in report.prioritised_findings),
    )

    counts: dict[str, int] = {}
    for finding in report.prioritised_findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    sheet.severity_counts = counts

    if fleet:
        sheet.failed_standards = sorted(k for k, v in fleet.compliance.items()
                                        if v == "fail")
        sheet.allowed_standards.update(fleet.compliance)

    # -- group by rule: one issue is one unit of remediation work ---------- #
    grouped: dict[str, list] = {}
    for finding in report.prioritised_findings:
        grouped.setdefault(finding.rule_id, []).append(finding)

    order = {s.value: i for i, s in enumerate(
        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])}

    for rule_id, group in grouped.items():
        worst = min(group, key=lambda f: order.get(f.severity.value, 99))
        platform, config = _pick_config(worst.remediation)
        endpoints = sorted({f"{f.affected_host}:{f.affected_port}" for f in group
                            if f.affected_host})
        standards = sorted({f"{s.body} {s.identifier}" for f in group
                            for s in (f.standards or []) if s.relation == "violates"})
        attacks = sorted({a for f in group for a in (f.related_attacks or [])})

        sheet.issues.append({
            "rule_id": rule_id,
            "title": worst.title,
            "severity": worst.severity.value,
            "category": worst.category.value,
            "description": worst.description,
            "occurrences": len(group),
            "endpoints": endpoints,
            "port_roles": sorted({f.port_role.value for f in group}),
            "severity_adjusted": worst.severity_adjustment_reason or "",
            "standards_violated": standards,
            "related_attacks": attacks,
            "remediation": worst.remediation.summary if worst.remediation else "",
            "effort": worst.remediation.effort if worst.remediation else "unknown",
            "risk_of_change": (worst.remediation.risk_of_change
                               if worst.remediation else "unknown"),
            "platform": platform,
            "config": config,
        })

        sheet.allowed_rules.add(rule_id)
        sheet.allowed_standards.update(standards)
        sheet.allowed_attacks.update(attacks)
        for f in group:
            if f.affected_host:
                sheet.allowed_hosts.add(f.affected_host)
            if f.affected_port:
                sheet.allowed_ports.add(f.affected_port)

    # Rank: severity first, then how widespread, then cheapness of the fix.
    effort_rank = {"trivial": 0, "low": 1, "medium": 2, "high": 3, "unknown": 2}
    sheet.issues.sort(key=lambda i: (order.get(i["severity"], 99),
                                     -i["occurrences"],
                                     effort_rank.get(i["effort"], 2)))

    for session in report.sessions:
        sheet.allowed_hosts.add(session.server_host)
        sheet.allowed_ports.add(session.server_port)

    return sheet
