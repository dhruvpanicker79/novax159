"""SIEM export. Deliverable-adjacent, and the cheapest credibility in the project.

A finding that stays in our dashboard is a finding a SOC will not see. Real
teams live in Splunk, QRadar, Sentinel or Elastic, so we emit the two formats
those actually ingest:

    CEF   ArcSight Common Event Format, understood by Splunk, QRadar, Sentinel
    ECS   Elastic Common Schema, as newline-delimited JSON

Stdlib only. No syslog client, no vendor SDK — a SOC already has a collector;
what it needs from us is correctly-shaped events on stdout, a file, or an HTTP
endpoint it polls.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from schema import Finding, Report, Severity

VENDOR = "SecureMailScope"
PRODUCT = "PassivePostureAssessment"
VERSION = "1.0"

#: CEF severity is 0-10. Map from our five levels, leaving headroom at the top
#: so a SOC can reserve 9-10 for its own correlation rules.
_CEF_SEVERITY = {
    Severity.INFO: 1, Severity.LOW: 3, Severity.MEDIUM: 5,
    Severity.HIGH: 7, Severity.CRITICAL: 9,
}
_ECS_SEVERITY = {
    Severity.INFO: 10, Severity.LOW: 25, Severity.MEDIUM: 50,
    Severity.HIGH: 75, Severity.CRITICAL: 99,
}


def _cef_escape(value: str) -> str:
    """CEF header fields escape backslash and pipe; extensions also escape `=`."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_extension_escape(value: str) -> str:
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\n", " ").replace("\r", " "))


def to_cef(finding: Finding, capture_sha256: str = "",
           timestamp: datetime | None = None) -> str:
    """One finding as a CEF line.

    CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
    """
    stamp = (timestamp or datetime.now(tz=timezone.utc)).strftime("%b %d %Y %H:%M:%S")
    header = "|".join([
        "CEF:0", VENDOR, PRODUCT, VERSION,
        _cef_escape(finding.rule_id), _cef_escape(finding.title),
        str(_CEF_SEVERITY.get(finding.severity, 1)),
    ])

    extensions: dict[str, str] = {
        "rt": stamp,
        "dst": finding.affected_host or "",
        "dpt": str(finding.affected_port or ""),
        "cat": finding.category.value,
        "outcome": finding.severity.value,
        "cs1Label": "portRole", "cs1": finding.port_role.value,
        "cs2Label": "confidence", "cs2": finding.confidence.value,
        "cs3Label": "captureSha256", "cs3": capture_sha256[:64],
        "cs4Label": "standards",
        "cs4": ",".join(f"{s.body} {s.identifier}" for s in finding.standards
                        if s.relation == "violates"),
        "msg": finding.description[:512],
    }
    if finding.evidence and finding.evidence.frame_numbers:
        # Frame numbers are what make this verifiable in Wireshark; a SIEM
        # event without them is an alert nobody can check.
        extensions["cn1Label"] = "firstFrame"
        extensions["cn1"] = str(min(finding.evidence.frame_numbers))
        extensions["cs5Label"] = "streamId"
        extensions["cs5"] = str(finding.evidence.stream_id or "")
    if finding.related_attacks:
        extensions["cs6Label"] = "attacks"
        extensions["cs6"] = ",".join(finding.related_attacks)[:200]

    body = " ".join(f"{k}={_cef_extension_escape(v)}"
                    for k, v in extensions.items() if v != "")
    return f"{header}|{body}"


def to_ecs(finding: Finding, capture_sha256: str = "",
           timestamp: datetime | None = None) -> dict:
    """One finding as an Elastic Common Schema document."""
    stamp = (timestamp or datetime.now(tz=timezone.utc)).isoformat()
    doc: dict = {
        "@timestamp": stamp,
        "event": {
            "kind": "alert",
            "category": ["network", "configuration"],
            "type": ["info"],
            "severity": _ECS_SEVERITY.get(finding.severity, 10),
            "risk_score": _ECS_SEVERITY.get(finding.severity, 10),
            "provider": VENDOR,
            "module": "email_tls_posture",
            "dataset": "securemailscope.finding",
            "outcome": "failure" if finding.severity.rank >= 2 else "unknown",
        },
        "rule": {
            "id": finding.rule_id,
            "name": finding.title,
            "category": finding.category.value,
            "description": finding.description,
        },
        "message": finding.title,
        "destination": {"address": finding.affected_host,
                        "port": finding.affected_port},
        "network": {"protocol": "smtp/imap/pop3", "transport": "tcp"},
        "securemailscope": {
            "port_role": finding.port_role.value,
            "confidence": finding.confidence.value,
            "base_severity": finding.base_severity.value,
            "severity": finding.severity.value,
            "severity_adjusted": finding.was_adjusted,
            "capture_sha256": capture_sha256,
        },
        "threat": {"technique": {"name": finding.related_attacks}} if
                  finding.related_attacks else {},
    }
    if finding.severity_adjustment_reason:
        doc["securemailscope"]["adjustment_reason"] = finding.severity_adjustment_reason
    if finding.evidence and finding.evidence.frame_numbers:
        doc["securemailscope"]["evidence"] = {
            "stream_id": finding.evidence.stream_id,
            "frame_numbers": finding.evidence.frame_numbers[:20],
            "byte_range": finding.evidence.byte_range,
        }
    if finding.standards:
        doc["securemailscope"]["standards_violated"] = [
            f"{s.body} {s.identifier}" for s in finding.standards
            if s.relation == "violates"]
    return doc


def export(report: Report, fmt: str = "cef",
           min_severity: Severity = Severity.MEDIUM) -> str:
    """Render a report's findings for a SIEM.

    Defaults to MEDIUM and above. Forwarding every informational finding to a
    SIEM is how a feed gets muted — and a muted feed is worse than no feed,
    because everyone believes it is working.
    """
    stamp = report.generated_at or datetime.now(tz=timezone.utc)
    sha = report.capture.sha256 if report.capture else ""
    findings = [f for f in report.prioritised_findings
                if f.severity.rank >= min_severity.rank]

    if fmt.lower() == "cef":
        return "\n".join(to_cef(f, sha, stamp) for f in findings)
    if fmt.lower() in ("ecs", "json", "ndjson"):
        return "\n".join(json.dumps(to_ecs(f, sha, stamp)) for f in findings)
    raise ValueError(f"unknown SIEM format {fmt!r}; expected 'cef' or 'ecs'")
