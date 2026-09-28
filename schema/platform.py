"""Platform-layer contract: jobs, dispositions, audit, snapshots.

The objects in `models.py` describe an *analysis*. These describe the
*application* around it — the parts of the user workflow that carry state
rather than facts:

    AnalysisJob        upload -> validate -> run -> result, or reject with a reason
    FindingDisposition what an analyst decided about a finding
    AuditEvent         append-only record of who did what
    PostureSnapshot    a finalised, immutable posture at a point in time

Same rules as the analysis contract (ADR-0005, ADR-0009): stdlib only, and a
field change updates `docs/03_ARCHITECTURE.md` in the same commit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .base import JsonModel


class JobState(str, Enum):
    """Lifecycle of one analysis request.

    `REJECTED` is distinct from `FAILED` on purpose. Rejected means we refused
    the input — not a capture, unreadable, too large — and is the workflow's
    ABORT/ERROR LOG outcome. Failed means we accepted it and then broke, which
    is our problem and needs a traceback.
    """

    QUEUED = "queued"
    VALIDATING = "validating"
    RUNNING = "running"
    COMPLETED = "completed"
    REJECTED = "rejected"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        return self in (JobState.COMPLETED, JobState.REJECTED, JobState.FAILED)


class DispositionState(str, Enum):
    """What an analyst decided about a finding.

    This is what separates a platform from a report generator: findings acquire
    a human decision and keep it across runs.

    FALSE_POSITIVE is the valuable one. Every finding an analyst marks as a
    false positive is a labelled training example, so analyst work feeds back
    into the model instead of evaporating.
    """

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"

    @property
    def is_open(self) -> bool:
        return self in (DispositionState.NEW, DispositionState.ACKNOWLEDGED,
                        DispositionState.IN_PROGRESS)

    @property
    def is_training_signal(self) -> bool:
        """Dispositions that carry supervised signal back to the model."""
        return self in (DispositionState.FALSE_POSITIVE, DispositionState.RESOLVED)


#: Legal transitions. An analyst may not jump straight from `new` to
#: `resolved` without acknowledging: the audit trail has to show someone
#: looked. Terminal states can be reopened to `acknowledged`, because
#: dispositions get made in error.
ALLOWED_TRANSITIONS: dict[DispositionState, set[DispositionState]] = {
    DispositionState.NEW: {
        DispositionState.ACKNOWLEDGED, DispositionState.FALSE_POSITIVE},
    DispositionState.ACKNOWLEDGED: {
        DispositionState.IN_PROGRESS, DispositionState.RESOLVED,
        DispositionState.FALSE_POSITIVE, DispositionState.ACCEPTED_RISK},
    DispositionState.IN_PROGRESS: {
        DispositionState.RESOLVED, DispositionState.FALSE_POSITIVE,
        DispositionState.ACCEPTED_RISK},
    DispositionState.RESOLVED: {DispositionState.ACKNOWLEDGED},
    DispositionState.FALSE_POSITIVE: {DispositionState.ACKNOWLEDGED},
    DispositionState.ACCEPTED_RISK: {
        DispositionState.ACKNOWLEDGED, DispositionState.IN_PROGRESS},
}


class AuditAction(str, Enum):
    """Everything worth recording. Keep this list short and meaningful."""

    JOB_SUBMITTED = "job.submitted"
    JOB_REJECTED = "job.rejected"
    JOB_COMPLETED = "job.completed"
    JOB_FAILED = "job.failed"
    DISPOSITION_CHANGED = "finding.disposition_changed"
    REPORT_EXPORTED = "report.exported"
    SIEM_EXPORTED = "finding.siem_exported"
    POSTURE_FINALISED = "posture.finalised"


@dataclass
class AnalysisJob(JsonModel):
    """One analysis request, from upload to result."""

    job_id: str = ""
    filename: str = ""
    capture_sha256: str = ""
    size_bytes: int = 0
    state: JobState = JobState.QUEUED
    current_stage: str = ""          #: S0..S10, for the progress bar
    progress: float = 0.0            #: 0.0-1.0
    submitted_by: str = "anonymous"
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    #: Why we refused the input. The workflow's ABORT/ERROR LOG artifact.
    reject_reason: str | None = None
    error: str | None = None
    session_count: int = 0
    finding_count: int = 0
    fleet_grade: str | None = None

    @property
    def duration_seconds(self) -> float | None:
        if not self.started_at or not self.finished_at:
            return None
        return round((self.finished_at - self.started_at).total_seconds(), 2)


@dataclass
class FindingDisposition(JsonModel):
    """An analyst's decision about one finding.

    `finding_key` is stable across re-analyses of the same infrastructure —
    rule + host + port — so a decision made today still applies when the same
    capture is re-run or a new capture of the same fleet arrives. Keying on a
    per-run finding id would lose the decision on every run.
    """

    finding_key: str = ""            #: "RULE-ID@host:port"
    job_id: str = ""
    state: DispositionState = DispositionState.NEW
    actor: str = "anonymous"
    note: str | None = None
    #: Required when accepting risk: an unexplained acceptance is indistinguishable
    #: from an unread alert.
    justification: str | None = None
    expires_at: datetime | None = None
    updated_at: datetime | None = None

    def can_move_to(self, target: DispositionState) -> bool:
        return target in ALLOWED_TRANSITIONS.get(self.state, set())


@dataclass
class AuditEvent(JsonModel):
    """Append-only. Never updated, never deleted.

    Serves the workflow's LOG AUDIT DATA box, the forensics persona, and the
    CERT-In Directions 2022 six-hour incident-reporting requirement: it records
    exactly when a finding was seen and who acted on it.
    """

    event_id: int = 0
    timestamp: datetime | None = None
    actor: str = "anonymous"
    action: AuditAction = AuditAction.JOB_SUBMITTED
    object_type: str = ""
    object_id: str = ""
    detail: str = ""
    before: str | None = None
    after: str | None = None


@dataclass
class PostureSnapshot(JsonModel):
    """A finalised posture, frozen at a point in time.

    Covers REPORT ARCHIVED and AUDIT POSTURE FINALIZATION. Two snapshots of the
    same estate are a diff, which is USP-10 (temporal posture drift) for free.
    """

    snapshot_id: str = ""
    job_id: str = ""
    capture_sha256: str = ""
    captured_at: datetime | None = None
    fleet_score: float = 0.0
    fleet_grade: str = ""
    host_count: int = 0
    session_count: int = 0
    finding_counts: dict[str, int] = field(default_factory=dict)
    compliance: dict[str, str] = field(default_factory=dict)
    finalised_by: str | None = None
    finalised_at: datetime | None = None

    @property
    def is_final(self) -> bool:
        return self.finalised_at is not None
