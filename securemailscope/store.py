"""Persistence. Stdlib `sqlite3`, no ORM, no migration framework.

One file, five tables. That is the whole design, and it is deliberate: after
seven Smart App Control blocks (ADR-0021), the thing that persists state must
not add a dependency. `sqlite3` ships with Python.

Every write that a human caused also writes an `AuditEvent`, because an audit
log that depends on callers remembering to append to it is not an audit log.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from schema.platform import (
    AnalysisJob,
    AuditAction,
    AuditEvent,
    DispositionState,
    FindingDisposition,
    JobState,
    PostureSnapshot,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY, filename TEXT, capture_sha256 TEXT,
    size_bytes INTEGER, state TEXT, current_stage TEXT, progress REAL,
    submitted_by TEXT, created_at TEXT, started_at TEXT, finished_at TEXT,
    reject_reason TEXT, error TEXT, session_count INTEGER,
    finding_count INTEGER, fleet_grade TEXT
);
CREATE TABLE IF NOT EXISTS reports (
    job_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
    FOREIGN KEY (job_id) REFERENCES jobs (job_id)
);
CREATE TABLE IF NOT EXISTS dispositions (
    finding_key TEXT PRIMARY KEY, job_id TEXT, state TEXT, actor TEXT,
    note TEXT, justification TEXT, expires_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, actor TEXT,
    action TEXT, object_type TEXT, object_id TEXT, detail TEXT,
    before TEXT, after TEXT
);
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY, job_id TEXT, capture_sha256 TEXT,
    captured_at TEXT, fleet_score REAL, fleet_grade TEXT, host_count INTEGER,
    session_count INTEGER, finding_counts TEXT, compliance TEXT,
    finalised_by TEXT, finalised_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit (timestamp DESC);
"""


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class Store:
    """All persistence. Thread-safe enough for a single-process Flask app."""

    def __init__(self, path: str | Path = "data/securemailscope.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # check_same_thread=False: the job runner writes progress from a worker
        # thread while the request thread reads it. Writes are short and
        # serialised by SQLite's own locking.
        conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- audit ------------------------------------------------------------- #

    def record(self, actor: str, action: AuditAction, object_type: str,
               object_id: str, detail: str = "",
               before: str | None = None, after: str | None = None) -> None:
        """Append to the audit log. Never updates, never deletes."""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO audit (timestamp, actor, action, object_type, "
                "object_id, detail, before, after) VALUES (?,?,?,?,?,?,?,?)",
                (_now(), actor, action.value, object_type, object_id,
                 detail, before, after))

    def audit_events(self, limit: int = 200) -> list[AuditEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit ORDER BY event_id DESC LIMIT ?", (limit,)).fetchall()
        return [AuditEvent(
            event_id=r["event_id"], timestamp=_dt(r["timestamp"]), actor=r["actor"],
            action=AuditAction(r["action"]), object_type=r["object_type"],
            object_id=r["object_id"], detail=r["detail"],
            before=r["before"], after=r["after"]) for r in rows]

    # -- jobs -------------------------------------------------------------- #

    def create_job(self, filename: str, size_bytes: int,
                   submitted_by: str = "anonymous") -> AnalysisJob:
        job = AnalysisJob(
            job_id=uuid.uuid4().hex[:12], filename=filename, size_bytes=size_bytes,
            state=JobState.QUEUED, submitted_by=submitted_by,
            created_at=datetime.now(tz=timezone.utc))
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO jobs (job_id, filename, capture_sha256, size_bytes, "
                "state, current_stage, progress, submitted_by, created_at, "
                "session_count, finding_count) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (job.job_id, filename, "", size_bytes, job.state.value, "", 0.0,
                 submitted_by, job.created_at.isoformat(), 0, 0))
        self.record(submitted_by, AuditAction.JOB_SUBMITTED, "job", job.job_id,
                    f"{filename} ({size_bytes:,} bytes)")
        return job

    def update_job(self, job: AnalysisJob) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE jobs SET capture_sha256=?, state=?, current_stage=?, "
                "progress=?, started_at=?, finished_at=?, reject_reason=?, error=?, "
                "session_count=?, finding_count=?, fleet_grade=? WHERE job_id=?",
                (job.capture_sha256, job.state.value, job.current_stage, job.progress,
                 job.started_at.isoformat() if job.started_at else None,
                 job.finished_at.isoformat() if job.finished_at else None,
                 job.reject_reason, job.error, job.session_count, job.finding_count,
                 job.fleet_grade, job.job_id))

    def get_job(self, job_id: str) -> AnalysisJob | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return self._job(row) if row else None

    def list_jobs(self, limit: int = 50) -> list[AnalysisJob]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._job(r) for r in rows]

    @staticmethod
    def _job(r: sqlite3.Row) -> AnalysisJob:
        return AnalysisJob(
            job_id=r["job_id"], filename=r["filename"],
            capture_sha256=r["capture_sha256"] or "", size_bytes=r["size_bytes"] or 0,
            state=JobState(r["state"]), current_stage=r["current_stage"] or "",
            progress=r["progress"] or 0.0, submitted_by=r["submitted_by"] or "anonymous",
            created_at=_dt(r["created_at"]), started_at=_dt(r["started_at"]),
            finished_at=_dt(r["finished_at"]), reject_reason=r["reject_reason"],
            error=r["error"], session_count=r["session_count"] or 0,
            finding_count=r["finding_count"] or 0, fleet_grade=r["fleet_grade"])

    # -- reports ----------------------------------------------------------- #

    def save_report(self, job_id: str, report_json: str) -> None:
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO reports (job_id, payload) VALUES (?,?)",
                         (job_id, report_json))

    def get_report(self, job_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute("SELECT payload FROM reports WHERE job_id=?",
                               (job_id,)).fetchone()
        return row["payload"] if row else None

    # -- dispositions ------------------------------------------------------ #

    def get_disposition(self, finding_key: str) -> FindingDisposition:
        """Missing means NEW — an untouched finding is not a missing record."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM dispositions WHERE finding_key=?",
                               (finding_key,)).fetchone()
        if row is None:
            return FindingDisposition(finding_key=finding_key)
        return FindingDisposition(
            finding_key=row["finding_key"], job_id=row["job_id"] or "",
            state=DispositionState(row["state"]), actor=row["actor"] or "anonymous",
            note=row["note"], justification=row["justification"],
            expires_at=_dt(row["expires_at"]), updated_at=_dt(row["updated_at"]))

    def set_disposition(self, finding_key: str, target: DispositionState, actor: str,
                        job_id: str = "", note: str | None = None,
                        justification: str | None = None) -> FindingDisposition:
        """Move a finding to a new disposition, enforcing the state machine.

        Raises ValueError on an illegal transition or a missing justification,
        rather than silently accepting it — the audit trail is only worth
        something if the transitions in it were legal.
        """
        current = self.get_disposition(finding_key)
        if target is not current.state and not current.can_move_to(target):
            raise ValueError(
                f"cannot move {finding_key} from {current.state.value} to {target.value}")
        if target is DispositionState.ACCEPTED_RISK and not justification:
            raise ValueError(
                "accepting risk requires a justification: an unexplained acceptance "
                "is indistinguishable from an unread alert")

        updated = FindingDisposition(
            finding_key=finding_key, job_id=job_id or current.job_id, state=target,
            actor=actor, note=note, justification=justification,
            updated_at=datetime.now(tz=timezone.utc))
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO dispositions (finding_key, job_id, state, "
                "actor, note, justification, expires_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (finding_key, updated.job_id, target.value, actor, note, justification,
                 None, updated.updated_at.isoformat()))
        self.record(actor, AuditAction.DISPOSITION_CHANGED, "finding", finding_key,
                    note or "", before=current.state.value, after=target.value)
        return updated

    def all_dispositions(self) -> dict[str, FindingDisposition]:
        with self._connect() as conn:
            rows = conn.execute("SELECT finding_key FROM dispositions").fetchall()
        return {r["finding_key"]: self.get_disposition(r["finding_key"]) for r in rows}

    def training_signal(self) -> list[tuple[str, str]]:
        """(finding_key, state) for dispositions that carry supervised signal.

        This is the feedback loop: analyst decisions become labels. See
        `DispositionState.is_training_signal`.
        """
        return [(k, d.state.value) for k, d in self.all_dispositions().items()
                if d.state.is_training_signal]

    # -- snapshots --------------------------------------------------------- #

    def save_snapshot(self, snapshot: PostureSnapshot) -> PostureSnapshot:
        if not snapshot.snapshot_id:
            snapshot.snapshot_id = uuid.uuid4().hex[:12]
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO snapshots (snapshot_id, job_id, "
                "capture_sha256, captured_at, fleet_score, fleet_grade, host_count, "
                "session_count, finding_counts, compliance, finalised_by, finalised_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (snapshot.snapshot_id, snapshot.job_id, snapshot.capture_sha256,
                 snapshot.captured_at.isoformat() if snapshot.captured_at else _now(),
                 snapshot.fleet_score, snapshot.fleet_grade, snapshot.host_count,
                 snapshot.session_count, json.dumps(snapshot.finding_counts),
                 json.dumps(snapshot.compliance), snapshot.finalised_by,
                 snapshot.finalised_at.isoformat() if snapshot.finalised_at else None))
        return snapshot

    def finalise_snapshot(self, snapshot_id: str, actor: str) -> PostureSnapshot | None:
        """Freeze a snapshot. This is AUDIT POSTURE FINALIZATION."""
        snapshot = self.get_snapshot(snapshot_id)
        if snapshot is None or snapshot.is_final:
            return snapshot
        snapshot.finalised_by = actor
        snapshot.finalised_at = datetime.now(tz=timezone.utc)
        self.save_snapshot(snapshot)
        self.record(actor, AuditAction.POSTURE_FINALISED, "snapshot", snapshot_id,
                    f"grade {snapshot.fleet_grade}, score {snapshot.fleet_score}")
        return snapshot

    def get_snapshot(self, snapshot_id: str) -> PostureSnapshot | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM snapshots WHERE snapshot_id=?",
                               (snapshot_id,)).fetchone()
        return self._snapshot(row) if row else None

    def list_snapshots(self, limit: int = 50) -> list[PostureSnapshot]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM snapshots ORDER BY captured_at DESC LIMIT ?",
                (limit,)).fetchall()
        return [self._snapshot(r) for r in rows]

    @staticmethod
    def _snapshot(r: sqlite3.Row) -> PostureSnapshot:
        return PostureSnapshot(
            snapshot_id=r["snapshot_id"], job_id=r["job_id"] or "",
            capture_sha256=r["capture_sha256"] or "", captured_at=_dt(r["captured_at"]),
            fleet_score=r["fleet_score"] or 0.0, fleet_grade=r["fleet_grade"] or "",
            host_count=r["host_count"] or 0, session_count=r["session_count"] or 0,
            finding_counts=json.loads(r["finding_counts"] or "{}"),
            compliance=json.loads(r["compliance"] or "{}"),
            finalised_by=r["finalised_by"], finalised_at=_dt(r["finalised_at"]))


def finding_key(rule_id: str, host: str | None, port: int | None) -> str:
    """Stable identity for a finding across runs.

    Rule + host + port, deliberately not a per-run id: an analyst's decision
    must survive re-analysing the same infrastructure, otherwise every run
    resets the queue and the dispositions are worthless.
    """
    return f"{rule_id}@{host or 'unknown'}:{port or 0}"
