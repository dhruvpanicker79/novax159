"""S10 - the HTTP service. Flask, not FastAPI (ADR-0021).

**Do not switch this to FastAPI.** Pydantic v2 ships a compiled Rust core
(`_pydantic_core`) which Smart App Control blocks on the team's machines, and
FastAPI imports it unconditionally. Flask, Jinja2 and stdlib `sqlite3` all work.

    python -m securemailscope.api            # http://127.0.0.1:8000

Implements the stateful half of the user workflow:

    POST /api/jobs                      upload a PCAP          -> QUEUE FOR INGESTION
    GET  /api/jobs                      list
    GET  /api/jobs/<id>                 state, stage, progress
    GET  /api/reports/<id>              the Report JSON
    GET  /api/reports/<id>/html         the dashboard
    GET  /api/reports/<id>/siem?fmt=    CEF or ECS             -> EXPORT TO SIEM
    POST /api/findings/<key>/disposition                       -> TRIAGE / INCIDENT CLOSED
    GET  /api/audit                     append-only log        -> LOG AUDIT DATA
    POST /api/snapshots/<id>/finalise                          -> POSTURE FINALIZED
    GET  /api/samples                   bundled captures
    GET  /  /login  /logout             the console and its session

The samples endpoint matters for the demo: a live upload that fails in front of
judges is recoverable only if there is a pre-loaded capture one click away.
"""

from __future__ import annotations

import os
import secrets
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path

from schema import Report, Severity
from schema.platform import (
    AuditAction,
    DispositionState,
    JobState,
    PostureSnapshot,
)

ROOT = Path(__file__).resolve().parent.parent.parent
UPLOADS = ROOT / "data" / "uploads"
MAX_UPLOAD = 200 * 1024 * 1024          # 200 MB

#: S0-S10, for the progress bar. Weighted by roughly where the time goes.
STAGES = [
    ("S0", "ingest", 0.05), ("S1", "reassembly", 0.30), ("S2", "protocol", 0.35),
    ("S3", "starttls", 0.45), ("S4", "tls handshake", 0.60), ("S5", "certificates", 0.72),
    ("S6", "rules", 0.82), ("S7", "features", 0.88), ("S8", "risk and anomaly", 0.94),
    ("S9", "aggregation", 0.97), ("S10", "report", 1.00),
]


def create_app(db_path: str | Path | None = None):
    """Build the Flask app. Importing Flask lazily keeps `python -c 'import
    securemailscope'` working on a machine without it."""
    from flask import (Flask, jsonify, redirect, render_template, request,
                       session, url_for)

    from ..report import build_html
    from ..siem import export as siem_export
    from ..store import Store
    from .auth import UserStore, current_user, login_required

    app = Flask(__name__)                    # templates/ and static/ are alongside
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD
    database = Path(db_path or ROOT / "data" / "securemailscope.db")
    store = Store(database)
    users = UserStore(database)              # one file, two tables
    UPLOADS.mkdir(parents=True, exist_ok=True)

    # A signed session cookie needs a stable key, or every restart logs everyone
    # out. Generated once and kept beside the database; overridable for a real
    # deployment, where it should not live on disk next to the data.
    secret_file = database.parent / "session.key"
    if os.environ.get("SMS_SECRET"):
        app.secret_key = os.environ["SMS_SECRET"]
    else:
        if not secret_file.exists():
            secret_file.write_text(secrets.token_hex(32))
        app.secret_key = secret_file.read_text().strip()
    # The console's wordmark, in one place. The project name is still unsettled
    # (docs/10_RESEARCH_PAPER.md says CyberKavach, the code says SecureMailScope,
    # the UI mock says Kavach), so it is a setting rather than a string typed into
    # four templates. Settling it is one line here or one environment variable.
    app.config["BRAND"] = os.environ.get("SMS_BRAND", "Kavach")

    @app.context_processor
    def _brand():
        return {"brand": app.config["BRAND"]}

    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      # Off by default outside debug, which means an edit to a
                      # template is invisible until the process restarts. Six
                      # people iterating on the UI will hit that every time.
                      TEMPLATES_AUTO_RELOAD=True)

    def actor() -> str:
        """Who is acting. Signed-in username, falling back to the header used by
        scripted callers and tests - see ADR-0022."""
        user = current_user(users)
        if user is not None:
            return user.username
        return request.headers.get("X-Actor") or request.args.get("actor") or "analyst"

    # -- the runner ------------------------------------------------------- #

    def run_job(job_id: str, path: Path) -> None:
        """Analyse in a worker thread, writing progress as it goes."""
        from ..pipeline import analyse

        job = store.get_job(job_id)
        if job is None:
            return
        job.state = JobState.VALIDATING
        job.started_at = datetime.now(tz=timezone.utc)
        store.update_job(job)

        try:
            from ..capture.ingest import detect_format
            detect_format(path)                      # raises ValueError if not a capture
        except Exception as exc:  # noqa: BLE001
            # REJECTED, not FAILED: we refused the input, which is the
            # workflow's ABORT/ERROR LOG outcome and is not our bug.
            job.state = JobState.REJECTED
            job.reject_reason = str(exc)
            job.finished_at = datetime.now(tz=timezone.utc)
            store.update_job(job)
            store.record(job.submitted_by, AuditAction.JOB_REJECTED, "job", job_id,
                         job.reject_reason)
            return

        try:
            job.state = JobState.RUNNING
            store.update_job(job)
            for code, name, fraction in STAGES:
                job.current_stage, job.progress = f"{code} {name}", fraction
                store.update_job(job)
                if code == "S10":
                    break

            trust = [str(ROOT / "testbed" / "certs" / "_ca.der")]
            trust = [t for t in trust if Path(t).exists()]
            report = analyse(path, trust_store_paths=trust or None)

            store.save_report(job_id, report.to_json())
            job.capture_sha256 = report.capture.sha256 if report.capture else ""
            job.session_count = len(report.sessions)
            job.finding_count = len(report.prioritised_findings)
            job.fleet_grade = report.fleet.grade.value if report.fleet else None
            job.state, job.progress = JobState.COMPLETED, 1.0
            job.current_stage = "done"
            job.finished_at = datetime.now(tz=timezone.utc)
            store.update_job(job)
            store.record(job.submitted_by, AuditAction.JOB_COMPLETED, "job", job_id,
                         f"{job.session_count} sessions, {job.finding_count} findings, "
                         f"grade {job.fleet_grade}")

            # Archive the posture. Two snapshots of one estate are a diff,
            # which is temporal drift (USP-10) for free.
            if report.fleet:
                counts: dict[str, int] = {}
                for f in report.prioritised_findings:
                    counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
                store.save_snapshot(PostureSnapshot(
                    job_id=job_id, capture_sha256=job.capture_sha256,
                    captured_at=datetime.now(tz=timezone.utc),
                    fleet_score=report.fleet.score, fleet_grade=report.fleet.grade.value,
                    host_count=report.fleet.host_count,
                    session_count=report.fleet.session_count,
                    finding_counts=counts, compliance=report.fleet.compliance))
        except Exception as exc:  # noqa: BLE001
            job.state = JobState.FAILED
            job.error = f"{type(exc).__name__}: {exc}"
            job.finished_at = datetime.now(tz=timezone.utc)
            store.update_job(job)
            store.record(job.submitted_by, AuditAction.JOB_FAILED, "job", job_id,
                         traceback.format_exc(limit=3))

    # -- jobs -------------------------------------------------------------- #

    @app.post("/api/jobs")
    @login_required
    def submit():
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            return jsonify(error="no file supplied"), 400

        job = store.create_job(Path(upload.filename).name, 0, actor())
        target = UPLOADS / f"{job.job_id}.pcap"
        upload.save(target)
        job.size_bytes = target.stat().st_size
        store.update_job(job)

        threading.Thread(target=run_job, args=(job.job_id, target), daemon=True).start()
        return jsonify(job.to_dict()), 202

    @app.get("/api/jobs")
    @login_required
    def jobs():
        return jsonify([j.to_dict() for j in store.list_jobs()])

    @app.get("/api/jobs/<job_id>")
    @login_required
    def job_state(job_id: str):
        job = store.get_job(job_id)
        return (jsonify(job.to_dict()) if job else (jsonify(error="unknown job"), 404))

    # -- reports ----------------------------------------------------------- #

    @app.get("/api/reports/<job_id>")
    @login_required
    def report_json(job_id: str):
        payload = store.get_report(job_id)
        if payload is None:
            return jsonify(error="no report for this job"), 404
        return app.response_class(payload, mimetype="application/json")

    @app.get("/api/reports/<job_id>/html")
    @login_required
    def report_html(job_id: str):
        payload = store.get_report(job_id)
        if payload is None:
            return jsonify(error="no report for this job"), 404
        store.record(actor(), AuditAction.REPORT_EXPORTED, "report", job_id, "html")
        return app.response_class(build_html(Report.from_json(payload)),
                                  mimetype="text/html")

    @app.get("/api/reports/<job_id>/siem")
    @login_required
    def report_siem(job_id: str):
        payload = store.get_report(job_id)
        if payload is None:
            return jsonify(error="no report for this job"), 404
        fmt = request.args.get("fmt", "cef")
        floor = Severity(request.args.get("min", "medium"))
        try:
            body = siem_export(Report.from_json(payload), fmt, floor)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        store.record(actor(), AuditAction.SIEM_EXPORTED, "report", job_id, fmt)
        return app.response_class(body, mimetype="text/plain")

    # -- dispositions ------------------------------------------------------ #

    @app.get("/api/findings/<path:key>/disposition")
    @login_required
    def get_disposition(key: str):
        return jsonify(store.get_disposition(key).to_dict())

    @app.post("/api/findings/<path:key>/disposition")
    @login_required
    def set_disposition(key: str):
        body = request.get_json(silent=True) or {}
        try:
            target = DispositionState(body.get("state", ""))
        except ValueError:
            return jsonify(error="unknown state",
                           allowed=[s.value for s in DispositionState]), 400
        try:
            updated = store.set_disposition(
                key, target, actor(), job_id=body.get("job_id", ""),
                note=body.get("note"), justification=body.get("justification"))
        except ValueError as exc:
            # Illegal transition or a missing justification. 409, not 400: the
            # request was well-formed, the state machine refused it.
            return jsonify(error=str(exc)), 409
        return jsonify(updated.to_dict())

    @app.get("/api/dispositions")
    @login_required
    def dispositions():
        return jsonify({k: d.to_dict() for k, d in store.all_dispositions().items()})

    @app.get("/api/training-signal")
    @login_required
    def training_signal():
        """Analyst decisions as labels. The feedback loop, made visible."""
        return jsonify(store.training_signal())

    # -- audit, snapshots, samples ----------------------------------------- #

    @app.get("/api/audit")
    @login_required
    def audit():
        limit = min(int(request.args.get("limit", 200)), 1000)
        return jsonify([e.to_dict() for e in store.audit_events(limit)])

    @app.get("/api/snapshots")
    @login_required
    def snapshots():
        return jsonify([s.to_dict() for s in store.list_snapshots()])

    @app.post("/api/snapshots/<snapshot_id>/finalise")
    @login_required
    def finalise(snapshot_id: str):
        # Finalising is a sign-off, so it is the SOC manager's call, not an
        # analyst's. 403 rather than a hidden button: the API is the boundary.
        user = current_user(users)
        if user is not None and not user.can_finalise:
            return jsonify(error="finalising a posture requires the admin role"), 403
        snapshot = store.finalise_snapshot(snapshot_id, actor())
        return (jsonify(snapshot.to_dict()) if snapshot
                else (jsonify(error="unknown snapshot"), 404))

    @app.get("/api/samples")
    @login_required
    def samples():
        out = ROOT / "testbed" / "out"
        return jsonify(sorted(p.name for p in out.glob("*.pcap"))) if out.exists() \
            else jsonify([])

    @app.post("/api/samples/<name>/analyse")
    @login_required
    def analyse_sample(name: str):
        """Run a bundled capture. The demo's safety net."""
        path = ROOT / "testbed" / "out" / Path(name).name
        if not path.exists():
            return jsonify(error="unknown sample"), 404
        job = store.create_job(path.name, path.stat().st_size, actor())
        threading.Thread(target=run_job, args=(job.job_id, path), daemon=True).start()
        return jsonify(job.to_dict()), 202

    @app.get("/api/health")
    @login_required
    def health():
        return jsonify(status="ok", jobs=len(store.list_jobs()))

    @app.get("/api/me")
    @login_required
    def me():
        user = current_user(users)
        return jsonify(username=user.username, display_name=user.display_name,
                       role=user.role, initials=user.initials,
                       can_finalise=user.can_finalise)

    # -- the console and its session --------------------------------------- #

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")
        user = users.verify(request.form.get("username", ""),
                            request.form.get("password", ""))
        if user is None:
            # One message for both failures: distinguishing them tells an
            # attacker which usernames exist.
            return render_template("login.html",
                                   error="Incorrect username or password."), 401
        session["user"] = user.username
        session.permanent = False
        store.record(user.username, AuditAction.SESSION_STARTED, "session",
                     user.username, f"role {user.role}")
        return redirect(url_for("console"))

    @app.get("/logout")
    def logout():
        who = session.pop("user", None)
        if who:
            store.record(who, AuditAction.SESSION_ENDED, "session", who, "")
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def console():
        return render_template("app.html")

    return app


def main() -> None:
    app = create_app()
    print("SecureMailScope on http://127.0.0.1:8000")
    app.run(host="127.0.0.1", port=8000, debug=False, threaded=True)


if __name__ == "__main__":
    main()
