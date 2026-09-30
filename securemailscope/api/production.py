"""Production entry point and hardening. Deployment only.

    python -m securemailscope.api.production

`python -m securemailscope.api` runs Flask's development server, which is fine
on a laptop and explicitly unsupported for anything reachable. This module
serves the same app through **waitress** — pure Python, so it runs on Windows
and on the deploy host without a compiled dependency, which matters because
Smart App Control blocks those on the team's machines (CLAUDE.md §5).

**What this deployment deliberately accepts.** The demo credentials stay, so a
judge can follow a link and sign in without being handed a password. That is a
choice, not an oversight: it means anyone who finds the URL can sign in and
upload a capture. The data is synthetic, the parser is pure Python with no
`eval` and no untrusted deserialisation, and the realistic worst case is
resource abuse rather than compromise. The mitigations below are sized for that
threat and no larger:

* uploads are capped and the oldest jobs are pruned, so disk cannot grow without
  bound;
* `/login` is rate-limited per address, so the known password cannot be used to
  hammer the box;
* cookies are `Secure` behind TLS and the app trusts only the proxy headers the
  platform actually sets.

Set `SMS_ADMIN_PASSWORD` to turn the open demo into a private one; the seeder
uses it instead of the default and `/api/health` reports which mode is running.
"""

from __future__ import annotations

import os
import time
from collections import deque
from pathlib import Path

#: Keep at most this many completed jobs; older uploads and reports are pruned.
MAX_JOBS = int(os.environ.get("SMS_MAX_JOBS", "40"))
#: Uploads are capped well below the local 200 MB: a demo capture is kilobytes.
MAX_UPLOAD_BYTES = int(os.environ.get("SMS_MAX_UPLOAD", str(25 * 1024 * 1024)))
#: Failed logins allowed per address per window, and the window in seconds.
LOGIN_ATTEMPTS = int(os.environ.get("SMS_LOGIN_ATTEMPTS", "20"))
LOGIN_WINDOW = int(os.environ.get("SMS_LOGIN_WINDOW", "300"))


def _client_address(request) -> str:
    """The caller's address, trusting `X-Forwarded-For` only one hop.

    Render and Railway both terminate TLS and forward; taking the left-most
    entry of a header the client can forge would let anyone reset their own
    rate-limit bucket, so take the *last* hop the proxy appended.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.remote_addr or "unknown"


def harden(app) -> None:
    """Apply the deployment-only settings to an app built by `create_app`."""
    from flask import jsonify, request

    behind_tls = os.environ.get("SMS_BEHIND_TLS", "1") != "0"
    app.config.update(
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
        SESSION_COOKIE_SECURE=behind_tls,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PREFERRED_URL_SCHEME="https" if behind_tls else "http",
    )

    # -- login rate limit ---------------------------------------------------
    attempts: dict[str, deque] = {}

    @app.before_request
    def _throttle_login():
        if request.path != "/login" or request.method != "POST":
            return None
        now = time.time()
        bucket = attempts.setdefault(_client_address(request), deque())
        while bucket and now - bucket[0] > LOGIN_WINDOW:
            bucket.popleft()
        if len(bucket) >= LOGIN_ATTEMPTS:
            retry = int(LOGIN_WINDOW - (now - bucket[0]))
            return ("Too many sign-in attempts. Try again in "
                    f"{max(retry, 1)} seconds.", 429)
        bucket.append(now)
        return None

    # -- a friendlier error than Flask's default for an oversized upload ----
    @app.errorhandler(413)
    def _too_large(_):
        return jsonify(
            error=f"capture too large; this deployment accepts "
                  f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB. "
                  f"The bundled captures are a few kilobytes each.",
        ), 413

    # -- report the deployment's posture honestly ---------------------------
    @app.get("/api/deployment")
    def _deployment():
        return jsonify(
            server="waitress",
            behind_tls=behind_tls,
            demo_credentials=not os.environ.get("SMS_ADMIN_PASSWORD"),
            max_upload_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
            max_jobs=MAX_JOBS,
            login_attempts_per_window=LOGIN_ATTEMPTS,
        )


def prune(db_path: Path, uploads: Path, keep: int = MAX_JOBS) -> int:
    """Drop the oldest jobs beyond `keep`, and their uploaded captures.

    Ephemeral disk on a free tier is small and an upload endpoint fills it.
    Returns how many were removed.
    """
    import sqlite3

    if not db_path.exists():
        return 0
    removed = 0
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT job_id FROM jobs ORDER BY created_at DESC").fetchall()
        for row in rows[keep:]:
            job_id = row["job_id"]
            conn.execute("DELETE FROM jobs WHERE job_id=?", (job_id,))
            conn.execute("DELETE FROM reports WHERE job_id=?", (job_id,))
            stale = uploads / f"{job_id}.pcap"
            if stale.exists():
                stale.unlink()
            removed += 1
        conn.commit()
    return removed


def seed(app, db_path: Path) -> None:
    """Analyse the bundled captures so a fresh container is not an empty shell.

    A judge following a link to "No capture analysed yet" has learned nothing
    about the tool. Free tiers restart on idle and the disk is ephemeral, so
    this runs on every boot and is cheap because it is skipped when the work is
    already there.

    Two captures, not one: `fleet.pcap` and `fleet_later.pcap` are the same
    estate a fortnight apart, which is what makes the Posture Drift view show
    anything (USP-10).
    """
    from ..store import Store

    store = Store(db_path)
    completed = [j for j in store.list_jobs() if j.state.value == "completed"]
    if len(completed) >= 2:
        return

    root = Path(__file__).resolve().parents[2]
    client = app.test_client()
    app.config["AUTH_DISABLED"] = True          # seeding is not a user action
    try:
        for name in ("fleet.pcap", "fleet_later.pcap"):
            if not (root / "testbed" / "out" / name).exists():
                continue
            if any(j.filename == name for j in completed):
                continue
            response = client.post(f"/api/samples/{name}/analyse")
            if response.status_code != 202:
                continue
            job_id = response.get_json()["job_id"]
            for _ in range(1800):               # the analysis runs in a thread
                state = store.get_job(job_id)
                if state and state.state.value in ("completed", "failed", "rejected"):
                    break
                time.sleep(0.1)
    finally:
        app.config["AUTH_DISABLED"] = False


def main() -> int:
    from waitress import serve

    from . import create_app

    root = Path(__file__).resolve().parents[2]
    db_path = Path(os.environ.get("SMS_DB", root / "data" / "securemailscope.db"))
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")    # noqa: S104 - a container needs this

    app = create_app(db_path)
    harden(app)

    pruned = prune(db_path, root / "data" / "uploads")
    if pruned:
        print(f"[deploy] pruned {pruned} old job(s)")

    print("[deploy] seeding the bundled captures…")
    seed(app, db_path)

    demo = not os.environ.get("SMS_ADMIN_PASSWORD")
    print(f"[deploy] waitress on {host}:{port}")
    print(f"[deploy] credentials: {'DEMO (publicly known)' if demo else 'from SMS_ADMIN_PASSWORD'}")
    print(f"[deploy] max upload: {MAX_UPLOAD_BYTES // (1024 * 1024)} MB, "
          f"keeping {MAX_JOBS} jobs")

    serve(app, host=host, port=port, threads=8, ident="SecureMailScope")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
