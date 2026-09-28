"""Authentication for the console. Stdlib only.

Passwords are PBKDF2-HMAC-SHA256 with a per-user salt, via `hashlib` — no
dependency, and not reversible. This is a hackathon MVP, not an identity
provider: there is no password reset, no MFA, no lockout. What it does provide
is a real credential check, a signed session cookie, and an actor name on every
audit event, which is what the SECURITY ADMIN lane in the workflow needs
(ADR-0022).

Seeded with two demo accounts on first run so the console is usable
immediately. Both are printed once at startup; change them before this is ever
exposed to a network.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

ITERATIONS = 240_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    display_name TEXT,
    role TEXT,
    salt BLOB,
    hash BLOB,
    created_at TEXT,
    last_login TEXT
);
"""

#: Seeded on first run. Analyst can triage; admin can also finalise a posture.
DEMO_USERS = [
    ("analyst", "Analyst", "analyst", "analyst123"),
    ("admin", "SOC Manager", "admin", "admin123"),
]


@dataclass
class User:
    username: str
    display_name: str
    role: str

    @property
    def initials(self) -> str:
        parts = self.display_name.split()
        return "".join(p[0] for p in parts[:2]).upper() or self.username[:2].upper()

    @property
    def can_finalise(self) -> bool:
        """Finalising a posture is a sign-off, so it is an admin action."""
        return self.role == "admin"


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)


class UserStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)
        self.seed()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def seed(self) -> list[tuple[str, str]]:
        """Create the demo accounts if the table is empty. Returns what it made."""
        created: list[tuple[str, str]] = []
        with self._connect() as conn:
            existing = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
            if existing:
                return created
            for username, display, role, password in DEMO_USERS:
                salt = os.urandom(16)
                conn.execute(
                    "INSERT INTO users (username, display_name, role, salt, hash, "
                    "created_at) VALUES (?,?,?,?,?,?)",
                    (username, display, role, salt, _hash(password, salt),
                     datetime.now(tz=timezone.utc).isoformat()))
                created.append((username, password))
            conn.commit()
        return created

    def verify(self, username: str, password: str) -> User | None:
        """Check a credential. Constant-time compare, and no distinction in the
        caller between 'no such user' and 'wrong password'."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username=?",
                               (username.strip().lower(),)).fetchone()
            if row is None:
                # Spend the time anyway so a missing user is not faster to probe.
                _hash(password, b"0" * 16)
                return None
            if not hmac.compare_digest(_hash(password, row["salt"]), row["hash"]):
                return None
            conn.execute("UPDATE users SET last_login=? WHERE username=?",
                         (datetime.now(tz=timezone.utc).isoformat(), row["username"]))
            conn.commit()
            return User(row["username"], row["display_name"] or row["username"],
                        row["role"] or "analyst")

    def get(self, username: str) -> User | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username=?",
                               (username,)).fetchone()
        return User(row["username"], row["display_name"] or row["username"],
                    row["role"] or "analyst") if row else None

    def list_users(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT username, display_name, role, created_at, last_login "
                "FROM users ORDER BY username").fetchall()
        return [dict(r) for r in rows]


def login_required(view):
    """Guard a route. Disabled under TESTING so the API tests stay hermetic."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        from flask import current_app, jsonify, redirect, request, session

        if current_app.config.get("AUTH_DISABLED") or current_app.config.get("TESTING"):
            return view(*args, **kwargs)
        if session.get("user"):
            return view(*args, **kwargs)
        if request.path.startswith("/api/"):
            return jsonify(error="authentication required"), 401
        return redirect("/login")
    return wrapper


def current_user(store: UserStore):
    from flask import current_app, session

    username = session.get("user")
    if username:
        return store.get(username)
    if current_app.config.get("AUTH_DISABLED") or current_app.config.get("TESTING"):
        return User("analyst", "Analyst", "analyst")
    return None
