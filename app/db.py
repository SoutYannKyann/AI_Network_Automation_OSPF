"""SQLite persistence (single file, WAL). Tables: projects, configs, approvals, jobs, events, audit."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path

from .models import utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects(
  id TEXT PRIMARY KEY, created_at TEXT, image_path TEXT, notes TEXT,
  extraction TEXT, discovery TEXT DEFAULT '{}', reachability TEXT, validation TEXT);
CREATE TABLE IF NOT EXISTS configs(
  id TEXT PRIMARY KEY, project_id TEXT, device TEXT, role TEXT, text TEXT, sha256 TEXT,
  deployable INTEGER, verification_cmds TEXT, expect TEXT, created_at TEXT, superseded INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS approvals(
  id TEXT PRIMARY KEY, config_id TEXT, device TEXT, sha256 TEXT, approver TEXT, approved_at TEXT,
  token TEXT, revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS jobs(
  id TEXT PRIMARY KEY, project_id TEXT, batch_id TEXT, device TEXT, job_type TEXT, status TEXT,
  config_id TEXT, approval_id TEXT, created_at TEXT, started_at TEXT, finished_at TEXT,
  message TEXT, error_kind TEXT, output TEXT, verification TEXT, applied_lines TEXT,
  rolled_back INTEGER DEFAULT 0, noop INTEGER DEFAULT 0, worker TEXT, kafka_message TEXT);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, ts TEXT, status TEXT, message TEXT);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, project_id TEXT,
  job_id TEXT, detail TEXT);
"""


def new_id() -> str:
    return uuid.uuid4().hex


class DB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.lock = threading.RLock()

    def q(self, sql: str, *args) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql: str, *args) -> dict | None:
        rows = self.q(sql, *args)
        return rows[0] if rows else None

    def x(self, sql: str, *args) -> int:
        with self.lock:
            return self.conn.execute(sql, args).rowcount

    def audit(self, actor: str, action: str, project_id: str | None = None, job_id: str | None = None,
              detail: dict | str | None = None) -> None:
        self.x("INSERT INTO audit(ts,actor,action,project_id,job_id,detail) VALUES(?,?,?,?,?,?)",
               utcnow(), actor, action, project_id, job_id,
               json.dumps(detail) if isinstance(detail, (dict, list)) else (detail or ""))

    def claim_job(self, job_id: str, lease_seconds: int) -> bool:
        """Atomic PENDING -> RUNNING (or reclaim a RUNNING job whose lease expired)."""
        from datetime import datetime, timedelta, timezone
        stale = (datetime.now(timezone.utc) - timedelta(seconds=lease_seconds)).isoformat(timespec="seconds")
        with self.lock:
            cur = self.conn.execute(
                "UPDATE jobs SET status='RUNNING', started_at=? WHERE id=? AND "
                "(status='PENDING' OR (status='RUNNING' AND started_at < ?))", (utcnow(), job_id, stale))
            return cur.rowcount == 1
