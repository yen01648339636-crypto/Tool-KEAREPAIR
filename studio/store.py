"""SQLite task state and durable, ordered events. Runtime data stays outside the index."""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from uuid import uuid4


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.db = self.directory / "studio.sqlite3"
        with self.connect() as con:
            con.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    status TEXT NOT NULL, case_key TEXT NOT NULL, variant TEXT NOT NULL,
                    title TEXT NOT NULL, error TEXT, validated INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL,
                    at TEXT NOT NULL, stage TEXT NOT NULL, message TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS validations (
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL,
                    candidate_id INTEGER NOT NULL, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL, status TEXT NOT NULL, error TEXT
                );
            """)
            columns = {row[1] for row in con.execute("PRAGMA table_info(tasks)")}
            if "stage" not in columns:
                con.execute("ALTER TABLE tasks ADD COLUMN stage TEXT NOT NULL DEFAULT 'all'")
            if "mode" not in columns:
                con.execute("ALTER TABLE tasks ADD COLUMN mode TEXT NOT NULL DEFAULT 'live'")
            if "deleted_at" not in columns:
                con.execute("ALTER TABLE tasks ADD COLUMN deleted_at TEXT")
            if "automatic" not in columns:
                con.execute("ALTER TABLE tasks ADD COLUMN automatic INTEGER NOT NULL DEFAULT 0")

    def connect(self):
        connection = sqlite3.connect(self.db, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def recover(self):
        with self.connect() as con:
            con.execute("UPDATE validations SET status='interrupted',updated_at=?,error=? WHERE status IN ('queued','running','pausing','paused','cancelling')",
                        (now(), "Service restarted; validation interrupted and saved artifacts retained"))
        for task in self.tasks():
            if task["status"] in ("queued", "running", "pausing", "paused", "cancelling"):
                self.update(task["id"], "interrupted", error="Service restarted; task interrupted. Start a new run; saved artifacts are retained.")
                self.event(task["id"], "interrupted", "Service restarted; artifacts retained without automatically repeating model calls")

    def create(self, case_key, variant, title, *, stage="all", mode="live", automatic=False):
        task_id, stamp = uuid4().hex[:16], now()
        with self.connect() as con:
            con.execute(
                "INSERT INTO tasks(id,created_at,updated_at,status,case_key,variant,title,stage,mode,automatic) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (task_id, stamp, stamp, "queued", case_key, variant, title, stage, mode, int(automatic)),
            )
        self.event(task_id, "queued", "Task queued; waiting for a worker")
        return self.task(task_id)

    def task(self, task_id, *, include_deleted=False):
        with self.connect() as con:
            row = con.execute("SELECT * FROM tasks WHERE id=?" + ("" if include_deleted else " AND deleted_at IS NULL"), (task_id,)).fetchone()
        if row is None:
            raise KeyError(task_id)
        value = dict(row)
        value.pop("deleted_at", None)
        value["validated"] = bool(value["validated"])
        value["automatic"] = bool(value["automatic"])
        return value

    def tasks(self):
        with self.connect() as con:
            rows = con.execute("SELECT * FROM tasks WHERE deleted_at IS NULL ORDER BY created_at DESC").fetchall()
        return [dict({k: row[k] for k in row.keys() if k != "deleted_at"}, validated=bool(row["validated"]), automatic=bool(row["automatic"])) for row in rows]

    def delete(self, task_id):
        """Remove an inactive task from the platform, retaining its saved evidence."""
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            task = con.execute("SELECT status FROM tasks WHERE id=? AND deleted_at IS NULL", (task_id,)).fetchone()
            if task is None:
                raise KeyError(task_id)
            validation = con.execute(
                "SELECT 1 FROM validations WHERE task_id=? AND status IN ('queued','running','pausing','paused','cancelling') LIMIT 1",
                (task_id,),
            ).fetchone()
            if task["status"] in ("queued", "running", "pausing", "paused", "cancelling") or validation:
                raise ValueError("This task is still running. Stop it or wait for it to finish before deleting.")
            con.execute("UPDATE tasks SET deleted_at=? WHERE id=?", (now(), task_id))

    def update(self, task_id, status, *, error=None, validated=False, stage=None):
        with self.connect() as con:
            con.execute(
                "UPDATE tasks SET status=?,updated_at=?,error=?,validated=?,stage=COALESCE(?,stage) WHERE id=?",
                (status, now(), error, int(validated), stage, task_id),
            )

    def event(self, task_id, stage, message):
        with self.connect() as con:
            con.execute(
                "INSERT INTO events(task_id,at,stage,message) VALUES(?,?,?,?)",
                (task_id, now(), stage, message),
            )

    def events(self, task_id, after=0):
        with self.connect() as con:
            rows = con.execute("SELECT * FROM events WHERE task_id=? AND seq>? ORDER BY seq", (task_id, after)).fetchall()
        return [dict(r) for r in rows]

    def create_validation(self, task_id, candidate_id):
        self.task(task_id)
        run_id, stamp = uuid4().hex, now()
        with self.connect() as con:
            con.execute("INSERT INTO validations VALUES(?,?,?,?,?,?,NULL)",
                        (run_id, task_id, candidate_id, stamp, stamp, "queued"))
        return self.validations(task_id)[-1]

    def validations(self, task_id):
        with self.connect() as con:
            rows = con.execute("SELECT * FROM validations WHERE task_id=? ORDER BY created_at,id", (task_id,)).fetchall()
        return [dict(row) for row in rows]

    def update_validation(self, run_id, status, error=None):
        with self.connect() as con:
            con.execute("UPDATE validations SET status=?,updated_at=?,error=? WHERE id=?",
                        (status, now(), error, run_id))

    def run_dir(self, task_id, *, include_deleted=False):
        self.task(task_id, include_deleted=include_deleted)  # Only database-owned identifiers may form filesystem paths.
        return self.directory / "runs" / task_id
