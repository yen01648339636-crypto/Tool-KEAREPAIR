"""Durable pause requests shared by live workers and historical playback."""

from contextlib import contextmanager
from datetime import datetime
import time
from uuid import uuid4

from utils.experiment_manifest import write_json_atomic
from .catalog import read_json
from .store import now

PAUSED = {"pausing", "paused"}
ACTIVE = {"queued", "running", "pausing", "paused", "cancelling"}


class TaskControl:
    def __init__(self, engine):
        self.engine, self.store = engine, engine.store

    def path(self, task_id):
        return self.store.run_dir(task_id) / "task_control.json"

    def state(self, task_id):
        return read_json(self.path(task_id), {"intervals": []})

    def save(self, task_id, state):
        write_json_atomic(self.path(task_id), state)

    def prepare(self, task_id):
        state = self.state(task_id)
        self._end_interval(state)
        state.update(requested=False, cancelled=False, paused_at=None)
        self.save(task_id, state)

    def _status(self, task_id, status):
        task = self.store.task(task_id)
        self.store.update(task_id, status, validated=task["validated"])
        if task["stage"] == "validation":
            for job in self.store.validations(task_id):
                if job["status"] in ACTIVE:
                    self.store.update_validation(job["id"], status)

    def pause(self, task_id):
        with self.engine.lock:
            task = self.store.task(task_id)
            if task["status"] in PAUSED:
                return task
            if self.engine.stopping or task["status"] not in {"queued", "running"}:
                raise ValueError("Only a queued or running task can be paused")
            state = self.state(task_id)
            state.update(requested=True, cancelled=False, request_id=uuid4().hex,
                         requested_at=now(), paused_at=None, resume_status=task["status"])
            self.save(task_id, state)
            if task.get("mode") == "replay" or task_id not in self.engine.processes:
                self._acknowledge(task_id, state, now())
            else:
                self._status(task_id, "pausing")
                self.store.event(task_id, "pausing", "Pause requested; finishing the current operation before pausing")
            return self.store.task(task_id)

    def _acknowledge(self, task_id, state, stamp):
        if state.get("paused_at"):
            return
        state["paused_at"] = stamp
        state.setdefault("intervals", []).append({"started_at": stamp, "finished_at": None})
        self.save(task_id, state)
        self._status(task_id, "paused")
        self.store.event(task_id, "paused", "Execution paused; select Resume to continue from this point")

    def observe(self, task_id):
        with self.engine.lock:
            if self.store.task(task_id)["status"] != "pausing":
                return
            state = self.state(task_id)
            ack = read_json(self.path(task_id).with_name("pause_ack.json"), {})
            execution = read_json(self.path(task_id).with_name("runtime_execution.json"), {})
            if ack.get("request_id") == state.get("request_id") and ack.get("execution_id") == execution.get("execution_id"):
                self._acknowledge(task_id, state, ack["paused_at"])

    def resume(self, task_id):
        with self.engine.lock:
            task = self.store.task(task_id)
            if task["status"] in {"queued", "running"}:
                return task
            if self.engine.stopping or task["status"] not in PAUSED:
                raise ValueError("Only a paused task can be resumed")
            self.observe(task_id)
            state = self.state(task_id)
            self._end_interval(state)
            state.update(requested=False, paused_at=None)
            self.save(task_id, state)
            self._status(task_id, state.get("resume_status", "running"))
            self.store.event(task_id, "resumed", "Execution resumed from the paused position")
            return self.store.task(task_id)

    @staticmethod
    def _end_interval(state):
        if state.get("intervals") and state["intervals"][-1].get("finished_at") is None:
            state["intervals"][-1]["finished_at"] = now()

    def cancel(self, task_id):
        state = self.state(task_id)
        self._end_interval(state)
        state.update(requested=False, cancelled=True, paused_at=None)
        self.save(task_id, state)

    def elapsed_pause(self, task_id, since=None):
        end = time.time()
        start = datetime.fromisoformat(since).timestamp() if since else 0
        return sum(max(0, (datetime.fromisoformat(i["finished_at"]).timestamp() if i.get("finished_at") else end)
                       - max(start, datetime.fromisoformat(i["started_at"]).timestamp()))
                   for i in self.state(task_id).get("intervals", []))

    @contextmanager
    def boundary(self, task_id, stop=None):
        """Wait before starting/committing an operation and hold the engine lock during it."""
        while True:
            with self.engine.lock:
                try:
                    task = self.store.task(task_id)
                except KeyError:
                    yield False
                    return
                if self.engine.stopping or (stop and stop.is_set()) or task["status"] in {"cancelled", "cancelling", "interrupted"}:
                    if task["status"] == "cancelling":
                        self._status(task_id, "cancelled")
                    yield False
                    return
                if task["status"] == "pausing":
                    # Called at a parent-side boundary after the current subprocess has ended.
                    self._acknowledge(task_id, self.state(task_id), now())
                elif task["status"] != "paused":
                    yield True
                    return
            if stop:
                stop.wait(.05)
            else:
                time.sleep(.05)
