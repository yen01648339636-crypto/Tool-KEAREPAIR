"""Atomic, invocation-bound UI telemetry, separate from experiment results.

These snapshots are observations only. They are never inputs to diagnosis,
retrieval, ranking, sampling, or validation.
"""

from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from copy import deepcopy
import os
from pathlib import Path
import time

from utils.experiment_manifest import write_json_atomic
from utils.telemetry import utc_now
from utils.execution_control import active_monotonic, wait_if_paused


_ACTIVE = ContextVar("runtime_progress", default=None)


class RuntimeProgress:
    """Describe actual boundaries and measured durations of one CLI invocation."""

    def __init__(self, path, *, stage="all", run_id=None, execution_id=None):
        self.path = Path(path)
        self.started_monotonic = active_monotonic()
        self.step_monotonic = self.started_monotonic
        stamp = utc_now()
        self.value = dict(
            schema_version=1,
            execution_id=execution_id or os.environ.get("KEA_STUDIO_EXECUTION_ID") or run_id,
            run_id=run_id,
            stage=stage,
            step="initializing",
            status="running",
            started_at=stamp,
            step_started_at=stamp,
            updated_at=stamp,
            elapsed_seconds=0.0,
            total_elapsed_seconds=0.0,
            sequence=0,
            history=[],
        )
        self._write()

    @contextmanager
    def activate(self):
        token = _ACTIVE.set(self)
        try:
            yield self
        finally:
            _ACTIVE.reset(token)

    def _write(self):
        now = active_monotonic()
        self.value.update(
            updated_at=utc_now(),
            elapsed_seconds=(max(0.0, now - self.step_monotonic)
                             if self.value["status"] == "running"
                             else self.value["elapsed_seconds"]),
            total_elapsed_seconds=max(0.0, now - self.started_monotonic),
            sequence=self.value["sequence"] + 1,
        )
        write_json_atomic(self.path, self.value)

    def _end_step(self, error=None):
        self.value["elapsed_seconds"] = max(0.0, active_monotonic() - self.step_monotonic)
        self.value["status"] = "failed" if error is not None else "completed"
        if error is not None:
            self.value["error"] = str(error)
        self._write()

        entry = deepcopy({
            key: self.value[key]
            for key in ("stage", "step", "status", "step_started_at", "updated_at",
                        "elapsed_seconds", "case_id", "error")
            if key in self.value
        })
        entry["started_at"] = entry["step_started_at"]
        self.value["history"].append(entry)
        # Keep the just-completed step in the same atomic snapshot as its history.
        self._write()

    def activity(self, label, status, **fields):
        """Public operational milestones only: never publish model reasoning."""
        record = dict(label=label, status=status, at=utc_now(),
                      sequence=self.value.get("activity_sequence", 0) + 1, **fields)
        self.value["activity_sequence"] = record["sequence"]
        self.value["activity"] = record
        self.value.setdefault("activity_history", []).append(record)
        self.value["activity_history"] = self.value["activity_history"][-200:]
        self._write()

    @contextmanager
    def step(self, stage, step, case_id=None):
        wait_if_paused()
        self.step_monotonic = active_monotonic()
        self.value.update(stage=stage, step=step, status="running", step_started_at=utc_now())
        self.value.pop("error", None)
        self.value.pop("case_id", None)
        self.value.pop("activity", None)
        if case_id is not None:
            self.value["case_id"] = case_id
        self._write()
        try:
            yield
        except BaseException as exc:
            self._end_step(exc)
            raise
        else:
            self._end_step()

    def finish(self, error=None):
        """Finalize even errors outside an instrumented step, including startup."""
        if self.value["status"] == "running":
            self.value["elapsed_seconds"] = max(0.0, active_monotonic() - self.step_monotonic)
        self.value["status"] = "failed" if error is not None else "completed"
        if error is not None:
            self.value["error"] = str(error)
        self._write()


def progress_step(stage, step, case_id=None):
    active = _ACTIVE.get()
    return active.step(stage, step, case_id) if active is not None else nullcontext()


def progress_event(label, status="completed", **fields):
    if status == "running":
        wait_if_paused()
    active = _ACTIVE.get()
    if active is not None:
        active.activity(label, status, **fields)


@contextmanager
def progress_activity(label, **fields):
    progress_event(label, "running", **fields)
    try:
        yield
    except BaseException:
        progress_event(label, "failed", **fields)
        raise
    else:
        progress_event(label, "completed", **fields)


class RetrievalProgress:
    """Unranked intermediate snapshots; never substitute for retrieval.json."""

    def __init__(self, path, *, run_id, experiment_id, source_hash, diagnosis_hash):
        active = _ACTIVE.get()
        stamp = utc_now()
        self.path = Path(path)
        self.value = dict(
            schema_version=1,
            execution_id=(active.value["execution_id"] if active is not None else
                          os.environ.get("KEA_STUDIO_EXECUTION_ID") or run_id),
            run_id=run_id,
            experiment_id=experiment_id,
            source_hash=source_hash,
            diagnosis_hash=diagnosis_hash,
            started_at=stamp,
            updated_at=stamp,
            sequence=0,
            status="running",
            step="query_generation",
            queries={},
            candidates=[],
            completed_views=[],
        )
        self.update()

    def update(self, **fields):
        self.value.update(deepcopy(fields))
        self.value.update(updated_at=utc_now(), sequence=self.value["sequence"] + 1)
        write_json_atomic(self.path, self.value)

    def __enter__(self):
        return self

    def __exit__(self, error_type, error, traceback):
        if error is not None:
            self.update(status="failed", error=str(error))
        return False
