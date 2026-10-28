"""Paced, server-side presentation of a frozen, verified historical run.

Replay has no model/subprocess entry point and never creates experiment results
or validation jobs. Only completed playback milestones are exposed by the API.
"""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
from uuid import uuid4

from utils.experiment_manifest import write_json_atomic
from .catalog import read_json
from .store import now
from .control import ACTIVE

STAGES = ("diagnosis", "retrieval", "repair", "validation")
TIMINGS = dict(diagnosis=15, retrieval=20, repair=10, validation=30)
TIMELINES = {
    "diagnosis": [(0, "Reading saved source"), (4, "Analyzing source"), (9, "Preparing tool evidence and the diagnosis report")],
    "retrieval": [(0, "Generating dual-view queries"), (5, "Preparing both retrieval views"), (10, "Loading data-flow results"),
                  (14, "Loading control-flow results"), (17, "Merging and reranking candidates")],
    "repair": [(0, "Preparing diagnosis and repair examples"), (4, "Loading the verified patch"), (8, "Preparing the code diff")],
    "validation": [(0, "Preparing source"), (6, "Applying the patch"), (9, "Build Check"),
                   (18, "PoC Test"), (24, "Unit Tests")],
}
READY = dict(diagnosis="diagnosis_ready", retrieval="retrieval_ready", repair="patch_ready", validation="completed")


class Replay:
    def __init__(self, engine):
        self.engine, self.store = engine, engine.store
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="kea-replay")
        self.stops = {}
        self.time_scale = 1.0  # Injectable clock scale for isolated tests only.

    def sources(self):
        result = {}
        for task in self.store.tasks():
            if (task.get("mode", "live") == "live" and task["status"] == "completed"
                    and task["validated"] and task["variant"] == "full"
                    and not self.engine.repair_request(task["id"]).get("uploaded_tests")):
                previous = result.get(task["case_key"])
                if previous is None or task["updated_at"] > previous["updated_at"]:
                    result[task["case_key"]] = task
        return result

    def submit_case(self, case_key, variant, *, automatic=True, repair_request=None, source_task_id=None):
        if variant != "full":
            raise ValueError("Replay requires a completed full-framework record. Use live execution for other variants.")
        if source_task_id:
            try:
                # A configured source is retained evidence even after its task-list
                # entry is deleted. Public task/replay endpoints still exclude it.
                source = self.store.task(source_task_id, include_deleted=True)
            except KeyError as exc:
                raise ValueError("The configured saved workflow is unavailable. Restore its successful source run before starting this demo.") from exc
            if source["case_key"] != case_key:
                raise ValueError("The configured saved workflow belongs to a different source target.")
        else:
            source = self.sources().get(case_key)
        if not source:
            raise ValueError("This case has no complete, validated historical run")
        return self.submit(source["id"], automatic=automatic, repair_request=repair_request,
                           include_deleted=bool(source_task_id))

    def _bundle(self, task_id, *, include_deleted=False):
        directory = self.store.run_dir(task_id, include_deleted=include_deleted)
        state = read_json(directory / "replay_state.json", {})
        raw = (directory / "replay_bundle.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != state.get("bundle_hash"):
            raise ValueError("Replay record verification failed. Create a new replay from the original successful task.")
        return json.loads(raw), state

    def _capture(self, task_id, *, include_deleted=False):
        task = self.store.task(task_id, include_deleted=include_deleted)
        if task.get("mode") == "replay":
            return self._bundle(task_id, include_deleted=include_deleted)[0]
        if task["status"] != "completed" or not task["validated"] or task["variant"] != "full":
            raise ValueError("Select a completed, validated full-framework task")
        data = self.engine.detail(task_id, include_deleted=True) if include_deleted else self.engine.detail(task_id)
        if data["diagnosis_issues"] or not data["retrieval"].get("final_exemplars"):
            raise ValueError("The historical record lacks complete diagnosis or retrieved examples, so the full workflow cannot be replayed.")
        pool = data["retrieval"].get("ranking", {}).get("candidates", [])
        if not all(any(h.get("query_view") == view for c in pool for h in c.get("retrieval_hits", []))
                   for view in ("data_flow", "control_flow")):
            raise ValueError("The historical record lacks details for both retrieval views")
        candidate = next((c for c in reversed(data["candidates"])
                          if c.get("patch") and (c.get("validation_result") or {}).get("success")), None)
        if candidate is None:
            raise ValueError("The historical record has no validated patch")
        # Revalidation records were checked by Engine.detail. Native automatic
        # runs must also pass the archive verifier before becoming a replay source.
        if not candidate.get("latest_validation"):
            from utils.metrics import verify_attempt
            case = self.store.run_dir(task_id, include_deleted=include_deleted) / "engine/cases" / task["case_key"].split(":", 1)[1]
            checked = verify_attempt(case, case / "attempts" / str(candidate["candidate_id"]))
            if not checked["success"]:
                raise ValueError("Original validation receipts could not be verified")
            candidate["validation_result"] = checked
        if hashlib.sha256(data["source"].encode("utf-8")).hexdigest() != data["source_hash"]:
            raise ValueError("Historical source snapshot verification failed")
        return self.engine.redact(dict(
            source_task_id=task_id, source_updated_at=task["updated_at"], captured_at=now(),
            case_key=task["case_key"], variant=task["variant"],
            input={key: data[key] for key in ("case_id", "language", "file", "dataset", "source", "source_hash")},
            diagnosis=data["diagnosis_report"], retrieval=data["retrieval"], candidate=candidate,
        ))

    def submit(self, source_task_id, *, automatic=True, repair_request=None, include_deleted=False):
        with self.engine.lock:
            if self.engine.stopping:
                raise ValueError("The service is stopping")
            bundle = self._capture(source_task_id, include_deleted=True) if include_deleted else self._capture(source_task_id)
            source_directory = self.store.run_dir(source_task_id, include_deleted=include_deleted)
            repair_request = deepcopy(repair_request or read_json(source_directory / "repair_request.json", {}) or None)
            if (repair_request or {}).get("uploaded_tests"):
                raise ValueError("Uploaded tests require live execution and cannot reuse historical test results")
            if repair_request:
                source = self.engine.catalog.case(bundle["case_key"])["_source"].read_bytes()
                if hashlib.sha256(source).hexdigest() != bundle["input"]["source_hash"]:
                    raise ValueError("The saved run uses a different source snapshot. Choose live execution for this target.")
            # Submitted presentation inputs have their own frozen copies. They
            # do not replace the inputs covered by the historical test receipts.
            with TemporaryDirectory(prefix="replay-input-", dir=self.store.directory) as staging:
                staged_case = self._stage_test_inputs(repair_request, source_directory, bundle, Path(staging))
                title = (repair_request or {}).get("display_name") or bundle["input"]["case_id"]
                task = self.store.create(bundle["case_key"], bundle["variant"], title,
                                         stage="diagnosis", mode="replay", automatic=automatic)
                directory = self.store.run_dir(task["id"])
                directory.mkdir(parents=True, exist_ok=True)
                if staged_case:
                    (directory / "input").mkdir()
                    staged_case.rename(directory / "input" / staged_case.name)
                if repair_request:
                    write_json_atomic(directory / "repair_request.json", repair_request)
            write_json_atomic(directory / "replay_bundle.json", bundle)
            raw = (directory / "replay_bundle.json").read_bytes()
            state = dict(bundle_hash=hashlib.sha256(raw).hexdigest(), completed_stages=[], stage="diagnosis",
                         phase=0, timings=dict(TIMINGS), sequence=0, execution_id=uuid4().hex)
            state["validation_mode"] = (repair_request or {}).get("validation_mode", "full")
            if state["validation_mode"] == "patch_only":
                state["timings"]["validation"] = 0
            elif state["validation_mode"] == "poc":
                state["timings"]["validation"] = 24
            write_json_atomic(directory / "replay_state.json", state)
            self.store.event(task["id"], "replay", f"Demo replay: using real historical task {bundle['source_task_id']} without model or container calls")
            self._queue(task["id"], "diagnosis", state)
            return self.store.task(task["id"])

    def _stage_test_inputs(self, request, source_directory, bundle, staging):
        submitted = (request or {}).get("submitted_test_inputs", {})
        if not submitted:
            return None
        if request.get("demo_source_task_id") != bundle["source_task_id"]:
            raise ValueError("Submitted presentation inputs require the configured historical workflow.")
        from .uploads import TestInputStore, _write_new
        from utils.validation_inputs import _input_bytes

        inputs = TestInputStore(self.store.directory)
        case = staging / bundle["input"]["case_id"]
        case.mkdir(mode=0o700)
        source_case = source_directory / "input" / case.name
        for kind, item in submitted.items():
            if kind not in {"poc", "unit"} or item.get("kind") != kind:
                raise ValueError("The submitted test input kind is invalid.")
            if item.get("relative_path"):
                # Replay Again reads the previous task snapshot, even if the
                # original temporary upload has since been removed or changed.
                relative = Path(item["relative_path"])
                if (relative.is_absolute() or len(relative.parts) != 3
                        or relative.parts[:2] != (".kea-test-inputs", item["id"])
                        or not relative.name.startswith("input.")):
                    raise ValueError("The submitted test input snapshot path is invalid.")
                content = _input_bytes({**item, "path": str(source_case / relative)})
                destination = case / relative
                destination.parent.mkdir(parents=True, mode=0o700)
                _write_new(destination, content)
                saved = deepcopy(item)
            else:
                saved = inputs.copy_to_case(item["id"], case, kind=kind)
                if any(saved[key] != item[key] for key in ("id", "kind", "filename", "size", "sha256")):
                    raise ValueError("The submitted test input changed before the snapshot was created.")
            saved["execution_status"] = "not_run"
            submitted[kind] = saved
        return case

    def _queue(self, task_id, stage, state):
        self.engine.control.prepare(task_id)
        state.update(stage=stage, phase=0, started_at=now(), updated_at=now(), execution_id=uuid4().hex)
        state["completed_stages"] = [s for s in state["completed_stages"] if STAGES.index(s) < STAGES.index(stage)]
        write_json_atomic(self.store.run_dir(task_id) / "replay_state.json", state)
        self.store.update(task_id, "queued", stage=stage)
        stop = threading.Event()
        self.stops[task_id] = stop
        self.pool.submit(self._run, task_id, stage, state, stop)

    def advance(self, task_id, stage):
        with self.engine.lock:
            task = self.store.task(task_id)
            if self.engine.stopping or task["status"] in ACTIVE:
                raise ValueError("Wait for the current replay stage to finish")
            allowed = {"retrieval": "diagnosis_ready", "repair": "retrieval_ready"}
            retry = task["stage"] == stage and task["status"] in {"cancelled", "interrupted", "failed"}
            if not retry and allowed.get(stage) != task["status"]:
                raise ValueError("Replay in order: diagnosis, retrieval, patch generation, then manual validation.")
            _, state = self._bundle(task_id)
            self._queue(task_id, stage, state)
            return self.store.task(task_id)

    def validate(self, task_id, candidate_id):
        with self.engine.lock:
            task = self.store.task(task_id)
            bundle, state = self._bundle(task_id)
            if self.engine.stopping or task["status"] in ACTIVE or "repair" not in state["completed_stages"]:
                raise ValueError("Finish patch generation replay before starting validation")
            if str(candidate_id) != str(bundle["candidate"]["candidate_id"]):
                raise ValueError("The patch does not match the current replay record")
            self._queue(task_id, "validation", state)
            return dict(task_id=task_id, candidate_id=candidate_id, status="queued", mode="replay")

    def _run(self, task_id, stage, state, stop):
        started, started_at = time.monotonic(), now()

        def wait_until(offset):
            while not stop.is_set():
                with self.engine.lock:
                    paused = self.store.task(task_id)["status"] in {"paused", "pausing"}
                    elapsed = time.monotonic() - started - self.engine.control.elapsed_pause(task_id, started_at)
                    remaining = offset * self.time_scale - elapsed
                    if not paused and remaining <= 0:
                        return True
                stop.wait(.05 if paused else min(.05, max(.001, remaining)))
            return False

        try:
            timeline = TIMELINES[stage][:-1] if stage == "validation" and state.get("validation_mode") == "poc" else TIMELINES[stage]
            for phase, (offset, label) in enumerate(timeline):
                if not wait_until(offset):
                    return
                with self.engine.control.boundary(task_id, stop) as proceed:
                    if not proceed:
                        return
                    state.update(phase=phase, sequence=state["sequence"] + 1, updated_at=now())
                    write_json_atomic(self.store.run_dir(task_id) / "replay_state.json", state)
                    self.store.update(task_id, "running", stage=stage)
                    self.store.event(task_id, "replay", "Replay · " + label)
            if not wait_until(state["timings"][stage]):
                return
            with self.engine.control.boundary(task_id, stop) as proceed:
                if not proceed:
                    return
                state["completed_stages"].append(stage)
                state.update(updated_at=now(), sequence=state["sequence"] + 1)
                write_json_atomic(self.store.run_dir(task_id) / "replay_state.json", state)
                automatic = self.store.task(task_id).get("automatic")
                patch_only_done = stage == "repair" and state.get("validation_mode") == "patch_only"
                if patch_only_done:
                    self.store.update(task_id, "completed", stage=stage, validated=False)
                    self.store.event(task_id, "replay", "Patch and report ready; validation was not requested")
                elif automatic and stage != "validation" and not self.engine.stopping:
                    self.store.event(task_id, "replay", stage.capitalize() + " replay complete; continuing automatically")
                    self._queue(task_id, STAGES[STAGES.index(stage) + 1], state)
                else:
                    self.store.update(task_id, READY[stage], stage=stage, validated=False)
                    self.store.event(task_id, "replay", {
                    "diagnosis": "Diagnosis replay complete. Review the report, then continue to retrieval.",
                    "retrieval": "Retrieval replay complete. Review the examples, then generate a patch.",
                    "repair": "Patch replay complete. Review the diff, then select Validate Patch.",
                    "validation": "Workflow replay complete. Passing results come from saved real validation records.",
                    }[stage])
        except Exception as exc:
            with self.engine.lock:
                if not stop.is_set():
                    self.store.update(task_id, "failed", error=self.engine.redact(str(exc)))
                    self.store.event(task_id, "failed", "Replay interrupted: " + self.engine.redact(str(exc)))
        finally:
            with self.engine.lock:
                if self.stops.get(task_id) is stop:
                    self.stops.pop(task_id, None)
                if self.store.task(task_id)["status"] not in ACTIVE:
                    self.engine.save_report(task_id)

    def cancel(self, task_id):
        with self.engine.lock:
            task = self.store.task(task_id)
            if task["status"] in ACTIVE:
                self.engine.control.cancel(task_id)
                if task_id in self.stops:
                    self.stops[task_id].set()
                self.store.update(task_id, "cancelled")
                self.store.event(task_id, "cancelled", "Replay stopped; original historical records are unchanged")
            return self.store.task(task_id)

    def close(self):
        for stop in list(self.stops.values()):
            stop.set()
        self.pool.shutdown(wait=True, cancel_futures=True)

    def detail(self, task_id):
        # The lock prevents observing a partially committed playback milestone.
        with self.engine.lock:
            task = self.store.task(task_id)
            bundle, state = self._bundle(task_id)
            stage, phase, completed = state["stage"], state["phase"], state["completed_stages"]
            repair_request = self.engine.repair_request(task_id)
            mode = repair_request.get("validation_mode", "full")
            running = task["status"] in ACTIVE
            diagnosis = deepcopy(bundle["diagnosis"]) if "diagnosis" in completed else {}
            retrieval = deepcopy(bundle["retrieval"]) if "retrieval" in completed else {}
            data = dict(**task, **bundle["input"], description="Replay of real historical records",
                        pause=self.engine.control.state(task_id),
                        diagnosis_report=diagnosis, diagnosis_issues=[], facts=diagnosis.get("facts", []),
                        tool_calls=diagnosis.get("tool_calls", []), hypotheses=diagnosis.get("hypotheses", []),
                        limitations=diagnosis.get("limitations", []), root_causes=diagnosis.get("root_causes_by_view", {}),
                        retrieval=retrieval, exemplars=retrieval.get("final_exemplars", []), candidates=[],
                        retrieval_progress={}, validation_runs=[], source_preflight={}, source_snapshot_stale=False,
                        repair_request=repair_request,
                        result={"success": False, "mode": "replay", "historical_success": "validation" in completed},
                        replay=dict(source_task_id=bundle["source_task_id"], source_updated_at=bundle["source_updated_at"],
                                    timings=state["timings"], total_seconds=sum(state["timings"].values()),
                                    submitted_test_inputs_executed=False,
                                    completed_stages=list(completed), bundle_hash=state["bundle_hash"]))
            label = TIMELINES[stage][phase][1]
            progress = dict(step=stage, replay_label="Replay · " + label, status="running" if running else "completed",
                            started_at=state["started_at"], updated_at=state["updated_at"],
                            step_started_at=state["updated_at"],
                            sequence=state["sequence"], execution_id=state["execution_id"])
            data["runtime"] = dict(execution_id=state["execution_id"], progress=progress)
            if stage == "diagnosis" and "diagnosis" not in completed and phase >= 2:
                data["facts"] = deepcopy(bundle["diagnosis"].get("facts", []))
                data["tool_calls"] = deepcopy(bundle["diagnosis"].get("tool_calls", []))
            if stage == "retrieval" and "retrieval" not in completed:
                views = ["data_flow", "control_flow"][:max(0, min(2, phase - 1))]
                pool = []
                for original in bundle["retrieval"]["ranking"]["candidates"]:
                    hits = [h for h in original.get("retrieval_hits", []) if h["query_view"] in views]
                    if hits:
                        c = deepcopy(original)
                        c["retrieval_hits"] = hits
                        for key in ("rerank_score", "code_cosine", "bm25_score", "normalized_bm25", "selection_rank", "presentation_rank"):
                            c.pop(key, None)
                        pool.append(c)
                data["retrieval_progress"] = dict(queries=deepcopy(bundle["retrieval"]["queries"]) if phase >= 1 else {},
                    candidates=pool, completed_views=views, status="running" if running else "failed",
                    step="reranking" if phase >= 4 else "retrieval")
            if "repair" in completed:
                original = bundle["candidate"]
                candidate = {key: deepcopy(original[key]) for key in ("candidate_id", "patch", "explanation", "hunk_ranges") if key in original}
                candidate.update(replayed=True, validation_result=None)
                if "validation" in completed:
                    candidate["validation_result"] = self.scoped_validation(original["validation_result"], mode)
                elif stage == "validation":
                    names = ("source_prepare", "patch_apply", "compile", "poc") + (() if mode == "poc" else ("unit",))
                    native = self.scoped_validation(original["validation_result"], mode).get("stage_details", {})
                    states = {name: "passed" if i < phase else "running" if i == phase and running else "not_run"
                              for i, name in enumerate(names)}
                    details = {name: deepcopy(native.get(name, {})) if i < phase else {} for i, name in enumerate(names)}
                    vp = dict(progress, step=names[phase], replay_label="Replay · " + label,
                              candidate_id=str(original["candidate_id"]), running=running,
                              stage_status=states, stage_details=details)
                    candidate["live_validation_progress"] = vp
                    data["runtime"]["validation_progress"] = vp
                data["candidates"] = [candidate]
            data["events"] = self.store.events(task_id)
            return self.engine.redact(data)

    @staticmethod
    def scoped_validation(original, mode):
        from utils.validation_scope import decorate_validation
        value = deepcopy(original)
        if mode == "poc":
            # The selected historical checks are evidence for this scope only.
            value["historical_validation_hash"] = hashlib.sha256(json.dumps(original, sort_keys=True).encode()).hexdigest()
            value["success"] = False
            value["unit_status"], value["unit_pass"] = "not_run", False
            value.setdefault("stage_status", {})["unit"] = "not_run"
            value.setdefault("stage_details", {}).pop("unit", None)
            value.pop("artifacts", None)
            preparation = value["stage_details"].get("source_prepare", {})
            steps = preparation.get("steps", [])
            if steps:
                selected = [s for s in steps if "unit" not in s.get("declared_covers", []) and s.get("step") != "unit"]
                preparation["steps"] = selected
                preparation["duration_seconds"] = sum(float(s.get("duration_seconds") or 0) for s in selected)
            value["scope_note"] = "Selected build and PoC checks from the historical run; unit tests were not requested."
        return decorate_validation(value, mode) if mode != "full" else value
