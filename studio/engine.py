"""Subprocess adapter to the existing CLI; no changes to repair algorithms."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from uuid import uuid4

from utils.experiment_manifest import write_json_atomic
from .store import now
from .runtime import task_runtime, STEP_LABELS

from .catalog import read_json
from utils.diagnosis_readiness import diagnosis_issues
from .control import ACTIVE, TaskControl



class Engine:
    def __init__(self, root, store, catalog, config):
        self.root, self.store, self.catalog = Path(root), store, catalog
        self.config = Path(config).resolve()
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="kea-studio")
        self.lock = threading.RLock()
        self.processes = {}
        self.stopping = False
        self.secrets = set()
        self.control = TaskControl(self)
        from .replay import Replay
        self.replay = Replay(self)

    def public_config(self):
        from config.runtime import load_config
        from dotenv import dotenv_values
        config = load_config(self.config)
        llm = config["models"]["llm"]
        env = {**dotenv_values(self.root / ".env"), **os.environ}
        key_name = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "gemini": "GOOGLE_API_KEY"}.get(llm["provider"], "")
        key = llm.get("api_key") or env.get(key_name) or (env.get("GEMINI_API_KEY") if llm["provider"] == "gemini" else None)
        for secret in (key, llm.get("api_key"), *(env.get(k) for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"))):
            if isinstance(secret, str) and len(secret) > 5:
                self.secrets.add(secret)
        return {
            "provider": llm["provider"], "model": llm["model_name"],
            "key_configured": bool(key),
            "execution_mode": config["online"]["phase3_repair"]["validation"]["execution_mode"],
            "max_iterations": config["online"]["phase3_repair"]["max_iterations"],
            "docker_installed": shutil.which("docker") is not None,
            "config_file": str(self.config.relative_to(self.root)) if self.config.is_relative_to(self.root) else self.config.name,
            "worker_count": 1,
        }

    def redact(self, value):
        if isinstance(value, dict):
            return {
                k: "[redacted]" if re.search(r"api.?key|authorization|access.?token|secret", str(k), re.I)
                else self.redact(v) for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.redact(v) for v in value]
        if isinstance(value, str):
            for secret in self.secrets:
                value = value.replace(secret, "[redacted]")
            return re.sub(r"sk-[A-Za-z0-9_-]{16,}", "[redacted]", value)
        return value

    def preflight(self, stage="diagnosis"):
        if stage == "validation":
            return [] if shutil.which("docker") else ["Docker was not found"]
        config = self.public_config()
        issues = []
        if not config["key_configured"]:
            issues.append("The online model has no API key. Check config/online.yaml or the project .env.")
        if stage == "repair" and config["execution_mode"] != "docker":
            issues.append("KeaRepair requires Docker validation. Set execution_mode to docker.")
        if stage == "repair" and not config["docker_installed"]:
            issues.append("Docker was not found")
        if stage == "retrieval" and not self.catalog.knowledge_summary()["ready"]:
            issues.append("Dual-view knowledge indexes are unavailable")
        return issues

    def submit(self, case_key, variant, *, automatic=True, repair_request=None):
        if self.stopping:
            raise ValueError("The service is stopping")
        issues = self.preflight()
        if issues:
            raise ValueError("; ".join(issues))
        case = self.catalog.case(case_key)
        title = (repair_request or {}).get("display_name") or case["case_id"]
        task = self.store.create(case_key, variant, title, stage="diagnosis", automatic=automatic)
        directory = self.store.run_dir(task["id"])
        case_dir = directory / "input" / case["case_id"]
        try:
            if repair_request is not None:
                write_json_atomic(directory / "repair_request.json", repair_request)
            source = case["_source"]
            target = case_dir / source.relative_to(case["_directory"])
            target.parent.mkdir(parents=True, exist_ok=True)
            raw_source = source.read_bytes()
            source_text = raw_source.decode("utf-8")
            target.write_bytes(raw_source)
            for name in ("test_cmds.json", "case_meta.json", "source_baseline.json"):
                item = case["_directory"] / name
                if item.is_file() and not item.is_symlink():
                    shutil.copyfile(item, case_dir / name)
            if repair_request is not None:
                from utils.validation_scope import scope_commands
                commands = scope_commands(read_json(case_dir / "test_cmds.json", {}), repair_request["validation_mode"])
                if repair_request.get("uploaded_tests"):
                    from .uploads import TestInputStore
                    from utils.validation_inputs import prepare_uploaded_commands
                    uploads, descriptors = TestInputStore(self.store.directory), {}
                    for kind, item in repair_request["uploaded_tests"].items():
                        saved = uploads.copy_to_case(item["id"], case_dir, kind=kind)
                        if saved["sha256"] != item["sha256"]:
                            raise ValueError("The uploaded test changed before the task snapshot was created")
                        repair_request["uploaded_tests"][kind] = saved
                        descriptors[kind] = {**saved, "path": str((case_dir / saved["relative_path"]).resolve())}
                    commands = prepare_uploaded_commands(commands, descriptors)
                    write_json_atomic(directory / "repair_request.json", repair_request)
                write_json_atomic(case_dir / "test_cmds.json", commands)
            # Explicit source path keeps CLI validation aligned with the selected snapshot.
            inputs = {
                "case_id": case["case_id"], "language": case["language"],
                "file": case["file"], "dataset": case["dataset"],
                "source": source_text,
                "source_hash": hashlib.sha256(raw_source).hexdigest(),
            }
            (directory / "input.json").write_text(json.dumps(inputs, ensure_ascii=False), encoding="utf-8")
        except Exception as exc:
            self.store.update(task["id"], "failed", error=str(exc))
            raise
        self.pool.submit(self.run, task["id"], case_dir)
        return task

    def command(self, task, case_dir):
        # Pin all stages of a repair to the same immutable knowledge generation.
        directory = self.store.run_dir(task["id"])
        snapshot_path = directory / "knowledge_index.json"
        snapshot = read_json(snapshot_path)
        if snapshot is None:
            previous = read_json(directory / "engine/manifest.json", {})
            selected = previous.get("parameters", {}).get("indices_dir") or str(self.catalog.indices)
            snapshot = {"directory": selected}
            write_json_atomic(snapshot_path, snapshot)
        return [
            sys.executable, "-u", str(self.root / "scripts/run_online.py"),
            "--config", str(self.config), "--vul-files-dir", str(case_dir),
            "--indices-dir", snapshot["directory"], "--index-snapshot", "--output-dir",
            str(self.store.run_dir(task["id"]) / "engine"),
            "--variant", task["variant"],
            "--stage", task.get("stage", "all"),
            "--studio-stage",
            *(["--defer-validation"] if task.get("stage") == "repair" and (not task.get("automatic") or self.repair_request(task["id"]).get("validation_mode") == "patch_only") else []),
        ]

    def repair_request(self, task_id):
        return read_json(self.store.run_dir(task_id) / "repair_request.json", {})

    def task_preflight(self, task_id, stage):
        if stage == "repair" and self.repair_request(task_id).get("validation_mode") == "patch_only":
            stage = "diagnosis"  # The patch-only plan needs the model, without container tests.
        return self.preflight(stage)

    def continue_automatically(self, task, completed_status, case_dir):
        """Commit the next active stage without exposing a manual review boundary."""
        if not task.get("automatic") or self.stopping:
            return False
        stage = {"diagnosis_ready": "repair" if task["variant"] == "no_retrieval" else "retrieval",
                 "retrieval_ready": "repair"}.get(completed_status)
        if not stage:
            return False
        # Archive each invocation before the next one replaces progress.json.
        self.archive_runtime(task["id"])
        issues = self.task_preflight(task["id"], stage)
        if issues:
            self.store.update(task["id"], "failed", stage=stage, error="; ".join(issues))
            self.store.event(task["id"], "failed", "; ".join(issues))
            return True
        self.store.update(task["id"], "queued", stage=stage)
        self.store.event(task["id"], "workflow", "Diagnosis complete; continuing to " + stage if completed_status == "diagnosis_ready"
                         else "Retrieval and reranking complete; generating and validating patches automatically")
        self.pool.submit(self.run, task["id"], case_dir)
        return True

    def archive_runtime(self, task_id):
        directory = self.store.run_dir(task_id)
        task = self.store.task(task_id)
        runtime, _ = task_runtime(directory, task, read_json(directory / "input.json", {}))
        if runtime.get("execution_id"):
            write_json_atomic(directory / "runtime_history" / (runtime["execution_id"] + ".json"), runtime)

    def save_report(self, task_id):
        from .report import build_report, render_report
        directory = self.store.run_dir(task_id)
        report = build_report(self.detail(task_id))
        write_json_atomic(directory / "repair_report.json", report)
        (directory / "repair_report.html").write_text(render_report(report), encoding="utf-8")

    def finish_report(self, task_id):
        try:
            task = self.store.task(task_id)
        except KeyError:
            return  # A cancelled queued task may already have been removed.
        if task["status"] not in ACTIVE:
            self.archive_runtime(task_id)
            self.save_report(task_id)

    def advance(self, task_id, stage):
        if self.store.task(task_id).get("mode") == "replay":
            return self.replay.advance(task_id, stage)
        with self.lock:
            task = self.store.task(task_id)
            if self.stopping or task["status"] in ACTIVE:
                raise ValueError("The task is running. Wait for the current stage to finish.")
            allowed = {
                "diagnosis": task["stage"] == "diagnosis" and task["status"] in {"diagnosis_incomplete", "failed", "interrupted", "cancelled"},
                "retrieval": task["status"] == "diagnosis_ready" and task["variant"] != "no_retrieval",
                "repair": task["status"] == "retrieval_ready" or (task["status"] == "diagnosis_ready" and task["variant"] == "no_retrieval"),
            }
            # A failed/interrupted stage can be retried without rerunning earlier stages.
            retry = task["stage"] == stage and task["status"] in {"failed", "interrupted", "cancelled"}
            if not (allowed.get(stage) or retry):
                raise ValueError("Continue in order: diagnosis, knowledge retrieval, patch generation, then validation.")
            if stage != "diagnosis":
                detail = self.detail(task_id)
                if detail["diagnosis_issues"]:
                    raise ValueError("; ".join(detail["diagnosis_issues"]))
            issues = self.task_preflight(task_id, stage)
            if issues:
                raise ValueError("; ".join(issues))
            self.store.update(task_id, "queued", stage=stage)
            self.store.event(task_id, "queued", {"diagnosis": "Diagnosis retry queued", "retrieval": "Knowledge retrieval started from the diagnosis report", "repair": "Patch generation and validation queued" if task.get("automatic") else "Patch generation started; manual validation follows review"}[stage])
            directory = self.store.run_dir(task_id) / "input" / task["case_key"].split(":", 1)[1]
            self.pool.submit(self.run, task_id, directory)
            return self.store.task(task_id)

    def validate_candidate(self, task_id, candidate_id):
        if self.repair_request(task_id).get("validation_mode") == "patch_only":
            raise ValueError("This task requested patch generation only. Start a new task with a validation plan to run tests.")
        if self.store.task(task_id).get("mode") == "replay":
            return self.replay.validate(task_id, candidate_id)
        from scripts.validate_saved_patch import load_candidate

        with self.lock:
            task = self.store.task(task_id)
            if self.stopping or task["status"] in ACTIVE:
                raise ValueError("The task is running. Wait for the current stage to finish.")
            case_dir = self.store.run_dir(task_id) / "engine/cases" / task["case_key"].split(":", 1)[1]
            attempt = read_json(case_dir / "attempts" / str(candidate_id) / "attempt.json", {})
            if not isinstance(attempt.get("patch"), str) or not attempt["patch"].strip():
                raise ValueError("This candidate has no valid patch. Select a candidate with a generated patch.")
            source, *_ = load_candidate(case_dir, candidate_id)
            current = self.catalog.case(task["case_key"])["_source"].read_bytes()
            if hashlib.sha256(current).hexdigest() != hashlib.sha256(source.encode("utf-8")).hexdigest():
                raise ValueError("This task uses a different source snapshot from the current case. Create a new task; previous diagnosis and patches are retained.")
            snapshot = read_json(self.store.run_dir(task_id) / "input.json", {})
            if hashlib.sha256(source.encode("utf-8")).hexdigest() != snapshot.get("source_hash"):
                raise ValueError("Candidate source does not match the task snapshot")
            issues = self.preflight("validation")
            if issues:
                raise ValueError("; ".join(issues))
            job = self.store.create_validation(task_id, candidate_id)
            self.store.update(task_id, "queued", stage="validation")
            self.store.event(task_id, "validation", f"Candidate patch {candidate_id} queued for validation")
            self.pool.submit(self.run_validation, task_id, case_dir, job)
            return job

    def validation_dir(self, task_id, job, *, include_deleted=False):
        return self.store.run_dir(task_id, include_deleted=include_deleted) / "validations" / job["id"]

    def validation_command(self, task_id, case_dir, job):
        return [sys.executable, "-u", str(self.root / "scripts/validate_saved_patch.py"),
                "--case-dir", str(case_dir), "--candidate-id", str(job["candidate_id"]),
                "--output-dir", str(self.validation_dir(task_id, job))]

    def checked_validation(self, task_id, case_dir, job, *, include_deleted=False):
        from utils.metrics import verify_attempt

        output = self.validation_dir(task_id, job, include_deleted=include_deleted)
        summary = read_json(output / "revalidation.json", {})
        saved_case = output / "cases" / case_dir.name
        original = (case_dir / "source.original").read_bytes()
        patch = (case_dir / "attempts" / str(job["candidate_id"]) / "effective.patch").read_bytes()
        if (summary.get("status") != "completed"
                or summary.get("operation") != "validation_only"
                or summary.get("original_case_dir") != str(case_dir.resolve())
                or summary.get("candidate_id") != job["candidate_id"]
                or summary.get("source_hash") != hashlib.sha256(original).hexdigest()
                or summary.get("patch_hash") != hashlib.sha256(patch).hexdigest()
                or (saved_case / "source.original").read_bytes() != original
                or (saved_case / "attempts" / str(job["candidate_id"]) / "effective.patch").read_bytes() != patch):
            raise ValueError("Validation artifacts do not match the current candidate patch or source")
        result = verify_attempt(saved_case, saved_case / "attempts" / str(job["candidate_id"]))
        if result["success"] != summary.get("success") or result["stage_status"] != summary.get("stage_status"):
            raise ValueError("The validation report does not match its stage receipts")
        return result

    def start_execution(self, task, *, validation_id=None):
        self.control.prepare(task["id"])
        record = {"execution_id": uuid4().hex, "task_id": task["id"],
                  "stage": task["stage"], "started_at": now()}
        if validation_id:
            record["validation_id"] = validation_id
        write_json_atomic(self.store.run_dir(task["id"]) / "runtime_execution.json", record)
        return {**os.environ, "PYTHONUNBUFFERED": "1", "KEA_STUDIO_EXECUTION_ID": record["execution_id"],
                "KEA_STUDIO_CONTROL": str(self.control.path(task["id"]))}

    def observe_runtime(self, task_id, seen):
        self.control.observe(task_id)
        task = self.store.task(task_id)
        if task["status"] == "paused":
            return
        snapshot = read_json(self.store.run_dir(task_id) / "input.json", {})
        runtime, partial = task_runtime(self.store.run_dir(task_id), task, snapshot)
        for kind, value in (("runtime", runtime.get("progress", {})),
                            ("validation_progress", runtime.get("validation_progress", {})),
                            ("retrieval_progress", partial)):
            if not value:
                continue
            for activity in value.get("activity_history", []):
                identity = ("activity", runtime.get("execution_id"), activity["sequence"])
                if identity not in seen:
                    seen.add(identity)
                    self.store.event(task_id, "agent", self.redact(activity["label"] + " · " + activity["status"]))
            marker = (kind, runtime.get("execution_id"), value.get("candidate_id"), value.get("sequence") if kind != "runtime" else None,
                      value.get("step"), value.get("status"), value.get("running"),
                      tuple(value.get("completed_views", [])))
            if marker in seen:
                continue
            seen.add(marker)
            step = value.get("step", "")
            label = STEP_LABELS.get(step, step or "Updating execution records")
            state = value.get("status") or ("running" if value.get("running") else "completed")
            suffix = {"running": "Running", "completed": "Completed", "failed": "Incomplete"}.get(state, state)
            if kind == "retrieval_progress":
                views = " / ".join(value.get("completed_views", []))
                label = "Queries and retrieval results saved" + (" · " + views if views else "")
            self.store.event(task_id, kind, self.redact(label + " · " + suffix))

    def run_validation(self, task_id, case_dir, job):
        process = None
        try:
            with self.control.boundary(task_id) as proceed:
                if not proceed:
                    return
                try:
                    task = self.store.task(task_id)
                except KeyError:
                    return  # A cancelled, queued entry may have been deleted.
                current_job = next(j for j in self.store.validations(task_id) if j["id"] == job["id"])
                if self.stopping or task["status"] != "queued" or current_job["status"] != "queued":
                    return
                self.store.update(task_id, "running", stage="validation")
                self.store.update_validation(job["id"], "running")
                environment = self.start_execution({**task, "stage": "validation"}, validation_id=job["id"])
                with (self.store.run_dir(task_id) / "engine.log").open("ab") as log:
                    process = subprocess.Popen(self.validation_command(task_id, case_dir, job),
                                               cwd=self.root, stdout=log, stderr=subprocess.STDOUT,
                                               start_new_session=True,
                                               env=environment)
                self.processes[task_id] = process
                self.store.event(task_id, "validation", f"Validating candidate patch {job['candidate_id']}")
            started, started_at, seen = time.monotonic(), now(), set()
            while process.poll() is None:
                self.observe_runtime(task_id, seen)
                if time.monotonic() - started - self.control.elapsed_pause(task_id, started_at) > 7200:
                    self.stop_process(process)
                    raise TimeoutError("Validation exceeded two hours. The worker was stopped.")
                time.sleep(.5)
            self.observe_runtime(task_id, seen)
            with self.control.boundary(task_id) as proceed:
                if not proceed:
                    return
                task = self.store.task(task_id)
                if task["status"] in {"cancelled", "cancelling", "interrupted"}:
                    self.store.update_validation(job["id"], "cancelled" if task["status"] == "cancelling" else task["status"])
                    if task["status"] == "cancelling":
                        self.store.update(task_id, "cancelled")
                    return
                result = self.checked_validation(task_id, case_dir, job)
                if process.returncode != (0 if result["success"] else 1):
                    raise ValueError(f"Validation worker exited unexpectedly with code {process.returncode}")
                self.store.update_validation(job["id"], "completed")
                validated = self.detail(task_id)["validated"]
                self.store.update(task_id, "completed", validated=validated, stage="validation")
                self.store.event(task_id, "completed", f"Candidate {job['candidate_id']} · " + ("All checks passed" if result["success"] else "Validation finished; some checks did not pass"))
        except Exception as exc:
            with self.lock:
                task = self.store.task(task_id)
                if task["status"] not in {"cancelled", "cancelling", "interrupted"}:
                    summary = read_json(self.validation_dir(task_id, job) / "revalidation.json", {})
                    message = self.redact(summary.get("error") or str(exc))
                    self.store.update_validation(job["id"], "failed", message)
                    self.store.update(task_id, "failed", error=message, stage="validation")
                    self.store.event(task_id, "failed", message)
        finally:
            if process and process.poll() is None:
                self.stop_process(process)
            with self.lock:
                self.processes.pop(task_id, None)
                self.finish_report(task_id)

    def observe(self, task_id, seen):
        self.observe_runtime(task_id, seen)
        task = self.store.task(task_id)
        if task["status"] == "paused":
            return
        case_id = task["case_key"].split(":", 1)[1]
        case_dir = self.store.run_dir(task_id) / "engine/cases" / case_id
        preflight = read_json(self.store.run_dir(task_id) / "engine/source_preflight.json", {})
        marker = ("source_preflight", preflight.get("run_id"), preflight.get("status"))
        if preflight and marker not in seen:
            seen.add(marker)
            message = {"running": "Checking container source against the task snapshot", "verified": "Source consistency verified; continuing the current stage", "blocked": "Source verification failed; stopped before calling the model"}.get(preflight.get("status"))
            if message:
                self.store.event(task_id, "source_preflight", message)
        paths = [(case_dir / name, stage, label) for name, stage, label in (
            ("diagnosis.json", "diagnosis", "Diagnosis records saved"),
            ("retrieval.json", "retrieval", "Retrieval and reranking records saved"),
        )]
        paths += [(p, "repair", f"Repair and validation records saved for candidate {p.parent.name}") for p in (case_dir / "attempts").glob("*/attempt.json")]
        for path, stage, label in paths:
            if path.exists() and path not in seen:
                seen.add(path)
                self.store.event(task_id, stage, label)

    def run(self, task_id, case_dir):
        process = None
        try:
            with self.control.boundary(task_id) as proceed:
                if not proceed:
                    return
                try:
                    task = self.store.task(task_id)
                except KeyError:
                    return  # A cancelled, queued entry may have been deleted.
                if task["status"] != "queued" or self.stopping:
                    return
                self.store.update(task_id, "running")
                log_path = self.store.run_dir(task_id) / "engine.log"
                log_offset = log_path.stat().st_size if log_path.exists() else 0
                result_path = self.store.run_dir(task_id) / "engine/cases" / case_dir.name / "result.json"
                previous_result = self.result_fingerprint(result_path)
                (self.store.run_dir(task_id) / "engine/source_preflight.json").unlink(missing_ok=True)
                environment = self.start_execution(task)
                log = log_path.open("ab")
                try:
                    process = subprocess.Popen(
                        self.command(task, case_dir), cwd=self.root,
                        stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                        env=environment,
                    )
                finally:
                    log.close()
                self.processes[task_id] = process
                label = {"diagnosis": "Starting the diagnosis agent", "retrieval": "Loading retrieval and reranking models", "repair": "Starting patch generation"}.get(task["stage"], "Starting the repair worker")
                self.store.event(task_id, "initializing", label)
            existing = self.store.run_dir(task_id) / "engine/cases" / case_dir.name
            seen = {p for p in existing.rglob("*.json") if p.name in {"diagnosis.json", "retrieval.json", "attempt.json"}}
            started, started_at = time.monotonic(), now()
            while process.poll() is None:
                self.observe(task_id, seen)
                if time.monotonic() - started - self.control.elapsed_pause(task_id, started_at) > 7200:
                    self.stop_process(process)
                    raise TimeoutError("Execution exceeded two hours. The worker was stopped.")
                time.sleep(0.75)
            self.observe(task_id, seen)
            with self.control.boundary(task_id) as proceed:
                if not proceed:
                    return
                current = self.store.task(task_id)
                if current["status"] in ("cancelled", "cancelling", "interrupted"):
                    if current["status"] == "cancelling":
                        self.store.update(task_id, "cancelled")
                        self.store.event(task_id, "cancelled", "Worker stopped; saved artifacts retained")
                    return
                fresh_result = self.result_fingerprint(result_path) != previous_result
                result = read_json(result_path, {}) if fresh_result else {}
                stage_status = result.get("status")
                expected = {"diagnosis": {"diagnosis_ready", "diagnosis_incomplete"}, "retrieval": {"retrieval_ready"}, "repair": {"patch_ready", "completed"}, "all": {"completed"}}[task["stage"]]
                if process.returncode == 0 and stage_status in expected and stage_status != "completed":
                    if stage_status == "patch_ready" and task.get("automatic") and self.repair_request(task_id).get("validation_mode") == "patch_only":
                        self.store.update(task_id, "completed", validated=False)
                        self.store.event(task_id, "completed", "Patch and report ready; validation was not requested")
                        return
                    if stage_status == "diagnosis_ready":
                        issues = self.detail(task_id)["diagnosis_issues"]
                        if issues:
                            stage_status, result["error"] = "diagnosis_incomplete", "; ".join(issues)
                    if self.continue_automatically(task, stage_status, case_dir):
                        return
                    self.store.update(task_id, stage_status, validated=False, error=self.redact(result.get("error")))
                    self.store.event(task_id, stage_status, {
                        "diagnosis_ready": "Diagnosis report ready. Review it before continuing.",
                        "retrieval_ready": "Retrieval complete. Review the examples, then generate a patch.",
                        "patch_ready": "Patch generated. Review the diff, then select Validate Patch.",
                        "diagnosis_incomplete": self.redact(result.get("error") or "Diagnosis is incomplete. See the report for details."),
                    }[stage_status])
                elif process.returncode != 0 or stage_status not in expected or result.get("error"):
                    error = result.get("error") or self.process_error(log_path, log_offset, process.returncode)
                    self.store.update(task_id, "failed", error=self.redact(str(error)))
                    self.store.event(task_id, "failed", self.redact(str(error)))
                else:
                    validated = bool(result.get("success"))
                    self.store.update(task_id, "completed", validated=validated)
                    self.store.event(task_id, "completed", "Run complete; all checks passed" if validated else
                                     "Run complete; requested PoC checks passed" if result.get("selected_checks_passed") else "Run complete; no patch has passed the requested checks")
        except Exception as exc:
            with self.lock:
                if self.store.task(task_id)["status"] not in ("cancelled", "cancelling", "interrupted"):
                    message = self.redact(str(exc))
                    self.store.update(task_id, "failed", error=message)
                    self.store.event(task_id, "failed", message)
        finally:
            if process and process.poll() is None:
                self.stop_process(process)
            with self.lock:
                self.processes.pop(task_id, None)
                self.finish_report(task_id)

    @staticmethod
    def result_fingerprint(path):
        try:
            return path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()
        except FileNotFoundError:
            return None

    def process_error(self, path, offset, returncode):
        with path.open("rb") as stream:
            stream.seek(max(offset, path.stat().st_size - 12000))
            text = stream.read().decode("utf-8", errors="replace")
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        detail = lines[-1][-2500:] if lines else "The worker did not write a stage result"
        return self.redact(f"Stage worker exited (code {returncode}): {detail}")

    @staticmethod
    def stop_process(process):
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        except ProcessLookupError:
            pass

    def delete_task(self, task_id):
        with self.lock:
            self.store.task(task_id)
            if self.stopping or task_id in self.processes or task_id in self.replay.stops:
                raise ValueError("This task is still running. Stop it or wait for it to finish before deleting.")
            self.store.delete(task_id)
            return {"id": task_id, "deleted": True}

    def cancel(self, task_id):
        if self.store.task(task_id).get("mode") == "replay":
            return self.replay.cancel(task_id)
        with self.lock:
            task = self.store.task(task_id)
            if task["status"] not in ACTIVE:
                return task
            self.control.cancel(task_id)
            process = self.processes.get(task_id)
            status = "cancelling" if process else "cancelled"
            self.store.update(task_id, status)
            if task["stage"] == "validation":
                for job in self.store.validations(task_id):
                    if job["status"] in ACTIVE:
                        self.store.update_validation(job["id"], status)
            self.store.event(task_id, status, "User requested to stop the run")
        if process:
            self.stop_process(process)
        return self.store.task(task_id)

    def pause(self, task_id):
        return self.control.pause(task_id)

    def resume(self, task_id):
        return self.control.resume(task_id)

    def close(self):
        with self.lock:
            self.stopping = True
        for task in self.store.tasks():
            if task["status"] in ACTIVE:
                self.cancel(task["id"])
        self.pool.shutdown(wait=True, cancel_futures=True)
        self.replay.close()

    def detail(self, task_id, *, include_deleted=False):
        task = self.store.task(task_id, include_deleted=include_deleted)
        if task.get("mode") == "replay":
            return self.replay.detail(task_id)
        directory = self.store.run_dir(task_id, include_deleted=include_deleted)
        source = read_json(directory / "input.json", {})
        stale = False
        try:
            current = self.catalog.case(task["case_key"])["_source"].read_bytes()
            stale = bool(source.get("source_hash") and hashlib.sha256(current).hexdigest() != source["source_hash"])
        except (OSError, KeyError):
            pass
        case_dir = directory / "engine/cases" / task["case_key"].split(":", 1)[1]
        diagnosis = read_json(case_dir / "diagnosis.json", {}).get("diagnostic_report", {})
        retrieval = read_json(case_dir / "retrieval.json", {})
        result = read_json(case_dir / "result.json", {})
        attempts = [read_json(p) for p in (case_dir / "attempts").glob("*/attempt.json")]
        attempts = sorted((a for a in attempts if isinstance(a, dict)), key=lambda a: int(a.get("candidate_id", 0)))
        jobs = self.store.validations(task_id)
        repair_request = read_json(directory / "repair_request.json", {})
        for attempt in attempts:
            history = [job for job in jobs if job["candidate_id"] == int(attempt.get("candidate_id", 0))]
            attempt["validation_runs"] = history
            if not history:
                continue
            latest = dict(history[-1])
            attempt["original_validation_result"] = attempt.get("validation_result")
            attempt["validation_result"] = None
            if latest["status"] == "completed":
                try:
                    attempt["validation_result"] = self.checked_validation(task_id, case_dir, latest, include_deleted=include_deleted)
                except (OSError, ValueError, KeyError) as exc:
                    latest.update(status="failed", error="Validation receipt check failed: " + str(exc))
            elif latest["status"] in ACTIVE:
                latest["progress"] = read_json(directory / "validations" / latest["id"] / "progress.json", {})
            attempt["latest_validation"] = latest
        if repair_request:
            from utils.validation_scope import decorate_validation
            for attempt in attempts:
                if attempt.get("validation_result"):
                    attempt["validation_result"] = decorate_validation(attempt["validation_result"], repair_request["validation_mode"])
        runtime, partial_retrieval = task_runtime(directory, task, source)
        progress = runtime.get("validation_progress", {})
        for attempt in attempts:
            if str(attempt.get("candidate_id")) == str(progress.get("candidate_id")):
                attempt["live_validation_progress"] = progress
                if attempt.get("latest_validation"):
                    attempt["latest_validation"]["progress"] = progress
        validated = any(a.get("validation_result", {}).get("success") for a in attempts if a.get("validation_result")) if jobs else task["validated"]
        return self.redact({
            **task, **source, "validated": bool(validated), "mode": "live", "description": source.get("dataset", "") + " · Local case",
            "pause": read_json(directory / "task_control.json", {"intervals": []}),
            "validation_runs": jobs, "runtime": runtime, "retrieval_progress": partial_retrieval,
            "runtime_history": [read_json(p, {}) for p in sorted((directory / "runtime_history").glob("*.json"))],
            "engine_result": result,
            "repair_request": repair_request,
            "source_preflight": read_json(directory / "engine/source_preflight.json", {}),
            "source_snapshot_stale": stale,
            "facts": diagnosis.get("facts", []),
            "hypotheses": diagnosis.get("hypotheses", []),
            "limitations": diagnosis.get("limitations", []),
            "root_causes": diagnosis.get("root_causes_by_view", {}),
            "diagnosis_report": diagnosis,
            "diagnosis_issues": diagnosis_issues(diagnosis),
            "tool_calls": diagnosis.get("tool_calls", []),
            "retrieval": retrieval,
            "candidates": attempts,
            "exemplars": retrieval.get("final_exemplars", []),
            "events": self.store.events(task_id),
            "result": {"success": bool(validated), "error": task.get("error")},
        })

    def logs(self, task_id):
        if self.store.task(task_id).get("mode") == "replay":
            return "Historical record replay; no model or Docker calls were made.\n" + "\n".join(
                f"{e['at']} {e['message']}" for e in self.store.events(task_id)
            )
        path = self.store.run_dir(task_id) / "engine.log"
        if not path.exists():
            return ""
        with path.open("rb") as handle:
            handle.seek(max(0, path.stat().st_size - 60000))
            return self.redact(handle.read().decode("utf-8", errors="replace"))
