"""Canonical artifacts for replayable case evaluation, including interrupted runs."""

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
from uuid import uuid4

from utils.experiment_manifest import hash_file, write_json_atomic
from utils.metrics import fully_validated, evaluate_experiment, verify_attempt
from utils.telemetry import (
    Recorder,
    current_recorder,
    load_pricing,
    measure,
    request_records,
)


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def persist_attempt(attempt):
    recorder = current_recorder()
    if not recorder or recorder.case_id is None:
        return
    attempt["run_id"] = recorder.run_id
    directory = recorder.directory / "attempts" / str(attempt["candidate_id"])
    directory.mkdir(parents=True, exist_ok=True)
    validation = attempt.get("validation_result")
    if validation and validation.get("patch_correction"):
        from utils.patches import extract_diff

        attempt.setdefault("patch_correction", validation["patch_correction"])
        if validation.get("generated_patch_hash") and isinstance(attempt.get("raw_response"), str):
            attempt.setdefault("generated_patch", extract_diff(attempt["raw_response"]))
        if (isinstance(attempt.get("patch"), str)
                and validation.get("corrected_patch_hash") == digest(attempt["patch"])):
            attempt.setdefault("corrected_patch", attempt["patch"])
    for key, filename in (
        ("raw_response", "raw.patch"), ("generated_patch", "generated.patch"),
        ("corrected_patch", "corrected.patch"), ("patch", "effective.patch"),
    ):
        if isinstance(attempt.get(key), str):
            (directory / filename).write_bytes(attempt[key].encode("utf-8"))
    if validation:
        if attempt.get("patch_correction"):
            write_json_atomic(directory / "patch_correction.json", attempt["patch_correction"])
            validation.setdefault("artifacts", {})["patch_correction.json"] = hash_file(directory / "patch_correction.json")
        details = validation.get("stage_details", {})
        for name in ("compile", "poc", "unit"):
            info = details.get(name, {})
            if info.get("source_attestation") is not None:
                filename = f"{name}.source.json"
                write_json_atomic(directory / filename, info["source_attestation"])
                validation.setdefault("artifacts", {})[filename] = hash_file(directory / filename)
            content = (
                f"status: {validation.get('stage_status', {}).get(name, 'not_run')}\n"
            )
            if info.get("stdout") is not None:
                content += "\n[stdout]\n" + str(info["stdout"])
            if info.get("stderr") is not None:
                content += "\n[stderr]\n" + str(info["stderr"])
            (directory / f"{name}.log").write_text(content, encoding="utf-8")
            validation.setdefault("artifacts", {})[f"{name}.log"] = hash_file(
                directory / f"{name}.log"
            )
        write_json_atomic(directory / "validation.json", validation)
    write_json_atomic(directory / "attempt.json", attempt)


def snapshot_sources(directory, manifest, project_root):
    for group in ("code", "prompts"):
        for supplied, metadata in manifest[group].items():
            source = Path(supplied)
            source = source if source.is_absolute() else project_root / source
            if hash_file(source) != metadata["sha256"]:
                raise ValueError(f"Implementation changed before snapshot: {source}")
            relative = Path(supplied)
            if relative.is_absolute() or ".." in relative.parts:
                relative = Path("external") / digest(str(source))[:16] / source.name
            target = Path(directory) / "provenance" / group / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                shutil.copyfile(source, target)
            if hash_file(target) != metadata["sha256"]:
                raise ValueError(f"Invalid archived implementation snapshot: {target}")


class ExperimentStore:
    def __init__(self, directory, manifest, cases, *, project_root=None):
        self.root, self.manifest = Path(directory), manifest
        self.project_root = Path(
            project_root or Path(__file__).resolve().parents[1]
        ).resolve()
        self.run_id = uuid4().hex
        self.case_ids = list(cases["case_ids"])
        if len(set(self.case_ids)) != len(self.case_ids) or any(
            Path(name).name != name or name in {".", ".."} for name in self.case_ids
        ):
            raise ValueError("Case IDs must be unique safe filenames")
        listing = dict(experiment_id=manifest["experiment_id"], **cases)
        case_file = self.root / "cases.json"
        if case_file.exists() and json.loads(case_file.read_text()) != listing:
            raise ValueError("Refusing to change the fixed case denominator")
        write_json_atomic(case_file, listing)
        import yaml

        (self.root / "config_snapshot.yaml").write_text(
            yaml.safe_dump(manifest["config"], allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        pricing_path = manifest["config"].get("experiment", {}).get("pricing_snapshot")
        self.pricing = load_pricing(pricing_path)
        if self.pricing is not None:
            write_json_atomic(self.root / "pricing_snapshot.json", self.pricing)
        self.recorder = Recorder(
            self.root / "runs" / self.run_id, pricing=self.pricing, run_id=self.run_id
        )
        for case_id in self.case_ids:
            directory = self.root / "cases" / case_id
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / "result.json"
            if not path.exists():
                write_json_atomic(
                    path,
                    dict(
                        cve_id=case_id,
                        experiment_id=manifest["experiment_id"],
                        success=False,
                        status="not_run",
                        repair_history=[],
                        error=None,
                    ),
                )
        if project_root is not None:
            snapshot_sources(self.root, manifest, Path(project_root))

    @contextmanager
    def case(self, case_id):
        recorder = Recorder(
            self.root / "cases" / case_id,
            case_id=case_id,
            pricing=self.pricing,
            run_id=self.run_id,
        )
        with recorder.activate(), measure("case_total"):
            started = dict(
                cve_id=case_id,
                experiment_id=self.manifest["experiment_id"],
                run_id=self.run_id,
                status="running",
                success=False,
            )
            write_json_atomic(recorder.directory / "result.json", started)
            write_json_atomic(
                self.root / "runs" / self.run_id / "cases" / case_id / "result.json",
                started,
            )
            try:
                yield recorder
            except BaseException as exc:
                self.finish_case(
                    case_id,
                    error=exc,
                    status="error" if isinstance(exc, Exception) else "interrupted",
                )
                raise

    def start_source(self, case_id, source, source_path=None):
        path = self.root / "cases" / case_id / "source.original"
        raw = source.encode("utf-8")
        if path.exists() and path.read_bytes() != raw:
            raise ValueError("Original source changed within an experiment")
        key = None
        if source_path is not None:
            source_path = Path(source_path).resolve()
            key = (
                source_path.relative_to(self.project_root).as_posix()
                if source_path.is_relative_to(self.project_root)
                else str(source_path)
            )
            if self.manifest["data"].get(key, {}).get("sha256") != digest(source):
                raise ValueError("Original source does not match the manifest input")
        path.write_bytes(raw)
        write_json_atomic(
            path.with_name("source.json"), dict(manifest_key=key, sha256=digest(source))
        )

    def write_component(self, case_id, name, data):
        data = dict(
            data, run_id=self.run_id, experiment_id=self.manifest["experiment_id"]
        )
        write_json_atomic(self.root / "cases" / case_id / f"{name}.json", data)
        write_json_atomic(
            self.root / "runs" / self.run_id / "cases" / case_id / f"{name}.json", data
        )

    def finish_case(self, case_id, result=None, *, error=None, status=None):
        directory = self.root / "cases" / case_id
        history, incomplete = [], []
        for path in sorted(
            (directory / "attempts").glob("*/attempt.json"),
            key=lambda path: (
                int(path.parent.name) if path.parent.name.isdigit() else -1
            ),
        ):
            try:
                attempt = json.loads(path.read_text())
                if not isinstance(attempt, dict):
                    raise ValueError("Expected an attempt object")
                history.append(attempt)
            except (OSError, ValueError) as exc:
                incomplete.append(dict(candidate_id=path.parent.name, error=str(exc)))
        lifetime_count = len(history)
        history = [item for item in history if item.get("run_id") == self.run_id]
        if result is None:
            try:
                existing = json.loads((directory / "result.json").read_text())
            except (OSError, ValueError):
                existing = {}
            result = (
                existing
                if isinstance(existing, dict) and existing.get("run_id") == self.run_id
                else {}
            )
        value = deepcopy(result)
        value.update(
            cve_id=case_id,
            experiment_id=self.manifest["experiment_id"],
            run_id=self.run_id,
            repair_history=history,
            status=status
            or (
                "error"
                if error is not None
                else "completed" if result is not None else "error"
            ),
            error=str(error) if error is not None else value.get("error"),
        )
        valid = []
        for item in history:
            try:
                validation = verify_attempt(
                    directory,
                    directory / "attempts" / str(item["candidate_id"]),
                    self.manifest,
                )
                valid.append((item, validation))
            except (OSError, ValueError, KeyError):
                continue
        value["success"] = any(fully_validated(validation) for _, validation in valid)
        value["generation_count"] = len(history)
        value["lifetime_candidate_count"] = lifetime_count
        value["incomplete_attempt_records"] = incomplete
        value["validation_count"] = sum(
            bool(item.get("validation_invoked")) for item in history
        )
        value["llm_call_count"] = len(request_records(directory / "llm_calls.jsonl"))
        poc = [
            item
            for item, validation in valid
            if validation["stage_status"]["patch_apply"]
            == validation["stage_status"]["poc"]
            == "passed"
        ]
        (directory / "poc_pass.patch").unlink(missing_ok=True)
        (directory / "final.patch").unlink(missing_ok=True)
        value["poc_pass_candidate_ids"] = [str(item["candidate_id"]) for item in poc]
        if poc:
            first = poc[0]
            value["saved_poc_candidate"] = str(first["candidate_id"])
            if isinstance(first.get("patch"), str):
                (directory / "poc_pass.patch").write_bytes(
                    first["patch"].encode("utf-8")
                )
        if isinstance(value.get("final_patch"), str):
            (directory / "final.patch").write_bytes(
                value["final_patch"].encode("utf-8")
            )
        write_json_atomic(directory / "result.json", value)
        write_json_atomic(
            self.root / "runs" / self.run_id / "cases" / case_id / "result.json", value
        )
        return value

    def startup_failure(self, error):
        for case_id in getattr(self, "pending_case_ids", self.case_ids):
            existing = json.loads(
                (self.root / "cases" / case_id / "result.json").read_text()
            )
            if (
                case_id in getattr(self, "pending_case_ids", [])
                or existing.get("status") == "not_run"
            ):
                self.finish_case(case_id, error=error, status="initialization_error")
        self.summarize()

    def summarize(self):
        result = evaluate_experiment(self.root)
        write_json_atomic(self.root / "summary.json", result)
        return result
