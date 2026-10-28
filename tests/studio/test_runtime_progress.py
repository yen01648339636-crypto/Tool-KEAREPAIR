"""Display telemetry may only describe its own task, source and invocation."""

import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from studio.engine import Engine
from studio.runtime import task_runtime
from studio.store import Store


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


@pytest.fixture
def bound_run(tmp_path):
    directory = tmp_path / "run"
    case_dir = directory / "engine/cases/CVE-2026-0001"
    task = {"id": "task-current", "case_key": "Vul4c:CVE-2026-0001", "stage": "retrieval", "status": "running"}
    snapshot = {"source_hash": "source-current"}
    execution = {"execution_id": "execution-current", "task_id": task["id"], "stage": "retrieval", "started_at": "2026-01-01T01:00:00Z"}
    diagnosis = {"diagnostic_report": {"summary": "Fixture diagnosis", "facts": []}}
    save(directory / "runtime_execution.json", execution)
    save(case_dir / "diagnosis.json", diagnosis)
    save(directory / "engine/manifest.json", {"experiment_id": "experiment-current"})
    progress = {"execution_id": execution["execution_id"], "case_id": "CVE-2026-0001", "step": "reranking", "status": "running", "sequence": 8}
    partial = {
        "execution_id": execution["execution_id"], "source_hash": snapshot["source_hash"],
        "diagnosis_hash": hashlib.sha256((case_dir / "diagnosis.json").read_bytes()).hexdigest(),
        "experiment_id": "experiment-current", "queries": {"data_flow": {"root_cause": "Unchecked input"}},
        "candidates": [{"sample_id": "historical-1", "retrieval_hits": [{"query_view": "data_flow", "rank": 1, "distance": .2}]}],
        "completed_views": ["data_flow"], "step": "retrieval", "status": "running", "sequence": 5,
    }
    save(directory / "engine/progress.json", progress)
    save(case_dir / "retrieval_progress.json", partial)
    return SimpleNamespace(directory=directory, case_dir=case_dir, task=task, snapshot=snapshot,
                           execution=execution, progress=progress, partial=partial)


def test_matching_partial_queries_and_unranked_hits_are_exposed(bound_run):
    run = bound_run
    runtime, partial = task_runtime(run.directory, run.task, run.snapshot)
    assert runtime["progress"] == run.progress
    assert runtime["execution_id"] == run.execution["execution_id"]
    assert partial == run.partial
    assert partial["candidates"][0]["retrieval_hits"][0]["rank"] == 1
    assert not (run.case_dir / "retrieval.json").exists()


@pytest.mark.parametrize("field", ["progress", "partial", "validation"])
def test_old_invocation_snapshots_are_rejected_independently(bound_run, field):
    run = bound_run
    paths = {"progress": run.directory / "engine/progress.json", "partial": run.case_dir / "retrieval_progress.json", "validation": run.case_dir / "validation_progress.json"}
    values = {"progress": run.progress, "partial": run.partial, "validation": {"candidate_id": 1, "running": True}}
    save(paths[field], {**values[field], "execution_id": "execution-previous"})
    runtime, partial = task_runtime(run.directory, run.task, run.snapshot)
    assert (runtime["progress"] if field == "progress" else runtime["validation_progress"] if field == "validation" else partial) == {}
    if field != "partial":
        assert partial == run.partial


@pytest.mark.parametrize("field,value", [("source_hash", "source-other"), ("diagnosis_hash", "diagnosis-other"), ("experiment_id", "experiment-other")])
def test_partial_retrieval_rejects_different_scientific_inputs(bound_run, field, value):
    run = bound_run
    save(run.case_dir / "retrieval_progress.json", {**run.partial, field: value})
    runtime, partial = task_runtime(run.directory, run.task, run.snapshot)
    assert partial == {}
    assert runtime["progress"] == run.progress


def test_partial_retrieval_rejects_diagnosis_changed_after_snapshot(bound_run):
    run = bound_run
    save(run.case_dir / "diagnosis.json", {"diagnostic_report": {"summary": "Changed diagnosis"}})
    assert task_runtime(run.directory, run.task, run.snapshot)[1] == {}


def test_partial_retrieval_requires_current_diagnosis_file(bound_run):
    run = bound_run
    (run.case_dir / "diagnosis.json").unlink()
    assert task_runtime(run.directory, run.task, run.snapshot)[1] == {}


@pytest.mark.parametrize("manifest", [{}, {"experiment_id": None}])
def test_partial_retrieval_requires_experiment_identity(bound_run, manifest):
    run = bound_run
    save(run.directory / "engine/manifest.json", manifest)
    assert task_runtime(run.directory, run.task, run.snapshot)[1] == {}


@pytest.mark.parametrize("manifest", [None, [], "not-a-manifest"])
def test_malformed_manifest_drops_preview_without_breaking_task_read(bound_run, manifest):
    run = bound_run
    save(run.directory / "engine/manifest.json", manifest)
    runtime, partial = task_runtime(run.directory, run.task, run.snapshot)
    assert runtime["progress"] == run.progress
    assert partial == {}


def test_partial_preview_requires_nonempty_source_identity_on_both_sides(bound_run):
    run = bound_run
    partial = {k: v for k, v in run.partial.items() if k != "source_hash"}
    save(run.case_dir / "retrieval_progress.json", partial)
    runtime, preview = task_runtime(run.directory, run.task, {})
    assert runtime["progress"] == run.progress
    assert preview == {}


@pytest.mark.parametrize("stage", ["diagnosis", "repair", "validation"])
def test_retrieval_preview_does_not_leak_into_a_later_stage(bound_run, stage):
    run = bound_run
    save(run.directory / "runtime_execution.json", {**run.execution, "stage": stage})
    task = {**run.task, "stage": stage}
    runtime, partial = task_runtime(run.directory, task, run.snapshot)
    assert runtime["stage"] == stage
    assert partial == {}


@pytest.mark.parametrize("execution", [None, [], "invalid", {"stage": "repair", "task_id": "task-current"}, {"stage": "retrieval", "task_id": "another-task"}])
def test_missing_or_unrelated_execution_metadata_is_not_current(bound_run, execution):
    run = bound_run
    save(run.directory / "runtime_execution.json", execution)
    assert task_runtime(run.directory, run.task, run.snapshot) == ({}, {})


def test_legacy_task_without_progress_files_remains_readable(tmp_path):
    task = {"id": "legacy", "case_key": "Vul4c:CVE-2026-0001", "stage": "repair"}
    assert task_runtime(tmp_path, task, {}) == ({}, {})


def test_wrong_case_general_progress_is_rejected(bound_run):
    run = bound_run
    save(run.directory / "engine/progress.json", {**run.progress, "case_id": "CVE-2026-OTHER"})
    runtime, partial = task_runtime(run.directory, run.task, run.snapshot)
    assert runtime["progress"] == {}
    assert partial == run.partial


def test_manual_validation_reads_only_its_own_job_snapshot(bound_run):
    run = bound_run
    execution = {**run.execution, "stage": "validation", "validation_id": "job-current"}
    save(run.directory / "runtime_execution.json", execution)
    save(run.case_dir / "validation_progress.json", {"execution_id": execution["execution_id"], "candidate_id": 99, "running": True})
    save(run.directory / "validations/job-other/progress.json", {"execution_id": execution["execution_id"], "candidate_id": 77, "running": True})
    runtime, _ = task_runtime(run.directory, {**run.task, "stage": "validation"}, run.snapshot)
    assert runtime["validation_progress"] == {}
    expected = {"execution_id": execution["execution_id"], "candidate_id": 2, "running": True, "stage_status": {"compile": "running"}}
    save(run.directory / "validations/job-current/progress.json", expected)
    assert task_runtime(run.directory, {**run.task, "stage": "validation"}, run.snapshot)[0]["validation_progress"] == expected


@pytest.mark.parametrize("status", ["completed", "failed", "interrupted", "cancelled", "retrieval_ready"])
def test_terminal_tasks_keep_bound_snapshots_as_recorded_history(bound_run, status):
    run = bound_run
    runtime, partial = task_runtime(run.directory, {**run.task, "status": status}, run.snapshot)
    assert runtime["progress"] == run.progress
    assert partial == run.partial
    assert "validated" not in runtime


@pytest.fixture
def engine_run(tmp_path):
    store = Store(tmp_path / "studio")
    task = store.create("Vul4c:CVE-2026-0001", "full", "CVE-2026-0001", stage="retrieval")
    directory = store.run_dir(task["id"])
    directory.mkdir(parents=True)
    source = tmp_path / "source.c"
    source.write_text("int main(void) { return 0; }\n")
    snapshot = {"source_hash": hashlib.sha256(source.read_bytes()).hexdigest(), "source": source.read_text(), "case_id": "CVE-2026-0001", "dataset": "Vul4c"}
    save(directory / "input.json", snapshot)
    catalog = SimpleNamespace(case=lambda key: {"_source": source})
    engine = Engine(tmp_path, store, catalog, tmp_path / "config.yaml")
    try:
        yield engine, store, task, directory
    finally:
        engine.pool.shutdown(wait=True)


def test_each_worker_invocation_rotates_identity_without_changing_environment(engine_run):
    engine, _, task, directory = engine_run
    environment_before = dict(os.environ)
    first = engine.start_execution(task)
    first_id = first["KEA_STUDIO_EXECUTION_ID"]
    second = engine.start_execution(task, validation_id="job-2")
    metadata = json.loads((directory / "runtime_execution.json").read_text())
    assert first_id != second["KEA_STUDIO_EXECUTION_ID"]
    assert metadata["execution_id"] == second["KEA_STUDIO_EXECUTION_ID"]
    assert metadata["task_id"] == task["id"]
    assert metadata["validation_id"] == "job-2"
    assert dict(os.environ) == environment_before


def test_observer_emits_once_per_progress_sequence_and_redacts_errors(engine_run):
    engine, store, task, directory = engine_run
    execution_id = engine.start_execution(task)["KEA_STUDIO_EXECUTION_ID"]
    progress = {"execution_id": execution_id, "sequence": 1, "step": "query_generation", "status": "running"}
    save(directory / "engine/progress.json", progress)
    seen = set()
    baseline = len(store.events(task["id"]))
    engine.observe_runtime(task["id"], seen)
    engine.observe_runtime(task["id"], seen)
    assert len(store.events(task["id"])) == baseline + 1
    save(directory / "engine/progress.json", {**progress, "sequence": 2, "status": "completed"})
    engine.observe_runtime(task["id"], seen)
    assert len(store.events(task["id"])) == baseline + 2
    secret = "sk-localfixturecredential123456789"
    save(directory / "engine/progress.json", {**progress, "sequence": 3, "step": secret, "status": "failed", "error": secret})
    engine.observe_runtime(task["id"], seen)
    assert secret not in json.dumps(store.events(task["id"]))
    assert "[redacted]" in store.events(task["id"])[-1]["message"]


def test_observer_keeps_progress_when_next_candidate_resets_sequence(engine_run):
    engine, store, task, directory = engine_run
    store.update(task["id"], "running", stage="repair")
    task = store.task(task["id"])
    execution_id = engine.start_execution(task)["KEA_STUDIO_EXECUTION_ID"]
    path = directory / "engine/cases/CVE-2026-0001/validation_progress.json"
    progress = {"execution_id": execution_id, "sequence": 1, "step": "compile", "status": "running", "running": True}
    baseline = len(store.events(task["id"]))
    seen = set()
    save(path, {**progress, "candidate_id": 1})
    engine.observe_runtime(task["id"], seen)
    save(path, {**progress, "candidate_id": 2})
    engine.observe_runtime(task["id"], seen)
    engine.observe_runtime(task["id"], seen)
    assert len(store.events(task["id"])) == baseline + 2
    assert [event["stage"] for event in store.events(task["id"])[baseline:]] == ["validation_progress", "validation_progress"]


def test_detail_exposes_only_redacted_bound_partial_and_native_result_separately(engine_run):
    engine, store, task, directory = engine_run
    execution_id = engine.start_execution(task)["KEA_STUDIO_EXECUTION_ID"]
    case_dir = directory / "engine/cases/CVE-2026-0001"
    diagnosis = {"diagnostic_report": {"summary": "Original native report", "facts": [], "termination_reason": "model_finished"}}
    save(case_dir / "diagnosis.json", diagnosis)
    save(directory / "engine/manifest.json", {"experiment_id": "current-experiment"})
    snapshot = json.loads((directory / "input.json").read_text())
    secret = "sk-localfixturecredential123456789"
    partial = {"execution_id": execution_id, "source_hash": snapshot["source_hash"], "diagnosis_hash": hashlib.sha256((case_dir / "diagnosis.json").read_bytes()).hexdigest(), "experiment_id": "current-experiment", "queries": {"data_flow": {"root_cause": secret, "api_key": "nested-secret"}}, "candidates": []}
    save(case_dir / "retrieval_progress.json", partial)
    native = {"queries": {"data_flow": {"root_cause": "Earlier native result"}}, "final_exemplars": [{"sample_id": "saved-1"}]}
    save(case_dir / "retrieval.json", native)
    detail = engine.detail(task["id"])
    assert detail["retrieval"] == native
    assert detail["exemplars"] == native["final_exemplars"]
    assert detail["diagnosis_report"] == diagnosis["diagnostic_report"]
    assert detail["retrieval_progress"]["queries"]["data_flow"] == {"root_cause": "[redacted]", "api_key": "[redacted]"}
    assert secret not in json.dumps(detail)
    assert detail["validated"] is False


def test_detail_of_legacy_task_has_empty_runtime_without_fabricating_progress(engine_run):
    engine, _, task, _ = engine_run
    detail = engine.detail(task["id"])
    assert detail["runtime"] == {}
    assert detail["retrieval_progress"] == {}
    assert detail["retrieval"] == {}
    assert detail["validated"] is False
