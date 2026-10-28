"""Actual timing and invocation isolation without models or external services."""

import json

import pytest

from utils import runtime_progress as telemetry
from utils.runtime_progress import RuntimeProgress, RetrievalProgress, progress_step


def read(path):
    return json.loads(path.read_text())


def test_runtime_records_measured_steps_and_terminal_startup_error(tmp_path, monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(telemetry.time, "monotonic", lambda: clock[0])
    monkeypatch.setenv("KEA_STUDIO_EXECUTION_ID", "new-execution")
    path = tmp_path / "progress.json"
    runtime = RuntimeProgress(path, stage="retrieval", run_id="run-1")
    assert read(path)["status"] == "running"
    assert read(path)["execution_id"] == "new-execution"
    first_sequence = read(path)["sequence"]
    with runtime.activate():
        with progress_step("retrieval", "embedding_model_loading"):
            assert read(path)["step"] == "embedding_model_loading"
            clock[0] += 2.5
        with pytest.raises(RuntimeError, match="model unavailable"):
            with progress_step("retrieval", "code_encoder_loading"):
                clock[0] += 4
                raise RuntimeError("model unavailable")
    runtime.finish(error="model unavailable")
    result = read(path)
    assert result["sequence"] > first_sequence
    assert result["status"] == "failed"
    assert result["elapsed_seconds"] == 4
    assert result["total_elapsed_seconds"] == 6.5
    assert [(s["step"], s["status"], s["elapsed_seconds"]) for s in result["history"]] == [
        ("embedding_model_loading", "completed", 2.5),
        ("code_encoder_loading", "failed", 4),
    ]
    assert all(s["started_at"] and s["updated_at"] for s in result["history"])


def test_activation_is_scoped_and_new_invocation_replaces_old_progress(tmp_path):
    path = tmp_path / "progress.json"
    runtime = RuntimeProgress(path, run_id="old", execution_id="old-execution")
    with runtime.activate(), progress_step("diagnosis", "diagnosis", "CVE-example"):
        assert read(path)["case_id"] == "CVE-example"
    runtime.finish()
    old = path.read_bytes()
    with progress_step("ignored", "outside-active-context"):
        pass
    assert path.read_bytes() == old
    RuntimeProgress(path, run_id="new", execution_id="new-execution")
    assert read(path)["execution_id"] == "new-execution"
    assert read(path)["history"] == []
    assert "case_id" not in read(path)


def test_agent_activity_preserves_stage_history_and_failed_requests(tmp_path):
    from utils.runtime_progress import progress_activity, progress_event
    path = tmp_path / "progress.json"
    runtime = RuntimeProgress(path, execution_id="activity-execution")
    with runtime.activate(), progress_step("diagnosis", "diagnosis", "CVE-test"):
        with progress_activity("Request source analysis", kind="model"):
            assert read(path)["activity"]["status"] == "running"
        progress_event("Tool result: trace_data_flow", kind="tool", fact_count=2)
        with pytest.raises(RuntimeError):
            with progress_activity("Request report", kind="model"):
                raise RuntimeError("provider unavailable")
    result = read(path)
    assert len(result["history"]) == 1
    assert [a["status"] for a in result["activity_history"]] == ["running", "completed", "completed", "running", "failed"]
    assert result["activity_history"][2]["fact_count"] == 2
    assert [a["sequence"] for a in result["activity_history"]] == list(range(1, 6))
    original = path.read_bytes()
    progress_event("Outside a worker")
    assert path.read_bytes() == original


def test_partial_has_identity_is_immutable_and_preserves_failure(tmp_path):
    path = tmp_path / "retrieval_progress.json"
    queries = {"data_flow": {"view": "data_flow", "root_cause": "input reaches sink"}}
    candidates = [{"sample_id": "1", "retrieval_hits": [{"query_view": "data_flow", "rank": 1}]}]
    runtime = RuntimeProgress(tmp_path / "progress.json", execution_id="execution", run_id="run")
    with runtime.activate():
        with pytest.raises(ValueError, match="reranker unavailable"):
            with RetrievalProgress(path, run_id="run", experiment_id="experiment",
                                   source_hash="source", diagnosis_hash="diagnosis") as partial:
                partial.update(step="reranking", queries=queries, candidates=candidates,
                               completed_views=["data_flow"])
                queries.clear()
                candidates[0]["retrieval_hits"].clear()
                raise ValueError("reranker unavailable")
    result = read(path)
    assert {key: result[key] for key in ("execution_id", "run_id", "experiment_id", "source_hash", "diagnosis_hash")} == {
        "execution_id": "execution", "run_id": "run", "experiment_id": "experiment",
        "source_hash": "source", "diagnosis_hash": "diagnosis",
    }
    assert result["status"] == "failed" and result["step"] == "reranking"
    assert result["queries"]["data_flow"]["root_cause"] == "input reaches sink"
    assert len(result["candidates"][0]["retrieval_hits"]) == 1
    assert "final_exemplars" not in result
    assert not path.with_name("retrieval.json").exists()


def test_cli_model_startup_has_progress_before_constructor_and_fails_terminally(monkeypatch):
    # This harness executes the real main() with a constructor that stops before
    # any model load or external request. It also verifies a run ledger exists.
    from tests.test_cli_identity import TestCLIIdentity as CLIHarness, ROOT, ModelStartupReached
    harness = CLIHarness()
    harness.setUp()
    monkeypatch.setenv("KEA_STUDIO_EXECUTION_ID", "cli-startup-test")
    try:
        case, output = harness.root / "CVE-1", harness.root / "output"
        case.mkdir()
        (case / "source.c").write_text("int main(void) { return 0; }\n")
        original_constructor = harness.modules["models"].LLMInterface

        def constructor(**kwargs):
            before = read(output / "progress.json")
            assert before["status"] == "running" and before["step"] == "model_loading"
            assert before["execution_id"] == "cli-startup-test"
            return original_constructor(**kwargs)

        harness.modules["models"].LLMInterface = constructor
        with pytest.raises(ModelStartupReached):
            harness.run_cli("scripts/run_online.py", [
                "--config", str(ROOT / "config/online.yaml"),
                "--vul-files-dir", str(case), "--output-dir", str(output),
                "--llm-provider", "mock", "--no-retrieval",
            ])
        after = read(output / "progress.json")
        assert after["status"] == "failed" and "ModelStartupReached" in after["error"]
        assert after["history"][-1]["step"] == "model_loading"
        assert after["history"][-1]["status"] == "failed"
        assert list((output / "runs").glob("*/run.json"))
    finally:
        harness.doCleanups()
