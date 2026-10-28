"""Stage handoff uses the reviewed artifacts; no downloads or external services."""

import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from config.runtime import load_config, resolve_online_config
from scripts import run_online as online
from Online.phase1_diagnosis import DiagnosticAgent
from tests.diagnostic_fixtures import ScriptedChatModel, call
from utils.experiment_manifest import create_manifest, bind_manifest
from utils.experiment_manifest import hash_object
from utils.experiment_store import ExperimentStore
from utils.stage_handoff import bind_studio_manifest

SUMMARY = {
    "hypotheses": ["Input may reach an unsafe sink"],
    "summary": "Untrusted input reaches a sink without a preceding guard; runtime exploitability is unverified.",
    "keywords": ["input", "sink"], "evidence_ids": [],
}


@pytest.fixture
def pipeline(tmp_path):
    source = tmp_path / "source.c"
    source.write_text("void f(int x) {\n sink(x);\n}\n")
    config = resolve_online_config(load_config("config/online.yaml"), provider="mock")
    output = tmp_path / "output"
    manifest = bind_manifest(output, create_manifest("online", config, data_paths=[source]))
    store = ExperimentStore(output, manifest, {"case_ids": ["CVE-fixture"]})
    agent = DiagnosticAgent(ScriptedChatModel(
        responses=[call("inspect_api_usage", {"call": {"line": 2}}), AIMessage(content="Done")],
        report_payload=SUMMARY,
    ))
    models = {
        "store": store, "llm": object(), "diagnostic_agent": agent,
        "query_generator": Mock(), "retriever": Mock(), "reranker": Mock(), "repair_agent": Mock(),
    }
    models["query_generator"].generate_queries.return_value = {"data_flow": "input", "control_flow": "guard"}
    models["retriever"].retrieve.return_value = [{"sample_id": "example"}]
    models["reranker"].rerank.return_value = [{"sample_id": "example"}]
    models["reranker"].last_run = {}
    models["repair_agent"].repair.return_value = {"success": False, "iterations": 1, "history": [], "final_patch": None}
    models["repair_agent"].last_rendered_exemplars = []
    def run(stage, **kwargs):
        with store.case("CVE-fixture"):
            return online.repair_single_cve("CVE-fixture", source, None, None, models, config, output, stage=stage, **kwargs)
    return SimpleNamespace(run=run, models=models, source=source, config=config, store=store,
                           case=output / "cases/CVE-fixture")


def test_diagnosis_stops_before_query_generation(pipeline):
    result = pipeline.run("diagnosis")
    assert result["status"] == "diagnosis_ready" and not result["success"]
    assert (pipeline.case / "diagnosis.json").is_file()
    assert not (pipeline.case / "retrieval.json").exists()
    pipeline.models["query_generator"].generate_queries.assert_not_called()
    pipeline.models["repair_agent"].repair.assert_not_called()


def test_retrieval_uses_saved_report_and_repair_uses_saved_examples(pipeline):
    pipeline.run("diagnosis")
    report = json.loads((pipeline.case / "diagnosis.json").read_text())["diagnostic_report"]
    pipeline.models["diagnostic_agent"] = None  # A later phase cannot silently re-diagnose.
    result = pipeline.run("retrieval")
    assert result["status"] == "retrieval_ready"
    pipeline.models["query_generator"].generate_queries.assert_called_once_with(report)
    pipeline.models["repair_agent"].repair.assert_not_called()
    pipeline.models["query_generator"] = pipeline.models["retriever"] = pipeline.models["reranker"] = None
    pipeline.run("repair")
    args = pipeline.models["repair_agent"].repair.call_args
    assert args.args[1][0]["sample_id"] == "example"
    assert args.kwargs["diagnostic_report"] == report


def test_retrieval_accepts_hash_bound_parent_report_without_rewriting_it(pipeline):
    pipeline.run("diagnosis")
    raw = (pipeline.case / "diagnosis.json").read_bytes()
    parent_id = pipeline.store.manifest["experiment_id"]
    candidate = deepcopy(pipeline.store.manifest)
    candidate["code"]["fixture-code-update.py"] = {"sha256": "a" * 64, "size": 1}
    candidate["identity"]["code_hash"] = hash_object(candidate["code"])
    candidate["experiment_id"] = hash_object(candidate["identity"])
    manifest = bind_studio_manifest(pipeline.store.root, candidate, stage="retrieval",
                                    case_ids=["CVE-fixture"])
    store = ExperimentStore(pipeline.store.root, manifest, {"case_ids": ["CVE-fixture"]})
    models = {**pipeline.models, "store": store, "diagnostic_agent": None}
    with store.case("CVE-fixture"):
        result = online.repair_single_cve("CVE-fixture", pipeline.source, None, None,
                                         models, pipeline.config, store.root, stage="retrieval")
    assert result["status"] == "retrieval_ready"
    assert (pipeline.case / "diagnosis.json").read_bytes() == raw
    assert json.loads(raw)["experiment_id"] == parent_id != manifest["experiment_id"]


def test_changed_report_cannot_reuse_old_retrieval(pipeline):
    pipeline.run("diagnosis")
    pipeline.run("retrieval")
    path = pipeline.case / "diagnosis.json"
    value = json.loads(path.read_text())
    value["diagnostic_report"]["keywords"].append("changed")
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="reviewed diagnosis"):
        pipeline.run("repair")
    pipeline.models["repair_agent"].repair.assert_not_called()


def test_invalid_report_retains_facts_and_blocks_retrieval(pipeline):
    model = ScriptedChatModel(
        responses=[call("inspect_api_usage", {"call": {"line": 2}})], report_error=True,
    )
    pipeline.models["diagnostic_agent"] = DiagnosticAgent(model)
    assert pipeline.run("diagnosis")["status"] == "diagnosis_incomplete"
    assert json.loads((pipeline.case / "diagnosis.json").read_text())["diagnostic_report"]["facts"]
    with pytest.raises(ValueError, match="诊断"):
        pipeline.run("retrieval")
    pipeline.models["retriever"].retrieve.assert_not_called()


def test_diagnosis_does_not_initialize_retrieval_or_validation(pipeline, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Unrelated model initialized before diagnosis")
    for name in ("EmbeddingModel", "CodeEncoder", "VectorStore", "Validator", "RepairAgent"):
        monkeypatch.setattr(online, name, forbidden)
    models = online.initialize_models(pipeline.config, pipeline.source.parent / "missing-index",
                                      pipeline.store, stage="diagnosis")
    assert models["diagnostic_agent"] is not None
    assert models["retriever"] is None and models["repair_agent"] is None


class GatewayReportModel(ScriptedChatModel):
    """Gateway can emit prose despite a schema, then valid text JSON on retry."""
    report_responses: list = []

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        if any(t["function"]["name"] == "DiagnosisSummary" for t in kwargs.get("tools", [])):
            self.requests.append(messages)
            assert kwargs["tool_choice"] == "auto"
            text = self.report_responses.pop(0)
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))])
        return super()._generate(messages, stop, run_manager, **kwargs)


def test_gateway_report_retries_invalid_json_and_accepts_schema_valid_text():
    model = GatewayReportModel(report_responses=["# prose is invalid", json.dumps(SUMMARY)])
    report = DiagnosticAgent(model).diagnose("void f() {}", file_path="source.c")["diagnostic_report"]
    assert report["report_call_count"] == 2
    assert report["summary"] == SUMMARY["summary"]
    assert report["root_causes_by_view"] == {}
    assert "report_error" not in report["termination_reason"]
    assert report["usage"]["model_calls"][-2]["error"]


def test_gateway_report_stops_after_three_format_failures():
    model = GatewayReportModel(report_responses=["invalid"] * 3)
    report = DiagnosticAgent(model).diagnose("void f() {}", file_path="source.c")["diagnostic_report"]
    assert report["report_call_count"] == 3
    assert "report_error" in report["termination_reason"]
    assert report["root_causes_by_view"] == {}


def test_repair_can_pause_with_saved_diff_and_no_validation(pipeline):
    import difflib
    from Online.phase3_repair import RepairAgent
    from tests.test_diff_repair import ScriptLLM
    from utils.metrics import verify_attempt
    pipeline.run("diagnosis")
    knowledge = {"root_cause": "Input reaches a sink", "risky_calls": ["sink"],
                 "taint_flow": "input -> sink", "fixing_strategy": "Validate input"}
    pipeline.models["reranker"].rerank.return_value = [{
        "sample_id": "example", "rerank_score": .8,
        "buggy_code": "sink(x);", "fixed_code": "sink(0);", "patch": "-sink(x);\n+sink(0);",
        "views": {"data_flow": {"extracted_knowledge": knowledge, "abstracted_knowledge": knowledge}},
    }]
    pipeline.run("retrieval")
    source = pipeline.source.read_text()
    diff = "".join(difflib.unified_diff(source.splitlines(True),
                   source.replace("sink(x)", "sink(0)").splitlines(True),
                   fromfile="a/source.c", tofile="b/source.c"))
    validator = Mock()
    pipeline.models["repair_agent"] = RepairAgent(ScriptLLM([diff]), validator)
    result = pipeline.run("repair", defer_validation=True)
    assert result["status"] == "patch_ready" and not result["success"]
    assert result["validation_count"] == 0 and result["generation_count"] == 1
    assert "validation" not in result["execution_trace"]
    assert not (pipeline.case / "final.patch").exists()
    attempt = pipeline.case / "attempts/1"
    assert (attempt / "effective.patch").read_text() == diff
    assert set(verify_attempt(pipeline.case, attempt)["stage_status"].values()) == {"not_run"}
    validator.validate.assert_not_called()


def test_generation_only_does_not_initialize_validator(pipeline, monkeypatch):
    monkeypatch.setattr(online, "LLMInterface", lambda **kw: object())
    monkeypatch.setattr(online, "Validator", lambda **kw: pytest.fail("Validator initialized during generation"))
    models = online.initialize_models(pipeline.config, pipeline.source.parent,
                                     pipeline.store, stage="repair", defer_validation=True)
    assert models["repair_agent"].validator is None
