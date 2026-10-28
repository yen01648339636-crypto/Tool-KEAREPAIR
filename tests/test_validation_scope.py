"""Selected Studio checks retain exact evidence and never imply full validation."""

from copy import deepcopy
import json
from unittest.mock import Mock

import pytest

from Online.phase3_repair import RepairAgent
from scripts import run_online as online
from tests.test_diff_repair import INFO, ORIGINAL, PATCH, ScriptLLM
from tests.test_online_stages import pipeline
from tests.test_source_baseline import Probe, record
from utils.case_commands import CommandMigrationError, validate_record
from utils.experiment_store import digest
from utils.metrics import fully_validated, verify_attempt
from utils.source_baseline import configuration_hash, ensure_source_baseline, preparation_steps
from utils.validation import finish_validation, new_validation, set_stage
from utils.validation_scope import (decorate_validation, requested_stages,
                                    scope_commands, validation_mode)


def test_legacy_full_commands_are_copied_without_semantic_changes():
    original = record()
    scoped = scope_commands(original)
    assert scoped == original and scoped is not original
    assert validation_mode(original) == "full"
    assert requested_stages(original) == ("patch_apply", "compile", "poc", "unit")
    scoped["validation_steps"].clear()
    assert len(original["validation_steps"]) == 2


@pytest.mark.parametrize("bad", ["all", "", True, 42, {"studio_validation_mode": None}])
def test_unknown_scope_is_rejected(bad):
    with pytest.raises(ValueError, match="Validation mode"):
        validation_mode(bad)


def test_poc_scope_removes_unit_execution_without_rewriting_bundled_commands():
    original = record()
    original["test_command"] = original["unit_test_cmd"]
    scoped = scope_commands(original, "poc")
    assert scoped["validation_steps"] == original["validation_steps"][:1]
    assert "unit_test_cmd" not in scoped and "test_command" not in scoped
    assert scope_commands(scoped) == scoped
    assert original["unit_test_cmd"] and len(original["validation_steps"]) == 2
    validate_record(scoped)
    assert [s["name"] for s in preparation_steps(scoped)] == ["build_and_poc"]
    full = deepcopy(scoped)
    full["studio_validation_mode"] = "full"
    with pytest.raises((KeyError, CommandMigrationError)):
        validate_record(full)


def test_scope_refuses_to_hide_tests_inside_a_combined_command():
    commands = record()
    commands["validation_steps"] = [dict(name="all", command="run all checks", covers=["compile", "poc", "unit"])]
    with pytest.raises(ValueError, match="cannot split"):
        scope_commands(commands, "poc")


def test_filtered_scope_invalidates_full_baseline_receipt(tmp_path):
    source = tmp_path / "parser.c"
    source.write_bytes(b"original\n")
    receipt = tmp_path / "source_baseline.json"
    original = record()
    full = ensure_source_baseline(source, original, probe=Probe(), receipt_path=receipt)
    scoped = scope_commands(original, "poc")
    probe = Probe()
    checked = ensure_source_baseline(source, scoped, probe=probe, receipt_path=receipt)
    assert [s["name"] for s in probe.reads] == ["build_and_poc"]
    assert checked["configuration_sha256"] != full["configuration_sha256"]
    assert checked["configuration_sha256"] == configuration_hash(scoped)
    assert len(original["validation_steps"]) == 2


def test_scoped_pass_does_not_upgrade_missing_unit_evidence():
    value = dict(success=True, stage_status=dict(patch_apply="passed", compile="passed", poc="passed", unit="not_run"))
    decorated = decorate_validation(value, "poc")
    assert decorated["selected_checks_passed"] is True
    assert decorated["requested_stages"] == ["patch_apply", "compile", "poc"]
    assert decorated["success"] is False and not fully_validated(decorated)
    assert value["success"] is True  # The source record is not mutated.
    assert not decorate_validation(value, "full")["selected_checks_passed"]
    assert not decorate_validation(value, "patch_only")["selected_checks_passed"]


class ScopedValidator:
    def __init__(self, pass_at=1):
        self.calls = []
        self.pass_at = pass_at

    def validate(self, source, patch, info):
        self.calls.append(deepcopy(info))
        result = new_validation(source, patch, {k: v for k, v in info.items() if k != "docker_image"})
        for name in ("patch_apply", "compile", "poc"):
            status = "failed" if name == "poc" and len(self.calls) < self.pass_at else "passed"
            set_stage(result, name, status, 0.01, stdout="fixture check", stderr="fixture failure" if status == "failed" else "")
        return finish_validation(result)


def test_poc_agent_stops_on_selected_checks_with_full_success_false():
    validator = ScopedValidator()
    result = RepairAgent(ScriptLLM(), validator, max_iterations=5).repair(
        ORIGINAL, [], project_info={**INFO, "studio_validation_mode": "poc"})
    assert result["iterations"] == 1 and len(validator.calls) == 1
    assert result["termination_reason"] == "requested_checks_passed"
    assert result["selected_checks_passed"] and not result["success"]
    assert result["final_patch"] == PATCH
    evidence = result["history"][0]["validation_result"]
    assert evidence["selected_checks_passed"] and evidence["unit_status"] == "not_run"
    assert not fully_validated(evidence)


def test_poc_failure_refines_until_requested_checks_pass():
    validator = ScopedValidator(pass_at=2)
    result = RepairAgent(ScriptLLM(), validator, max_iterations=5).repair(
        ORIGINAL, [], project_info={**INFO, "studio_validation_mode": "poc"})
    assert result["iterations"] == 2 and len(validator.calls) == 2
    assert not result["history"][0]["validation_result"]["selected_checks_passed"]
    assert result["termination_reason"] == "requested_checks_passed" and not result["success"]


def test_full_agent_does_not_stop_on_poc_only_success():
    validator = ScopedValidator()
    result = RepairAgent(ScriptLLM(), validator, max_iterations=2).repair(
        ORIGINAL, [], project_info={**INFO, "studio_validation_mode": "full"})
    assert result["iterations"] == 2 and not result["selected_checks_passed"]
    assert result["termination_reason"] == "budget_exhausted" and not result["success"]


def test_patch_only_cannot_invoke_validation_even_without_defer_flag():
    validator = Mock()
    result = RepairAgent(ScriptLLM(), validator).repair(
        ORIGINAL, [], project_info={**INFO, "studio_validation_mode": "patch_only"})
    validator.validate.assert_not_called()
    assert result["termination_reason"] == "awaiting_validation" and not result["success"]
    assert result["requested_stages"] == [] and result["validation_count"] == 0
    assert result["history"][0]["patch"] == PATCH
    assert set(result["history"][0]["validation_result"]["stage_status"].values()) == {"not_run"}


def test_poc_driver_persists_scoped_result_and_verifiable_candidate(pipeline, monkeypatch):
    commands = scope_commands(record(), "poc")
    commands["source_file"] = "source.c"
    source = pipeline.source.read_text()
    monkeypatch.setattr(online, "ensure_source_baseline", lambda *a, **kw:
                        dict(source_sha256=digest(source), configuration_sha256=configuration_hash(commands), docker_image_id="sha256:fixture"))
    diff = "--- a/source.c\n+++ b/source.c\n@@ -1,3 +1,3 @@\n void f(int x) {\n- sink(x);\n+ sink(0);\n }\n"
    validator = ScopedValidator()
    pipeline.models["repair_agent"] = RepairAgent(ScriptLLM([diff]), validator)
    with pipeline.store.case("CVE-fixture"):
        result = online.repair_single_cve("CVE-fixture", pipeline.source, commands, None,
                                         pipeline.models, pipeline.config, pipeline.store.root,
                                         use_retrieval=False)
    assert result["status"] == "completed" and not result["success"]
    assert result["selected_checks_passed"] and result["termination_reason"] == "requested_checks_passed"
    assert result["validation_mode"] == "poc" and result["requested_stages"] == ["patch_apply", "compile", "poc"]
    checked = verify_attempt(pipeline.case, pipeline.case / "attempts/1")
    assert checked["selected_checks_passed"] and not checked["success"]
    inputs = json.loads((pipeline.case / "inputs.json").read_text())
    assert [s["name"] for s in inputs["effective_validation"]["validation_steps"]] == ["build_and_poc"]
    assert "unit_test_command" not in validator.calls[0]


@pytest.mark.parametrize("stage", ["diagnosis", "retrieval", "repair"])
def test_patch_only_cli_skips_baseline_before_model_initialization(tmp_path, monkeypatch, stage):
    case = tmp_path / "CVE-scope"
    case.mkdir()
    (case / "source.c").write_text(ORIGINAL)
    commands = scope_commands(record(), "patch_only")
    commands["source_file"] = "source.c"
    (case / "test_cmds.json").write_text(json.dumps(commands))
    class ModelsReached(RuntimeError):
        pass
    def reached(*args, **kwargs):
        raise ModelsReached("source-preflight bypassed")
    monkeypatch.setattr(online, "ensure_source_baseline", lambda *a, **kw: pytest.fail("Patch-only invoked Docker baseline"))
    monkeypatch.setattr(online, "initialize_models", reached)
    monkeypatch.setattr("sys.argv", ["run_online.py", "--vul-files-dir", str(case), "--output-dir", str(tmp_path / "output"),
                                    "--stage", stage, "--llm-provider", "mock", "--no-retrieval"] +
                                   (["--defer-validation"] if stage == "repair" else []))
    with pytest.raises(ModelsReached):
        online.main()
    assert not (tmp_path / "output/source_preflight.json").exists()
