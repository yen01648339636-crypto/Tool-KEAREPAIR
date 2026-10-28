"""Request accounting and artifact-only evaluation, without external services."""

import contextlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from models.llm_interface import LLMInterface, LLMError
from Online.phase1_diagnosis import DiagnosticAgent
from Online.phase3_repair import RepairAgent, Validator
from tests.diagnostic_fixtures import ScriptedChatModel, diagnostic_report, call
from tests.test_diff_repair import ScriptLLM, ORIGINAL, PATCH, INFO
from tests.container_fixtures import DockerSandbox
from utils.experiment_manifest import create_manifest, bind_manifest, write_json_atomic
from utils.experiment_store import ExperimentStore
from utils.metrics import evaluate_experiment, summarize_calls, fully_validated
from utils.telemetry import (
    Recorder,
    begin_call,
    finish_call,
    request_records,
    read_jsonl,
    stage,
    normalize_usage,
    estimate_cost,
    load_pricing,
    text_call,
)

ROOT = Path(__file__).resolve().parents[1]


def prices(model="fixture-model", provider="openai"):
    # Synthetic unit-test rates, never used as a real model price snapshot.
    return {
        "prices": [
            dict(
                provider=provider,
                model=model,
                currency="USD",
                as_of="2026-01-01",
                source="test fixture only",
                input_per_million=2,
                output_per_million=4,
                cached_input_per_million=1,
                cache_write_per_million=3,
            )
        ]
    }


class TestRequests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def interface(self, provider, response):
        with patch.object(LLMInterface, "_initialize_client"):
            llm = LLMInterface(
                provider=provider, model_name="fixture-model", api_key="unused"
            )
        create = Mock(return_value=response)
        llm.client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create)),
            messages=SimpleNamespace(create=create),
            models=SimpleNamespace(generate_content=create),
        )
        return llm, create

    def test_provider_usage_is_saved_including_hidden_reasoning_and_cache(self):
        fixtures = [
            (
                "openai",
                SimpleNamespace(
                    choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
                    usage=SimpleNamespace(
                        prompt_tokens=100,
                        completion_tokens=20,
                        total_tokens=120,
                        prompt_tokens_details={"cached_tokens": 40},
                        completion_tokens_details={"reasoning_tokens": 5},
                    ),
                    id="response-1",
                    model="fixture-model",
                    cost={"amount": 0.12, "currency": "USD"},
                ),
                20,
            ),
            (
                "anthropic",
                SimpleNamespace(
                    content=[SimpleNamespace(type="text", text="ok")],
                    usage={
                        "input_tokens": 100,
                        "output_tokens": 20,
                        "cache_read_input_tokens": 40,
                        "cache_creation_input_tokens": 10,
                    },
                ),
                20,
            ),
            (
                "gemini",
                SimpleNamespace(
                    text="ok",
                    usage_metadata={
                        "prompt_token_count": 100,
                        "candidates_token_count": 20,
                        "thoughts_token_count": 5,
                        "total_token_count": 125,
                        "cached_content_token_count": 40,
                    },
                ),
                25,
            ),
        ]
        for provider, response, output in fixtures:
            with self.subTest(provider=provider):
                llm, create = self.interface(provider, response)
                recorder = Recorder(
                    self.root / provider, pricing=prices(provider=provider)
                )
                with recorder.activate(), stage("initial_repair", candidate_id=1):
                    self.assertEqual(
                        llm.generate("source", max_tokens=50, temperature=0.4), "ok"
                    )
                records = request_records(recorder.directory / "llm_calls.jsonl")
                self.assertEqual(len(records), 1)
                record = records[0]
                self.assertEqual(record["candidate_id"], 1)
                self.assertEqual(record["usage"]["input_tokens"], 100)
                self.assertEqual(record["usage"]["output_tokens"], output)
                self.assertEqual(record["usage"]["cached_input_tokens"], 40)
                self.assertIsNotNone(record["estimated_cost"])
                self.assertEqual(record["stage"], "initial_repair")
                self.assertGreaterEqual(record["duration_seconds"], 0)
                if provider == "openai":
                    self.assertEqual(record["provider_cost"]["amount"], 0.12)
                    self.assertEqual(record["response_metadata"]["id"], "response-1")
                else:
                    self.assertIsNone(record["provider_cost"])
                self.assertEqual(create.call_count, 1)

    def test_retries_failures_and_crashed_attempts_keep_unknown_usage(self):
        response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))], usage=None
        )
        llm, create = self.interface("openai", response)
        create.side_effect = [RuntimeError("503 temporarily unavailable"), response]
        recorder = Recorder(self.root)
        with recorder.activate(), patch.dict(
            "os.environ", {"LLM_MAX_RETRIES": "2"}
        ), patch("models.llm_interface.time.sleep"):
            text_call(llm, "source", "query:data_flow")
            begin_call(
                "fixture-model",
                "openai",
                {},
                retry_index=2,
                request_group_id="interrupted-group",
            )
        events = read_jsonl(self.root / "llm_calls.jsonl")
        records = request_records(self.root / "llm_calls.jsonl")
        self.assertEqual(len(events), 5)
        self.assertEqual(
            [item["retry_index"] for item in events if item["event"] == "started"],
            [0, 1, 2],
        )
        self.assertEqual(
            [item["status"] for item in records], ["failed", "completed", "incomplete"]
        )
        summary = summarize_calls(records)
        self.assertEqual(summary["request_attempt_count"], 3)
        self.assertEqual(summary["failed_request_attempt_count"], 1)
        self.assertIsNone(summary["input_tokens"])
        self.assertIsNone(summary["provider_cost"]["total"])
        self.assertEqual(summary["provider_cost"]["unknown_calls"], 3)

    def test_mock_tokens_and_prices_never_become_billable_zero(self):
        llm = LLMInterface(provider="mock")
        estimate = llm.count_tokens("Hello world")
        self.assertIsInstance(estimate, int)
        self.assertGreater(estimate, 0)
        recorder = Recorder(self.root, pricing=prices())
        with recorder.activate():
            text_call(llm, "fixture", "initial_repair")
        record = request_records(self.root / "llm_calls.jsonl")[0]
        self.assertTrue(record["simulation"])
        self.assertIsNone(record["usage"]["input_tokens"])
        self.assertIsNone(record["estimated_cost"])

    def test_native_chat_callbacks_include_failed_reports_once(self):
        model = ScriptedChatModel(
            responses=[call("inspect_api_usage", {"call": {"line": 2}})],
            report_error=True,
        )
        recorder = Recorder(self.root, case_id="CVE-fixture")
        with recorder.activate():
            result = DiagnosticAgent(model, model).diagnose(
                "void f(int x) {\n sink(x);\n}", file_path="source.c"
            )
        records = request_records(self.root / "llm_calls.jsonl")
        self.assertEqual(len(records), len(model.requests))
        self.assertEqual(
            sum(item["stage"] == "diagnosis_report" for item in records), 1
        )
        self.assertEqual(records[-1]["status"], "failed")
        self.assertTrue(all(item["usage"]["input_tokens"] is None for item in records))
        self.assertTrue(result["diagnostic_report"]["facts"])

    def test_currency_coverage_and_provider_cost_are_separate_from_estimates(self):
        recorder = Recorder(self.root, pricing=prices())
        with recorder.activate():
            for currency in ("USD", "EUR", None):
                record = begin_call("fixture-model", "openai", {})
                finish_call(
                    record,
                    time.monotonic(),
                    raw_usage={
                        "prompt_tokens": 100,
                        "completion_tokens": 20,
                        "total_tokens": 120,
                        "prompt_tokens_details": {"cached_tokens": 0},
                    },
                    cost={"amount": 0.01, "currency": currency} if currency else 0.01,
                )
        summary = summarize_calls(request_records(self.root / "llm_calls.jsonl"))
        self.assertIsNone(summary["provider_cost"]["total"])
        self.assertEqual(
            summary["provider_cost"]["known_subtotals"], {"USD": 0.01, "EUR": 0.01}
        )
        self.assertEqual(summary["provider_cost"]["unknown_calls"], 1)
        self.assertAlmostEqual(summary["estimated_cost"]["total"], 3 * 0.00028)

    def test_failed_request_never_reuses_previous_response_usage(self):
        response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
            usage={"prompt_tokens": 100, "completion_tokens": 20},
        )
        llm, create = self.interface("openai", response)
        create.side_effect = [response, RuntimeError("local transport failure")]
        with Recorder(self.root).activate(), patch.dict(
            "os.environ", {"LLM_MAX_RETRIES": "1"}
        ):
            llm.generate("first")
            with self.assertRaises(LLMError):
                llm.generate("second")
        records = request_records(self.root / "llm_calls.jsonl")
        self.assertEqual(records[0]["usage"]["input_tokens"], 100)
        self.assertIsNone(records[1]["usage"]["input_tokens"])

    def test_prices_require_exact_identity_and_known_cache_counts(self):
        path = self.root / "prices.json"
        write_json_atomic(path, prices())
        snapshot = load_pricing(path)
        record = begin_call("fixture-model", "openai", {})
        record["usage"] = normalize_usage(
            {"prompt_tokens": 100, "completion_tokens": 20}, "openai"
        )
        self.assertIsNone(estimate_cost(record, snapshot))
        record["usage"]["cached_input_tokens"] = 40
        self.assertAlmostEqual(estimate_cost(record, snapshot)["amount"], 0.00024)
        record["model"] = "alias-or-other-version"
        self.assertIsNone(estimate_cost(record, snapshot))
        record["model"], record["provider"] = "fixture-model", "anthropic"
        record["usage"] = normalize_usage(
            {"input_tokens": 100, "output_tokens": 20}, "anthropic"
        )
        self.assertIsNone(estimate_cost(record, prices(provider="anthropic")))
        # LangChain normalized Gemini usage already includes reasoning output.
        self.assertEqual(
            normalize_usage(
                {
                    "input_tokens": 100,
                    "output_tokens": 25,
                    "total_tokens": 125,
                    "output_token_details": {"reasoning": 5},
                },
                "gemini",
                unified=True,
            )["output_tokens"],
            25,
        )
        self.assertIsNone(
            normalize_usage({"candidates_token_count": 20}, "gemini")["output_tokens"]
        )
        bad = prices()
        bad["prices"][0]["input_per_million"] = None
        write_json_atomic(path, bad)
        with self.assertRaises(ValueError):
            load_pricing(path)

    def test_native_and_text_anthropic_cache_usage_has_one_summary_semantics(self):
        raw = normalize_usage(
            dict(
                input_tokens=100,
                output_tokens=20,
                cache_read_input_tokens=40,
                cache_creation_input_tokens=10,
            ),
            "anthropic",
        )
        unified = normalize_usage(
            dict(
                input_tokens=150,
                output_tokens=20,
                total_tokens=170,
                input_token_details=dict(cache_read=40, cache_creation=10),
            ),
            "anthropic",
            unified=True,
        )
        self.assertEqual(raw["input_tokens"], 100)
        summary = summarize_calls([{"usage": raw}, {"usage": unified}])
        self.assertEqual(summary["input_tokens"], 300)
        self.assertEqual(summary["cached_input_tokens"], 80)
        self.assertEqual(summary["cache_write_input_tokens"], 20)


class TestValidationEvidence(unittest.TestCase):
    def test_python_compile_rejects_parseable_invalid_programs(self):
        validator = Validator(compiler="gcc")
        self.assertEqual(validator.compiler, "gcc")
        self.assertFalse(validator._validate_python("return 1\n")["success"])

    def test_local_commands_run_against_the_patched_workspace_in_order(self):
        source = "value = 0\n"
        patch_text = (
            "--- a/source.py\n+++ b/source.py\n@@ -1 +1 @@\n-value = 0\n+value = 1\n"
        )
        info = dict(
            repo_relpath="source.py",
            buggy_code_file="source.py",
            compile_command="python3 -m py_compile source.py",
            poc_test_command="python3 -c \"import source; assert source.value == 1; print('PoC passed')\"",
            unit_test_command='python3 -c "import source; assert isinstance(source.value, int)"',
        )
        result = Validator().validate(source, patch_text, info)
        self.assertTrue(fully_validated(result))
        self.assertIn("PoC passed", result["stage_details"]["poc"]["stdout"])
        for name in ("patch_apply", "compile", "poc", "unit"):
            self.assertGreaterEqual(
                result["stage_details"][name]["duration_seconds"], 0
            )

    def test_failed_poc_and_timeouts_do_not_execute_unit(self):
        for outcome in (
            SimpleNamespace(returncode=1, stdout="poc output", stderr="unsafe"),
            subprocess.TimeoutExpired(
                ["bash"], 2, output=b"partial", stderr=b"timeout"
            ),
        ):
            with self.subTest(outcome=outcome):
                effects = [
                    SimpleNamespace(returncode=0, stdout="build", stderr=""),
                    outcome,
                ]
                with patch(
                    "Online.phase3_repair.validator.subprocess.run", side_effect=effects
                ) as run:
                    result = Validator().validate(
                        ORIGINAL,
                        PATCH,
                        {
                            **INFO,
                            "compile_command": "compile",
                            "poc_test_command": "poc",
                            "unit_test_command": "unit",
                        },
                    )
                self.assertEqual(run.call_count, 2)
                self.assertEqual(result["stage_status"]["unit"], "not_run")
                self.assertIn(result["stage_status"]["poc"], {"failed", "error"})
                self.assertFalse(result["success"])

    def test_unit_only_cannot_attest_poc_or_unobserved_compile(self):
        with patch(
            "Online.phase3_repair.validator.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout="unit", stderr=""),
        ):
            result = Validator().validate(
                ORIGINAL,
                PATCH,
                {**INFO, "buggy_code_file": "source.go", "unit_test_command": "unit"},
            )
        self.assertEqual(
            result["stage_status"],
            dict(patch_apply="passed", compile="not_run", poc="not_run", unit="passed"),
        )
        self.assertFalse(result["success"])

    def test_bundled_stage_duration_is_not_fabricated(self):
        info = {
            **INFO,
            "validation_steps": [
                dict(name="poc", command="pipeline", covers=["compile", "poc"]),
                dict(name="unit", command="unit", covers=["unit"]),
            ],
        }
        with tempfile.TemporaryDirectory() as temporary, Recorder(
            temporary
        ).activate(), patch(
            "Online.phase3_repair.validator.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout="passed", stderr=""),
        ):
            result = Validator().validate(ORIGINAL, PATCH, info)
            measured = [
                event["stage"]
                for event in read_jsonl(Path(temporary) / "timings.jsonl")
            ]
        self.assertTrue(result["success"])
        self.assertIsNone(result["stage_details"]["compile"]["duration_seconds"])
        self.assertGreaterEqual(
            result["stage_details"]["compile"]["command_duration_seconds"], 0
        )

        self.assertIn("validation_command", measured)
        self.assertNotIn("poc", measured)

    def test_docker_commands_use_the_recorded_immutable_image(self):
        validator = Validator()
        validator.execution_mode = "docker"
        image_id = "sha256:" + "a" * 64
        sandbox = DockerSandbox(ORIGINAL)
        command = '\n'.join([
            'set -e',
            'bash /kea-validation/protocol.sh apply "$PWD"',
            'bash /kea-validation/protocol.sh before "$PWD"',
            'grep -q "return 1" source.c',
            'bash /kea-validation/protocol.sh after "$PWD"',
        ])

        with patch.object(validator, "_check_docker_available"), patch.object(
            validator, "_get_docker_subprocess_env", return_value={}
        ), patch.object(
            validator,
            "_image_identity",
            return_value={"image_id": image_id, "repo_digests": []},
        ), patch(
            "Online.phase3_repair.validator.subprocess.run", side_effect=sandbox
        ):
            result = validator.validate(
                ORIGINAL,
                PATCH,
                {
                    **INFO,
                    "docker_image": "fixture:tag",
                    "compile_command": command,
                    "poc_test_command": command,
                    "unit_test_command": command,
                },
            )
        self.assertEqual(result["docker_digest"], image_id)
        self.assertTrue(result["success"])
        self.assertTrue(
            all(image_id in argv and "fixture:tag" not in argv for argv in sandbox.commands)
        )

    def test_docker_tag_changes_are_rejected_on_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            validator = Validator()
            responses = [
                SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(
                        {
                            "Id": "sha256:" + char * 64,
                            "RepoDigests": ["fixture@sha256:" + char * 64],
                        }
                    ),
                    stderr="",
                )
                for char in ("a", "b")
            ]
            recorder = Recorder(root / "cases/CVE-fixture", case_id="CVE-fixture")
            with recorder.activate(), patch.object(
                validator, "_ensure_docker_image"
            ), patch(
                "Online.phase3_repair.validator.subprocess.run", side_effect=responses
            ):
                first = validator._image_identity("fixture:tag", {})
                with self.assertRaises(ValueError):
                    validator._image_identity("fixture:tag", {})
            self.assertEqual(
                json.loads((root / "docker_images.json").read_text())["fixture:tag"],
                first,
            )


class TestArtifactEvaluation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.ids = ["CVE-1", "CVE-2", "CVE-3"]
        self.cases = dict(
            case_ids=self.ids,
            excluded=[{"case_id": "CVE-4", "reason": "explicit_limit"}],
        )
        self.manifest = bind_manifest(
            self.root / "experiment",
            create_manifest(
                "online",
                {"experiment": {}},
                project_root=self.root,
                parameters={"case_selection": self.cases},
            ),
        )
        self.store = ExperimentStore(
            self.root / "experiment", self.manifest, self.cases
        )

    def repair(self, outcomes):
        validators = iter(outcomes)

        def validate(*args):
            return {"stage_status": next(validators), "success": False}

        with self.store.case("CVE-1"):
            self.store.start_source("CVE-1", ORIGINAL)
            self.store.write_component(
                "CVE-1", "inputs", {"effective_validation": INFO}
            )
            result = RepairAgent(
                ScriptLLM(),
                SimpleNamespace(validate=validate),
                max_iterations=len(outcomes),
            ).repair(ORIGINAL, [], diagnostic_report(), INFO)
            return self.store.finish_case(
                "CVE-1",
                dict(
                    final_patch=result["final_patch"],
                    selected_candidate=result.get("selected_candidate"),
                ),
            )

    def test_fixed_denominator_and_separate_same_candidate_metrics(self):
        result = self.repair(
            [
                dict(
                    patch_apply="passed", compile="passed", poc="passed", unit="failed"
                ),
                dict(
                    patch_apply="passed", compile="passed", poc="failed", unit="passed"
                ),
            ]
        )
        case = self.store.root / "cases/CVE-1"
        self.assertEqual((case / "poc_pass.patch").read_text(), PATCH)
        self.assertEqual(result["saved_poc_candidate"], "1")
        self.assertFalse(result["success"])
        (self.store.root / "cases/CVE-2/result.json").unlink()
        write_json_atomic(self.store.root / "cases/CVE-3/result.json", ["malformed"])
        summary = evaluate_experiment(self.store.root)
        self.assertEqual(summary["metrics"]["denominator"], 3)
        self.assertEqual(summary["metrics"]["poc_pass_rate"], 1 / 3)
        self.assertEqual(summary["metrics"]["poc_and_unit_pass_rate"], 0)
        self.assertEqual(summary["metrics"]["repair_rate"], 0)
        self.assertEqual(summary["metrics"]["status_counts"]["missing_result"], 2)
        self.assertIsNone(summary["metrics"]["average_case_wall_seconds"])

    def test_hash_and_log_tampering_reject_positive_claims(self):
        self.repair(
            [dict.fromkeys(("patch_apply", "compile", "poc", "unit"), "passed")]
        )
        self.assertEqual(
            evaluate_experiment(self.store.root)["metrics"]["repair_rate"], 1 / 3
        )
        directory = self.store.root / "cases/CVE-1/attempts/1"
        for name in ("raw.patch", "effective.patch", "poc.log"):
            original = (directory / name).read_bytes()
            (directory / name).write_bytes(original + b"tampered")
            summary = evaluate_experiment(self.store.root)
            self.assertEqual(summary["metrics"]["repair_rate"], 0)
            self.assertEqual(len(summary["cases"][0]["invalid_candidate_evidence"]), 1)
            (directory / name).write_bytes(original)

    def test_missing_request_journal_never_implies_zero_cost(self):
        self.repair(
            [dict.fromkeys(("patch_apply", "compile", "poc", "unit"), "passed")]
        )
        path = self.store.root / "cases/CVE-1/llm_calls.jsonl"
        record = request_records(path)[0]
        record["provider_cost"] = dict(amount=0.01, currency="USD")
        path.write_text(json.dumps(record) + "\n")
        self.assertEqual(
            evaluate_experiment(self.store.root)["metrics"]["online_calls"][
                "provider_cost"
            ]["total"],
            0.01,
        )
        path.unlink()
        calls = evaluate_experiment(self.store.root)["metrics"]["online_calls"]
        self.assertEqual(calls["request_attempt_count"], 1)
        self.assertIsNone(calls["provider_cost"]["total"])
        (path.parent / "result.json").unlink()
        self.assertIsNone(
            evaluate_experiment(self.store.root)["metrics"]["online_calls"][
                "request_attempt_count"
            ]
        )

    def test_retry_run_keeps_all_costs_but_respects_latest_candidate_budget(self):
        self.repair(
            [dict.fromkeys(("patch_apply", "compile", "poc", "unit"), "passed")]
        )
        self.store = ExperimentStore(self.store.root, self.manifest, self.cases)
        self.repair(
            [dict(patch_apply="passed", compile="passed", poc="failed", unit="not_run")]
        )
        summary = evaluate_experiment(self.store.root)
        self.assertEqual(summary["metrics"]["repair_rate"], 0)
        self.assertEqual(summary["cases"][0]["candidate_count"], 1)
        self.assertEqual(summary["cases"][0]["lifetime_candidate_count"], 2)
        self.assertEqual(summary["metrics"]["online_calls"]["request_attempt_count"], 2)
        self.assertFalse((self.store.root / "cases/CVE-1/poc_pass.patch").exists())

    def test_initialization_errors_and_interruptions_remain_in_denominator(self):
        self.store.pending_case_ids = self.ids
        self.store.startup_failure("fixture initialization failure")
        summary = evaluate_experiment(self.store.root)
        self.assertEqual(
            summary["metrics"]["status_counts"], {"initialization_error": 3}
        )
        with self.assertRaises(KeyboardInterrupt), self.store.case("CVE-1"):
            raise KeyboardInterrupt("fixture interrupt")
        summary = evaluate_experiment(self.store.root)
        self.assertEqual(summary["cases"][0]["status"], "interrupted")
        self.assertEqual(summary["metrics"]["denominator"], 3)

    def test_missing_wall_time_after_a_rerun_is_unknown(self):
        self.repair(
            [dict.fromkeys(("patch_apply", "compile", "poc", "unit"), "passed")]
        )
        self.store = ExperimentStore(self.store.root, self.manifest, self.cases)
        self.repair(
            [dict.fromkeys(("patch_apply", "compile", "poc", "unit"), "passed")]
        )
        path = self.store.root / "cases/CVE-1/timings.jsonl"
        previous = [
            event for event in read_jsonl(path) if event["run_id"] != self.store.run_id
        ]
        path.write_text("".join(json.dumps(event) + "\n" for event in previous))
        case = evaluate_experiment(self.store.root)["cases"][0]
        self.assertGreater(case["timings_seconds"]["case_total"], 0)
        self.assertIsNone(case["case_wall_seconds"])

    def test_case_list_is_bound_and_cli_recomputes_without_model_dependencies(self):
        self.repair(
            [dict.fromkeys(("patch_apply", "compile", "poc", "unit"), "passed")]
        )
        expected = evaluate_experiment(self.store.root)
        with patch.object(
            sys, "argv", ["evaluate.py", "--experiment-dir", str(self.store.root)]
        ), contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(ROOT / "scripts/evaluate.py"), run_name="__main__")
        self.assertEqual(
            json.loads((self.store.root / "summary.json").read_text()), expected
        )
        cases = json.loads((self.store.root / "cases.json").read_text())
        cases["case_ids"].pop()
        write_json_atomic(self.store.root / "cases.json", cases)
        with self.assertRaises(ValueError):
            evaluate_experiment(self.store.root)

    def test_invalid_diff_and_generation_error_have_traceable_negative_evidence(self):
        with self.store.case("CVE-1"):
            self.store.start_source("CVE-1", ORIGINAL)
            RepairAgent(ScriptLLM(["invalid diff"]), None, max_iterations=1).repair(
                ORIGINAL, [], diagnostic_report(), INFO
            )
            self.store.finish_case("CVE-1", {})
        summary = evaluate_experiment(self.store.root)
        self.assertEqual(
            summary["cases"][0]["candidate_evidence"][0]["stage_status"]["patch_apply"],
            "failed",
        )
        self.assertEqual(summary["cases"][0]["invalid_candidate_evidence"], [])
        self.store = ExperimentStore(self.store.root, self.manifest, self.cases)
        llm = SimpleNamespace(
            generate=Mock(side_effect=LLMError("fixture generation failure"))
        )
        with self.assertRaises(LLMError), self.store.case("CVE-1"):
            RepairAgent(llm, None, max_iterations=1).repair(
                ORIGINAL, [], diagnostic_report(), INFO
            )
        summary = evaluate_experiment(self.store.root)
        self.assertEqual(
            summary["cases"][0]["candidate_evidence"][0]["outcome"], "generation_error"
        )
        self.assertEqual(summary["cases"][0]["invalid_candidate_evidence"], [])
        self.assertEqual(summary["metrics"]["denominator"], 3)


if __name__ == "__main__":
    unittest.main()
