"""Uniform diff generation, immutable originals, explicit windows and exact budgets."""

from copy import deepcopy
from types import SimpleNamespace
import unittest

from config.runtime import load_config, resolve_online_config, ConfigurationError
from models import LLMInterface
from Online.phase1_diagnosis.root_cause_report import RootCauseReporter
from Online.phase3_repair import RepairAgent, Validator
from tests.diagnostic_fixtures import diagnostic_report
from utils.patches import PatchError, prepare_patch
from utils.source_context import select_source_context, numbered_source


ORIGINAL = "int main(void) { return 0; }\n"
PATCH = "--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n-int main(void) { return 0; }\n+int main(void) { return 1; }\n"
INFO = {"repo_relpath": "source.c", "buggy_code_file": "source.c"}


class ScriptLLM:
    temperature, max_tokens = 0.2, 4096

    def __init__(self, outputs=None):
        self.outputs = list(outputs or [PATCH])
        self.calls = []

    def generate(self, prompt, **options):
        self.calls.append((prompt, options))
        return self.outputs.pop(0) if len(self.outputs) > 1 else self.outputs[0]


class RecordingValidator:
    def __init__(self, succeeds_at=None):
        self.calls = []
        self.succeeds_at = succeeds_at

    def validate(self, original, patch, info):
        self.calls.append((original, patch, deepcopy(info)))
        return dict(
            success=len(self.calls) == self.succeeds_at,
            stage_status=dict(
                patch_apply="passed",
                compile="passed",
                poc="passed" if len(self.calls) == self.succeeds_at else "failed",
                unit="passed" if len(self.calls) == self.succeeds_at else "not_run",
            ),
            stage="test",
            error_log="AssertionError: expected safe behavior",
        )


class TestExactDiffs(unittest.TestCase):
    def test_crlf_source_and_patch_content_are_preserved(self):
        source = "old\r\nunchanged\r\n"
        patch = "--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n-old\r\n+new\r\n"
        actual, fixed, _ = prepare_patch(source, patch, "source.c")
        self.assertEqual(actual, patch)
        self.assertEqual(fixed, "new\r\nunchanged\r\n")
        _, context = select_source_context(source)
        self.assertEqual(context["line_ending_style"], "crlf")
        self.assertTrue(context["final_newline"])

    def test_accepts_raw_or_one_fence_without_rewriting_the_patch(self):
        for response in (PATCH, "```diff\n" + PATCH + "```"):
            patch, fixed, ranges = prepare_patch(ORIGINAL, response, "source.c")
            self.assertEqual(patch, PATCH)
            self.assertEqual(fixed, ORIGINAL.replace("return 0", "return 1"))
            self.assertEqual(
                ranges, [dict(old_start=1, old_count=1, new_start=1, new_count=1)]
            )

    def test_full_file_xml_prose_wrong_file_and_truncated_hunks_are_rejected(self):
        responses = [
            ORIGINAL,
            "<FIXED_CODE>" + ORIGINAL + "</FIXED_CODE>",
            "Here is the fix:\n" + PATCH,
            PATCH.replace("source.c", "other.c"),
            PATCH.replace("@@ -1 +1 @@", "@@ -1,2 +1,2 @@"),
            PATCH + "\n" + PATCH,
            PATCH.replace("return 0", "return 9"),
        ]
        for response in responses:
            with self.subTest(response=response), self.assertRaises(PatchError):
                prepare_patch(ORIGINAL, response, "source.c")

    def test_partial_multi_hunk_application_is_never_accepted(self):
        original = "one\ntwo\nthree\nfour\n"
        patch = "--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n-one\n+ONE\n@@ -4 +4 @@\n-wrong\n+FOUR\n"
        validator = Validator()
        result = validator.validate(original, patch, INFO)
        self.assertFalse(result["success"])
        self.assertEqual(result["stage"], "patch_application")

    def test_no_newline_marker_is_preserved(self):
        patch = "--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n"
        actual, fixed, _ = prepare_patch("old", patch, "source.c")
        self.assertEqual(actual, patch)
        self.assertEqual(fixed, "new")

    def test_window_uses_original_file_lines_and_validates_complete_source(self):
        original = "".join(f"line{number}\n" for number in range(1, 11))
        selected, context = select_source_context(
            original,
            dict(
                strategy="line_range",
                start_line=6,
                end_line=8,
                line_hint_source="operator-selected range",
            ),
        )
        self.assertEqual(selected, "line6\nline7\nline8\n")
        self.assertEqual(context["window_offset"], 5)
        self.assertEqual(context["selection_source"], "operator-selected range")
        self.assertEqual(
            numbered_source(original, context), "6: line6\n7: line7\n8: line8"
        )
        patch = "--- a/source.c\n+++ b/source.c\n@@ -7 +7 @@\n-line7\n+fixed7\n"
        saved, fixed, _ = prepare_patch(original, patch, "source.c", context)
        self.assertEqual(saved, patch)
        self.assertEqual(fixed, original.replace("line7\n", "fixed7\n"))
        with self.assertRaises(PatchError):
            prepare_patch(
                original, patch.replace("-7 +7", "-2 +2"), "source.c", context,
                allow_correction=False,
            )
        validator = RecordingValidator(succeeds_at=1)
        llm = ScriptLLM([patch])
        result = RepairAgent(llm, validator).repair(
            original, [], diagnostic_report(), {**INFO, "source_context": context}
        )
        self.assertTrue(result["success"])
        self.assertEqual(validator.calls[0][0], original)
        self.assertEqual(result["final_patch"], patch)
        self.assertIn("7: line7", llm.calls[0][0])
        self.assertNotIn("1: line1\n", llm.calls[0][0])

    def test_default_never_uses_metadata_or_implicit_large_file_windows(self):
        original = "line\n" * 6001
        selected, context = select_source_context(original)
        self.assertEqual(selected, original)
        self.assertFalse(context["window_active"])
        self.assertEqual(context["total_lines"], 6001)
        self.assertEqual(context["display_line_numbers"], "original_file")
        with self.assertRaises(ValueError):
            select_source_context(
                original,
                dict(
                    strategy="line_range", start_line=2, end_line=4, line_hint_source=""
                ),
            )


class TestCandidateBudget(unittest.TestCase):
    def test_late_source_drift_stops_without_spending_remaining_model_budget(self):
        for error in (
            "Source attestation failed: container original differs from saved source",
            "Docker image changed after source preflight; recheck the source baseline",
            "Docker tag resolved to another image within this experiment",
        ):
            with self.subTest(error=error):
                validator = RecordingValidator()
                original_validate = validator.validate

                def changed(*args):
                    result = original_validate(*args)
                    result["error_log"] = error
                    return result

                validator.validate = changed
                llm = ScriptLLM()
                result = RepairAgent(llm, validator).repair(ORIGINAL, [], diagnostic_report(), INFO)
                self.assertEqual(len(llm.calls), 1)
                self.assertEqual(result["generation_count"], 1)
                self.assertEqual(result["termination_reason"], "source_baseline_mismatch")
                self.assertFalse(result["success"])

    def test_five_failures_mean_exactly_five_generations_and_validations(self):
        llm, validator = ScriptLLM(), RecordingValidator()
        result = RepairAgent(llm, validator).repair(
            ORIGINAL, [], diagnostic_report(), INFO
        )
        self.assertEqual(result["generation_count"], 5)
        self.assertEqual(result["validation_count"], 5)
        self.assertEqual(len(llm.calls), 5)
        self.assertEqual(len(validator.calls), 5)
        self.assertEqual(
            [item["stage"] for item in result["history"]],
            ["initial_repair"] + ["refine_repair"] * 4,
        )
        self.assertTrue(all(call[0] == ORIGINAL for call in validator.calls))
        self.assertEqual(result["final_patch"], PATCH)
        self.assertEqual(result["termination_reason"], "budget_exhausted")
        for prompt, _ in llm.calls[1:]:
            self.assertIn("[Original vulnerable source", prompt)
            self.assertIn("1: int main(void) { return 0; }", prompt)
            self.assertIn("[Previous candidate", prompt)
            self.assertIn(PATCH, prompt)
            self.assertIn("expected safe behavior", prompt)
            self.assertIn("not to the previous candidate", prompt)

    def test_stops_after_success_without_an_extra_candidate(self):
        llm, validator = ScriptLLM(), RecordingValidator(succeeds_at=2)
        result = RepairAgent(llm, validator).repair(
            ORIGINAL, [], diagnostic_report(), INFO
        )
        self.assertTrue(result["success"])
        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(result["validation_count"], 2)

    def test_no_iteration_invalid_full_file_has_no_stitch_or_retry(self):
        llm, validator = ScriptLLM([ORIGINAL]), RecordingValidator()
        result = RepairAgent(llm, validator, single_attempt=True).repair(
            ORIGINAL, [], diagnostic_report(), INFO
        )
        self.assertFalse(result["success"])
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(validator.calls, [])
        self.assertEqual(result["history"][0]["raw_response"], ORIGINAL)
        self.assertEqual(result["iterations"], 1)

    def test_new_candidates_are_diffs_from_original_not_previous_version(self):
        second = PATCH.replace("return 1", "return 2")
        llm, validator = ScriptLLM([PATCH, second]), RecordingValidator(succeeds_at=2)
        result = RepairAgent(llm, validator).repair(
            ORIGINAL, [], diagnostic_report(), INFO
        )
        self.assertEqual([item[0] for item in validator.calls], [ORIGINAL, ORIGINAL])
        self.assertEqual(result["final_patch"], second)

    def test_each_stage_uses_configured_sampling_without_size_or_model_overrides(self):
        llm, validator = ScriptLLM(), RecordingValidator(succeeds_at=2)
        llm.provider, llm.model_name = "openai", "deepseek-test"
        sampling = dict(
            initial_repair=dict(temperature=0.6, max_tokens=1234),
            refine_repair=dict(temperature=0.7, max_tokens=2345),
        )
        result = RepairAgent(llm, validator, sampling=sampling).repair(
            ORIGINAL, [], diagnostic_report(), INFO
        )
        self.assertEqual([options for _, options in llm.calls], list(sampling.values()))
        self.assertEqual(
            [item["requested_sampling"] for item in result["history"]],
            list(sampling.values()),
        )


class TestToolFreeReport(unittest.TestCase):
    def payload(self):
        return dict(
            root_causes_by_view={
                "data_flow": "possible unchecked input length",
                "control_flow": "possible missing bounds guard",
            },
            hypotheses=["length may reach memcpy unchecked"],
            keywords=["memcpy", "length"],
            limitations=["Only source was inspected"],
        )

    def test_report_is_real_llm_output_and_has_no_tool_facts(self):
        import json

        payload = self.payload()
        llm = ScriptLLM([json.dumps(payload)])
        result = RootCauseReporter(
            llm, {"diagnosis_report": dict(temperature=0.4, max_tokens=321)}
        ).diagnose(ORIGINAL, file_path="source.c")
        report = result["diagnostic_report"]
        self.assertEqual(report["mode"], "llm_only")
        self.assertEqual(report["facts"], [])
        self.assertEqual(report["tool_calls"], [])
        self.assertEqual(report["root_causes_by_view"], payload["root_causes_by_view"])
        self.assertIn("possible missing bounds guard", result["enhanced_context"])
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(llm.calls[0][1], dict(temperature=0.4, max_tokens=321))

    def test_empty_placeholder_missing_view_and_tool_fact_payloads_fail(self):
        import json

        payload = self.payload()
        invalid = [
            "Diagnostic analysis was disabled.",
            json.dumps({**payload, "root_causes_by_view": {}}),
            json.dumps({**payload, "facts": ["pretend verified"]}),
        ]
        for output in invalid:
            with self.subTest(output=output), self.assertRaises(ValueError):
                RootCauseReporter(
                    ScriptLLM([output]), {"diagnosis_report": {}}
                ).diagnose(ORIGINAL, file_path="source.c")


class TestSamplingAndVariants(unittest.TestCase):
    def test_existing_offline_model_uses_its_explicit_wire_parameter_configuration(
        self,
    ):
        config = load_config("config/offline.yaml")
        model = config["models"]["llm"]
        calls = []
        llm = LLMInterface(
            provider="mock",
            model_name=model["model_name"],
            temperature_policy=model["temperature_policy"],
            token_limit_parameter=model["token_limit_parameter"],
        )
        llm.provider = "openai"

        def create(**kwargs):
            calls.append(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=PATCH))]
            )

        llm.client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create))
        )
        llm.generate("prompt", **config["sampling"]["extraction"])
        self.assertEqual(calls[0]["model"], model["model_name"])
        self.assertNotIn("temperature", calls[0])
        self.assertNotIn("max_tokens", calls[0])
        self.assertEqual(
            calls[0]["max_completion_tokens"],
            config["sampling"]["extraction"]["max_tokens"],
        )
        self.assertEqual(
            llm.last_call_parameters["wire_token_limit_parameter"],
            "max_completion_tokens",
        )

    def test_native_diagnostic_models_do_not_restore_a_default_temperature(self):
        from unittest.mock import patch
        from models.chat import create_diagnostic_models

        sampling = dict(
            diagnosis=dict(temperature=0.6, max_tokens=123),
            diagnosis_report=dict(temperature=0.7, max_tokens=234),
        )
        with patch("models.chat.init_chat_model") as factory:
            create_diagnostic_models(
                dict(
                    provider="gemini",
                    model_name="local-model",
                    temperature_policy="omit",
                ),
                sampling,
            )
        self.assertEqual(factory.call_count, 2)
        for call in factory.call_args_list:
            self.assertIsNone(call.kwargs["temperature"])
        self.assertEqual(
            [call.kwargs["max_tokens"] for call in factory.call_args_list], [123, 234]
        )

    def test_source_range_and_temperature_policy_require_explicit_valid_configuration(
        self,
    ):
        from config.runtime import normalize_config

        for context in (
            dict(strategy="middle"),
            dict(strategy="line_range", start_line=2, end_line=4),
            dict(strategy="full", start_line=2),
        ):
            config = load_config("config/online.yaml")
            config["online"]["source_context"] = context
            with self.assertRaises(ConfigurationError):
                normalize_config(config)
        config = load_config("config/online.yaml")
        config["models"]["llm"]["temperature_policy"] = "auto"
        with self.assertRaises(ConfigurationError):
            normalize_config(config)

    def test_temperature_omission_is_effective_and_recorded_without_a_remote_call(self):
        calls = []
        llm = LLMInterface(provider="mock", temperature_policy="omit")
        llm.provider = "openai"

        def create(**kwargs):
            calls.append(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=PATCH))]
            )

        llm.client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create))
        )
        llm.generate("prompt", temperature=0.7, max_tokens=345)
        self.assertNotIn("temperature", calls[0])
        self.assertEqual(calls[0]["max_tokens"], 345)
        self.assertEqual(llm.last_call_parameters["temperature_policy"], "omit")
        validator = RecordingValidator(succeeds_at=1)
        result = RepairAgent(
            llm,
            validator,
            sampling={"initial_repair": dict(temperature=0.7, max_tokens=345)},
        ).repair(ORIGINAL, [], diagnostic_report(), INFO)
        self.assertEqual(result["history"][0]["requested_sampling"]["temperature"], 0.7)
        self.assertNotIn("temperature", result["history"][0]["effective_sampling"])

    def test_variants_are_canonical_and_combinations_are_rejected(self):
        config = load_config("config/online.yaml")
        for variant in (
            "full",
            "df_only",
            "cf_only",
            "no_retrieval",
            "no_diagnosis",
            "no_iteration",
        ):
            resolved = resolve_online_config(config, variant=variant)
            self.assertEqual(resolved["experiment"]["variant"], variant)
            self.assertEqual(
                resolved["online"]["phase2_retrieval"]["enabled"],
                variant != "no_retrieval",
            )
            self.assertEqual(
                resolved["online"]["phase3_repair"]["single_attempt"],
                variant == "no_iteration",
            )
        with self.assertRaises(ConfigurationError):
            resolve_online_config(config, no_retrieval=True, no_iteration=True)
        with self.assertRaises(ConfigurationError):
            resolve_online_config(config, variant="df_only", no_diagnosis=True)


class TestDeferredValidation(unittest.TestCase):
    def test_prepared_patch_stops_without_invoking_validator(self):
        validator = RecordingValidator(succeeds_at=1)
        agent = RepairAgent(ScriptLLM(), validator, max_iterations=5)
        result = agent.repair(ORIGINAL, [], project_info=INFO, defer_validation=True)
        self.assertEqual(validator.calls, [])
        self.assertEqual(result["termination_reason"], "awaiting_validation")
        self.assertEqual(result["generation_count"], 1)
        self.assertEqual(result["validation_count"], 0)
        self.assertFalse(result["success"])
        self.assertIsNone(result["final_patch"])
        attempt = result["history"][0]
        self.assertEqual(attempt["patch"], PATCH)
        self.assertFalse(attempt["validation_invoked"])
        self.assertEqual(set(attempt["validation_result"]["stage_status"].values()), {"not_run"})

    def test_malformed_response_is_repaired_before_pausing(self):
        validator = RecordingValidator(succeeds_at=1)
        agent = RepairAgent(ScriptLLM(["not a diff", PATCH]), validator, max_iterations=2)
        result = agent.repair(ORIGINAL, [], project_info=INFO, defer_validation=True)
        self.assertEqual(result["generation_count"], 2)
        self.assertEqual(result["selected_candidate"], 2)
        self.assertEqual(result["termination_reason"], "awaiting_validation")
        self.assertEqual(validator.calls, [])
