"""Verify JSON/schema retries share the transport budget and preserve valid caches."""

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from Offline import IndexBuilder, MultiViewGenerator, VectorStore, ViewDistillation
from models.llm_interface import LLMInterface
from tests.offline_fixtures import LocalEmbedding, knowledge, source_sample
from tests.test_offline_batch_skips import GatewayFailure, LocalGateway
from utils.knowledge import normalize_sample
from utils.llm_errors import LLMAuthError, LLMError, LLMOutputValidationError
from utils.schemas import ContractError
from utils.telemetry import Recorder, read_jsonl, request_records


class InvalidOutputGateway(LocalGateway):
    def __init__(self, invalid, *, stage="extraction", view="control_flow", invalid_count=3):
        super().__init__(failure=None)
        self.invalid = invalid if isinstance(invalid, str) else json.dumps(invalid)
        self.invalid_stage, self.invalid_view = stage, view
        self.invalid_count, self.invalid_returned = invalid_count, 0

    def _generate_openai(self, prompt, max_tokens, temperature, stop):
        view = "control_flow" if '"view_type": "control_flow"' in prompt or "The view is control_flow" in prompt else "data_flow"
        abstracting = "[Extracted Knowledge]" in prompt
        marked = "copy_1(input)" in prompt or "BAD_SOURCE" in prompt
        if (marked and view == self.invalid_view
                and abstracting == (self.invalid_stage == "abstraction")
                and self.invalid_returned < self.invalid_count):
            self.invalid_returned += 1
            return self.invalid
        return super()._generate_openai(prompt, max_tokens, temperature, stop)


class TestOfflineOutputRetries(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sample = normalize_sample(source_sample())
        self.samples = [source_sample(str(i), f"copy_{i}(input);\n") for i in range(5)]
        retries = patch.dict("os.environ", {"LLM_MAX_RETRIES": "3", "LLM_RETRY_BASE_DELAY": "0"})
        retries.start()
        self.addCleanup(retries.stop)
        sleeping = patch("models.llm_interface.time.sleep")
        sleeping.start()
        self.addCleanup(sleeping.stop)

    def interface(self, outputs):
        with patch.object(LLMInterface, "_initialize_client", return_value=None):
            llm = LLMInterface(provider="openai", model_name="local-gateway", api_key="unused")
        replies = []
        for i, output in enumerate(outputs):
            if isinstance(output, BaseException):
                replies.append(output)
                continue
            replies.append(SimpleNamespace(
                id=f"local-response-{i}", model="local-gateway",
                choices=[SimpleNamespace(message=SimpleNamespace(content=output))],
                usage={"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
            ))
        create = Mock(side_effect=replies)
        llm.client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
        return llm, create

    def build(self, llm, path):
        store = VectorStore()
        builder = IndexBuilder(MultiViewGenerator(llm), ViewDistillation(llm), store, LocalEmbedding())
        builder.build_from_dataset(self.samples, path, batch_size=2)
        return builder, store

    def test_invalid_json_and_fields_recover_on_third_attempt_with_usage_preserved(self):
        outputs = ['{"root_cause": "broken"', '{"root_cause": "missing fields"}', json.dumps(knowledge())]
        llm, create = self.interface(outputs)
        with Recorder(self.root).activate():
            value = MultiViewGenerator(llm).extract_knowledge(self.sample, "data_flow")
        self.assertEqual(value.root_cause, knowledge()["root_cause"])
        self.assertEqual(create.call_count, 3)
        records = request_records(self.root / "llm_calls.jsonl")
        self.assertEqual([r["status"] for r in records], ["failed", "failed", "completed"])
        self.assertEqual([r["retry_index"] for r in records], [0, 1, 2])
        self.assertEqual(len({r["request_group_id"] for r in records}), 1)
        self.assertEqual(records[0]["response"], outputs[0])
        self.assertEqual(records[0]["usage"]["total_tokens"], 30)
        for call in create.call_args_list:
            self.assertNotIn("response_validator", call.kwargs)
            self.assertEqual(call.kwargs["messages"][0]["content"], create.call_args_list[0].kwargs["messages"][0]["content"])
            self.assertEqual(call.kwargs["max_tokens"], 1024)

    def test_transport_and_invalid_output_use_three_attempts_in_total(self):
        llm, create = self.interface([GatewayFailure(), "invalid JSON", json.dumps(knowledge())])
        with Recorder(self.root).activate():
            MultiViewGenerator(llm).extract_knowledge(self.sample, "data_flow")
        self.assertEqual(create.call_count, 3)
        records = request_records(self.root / "llm_calls.jsonl")
        self.assertEqual([r["status"] for r in records], ["failed", "failed", "completed"])
        self.assertIsNone(records[0]["response"])
        self.assertIsNone(records[0]["usage"]["total_tokens"])
        self.assertEqual(records[1]["response"], "invalid JSON")
        self.assertEqual(records[1]["usage"]["total_tokens"], 30)

    def test_mixed_failures_exhaust_the_shared_budget_without_nested_retries(self):
        llm, create = self.interface([GatewayFailure(), "invalid JSON", "still invalid JSON"])
        with self.assertRaises(LLMOutputValidationError) as caught:
            MultiViewGenerator(llm).extract_knowledge(self.sample, "data_flow")
        self.assertEqual(create.call_count, 3)
        self.assertEqual(caught.exception.attempts, 3)
        self.assertIsInstance(caught.exception.__cause__, ContractError)

    def test_custom_text_backend_retries_validation_and_records_raw_outputs(self):
        generate = Mock(side_effect=["bad JSON", '{"root_cause":"missing"}', json.dumps(knowledge())])
        llm = SimpleNamespace(generate=generate, provider="local", model_name="custom")
        with Recorder(self.root).activate():
            MultiViewGenerator(llm).extract_knowledge(self.sample, "data_flow")
        self.assertEqual(generate.call_count, 3)
        records = request_records(self.root / "llm_calls.jsonl")
        self.assertEqual([r["status"] for r in records], ["failed", "failed", "completed"])
        self.assertEqual([r["retry_index"] for r in records], [0, 1, 2])
        self.assertEqual(len({r["request_group_id"] for r in records}), 1)
        self.assertEqual(records[0]["response"], "bad JSON")
        self.assertTrue(all("response_validator" not in r["parameters"] for r in records))

    def test_invalid_json_or_schema_skip_current_batch_then_continue(self):
        invalid_values = [
            '{"root_cause": "broken"',
            {"root_cause": "missing fields"},
            {**knowledge("control_flow"), "risky_calls": "wrong type"},
            {**knowledge("control_flow"), "control_branch": ""},
            {**knowledge("control_flow"), "extra": "unsupported"},
            {**knowledge("control_flow"), "view_type": "data_flow"},
            '{"root_cause": "one", "root_cause": "two"}',
        ]
        for i, invalid in enumerate(invalid_values):
            with self.subTest(invalid=invalid):
                llm = InvalidOutputGateway(invalid)
                builder, store = self.build(llm, self.root / str(i))
                report = builder.build_report
                self.assertEqual(report["status"], "complete_with_skips")
                skipped = report["skipped_batches"][0]
                self.assertEqual(skipped["reason"], "knowledge_validation_retries_exhausted")
                self.assertEqual(skipped["sample_ids"], ["0", "1"])
                self.assertEqual(skipped["attempts"], 3)
                self.assertEqual(llm.invalid_returned, 3)
                self.assertEqual(len(store.metadata["data_flow"]), 5)
                self.assertEqual([r["sample_id"] for r in store.metadata["control_flow"]], ["2", "3", "4"])

    def test_abstraction_losing_risky_calls_is_retried_then_skipped(self):
        llm = InvalidOutputGateway({**knowledge("control_flow"), "risky_calls": []}, stage="abstraction")
        builder, store = self.build(llm, self.root)
        self.assertEqual(llm.invalid_returned, 3)
        self.assertEqual(builder.build_report["skipped_batches"][0]["stage"], "abstraction")
        self.assertIn("discarded all", builder.build_report["failures"][0]["error"])
        self.assertEqual(len(store.metadata["control_flow"]), 3)

    def test_resume_repairs_only_the_missing_batch_after_json_failure(self):
        self.build(InvalidOutputGateway("invalid JSON"), self.root)
        previous = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.glob("cache/*/batch_*.*")}
        llm = InvalidOutputGateway("unused", invalid_count=0)
        builder, store = self.build(llm, self.root)
        self.assertEqual(llm.request_attempt_count, 4)
        self.assertEqual(builder.build_report["status"], "complete")
        self.assertEqual(previous, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in previous})
        self.assertEqual(len(store.metadata["data_flow"]), 5)
        self.assertEqual(len(store.metadata["control_flow"]), 5)
        self.assertFalse((self.root / "checkpoint.json").exists())

    def test_bad_abstraction_input_is_rejected_before_any_request(self):
        llm, create = self.interface([])
        with self.assertRaises(ContractError):
            ViewDistillation(llm).distill_without_patch({"root_cause": "invalid input"}, "control_flow")
        self.assertEqual(create.call_count, 0)

    def test_authentication_failure_after_bad_json_still_aborts_immediately(self):
        llm, create = self.interface(["invalid JSON", GatewayFailure(401), json.dumps(knowledge())])
        with self.assertRaises(LLMAuthError):
            MultiViewGenerator(llm).extract_knowledge(self.sample, "data_flow")
        self.assertEqual(create.call_count, 2)

    def test_validator_programming_error_is_not_treated_as_invalid_model_output(self):
        llm, create = self.interface([json.dumps(knowledge())])
        with self.assertRaises(LLMError) as caught:
            llm.generate("prompt", response_validator=Mock(side_effect=ValueError("validator bug")))
        self.assertNotIsInstance(caught.exception, LLMOutputValidationError)
        self.assertEqual(create.call_count, 1)


if __name__ == "__main__":
    unittest.main()
