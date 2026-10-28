"""Exercise actual retry exhaustion, skipped batches, FAISS output and gap repair."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from Offline import IndexBuilder, MultiViewGenerator, VectorStore, ViewDistillation
from models.llm_interface import LLMInterface
from tests.offline_fixtures import LocalEmbedding, knowledge, source_sample
from utils.llm_errors import LLMAuthError, LLMError, LLMRetryExhaustedError


class GatewayFailure(RuntimeError):
    def __init__(self, status=503):
        super().__init__("Service temporarily unavailable" if status == 503 else "Request rejected")
        self.status_code = status


class LocalGateway(LLMInterface):
    """Keep real retry/accounting behavior; replace only the network transport."""

    def _initialize_client(self):
        return None

    def __init__(self, *, failure="extraction", status=503, fail_all=False, recover_after=None):
        super().__init__(provider="openai", model_name="local-gateway", api_key="unused")
        self.failure, self.status = failure, status
        self.fail_all, self.recover_after = fail_all, recover_after
        self.failures_raised = 0

    def _generate_openai(self, prompt, max_tokens, temperature, stop):
        view = "control_flow" if '"view_type": "control_flow"' in prompt or "The view is control_flow" in prompt else "data_flow"
        abstracting = "[Extracted Knowledge]" in prompt
        marked = "copy_1(input)" in prompt or "BAD_SOURCE" in prompt
        selected_stage = abstracting == (self.failure == "abstraction")
        should_fail = self.fail_all or (self.failure and marked and view == "data_flow" and selected_stage)
        if should_fail and (self.recover_after is None or self.failures_raised < self.recover_after):
            self.failures_raised += 1
            raise GatewayFailure(self.status)
        value = knowledge(view, abstracting)
        if marked and not abstracting:
            value["root_cause"] = "BAD_SOURCE unchecked input"
        return json.dumps(value)


class TestOfflineBatchSkips(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.samples = [source_sample(str(i), f"copy_{i}(input);\n") for i in range(5)]
        self.retry_env = patch.dict("os.environ", {"LLM_MAX_RETRIES": "3", "LLM_RETRY_BASE_DELAY": "0"})
        self.retry_env.start()
        self.addCleanup(self.retry_env.stop)
        sleeping = patch("models.llm_interface.time.sleep")
        sleeping.start()
        self.addCleanup(sleeping.stop)

    def build(self, llm, *, views=None, batch_size=2, samples=None):
        store = VectorStore()
        builder = IndexBuilder(MultiViewGenerator(llm, views), ViewDistillation(llm), store, LocalEmbedding())
        builder.build_from_dataset(self.samples if samples is None else samples, self.root, batch_size=batch_size)
        return builder, store

    def report(self):
        return json.loads((self.root / "build_report.json").read_text())

    def test_three_failed_attempts_skip_the_entire_batch_and_continue_both_views(self):
        llm = LocalGateway()
        builder, store = self.build(llm)
        report = self.report()
        self.assertEqual(llm.failures_raised, 3)
        self.assertEqual(report["status"], "complete_with_skips")
        skipped = report["skipped_batches"][0]
        self.assertEqual(skipped["sample_ids"], ["0", "1"])
        self.assertEqual(skipped["failed_sample_id"], "1")
        self.assertEqual(skipped["attempts"], 3)
        self.assertEqual(skipped["stage"], "extraction")
        self.assertEqual(report["views"]["data_flow"]["skipped_count"], 2)
        self.assertEqual([r["sample_id"] for r in store.metadata["data_flow"]], ["2", "3", "4"])
        self.assertEqual(len(store.metadata["control_flow"]), 5)
        self.assertFalse((self.root / "cache/data_flow/batch_00000.npz").exists())
        self.assertTrue((self.root / "cache/data_flow/batch_00001.npz").exists())
        self.assertTrue((self.root / "checkpoint.json").exists())
        restored = VectorStore()
        restored.load(self.root)
        self.assertEqual(restored.get_statistics("data_flow")["total_vectors"], 3)
        self.assertEqual(builder.build_report["status"], "complete_with_skips")

    def test_resume_repairs_only_skipped_batches_and_preserves_later_caches(self):
        self.build(LocalGateway())
        previous = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.glob("cache/*/batch_*.*")}
        llm = LocalGateway(failure=None)
        self.build(llm)
        self.assertEqual(llm.request_attempt_count, 4)  # Two samples in the one missing batch.
        self.assertEqual(self.report()["status"], "complete")
        self.assertFalse(self.report()["skipped_batches"])
        self.assertFalse((self.root / "checkpoint.json").exists())
        self.assertEqual(previous, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in previous})
        self.assertTrue((self.root / "failures.jsonl").read_text().strip())
        restored = VectorStore()
        restored.load(self.root)
        self.assertEqual(len(restored.metadata["data_flow"]), 5)

    def test_exhausted_abstraction_also_advances_to_next_batch(self):
        llm = LocalGateway(failure="abstraction")
        self.build(llm, views=["data_flow"], batch_size=1)
        report = self.report()
        self.assertEqual(report["skipped_batches"][0]["stage"], "abstraction")
        self.assertEqual(report["views"]["data_flow"]["count"], 4)
        checkpoint = json.loads((self.root / "checkpoint.json").read_text())
        self.assertEqual(checkpoint["batch_idx"], 5)
        self.assertEqual(checkpoint["cached_batches"], 4)
        self.assertEqual(checkpoint["skipped_batches"], 1)

    def test_authentication_failure_still_stops_without_skipping(self):
        llm = LocalGateway(status=401)
        with self.assertRaises(LLMAuthError):
            self.build(llm)
        self.assertEqual(llm.failures_raised, 1)
        self.assertEqual(self.report()["status"], "failed")
        self.assertFalse(self.report()["skipped_batches"])
        self.assertFalse((self.root / "cache/data_flow/batch_00001.npz").exists())

    def test_non_retryable_request_failure_is_not_treated_as_retry_exhaustion(self):
        llm = LocalGateway(status=400)
        with self.assertRaises(LLMError) as caught:
            self.build(llm)
        self.assertNotIsInstance(caught.exception, LLMRetryExhaustedError)
        self.assertEqual(llm.failures_raised, 1)
        self.assertEqual(self.report()["status"], "failed")
        self.assertFalse(self.report()["skipped_batches"])

    def test_all_batches_can_be_skipped_without_fabricating_vectors(self):
        llm = LocalGateway(fail_all=True)
        _, store = self.build(llm, samples=self.samples[:2], batch_size=1)
        report = self.report()
        self.assertEqual(len(report["skipped_batches"]), 4)
        self.assertEqual(llm.request_attempt_count, 12)
        self.assertTrue(all(not rows for rows in store.metadata.values()))
        self.assertFalse(list(self.root.glob("cache/*/batch_*.npz")))
        restored = VectorStore()
        restored.load(self.root)
        self.assertTrue(all(restored.get_statistics(v)["total_vectors"] == 0 for v in restored.get_available_views()))

    def test_request_that_recovers_on_third_attempt_keeps_the_batch(self):
        llm = LocalGateway(recover_after=2)
        self.build(llm, views=["data_flow"])
        self.assertEqual(llm.failures_raised, 2)
        self.assertEqual(self.report()["status"], "complete")
        self.assertEqual(self.report()["views"]["data_flow"]["count"], 5)
        self.assertFalse(self.report()["skipped_batches"])

    def test_invalid_knowledge_retries_then_records_skipped_batches(self):
        llm = LocalGateway(failure=None)
        with patch.object(llm, "_generate_openai", return_value='{"root_cause": "incomplete"}'):
            self.build(llm)
        self.assertEqual(self.report()["status"], "complete_with_skips")
        self.assertEqual(len(self.report()["skipped_batches"]), 6)
        self.assertEqual(llm.request_attempt_count, 18)
        self.assertTrue(all(batch["reason"] == "knowledge_validation_retries_exhausted"
                            for batch in self.report()["skipped_batches"]))


if __name__ == "__main__":
    unittest.main()
