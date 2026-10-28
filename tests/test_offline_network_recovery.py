"""A disconnected gateway stops advancement while retaining caches for recovery."""

import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

import httpx
from openai import APIConnectionError

from Offline import IndexBuilder, MultiViewGenerator, VectorStore, ViewDistillation
from tests.offline_fixtures import LocalEmbedding, knowledge, source_sample
from tests.test_offline_batch_skips import GatewayFailure, LocalGateway
from utils.llm_errors import LLMConnectionError, LLMRetryExhaustedError
from utils.telemetry import Recorder, request_records


def disconnected():
    root = socket.gaierror(-3, "Temporary failure in name resolution")
    transport = httpx.ConnectError("DNS lookup failed")
    transport.__cause__ = root
    error = APIConnectionError(request=httpx.Request("POST", "https://example.invalid/v1/chat/completions"))
    error.__cause__ = transport
    return error


class DisconnectedGateway(LocalGateway):
    def __init__(self):
        super().__init__(failure=None)
        self.network_failures = 0
        self.seen_prompts = []

    def _generate_openai(self, prompt, max_tokens, temperature, stop):
        self.seen_prompts.append(prompt)
        if "copy_2(input)" in prompt:
            self.network_failures += 1
            raise disconnected()
        return super()._generate_openai(prompt, max_tokens, temperature, stop)


class TestOfflineNetworkRecovery(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.samples = [source_sample(str(i), f"copy_{i}(input);\n") for i in range(5)]
        environment = patch.dict("os.environ", {"LLM_MAX_RETRIES": "3", "LLM_RETRY_BASE_DELAY": "0"})
        environment.start()
        self.addCleanup(environment.stop)
        sleeping = patch("models.llm_interface.time.sleep")
        sleeping.start()
        self.addCleanup(sleeping.stop)

    def builder(self, llm):
        return IndexBuilder(MultiViewGenerator(llm, ["data_flow"]), ViewDistillation(llm), VectorStore(), LocalEmbedding())

    def test_connection_exhaustion_is_distinct_from_a_skippable_request(self):
        llm = LocalGateway(failure=None)
        with Recorder(self.root).activate(), patch.object(llm, "_generate_openai", side_effect=disconnected()):
            with self.assertRaises(LLMConnectionError) as caught:
                llm.generate("minimal request")
        self.assertEqual(caught.exception.attempts, 3)
        self.assertNotIsInstance(caught.exception, LLMRetryExhaustedError)
        self.assertEqual([r["type"] for r in caught.exception.causes], ["APIConnectionError", "ConnectError", "gaierror"])
        records = request_records(self.root / "llm_calls.jsonl")
        self.assertEqual(len(records), 3)
        self.assertTrue(all(r["status"] == "failed" for r in records))
        self.assertTrue(all(r["connection_causes"][-1]["type"] == "gaierror" for r in records))

    def test_outage_preserves_completed_batch_and_does_not_visit_next_batches(self):
        llm = DisconnectedGateway()
        builder = self.builder(llm)
        with self.assertRaises(LLMConnectionError):
            builder.build_from_dataset(self.samples, self.root, batch_size=2)
        report = json.loads((self.root / "build_report.json").read_text())
        checkpoint = json.loads((self.root / "checkpoint.json").read_text())
        self.assertEqual(report["status"], "network_unavailable")
        self.assertEqual(report["blocked_batch"]["batch_number"], 2)
        self.assertEqual(report["blocked_batch"]["sample_ids"], ["2", "3"])
        self.assertFalse(report["skipped_batches"])
        self.assertEqual(checkpoint["batch_idx"], 1)
        self.assertEqual(llm.network_failures, 3)
        self.assertFalse(any("copy_3(input)" in p or "copy_4(input)" in p for p in llm.seen_prompts))
        self.assertTrue((self.root / "cache/data_flow/batch_00000.npz").exists())
        self.assertFalse((self.root / "cache/data_flow/batch_00001.npz").exists())

    def test_healthy_resume_reuses_completed_cache_and_retries_the_blocked_batch(self):
        with self.assertRaises(LLMConnectionError):
            self.builder(DisconnectedGateway()).build_from_dataset(self.samples, self.root, batch_size=2)
        previous = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.glob("cache/*/batch_*.*")}
        healthy = LocalGateway(failure=None)
        builder = self.builder(healthy)
        builder.build_from_dataset(self.samples, self.root, batch_size=2)
        self.assertEqual(healthy.request_attempt_count, 6)
        self.assertEqual(builder.build_report["status"], "complete")
        self.assertEqual(previous, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in previous})
        self.assertEqual(builder.build_report["views"]["data_flow"]["count"], 5)

    def test_http_503_remains_skippable_even_with_a_transport_context(self):
        error = GatewayFailure(503)
        error.__cause__ = disconnected()
        llm = LocalGateway(failure=None)
        self.assertFalse(llm._is_connection_error(error))
        with patch.object(llm, "_generate_openai", side_effect=error):
            with self.assertRaises(LLMRetryExhaustedError) as caught:
                llm.generate("minimal request")
        self.assertNotIsInstance(caught.exception, LLMConnectionError)

    def test_temporary_connection_failure_can_recover_within_three_attempts(self):
        llm = LocalGateway(failure=None)
        with patch.object(llm, "_generate_openai", side_effect=[disconnected(), disconnected(), json.dumps(knowledge())]):
            result = llm.generate("minimal request")
        self.assertEqual(json.loads(result), knowledge())
        self.assertEqual(llm.request_attempt_count, 3)

    def test_connection_details_redact_key_and_proxy_credentials(self):
        llm = LocalGateway(failure=None)
        llm.api_key = "private-key-value"
        error = httpx.ProxyError("Cannot connect to http://alice:proxy-password@proxy.invalid:7890/ private-key-value sk-example-secret")
        with Recorder(self.root).activate(), patch.object(llm, "_generate_openai", side_effect=error):
            with self.assertRaises(LLMConnectionError) as caught:
                llm.generate("minimal request")
        text = str(caught.exception) + json.dumps(caught.exception.causes) + (self.root / "llm_calls.jsonl").read_text()
        for private in ("private-key-value", "alice", "proxy-password", "sk-example-secret"):
            self.assertNotIn(private, text)
        self.assertIn("[REDACTED]", text)

    def test_keyboard_interrupt_is_not_converted_to_a_skipped_batch(self):
        llm = LocalGateway(failure=None)
        with patch.object(llm, "_generate_openai", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.builder(llm).build_from_dataset(self.samples, self.root, batch_size=2)
        report = json.loads((self.root / "build_report.json").read_text())
        self.assertFalse(report["skipped_batches"])
        self.assertFalse(list(self.root.glob("cache/*/batch_*.npz")))


if __name__ == "__main__":
    unittest.main()
