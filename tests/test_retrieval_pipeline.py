"""Hand-checkable recall, BM25, mixed ranking, and prompt injection checks."""

from copy import deepcopy
import json
import math
from types import SimpleNamespace
import unittest

import numpy as np

from Online.phase2_retrieval import QueryGenerator, Retriever, Reranker
from Online.phase2_retrieval.reranker import (
    behavior_document,
    bm25_scores,
    tokenize_behavior,
)
from Online.phase3_repair import RepairAgent
from tests.diagnostic_fixtures import diagnostic_report
from tests.offline_fixtures import LocalEmbedding
from tests.retrieval_fixtures import candidate, LocalCodeEncoder
from utils.exemplars import render_exemplars


class TestRootCauseQueries(unittest.TestCase):
    def test_api_query_view_is_no_longer_supported(self):
        with self.assertRaises(ValueError):
            QueryGenerator(SimpleNamespace(), ["api_semantic"])

    def test_llm_only_queries_consume_the_root_cause_report(self):
        report = diagnostic_report()
        report.update(
            mode="llm_only",
            facts=[],
            tool_calls=[],
            termination_reason="report_completed",
            root_causes_by_view={"data_flow": "REPORT_ROOT_CAUSE"},
        )
        prompts = []

        def generate(prompt, **kwargs):
            prompts.append(prompt)
            return '{"view":"data_flow","root_cause":"unchecked length"}'

        QueryGenerator(
            SimpleNamespace(generate=generate), ["data_flow"]
        ).generate_queries(report)
        self.assertIn("REPORT_ROOT_CAUSE", prompts[0])

    def test_structured_queries_use_report_and_same_root_cause_abstraction(self):
        prompts = []

        def generate(prompt, **kwargs):
            prompts.append(prompt)
            view = (
                "control_flow"
                if "Generate a reusable control_flow" in prompt
                else "data_flow"
            )
            return json.dumps(
                dict(view=view, root_cause="unchecked input length reaches memcpy")
            )

        queries = QueryGenerator(SimpleNamespace(generate=generate)).generate_queries(
            diagnostic_report("input length reaches memcpy")
        )
        self.assertEqual(list(queries), ["data_flow", "control_flow"])
        self.assertEqual(
            queries["data_flow"]["root_cause"], "unchecked input length reaches memcpy"
        )
        self.assertEqual(queries["data_flow"]["source"], "generated")
        self.assertTrue(
            all("[FACTS]" in prompt and "unverified" in prompt for prompt in prompts)
        )

    def test_malformed_generation_uses_only_labeled_view_hypothesis(self):
        report = diagnostic_report()
        report["root_causes_by_view"] = {"data_flow": "possible unchecked length"}
        model = SimpleNamespace(generate=lambda *a, **k: "<html>gateway error</html>")
        result = QueryGenerator(model, ["data_flow"]).generate_queries(report)
        self.assertEqual(result["data_flow"]["root_cause"], "possible unchecked length")
        self.assertEqual(result["data_flow"]["source"], "diagnostic_hypothesis")
        with self.assertRaises(ValueError):
            QueryGenerator(model, ["control_flow"]).generate_queries(report)

    def test_wrong_view_or_duplicate_json_field_is_not_a_query(self):
        for response in (
            '{"view":"control_flow","root_cause":"x"}',
            '{"view":"data_flow","root_cause":"x","root_cause":"y"}',
        ):
            with self.assertRaises(ValueError):
                QueryGenerator(
                    SimpleNamespace(generate=lambda *a, **k: response), ["data_flow"]
                ).generate_queries(diagnostic_report())


class TestRecall(unittest.TestCase):
    def store(self):
        metadata = {view: [] for view in ("data_flow", "control_flow")}
        for index in range(12):
            item = candidate(f"{index:02}")
            for view in metadata:
                metadata[view].append(
                    {**item, **item["views"][view], "view_type": view}
                )
        calls = []

        def search(view, embedding, k):
            calls.append((view, k))
            records = (
                metadata[view][:10] if view == "data_flow" else metadata[view][2:12]
            )
            return np.arange(len(records)) / 10, records

        return (
            SimpleNamespace(
                metadata=metadata,
                search=search,
                get_available_views=lambda: list(metadata),
            ),
            calls,
        )

    def test_top_ten_per_view_union_deduplicates_and_loads_both_views(self):
        store, calls = self.store()
        embedding = LocalEmbedding()
        results = Retriever(store, embedding).retrieve(
            {
                view: dict(view=view, root_cause=view + " root")
                for view in store.metadata
            }
        )
        self.assertEqual(calls, [("data_flow", 10), ("control_flow", 10)])
        self.assertEqual(embedding.texts, ["data_flow root", "control_flow root"])
        self.assertEqual(len(results), 12)
        self.assertEqual(sum(len(item["retrieval_hits"]) for item in results), 20)
        self.assertEqual(
            results[2]["retrieval_hits"],
            [
                {
                    "query_view": "data_flow",
                    "index_view": "data_flow",
                    "rank": 3,
                    "distance": 0.2,
                },
                {
                    "query_view": "control_flow",
                    "index_view": "control_flow",
                    "rank": 1,
                    "distance": 0.0,
                },
            ],
        )
        self.assertTrue(
            all(set(item["views"]) == {"data_flow", "control_flow"} for item in results)
        )
        self.assertNotIn("knowledge_by_view", results[0])

    def test_inconsistent_source_pair_cannot_share_stable_id(self):
        store, _ = self.store()
        store.metadata["control_flow"][0]["fixed_code"] = "different fix"
        with self.assertRaises(ValueError):
            Retriever(store, LocalEmbedding())

    def test_missing_index_fails_instead_of_silently_changing_recall(self):
        store, _ = self.store()
        with self.assertRaises(ValueError):
            Retriever(store, LocalEmbedding()).retrieve(
                {"missing": dict(view="missing", root_cause="root")}
            )


class TestMixedRanking(unittest.TestCase):
    def test_bm25_matches_hand_calculation(self):
        raw, normalized, stats = bm25_scores(
            "memcpy memcpy", ["memcpy length", "guard"], k1=1.5, b=0.75
        )
        expected = math.log(2) * 2.5 / (1 + 1.5 * (0.25 + 0.75 * 2 / 1.5))
        self.assertAlmostEqual(raw[0], expected)
        self.assertEqual(raw[1], 0)
        self.assertEqual(normalized, [1.0, 0.0])
        self.assertEqual(stats["document_lengths"], [2, 1])
        self.assertEqual(
            tokenize_behavior("readHTTPValue buffer_size memcpy"),
            ["read", "http", "value", "buffer", "size", "memcpy"],
        )

    def test_empty_no_overlap_single_and_equal_scores_are_finite_zero(self):
        for docs in ([], [""], ["memcpy"], ["memcpy", "memcpy"], ["other", ""]):
            _, normalized, _ = bm25_scores("memcpy", docs)
            self.assertEqual(normalized, [0.0] * len(docs))

    def test_formula_input_separation_and_ascending_presentation(self):
        a, b = candidate("a"), candidate("b")
        b["views"] = deepcopy(a["views"])
        for payload in b["views"].values():
            payload["abstracted_knowledge"].update(
                risky_calls=["guard"],
                taint_flow=(
                    "guard" if "taint_flow" in payload["abstracted_knowledge"] else None
                ),
                control_branch=(
                    "guard"
                    if "control_branch" in payload["abstracted_knowledge"]
                    else None
                ),
            )
        encoder = LocalCodeEncoder([[1, 0], [0.6, 0.8], [1, 0]])
        ranker = Reranker(encoder)
        original = deepcopy([a, b])
        result = ranker.rerank(
            diagnostic_report("memcpy input length"), "TARGET_SOURCE_SENTINEL", [a, b]
        )
        self.assertEqual([item["sample_id"] for item in result], ["b", "a"])
        self.assertAlmostEqual(result[0]["rerank_score"], 0.3)
        self.assertAlmostEqual(result[1]["rerank_score"], 0.3 * 0.6 + 0.7)
        self.assertEqual([a, b], original)
        self.assertEqual(
            encoder.calls[0],
            ["TARGET_SOURCE_SENTINEL", a["buggy_code"], b["buggy_code"]],
        )
        self.assertNotIn("TARGET_SOURCE_SENTINEL", ranker.last_run["behavioral_query"])
        for item in result:
            self.assertEqual(item["behavior_document"], behavior_document(item))
            for excluded in (
                "vulnerable_",
                "checked_",
                "validate the length",
                "unsafe n",
            ):
                self.assertNotIn(excluded, item["behavior_document"])
        self.assertEqual(ranker.last_run["bm25_statistics"]["document_count"], 2)

    def test_top_four_ties_use_ids_and_keep_negative_cosine(self):
        encoder = LocalCodeEncoder([[1, 0]] + [[-1, 0]] * 6)
        ranker = Reranker(encoder)
        results = ranker.rerank(
            diagnostic_report("no match"), "target", [candidate(i) for i in "fedcba"]
        )
        self.assertEqual([item["sample_id"] for item in results], list("abcd"))
        self.assertTrue(all(item["rerank_score"] == -0.3 for item in results))

    def test_encoder_failure_or_invalid_vectors_does_not_produce_fake_scores(self):
        for vectors in ([[0, 0], [0, 0]], [[1, 0], [float("nan"), 1]], [[1, 0]]):
            with self.assertRaises(ValueError):
                Reranker(LocalCodeEncoder(vectors)).rerank(
                    diagnostic_report(), "target", [candidate()]
                )
        encoder = LocalCodeEncoder()
        encoder.encode = lambda codes: (_ for _ in ()).throw(
            RuntimeError("model unavailable")
        )
        with self.assertRaises(RuntimeError):
            Reranker(encoder).rerank(diagnostic_report(), "target", [candidate()])


class TestKnowledgeInjection(unittest.TestCase):
    def test_four_high_score_examples_keep_full_source_patch_and_knowledge(self):
        examples = [candidate(str(index), 0.99 - index / 100) for index in range(4)]
        examples[0]["buggy_code"] += "X" * 1500 + "SOURCE_TAIL"
        examples[0]["patch"] += " context\n" * 200 + "+PATCH_TAIL\n"
        agent = RepairAgent(SimpleNamespace(), None)
        prompt = agent._build_initial_prompt(
            "int main(void) { return 0; }", examples, diagnostic_report()
        )
        self.assertEqual(prompt.count("(sample_id="), 4)
        self.assertIn("SOURCE_TAIL", prompt)
        self.assertIn("+PATCH_TAIL", prompt)
        self.assertIn("fixing_strategy", prompt)
        self.assertIn("control_branch", prompt)
        self.assertIn("taint_flow", prompt)
        self.assertIn("memcpy: input length controls the write", prompt)
        records = agent.last_rendered_exemplars
        self.assertEqual([item["sample_id"] for item in records], ["3", "2", "1", "0"])
        for record in records:
            self.assertIn(record["rendered_text"], prompt)
            self.assertFalse(record["clipping"]["truncated"])
            self.assertEqual(record["clipping"]["strategy"], "full_example")

    def test_limit_selects_best_before_ascending_render_and_resets_between_calls(self):
        examples = [candidate("a", 0.1), candidate("b", 0.8), candidate("c", 0.9)]
        _, records = render_exemplars(examples, 2)
        self.assertEqual([item["sample_id"] for item in records], ["b", "c"])
        agent = RepairAgent(SimpleNamespace(), None)
        agent._build_initial_prompt("int x;", examples, diagnostic_report())
        agent._build_initial_prompt("int x;", [], diagnostic_report())
        self.assertEqual(agent.last_rendered_exemplars, [])
