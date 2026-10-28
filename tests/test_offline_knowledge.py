"""Source integrity, structured knowledge, cache recovery, and FAISS regressions."""

import importlib
import json
from pathlib import Path
import pickle
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from data_loader import BigVulLoader
from Offline import IndexBuilder, MultiViewGenerator, ViewDistillation, VectorStore
from Online.phase2_retrieval.retriever import Retriever
from tests.offline_fixtures import (
    KnowledgeLLM,
    LocalEmbedding,
    LocalStore,
    knowledge,
    source_sample,
)
from utils.experiment_manifest import ManifestMismatchError
from utils.knowledge import (
    DatasetError,
    apply_unified_diff,
    normalize_sample,
    parse_knowledge,
    prepare_dataset,
)
from utils.llm_errors import LLMOutputValidationError
from utils.prompt_templates import load_template
from utils.schemas import ContractError, KnowledgeRecord


ROOT = Path(__file__).resolve().parents[1]


class TestSourcePairs(unittest.TestCase):
    def test_strict_diff_round_trip_including_no_final_newline(self):
        for before, after in (
            ("old\n", "new\n"),
            ("old", "new"),
            ("a\nb\nc\nd\ne\nf\ng\nh\ni\n", "A\nb\nc\nd\ne\nf\ng\nh\nI\n"),
            ("a\n", "prefix\na\n"),
            ("a\nb\n", "b\n"),
        ):
            with self.subTest(before=before):
                sample = normalize_sample(source_sample(code=before, fixed_code=after))
                self.assertEqual(apply_unified_diff(before, sample["patch"]), after)
                del sample["fixed_code"]
                self.assertEqual(normalize_sample(sample)["fixed_code"], after)

    def test_incomplete_ambiguous_or_inconsistent_diff_is_rejected(self):
        patches = [
            "new source code",
            "@@ -1 +1 @@\n-wrong\n+new\n",
            "@@ -1,2 +1 @@\n-old\n+new\n",
            "@@ -100 +100 @@\n-old\n+new\n",
            "@@ -1 +1 @@\n-old\n+new\n--- a/second\n+++ b/second\n@@ -1 +1 @@\n-old\n+new\n",
        ]
        for value in patches:
            with self.subTest(patch=value), self.assertRaises(DatasetError):
                normalize_sample(
                    source_sample(code="old\n", fixed_code="", patch=value)
                )
        with self.assertRaises(DatasetError):
            normalize_sample(
                source_sample(
                    code="old\n",
                    fixed_code="different\n",
                    patch="@@ -1 +1 @@\n-old\n+new\n",
                )
            )

    def test_missing_fields_fail_with_an_auditable_report(self):
        for update in (
            dict(cve_description=""),
            dict(fixed_code=""),
            dict(buggy_code=""),
            dict(fixed_code="copy(input);\n"),
        ):
            with self.subTest(update=update), self.assertRaises(DatasetError) as caught:
                prepare_dataset([source_sample(**update)])
            self.assertEqual(caught.exception.report["counts"]["failed"], 1)

    def test_ids_are_stable_and_dedup_exclusion_is_recorded(self):
        first = source_sample()
        first.pop("sample_id")
        second = source_sample("second", "other();\n", cve_id="CVE-2024-9999")
        forward, _ = prepare_dataset([first, second])
        reverse, _ = prepare_dataset([second, first])
        self.assertEqual(forward[0]["sample_id"], reverse[1]["sample_id"])
        samples, report = prepare_dataset(
            [first, {**first, "sample_id": "duplicate"}, second],
            excluded_cve_ids=["CVE-2024-9999"],
        )
        self.assertEqual(len(samples), 1)
        self.assertEqual(
            report["counts"],
            dict(input=3, accepted=1, duplicates=1, excluded=1, failed=0),
        )
        self.assertEqual(
            report["duplicates"][0]["kept_sample_id"], samples[0]["sample_id"]
        )
        with self.assertRaises(DatasetError):
            prepare_dataset(
                [source_sample("same"), source_sample("same", "other();\n")]
            )

    def test_loader_preserves_long_sources_and_rejects_lfs_pointer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.json"
            path.write_text(json.dumps([source_sample(code="x" * 50001)]))
            rows = BigVulLoader(path).load_records()
            self.assertEqual(len(prepare_dataset(rows)[0]), 1)
            with self.assertRaises(DatasetError):
                prepare_dataset(rows, max_code_length=50000)
            path.write_text(
                "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 123\n"
            )
            with self.assertRaisesRegex(DatasetError, "Git LFS pointer"):
                BigVulLoader(path).load_records()

    def test_aliases_and_provenance_survive_normalization(self):
        sample = normalize_sample(
            {
                "id": 12,
                "description": "unsafe input",
                "func_before": "old\n",
                "func_after": "new\n",
                "cve": "CVE-2024-1234",
                "project_name": "repo",
                "programming_language": "c",
                "commit_id": "abc",
            },
            source="input.csv",
            row_index=7,
        )
        self.assertEqual(sample["sample_id"], "12")
        self.assertEqual(
            sample["source_provenance"],
            dict(commit_id="abc", source_file="input.csv", source_row=7),
        )
        self.assertEqual(sample["language"], "c")


class TestKnowledgeGeneration(unittest.TestCase):
    def test_all_offline_templates_format_and_include_source_evidence(self):
        for path in (ROOT / "prompts/offline").rglob("*.txt"):
            self.assertTrue(load_template(path))
        llm = KnowledgeLLM()
        generator = MultiViewGenerator(llm)
        self.assertEqual(generator.VIEW_TYPES, ["data_flow", "control_flow"])
        sample = normalize_sample(source_sample())
        generator.extract_knowledge(sample, "data_flow")
        for field in ("buggy_code", "fixed_code", "cve_description"):
            self.assertIn(sample[field], llm.calls[0][0])
        with self.assertRaises(ValueError):
            MultiViewGenerator(llm, view_types=["api_semantic"])
        with self.assertRaises(ValueError):
            MultiViewGenerator(llm, view_types=["api_semantic"], mode="extended")

    def test_invalid_knowledge_never_falls_back_to_text(self):
        invalid = [
            "free prose",
            {**knowledge(), "taint_flow": ""},
            {**knowledge(), "risky_calls": "memcpy"},
            {**knowledge(), "fixing_strategy": ""},
            {**knowledge(), "extra": "field"},
            {**knowledge(), "view_type": "control_flow"},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ContractError):
                parse_knowledge(value, "data_flow")
        self.assertEqual(
            parse_knowledge(
                "```json\n" + json.dumps(knowledge()) + "\n```", "data_flow"
            ).root_cause,
            knowledge()["root_cause"],
        )
        failing = SimpleNamespace(generate=lambda *a, **k: "not JSON")
        with self.assertRaises(LLMOutputValidationError) as invalid_output:
            ViewDistillation(failing).distill_without_patch(knowledge(), "data_flow")
        self.assertIsInstance(invalid_output.exception.__cause__, ContractError)
        with self.assertRaises(ContractError):
            parse_knowledge('{"root_cause": "one", "root_cause": "two"}', "data_flow")
        discarded_calls = SimpleNamespace(
            generate=lambda *a, **k: json.dumps({**knowledge(), "risky_calls": []})
        )
        with self.assertRaises(LLMOutputValidationError) as discarded_output:
            ViewDistillation(discarded_calls).distill_without_patch(
                knowledge(), "data_flow"
            )
        self.assertIsInstance(discarded_output.exception.__cause__, ContractError)

    def test_missing_source_pair_is_rejected_before_model_call(self):
        llm = KnowledgeLLM()
        with self.assertRaises(DatasetError):
            MultiViewGenerator(llm).generate_single_view_with_patch(
                "old", "", "data_flow"
            )
        self.assertEqual(llm.calls, [])

    def test_explicit_mock_provider_respects_both_knowledge_contracts(self):
        from models.llm_interface import LLMInterface

        llm = LLMInterface(provider="mock", model_name="local-mock")
        generator, abstraction = MultiViewGenerator(llm), ViewDistillation(llm)
        for view in generator.VIEW_TYPES:
            extracted = generator.extract_knowledge(
                normalize_sample(source_sample()), view
            )
            self.assertTrue(
                abstraction.distill_without_patch(extracted, view).root_cause
            )

    def test_only_abstract_root_is_encoded_and_both_records_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            llm, embedding, store = KnowledgeLLM(), LocalEmbedding(), LocalStore()
            builder = IndexBuilder(
                MultiViewGenerator(llm), ViewDistillation(llm), store, embedding
            )
            builder.build_from_dataset([source_sample()], directory, batch_size=1)
            self.assertEqual(
                embedding.texts, [knowledge(abstracted=True)["root_cause"]] * 2
            )
            self.assertEqual(len(llm.calls), 4)
            for record in store.items:
                KnowledgeRecord.from_dict(record)
                self.assertNotEqual(
                    record["extracted_knowledge"]["root_cause"],
                    record["abstracted_knowledge"]["root_cause"],
                )
                self.assertTrue(record["fixed_code"])
                self.assertTrue(record["cve_description"])
            self.assertEqual(store.items[0]["sample_id"], store.items[1]["sample_id"])
            self.assertEqual(
                json.loads((Path(directory) / "build_report.json").read_text())[
                    "status"
                ],
                "complete",
            )

    def test_resume_restores_an_earlier_view_and_records_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            first = KnowledgeLLM()
            first.fail_control = True
            builder = IndexBuilder(
                MultiViewGenerator(first),
                ViewDistillation(first),
                LocalStore(),
                LocalEmbedding(),
            )
            with self.assertRaisesRegex(RuntimeError, "control-flow failure"):
                builder.build_from_dataset([source_sample()], directory, batch_size=1)
            report = json.loads((Path(directory) / "build_report.json").read_text())
            self.assertEqual(report["failures"][0]["stage"], "extraction")
            second, store = KnowledgeLLM(), LocalStore()
            resumed = IndexBuilder(
                MultiViewGenerator(second),
                ViewDistillation(second),
                store,
                LocalEmbedding(),
            )
            resumed.build_from_dataset([source_sample()], directory, batch_size=1)
            self.assertEqual(len(second.calls), 2)
            self.assertEqual(set(store.metadata), {"data_flow", "control_flow"})
            self.assertEqual(len(store.items), 2)
            self.assertFalse((Path(directory) / "checkpoint.json").exists())
            self.assertTrue((Path(directory) / "failures.jsonl").exists())

    def test_encoding_failure_and_zero_vectors_do_not_produce_indices(self):
        for output in (
            np.zeros((1, 384)),
            np.ones((1, 768)),
            np.full((1, 384), np.nan),
            RuntimeError("encoder failed"),
        ):
            with self.subTest(
                output=type(output)
            ), tempfile.TemporaryDirectory() as directory:
                llm = KnowledgeLLM()
                embedding = LocalEmbedding()
                with patch.object(
                    embedding,
                    "encode",
                    side_effect=output if isinstance(output, Exception) else None,
                    return_value=output,
                ):
                    builder = IndexBuilder(
                        MultiViewGenerator(llm, ["data_flow"]),
                        ViewDistillation(llm),
                        LocalStore(),
                        embedding,
                    )
                    with self.assertRaises((ValueError, RuntimeError)):
                        builder.build_from_dataset(
                            [source_sample()], directory, batch_size=1
                        )
                self.assertFalse((Path(directory) / "metadata.pkl").exists())
                self.assertEqual(
                    json.loads((Path(directory) / "build_report.json").read_text())[
                        "failures"
                    ][0]["stage"],
                    "embedding",
                )

    def test_cached_vectors_cannot_be_silently_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            llm = KnowledgeLLM()

            def builder():
                return IndexBuilder(
                    MultiViewGenerator(llm, ["data_flow"]),
                    ViewDistillation(llm),
                    LocalStore(),
                    LocalEmbedding(),
                )

            first = builder()
            first.build_from_dataset([source_sample()], directory, batch_size=1)
            path = Path(directory) / "cache/data_flow/batch_00000.npz"
            np.savez_compressed(
                path,
                embeddings=np.zeros((1, 384)),
                experiment_id=np.array(first.experiment_id),
            )
            with self.assertRaises(ManifestMismatchError):
                builder().build_from_dataset([source_sample()], directory, batch_size=1)


class TestEmbeddingSafety(unittest.TestCase):
    def test_valid_encoding_and_similarity_without_model_downloads(self):
        module = importlib.import_module("models.embeddings")
        vectors = np.eye(2, 384, dtype=np.float32)
        backend = SimpleNamespace(
            get_sentence_embedding_dimension=lambda: 384,
            encode=lambda *args, **kwargs: vectors,
        )
        with patch.object(module, "SentenceTransformer", return_value=backend):
            model = module.EmbeddingModel()
            embeddings = model.encode(["text1", "text2"])
        self.assertEqual(embeddings.shape, (2, model.get_dimension()))
        np.testing.assert_allclose(model.similarity(embeddings, embeddings), np.eye(2))

    def test_dependency_load_and_model_dimensions_fail_explicitly(self):
        module = importlib.import_module("models.embeddings")
        with patch.object(module, "SentenceTransformer", None), self.assertRaises(
            ImportError
        ):
            module.EmbeddingModel()
        with patch.object(
            module,
            "SentenceTransformer",
            return_value=SimpleNamespace(get_sentence_embedding_dimension=lambda: 768),
        ), self.assertRaises(ValueError):
            module.EmbeddingModel()

    def test_bad_model_output_is_rejected(self):
        module = importlib.import_module("models.embeddings")
        model = SimpleNamespace(
            get_sentence_embedding_dimension=lambda: 384,
            encode=lambda *a, **k: np.zeros((1, 384)),
        )
        with patch.object(module, "SentenceTransformer", return_value=model):
            with self.assertRaises(ValueError):
                module.EmbeddingModel().encode(["root cause"])


class TestVectorIntegrity(unittest.TestCase):
    def test_single_view_load_never_reads_the_other_faiss_index(self):
        module = importlib.import_module("Offline.vector_store")
        with tempfile.TemporaryDirectory() as directory:
            store = VectorStore()
            for view in ("data_flow", "control_flow"):
                store.add_vectors(view, np.ones((1, 384)), [{"sample_id": "a"}])
            store.save(directory)
            with patch.object(
                module.faiss, "read_index", wraps=module.faiss.read_index
            ) as read:
                loaded = VectorStore()
                loaded.load(directory, views=["data_flow"])
            self.assertEqual(loaded.get_available_views(), ["data_flow"])
            self.assertEqual(set(loaded.metadata), {"data_flow"})
            self.assertEqual(read.call_count, 1)
            self.assertEqual(Path(read.call_args.args[0]).name, "index_data_flow.faiss")

    def test_api_index_creation_and_metadata_are_rejected(self):
        store = VectorStore()
        with self.assertRaises(ValueError):
            store.create_index("api_semantic")
        with tempfile.TemporaryDirectory() as directory:
            store.add_vectors("data_flow", np.ones((1, 384)), [{"sample_id": "a"}])
            store.save(directory)
            metadata_path = Path(directory) / "metadata.pkl"
            payload = pickle.loads(metadata_path.read_bytes())
            payload["views"]["api_semantic"] = payload["views"].pop("data_flow")
            metadata_path.write_bytes(pickle.dumps(payload))
            with self.assertRaisesRegex(ValueError, "Invalid index metadata views"):
                VectorStore().load(directory)

    def setUp(self):
        if importlib.import_module("Offline.vector_store").faiss is None:
            self.skipTest("Requires local faiss-cpu")

    def test_search_filters_invalid_positions_with_their_distances(self):
        store = VectorStore()
        store.metadata["data_flow"] = [{"sample_id": "a"}, {"sample_id": "b"}]
        store.indices["data_flow"] = SimpleNamespace(
            d=384,
            ntotal=2,
            search=lambda *a: (
                np.array([[1.0, 2.0, 3.0, 4.0, np.nan]]),
                np.array([[0, -1, 99, 1, 0]]),
            ),
        )
        distances, results = store.search("data_flow", np.ones(384), 5)
        self.assertEqual(distances.tolist(), [1.0, 4.0])
        self.assertEqual([row["sample_id"] for row in results], ["a", "b"])

    def test_real_faiss_round_trip_and_oversized_k(self):
        with tempfile.TemporaryDirectory() as directory:
            store = VectorStore()
            store.add_vectors(
                "data_flow", np.ones((2, 384)), [{"sample_id": "a"}, {"sample_id": "b"}]
            )
            store.save(directory)
            restored = VectorStore()
            restored.load(directory)
            distances, results = restored.search("data_flow", np.ones(384), 10)
            self.assertEqual(len(distances), 2)
            self.assertEqual(len(results), 2)
            self.assertEqual(restored.get_statistics("data_flow")["dimension"], 384)
            with self.assertRaises(ValueError):
                VectorStore(dimension=768).load(directory)
            (Path(directory) / "build_report.json").write_text('{"status": "running"}')
            with self.assertRaisesRegex(ValueError, "incomplete"):
                VectorStore().load(directory)

    def test_vector_metadata_counts_are_checked_on_add_save_and_load(self):
        store = VectorStore()
        with self.assertRaises(ValueError):
            store.add_vectors("data_flow", np.ones((2, 384)), [{}])
        store.add_vectors("data_flow", np.ones((1, 384)), [{"sample_id": "a"}])
        with tempfile.TemporaryDirectory() as directory:
            store.save(directory)
            path = Path(directory) / "metadata.pkl"
            payload = pickle.loads(path.read_bytes())
            payload["views"]["data_flow"].append({"sample_id": "extra"})
            path.write_bytes(pickle.dumps(payload))
            with self.assertRaises(ValueError):
                VectorStore().load(directory)
            store.metadata["data_flow"].clear()
            with self.assertRaises(ValueError):
                store.save(directory)

    def test_inner_product_and_small_ivf_indices_keep_their_metric(self):
        with tempfile.TemporaryDirectory() as directory:
            store = VectorStore(metric="IP", index_type="IVFFlat", nlist=2)
            store.add_vectors("data_flow", np.ones((1, 384)), [{"sample_id": "a"}])
            store.save(directory)
            restored = VectorStore(metric="IP")
            restored.load(directory)
            distances, results = restored.search("data_flow", np.ones(384), 3)
            self.assertEqual(len(results), 1)
            self.assertAlmostEqual(float(distances[0]), 1.0, places=5)

    def test_single_view_hit_recovers_full_cross_view_knowledge(self):
        with tempfile.TemporaryDirectory() as directory:
            llm, store = KnowledgeLLM(), VectorStore()
            IndexBuilder(
                MultiViewGenerator(llm), ViewDistillation(llm), store, LocalEmbedding()
            ).build_from_dataset([source_sample()], directory, batch_size=1)
            candidates = Retriever(store, LocalEmbedding()).retrieve(
                {"data_flow": {"view": "data_flow", "root_cause": "unchecked length"}}
            )
            self.assertEqual(len(candidates), 1)
            self.assertEqual(set(candidates[0]["views"]), {"data_flow", "control_flow"})
            self.assertTrue(candidates[0]["fixed_code"])
            self.assertIn(
                "fixing_strategy",
                candidates[0]["views"]["control_flow"]["abstracted_knowledge"],
            )


if __name__ == "__main__":
    unittest.main()
