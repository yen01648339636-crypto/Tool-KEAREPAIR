"""Exercise real component boundaries with local models and stores."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np

from config.runtime import load_config
from Offline.index_builder import IndexBuilder
from Offline.multiview_generator import MultiViewGenerator
from Offline.distillation import ViewDistillation
from Online.phase2_retrieval.query_generator import QueryGenerator
from Online.phase3_repair.repair_agent import RepairAgent
from utils.experiment_manifest import ManifestMismatchError
from tests.offline_fixtures import (
    KnowledgeLLM,
    LocalEmbedding,
    LocalStore,
    knowledge,
    source_sample,
)
from tests.diagnostic_fixtures import diagnostic_report


ROOT = Path(__file__).resolve().parents[1]


class LocalLLM:
    provider = "mock"
    model_name = "local"
    temperature = 0.0
    max_tokens = 16384
    base_url = None

    def __init__(self):
        self.calls = []
        self.response = "<FIXED_CODE>int main(void) { return 1; }</FIXED_CODE>"

    def generate(self, prompt, **kwargs):
        self.calls.append((prompt, kwargs))
        return self.response


class TestRuntimeIntegration(unittest.TestCase):
    def test_configured_sampling_reaches_generation(self):
        config = load_config(ROOT / "config/online.yaml")
        llm = LocalLLM()
        generator = MultiViewGenerator(
            llm, view_types=["data_flow"], sampling=config["sampling"]
        )
        self.assertIsInstance(
            generator.generate_single_view("int x;", "data_flow"), str
        )
        llm.response = json.dumps(knowledge())
        generator.extract_knowledge({**source_sample(), "patch": ""}, "data_flow")
        ViewDistillation(llm, sampling=config["sampling"]).distill_without_patch(
            knowledge(), "data_flow"
        )
        llm.response = '{"view": "control_flow", "root_cause": "bounds check"}'
        query = QueryGenerator(
            llm, view_types=["control_flow"], sampling=config["sampling"]
        )
        self.assertEqual(
            list(query.generate_queries(diagnostic_report())), ["control_flow"]
        )
        self.assertEqual(len(llm.calls), 4)
        self.assertTrue(all(options["temperature"] == 0 for _, options in llm.calls))

    def test_repair_sampling_and_exemplar_limit_are_configurable(self):
        config = load_config(ROOT / "config/online.yaml")
        llm = LocalLLM()
        agent = RepairAgent(
            llm, validator=None, sampling=config["sampling"], max_exemplars=4
        )
        examples = [
            {
                "sample_id": str(i),
                "buggy_code": f"unique_example_{i}",
                "fixed_code": "fixed example",
                "patch": "fix",
                "views": {
                    "data_flow": {
                        "extracted_knowledge": knowledge(),
                        "abstracted_knowledge": knowledge(abstracted=True),
                    }
                },
                "rerank_score": 0.95,
            }
            for i in range(4)
        ]
        prompt = agent._build_initial_prompt(
            "int main(void) { return 0; }", examples, diagnostic_report("bounds")
        )
        self.assertEqual(prompt.count("unique_example_"), 4)
        agent._generate_initial_patch(
            "int main(void) { return 0; }", [], diagnostic_report("bounds")
        )
        self.assertEqual(llm.calls[-1][1]["temperature"], 0)
        agent._refine_patch(
            "int main(void) { return 0; }",
            "int main(void) { return 2; }",
            "ordinary validation failure",
            1,
        )
        self.assertEqual(llm.calls[-1][1]["temperature"], 0)

    def test_offline_cache_reuse_requires_matching_inputs_and_model(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "index"
            samples = [source_sample()]

            def builder(model="local", sampling=None):
                llm = KnowledgeLLM()
                llm.model_name = model
                generator = MultiViewGenerator(
                    llm, view_types=["data_flow"], sampling=sampling
                )
                return (
                    IndexBuilder(
                        generator, ViewDistillation(llm), LocalStore(), LocalEmbedding()
                    ),
                    llm,
                )

            first, first_llm = builder()
            first.build_from_dataset(samples, output, batch_size=1)
            self.assertEqual(len(first_llm.calls), 2)
            second, second_llm = builder()
            second.build_from_dataset(samples, output, batch_size=1)
            self.assertEqual(second_llm.calls, [])
            self.assertEqual(len(second.vector_store.items), 1)
            changed = deepcopy(samples)
            changed[0]["fixed_code"] = "different fix"
            for data, batch_size, model in (
                (changed, 1, "local"),
                (samples, 2, "local"),
                (samples, 1, "different-model"),
            ):
                instance, llm = builder(model)
                with self.assertRaises(ManifestMismatchError):
                    instance.build_from_dataset(data, output, batch_size=batch_size)
                self.assertFalse(llm.calls)
            instance, _ = builder(
                sampling={"extraction": {"temperature": 0.9, "max_tokens": 1024}}
            )
            with self.assertRaises(ManifestMismatchError):
                instance.build_from_dataset(samples, output, batch_size=1)
            first.multiview_gen.sampling = {
                "extraction": {"temperature": 0.8, "max_tokens": 1024}
            }
            with self.assertRaises(ManifestMismatchError):
                first.build_from_dataset(samples, output, batch_size=1)
            instance, _ = builder()
            instance.multiview_gen._patch_guided_prompts["data_flow"] = (
                "new prompt {patch}"
            )
            with self.assertRaises(ManifestMismatchError):
                instance.build_from_dataset(samples, output, batch_size=1)

    def test_tampered_batch_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            llm = KnowledgeLLM()
            generator = MultiViewGenerator(llm, view_types=["data_flow"])
            instance = IndexBuilder(
                generator, ViewDistillation(llm), LocalStore(), LocalEmbedding()
            )
            samples = [source_sample()]
            instance.build_from_dataset(samples, directory, batch_size=1)
            cache = Path(directory) / "cache/data_flow/batch_00000.npz"
            np.savez_compressed(
                cache, embeddings=np.ones((1, 384)), experiment_id=np.array("other")
            )
            fresh = IndexBuilder(
                generator, ViewDistillation(llm), LocalStore(), LocalEmbedding()
            )
            with self.assertRaises(ManifestMismatchError):
                fresh.build_from_dataset(samples, directory, batch_size=1)

    def test_incremental_build_records_immutable_base_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "base"
            output = Path(directory) / "extended"
            generator = MultiViewGenerator(KnowledgeLLM(), view_types=["data_flow"])
            first = IndexBuilder(
                generator,
                ViewDistillation(generator.llm),
                LocalStore(),
                LocalEmbedding(),
            )
            first.build_from_dataset([source_sample("one", "one")], base, batch_size=1)
            second = IndexBuilder(
                generator,
                ViewDistillation(generator.llm),
                LocalStore(),
                LocalEmbedding(),
            )
            with self.assertRaises(ManifestMismatchError):
                second.build_incremental([], base)
            second.build_incremental([source_sample("two", "two")], base, output)
            self.assertEqual(len(second.vector_store.items), 2)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(
                manifest["parameters"]["base_index_id"], first.experiment_id
            )
            self.assertTrue(
                any(name.endswith("base/metadata.pkl") for name in manifest["data"])
            )


if __name__ == "__main__":
    unittest.main()
