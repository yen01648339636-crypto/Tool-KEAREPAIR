"""Configuration inheritance, migration and effective CLI options."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from config.runtime import (
    ConfigurationError,
    load_config,
    normalize_config,
    resolve_offline_config,
    resolve_online_config,
)


ROOT = Path(__file__).resolve().parents[1]


class TestRuntimeConfig(unittest.TestCase):
    def test_stage_configs_resolve_inheritance(self):
        import yaml

        shared = load_config(ROOT / "config/base.yaml")
        offline = load_config(ROOT / "config/offline.yaml")
        online = load_config(ROOT / "config/online.yaml")
        with (ROOT / "config/offline.yaml").open(encoding="utf-8") as stream:
            configured_model = yaml.safe_load(stream)["models"]["llm"]["model_name"]
        self.assertEqual(
            offline["models"]["llm"]["model_name"], configured_model
        )
        with (ROOT / "config/online.yaml").open(encoding="utf-8") as stream:
            configured_online = yaml.safe_load(stream)["models"]["llm"]
        for name, value in configured_online.items():
            self.assertEqual(online["models"]["llm"][name], value)
        for config in (shared, offline, online):
            self.assertNotIn("extends", config)
            self.assertEqual(config["experiment"]["mode"], "standard")
            self.assertEqual(
                config["offline"]["multiview"]["views"], ["data_flow", "control_flow"]
            )
            self.assertEqual(
                config["online"]["phase2_retrieval"]["views"],
                ["data_flow", "control_flow"],
            )
            self.assertEqual(
                config["models"]["embeddings"]["model_name"], "all-MiniLM-L6-v2"
            )
            self.assertEqual(config["models"]["embeddings"]["dimension"], 384)
            self.assertEqual(config["online"]["phase1_diagnosis"]["max_tool_calls"], 15)
            self.assertEqual(config["online"]["phase2_retrieval"]["top_k_per_view"], 10)
            self.assertEqual(config["online"]["phase2_retrieval"]["final_top_k"], 4)
            self.assertEqual(config["online"]["phase3_repair"]["max_iterations"], 5)
            self.assertEqual(config["online"]["phase3_repair"]["max_exemplars"], 4)
            self.assertEqual(
                config["online"]["phase2_retrieval"]["reranking"]["code_weight"], 0.3
            )
            self.assertEqual(
                config["online"]["phase2_retrieval"]["reranking"]["behavior_weight"],
                0.7,
            )
            self.assertTrue(
                all(value["temperature"] == 0 for value in config["sampling"].values())
            )

    def test_stage_overrides_remain_independent_of_other_stage(self):
        import yaml

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("base.yaml", "offline.yaml", "online.yaml"):
                (root / name).write_text(
                    (ROOT / "config" / name).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            shared_path = root / "base.yaml"
            shared = yaml.safe_load(shared_path.read_text(encoding="utf-8"))
            shared["sampling"]["query"]["temperature"] = 0.4
            shared_path.write_text(yaml.safe_dump(shared), encoding="utf-8")
            with (root / "offline.yaml").open("a", encoding="utf-8") as stream:
                stream.write("\nsampling:\n  query: {temperature: 0.8}\n")
            offline = load_config(root / "offline.yaml")
            online = load_config(root / "online.yaml")
            self.assertEqual(offline["sampling"]["query"]["temperature"], 0.8)
            self.assertEqual(online["sampling"]["query"]["temperature"], 0.4)

    def test_missing_sampling_inherits_llm_settings_without_legacy_temperatures(self):
        config = load_config(ROOT / "config/base.yaml")
        config.pop("sampling")
        config["experiment"].pop("mode")
        for temperature in (0.0, 0.6):
            config["models"]["llm"]["temperature"] = temperature
            config["models"]["llm"]["max_tokens"] = 4096
            resolved = normalize_config(config)
            self.assertEqual(resolved["experiment"]["mode"], "standard")
            self.assertTrue(
                all(
                    value["temperature"] == temperature
                    for value in resolved["sampling"].values()
                )
            )
            self.assertEqual(resolved["sampling"]["query"]["max_tokens"], 1024)
            self.assertEqual(resolved["sampling"]["refine_repair"]["max_tokens"], 4096)

    def test_cli_overrides_are_resolved_without_mutating_input(self):
        original = load_config(ROOT / "config/base.yaml")
        before = deepcopy(original)
        offline = resolve_offline_config(
            original,
            provider="mock",
            model_name="test",
            base_url="https://gateway.example/v1",
            views=["control_flow"],
        )
        self.assertEqual(offline["models"]["llm"]["provider"], "mock")
        self.assertEqual(offline["offline"]["multiview"]["views"], ["control_flow"])
        for variant, section, key, expected in (
            ("no_diagnosis", "phase1_diagnosis", "enabled", False),
            ("no_retrieval", "phase2_retrieval", "enabled", False),
            ("no_iteration", "phase3_repair", "single_attempt", True),
        ):
            online = resolve_online_config(original, provider="mock", variant=variant)
            self.assertEqual(online["online"][section][key], expected)
        self.assertEqual(original, before)

    def test_retrieval_selection_changes_actual_query_views(self):
        config = load_config(ROOT / "config/base.yaml")
        config["experiment"]["mode"] = "extended"
        resolved = resolve_online_config(config, retrieval_view="data_flow")
        self.assertEqual(
            resolved["online"]["phase2_retrieval"]["views"],
            ["data_flow"],
        )
        with self.assertRaises(ConfigurationError):
            resolve_online_config(
                load_config(ROOT / "config/online.yaml"), retrieval_view="api_semantic"
            )

    def test_only_data_and_control_are_accepted_in_all_modes(self):
        for mode in ("standard", "extended"):
            for section in ("offline", "online", "prompts"):
                config = load_config(ROOT / "config/base.yaml")
                config["experiment"]["mode"] = mode
                if section == "offline":
                    config["offline"]["multiview"]["views"] = ["api_semantic"]
                elif section == "online":
                    config["online"]["phase2_retrieval"]["views"] = ["api_semantic"]
                else:
                    config["offline"]["multiview"]["extraction_prompts"][
                        "api_semantic"
                    ] = "removed.txt"
                with self.subTest(mode=mode, section=section), self.assertRaises(
                    ConfigurationError
                ):
                    normalize_config(config)

    def test_unsupported_ranking_protocol_is_rejected(self):
        for update in (
            {"normalization": "softmax"},
            {"k1": 0},
            {"b": 1.1},
            {"statistics_scope": "full_index"},
        ):
            config = load_config(ROOT / "config/base.yaml")
            config["online"]["phase2_retrieval"]["reranking"]["bm25"].update(update)
            with self.assertRaises(ConfigurationError):
                normalize_config(config)
        config = load_config(ROOT / "config/base.yaml")
        config["models"]["code_encoder"]["revision"] = "main"
        with self.assertRaises(ConfigurationError):
            normalize_config(config)

    def test_invalid_budgets_views_weights_and_booleans_fail(self):
        base = load_config(ROOT / "config/offline.yaml")
        mutations = [
            lambda c: c["online"]["phase1_diagnosis"].update(max_tool_calls=0),
            lambda c: c["offline"]["multiview"].update(
                views=["data_flow", "data_flow"]
            ),
            lambda c: c["online"]["phase2_retrieval"]["reranking"].update(
                code_weight=0.8
            ),
            lambda c: c["sampling"]["query"].update(temperature=float("nan")),
            lambda c: c["online"]["phase3_repair"].update(single_attempt="false"),
            lambda c: c["sampling"]["query"].update(temperatur=0),
            lambda c: c["offline"]["dataset"].update(max_code_length=0),
            lambda c: c["models"]["embeddings"].update(dimension=768),
            lambda c: c["offline"]["multiview"].update(views=["api_semantic"]),
        ]
        for mutation in mutations:
            config = deepcopy(base)
            mutation(config)
            with self.subTest(config=config), self.assertRaises(ConfigurationError):
                normalize_config(config)

    def test_inheritance_is_relative_and_cycles_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "first.yaml").write_text("extends: second.yaml\n")
            (root / "second.yaml").write_text("extends: first.yaml\n")
            with self.assertRaises(ConfigurationError):
                load_config(root / "first.yaml")


if __name__ == "__main__":
    unittest.main()
