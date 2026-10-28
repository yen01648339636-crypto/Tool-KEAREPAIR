"""CLI smoke checks stop at model startup; no external model or dataset is needed."""

import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

import utils.logger  # Load before patch.dict snapshots sys.modules.
from utils.experiment_manifest import ManifestMismatchError
from tests.offline_fixtures import KnowledgeLLM, LocalEmbedding, source_sample
from tests.diagnostic_fixtures import ScriptedChatModel, call


ROOT = Path(__file__).resolve().parents[1]


class ModelStartupReached(Exception):
    pass


class TestCLIIdentity(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.calls = []
        dotenv = ModuleType("dotenv")
        dotenv.load_dotenv = lambda *a, **k: None
        models = ModuleType("models")

        def start_model(**kwargs):
            self.calls.append(kwargs)
            raise ModelStartupReached()

        models.LLMInterface = start_model
        models.EmbeddingModel = models.CodeEncoder = object
        interface = ModuleType("models.llm_interface")
        interface.LLMAuthError = type("LLMAuthError", (RuntimeError,), {})
        interface.LLMError = type("LLMError", (RuntimeError,), {})
        loader = ModuleType("data_loader")

        loader.BigVulLoader = lambda *a: SimpleNamespace(
            load_records=lambda: [source_sample()]
        )
        chat = ModuleType("models.chat")
        chat.create_diagnostic_models = lambda *a: (_ for _ in ()).throw(
            RuntimeError("Diagnostic model initialization was not expected")
        )
        self.modules = {
            "dotenv": dotenv,
            "models": models,
            "models.llm_interface": interface,
            "models.chat": chat,
            "data_loader": loader,
        }

    def run_cli(self, script, args):
        paths = SimpleNamespace(raw_data=self.root / "raw")
        with patch.dict(sys.modules, self.modules), patch(
            "config.paths.ProjectPaths", return_value=paths
        ), patch("utils.logger.setup_logger"), patch.object(
            sys, "argv", [script, *args]
        ):
            runpy.run_path(str(ROOT / script), run_name="__main__")

    def test_offline_manifest_uses_effective_overrides_and_blocks_before_model_startup(
        self,
    ):
        data = self.root / "samples.csv"
        data.write_text("input-data")
        output = self.root / "offline"
        args = [
            "--config",
            str(ROOT / "config/offline.yaml"),
            "--data-path",
            str(data),
            "--output-dir",
            str(output),
            "--llm-provider",
            "mock",
            "--llm-model",
            "custom-model",
            "--batch-size",
            "1",
            "--views",
            "control_flow",
        ]
        with self.assertRaises(ModelStartupReached):
            self.run_cli("scripts/run_offline.py", args)
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(
            manifest["config"]["models"]["llm"]["model_name"], "custom-model"
        )
        self.assertEqual(manifest["parameters"]["views"], ["control_flow"])
        self.assertEqual(self.calls[0]["provider"], "mock")
        self.assertEqual(self.calls[0]["temperature_policy"], "omit")
        self.assertEqual(
            self.calls[0]["token_limit_parameter"], "max_completion_tokens"
        )
        data.write_text("modified-input")
        with self.assertRaises(ManifestMismatchError):
            self.run_cli("scripts/run_offline.py", args)
        self.assertEqual(len(self.calls), 1)

    def test_online_identity_binds_ablation_and_no_resume_cannot_bypass_it(self):
        case = self.root / "CVE-1"
        case.mkdir()
        (case / "source.c").write_text("int main(void) { return 0; }\n")
        output = self.root / "online"
        indices = self.root / "indices"
        indices.mkdir()
        args = [
            "--config",
            str(ROOT / "config/online.yaml"),
            "--vul-files-dir",
            str(case),
            "--output-dir",
            str(output),
            "--llm-provider",
            "mock",
            "--no-retrieval",
            "--indices-dir",
            str(indices),
        ]
        # The existing entry point sets its temp root globally; restore it for other tests.
        import os
        import tempfile as temporary_module

        with patch.dict(os.environ), patch.object(
            temporary_module, "tempdir", temporary_module.tempdir
        ):
            with self.assertRaises(ModelStartupReached):
                self.run_cli("scripts/run_online.py", args)
            manifest = json.loads((output / "manifest.json").read_text())
            checkpoint = json.loads((output / "checkpoint.json").read_text())
            self.assertEqual(manifest["experiment_id"], checkpoint["experiment_id"])
            self.assertTrue(
                manifest["config"]["experiment"]["variant"] == "no_retrieval"
            )
            with self.assertRaises(ManifestMismatchError):
                self.run_cli(
                    "scripts/run_online.py",
                    ["--no-diagnosis" if x == "--no-retrieval" else x for x in args]
                    + ["--no-resume"],
                )
            self.assertEqual(len(self.calls), 1)

    def test_invalid_offline_data_stops_before_model_initialization(self):
        self.modules["data_loader"].BigVulLoader = lambda *a: SimpleNamespace(
            load_records=lambda: [source_sample(cve_description="")]
        )
        data, output = self.root / "invalid.csv", self.root / "invalid-index"
        data.write_text("invalid source pair")
        with self.assertRaises(SystemExit) as caught:
            self.run_cli(
                "scripts/run_offline.py",
                ["--data-path", str(data), "--output-dir", str(output)],
            )
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.calls, [])
        self.assertFalse(output.exists())
        report = json.loads(
            (self.root / "invalid-index.dataset_report.json").read_text()
        )
        self.assertEqual(report["counts"]["failed"], 1)

    def test_writing_derived_baseline_cache_does_not_change_cli_data_identity(self):
        from utils.experiment_manifest import write_json_atomic
        from tests.test_source_baseline import record
        case = self.root / "CVE-cache"
        source = case / "src/parser.c"
        source.parent.mkdir(parents=True)
        source.write_text("int value;\n")
        (case / "test_cmds.json").write_text(json.dumps(record()))
        output = self.root / "cache-output"

        def checked(*args, **kwargs):
            write_json_atomic(case / "source_baseline.json", {"derived": True})
            return {"status": "verified"}

        args = ["--vul-files-dir", str(case), "--output-dir", str(output),
                "--stage", "diagnosis", "--llm-provider", "mock", "--no-retrieval"]
        with patch("utils.source_baseline.ensure_source_baseline", side_effect=checked):
            for _ in range(2):
                with self.assertRaises(ModelStartupReached):
                    self.run_cli("scripts/run_online.py", args)
        self.assertEqual(len(self.calls), 2)
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertFalse(any(key.endswith("/source_baseline.json") for key in manifest["data"]))

    def test_source_mismatch_stops_every_online_stage_before_model_initialization(self):
        from utils.source_baseline import SourceBaselineError
        case = self.root / "CVE-baseline"
        case.mkdir()
        (case / "source.c").write_text("int x;\n")
        (case / "test_cmds.json").write_text(json.dumps({"source_file": "source.c", "docker_image": "fixture:tag"}))
        for stage in ("all", "diagnosis", "retrieval", "repair"):
            output = self.root / ("mismatch-" + stage)
            with self.subTest(stage=stage), patch("utils.source_baseline.ensure_source_baseline",
                    side_effect=SourceBaselineError("fixture source mismatch")):
                self.run_cli("scripts/run_online.py", ["--vul-files-dir", str(case),
                    "--output-dir", str(output), "--stage", stage,
                    "--llm-provider", "mock", "--no-retrieval"])
            self.assertEqual(self.calls, [])
            result = json.loads((output / "cases/CVE-baseline/result.json").read_text())
            self.assertEqual(result["status"], "error")
            self.assertIn("fixture source mismatch", result["error"])
            self.assertFalse(list((output / "cases/CVE-baseline/attempts").glob("*")))

    def test_incomplete_docker_case_cannot_bypass_baseline_before_diagnosis(self):
        case = self.root / "CVE-no-image"
        case.mkdir()
        (case / "source.c").write_text("int x;\n")
        (case / "test_cmds.json").write_text(json.dumps({"source_file": "source.c"}))
        output = self.root / "no-image"
        self.run_cli("scripts/run_online.py", ["--vul-files-dir", str(case),
            "--output-dir", str(output), "--stage", "diagnosis", "--llm-provider", "mock", "--no-retrieval"])
        self.assertEqual(self.calls, [])
        result = json.loads((output / "cases/CVE-no-image/result.json").read_text())
        self.assertEqual(result["status"], "error")
        self.assertIn("配置不完整", result["error"])

    def test_malformed_case_config_never_falls_back_to_unchecked_diagnosis(self):
        case = self.root / "CVE-invalid-config"
        case.mkdir()
        (case / "source.c").write_text("int x;\n")
        for index, text in enumerate(("[1, 2]", "{}", "invalid json")):
            (case / "test_cmds.json").write_text(text)
            output = self.root / ("invalid-config-" + str(index))
            self.run_cli("scripts/run_online.py", ["--vul-files-dir", str(case),
                "--output-dir", str(output), "--stage", "diagnosis", "--llm-provider", "mock", "--no-retrieval"])
            self.assertEqual(self.calls, [])
            result = json.loads((output / "cases/CVE-invalid-config/result.json").read_text())
            self.assertEqual(result["status"], "error")
            self.assertIn("验证配置", result["error"])

    def test_explicit_missing_cases_survive_initialization_failure(self):
        cases = self.root / "input"
        (cases / "CVE-1").mkdir(parents=True)
        (cases / "CVE-1/source.c").write_text("int x;\n")
        listing = self.root / "cases.txt"
        listing.write_text("CVE-1\nCVE-MISSING\n")
        output = self.root / "failed-start"
        with self.assertRaises(ModelStartupReached):
            self.run_cli(
                "scripts/run_online.py",
                [
                    "--vul-files-dir",
                    str(cases),
                    "--case-list-file",
                    str(listing),
                    "--output-dir",
                    str(output),
                    "--llm-provider",
                    "mock",
                    "--no-retrieval",
                ],
            )
        summary = json.loads((output / "summary.json").read_text())
        self.assertEqual(summary["metrics"]["denominator"], 2)
        self.assertEqual(
            summary["metrics"]["status_counts"], {"initialization_error": 2}
        )
        fixed = json.loads((output / "cases.json").read_text())
        self.assertEqual(fixed["missing_at_selection"], ["CVE-MISSING"])
        self.assertTrue(list((output / "provenance/code").rglob("requirements.txt")))

    def test_patcheval_preserves_both_poc_and_unit_commands(self):
        case = self.root / "CVE-2024-1234"
        case.mkdir()
        (case / "source.c").write_text("int x;\n")
        (case / "test_cmds.json").write_text(
            json.dumps(
                {
                    "dataset": "PatchEval",
                    "source_file": "source.c",
                    "poc_test_cmd": "poc-command",
                    "unit_test_cmd": "unit-command",
                    "docker_image": "fixture@sha256:" + "a" * 64,
                    "workdir": "/fixture",
                    "validation_steps": [
                        {
                            "name": "build_and_poc",
                            "command": "fixture-script",
                            "covers": ["compile", "poc"],
                        }
                    ],
                }
            )
        )
        self.modules["models"].LLMInterface = lambda **kwargs: SimpleNamespace()
        model = ScriptedChatModel()
        self.modules["models.chat"].create_diagnostic_models = lambda *args: (
            model,
            model,
        )
        observed = []

        def repair(*args, **kwargs):
            observed.append(kwargs["project_info"])
            return dict(success=False, iterations=0, final_patch=None, history=[])

        from utils.source_baseline import configuration_hash, sha256
        baseline = {"source_sha256": sha256((case / "source.c").read_bytes()),
                    "configuration_sha256": configuration_hash(json.loads((case / "test_cmds.json").read_text())),
                    "docker_image_id": "sha256:" + "a" * 64}
        with patch("utils.source_baseline.ensure_source_baseline", return_value=baseline), patch("Online.phase3_repair.Validator", return_value=object()), patch(
            "Online.phase3_repair.RepairAgent",
            return_value=SimpleNamespace(repair=repair),
        ):
            self.run_cli(
                "scripts/run_online.py",
                [
                    "--vul-files-dir",
                    str(case),
                    "--output-dir",
                    str(self.root / "protocol"),
                    "--llm-provider",
                    "mock",
                    "--no-retrieval",
                ],
            )
        self.assertEqual(observed[0]["poc_test_command"], "poc-command")
        self.assertEqual(observed[0]["unit_test_command"], "unit-command")
        self.assertEqual(observed[0]["docker_image"], "fixture@sha256:" + "a" * 64)
        self.assertEqual(observed[0]["workdir"], "/fixture")
        self.assertEqual(
            observed[0]["validation_steps"][0]["covers"], ["compile", "poc"]
        )

    def test_complete_offline_cli_with_local_models_binds_the_same_manifest(self):
        import Offline.vector_store as vector_module

        if vector_module.faiss is None:
            self.skipTest("Requires local faiss-cpu")
        llm, embeddings = KnowledgeLLM(), LocalEmbedding()

        def model(**kwargs):
            llm.model_name = kwargs["model_name"]
            return llm

        self.modules["models"].LLMInterface = model
        self.modules["models"].EmbeddingModel = lambda **kwargs: embeddings
        data, output = self.root / "samples.csv", self.root / "knowledge"
        data.write_text("local fixture")
        self.run_cli(
            "scripts/run_offline.py",
            [
                "--data-path",
                str(data),
                "--output-dir",
                str(output),
                "--llm-provider",
                "mock",
            ],
        )
        report = json.loads((output / "build_report.json").read_text())
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(embeddings.texts), 2)
        self.assertEqual(len(llm.calls), 4)
        offline_summary = json.loads((output / "offline_summary.json").read_text())
        self.assertEqual(
            offline_summary["metrics"]["offline_calls"]["request_attempt_count"], 4
        )
        self.assertNotIn("online_calls", offline_summary["metrics"])

    def test_offline_cli_reports_skipped_batches_instead_of_full_completion(self):
        from utils.llm_errors import LLMRetryExhaustedError

        llm, embeddings = KnowledgeLLM(), LocalEmbedding()
        original = llm.generate

        def generate(prompt, **kwargs):
            if "copy_1(input)" in prompt and '"view_type": "data_flow"' in prompt:
                raise LLMRetryExhaustedError("fixture upstream unavailable", attempts=3)
            return original(prompt, **kwargs)

        llm.generate = generate

        def model(**kwargs):
            llm.model_name = kwargs["model_name"]
            return llm

        self.modules["models"].LLMInterface = model
        self.modules["models"].EmbeddingModel = lambda **kwargs: embeddings
        self.modules["data_loader"].BigVulLoader = lambda *args: SimpleNamespace(
            load_records=lambda: [source_sample("1", "copy_1(input);\n"), source_sample("2", "copy_2(input);\n")]
        )
        data, output = self.root / "samples.csv", self.root / "partial-knowledge"
        data.write_text("local fixture")
        self.run_cli("scripts/run_offline.py", [
            "--data-path", str(data), "--output-dir", str(output),
            "--llm-provider", "mock", "--batch-size", "1",
        ])
        report = json.loads((output / "build_report.json").read_text())
        self.assertEqual(report["status"], "complete_with_skips")
        self.assertEqual(report["views"]["data_flow"]["count"], 1)
        self.assertEqual(report["views"]["control_flow"]["count"], 2)
        runs = [json.loads(p.read_text()) for p in (output / "runs").glob("*/run.json")]
        self.assertEqual([run["status"] for run in runs], ["completed_with_skips"])

    def test_offline_interruption_updates_the_build_and_run_status(self):
        llm = KnowledgeLLM()

        def generate(*args, **kwargs):
            raise KeyboardInterrupt

        llm.generate = generate

        def model(**kwargs):
            llm.model_name = kwargs["model_name"]
            return llm

        self.modules["models"].LLMInterface = model
        self.modules["models"].EmbeddingModel = lambda **kwargs: LocalEmbedding()
        data, output = self.root / "samples.csv", self.root / "interrupted-knowledge"
        data.write_text("local fixture")
        with self.assertRaises(KeyboardInterrupt):
            self.run_cli("scripts/run_offline.py", [
                "--data-path", str(data), "--output-dir", str(output), "--llm-provider", "mock",
            ])
        report = json.loads((output / "build_report.json").read_text())
        self.assertEqual(report["status"], "interrupted")
        runs = [json.loads(p.read_text()) for p in (output / "runs").glob("*/run.json")]
        self.assertEqual([r["status"] for r in runs], ["interrupted"])

    def test_online_cli_runs_native_diagnosis_and_exports_the_new_contract(self):
        import os
        import tempfile as temporary_module

        case = self.root / "CVE-2024-1234"
        case.mkdir()
        (case / "source.c").write_text("void f(int x) {\n sink(x);\n}")
        output = self.root / "diagnosis-run"
        self.modules["models"].LLMInterface = lambda **kwargs: SimpleNamespace()
        diagnostic_model = ScriptedChatModel(
            responses=[call("inspect_api_usage", {"call": {"line": 2}})]
        )
        self.modules["models.chat"].create_diagnostic_models = lambda *a: (
            diagnostic_model,
            diagnostic_model,
        )
        repair = SimpleNamespace(
            repair=lambda *a, **k: {
                "success": False,
                "iterations": 0,
                "final_patch": None,
                "history": [],
            }
        )
        with patch.dict(os.environ), patch.object(
            temporary_module, "tempdir", temporary_module.tempdir
        ), patch("Online.phase3_repair.Validator", return_value=object()), patch(
            "Online.phase3_repair.RepairAgent", return_value=repair
        ):
            self.run_cli(
                "scripts/run_online.py",
                [
                    "--vul-files-dir",
                    str(case),
                    "--output-dir",
                    str(output),
                    "--llm-provider",
                    "mock",
                    "--no-retrieval",
                ],
            )
        results = list(output.glob("cases/*/result.json"))
        self.assertEqual(len(results), 1)
        result = json.loads(results[0].read_text())
        report = result["phase1_diagnosis"]["diagnostic_report"]
        self.assertEqual(report["tool_call_count"], 1)
        self.assertTrue(report["facts"])
        self.assertIn("evidence_id", report["facts"][0])
        self.assertTrue(list(output.rglob("diagnosis.json")))
        archive = self.root / "relocated"
        shutil.copytree(output, archive)
        shutil.rmtree(case)
        replay = subprocess.run(
            [
                sys.executable,
                "-S",
                str(archive / "provenance/code/scripts/evaluate.py"),
                "--experiment-dir",
                str(archive),
            ],
            capture_output=True,
            text=True,
            cwd=self.root,
        )
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertEqual(json.loads(replay.stdout)["denominator"], 1)

    def test_online_retrieval_scores_and_actual_prompt_examples_survive_json_export(
        self,
    ):
        import os
        import numpy as np
        from tests.retrieval_fixtures import candidate, LocalCodeEncoder

        case = self.root / "CVE-2024-1234"
        case.mkdir()
        (case / "source.c").write_text("int main(void) { return 0; }\n")
        indices, output = self.root / "indices", self.root / "retrieval-run"
        indices.mkdir()
        prompts = []

        def generate(prompt, **kwargs):
            prompts.append(prompt)
            if prompt.startswith("Analyze the vulnerable source in"):
                return json.dumps(
                    {
                        "root_causes_by_view": {
                            view: "unchecked length reaches memcpy"
                            for view in ("data_flow", "control_flow")
                        },
                        "hypotheses": ["possible unchecked length"],
                        "keywords": ["memcpy"],
                        "limitations": ["No static tools"],
                    }
                )
            if "Generate a reusable" in prompt:
                view = (
                    "control_flow"
                    if "Generate a reusable control_flow" in prompt
                    else "data_flow"
                )
                return json.dumps(
                    dict(view=view, root_cause="unchecked length reaches memcpy")
                )
            return "--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n-int main(void) { return 0; }\n+int main(void) { return 1; }\n"

        llm = SimpleNamespace(
            generate=generate, provider="mock", model_name="local", max_tokens=16384
        )
        self.modules["models"].LLMInterface = lambda **kwargs: llm
        self.modules["models"].EmbeddingModel = lambda **kwargs: LocalEmbedding()
        self.modules["models"].CodeEncoder = lambda **kwargs: LocalCodeEncoder()
        metadata = {view: [] for view in ("data_flow", "control_flow")}
        for identifier in "abcde":
            item = candidate(identifier)
            for view in metadata:
                metadata[view].append(
                    {**item, **item["views"][view], "view_type": view}
                )
        store = SimpleNamespace(
            metadata=metadata,
            load=lambda path, views=None: None,
            get_available_views=lambda: list(metadata),
            search=lambda view, embedding, k: (np.arange(5), metadata[view]),
        )
        validator = SimpleNamespace(
            validate=lambda *a: {
                "success": True,
                "stage_status": {
                    name: "passed" for name in ("patch_apply", "compile", "poc", "unit")
                },
            },
        )
        with patch.dict(os.environ), patch.object(
            tempfile, "tempdir", tempfile.tempdir
        ), patch("Offline.VectorStore", return_value=store), patch(
            "Online.phase3_repair.Validator", return_value=validator
        ):
            self.run_cli(
                "scripts/run_online.py",
                [
                    "--vul-files-dir",
                    str(case),
                    "--indices-dir",
                    str(indices),
                    "--output-dir",
                    str(output),
                    "--llm-provider",
                    "mock",
                    "--no-diagnosis",
                ],
            )
        result_files = list(output.glob("cases/*/result.json"))
        self.assertEqual(len(result_files), 1)
        result = json.loads(result_files[0].read_text())
        self.assertTrue(result["success"])
        retrieval = result["retrieval"]
        self.assertEqual(retrieval["num_candidates"], 5)
        self.assertEqual(
            retrieval["ranking"]["protocol"]["bm25"]["statistics_scope"],
            "candidate_pool",
        )
        self.assertEqual(len(retrieval["ranking"]["candidates"]), 5)
        self.assertEqual(
            [item["sample_id"] for item in retrieval["rendered_exemplars"]],
            list("abcd"),
        )
        self.assertEqual(
            [item["sample_id"] for item in retrieval["final_exemplars"]], list("abcd")
        )
        for item in retrieval["rendered_exemplars"]:
            self.assertIn(item["rendered_text"], prompts[-1])
            self.assertFalse(item["clipping"]["truncated"])
            self.assertIn("control_flow", item["views"])
        self.assertIn("root_cause", retrieval["queries"]["data_flow"])
        query_sidecar = next(output.rglob("retrieval.json")).read_text()
        self.assertNotIn("api_semantic", query_sidecar)
        archive = self.root / "positive-archive"
        shutil.copytree(output, archive)
        shutil.rmtree(case)
        shutil.rmtree(indices)
        replay = subprocess.run(
            [
                sys.executable,
                "-S",
                str(archive / "provenance/code/scripts/evaluate.py"),
                "--experiment-dir",
                str(archive),
            ],
            capture_output=True,
            text=True,
            cwd=self.root,
        )
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertEqual(json.loads(replay.stdout)["repaired_cases"], 1)

    def test_all_six_variants_execute_only_their_declared_components(self):
        import os
        from copy import deepcopy
        import numpy as np
        from tests.retrieval_fixtures import candidate, LocalCodeEncoder

        original = "void f(int n) {\n  sink(n);\n}\n"
        patch_text = "--- a/source.c\n+++ b/source.c\n@@ -2 +2 @@\n-  sink(n);\n+  checked_sink(n);\n"
        for variant in (
            "full",
            "df_only",
            "cf_only",
            "no_retrieval",
            "no_diagnosis",
            "no_iteration",
        ):
            with self.subTest(variant=variant):
                root = self.root / variant
                case, indices, output = (
                    root / "CVE-2024-1234",
                    root / "indices",
                    root / "output",
                )
                case.mkdir(parents=True)
                indices.mkdir()
                (case / "source.c").write_text(original)
                events, validation_calls = [], []
                native_model = ScriptedChatModel(
                    responses=[call("inspect_api_usage", {"call": {"line": 2}})]
                )

                def chat_models(*args):
                    events.append("chat_models")
                    return native_model, native_model

                self.modules["models.chat"].create_diagnostic_models = chat_models

                def generate(prompt, **kwargs):
                    if prompt.startswith("Analyze the vulnerable source in"):
                        events.append("llm_report")
                        return json.dumps(
                            {
                                "root_causes_by_view": {
                                    view: "possibly unchecked input length"
                                    for view in ("data_flow", "control_flow")
                                },
                                "hypotheses": ["possible missing guard"],
                                "keywords": ["sink"],
                                "limitations": ["No tools were used"],
                            }
                        )
                    if prompt.startswith("Generate a reusable"):
                        view = (
                            "control_flow"
                            if "reusable control_flow" in prompt
                            else "data_flow"
                        )
                        events.append("query:" + view)
                        return json.dumps(
                            {"view": view, "root_cause": "unchecked input length"}
                        )
                    events.append(
                        "initial"
                        if prompt.startswith("Repair the vulnerability")
                        else "refine"
                    )
                    return patch_text

                llm = SimpleNamespace(
                    generate=generate,
                    provider="mock",
                    model_name="local",
                    temperature=0.0,
                    max_tokens=16384,
                )
                self.modules["models"].LLMInterface = lambda **kwargs: llm

                def embedding(**kwargs):
                    events.append("embedding_model")
                    return LocalEmbedding()

                def code_encoder(**kwargs):
                    events.append("code_encoder")
                    return LocalCodeEncoder()

                self.modules["models"].EmbeddingModel = embedding
                self.modules["models"].CodeEncoder = code_encoder
                item = candidate("a")
                metadata = {
                    view: [
                        {
                            **deepcopy(item),
                            **deepcopy(item["views"][view]),
                            "view_type": view,
                        }
                    ]
                    for view in ("data_flow", "control_flow")
                }
                store = SimpleNamespace(
                    metadata=metadata, get_available_views=lambda: list(store.metadata)
                )

                def load(path, views=None):
                    events.append("load:" + ",".join(views))
                    store.metadata = {view: metadata[view] for view in views}

                def search(view, embedding, k):
                    events.append("search:" + view)
                    return np.array([0.25]), store.metadata[view]

                store.load, store.search = load, search

                def validate(source, patch, info):
                    validation_calls.append((source, patch))
                    events.append("validate")
                    return {
                        "success": False,
                        "stage": "test",
                        "error_log": "AssertionError: expected safe behavior",
                    }

                validator = SimpleNamespace(validate=validate)
                with patch.dict(os.environ), patch.object(
                    tempfile, "tempdir", tempfile.tempdir
                ), patch(
                    "Offline.VectorStore", return_value=store
                ) as make_store, patch(
                    "Online.phase3_repair.Validator", return_value=validator
                ):
                    self.run_cli(
                        "scripts/run_online.py",
                        [
                            "--vul-files-dir",
                            str(case),
                            "--indices-dir",
                            str(indices),
                            "--output-dir",
                            str(output),
                            "--llm-provider",
                            "mock",
                            "--variant",
                            variant,
                        ],
                    )
                result = json.loads(
                    next(output.glob("cases/*/result.json")).read_text()
                )
                count = 1 if variant == "no_iteration" else 5
                self.assertEqual(result["generation_count"], count)
                self.assertEqual(result["validation_count"], count)
                self.assertEqual(len(validation_calls), count)
                self.assertTrue(
                    all(
                        source == original and diff == patch_text
                        for source, diff in validation_calls
                    )
                )
                self.assertEqual(events.count("initial"), 1)
                self.assertEqual(events.count("refine"), count - 1)
                self.assertEqual(result["variant"], variant)
                report = result["phase1_diagnosis"]["diagnostic_report"]
                self.assertEqual(
                    report["mode"],
                    "llm_only" if variant == "no_diagnosis" else "tool_grounded",
                )
                self.assertEqual(
                    events.count("chat_models"), int(variant != "no_diagnosis")
                )
                self.assertEqual(
                    events.count("llm_report"), int(variant == "no_diagnosis")
                )
                self.assertEqual(
                    report["tool_call_count"], 0 if variant == "no_diagnosis" else 1
                )
                if variant == "no_retrieval":
                    self.assertNotIn("embedding_model", events)
                    self.assertNotIn("code_encoder", events)
                    make_store.assert_not_called()
                    self.assertFalse(
                        any(
                            event.startswith(("query:", "search:", "load:"))
                            for event in events
                        )
                    )
                    self.assertEqual(result["retrieval"]["rendered_exemplars"], [])
                else:
                    views = (
                        ["data_flow"]
                        if variant == "df_only"
                        else (
                            ["control_flow"]
                            if variant == "cf_only"
                            else ["data_flow", "control_flow"]
                        )
                    )
                    self.assertIn("load:" + ",".join(views), events)
                    self.assertEqual(
                        [event for event in events if event.startswith("query:")],
                        ["query:" + view for view in views],
                    )
                    self.assertEqual(
                        [event for event in events if event.startswith("search:")],
                        ["search:" + view for view in views],
                    )
                    self.assertEqual(
                        set(result["retrieval"]["rendered_exemplars"][0]["views"]),
                        set(views),
                    )
                self.assertIn(
                    "diagnosis_llm" if variant == "no_diagnosis" else "diagnosis_tools",
                    result["execution_trace"],
                )


if __name__ == "__main__":
    unittest.main()
