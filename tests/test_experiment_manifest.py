"""Identities include effective inputs and protect artifacts from cross-run reuse."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from utils.checkpoints import CheckpointManager
from utils.experiment_manifest import ManifestMismatchError, bind_manifest, create_manifest, validate_manifest


class TestExperimentManifest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "prompts").mkdir()
        (self.root / "prompts/query.txt").write_text("query")
        (self.root / "models").mkdir()
        (self.root / "models/model.py").write_text("version = 1\n")
        (self.root / "data.txt").write_text("one")
        self.config = {"experiment": {"mode": "standard"}, "models": {"model_name": "one", "revision": "commit-1"}}

    def manifest(self, config=None, parameters=None):
        return create_manifest("online", config or self.config, project_root=self.root, data_paths=[self.root / "data.txt"], parameters=parameters)

    def test_stable_identity_and_credential_redaction(self):
        first = self.manifest()
        self.assertEqual(first["experiment_id"], self.manifest()["experiment_id"])
        config = deepcopy(self.config)
        config["models"]["api_key"] = "sensitive"
        self.assertEqual(first["experiment_id"], self.manifest(config)["experiment_id"])
        config["models"]["headers"] = {"x-api-key": "sensitive", "Authorization": "sensitive"}
        config["models"]["base_url"] = "https://user:password@example.com/v1?api_key=sensitive&version=1"
        snapshot = self.manifest(config)
        self.assertNotIn("sensitive", json.dumps(snapshot))
        self.assertNotIn("password", json.dumps(snapshot))
        self.assertIn("version=1", snapshot["config"]["models"]["base_url"])

    def test_runtime_retry_settings_participate_in_identity(self):
        with patch.dict("os.environ", {"LLM_MAX_RETRIES": "3"}):
            first = self.manifest()
        with patch.dict("os.environ", {"LLM_MAX_RETRIES": "7"}):
            changed = self.manifest()
        self.assertNotEqual(first["experiment_id"], changed["experiment_id"])

    def test_environment_endpoint_is_recorded_without_credentials(self):
        with patch.dict("os.environ", {"OPENAI_BASE_URL": "https://user:private@example.com/v1?api_key=private"}):
            manifest = self.manifest()
        self.assertEqual(manifest["runtime"]["api_endpoints"]["OPENAI_BASE_URL"], "https://example.com/v1")
        self.assertNotIn("private", json.dumps(manifest))

    def test_changes_to_model_mode_revision_parameters_prompts_data_or_code_change_identity(self):
        first = self.manifest()["experiment_id"]
        for path, content in (("prompts/query.txt", "changed"), ("data.txt", "changed"), ("models/model.py", "version = 2")):
            file = self.root / path
            original = file.read_text()
            file.write_text(content)
            self.assertNotEqual(first, self.manifest()["experiment_id"])
            file.write_text(original)
        for section, key, value in (("models", "model_name", "two"), ("models", "revision", "commit-2"), ("experiment", "mode", "extended")):
            config = deepcopy(self.config)
            config[section][key] = value
            self.assertNotEqual(first, self.manifest(config)["experiment_id"])
        self.assertNotEqual(first, self.manifest(parameters={"views": ["data_flow"]})["experiment_id"])

    def test_mismatch_and_tampering_do_not_overwrite_existing_manifest(self):
        output = self.root / "out"
        original = bind_manifest(output, self.manifest())
        self.assertEqual(bind_manifest(output, self.manifest()), original)
        before = (output / "manifest.json").read_bytes()
        with self.assertRaises(ManifestMismatchError):
            bind_manifest(output, self.manifest(parameters={"different": True}))
        self.assertEqual((output / "manifest.json").read_bytes(), before)
        original["config"]["models"]["revision"] = "tampered"
        with self.assertRaises(ManifestMismatchError):
            validate_manifest(original)

    def test_configured_external_templates_participate_in_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "extraction.txt"
            template.write_text("first template")
            config = deepcopy(self.config)
            config["offline"] = {"multiview": {"extraction_prompts": {"data_flow": str(template)}}}
            first = self.manifest(config)
            self.assertIn(str(template), first["prompts"])
            template.write_text("second template")
            self.assertNotEqual(first["experiment_id"], self.manifest(config)["experiment_id"])

    def test_unversioned_artifacts_are_not_adopted(self):
        output = self.root / "old"
        output.mkdir()
        (output / "checkpoint.json").write_text('{"processed": {}}')
        with self.assertRaises(ManifestMismatchError):
            bind_manifest(output, self.manifest())
        self.assertFalse((output / "manifest.json").exists())

    def test_checkpoint_resume_reset_and_writes_require_matching_identity(self):
        output = self.root / "checkpoints"
        checkpoint = CheckpointManager(output, "cases", "one")
        self.assertFalse(checkpoint.load())
        checkpoint.mark("CVE-1", "success")
        checkpoint.mark("CVE-2", "failed")
        resumed = CheckpointManager(output, "cases", "one")
        self.assertTrue(resumed.load())
        self.assertTrue(resumed.is_done("CVE-1"))
        resumed.clear_failed()
        self.assertFalse(resumed.is_processed("CVE-2"))
        other = CheckpointManager(output, "cases", "two")
        for action in (other.load, other.reset, lambda: other.mark("CVE-3", "success")):
            with self.assertRaises(ManifestMismatchError):
                action()
        self.assertTrue(CheckpointManager(output, "cases", "one").load())


if __name__ == "__main__":
    unittest.main()
