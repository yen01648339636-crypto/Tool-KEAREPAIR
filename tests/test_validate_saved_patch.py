"""Saved-patch replay must reject changed inputs and preserve previous evidence."""

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from Online.phase3_repair import Validator
from scripts import validate_saved_patch as replay
from utils.experiment_store import digest
from utils.validation import finish_validation


SOURCE = "int main(void) { return 0; }\n"
DIFF = "--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n-int main(void) { return 0; }\n+int main(void) { return 1; }\n"
RAW = "```diff\n" + DIFF + "```"


class TestSavedPatchValidation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.case = self.root / "engine/cases/CVE-fixture"
        self.candidate = self.case / "attempts/8"
        self.candidate.mkdir(parents=True)
        (self.case / "source.original").write_bytes(SOURCE.encode())
        self.write_json(self.case / "source.json", {"sha256": digest(SOURCE)})
        self.write_json(self.case / "inputs.json", {"effective_validation": {
            "cve_id": "CVE-fixture", "repo_relpath": "source.c",
            "docker_image": "fixture:no-network",
        }})
        self.write_json(self.candidate / "attempt.json", {
            "patch": DIFF, "raw_response": RAW,
            "validation_result": {"raw_patch_hash": digest(RAW),
                                  "effective_patch_hash": digest(DIFF)},
        })
        (self.candidate / "effective.patch").write_bytes(DIFF.encode())
        (self.candidate / "raw.patch").write_bytes(RAW.encode())
        (self.case.parents[1] / "config_snapshot.yaml").write_text(yaml.safe_dump({
            "online": {"phase3_repair": {"validation": {
                "compiler": "gcc", "compile_timeout": 30, "test_timeout": 60,
            }}},
        }))

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value))

    def test_load_preserves_raw_response_and_effective_patch(self):
        source, diff, raw, prepared, _, info, _ = replay.load_candidate(self.case, 8)
        self.assertEqual((source, diff, raw), (SOURCE, DIFF, RAW))
        self.assertEqual(prepared.patch, DIFF)
        self.assertEqual(info["raw_patch_hash"], digest(RAW))
        self.assertEqual(info["candidate_id"], "8")

    def test_changed_source_or_candidate_is_rejected_before_validation(self):
        for path in (self.case / "source.original", self.candidate / "raw.patch",
                     self.candidate / "effective.patch"):
            with self.subTest(path=path.name):
                saved = path.read_bytes()
                path.write_bytes(saved + b"changed")
                with patch.object(replay, "ProgressValidator") as validator:
                    with self.assertRaises(ValueError):
                        replay.validate_saved(self.case, 8, self.root / "new")
                    validator.assert_not_called()
                self.assertFalse((self.root / "new").exists())
                path.write_bytes(saved)

    def test_incomplete_validation_is_saved_without_changing_original_history(self):
        before = {p.relative_to(self.case): p.read_bytes()
                  for p in self.case.rglob("*") if p.is_file()}
        validator = Validator(execution_mode="local")

        def unavailable(original, fixed, diff, info, result):
            result["error_log"] = "Docker unavailable in fixture"
            return finish_validation(result)

        output = self.root / "independent"
        with patch.object(replay, "ProgressValidator", return_value=validator), \
                patch.object(validator, "_validate_in_docker", side_effect=unavailable), \
                redirect_stdout(StringIO()):
            result = replay.validate_saved(self.case, 8, output)
        self.assertFalse(result["success"])
        self.assertEqual(result["stage_status"]["patch_apply"], "passed")
        self.assertEqual(result["stage_status"]["poc"], "not_run")
        self.assertEqual(result["model_calls"], 0)
        self.assertTrue((output / "cases/CVE-fixture/attempts/8/validation.json").is_file())
        self.assertEqual(json.loads((output / "revalidation.json").read_text()), result)
        self.assertEqual(before, {p.relative_to(self.case): p.read_bytes()
                                  for p in self.case.rglob("*") if p.is_file()})
        with patch.object(replay, "ProgressValidator") as factory:
            with self.assertRaisesRegex(ValueError, "new output directory"):
                replay.validate_saved(self.case, 8, output)
            factory.assert_not_called()

    def test_environment_setup_error_is_saved_for_platform_feedback(self):
        output = self.root / "unavailable"
        with patch.object(replay, "ProgressValidator", side_effect=RuntimeError("Docker daemon unavailable")), \
                redirect_stdout(StringIO()):
            with self.assertRaisesRegex(RuntimeError, "Docker daemon unavailable"):
                replay.validate_saved(self.case, 8, output)
        summary = json.loads((output / "revalidation.json").read_text())
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["error"], "Docker daemon unavailable")
        self.assertNotIn("success", summary)
