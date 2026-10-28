"""Live progress observes source receipts without replacing validation evidence."""

from copy import deepcopy
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from Online.phase3_repair import Validator
from tests.container_fixtures import DockerSandbox
from utils.experiment_manifest import write_json_atomic
from utils.telemetry import Recorder


SOURCE = "value = 0\n"
DIFF = "--- a/source.py\n+++ b/source.py\n@@ -1 +1 @@\n-value = 0\n+value = 1\n"
COMMAND = '\n'.join([
    'set -e', 'bash /kea-validation/protocol.sh apply "$PWD"',
    'bash /kea-validation/protocol.sh before "$PWD"',
    'sleep .15', 'grep -q "value = 1" source.py',
    'bash /kea-validation/protocol.sh after "$PWD"',
])


class TestValidationProgress(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.snapshots = []
        self.validator = Validator()

    def capture(self, path, value):
        self.snapshots.append(deepcopy(value))
        return write_json_atomic(path, value)

    def docker(self, *, command=COMMAND, covers=None, candidate="7", wrong_source=False):
        self.validator.execution_mode = "docker"
        sandbox = DockerSandbox("value = 99\n" if wrong_source else SOURCE)
        info = dict(candidate_id=candidate, repo_relpath="source.py", docker_image="fixture:tag",
                    validation_steps=[dict(name="build_and_poc", command=command,
                                           covers=covers or ["compile", "poc"])])
        with patch.object(self.validator, "_check_docker_available"), \
                patch.object(self.validator, "_get_docker_subprocess_env", return_value={}), \
                patch.object(self.validator, "_image_identity", return_value={"image_id": "sha256:" + "a" * 64}), \
                patch("Online.phase3_repair.validator.subprocess.run", side_effect=sandbox), \
                patch("Online.phase3_repair.validator.write_json_atomic", side_effect=self.capture), \
                patch.dict("os.environ", {"KEA_STUDIO_EXECUTION_ID": "execution-fixture"}), \
                Recorder(self.root / "case", case_id="fixture").activate():
            result = self.validator.validate(SOURCE, DIFF, info)
        return result, sandbox

    def test_auto_progress_has_identity_and_real_receipt_boundaries(self):
        result, sandbox = self.docker()
        progress = json.loads((self.root / "case/validation_progress.json").read_text())
        self.assertEqual(progress["candidate_id"], "7")
        self.assertEqual(progress["execution_id"], "execution-fixture")
        self.assertFalse(progress["running"])
        self.assertEqual(progress["stage_status"]["source_prepare"], "passed")
        self.assertEqual(sandbox.commands[0][-1], COMMAND)  # No script instrumentation.
        self.assertNotIn("source_prepare", result["stage_status"])
        self.assertEqual(result["stage_details"]["source_prepare"]["steps"][0]["boundary"], "apply")
        preparing = next(s for s in self.snapshots if s.get("substep") == "source_prepare" and s["step"] == "build_and_poc")
        self.assertEqual(preparing["stage_status"]["compile"], "not_run")
        testing = next(s for s in self.snapshots if s.get("substep") == "test_command")
        self.assertEqual(testing["stage_status"]["compile"], "running")
        self.assertEqual(testing["stage_status"]["poc"], "running")
        self.assertEqual([s["sequence"] for s in self.snapshots], sorted({s["sequence"] for s in self.snapshots}))

    def test_shared_command_keeps_native_stage_durations_unknown(self):
        result, _ = self.docker(covers=["compile", "poc", "unit"])
        self.assertTrue(result["success"])
        for name in ("compile", "poc", "unit"):
            detail = result["stage_details"][name]
            self.assertIsNone(detail["duration_seconds"])
            self.assertGreater(detail["command_duration_seconds"], 0)
            self.assertEqual(len(detail["source_attestation"]["receipts"]), 3)

    def test_step_clock_is_stable_until_the_actual_boundary_changes(self):
        result = {"candidate_id": "clock", "stage_status": {}, "stage_details": {}}
        self.validator.progress_path = self.root / "clock.json"
        with patch("Online.phase3_repair.validator.write_json_atomic", side_effect=self.capture):
            self.validator._publish_progress(result, "build", True, substep="source_prepare")
            self.validator._publish_progress(result, "build", True, substep="source_prepare")
            self.validator._publish_progress(result, "build", True, substep="test_command", covers=["compile", "poc"])
        first, repeat, testing = self.snapshots
        self.assertEqual(first["step_started_at"], repeat["step_started_at"])
        self.assertEqual(testing["step_started_at"], testing["updated_at"])
        self.assertGreaterEqual(testing["step_started_at"], repeat["step_started_at"])
        self.assertEqual(testing["started_at"], first["started_at"])

    def test_no_receipt_or_foreign_source_cannot_pass_preparation(self):
        for options in ({"command": "true"}, {"wrong_source": True}):
            with self.subTest(options=options):
                self.snapshots.clear()
                result, _ = self.docker(**options)
                self.assertFalse(result["success"])
                self.assertEqual(result["stage_details"]["source_prepare"]["status"], "error")
                self.assertEqual(result["stage_status"]["patch_apply"], "error")
                self.assertFalse(any(s.get("substep") == "test_command" for s in self.snapshots))
                self.assertEqual(self.snapshots[-1]["status"], "failed")

    def test_docker_setup_failure_is_terminal_before_any_test(self):
        self.validator.execution_mode = "docker"
        self.validator.progress_path = self.root / "progress.json"
        with patch.object(self.validator, "_check_docker_available", side_effect=RuntimeError("daemon unavailable")):
            result = self.validator.validate(SOURCE, DIFF, {"repo_relpath": "source.py", "docker_image": "fixture:tag"})
        progress = json.loads(self.validator.progress_path.read_text())
        self.assertFalse(progress["running"])
        self.assertEqual(progress["stage_status"]["source_prepare"], "error")
        self.assertEqual(result["stage_status"]["compile"], "not_run")
        self.assertIn("daemon unavailable", progress["error"])

    def test_later_candidate_does_not_inherit_preparation(self):
        self.docker(covers=["compile", "poc", "unit"])
        self.snapshots.clear()
        self.validator.execution_mode = "local"
        self.validator.progress_path = self.root / "case/validation_progress.json"
        result = self.validator.validate(SOURCE, DIFF, {
            "candidate_id": "8", "repo_relpath": "source.py", "buggy_code_file": "source.py",
        })
        progress = json.loads(self.validator.progress_path.read_text())
        self.assertEqual(progress["candidate_id"], "8")
        self.assertNotIn("source_prepare", progress["stage_status"])
        self.assertNotIn("source_prepare", result["stage_details"])

    def test_timeout_clears_running_preparation_without_claiming_test_start(self):
        self.validator.execution_mode = "docker"
        self.validator.progress_path = self.root / "progress.json"
        with patch.object(self.validator, "_check_docker_available"), \
                patch.object(self.validator, "_get_docker_subprocess_env", return_value={}), \
                patch.object(self.validator, "_image_identity", return_value={"image_id": "sha256:" + "a" * 64}), \
                patch("Online.phase3_repair.validator.subprocess.run", side_effect=subprocess.TimeoutExpired(["docker"], 1)):
            result = self.validator.validate(SOURCE, DIFF, dict(
                repo_relpath="source.py", docker_image="fixture:tag",
                validation_steps=[dict(name="build_and_poc", command=COMMAND, covers=["compile", "poc"])],
            ))
        progress = json.loads(self.validator.progress_path.read_text())
        self.assertFalse(progress["running"])
        self.assertEqual(progress["stage_status"]["source_prepare"], "error")
        self.assertEqual(result["stage_status"]["unit"], "not_run")

    def test_saved_revalidation_preflight_failure_does_not_claim_preparation(self):
        from scripts import validate_saved_patch as replay
        from tests.test_validate_saved_patch import TestSavedPatchValidation as Fixture
        fixture = Fixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        inputs_path = fixture.case / "inputs.json"
        inputs = json.loads(inputs_path.read_text())
        inputs["test_commands"] = {}
        inputs_path.write_text(json.dumps(inputs))
        output = fixture.root / "new-progress"
        with patch("utils.source_baseline.needs_source_baseline", return_value=True), \
                patch("utils.source_baseline.ensure_source_baseline", side_effect=RuntimeError("source check unavailable")), \
                patch.object(replay, "ProgressValidator") as factory, \
                redirect_stdout(StringIO()):
            with self.assertRaisesRegex(RuntimeError, "source check unavailable"):
                replay.validate_saved(fixture.case, 8, output)
            factory.assert_not_called()
        progress = json.loads((output / "progress.json").read_text())
        self.assertFalse(progress["running"])
        self.assertEqual(progress["step"], "source_check")
        self.assertEqual(progress["status"], "failed")
        self.assertNotIn("source_prepare", progress["stage_status"])


if __name__ == "__main__":
    unittest.main()
