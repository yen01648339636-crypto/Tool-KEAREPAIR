"""Exercise the real source protocol and archived evidence without Docker."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from Online.phase3_repair import Validator
from tests.container_fixtures import DockerSandbox
from utils.container_validation import create_payload, read_attestation
from utils.experiment_store import persist_attempt
from utils.metrics import verify_attempt
from utils.patches import prepare_patch
from utils.telemetry import Recorder


COMMAND_FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'container_commands'
ORIGINAL = 'value = 0\n'
PATCH = '--- a/source.py\n+++ b/source.py\n@@ -1 +1 @@\n-value = 0\n+value = 1\n'
INFO = {'repo_relpath': 'source.py', 'buggy_code_file': 'source.py'}
HELPER = 'bash /kea-validation/protocol.sh'
COMMAND = '\n'.join([
    'set -e',
    HELPER + ' apply "$PWD"', HELPER + ' before "$PWD"',
    'grep -q "value = 1" source.py', HELPER + ' after "$PWD"',
])


class TestSourceProtocol(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / 'project'
        self.project.mkdir()
        self.source = self.project / 'source.py'
        self.source.write_text(ORIGINAL)
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        self.payload = self.root / 'payload'
        self.fixed = prepare_patch(ORIGINAL, PATCH, 'source.py')[1]
        self.expected = create_payload(
            self.payload, ORIGINAL, self.fixed, PATCH, 'source.py', '1', 'poc',
            evidence_dir=self.evidence,
        )

    def execute(self, phase, root=None):
        return subprocess.run(
            ['bash', str(self.payload / 'protocol.sh'), phase, str(root or self.project)],
            capture_output=True, text=True, timeout=10,
        )

    def receipts(self, complete=True):
        return read_attestation(self.evidence / 'receipts.tsv', self.expected, 'sha256:fixture', complete=complete)

    def test_atomic_install_preserves_mode_and_emits_all_test_boundaries(self):
        self.source.chmod(0o750)
        for phase in ('apply', 'before', 'after'):
            self.assertEqual(self.execute(phase).returncode, 0)
        self.assertEqual(self.source.read_text(), self.fixed)
        self.assertEqual(self.source.stat().st_mode & 0o777, 0o750)
        self.assertEqual(len(self.receipts()['receipts']), 3)
        self.assertFalse(list(self.project.glob('*.candidate.*')))

    def test_wrong_container_source_is_rejected_without_modification(self):
        self.source.write_text('value = 99\n')
        output = self.execute('apply')
        self.assertNotEqual(output.returncode, 0)
        self.assertIn('container original differs', output.stderr)
        self.assertEqual(self.source.read_text(), 'value = 99\n')
        with self.assertRaises(ValueError):
            self.receipts()

    def test_second_application_and_modified_candidate_payload_are_rejected(self):
        self.assertEqual(self.execute('apply').returncode, 0)
        self.assertNotEqual(self.execute('apply').returncode, 0)
        (self.payload / 'fixed.source').write_text('value = 42\n')
        self.assertNotEqual(self.execute('before').returncode, 0)
        self.assertEqual(self.source.read_text(), self.fixed)

    def test_source_change_between_boundaries_cannot_pass(self):
        self.assertEqual(self.execute('apply').returncode, 0)
        self.assertEqual(self.execute('before').returncode, 0)
        self.source.write_text(ORIGINAL)
        self.assertNotEqual(self.execute('after').returncode, 0)
        with self.assertRaises(ValueError):
            self.receipts()

    def test_baseline_copy_can_attest_the_actual_tested_source_separately(self):
        self.assertEqual(self.execute('apply').returncode, 0)
        tested = self.root / 'tested'
        tested.mkdir()
        (tested / 'source.py').write_text(self.fixed)
        for phase in ('before', 'after'):
            self.assertEqual(self.execute(phase, tested).returncode, 0)
        receipts = self.receipts()['receipts']
        self.assertNotEqual(receipts[0]['source_path'], receipts[1]['source_path'])
        self.assertEqual(receipts[1]['source_path'], receipts[2]['source_path'])

    def test_symlink_outside_repository_cannot_be_overwritten(self):
        outside = self.root / 'outside.py'
        outside.write_text(ORIGINAL)
        self.source.unlink()
        self.source.symlink_to(outside)
        self.assertNotEqual(self.execute('apply').returncode, 0)
        self.assertEqual(outside.read_text(), ORIGINAL)

    def test_baseline_suite_attests_patched_source_and_keeps_baseline(self):
        # Execute a retained command fixture with local checkout/build doubles.
        # The suite records which bytes it actually read, including the baseline.
        case = COMMAND_FIXTURES / 'baseline_suite.json'
        script = json.loads(case.read_text())['unit_test_cmd']
        project = self.root / 'checkout'
        source = project / 'source'
        source.mkdir(parents=True)
        (source / 'parser.c').write_text(ORIGINAL)
        (source / 'autogen.sh').write_text('#!/bin/bash\nexit 0\n')
        (source / 'autogen.sh').chmod(0o755)
        patch_text = PATCH.replace('source.py', 'parser.c')
        expected = create_payload(self.payload, ORIGINAL, self.fixed, patch_text,
                                  'parser.c', '1', 'unit', evidence_dir=self.evidence)
        binaries = self.root / 'bin'
        binaries.mkdir()
        (binaries / 'vul4c').write_text('#!/bin/bash\nexit 0\n')
        checks = self.root / 'checks.log'
        (binaries / 'make').write_text(
            '#!/bin/bash\nif [[ "${1:-}" == check ]]; then\n'
            ' cat parser.c >> "$CHECKS_LOG"\n echo "suite passed"\nfi\n'
        )
        for binary in binaries.iterdir():
            binary.chmod(0o755)
        # Keep preparation intact; only relocate container paths and use the
        # prepared checkout when the stub checkout command is invoked.
        script = script.replace('/tmp/mv-bdsr-vul4c/CVE-2016-1838', str(project))
        script = script.replace('rm -rf "$PROJECT_DIR" "$TEST_SCRIPT"', 'rm -f "$TEST_SCRIPT"')
        script = script.replace('/tmp/mv_bdsr_vul4c_project_test.sh', str(self.root / 'suite.sh'))
        script = script.replace('/kea-validation', str(self.payload))
        output = subprocess.run(
            ['bash', '-c', script], capture_output=True, text=True, timeout=10,
            env={**os.environ, 'PATH': str(binaries) + ':' + os.environ['PATH'],
                 'CHECKS_LOG': str(checks)},
        )
        self.assertEqual(output.returncode, 0, output.stderr)
        receipt = read_attestation(self.evidence / 'receipts.tsv', expected, 'sha256:fixture', complete=True)
        self.assertEqual(checks.read_text(), ORIGINAL + self.fixed)
        self.assertEqual((source / 'parser.c').read_text(), ORIGINAL)
        self.assertEqual(receipt['receipts'][0]['source_path'], str(project / 'source_patched/parser.c'))
        self.assertEqual(receipt['receipts'][1]['source_path'], str(source / 'parser.c'))


class TestDockerEvidence(unittest.TestCase):
    def validate(self, command=COMMAND, *, original=ORIGINAL, save=None):
        validator = Validator()
        validator.execution_mode = 'docker'
        sandbox = DockerSandbox(original)
        with patch.object(validator, '_check_docker_available'), patch.object(
            validator, '_get_docker_subprocess_env', return_value={}
        ), patch.object(validator, '_image_identity', return_value={
            'image_id': 'sha256:' + 'a' * 64, 'repo_digests': [],
        }), patch('Online.phase3_repair.validator.subprocess.run', side_effect=sandbox):
            result = validator.validate(ORIGINAL, PATCH, {
                **INFO, 'candidate_id': '1', 'docker_image': 'fixture:tag',
                'compile_command': command, 'poc_test_command': command,
                'unit_test_command': command,
            })
        if save:
            save(result)
        return result, sandbox

    def test_each_fresh_container_installs_and_checks_the_same_candidate(self):
        result, sandbox = self.validate()
        self.assertTrue(result['success'], result)
        self.assertEqual(len(sandbox.commands), 3)
        for name in ('compile', 'poc', 'unit'):
            receipt = result['stage_details'][name]['source_attestation']
            self.assertEqual(receipt['source_hash'], result['validated_source_hash'])
            self.assertEqual(len(receipt['receipts']), 3)
        self.assertTrue(all(source == 'value = 1\n' for source in sandbox.sources))

    def test_success_exit_without_receipts_does_not_establish_validation(self):
        result, sandbox = self.validate('true')
        self.assertFalse(result['success'])
        self.assertEqual(result['stage_status']['patch_apply'], 'error')
        self.assertEqual(result['stage_status']['compile'], 'error')
        self.assertEqual(result['stage_status']['poc'], 'not_run')
        self.assertEqual(len(sandbox.commands), 1)

    def test_wrong_image_source_and_restored_source_are_rejected(self):
        result, _ = self.validate(original='value = 99\n')
        self.assertEqual(result['stage_status']['patch_apply'], 'error')
        result, _ = self.validate(COMMAND.replace(HELPER + ' after', 'echo "value = 0" > source.py\n' + HELPER + ' after'))
        self.assertFalse(result['success'])
        self.assertEqual(result['stage_status']['compile'], 'failed')

    def test_archived_receipts_are_required_and_bound_to_the_saved_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = root / 'cases' / 'case'
            case.mkdir(parents=True)
            (case / 'source.original').write_text(ORIGINAL)
            (case / 'source.json').write_text(json.dumps({'sha256': hashlib.sha256(ORIGINAL.encode()).hexdigest()}))
            (case / 'inputs.json').write_text(json.dumps({'effective_validation': INFO}))
            result, _ = self.validate()
            with Recorder(case, case_id='case', run_id='run').activate():
                persist_attempt({'candidate_id': '1', 'raw_response': PATCH, 'patch': PATCH, 'validation_result': result})
            attempt = case / 'attempts' / '1'
            self.assertTrue(verify_attempt(case, attempt)['success'])
            evidence = attempt / 'poc.source.json'
            data = json.loads(evidence.read_text())
            data['receipts'][1]['source_hash'] = 'b' * 64
            evidence.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                verify_attempt(case, attempt)
            # Even updating the receipt inventory and its embedded copy cannot
            # make a foreign tested-source hash match the saved candidate.
            validation_file = attempt / 'validation.json'
            validation = json.loads(validation_file.read_text())
            validation['artifacts']['poc.source.json'] = hashlib.sha256(evidence.read_bytes()).hexdigest()
            validation['stage_details']['poc']['source_attestation'] = data
            validation_file.write_text(json.dumps(validation))
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                verify_attempt(case, attempt)


class TestCaseCommands(unittest.TestCase):
    def test_command_fixtures_use_explicit_source_boundaries_without_fuzz(self):
        files = sorted(COMMAND_FIXTURES.glob('*.json'))
        self.assertEqual({file.stem for file in files}, {
            'baseline_suite', 'javascript_suite', 'python_suite', 'go_suite',
        })
        for file in files:
            record = json.loads(file.read_text())
            for key in ('poc_test_cmd', 'unit_test_cmd'):
                script = record[key]
                with self.subTest(case=file.parent.name, command=key):
                    for phase in ('apply', 'before', 'after'):
                        self.assertEqual(script.count(HELPER + ' ' + phase), 1)
                    self.assertNotIn('--fuzz', script)
                    self.assertNotIn('/workspace/fix.patch', script)
                    check = subprocess.run(['bash', '-n'], input=script, capture_output=True, text=True)
                    self.assertEqual(check.returncode, 0, check.stderr)
