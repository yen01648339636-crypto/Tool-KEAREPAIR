"""Deterministic correction, edit preservation, budgets and evidence replay."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch as mock_patch

from Online.phase3_repair import RepairAgent, Validator
from tests.container_fixtures import DockerSandbox
from tests.test_diff_repair import ScriptLLM, RecordingValidator
from utils import patch_correction
from utils.metrics import verify_attempt
from utils.patch_correction import edit_fingerprint, parse_diff
from utils.patches import PatchError, extract_diff, prepare_candidate, prepare_patch
from utils.source_context import select_source_context
from utils.telemetry import Recorder


SOURCE = 'prefix = 0\nvalue = 0\n'
RAW = '--- a/source.py\n+++ b/source.py\n@@ -1 +1 @@\n-value = 0\n+value = 1\n'
INFO = {'repo_relpath': 'source.py', 'buggy_code_file': 'source.py'}


def diff(body, header='@@ -1,3 +1,3 @@'):
    return '--- a/source.c\n+++ b/source.c\n' + header + '\n' + body


class TestCorrectionAlignment(unittest.TestCase):
    def prepare(self, source, raw):
        prepared = prepare_candidate(source, raw, 'source.c')
        self.assertEqual(edit_fingerprint(parse_diff(extract_diff(raw))[1]),
                         edit_fingerprint(parse_diff(prepared.patch)[1]))
        self.assertEqual(prepare_patch(source, prepared.patch, 'source.c', allow_correction=False)[1], prepared.fixed_source)
        return prepared

    def test_exact_diff_and_fence_preserve_all_original_bytes(self):
        raw = RAW.replace('-1 +1', '-2 +2')
        for response in (raw, '```diff\n' + raw + '```'):
            result = prepare_candidate(SOURCE, response, 'source.py')
            self.assertEqual(result.patch, raw)
            self.assertEqual(result.correction['status'], 'unchanged')
            self.assertEqual(result.raw_diff, raw)

    def test_wrong_original_and_new_coordinates_are_corrected_without_a_model(self):
        result = prepare_candidate(SOURCE, RAW.replace('+1 @@', '+99 @@'), 'source.py')
        self.assertEqual(result.fixed_source, 'prefix = 0\nvalue = 1\n')
        self.assertEqual(result.ranges, [dict(old_start=2, old_count=1, new_start=2, new_count=1)])
        self.assertEqual(result.correction['status'], 'corrected')
        self.assertEqual(result.correction['hunks'][0]['edit_distance'], 0)
        with self.assertRaises(PatchError):
            prepare_patch(SOURCE, RAW, 'source.py', allow_correction=False)

    def test_context_substitution_preserves_the_actual_source(self):
        result = self.prepare('real\nold\ntail\n', diff(' hallucinated\n-old\n+new\n tail\n'))
        self.assertEqual(result.fixed_source, 'real\nnew\ntail\n')
        self.assertEqual(result.correction['hunks'][0]['edit_distance'], 1)

    def test_missing_and_extra_context_are_corrected_without_changing_file_context(self):
        result = self.prepare('a\nkeep\nold\nb\n', diff(' a\n-old\n+new\n b\n'))
        self.assertEqual(result.fixed_source, 'a\nkeep\nnew\nb\n')
        self.assertEqual(result.ranges[0]['old_count'], 4)
        self.assertEqual(result.correction['hunks'][0]['context_changes'][0]['operation'], 'insert_context')
        result = self.prepare('a\nold\nb\n', diff(' a\n phantom\n-old\n+new\n b\n', '@@ -1,4 +1,4 @@'))
        self.assertEqual(result.fixed_source, 'a\nnew\nb\n')
        self.assertEqual(result.ranges[0]['old_count'], 3)

    def test_minimum_edit_distance_precedes_coordinate_proximity(self):
        source = 'wrong\nold\ntail\nfiller\ncorrect\nold\ntail\n'
        result = self.prepare(source, diff(' correct\n-old\n+new\n tail\n'))
        self.assertEqual(result.ranges[0]['old_start'], 5)
        self.assertEqual(result.correction['hunks'][0]['edit_distance'], 0)
        self.assertTrue(result.fixed_source.startswith('wrong\nold\n'))

    def test_nearest_range_breaks_distance_ties_and_equal_ties_are_rejected(self):
        result = self.prepare('old\nx\nx\nold\n', diff('-old\n+new\n', '@@ -2 +2 @@'))
        self.assertEqual(result.ranges[0]['old_start'], 1)
        with self.assertRaisesRegex(PatchError, 'ambiguous'):
            self.prepare('old\nx\nold\n', diff('-old\n+new\n', '@@ -2 +2 @@'))

    def test_ambiguous_insertion_position_within_the_same_span_is_rejected(self):
        raw = diff(' a\n k\n+inserted\n-old\n+new\n', '@@ -1,3 +1,4 @@')
        with self.assertRaisesRegex(PatchError, 'ambiguous'):
            self.prepare('a\nk\nk\nold\n', raw)

    def test_deletion_typos_and_incomplete_hunks_are_never_repaired(self):
        for raw in (diff('-typo\n+new\n', '@@ -1 +1 @@'),
                    diff('-old\n+new\n', '@@ -1,2 +1,2 @@')):
            with self.assertRaises(PatchError):
                self.prepare('old\n', raw)

    def test_multi_hunk_offsets_use_the_same_original_and_cumulative_new_positions(self):
        source = 'a\nold\nb\nend\n'
        raw = diff('-old\n+new\n+extra\n@@ -99 +99 @@\n-end\n+END\n', '@@ -1 +1,2 @@')
        result = self.prepare(source, raw)
        self.assertEqual(result.fixed_source, 'a\nnew\nextra\nb\nEND\n')
        self.assertEqual(len(result.ranges), 2)
        self.assertEqual(result.ranges[1]['old_start'], 4)
        self.assertEqual(result.ranges[1]['new_start'], 5)

    def test_one_failed_hunk_and_overlapping_best_placements_reject_the_whole_candidate(self):
        for raw in (
            diff('-old\n+new\n@@ -3 +3 @@\n-missing\n+NEW\n', '@@ -1 +1 @@'),
            diff('-old\n+new\n@@ -1 +1 @@\n-old\n+NEW\n', '@@ -1 +1 @@'),
        ):
            with self.assertRaises(PatchError):
                self.prepare('old\nx\nold\n', raw)

    def test_pure_insertions_need_context_or_a_valid_explicit_original_boundary(self):
        result = self.prepare('a\nb\n', diff('+new\n', '@@ -1,0 +99 @@'))
        self.assertEqual(result.fixed_source, 'a\nnew\nb\n')
        with self.assertRaises(PatchError):
            self.prepare('a\nb\n', diff('+new\n', '@@ -99,0 +99 @@'))
        result = self.prepare('a\nb\n', diff(' a\n+new\n b\n', '@@ -99,2 +99,3 @@'))
        self.assertEqual(result.fixed_source, 'a\nnew\nb\n')

    def test_empty_source_and_complete_content_deletion(self):
        self.assertEqual(self.prepare('', diff('+new\n', '@@ -0,0 +99 @@')).fixed_source, 'new\n')
        self.assertEqual(self.prepare('old\n', diff('-old\n', '@@ -99 +99,0 @@')).fixed_source, '')

    def test_crlf_and_no_newline_edit_rows_are_preserved_exactly(self):
        raw = diff('-old\r\n+new\r\n', '@@ -1 +1 @@')
        self.assertEqual(self.prepare('prefix\r\nold\r\n', raw).fixed_source, 'prefix\r\nnew\r\n')
        raw = diff('-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n', '@@ -1 +1 @@')
        self.assertEqual(self.prepare('prefix\nold', raw).fixed_source, 'prefix\nnew')
        with self.assertRaises(PatchError):
            self.prepare('old', diff('-old\n+new\n', '@@ -1 +1 @@'))

    def test_context_final_newline_can_be_corrected_without_changing_edit_rows(self):
        raw = diff('-old\n+new\n tail\n', '@@ -1,2 +1,2 @@')
        self.assertEqual(self.prepare('old\ntail', raw).fixed_source, 'new\ntail')

    def test_correction_stays_inside_the_visible_original_file_window(self):
        source = ''.join(f'line{i}\n' for i in range(1, 11))
        context = select_source_context(source, dict(strategy='line_range', start_line=6, end_line=8, line_hint_source='operator'))[1]
        raw = diff('-line7\n+fixed7\n', '@@ -2 +2 @@')
        result = prepare_candidate(source, raw, 'source.c', context)
        self.assertEqual(result.ranges[0]['old_start'], 7)
        with self.assertRaises(PatchError):
            prepare_candidate(source, raw.replace('line7', 'line9'), 'source.c', context)

    def test_target_path_and_addition_bytes_are_not_rewritten(self):
        with self.assertRaises(PatchError):
            prepare_candidate(SOURCE, RAW.replace('source.py', 'other.py'), 'source.py')
        raw = RAW.replace('+value = 1', '+value = 123456')
        result = prepare_candidate(SOURCE, raw, 'source.py')
        self.assertIn('+value = 123456\n', result.patch)

    def test_bounded_search_rejects_instead_of_accepting_a_partial_minimum(self):
        with mock_patch.object(patch_correction, 'MAX_DP_CELLS', 0):
            with self.assertRaisesRegex(PatchError, 'budget'):
                prepare_candidate(SOURCE, RAW, 'source.py')
            exact = RAW.replace('-1 +1', '-2 +2')
            self.assertEqual(prepare_candidate(SOURCE, exact, 'source.py').patch, exact)
        with mock_patch.object(patch_correction, 'MAX_HUNK_ROWS', 1):
            with self.assertRaisesRegex(PatchError, 'hunk-row budget'):
                prepare_candidate(SOURCE, RAW, 'source.py')

    def test_addition_only_alignment_does_not_force_a_hallucinated_rare_context_anchor(self):
        source = 'noise\nhallucinated\nother\nreal\nanchor\nsep\nanchor\n'
        raw = diff(' hallucinated\n+inserted\n anchor\n', '@@ -4,2 +4,3 @@')
        prepared = self.prepare(source, raw)
        self.assertEqual(prepared.fixed_source, 'noise\nhallucinated\nother\nreal\ninserted\nanchor\nsep\nanchor\n')

    def test_repeated_preparation_is_byte_and_report_deterministic(self):
        first = prepare_candidate(SOURCE, RAW, 'source.py')
        second = prepare_candidate(SOURCE, RAW, 'source.py')
        self.assertEqual(first, second)


class TestCorrectionPipeline(unittest.TestCase):
    def test_one_candidate_correction_does_not_consume_an_extra_generation(self):
        llm, validator = ScriptLLM([RAW]), RecordingValidator(succeeds_at=1)
        result = RepairAgent(llm, validator, single_attempt=True).repair(SOURCE, [], project_info=INFO)
        self.assertTrue(result['success'])
        self.assertEqual(result['generation_count'], 1)
        self.assertEqual(result['validation_count'], 1)
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(result['history'][0]['raw_response'], RAW)
        self.assertNotEqual(result['history'][0]['patch'], RAW)
        self.assertEqual(validator.calls[0][0], SOURCE)

    def test_rejected_hunk_is_recorded_without_validation_or_an_extra_candidate(self):
        llm, validator = ScriptLLM([RAW.replace('-value = 0', '-not present')]), RecordingValidator()
        result = RepairAgent(llm, validator, single_attempt=True).repair(SOURCE, [], project_info=INFO)
        self.assertFalse(result['success'])
        self.assertEqual(validator.calls, [])
        self.assertEqual(result['generation_count'], 1)
        self.assertEqual(result['history'][0]['patch_correction']['status'], 'rejected')

    def test_corrected_diff_is_the_one_installed_and_attested_in_each_container(self):
        validator = Validator()
        validator.execution_mode = 'docker'
        sandbox = DockerSandbox(SOURCE)
        command = '\n'.join(['set -e',
            'bash /kea-validation/protocol.sh apply "$PWD"',
            'bash /kea-validation/protocol.sh before "$PWD"',
            'grep -q "value = 1" source.py',
            'bash /kea-validation/protocol.sh after "$PWD"'])
        with mock_patch.object(validator, '_check_docker_available'), mock_patch.object(
            validator, '_get_docker_subprocess_env', return_value={}
        ), mock_patch.object(validator, '_image_identity', return_value={'image_id': 'sha256:' + 'a'*64}), mock_patch(
            'Online.phase3_repair.validator.subprocess.run', side_effect=sandbox
        ):
            result = validator.validate(SOURCE, RAW, {**INFO, 'docker_image': 'fixture',
                'compile_command': command, 'poc_test_command': command, 'unit_test_command': command})
        self.assertTrue(result['success'], result)
        self.assertNotEqual(result['generated_patch_hash'], result['effective_patch_hash'])
        for name in ('compile', 'poc', 'unit'):
            self.assertEqual(result['stage_details'][name]['source_attestation']['patch_hash'], result['corrected_patch_hash'])
        self.assertEqual(sandbox.sources, ['prefix = 0\nvalue = 1\n'] * 3)

    def archived(self, root, raw=RAW):
        case = Path(root) / 'cases' / 'case'
        case.mkdir(parents=True)
        (case / 'source.original').write_bytes(SOURCE.encode())
        (case / 'source.json').write_text(json.dumps({'sha256': hashlib.sha256(SOURCE.encode()).hexdigest()}))
        info = {**INFO, 'compile_command': 'python3 -m py_compile source.py',
                'poc_test_command': 'python3 -c "import source; assert source.value == 1"',
                'unit_test_command': 'python3 -c "import source; assert source.prefix == 0"'}
        (case / 'inputs.json').write_text(json.dumps({'effective_validation': info}))
        with Recorder(case, case_id='case', run_id='run').activate():
            result = RepairAgent(ScriptLLM([raw]), Validator(), single_attempt=True).repair(SOURCE, [], project_info=info)
        return case, case / 'attempts' / '1', result

    def test_raw_generated_corrected_and_validated_artifacts_replay_without_models(self):
        with tempfile.TemporaryDirectory() as root:
            raw = '```diff\n' + RAW + '```'
            case, directory, result = self.archived(root, raw)
            self.assertTrue(result['success'])
            self.assertEqual((directory / 'raw.patch').read_text(), raw)
            self.assertEqual((directory / 'generated.patch').read_text(), RAW)
            self.assertEqual((directory / 'corrected.patch').read_bytes(), (directory / 'effective.patch').read_bytes())
            self.assertTrue(verify_attempt(case, directory)['success'])
            report = json.loads((directory / 'patch_correction.json').read_text())
            self.assertEqual(report['status'], 'corrected')

    def test_rejected_preparation_has_replayable_negative_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            case, directory, result = self.archived(root, RAW.replace('-value = 0', '-missing'))
            self.assertFalse(result['success'])
            self.assertFalse((directory / 'effective.patch').exists())
            self.assertFalse(verify_attempt(case, directory)['success'])

    def test_tampering_with_correction_artifacts_cannot_support_a_positive_claim(self):
        for filename in ('generated.patch', 'corrected.patch', 'patch_correction.json'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as root:
                case, directory, _ = self.archived(root)
                file = directory / filename
                file.write_bytes(file.read_bytes() + b'tampered')
                with self.assertRaises(ValueError):
                    verify_attempt(case, directory)

    def test_saved_effective_patch_is_never_implicitly_corrected_during_evaluation(self):
        with tempfile.TemporaryDirectory() as root:
            case, directory, _ = self.archived(root)
            (directory / 'effective.patch').write_text(RAW)
            validation_file = directory / 'validation.json'
            validation = json.loads(validation_file.read_text())
            validation['effective_patch_hash'] = hashlib.sha256(RAW.encode()).hexdigest()
            validation_file.write_text(json.dumps(validation))
            with self.assertRaisesRegex(ValueError, 'differs from the corrected'):
                verify_attempt(case, directory)

    def test_legacy_effective_patch_replay_is_strict_even_when_the_raw_diff_matches(self):
        with tempfile.TemporaryDirectory() as root:
            case, directory, _ = self.archived(root)
            (directory / 'effective.patch').write_text(RAW)
            file = directory / 'validation.json'
            validation = json.loads(file.read_text())
            validation['effective_patch_hash'] = hashlib.sha256(RAW.encode()).hexdigest()
            for key in ('generated_patch_hash', 'corrected_patch_hash', 'patch_correction'):
                validation.pop(key, None)
            validation['artifacts'].pop('patch_correction.json')
            file.write_text(json.dumps(validation))
            with self.assertRaises(ValueError):
                verify_attempt(case, directory)
