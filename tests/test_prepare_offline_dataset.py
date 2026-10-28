"""Check exact nested-pair conversion, split exclusions and real CSV round trips."""

from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from scripts.prepare_offline_dataset import convert, encode_csv, evaluation_cases, main
from utils.knowledge import apply_unified_diff, prepare_dataset


def function(prefix, number=1, code=None, file="example.py"):
    return dict(id=f"{prefix}_py_1_{number}", commit="a" * 40 if prefix == "vul" else "b" * 40,
                file_path=file, start_line=20, end_line=21,
                snippet=code if code is not None else ("value = 0\n" if prefix == "vul" else "value = 1\n"))


def record(cve="CVE-2024-1111", **updates):
    return dict(cve_id=cve, cve_description="The reference repair adds a missing input guard.",
                repo="https://example.org/project", programming_language="Python",
                patch_url=["https://example.org/project/commit/" + "b" * 40],
                vul_func=[function("vul")], fix_func=[function("fix")], **updates)


def converted(rows, **options):
    return convert(rows, input_path="/source/input.json", input_sha256="a" * 64, **options)


class TestPrepareOfflineDataset(unittest.TestCase):
    def test_pairs_by_id_not_position_and_reports_new_helpers(self):
        row = record()
        row["vul_func"].append(function("vul", 2, "other = 0\n"))
        row["fix_func"] = [function("fix", 3, "helper = 1\n"),
                           function("fix", 2, "other = 1\n"), function("fix")]
        samples, report = converted([row])
        self.assertEqual([(r["buggy_code"], r["fixed_code"]) for r in samples],
                         [("value = 0\n", "value = 1\n"), ("other = 0\n", "other = 1\n")])
        self.assertEqual(report["unmatched_functions"][0]["function_id"], "fix_py_1_3")
        self.assertEqual(samples[0]["source_provenance"]["vulnerable_function"]["start_line"], 20)

    def test_explicit_evaluation_cves_are_excluded_before_pair_conversion(self):
        training, evaluation = record(), record("CVE-2024-2222")
        samples, report = converted([training, evaluation], excluded_cves=["cve-2024-2222"])
        self.assertEqual(len(samples), 1)
        self.assertEqual(report["counts"]["excluded_records"], 1)
        self.assertEqual(report["excluded_records"][0]["cve_id"], "CVE-2024-2222")
        self.assertNotIn(b"CVE-2024-2222", encode_csv(samples))

    def test_invalid_description_code_and_changed_paths_have_explicit_rejections(self):
        missing = record("CVE-2024-2222")
        missing["cve_description"] = None
        changed_path = record("CVE-2024-3333")
        changed_path["fix_func"][0]["file_path"] = "other.py"
        unchanged = record("CVE-2024-4444")
        unchanged["fix_func"][0]["snippet"] = unchanged["vul_func"][0]["snippet"]
        samples, report = converted([record(), missing, changed_path, unchanged])
        self.assertEqual(len(samples), 1)
        self.assertEqual(report["counts"]["rejected_records"], 1)
        self.assertEqual(report["counts"]["rejected_pairs"], 2)
        self.assertEqual(report["rejected_records"][0]["reason"], "missing_cve_description")

    def test_duplicate_function_ids_are_ambiguous_even_if_text_matches(self):
        row = record()
        row["vul_func"].append(deepcopy(row["vul_func"][0]))
        samples, report = converted([row])
        self.assertFalse(samples)
        self.assertEqual(report["counts"]["unmatched_functions"], 3)
        self.assertTrue(all(x["reason"] == "ambiguous_duplicate_id" for x in report["unmatched_functions"]))

    def test_empty_unknown_and_unpaired_functions_do_not_get_guessed_counterparts(self):
        row = record()
        row["vul_func"][0]["snippet"] = ""
        row["vul_func"].extend([dict(id="unknown", snippet="bad"), function("vul", 9)])
        samples, report = converted([row])
        self.assertFalse(samples)
        self.assertEqual(report["counts"]["rejected_pairs"], 1)
        self.assertEqual(report["counts"]["unmatched_functions"], 2)

    def test_csv_preserves_indentation_crlf_unicode_quotes_and_final_newline(self):
        row = record()
        row["vul_func"][0]["snippet"] = '    value = "原始,代码"\r\n    return value'
        row["fix_func"][0]["snippet"] = '    value = "修复,代码"\r\n    return value'
        samples, _ = converted([row])
        raw = encode_csv(samples)
        decoded = list(csv.DictReader(io.StringIO(raw.decode(), newline="")))
        checked, _ = prepare_dataset(decoded)
        self.assertEqual(checked, samples)
        self.assertEqual(checked[0]["buggy_code"], row["vul_func"][0]["snippet"])
        self.assertEqual(apply_unified_diff(checked[0]["buggy_code"], checked[0]["patch"]), checked[0]["fixed_code"])

    def test_duplicate_pairs_retain_actual_duplicate_origin_and_stable_ids(self):
        first, second = record(), record("CVE-2024-2222")
        samples, report = converted([first, second])
        self.assertEqual(len(samples), 1)
        self.assertEqual(report["duplicate_pairs"][0]["source_pair"]["source_row"], 1)
        repeated, _ = converted([first])
        self.assertEqual(samples[0]["sample_id"], repeated[0]["sample_id"])

    def test_generated_model_outputs_and_unrelated_patch_text_are_not_training_fields(self):
        row = record(one_shot="DO_NOT_TRAIN_ON_THIS", modification="MODEL_GENERATED_FIX", vul_patch="unusable full-file diff")
        samples, _ = converted([row])
        data = encode_csv(samples)
        self.assertNotIn(b"DO_NOT_TRAIN_ON_THIS", data)
        self.assertNotIn(b"MODEL_GENERATED_FIX", data)
        self.assertNotIn(b"unusable full-file diff", data)
        self.assertEqual(samples[0]["fixed_code"], row["fix_func"][0]["snippet"])

    def test_cli_writes_validated_artifacts_is_repeatable_and_preserves_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            source.write_text(json.dumps([record(), record("CVE-2024-2222")]))
            original = source.read_bytes()
            case = root / "evaluation/CVE-2024-2222"
            case.mkdir(parents=True)
            (case / "test_cmds.json").write_text('{"cve_id":"CVE-2024-2222"}')
            output = root / "prepared.csv"
            args = ["--input", str(source), "--output", str(output), "--exclude-evaluation-root", str(case.parent)]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
                self.assertFalse(output.exists())
                self.assertEqual(main(args + ["--write"]), 0)
                before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in [output, output.with_suffix(".report.json")]}
                self.assertEqual(main(args + ["--write"]), 0)
            self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before})
            self.assertEqual(source.read_bytes(), original)
            report = json.loads(output.with_suffix(".report.json").read_text())
            self.assertEqual(report["source"]["sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(report["output"]["sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertEqual(report["counts"]["accepted_samples"], 1)

    def test_existing_output_and_inconsistent_evaluation_ids_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            source.write_text(json.dumps([record()]))
            output = root / "existing.csv"
            output.write_bytes(b"user data\n")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--input", str(source), "--output", str(output), "--write"]), 2)
            self.assertEqual(output.read_bytes(), b"user data\n")
            self.assertFalse(output.with_suffix(".report.json").exists())
            case = root / "CVE-2024-2222"
            case.mkdir()
            (case / "test_cmds.json").write_text('{"cve_id":"CVE-2024-3333"}')
            with self.assertRaises(ValueError):
                evaluation_cases([case])


if __name__ == "__main__":
    unittest.main()
