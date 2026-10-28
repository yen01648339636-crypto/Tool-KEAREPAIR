"""Exercise migrated real command families with the real source protocol.

Only checkout/build/test executables are local doubles. Bash, source installation,
hashes, test boundaries, baseline restoration and failure propagation are real.
No model packages, network, benchmark images or Docker daemon are needed.
"""

from copy import deepcopy
import difflib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from scripts.migrate_case_commands import main, source_file
from utils.case_commands import CommandMigrationError, migrate_record, validate_record
from utils.container_validation import create_payload, read_attestation


FIXTURES = Path(__file__).parent / "fixtures/case_command_migration/legacy_cases.json"
CASES = json.loads(FIXTURES.read_text())
ORIGINAL, FIXED = "value = 0\n", "value = 1\n"

STUB = r'''#!/usr/bin/python3
import json, os, pathlib, shutil, sys
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
root = pathlib.Path(os.environ['STUB_ROOT'])
target = pathlib.Path.cwd() / os.environ['STUB_TARGET']
if name == 'vul4c':
    project = pathlib.Path(args[args.index('-d') + 1])
    target = project / 'source' / os.environ['STUB_TARGET']
    if args[0] == 'checkout':
        shutil.copytree(root / 'template', project / 'source', dirs_exist_ok=True)
        sys.exit(0)
    phase = 'build' if args[0] == 'compile' else 'test'
elif name == 'git' or (name == 'go' and args[:2] == ['mod', 'vendor']):
    assert '/workspace/fix.patch' not in ' '.join(args)
    with (root / 'preparations.jsonl').open('a') as f:
        f.write(json.dumps(args) + '\n')
    if os.environ.get('STUB_FAILURE') == 'preparation': sys.exit(23)
    sys.exit(0)
elif name == 'make':
    if args and args[0] == 'clean': sys.exit(0)
    phase = 'test' if args and args[0] == 'check' else 'build'
else:
    target = pathlib.Path(os.environ['STUB_PROJECT']) / os.environ['STUB_TARGET']
    phase = 'build' if '--check' in args or 'py_compile' in args else 'test'
value = target.read_text()
with (root / 'calls.jsonl').open('a') as f:
    f.write(json.dumps(dict(name=name, args=args, phase=phase, value=value)) + '\n')
failure = os.environ.get('STUB_FAILURE', '')
if phase == 'build' and failure == 'build' and value == 'value = 1\n': sys.exit(17)
if name == 'make' and phase == 'test':
    print('# TOTAL: 1\n# PASS:  1\n# SKIP:  0\n# XFAIL: 0\n# FAIL:  0\n# XPASS: 0\n# ERROR: 0')
    print('Total tests: 1\nPasses: 1\nFailures: 0\nUnexpected Passes: 0\nExpected Failures: 0\nMissing Tests: 0\nExtra Tests: 0')
if phase == 'test' and value == 'value = 1\n':
    if failure == 'source_change': target.write_text('value = 99\n')
    if failure == 'test': sys.exit(19)
'''


def migrated(case):
    return migrate_record(case["record"], dataset=case["dataset"],
                          case_id=case["case_id"], source_file=case["source_file"])


def run_command(case, key, failure=""):
    record = migrated(case)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        workspace, payload, evidence = root / "workspace", root / "payload", root / "evidence"
        workspace.mkdir()
        evidence.mkdir()
        bins = root / "bin"
        bins.mkdir()
        program = bins / "stub"
        program.write_text(STUB)
        program.chmod(0o755)
        for name in ("vul4c", "make", "git", "node", "npx", "npm", "jest", "go", "aclocal",
                     "autoheader", "autoconf", "libtoolize", "automake"):
            # Autotools are setup operations, not candidate tests.
            if name in {"aclocal", "autoheader", "autoconf", "libtoolize", "automake"}:
                (bins / name).write_text("#!/bin/bash\nexit 0\n")
                (bins / name).chmod(0o755)
            else:
                (bins / name).symlink_to(program)
        command = record[key]
        if case["dataset"] == "PatchEval":
            project_name = re.search(r"^cd /workspace/(\S+)", command, re.M)[1]
            project = workspace / project_name
            for directory in ("tests", "test/integration/targets/template", "x/claims/keeper"):
                (project / directory).mkdir(parents=True, exist_ok=True)
            target = project / case["source_file"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(ORIGINAL)
            if case["case_id"] == "CVE-2020-4037":
                (project / "oauthproxy_test.go").write_text("// fixture test input\n" * 500)
            venv = workspace / "PoC_env" / case["case_id"] / "bin"
            venv.mkdir(parents=True)
            for name in ("python", "ansible-playbook", "ansible-test", "pytest"):
                (venv / name).symlink_to(program)
        else:
            project = root / "checkout" / "source"
            template = root / "template"
            target = template / case["source_file"]
            target.parent.mkdir(parents=True)
            target.write_text(ORIGINAL)
            for name in ("configure", "autogen.sh", "build/autogen.sh", "scripts/autogen.sh"):
                file = template / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("#!/bin/bash\nexit 0\n")
                file.chmod(0o755)
            command = command.replace(f"/tmp/mv-bdsr-vul4c/{case['case_id']}", str(root / "checkout"))
            command = command.replace("/tmp/mv_bdsr_vul4c_project_test.sh", str(root / "suite.sh"))
        patch = "".join(difflib.unified_diff(ORIGINAL.splitlines(True), FIXED.splitlines(True),
                                            fromfile="a/" + case["source_file"],
                                            tofile="b/" + case["source_file"]))
        expected = create_payload(payload, ORIGINAL, FIXED, patch, case["source_file"],
                                  "1", "build_and_poc" if key == "poc_test_cmd" else "unit",
                                  evidence_dir=evidence)
        command = command.replace("/kea-validation", str(payload)).replace("/workspace", str(workspace))
        result = subprocess.run(["bash", "-c", command], text=True, capture_output=True,
                                timeout=10, cwd=root,
                                env={**os.environ, "PATH": str(bins) + ":" + os.environ["PATH"],
                                     "STUB_ROOT": str(root), "STUB_PROJECT": str(project),
                                     "STUB_TARGET": case["source_file"], "STUB_FAILURE": failure})
        logs = root / "calls.jsonl"
        calls = [json.loads(line) for line in logs.read_text().splitlines()] if logs.exists() else []
        receipt = read_attestation(evidence / "receipts.tsv", expected, "sha256:fixture",
                                   complete=result.returncode == 0)
        source = project / case["source_file"]
        final_source = source.read_text() if source.exists() else None
        return result, calls, receipt, final_source


class TestCommandMigration(unittest.TestCase):
    def test_all_retained_real_families_declare_build_and_source_boundaries(self):
        self.assertEqual(len(CASES), 23)
        for case in CASES:
            with self.subTest(case=case["case_id"]):
                record = migrated(case)
                validate_record(record)
                self.assertEqual(migrate_record(record, dataset=case["dataset"],
                    case_id=case["case_id"], source_file=case["source_file"]), record)
                self.assertEqual([s["covers"] for s in record["validation_steps"]],
                                 [["compile", "poc"], ["unit"]])
                if case["record"]["programming_language"] == "Python":
                    self.assertIn(" -m py_compile ", record["poc_test_cmd"])
                if case["record"]["programming_language"] == "JavaScript":
                    self.assertIn("node --check ", record["poc_test_cmd"])
                for patch in ("/workspace/test.patch", "/workspace/dep.patch"):
                    for key in ("poc_test_cmd", "unit_test_cmd"):
                        if patch in case["record"][key]:
                            self.assertIn(patch, record[key])

    def test_all_command_families_execute_candidate_and_record_actual_test_source(self):
        for case in CASES:
            for key in ("poc_test_cmd", "unit_test_cmd"):
                with self.subTest(case=case["case_id"], command=key):
                    result, calls, receipt, final = run_command(case, key)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(receipt["receipts"]), 3)
                    tests = [c for c in calls if c["phase"] == "test"]
                    self.assertTrue(tests)
                    if case["dataset"] == "Vul4c" and key == "unit_test_cmd":
                        self.assertEqual([c["value"] for c in tests], [ORIGINAL, FIXED])
                        self.assertEqual(final, ORIGINAL)
                        self.assertNotEqual(receipt["receipts"][0]["source_path"],
                                            receipt["receipts"][1]["source_path"])
                    else:
                        self.assertTrue(all(c["value"] == FIXED for c in tests))

    def test_test_failure_cannot_be_hidden_by_receipts_or_baseline_cleanup(self):
        for case in CASES:
            for key in ("poc_test_cmd", "unit_test_cmd"):
                with self.subTest(case=case["case_id"], command=key):
                    result, calls, receipt, final = run_command(case, key, "test")
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(len(receipt["receipts"]), 3)
                    if case["dataset"] == "Vul4c" and key == "unit_test_cmd":
                        self.assertEqual(final, ORIGINAL)
                    if case["case_id"] == "CVE-2021-3583":
                        self.assertEqual(len([c for c in calls if c["phase"] == "test"]), 1)

    def test_failed_explicit_compile_does_not_execute_poc(self):
        for case in CASES:
            if case["record"]["programming_language"] == "Go":
                continue  # go test supplies the build/test contract in one process.
            with self.subTest(case=case["case_id"]):
                result, calls, _, _ = run_command(case, "poc_test_cmd", "build")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse([c for c in calls if c["phase"] == "test"])

    def test_source_mutation_cannot_obtain_complete_success_receipts(self):
        go_case = next(c for c in CASES if c["case_id"] == "CVE-2022-24738")
        for case in (CASES[0], go_case):
            result, _, receipt, _ = run_command(case, "poc_test_cmd", "source_change")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual([r["phase"] for r in receipt["receipts"]], ["apply", "before"])

    def test_failed_dependency_patch_stops_before_candidate_installation(self):
        case = next(c for c in CASES if c["case_id"] == "CVE-2021-3664")
        result, calls, receipt, _ = run_command(case, "poc_test_cmd", "preparation")
        self.assertEqual(result.returncode, 23)
        self.assertFalse(calls)
        self.assertFalse(receipt["receipts"])

    def test_a_declared_compile_stage_requires_an_actual_check(self):
        case = next(c for c in CASES if c["case_id"] == "CVE-2017-16025")
        record = migrated(case)
        record["poc_test_cmd"] = record["poc_test_cmd"].replace("node --check ", "echo ")
        record["validation_steps"][0]["command"] = record["poc_test_cmd"]
        with self.assertRaises(CommandMigrationError):
            validate_record(record)

    def test_unknown_or_partial_contracts_and_shell_shapes_are_rejected(self):
        case = next(c for c in CASES if c["case_id"] == "CVE-2024-27289")
        for change in ({"validation_protocol": "unknown"}, {"validation_steps": []},
                       {"poc_test_cmd": case["record"]["poc_test_cmd"].replace(
                           "git apply --whitespace=nowarn", "git apply --unsafe-paths")}):
            record = {**deepcopy(case["record"]), **change}
            with self.assertRaises(CommandMigrationError):
                migrate_record(record, dataset=case["dataset"], case_id=case["case_id"],
                               source_file=case["source_file"])

    def test_stray_header_test_command_is_removed_and_unknown_prologue_rejected(self):
        case = next(c for c in CASES if c["case_id"] == "CVE-2019-10787")
        record = migrated(case)
        self.assertNotIn("npx mocha --#!", record["unit_test_cmd"])
        result, calls, _, _ = run_command(case, "unit_test_cmd")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["value"], FIXED)
        original = deepcopy(case["record"])
        original["unit_test_cmd"] = original["unit_test_cmd"].replace(
            "npx mocha --#!/bin/bash", "npm test\n#!/bin/bash")
        with self.assertRaises(CommandMigrationError):
            migrate_record(original, dataset=case["dataset"], case_id=case["case_id"],
                           source_file=case["source_file"])

    def test_cli_preflights_all_cases_backs_up_originals_and_is_repeatable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = [CASES[0], CASES[-1]]
            originals = {}
            for case in selected:
                directory = root / case["dataset"] / case["case_id"]
                source = directory / (case["source_file"] if case["dataset"] == "Vul4c"
                                      else "abcdef123/" + case["source_file"])
                source.parent.mkdir(parents=True)
                source.write_text(ORIGINAL)
                path = directory / "test_cmds.json"
                path.write_text(json.dumps(case["record"]))
                originals[path] = path.read_bytes()
            backup = root / "backup"
            self.assertEqual(main(["--data-root", str(root), "--check"]), 1)
            bad = next(p for p in originals if "PatchEval" in p.parts)
            bad.write_text(json.dumps({**selected[-1]["record"], "validation_protocol": "unknown"}))
            before = {p: p.read_bytes() for p in originals}
            self.assertEqual(main(["--data-root", str(root), "--write", "--backup-dir", str(backup)]), 2)
            self.assertEqual({p: p.read_bytes() for p in originals}, before)
            self.assertFalse(backup.exists())
            bad.write_bytes(originals[bad])
            self.assertEqual(main(["--data-root", str(root), "--write", "--backup-dir", str(backup)]), 0)
            for path, original in originals.items():
                self.assertEqual((backup / path.relative_to(root)).read_bytes(), original)
                validate_record(json.loads(path.read_text()))
            self.assertEqual(main(["--data-root", str(root), "--check"]), 0)
            self.assertEqual(main(["--data-root", str(root), "--write", "--backup-dir", str(backup)]), 0)


if __name__ == "__main__":
    unittest.main()
