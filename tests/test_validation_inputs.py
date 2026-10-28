"""Uploaded test adapters preserve exact source boundaries and selected checks.

All scripts executed here are harmless test fixtures in temporary directories.
Prepared project commands are parsed and syntax-checked, never executed.
"""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys

import pytest

from utils.case_commands import migrate_record, validate_record
from utils.source_baseline import preparation_steps
from utils.validation_inputs import (prepare_uploaded_commands, stage_uploaded_tests,
                                     validate_uploaded_tests)
from utils.validation_scope import scope_commands


ROOT = Path(__file__).resolve().parents[1]
PREPARED = sorted(p for dataset in ("PatchEval", "Vul4c")
                  for p in (ROOT / "data/processed" / dataset).glob("*/test_cmds.json"))


def descriptor(directory, kind="poc", filename="poc.py", content=b"assert True\n"):
    identity = ("1" if kind == "poc" else "2") * 32
    relative = Path(".kea-test-inputs") / identity / ("input" + Path(filename).suffix.lower())
    path = directory / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return dict(id=identity, kind=kind, filename=filename, size=len(content),
                sha256=hashlib.sha256(content).hexdigest(), relative_path=relative.as_posix(), path=str(path))


def patcheval_record(language="Python", test_body=None):
    prefix = "#!/bin/bash\n# From fixture:tag\nset -e\ncd /workspace/project\ngit apply --whitespace=nowarn /workspace/fix.patch\n"
    source = {"Python": "src/parser.py", "JavaScript": "src/parser.js", "Go": "src/parser.go"}[language]
    body = test_body or {
        "Python": "/workspace/PoC_env/CVE-2026-0001/bin/python -m pytest tests/test_parser.py::test_poc",
        "JavaScript": "npx mocha tests/parser.js --grep fixture",
        "Go": "go test -timeout 30s -run '^TestFixture$' example.com/project/pkg",
    }[language]
    return migrate_record({"programming_language": language,
                           "poc_test_cmd": prefix + body + "\n",
                           "unit_test_cmd": prefix + body + "\n"},
                          dataset="PatchEval", case_id="CVE-2026-0001", source_file=source)


def vul4c_record():
    prefix = ('set -euo pipefail\nPROJECT_DIR="/tmp/mv-bdsr-vul4c/CVE-2026-0001"\n'
              'vul4c checkout -i "CVE-2026-0001" -d "$PROJECT_DIR"\ncd "$PROJECT_DIR/source"\n'
              'bash /kea-validation/protocol.sh apply "$PWD"\nvul4c compile -d "$PROJECT_DIR"\n')
    poc = (prefix + 'bash /kea-validation/protocol.sh before "$PROJECT_DIR/source"\n'
           'KEA_TEST_STATUS=0\nvul4c reproduce -d "$PROJECT_DIR" || KEA_TEST_STATUS=$?\n'
           'bash /kea-validation/protocol.sh after "$PROJECT_DIR/source"\nexit "$KEA_TEST_STATUS"\n')
    unit = (prefix + 'bash /kea-validation/protocol.sh before "$PROJECT_DIR/source"\n'
            'make check\nbash /kea-validation/protocol.sh after "$PROJECT_DIR/source"\n')
    value = dict(source_file="src/parser.c", docker_image="fixture:tag", validation_protocol="exact-source-v1",
                 validation_compile_kind="project_build", poc_test_cmd=poc, unit_test_cmd=unit,
                 validation_steps=[dict(name="build_and_poc", command=poc, covers=["compile", "poc"]),
                                   dict(name="unit", command=unit, covers=["unit"])])
    validate_record(value)
    return value


@pytest.mark.parametrize("command_file", PREPARED or [None], ids=lambda p: f"{p.parent.parent.name}-{p.parent.name}" if p else "datasets-unavailable")
def test_every_prepared_case_accepts_script_inputs_without_preflight_execution(tmp_path, command_file):
    if command_file is None:
        pytest.skip("Prepared repository datasets are unavailable")
    original = json.loads(command_file.read_text())
    before = deepcopy(original)
    inputs = {
        "poc": descriptor(tmp_path, "poc", "custom.py", b"print('UPLOAD_MUST_NOT_RUN_DURING_PREFLIGHT')\n"),
        "unit": descriptor(tmp_path, "unit", "custom.sh", b"printf 'UNIT_MUST_NOT_RUN_DURING_PREFLIGHT\\n'\n"),
    }
    result = prepare_uploaded_commands(original, inputs)
    validate_record(result)
    assert original == before
    assert [step["covers"] for step in result["validation_steps"]] == [["compile", "poc"], ["unit"]]
    preflight = preparation_steps(result)
    assert preflight[0]["prefix"] == preparation_steps(original)[0]["prefix"]
    for step in preflight:
        for value in ("uploaded-poc", "uploaded-unit", "UPLOAD_MUST_NOT_RUN", "UNIT_MUST_NOT_RUN", inputs["poc"]["sha256"], " -m py_compile ", "vul4c compile", "go test "):
            assert value not in step["prefix"]
    if command_file.parent.parent.name == "Vul4c":
        raw = descriptor(tmp_path, "poc", "crash.tiff", b"\x00\xfffixture")
        result = prepare_uploaded_commands(scope_commands(original, "poc"), {"poc": raw})
        assert result["studio_uploaded_tests"]["poc"]["input_mode"] == "data"
        assert '"$PROJECT_DIR/VUL4C/exploit"' in result["poc_test_cmd"]


@pytest.mark.parametrize("language", ["Python", "JavaScript", "Go"])
@pytest.mark.parametrize("extension", [".py", ".sh"])
def test_script_interpreter_and_bundled_other_check_are_preserved(tmp_path, language, extension):
    record = patcheval_record(language)
    source = descriptor(tmp_path, filename="user script" + extension)
    value = prepare_uploaded_commands(record, {"poc": source})
    assert value["unit_test_cmd"] == record["unit_test_cmd"]
    assert "user script" not in value["poc_test_cmd"]
    executable = "bash" if extension == ".sh" else "/workspace/PoC_env/CVE-2026-0001/bin/python" if language == "Python" else "python3"
    assert executable + " /kea-validation/uploaded-poc" + extension in value["poc_test_cmd"]
    for phase in ("apply", "before", "after"):
        assert value["poc_test_cmd"].count("protocol.sh " + phase) == 1


@pytest.mark.parametrize("body,expected", [
    ("go test -run '^TestOriginal$' -bench BenchmarkOriginal -timeout 30s example.com/project/pkg", ["go test -run '^$' -timeout 30s example.com/project/pkg"]),
    ("cd ./pkg/auth && go test -run=TestOriginal -count=1 example.com/project/pkg/auth", ["cd ./pkg/auth", "go test -run '^$' -count=1 example.com/project/pkg/auth"]),
    ("sed -i '4d;15d' oauthproxy_test.go\ngo test -timeout 30s -run '^TestOriginal$' example.com/project", ["sed -i '4d;15d' oauthproxy_test.go", "go test -run '^$' -timeout 30s example.com/project"]),
])
def test_go_build_only_preserves_case_preparation_and_package_selection(tmp_path, body, expected):
    record = patcheval_record("Go", body)
    result = prepare_uploaded_commands(record, {"poc": descriptor(tmp_path)})["poc_test_cmd"]
    for fragment in expected:
        assert fragment in result
    assert "TestOriginal" not in result and "BenchmarkOriginal" not in result
    assert '\n(\n' in result and '\n)\n' in result
    assert result.index('\n)\n') < result.index('cd "$KEA_SOURCE_ROOT"')


def test_raw_vul4c_poc_replaces_exact_payload_before_reproduction(tmp_path):
    original = vul4c_record()
    info = descriptor(tmp_path, filename="crash.tiff", content=b"\x00\xffpayload")
    result = prepare_uploaded_commands(original, {"poc": info})
    command = result["poc_test_cmd"]
    assert result["unit_test_cmd"] == original["unit_test_cmd"]
    assert command.index("sha256sum -c -") < command.index('cp -- /kea-validation/uploaded-poc.bin "$PROJECT_DIR/VUL4C/exploit"')
    assert command.index('cp -- ') < command.index('protocol.sh before') < command.index('uploaded-poc-runner.py')
    assert 'vul4c reproduce' not in command
    assert 'test -f "$PROJECT_DIR/VUL4C/exploit" && test ! -L "$PROJECT_DIR/VUL4C/exploit"' in command
    assert preparation_steps(original) == preparation_steps(result)


def test_staging_uses_verified_bytes_and_read_only_payload_files(tmp_path):
    inputs = {"poc": descriptor(tmp_path, "poc", "fixture.py", b"assert True\n"),
              "unit": descriptor(tmp_path, "unit", "fixture.sh", b"exit 0\n")}
    info = prepare_uploaded_commands(patcheval_record(), inputs)["studio_uploaded_tests"]
    payload = tmp_path / "payload"
    payload.mkdir()
    stage_uploaded_tests(payload, info)
    assert {p.name for p in payload.iterdir()} == {"uploaded-poc.py", "uploaded-unit.sh"}
    for kind, item in info.items():
        saved = payload / ("uploaded-" + kind + Path(item["filename"]).suffix)
        assert hashlib.sha256(saved.read_bytes()).hexdigest() == item["sha256"]
        assert stat.S_IMODE(saved.stat().st_mode) == 0o444


@pytest.mark.parametrize("tamper", ["content", "size", "hash", "path", "relative", "symlink"])
def test_changed_or_unsafe_task_snapshot_cannot_be_staged(tmp_path, tamper):
    item = descriptor(tmp_path)
    info = prepare_uploaded_commands(patcheval_record(), {"poc": item})["studio_uploaded_tests"]
    value = info["poc"]
    if tamper == "content":
        Path(value["path"]).write_bytes(b"assert False\n")
    elif tamper == "size":
        value["size"] += 1
    elif tamper == "hash":
        value["sha256"] = "0" * 64
    elif tamper == "path":
        value["path"] = "relative/input.py"
    elif tamper == "relative":
        value["relative_path"] = "../other/input.py"
    else:
        path = Path(value["path"])
        moved = tmp_path / "other.py"
        path.rename(moved)
        path.symlink_to(moved)
    payload = tmp_path / "payload"
    payload.mkdir()
    with pytest.raises((OSError, ValueError)):
        stage_uploaded_tests(payload, info)
    assert not list(payload.iterdir())


@pytest.mark.parametrize("case,kind,filename,scope", [
    ("patcheval", "poc", "crash.tiff", "poc"),
    ("vul4c", "unit", "suite.zip", "full"),
    ("vul4c", "poc", "fixture.py", "patch_only"),
    ("vul4c", "unit", "fixture.sh", "poc"),
])
def test_invalid_input_kind_or_scope_rejected(tmp_path, case, kind, filename, scope):
    original = vul4c_record() if case == "vul4c" else patcheval_record()
    commands = scope_commands(original, scope)
    with pytest.raises(ValueError):
        validate_uploaded_tests(commands, {kind: descriptor(tmp_path, kind, filename)})


@pytest.mark.parametrize("extension,exit_code", [(".sh", 0), (".sh", 7), (".py", 0), (".py", 7)])
def test_uploaded_script_exit_status_and_source_boundaries_are_preserved(tmp_path, monkeypatch, extension, exit_code):
    import utils.validation_inputs as inputs

    payload = tmp_path / "payload"
    payload.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    phases = tmp_path / "phases.log"
    (payload / "protocol.sh").write_text("printf '%s\\n' \"$1\" >> " + shlex.quote(str(phases)) + "\n")
    body = f"printf 'fixture ran\\n'\nexit {exit_code}\n" if extension == ".sh" else f"print('fixture ran')\nraise SystemExit({exit_code})\n"
    item = descriptor(tmp_path, filename="fixture" + extension, content=body.encode())
    item["input_mode"] = "script"
    stage_uploaded_tests(payload, {"poc": item})
    helper = "bash " + shlex.quote(str(payload / "protocol.sh"))
    monkeypatch.setattr(inputs, "PAYLOAD_ROOT", str(payload))
    monkeypatch.setattr(inputs, "HELPER", helper)
    adapter = dict(prefix="set -e\nexport KEA_SOURCE_ROOT=" + shlex.quote(str(project)) + "\n" + helper + ' apply "$KEA_SOURCE_ROOT"\n', python=sys.executable)
    command = inputs._script_command(adapter, "poc", item)
    output = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=5)
    assert output.returncode == exit_code, output.stderr
    assert "fixture ran" in output.stdout
    assert phases.read_text().splitlines() == ["apply", "before", "after"]


def test_failed_payload_hash_stops_before_uploaded_code(tmp_path, monkeypatch):
    import utils.validation_inputs as inputs

    payload = tmp_path / "payload"
    payload.mkdir()
    phases = tmp_path / "phases.log"
    (payload / "protocol.sh").write_text("printf '%s\\n' \"$1\" >> " + shlex.quote(str(phases)) + "\n")
    item = descriptor(tmp_path, filename="fixture.sh", content=b"printf 'MUST_NOT_EXECUTE\\n'\n")
    item["input_mode"] = "script"
    stage_uploaded_tests(payload, {"poc": item})
    changed = payload / "uploaded-poc.sh"
    changed.chmod(0o600)
    changed.write_text("printf 'MUST_NOT_EXECUTE\\n'\nexit 1\n")
    helper = "bash " + shlex.quote(str(payload / "protocol.sh"))
    monkeypatch.setattr(inputs, "PAYLOAD_ROOT", str(payload))
    monkeypatch.setattr(inputs, "HELPER", helper)
    adapter = dict(prefix="set -e\nexport KEA_SOURCE_ROOT=" + shlex.quote(str(tmp_path)) + "\n" + helper + ' apply "$KEA_SOURCE_ROOT"\n', python=sys.executable)
    result = subprocess.run(["bash", "-c", inputs._script_command(adapter, "poc", item)], capture_output=True, text=True, timeout=5)
    assert result.returncode != 0
    assert "MUST_NOT_EXECUTE" not in result.stdout
    assert phases.read_text().splitlines() == ["apply"]


def test_native_validator_stages_uploads_in_the_read_only_payload(tmp_path, monkeypatch):
    from Online.phase3_repair import Validator

    content = b"assert True\n"
    commands = prepare_uploaded_commands(patcheval_record(), {"poc": descriptor(tmp_path, content=content)})
    validator = Validator()
    validator.execution_mode = "docker"
    monkeypatch.setattr(validator, "_check_docker_available", lambda: None)
    monkeypatch.setattr(validator, "_get_docker_subprocess_env", lambda: {})
    monkeypatch.setattr(validator, "_image_identity", lambda *a: {"image_id": "sha256:" + "a" * 64})
    observed = []

    def capture(result, step, argv, **kwargs):
        mounts = [argv[i + 1] for i, value in enumerate(argv) if value == "-v"]
        mount = next(value for value in mounts if value.endswith(":/kea-validation:ro"))
        payload = Path(mount.rsplit(":", 2)[0])
        uploaded = payload / "uploaded-poc.py"
        assert uploaded.read_bytes() == content
        assert stat.S_IMODE(uploaded.stat().st_mode) == 0o444
        assert "/kea-validation/uploaded-poc.py" in argv[-1]
        observed.append(step["name"])
        return False  # Stop without executing a container or claiming success.

    monkeypatch.setattr(validator, "_command", capture)
    source = "value = 0\n"
    patch = "--- a/src/parser.py\n+++ b/src/parser.py\n@@ -1 +1 @@\n-value = 0\n+value = 1\n"
    result = validator.validate(source, patch, {**commands, "repo_relpath": "src/parser.py", "candidate_id": "1"})
    assert observed == ["build_and_poc"]
    assert result["success"] is False


@pytest.mark.parametrize("exit_code", [0, 7])
def test_raw_poc_runner_consumes_uploaded_bytes_and_preserves_actual_exit(tmp_path, exit_code):
    """Execute the generated raw adapter against harmless checkout/build doubles."""
    project = tmp_path / "project"
    source = project / "source"
    data = project / "VUL4C"
    source.mkdir(parents=True)
    data.mkdir()
    (data / "exploit").write_bytes(b"old bundled input")
    raw = b"\x00\xffuploaded-input\x80"
    (source / "read_poc.py").write_text(
        "from pathlib import Path\nimport sys\n"
        "Path('consumed.bin').write_bytes(Path(sys.argv[1]).read_bytes())\n"
        f"raise SystemExit({exit_code})\n"
    )
    (source / "after_poc.py").write_text("from pathlib import Path\nPath('second-command-ran').touch()\n")
    (data / "vulnerability_info.json").write_text(json.dumps({"test_command": [
        "python3 read_poc.py ../VUL4C/exploit", "python3 after_poc.py ../VUL4C/exploit",
    ]}))
    saved = descriptor(tmp_path, filename="crash.tiff", content=raw)
    commands = prepare_uploaded_commands(vul4c_record(), {"poc": saved})
    payload = tmp_path / "payload"
    payload.mkdir()
    stage_uploaded_tests(payload, commands["studio_uploaded_tests"])
    assert stat.S_IMODE((payload / "uploaded-poc-runner.py").stat().st_mode) == 0o444
    phases = tmp_path / "phases.log"
    (payload / "protocol.sh").write_text("printf '%s\\n' \"$1\" >> " + shlex.quote(str(phases)) + "\n")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    (binaries / "vul4c").write_text("#!/bin/bash\nexit 0\n")
    (binaries / "vul4c").chmod(0o755)
    command = commands["poc_test_cmd"].replace("/tmp/mv-bdsr-vul4c/CVE-2026-0001", str(project)).replace("/kea-validation", str(payload))
    output = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=5,
                            env={**os.environ, "PATH": str(binaries) + os.pathsep + os.environ.get("PATH", "")})
    assert output.returncode == exit_code, output.stderr
    assert (source / "consumed.bin").read_bytes() == raw
    assert (data / "exploit").read_bytes() == raw
    assert (source / "second-command-ran").exists() == (exit_code == 0)
    assert phases.read_text().splitlines() == ["apply", "before", "after"]


def test_raw_poc_runner_rejects_commands_without_matching_input(tmp_path):
    from utils.validation_inputs import RAW_POC_RUNNER

    project = tmp_path / "project"
    (project / "source").mkdir(parents=True)
    (project / "VUL4C").mkdir()
    marker = project / "source/unexpected-command-ran"
    (project / "VUL4C/vulnerability_info.json").write_text(json.dumps({"test_command": [
        "touch unexpected-command-ran",
    ]}))
    runner = tmp_path / "runner.py"
    runner.write_text(RAW_POC_RUNNER)
    output = subprocess.run([sys.executable, str(runner), str(project)], capture_output=True, text=True, timeout=5)
    assert output.returncode != 0
    assert "does not identify the uploaded input" in output.stderr
    assert not marker.exists()


@pytest.mark.parametrize("filename", ["empty.py", "empty.sh"])
def test_empty_script_cannot_claim_a_passing_test(tmp_path, filename):
    item = descriptor(tmp_path, filename=filename, content=b"")
    with pytest.raises(ValueError, match="empty"):
        validate_uploaded_tests(patcheval_record(), {"poc": item})
