"""Run task-owned uploaded test inputs through the existing container adapters.

Script inputs are self-contained Bash/Python test entry points (zero means
pass). Vul4C also accepts a raw PoC payload for its configured reproduce runner.
User bytes are staged as files, never interpolated into shell program text.
"""

from copy import deepcopy
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat

from utils.validation_scope import validation_mode


MAX_INPUT_BYTES = 10 * 1024 * 1024
PAYLOAD_ROOT = "/kea-validation"
HELPER = f"bash {PAYLOAD_ROOT}/protocol.sh"

# Some Vul4C releases print reproduce output without propagating its exit code.
# Uploaded payloads must use the configured command's actual result.
RAW_POC_RUNNER = '''import json
from pathlib import Path
import subprocess
import sys

project = Path(sys.argv[1])
metadata = json.loads((project / "VUL4C/vulnerability_info.json").read_text())
commands = metadata.get("test_command")
if not isinstance(commands, list) or not commands or any(
    not isinstance(command, str) or "../VUL4C/exploit" not in command for command in commands
):
    raise SystemExit("The prepared PoC runner does not identify the uploaded input")
for command in commands:
    print("Running configured PoC command:", command, flush=True)
    result = subprocess.run(command, shell=True, cwd=project / "source")
    if result.returncode:
        raise SystemExit(result.returncode if 0 < result.returncode < 256 else 1)
'''


def _script_name(kind, descriptor):
    extension = Path(descriptor["filename"]).suffix.lower()
    return f"uploaded-{kind}" + (extension if descriptor["input_mode"] == "script" else ".bin")


def _adapter(commands):
    """Extract only supported trusted preparation/build shapes, before tests."""
    from utils.case_commands import validate_record

    validate_record(commands)
    command = commands["poc_test_cmd"]
    kind = commands["validation_compile_kind"]
    if kind == "project_build":
        marker = f'{HELPER} before "$PROJECT_DIR/source"\n'
        if command.count(marker) != 1 or command.count('vul4c compile -d "$PROJECT_DIR"') != 1:
            raise ValueError("Uploaded inputs require the supported Vul4C build adapter")
        prefix = command.split(marker, 1)[0]
        return dict(kind="vul4c", prefix=prefix + 'export KEA_SOURCE_ROOT="$PROJECT_DIR/source"\nexport KEA_CASE_DIR="$PROJECT_DIR"\n',
                    python="python3")
    marker = f'{HELPER} before "$KEA_SOURCE_ROOT"\n'
    delimiter = "<<'KEA_CANDIDATE_TEST_EOF'\n"
    if command.count(marker) != 1 or command.count(delimiter) != 1:
        raise ValueError("Uploaded inputs require a supported PatchEval test adapter")
    prefix = command.split(marker, 1)[0]
    body = command.split(delimiter, 1)[1].split("\nKEA_CANDIDATE_TEST_EOF", 1)[0]
    build = body.splitlines()[0]
    interpreter = "python3"
    if kind == "python_bytecode":
        words = shlex.split(build)
        if len(words) < 4 or words[1:3] != ["-m", "py_compile"] or not re.fullmatch(r"/workspace/PoC_env/[A-Za-z0-9._-]+/bin/python[0-9.]*", words[0]):
            raise ValueError("The case Python interpreter/build command is unsupported")
        interpreter = words[0]
    elif kind == "javascript_syntax":
        if not build.startswith("node --check "):
            raise ValueError("The case JavaScript build command is unsupported")
    elif kind == "go_test_build":
        lines = body.splitlines()
        build = lines[-1]
        preparation = lines[:-1]
        if " && go test " in build:
            change, build = build.split(" && ", 1)
            change_words = shlex.split(change)
            if len(change_words) != 2 or change_words[0] != "cd":
                raise ValueError("The case Go build directory is unsupported")
            preparation.append(shlex.join(change_words))
        if not build.startswith("go test "):
            raise ValueError("The case Go build command is unsupported")
        words = shlex.split(build)
        filtered, index = words[:2], 2
        while index < len(words):
            word = words[index]
            if word in ("-run", "-bench"):
                index += 2
                continue
            if word.startswith(("-run=", "-bench=")):
                index += 1
                continue
            if word.startswith("-fuzz") or any(c in word for c in ";|&`\n"):
                raise ValueError("The case Go build command is unsupported")
            filtered.append(word)
            index += 1
        # Build/link the existing package selection without executing its tests.
        # Preserve the bundled test-file preparation and package directory,
        # while restoring source-root cwd before the uploaded script runs.
        build = "(\n" + "\n".join(preparation + [shlex.join(filtered[:2] + ["-run", "^$"] + filtered[2:])]) + "\n)"
    else:
        raise ValueError("Uploaded test scripts are unsupported by this case adapter")
    return dict(kind="patcheval", prefix=prefix + build + '\nexport KEA_CASE_DIR="$KEA_SOURCE_ROOT"\n', python=interpreter)


def validate_uploaded_tests(commands, descriptors):
    """Validate upload metadata and adapter compatibility; never execute inputs."""
    if not isinstance(descriptors, dict) or not set(descriptors) <= {"poc", "unit"}:
        raise ValueError("Uploaded tests must contain PoC and/or unit-test inputs")
    if not descriptors:
        return {}
    mode = validation_mode(commands)
    if mode == "patch_only" or (mode == "poc" and "unit" in descriptors):
        raise ValueError("Uploaded files must belong to the requested validation checks")
    adapter = _adapter(commands)
    value = deepcopy(descriptors)
    for kind, item in value.items():
        if not isinstance(item, dict):
            raise ValueError("Invalid uploaded test metadata")
        filename = item.get("filename")
        if (not isinstance(filename, str) or not filename or len(filename.encode("utf-8")) > 255
                or filename in {".", ".."} or re.search(r"[/\\\x00-\x1f\x7f]", filename)):
            raise ValueError("Uploaded test file names must not contain paths or control characters")
        if item.get("kind", kind) != kind:
            raise ValueError("Uploaded test type does not match the selected check")
        if not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))):
            raise ValueError("Uploaded tests require an exact SHA256 identity")
        if type(item.get("size")) is not int or not 0 <= item["size"] <= MAX_INPUT_BYTES:
            raise ValueError("Uploaded tests must be at most 10 MiB")
        extension = Path(filename).suffix.lower()
        input_mode = "script" if extension in {".sh", ".py"} else "data"
        if input_mode == "script" and not item["size"]:
            raise ValueError("Uploaded test scripts must not be empty")
        if input_mode == "data" and (kind != "poc" or adapter["kind"] != "vul4c"):
            raise ValueError("This case requires a self-contained .sh or .py test script; raw PoC files are supported for Vul4C")
        if item.get("input_mode", input_mode) != input_mode:
            raise ValueError("Uploaded input mode does not match the file type")
        item.update(kind=kind, input_mode=input_mode)
    return value


def _input_bytes(item):
    """Recheck only a server-created task snapshot, with no symlink traversal."""
    supplied = item.get("path")
    relative = PurePosixPath(item.get("relative_path", ""))
    if (not isinstance(supplied, str) or not Path(supplied).is_absolute()
            or len(relative.parts) != 3 or relative.parts[0] != ".kea-test-inputs"
            or not re.fullmatch(r"[0-9a-f]{32}", relative.parts[1])
            or not re.fullmatch(r"input\.[a-z0-9]{1,16}", relative.parts[2])):
        raise ValueError("Uploaded tests require an immutable task-owned input snapshot")
    path = Path(supplied)
    if tuple(path.parts[-3:]) != relative.parts or path.resolve() != path:
        raise ValueError("Invalid uploaded test snapshot location")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        identity = os.fstat(descriptor)
        if not stat.S_ISREG(identity.st_mode) or identity.st_size != item["size"] or identity.st_size > MAX_INPUT_BYTES:
            raise ValueError("Uploaded test snapshot size changed")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(MAX_INPUT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(content) != item["size"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
        raise ValueError("Uploaded test snapshot does not match its recorded hash")
    return content


def _file_check(kind, item):
    path = f"{PAYLOAD_ROOT}/{_script_name(kind, item)}"
    return f"printf '%s  %s\\n' {shlex.quote(item['sha256'])} {shlex.quote(path)} | sha256sum -c -\n", path


def _script_command(adapter, kind, item):
    check, path = _file_check(kind, item)
    executable = "bash" if Path(item["filename"]).suffix.lower() == ".sh" else adapter["python"]
    invoke = shlex.join([executable, path])
    return (adapter["prefix"] + 'cd "$KEA_SOURCE_ROOT"\n' + check
            + f'{HELPER} before "$KEA_SOURCE_ROOT"\n'
            + "set +e\n" + invoke + "\nKEA_TEST_STATUS=$?\nset -e\n"
            + f'{HELPER} after "$KEA_SOURCE_ROOT"\nexit "$KEA_TEST_STATUS"\n')


def prepare_uploaded_commands(commands, descriptors):
    """Replace only requested test bodies and bind their exact snapshot hashes."""
    normalized = validate_uploaded_tests(commands, descriptors)
    value = deepcopy(commands)
    if not normalized:
        return value
    adapter = _adapter(commands)
    for kind, item in normalized.items():
        _input_bytes(item)
        if item["input_mode"] == "data":
            check, path = _file_check(kind, item)
            # Vul4C's pinned reproduce runner consumes this checkout-owned file.
            # Refuse a missing/symlink payload instead of creating an unused file.
            install = (check + 'test -f "$PROJECT_DIR/VUL4C/exploit" && test ! -L "$PROJECT_DIR/VUL4C/exploit"\n'
                       + f'cp -- {shlex.quote(path)} "$PROJECT_DIR/VUL4C/exploit"\n')
            marker = f'{HELPER} before "$PROJECT_DIR/source"\n'
            run = 'vul4c reproduce -d "$PROJECT_DIR"'
            if commands["poc_test_cmd"].count(run) != 1:
                raise ValueError("The prepared PoC command is unsupported")
            value["poc_test_cmd"] = commands["poc_test_cmd"].replace(marker, install + marker, 1).replace(
                run, f'python3 {PAYLOAD_ROOT}/uploaded-poc-runner.py "$PROJECT_DIR"', 1)
        else:
            value[kind + "_test_cmd"] = _script_command(adapter, kind, item)
    value["studio_uploaded_tests"] = normalized
    value["validation_steps"] = [dict(name="build_and_poc", command=value["poc_test_cmd"], covers=["compile", "poc"])]
    if validation_mode(value) == "full":
        value["validation_steps"].append(dict(name="unit", command=value["unit_test_cmd"], covers=["unit"]))
    from utils.case_commands import validate_record
    validate_record(value)
    return value


def stage_uploaded_tests(payload, descriptors):
    """Copy verified test bytes into the existing read-only container payload."""
    for kind, item in (descriptors or {}).items():
        if kind not in {"poc", "unit"}:
            raise ValueError("Unknown uploaded test type")
        target = Path(payload) / _script_name(kind, item)
        content = _input_bytes(item)
        target.write_bytes(content)
        target.chmod(0o444)
        if kind == "poc" and item["input_mode"] == "data":
            runner = Path(payload) / "uploaded-poc-runner.py"
            runner.write_text(RAW_POC_RUNNER, encoding="utf-8")
            runner.chmod(0o444)
