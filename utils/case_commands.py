"""Migrate known Vul4C/PatchEval commands to exact candidate source validation.

This module is deliberately independent of model and agent dependencies. Unknown
script shapes are rejected rather than rewritten with best-effort shell parsing.
"""

from copy import deepcopy
from pathlib import PurePosixPath
import re
import shlex
import subprocess

from utils.container_validation import PROTOCOL
from utils.source_text import ngiflib_preparation


HELPER = "bash /kea-validation/protocol.sh"
LEGACY_PATCH = "/workspace/fix.patch"
MIGRATION_VERSION = 1


class CommandMigrationError(ValueError):
    pass


def bash_syntax(command):
    result = subprocess.run(
        ["bash", "-n"], input=command, text=True, capture_output=True, timeout=10
    )
    if result.returncode:
        raise CommandMigrationError("Invalid Bash script: " + result.stderr.strip())


def _once(text, old, new):
    if text.count(old) != 1:
        raise CommandMigrationError("Expected exactly one script anchor: " + old)
    return text.replace(old, new, 1)


def _candidate_test(body):
    # A separate Bash preserves errexit inside multi-command tests. An `if` or
    # `||` around a shell function/subshell would disable errexit in that body.
    delimiter = "KEA_CANDIDATE_TEST_EOF"
    if delimiter in body:
        raise CommandMigrationError("Test body conflicts with wrapper delimiter")
    return (
        f"{HELPER} before \"$KEA_SOURCE_ROOT\"\n"
        "set +e\n"
        f"bash -e -o pipefail -s -- \"$@\" <<'{delimiter}'\n"
        + body.rstrip() + "\n" + delimiter + "\n"
        "KEA_TEST_STATUS=$?\n"
        "set -e\n"
        f"{HELPER} after \"$KEA_SOURCE_ROOT\"\n"
        'exit "$KEA_TEST_STATUS"\n'
    )


def _patcheval(command, *, language, source_file, case_id, poc):
    lines = command.splitlines()
    # The retained node-im-resize Unit script has this stray command joined to
    # its shebang. Its actual Mocha selection remains in the test body below.
    if lines and lines[0] == "npx mocha --#!/bin/bash":
        lines[0] = "#!/bin/bash"
    roots = [i for i, line in enumerate(lines)
             if re.fullmatch(r"cd /workspace/\S+\s*", line)]
    if len(roots) != 1:
        raise CommandMigrationError("Expected one explicit PatchEval repository root")
    if any(line.strip() and not (line.lstrip().startswith("#")
               or line == "set -e" or line.startswith("export PATH="))
           for line in lines[:roots[0]]):
        raise CommandMigrationError("Unsupported command before repository selection")
    install_after = roots[0]
    removed = 0
    for index, line in enumerate(lines):
        if not line.startswith("git apply "):
            if LEGACY_PATCH in line:
                raise CommandMigrationError("Unsupported candidate application syntax")
            continue
        if index < roots[0]:
            raise CommandMigrationError("Patch preparation precedes repository selection")
        words = shlex.split(line)
        if words[:2] != ["git", "apply"] or any(
            word not in {"--whitespace=nowarn", LEGACY_PATCH,
                         "/workspace/test.patch", "/workspace/dep.patch"}
            for word in words[2:]
        ):
            raise CommandMigrationError("Unsupported PatchEval preparation command")
        removed += words.count(LEGACY_PATCH)
        remaining = [word for word in words if word != LEGACY_PATCH]
        lines[index] = (shlex.join(remaining) if any(
            word.endswith(".patch") for word in remaining[2:]
        ) else "")
        install_after = index
    if removed > 1 or (poc and removed != 1):
        raise CommandMigrationError("Unexpected number of legacy candidate applications")
    prefix = "\n".join(lines[:install_after + 1]).rstrip()
    body = "\n".join(lines[install_after + 1:]).strip()
    if not body:
        raise CommandMigrationError("Missing test invocation")
    if poc:
        target = '"$KEA_SOURCE_ROOT"/' + shlex.quote(source_file)
        if language == "python":
            environments = set(re.findall(r"/workspace/PoC_env/[^/\s]+/bin/", command))
            expected = f"/workspace/PoC_env/{case_id}/bin/"
            if environments != {expected}:
                raise CommandMigrationError("Cannot determine the case Python interpreter")
            body = shlex.quote(expected + "python") + " -m py_compile " + target + "\n" + body
        elif language == "javascript":
            body = "node --check " + target + "\n" + body
        elif language == "go":
            if not re.search(r"\bgo test\s", body):
                raise CommandMigrationError("Go PoC does not declare a go test build")
        else:
            raise CommandMigrationError("Unsupported PatchEval language")
    return (
        "set -e -o pipefail\n" + prefix + "\n"
        'export KEA_SOURCE_ROOT="$PWD"\n'
        f"{HELPER} apply \"$KEA_SOURCE_ROOT\"\n"
        + _candidate_test(body)
    )


def _vul4c(command, *, poc):
    legacy = [line for line in command.splitlines() if LEGACY_PATCH in line]
    if len(legacy) != 1 or not legacy[0].startswith("(git apply "):
        raise CommandMigrationError("Unsupported Vul4C candidate application")
    command = _once(command, legacy[0], f'{HELPER} apply "$PWD"')
    if poc:
        if command.count('vul4c compile -d "$PROJECT_DIR"') != 1:
            raise CommandMigrationError("Missing Vul4C project build")
        return _once(
            command, 'vul4c reproduce -d "$PROJECT_DIR"',
            f'{HELPER} before "$PROJECT_DIR/source"\n'
            'KEA_TEST_STATUS=0\n'
            'vul4c reproduce -d "$PROJECT_DIR" || KEA_TEST_STATUS=$?\n'
            f'{HELPER} after "$PROJECT_DIR/source"\n'
            'exit "$KEA_TEST_STATUS"',
        ) + "\n"
    # Candidate installation is in source_patched; the benchmark copies that
    # candidate into source only AFTER measuring the original baseline.
    before, body = command.split("<<'EOF'\n", 1)
    body, after = body.split("\nEOF\n", 1)
    body = _once(body, "cd $1", 'cd "$1" || exit $?')
    for number, status in ((1, "KEA_BASELINE_STATUS"), (2, "KEA_CANDIDATE_STATUS")):
        matches = re.findall(rf"^output{number}=\$\((make check[^\n]*)\)$", body, re.M)
        if len(matches) != 1:
            raise CommandMigrationError("Expected one baseline and candidate make check")
        original = f"output{number}=$({matches[0]})"
        replacement = f"{status}=0\n{original} || {status}=$?"
        if number == 2:
            replacement = (
                f'{HELPER} before "$1" || exit $?\n' + replacement + "\n"
                f'{HELPER} after "$1" || exit $?'
            )
        body = _once(body, original, replacement)
    comparisons = re.findall(r"^if (?:diff -q[^\n]*|\[ \"\$total1\"[^\n]*)$", body, re.M)
    if len(comparisons) != 1:
        raise CommandMigrationError("Unknown Vul4C baseline comparison")
    # Keep baseline-relative test semantics, including pre-existing failures,
    # but never let cleanup hide a newly failing suite or an empty test output.
    guard = (
        'if [ "$KEA_BASELINE_STATUS" -ne "$KEA_CANDIDATE_STATUS" ] || '
        '[ -z "$output1" ] || [ -z "$output2" ]; then\n    exit 1\nfi\n\n'
    )
    body = _once(body, comparisons[0], guard + comparisons[0])
    return before + "<<'EOF'\n" + body + "\nEOF\n" + after.rstrip() + "\n"


def validate_record(record):
    if record.get("validation_protocol") != PROTOCOL:
        raise CommandMigrationError("Missing exact-source validation protocol")
    source = record.get("source_file", "")
    path = PurePosixPath(source)
    if not source or path.is_absolute() or ".." in path.parts or str(path) != source:
        raise CommandMigrationError("Invalid repository-relative source_file")
    if not isinstance(record.get("docker_image"), str) or not record["docker_image"]:
        raise CommandMigrationError("Missing explicit Docker image")
    kind = record.get("validation_compile_kind")
    build = record["poc_test_cmd"]
    checks = {
        "project_build": 'vul4c compile -d "$PROJECT_DIR"',
        "go_test_build": "go test ",
        "python_bytecode": " -m py_compile ",
        "javascript_syntax": "node --check ",
    }
    if kind not in checks or checks[kind] not in build:
        raise CommandMigrationError("Declared compile kind has no matching build/check command")
    from utils.validation_scope import validation_mode

    mode = validation_mode(record)
    expected = [
        {"name": "build_and_poc", "command": record["poc_test_cmd"], "covers": ["compile", "poc"]},
    ]
    if mode != "poc":
        expected.append({"name": "unit", "command": record["unit_test_cmd"], "covers": ["unit"]})
    elif record.get("unit_test_cmd") or record.get("unit_test_command"):
        raise CommandMigrationError("PoC-only validation must exclude unit-test commands")
    if record.get("validation_steps") != expected:
        raise CommandMigrationError("Validation steps differ from the recorded commands")
    for step in expected:
        command = step["command"]
        if LEGACY_PATCH in command or "--fuzz" in command:
            raise CommandMigrationError("Legacy/fuzzy candidate application remains")
        for phase in ("apply", "before", "after"):
            if command.count(HELPER + " " + phase) != 1:
                raise CommandMigrationError("Missing or duplicate source boundary: " + phase)
        if not (command.index(HELPER + " apply") < command.index(HELPER + " before")
                < command.index(HELPER + " after")):
            raise CommandMigrationError("Candidate source boundaries are out of order")
        bash_syntax(command)


def _known_encoding_preparation(record, dataset, case_id):
    # These four pinned ngiflib checkouts contain Latin-1 French comments.
    # Normalize during preparation, before both source installation boundaries.
    if dataset != "Vul4c" or case_id not in {
        "CVE-2018-10677", "CVE-2018-10717", "CVE-2019-16346", "CVE-2019-16347",
    }:
        return
    if record["source_file"] != "ngiflib.c":
        raise CommandMigrationError("Unexpected target for legacy ngiflib comments")
    preparation = ngiflib_preparation()
    anchor = f'vul4c checkout -i "{case_id}" -d "$PROJECT_DIR"\n'
    for key in ("poc_test_cmd", "unit_test_cmd"):
        if "KEA_SOURCE_UTF8_COMMENTS" not in record[key]:
            record[key] = _once(record[key], anchor, anchor + preparation)
        elif record[key].count(preparation) != 1:
            raise CommandMigrationError("Unknown source encoding preparation")
    record["source_text_preparation"] = {
        "original_encoding": "ISO-8859-1", "encoding": "UTF-8",
        "scope": "comments_only", "version": 1,
    }
    record["validation_steps"] = [
        {"name": "build_and_poc", "command": record["poc_test_cmd"], "covers": ["compile", "poc"]},
        {"name": "unit", "command": record["unit_test_cmd"], "covers": ["unit"]},
    ]


def migrate_record(record, *, dataset, case_id, source_file):
    result = deepcopy(record)
    if result.get("validation_protocol") == PROTOCOL:
        validate_record(result)
        if result["source_file"] != source_file:
            raise CommandMigrationError("Migrated source path differs from the case input")
        _known_encoding_preparation(result, dataset, case_id)
        validate_record(result)
        return result
    if result.get("validation_protocol") or result.get("validation_steps") is not None:
        raise CommandMigrationError("Refusing to overwrite an unknown validation contract")
    images = []
    for key in ("poc_test_cmd", "unit_test_cmd"):
        command = result.get(key)
        if not isinstance(command, str) or HELPER in command:
            raise CommandMigrationError("Missing command or partially migrated record")
        matches = re.findall(r"#\s*From\s+(\S+)", command)
        if len(matches) != 1:
            raise CommandMigrationError("Expected one explicit image header per command")
        images.append(matches[0])
    if images[0] != images[1]:
        raise CommandMigrationError("PoC and Unit image headers disagree")
    language = str(result.get("programming_language", "")).lower()
    for key, poc in (("poc_test_cmd", True), ("unit_test_cmd", False)):
        if dataset == "Vul4c" and language in {"c", "cpp"}:
            result[key] = _vul4c(result[key], poc=poc)
        elif dataset == "PatchEval":
            result[key] = _patcheval(result[key], language=language,
                                     source_file=source_file, case_id=case_id, poc=poc)
        else:
            raise CommandMigrationError("Unsupported dataset/language combination")
    result.update(
        source_file=source_file, docker_image=images[0], validation_protocol=PROTOCOL,
        validation_migration_version=MIGRATION_VERSION,
        validation_compile_kind={"c": "project_build", "cpp": "project_build",
                                 "go": "go_test_build", "python": "python_bytecode",
                                 "javascript": "javascript_syntax"}[language],
    )
    result["validation_steps"] = [
        {"name": "build_and_poc", "command": result["poc_test_cmd"], "covers": ["compile", "poc"]},
        {"name": "unit", "command": result["unit_test_cmd"], "covers": ["unit"]},
    ]
    _known_encoding_preparation(result, dataset, case_id)
    validate_record(result)
    return result
