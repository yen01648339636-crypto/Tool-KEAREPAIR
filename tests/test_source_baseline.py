"""Baseline checks must precede model work and preserve exact source bytes."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from utils.source_baseline import (SourceBaselineError, preparation_steps, inspect_baseline,
                                  ensure_source_baseline, select_source, configuration_hash, sha256, DockerSourceProbe, needs_source_baseline)


def record():
    commands = []
    for name in ("build_and_poc", "unit"):
        commands.append('set -e\ncd /workspace/project\n'
            'bash /kea-validation/protocol.sh apply "$PWD"\n'
            'vul4c compile -d "$PROJECT_DIR"\n'
            'bash /kea-validation/protocol.sh before "$PWD"\n'
            'echo TESTS_MUST_NOT_RUN_DURING_PROBE\n'
            'bash /kea-validation/protocol.sh after "$PWD"\n')
    return {"validation_protocol": "exact-source-v1", "source_file": "src/parser.c",
            "docker_image": "fixture:tag", "validation_compile_kind": "project_build",
            "poc_test_cmd": commands[0], "unit_test_cmd": commands[1],
            "validation_steps": [{"name": "build_and_poc", "command": commands[0], "covers": ["compile", "poc"]},
                                 {"name": "unit", "command": commands[1], "covers": ["unit"]}]}


class Probe:
    def __init__(self, source=b"original\n", unit=None):
        self.source, self.unit = source, unit
        self.reads = []

    def image_id(self, image):
        return "sha256:" + "a" * 64

    def read(self, record, step, identity):
        self.reads.append(step)
        source = self.unit if step["name"] == "unit" and self.unit is not None else self.source
        return source, {"name": step["name"], "source_sha256": sha256(source),
                        "preparation_sha256": sha256(step["prefix"].encode())}


def test_probe_uses_both_preparation_paths_and_excludes_tests():
    probe = Probe()
    data, receipt = inspect_baseline(record(), probe)
    assert data == b"original\n"
    assert [s["name"] for s in probe.reads] == ["build_and_poc", "unit"]
    assert all("TESTS_MUST_NOT_RUN" not in s["prefix"] and "vul4c compile" not in s["prefix"] for s in probe.reads)
    assert receipt["configuration_sha256"] == configuration_hash(record())
    assert receipt["source_sha256"] == sha256(data)


def test_poc_and_unit_different_baselines_cannot_be_aligned():
    with pytest.raises(SourceBaselineError, match="单元测试准备出的目标源码不一致"):
        inspect_baseline(record(), Probe(unit=b"other version\n"))


def test_live_check_rejects_byte_difference_without_changing_source(tmp_path):
    source = tmp_path / "source.c"
    source.write_bytes(b"original\r\n")
    with pytest.raises(SourceBaselineError, match="源码版本不一致"):
        ensure_source_baseline(source, record(), probe=Probe())
    assert source.read_bytes() == b"original\r\n"
    source.write_bytes(b"original\n")
    assert ensure_source_baseline(source, record(), probe=Probe())["status"] == "verified"


def test_unknown_install_boundary_and_incomplete_contract_are_rejected():
    broken = record()
    broken["unit_test_cmd"] = broken["unit_test_cmd"].replace('apply "$PWD"', 'apply $(pwd)')
    broken["validation_steps"][1]["command"] = broken["unit_test_cmd"]
    with pytest.raises(SourceBaselineError, match="无法识别"):
        preparation_steps(broken)
    with pytest.raises(SourceBaselineError, match="配置不完整"):
        preparation_steps({"docker_image": "fixture"})


def test_legacy_container_commands_cannot_skip_the_source_gate():
    assert needs_source_baseline({"poc_test_cmd": "# From fixture:tag\nrun tests"})
    assert needs_source_baseline({"test_command": "cd /workspace/repo; run tests"})
    assert needs_source_baseline({"container_src_dir": "/experiment/project"})
    assert not needs_source_baseline(None)
    assert not needs_source_baseline({"test_command": "python test.py"})


def test_declared_source_wins_over_larger_unrelated_file(tmp_path):
    target = tmp_path / "revision/src/parser.c"
    target.parent.mkdir(parents=True)
    target.write_text("small")
    (tmp_path / "unrelated.c").write_text("large" * 1000)
    assert select_source(tmp_path, record()) == target
    duplicate = tmp_path / "second/src/parser.c"
    duplicate.parent.mkdir(parents=True)
    duplicate.write_text("duplicate")
    with pytest.raises(SourceBaselineError, match="不唯一"):
        select_source(tmp_path, record())


def test_audit_archives_original_before_aligning(tmp_path, monkeypatch):
    from scripts import sync_case_sources as sync
    case = tmp_path / "Vul4c/CVE-fixture"
    source = case / "src/parser.c"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"different version\n")
    commands = case / "test_cmds.json"
    commands.write_text(json.dumps(record()))
    monkeypatch.setattr(sync, "DockerSourceProbe", lambda **kwargs: Probe())
    output = tmp_path / "audit"
    checked = sync.audit_case(commands, output, apply=True)
    assert checked["status"] == "aligned"
    assert source.read_bytes() == b"original\n"
    archive = output / "cases/Vul4c/CVE-fixture"
    assert (archive / "source.before").read_bytes() == b"different version\n"
    assert json.loads((case / "source_baseline.json").read_text())["changed"]


def test_divergent_test_sources_do_not_overwrite_case(tmp_path, monkeypatch):
    from scripts import sync_case_sources as sync
    case = tmp_path / "Vul4c/CVE-fixture"
    source = case / "src/parser.c"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"saved\n")
    commands = case / "test_cmds.json"
    commands.write_text(json.dumps(record()))
    monkeypatch.setattr(sync, "DockerSourceProbe", lambda **kwargs: Probe(unit=b"different\n"))
    assert sync.audit_case(commands, tmp_path / "audit", apply=True)["status"] == "blocked"
    assert source.read_bytes() == b"saved\n"
    assert not (case / "source_baseline.json").exists()


def test_image_drift_is_rejected_before_validation_commands(monkeypatch):
    from Online.phase3_repair import Validator
    from tests.test_diff_repair import ORIGINAL, PATCH, INFO
    validator = Validator()
    monkeypatch.setattr(validator, "_check_docker_available", lambda: None)
    monkeypatch.setattr(validator, "_get_docker_subprocess_env", lambda: {})
    monkeypatch.setattr(validator, "_image_identity", lambda *a: {"image_id": "sha256:" + "b" * 64})
    monkeypatch.setattr(validator, "_command", lambda *a, **k: pytest.fail("image drift must stop before any test command"))
    result = validator.validate(ORIGINAL, PATCH, {**INFO, "docker_image": "fixture:tag",
        "expected_docker_image_id": "sha256:" + "a" * 64})
    assert not result["success"]
    assert result["stage_status"]["compile"] == "not_run"
    assert "image changed after source preflight" in result["error_log"]


def test_audited_cache_requires_matching_image_recipe_and_exact_source(tmp_path):
    source = tmp_path / "source.c"
    source.write_bytes(b"original\n")
    _, receipt = inspect_baseline(record(), Probe())
    for saved, step in zip(receipt["steps"], preparation_steps(record())):
        saved["preparation_sha256"] = sha256(step["prefix"].encode())
    path = tmp_path / "source_baseline.json"
    path.write_text(json.dumps(receipt))
    probe = Probe()
    result = ensure_source_baseline(source, record(), probe=probe, receipt_path=path)
    assert "cache_verified_at" in result and not probe.reads
    source.write_bytes(b"changed\n")
    with pytest.raises(SourceBaselineError):
        ensure_source_baseline(source, record(), probe=probe, receipt_path=path)
    assert len(probe.reads) == 2
    source.write_bytes(b"original\n")
    for field in ("docker_image_id", "configuration_sha256"):
        changed = {**receipt, field: "different"}
        path.write_text(json.dumps(changed))
        fresh = Probe()
        assert "cache_verified_at" not in ensure_source_baseline(source, record(), probe=fresh, receipt_path=path)
        assert len(fresh.reads) == 2
    path.write_text("[]")
    assert ensure_source_baseline(source, record(), probe=Probe(), receipt_path=path)["status"] == "verified"


def test_fresh_preflight_is_saved_for_later_stages(tmp_path):
    source = tmp_path / "source.c"
    source.write_bytes(b"original\n")
    path = tmp_path / "source_baseline.json"
    first = Probe()
    ensure_source_baseline(source, record(), probe=first, receipt_path=path)
    assert len(first.reads) == 2 and path.is_file()
    later = Probe()
    receipt = ensure_source_baseline(source, record(), probe=later, receipt_path=path)
    assert not later.reads and "cache_verified_at" in receipt


def test_unwritable_cache_does_not_discard_a_successful_live_check(tmp_path, monkeypatch, caplog):
    source = tmp_path / "source.c"
    source.write_bytes(b"original\n")

    def read_only(*args):
        raise PermissionError("read-only case directory")

    monkeypatch.setattr("utils.source_baseline.write_json_atomic", read_only)
    probe = Probe()
    result = ensure_source_baseline(source, record(), probe=probe,
                                   receipt_path=tmp_path / "source_baseline.json")
    assert result["status"] == "verified" and len(probe.reads) == 2
    assert "Could not save source-baseline cache" in caplog.text


def test_prior_stage_receipt_is_reused_when_input_cache_is_missing(tmp_path):
    source = tmp_path / "source.c"
    source.write_bytes(b"original\n")
    _, receipt = inspect_baseline(record(), Probe())
    prior = tmp_path / "engine-source-baseline.json"
    prior.write_text(json.dumps(receipt))
    primary = tmp_path / "input-source-baseline.json"
    probe = Probe()
    cached = ensure_source_baseline(source, record(), probe=probe, receipt_path=primary,
                                   fallback_receipt_paths=(prior,))
    assert not probe.reads and "cache_verified_at" in cached
    assert json.loads(primary.read_text())["source_sha256"] == sha256(source.read_bytes())


@pytest.mark.parametrize("field", ["docker_image_id", "configuration_sha256", "source_sha256"])
def test_prior_stage_receipt_cannot_bypass_changed_identity(tmp_path, field):
    source = tmp_path / "source.c"
    source.write_bytes(b"original\n")
    _, receipt = inspect_baseline(record(), Probe())
    receipt[field] = "different"
    prior = tmp_path / "engine-source-baseline.json"
    prior.write_text(json.dumps(receipt))
    probe = Probe()
    result = ensure_source_baseline(source, record(), probe=probe,
                                   fallback_receipt_paths=(prior,))
    assert len(probe.reads) == 2 and "cache_verified_at" not in result


def test_real_probe_shell_copies_bytes_and_never_executes_tests(tmp_path, monkeypatch):
    import subprocess
    project = tmp_path / "project"
    target = project / "src/parser.c"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"original\r\n")
    run = subprocess.run
    observed = []
    step = preparation_steps(record())[0]

    def docker(argv, **kwargs):
        observed.append(argv)
        if argv[:2] == ["docker", "rm"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        mount = argv[argv.index("-v") + 1].split(":/kea-source-probe:")[0]
        command = argv[-1].replace("/workspace/project", str(project)).replace("/kea-source-probe", mount)
        assert "TESTS_MUST_NOT_RUN" not in command
        return run(["bash", "-lc", command], capture_output=True, text=True, timeout=10)

    monkeypatch.setattr("utils.source_baseline.subprocess.run", docker)
    probe = DockerSourceProbe(env={})
    source, receipt = probe.read(record(), step, "sha256:" + "a" * 64)
    assert source == b"original\r\n" and receipt["source_sha256"] == sha256(source)
    assert len(observed) == 1  # Successful --rm containers need no second removal.


def test_probe_timeout_removes_only_its_owned_container(monkeypatch):
    import subprocess
    calls = []
    step = preparation_steps(record())[0]

    def timeout(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(argv, 1)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("utils.source_baseline.subprocess.run", timeout)
    with pytest.raises(SourceBaselineError, match="源码准备超时"):
        DockerSourceProbe(env={}, timeout=1).read(record(), step, "sha256:" + "a" * 64)
    name = calls[0][calls[0].index("--name") + 1]
    assert name.startswith("kea-source-probe-") and calls[-1] == ["docker", "rm", "-f", name]
