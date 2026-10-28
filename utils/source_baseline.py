"""Check the exact prepared container source before spending model requests."""

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import tempfile
from uuid import uuid4

from utils.case_commands import validate_record
from utils.experiment_manifest import write_json_atomic


class SourceBaselineError(ValueError):
    pass


def needs_source_baseline(record):
    """Include legacy/incomplete Docker declarations so they cannot bypass the gate."""
    if record is not None and not isinstance(record, dict):
        raise SourceBaselineError("案例验证配置必须为 JSON 对象")
    record = record or {}
    if any(record.get(k) for k in ("docker_image", "validation_protocol", "validation_steps", "container_src_dir")):
        return True
    return any(re.search(r"#\s*From\s+\S+|/workspace/", str(record.get(k) or ""))
               for k in ("poc_test_cmd", "unit_test_cmd", "test_command"))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def preparation_steps(record):
    """Only run preparation preceding the existing candidate-install boundary."""
    try:
        validate_record(record)
    except (KeyError, TypeError, ValueError) as exc:
        raise SourceBaselineError("案例验证配置不完整，无法核对容器源码：" + str(exc)) from exc
    steps = []
    for step in record["validation_steps"]:
        matches = list(re.finditer(r'^bash /kea-validation/protocol\.sh apply "\$(PWD|KEA_SOURCE_ROOT)"\s*$', step["command"], re.M))
        if len(matches) != 1:
            raise SourceBaselineError("无法识别源码安装前的准备步骤：" + step["name"])
        match = matches[0]
        steps.append({"name": step["name"], "prefix": step["command"][:match.start()],
                      "root_variable": match.group(1)})
    return steps


def select_source(case_dir, record):
    """Select the declared target, never another (possibly larger) source file."""
    case_dir = Path(case_dir).resolve()
    target = record.get("source_file", "")
    path = PurePosixPath(target)
    if not target or path.is_absolute() or ".." in path.parts or str(path) != target:
        raise SourceBaselineError("缺少有效的 source_file 相对路径")
    direct = case_dir / target
    matches = [direct] if direct.is_file() else [p for p in case_dir.rglob(path.name)
        if p.is_file() and p.relative_to(case_dir).as_posix().endswith("/" + target)]
    if len(matches) != 1 or matches[0].is_symlink() or not matches[0].resolve().is_relative_to(case_dir):
        raise SourceBaselineError("案例源码路径缺失或不唯一：" + target)
    return matches[0]


def configuration_hash(record):
    fields = {k: record.get(k) for k in ("source_file", "docker_image", "workdir", "extra_mounts", "validation_steps")}
    return sha256(json.dumps(fields, sort_keys=True, ensure_ascii=False).encode())


class DockerSourceProbe:
    def __init__(self, timeout=600, env=None):
        self.timeout = timeout
        if env is None:
            # Use the same daemon selection/fallback as the actual validator.
            from Online.phase3_repair.validator import Validator
            env = Validator()._get_docker_subprocess_env()
        self.env = env

    def image_id(self, image):
        output = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", image],
                                capture_output=True, text=True, timeout=30, env=self.env)
        identity = output.stdout.strip()
        if output.returncode or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
            raise SourceBaselineError("本地镜像不可用，请先下载案例镜像：" + image)
        return identity

    def read(self, record, step, image_id):
        name = "kea-source-probe-" + uuid4().hex
        with tempfile.TemporaryDirectory(prefix="kea-source-probe-") as temporary:
            directory = Path(temporary)
            directory.chmod(0o777)
            target = shlex.quote(record["source_file"])
            script = step["prefix"] + '\nset -euo pipefail\n'
            script += 'KEA_PROBE_ROOT=$(cd -- "$' + step["root_variable"] + '" && pwd -P)\n'
            script += 'KEA_PROBE_TARGET=$(readlink -f -- "$KEA_PROBE_ROOT"/' + target + ')\n'
            script += '[[ "$KEA_PROBE_TARGET" == "$KEA_PROBE_ROOT/"* && -f "$KEA_PROBE_TARGET" && ! -L "$KEA_PROBE_ROOT"/' + target + ' ]]\n'
            script += 'cp -- "$KEA_PROBE_TARGET" /kea-source-probe/source.original\n'
            script += 'git -C "$KEA_PROBE_ROOT" rev-parse HEAD > /kea-source-probe/commit.txt 2>/dev/null || true\n'
            argv = ["docker", "run", "--rm", "--pull", "never", "--name", name,
                    "--platform", "linux/amd64", "-v", f"{directory}:/kea-source-probe:rw"]
            # These recipes clone/copy a disposable checkout beneath this exact
            # scratch parent. RAM storage changes no source bytes and avoids
            # expensive metadata writes to the user's Docker backing disk.
            if re.search(r'^PROJECT_DIR="/tmp/mv-bdsr-vul4c/CVE-[0-9-]+"\s*$', step["prefix"], re.M):
                argv += ["--tmpfs", "/tmp/mv-bdsr-vul4c:rw,exec,size=4g"]
            for destination, source in (record.get("extra_mounts") or {}).items():
                if not str(destination).startswith("/") or PurePosixPath(destination) == PurePosixPath("/") or (
                        PurePosixPath(destination) == PurePosixPath("/kea-source-probe")
                        or PurePosixPath(destination) in PurePosixPath("/kea-source-probe").parents
                        or PurePosixPath("/kea-source-probe") in PurePosixPath(destination).parents):
                    raise SourceBaselineError("源码检查挂载路径冲突")
                argv += ["-v", f"{source}:{destination}:ro"]
            argv += ["--workdir", record.get("workdir", "/workspace"), image_id, "bash", "-lc", script]
            finished = False
            try:
                output = subprocess.run(argv, capture_output=True, text=True,
                                        timeout=self.timeout, env=self.env)
                finished = True
                if output.returncode or not (directory / "source.original").is_file():
                    reason = (output.stderr or output.stdout or "no source returned")[-2500:]
                    raise SourceBaselineError(f"{step['name']} 源码准备失败：{reason}")
                source = (directory / "source.original").read_bytes()
                source.decode("utf-8")
                commit = (directory / "commit.txt").read_text().strip()
                return source, {"name": step["name"], "source_sha256": sha256(source),
                                "preparation_sha256": sha256(step["prefix"].encode()), "commit": commit}
            except subprocess.TimeoutExpired as exc:
                raise SourceBaselineError(f"{step['name']} 源码准备超时（{self.timeout}s）") from exc
            finally:
                # A killed Docker client must not leave our probe container behind.
                # Normal exits already have --rm; a second removal can contend
                # with Docker's large checkout cleanup on a slow backing disk.
                if not finished:
                    try:
                        subprocess.run(["docker", "rm", "-f", name], capture_output=True,
                                       timeout=90, env=self.env)
                    except (OSError, subprocess.TimeoutExpired):
                        logging.getLogger(__name__).warning("Probe cleanup still pending: %s", name)


def inspect_baseline(record, probe=None):
    steps = preparation_steps(record)
    probe = probe or DockerSourceProbe()
    identity = probe.image_id(record["docker_image"])
    values = [probe.read(record, step, identity) for step in steps]
    if any(source != values[0][0] for source, _ in values[1:]):
        raise SourceBaselineError("编译／PoC 与单元测试准备出的目标源码不一致，需先修正案例准备命令")
    source = values[0][0]
    receipt = {"schema_version": 1, "status": "verified", "checked_at": datetime.now(timezone.utc).isoformat(),
               "docker_image": record["docker_image"], "docker_image_id": identity,
               "source_file": record["source_file"], "source_sha256": sha256(source),
               "configuration_sha256": configuration_hash(record), "steps": [v for _, v in values]}
    return source, receipt


def verified_receipt(actual, record, identity, receipt_path):
    """Reuse only an exact audited source/recipe/image triple without live mounts."""
    steps = preparation_steps(record)
    # An audited immutable image/recipe/source triple avoids cloning large
    # repositories again for every interactive stage. External mounts are live
    # inputs and therefore always require a fresh probe.
    if receipt_path and not record.get("extra_mounts"):
        try:
            cached = json.loads(Path(receipt_path).read_text())
            if (isinstance(cached, dict) and cached.get("schema_version") == 1 and cached.get("status") == "verified"
                    and cached.get("source_file") == record["source_file"]
                    and cached.get("docker_image") == record["docker_image"]
                    and cached.get("docker_image_id") == identity
                    and cached.get("configuration_sha256") == configuration_hash(record)
                    and cached.get("source_sha256") == sha256(actual)
                    and isinstance(cached.get("steps"), list)
                    and all(isinstance(s, dict) for s in cached["steps"])
                    and [s.get("name") for s in cached["steps"]] == [s["name"] for s in steps]
                    and all(s.get("source_sha256") == sha256(actual) and s.get("preparation_sha256") == sha256(step["prefix"].encode())
                            for s, step in zip(cached["steps"], steps))):
                return {**cached, "cache_verified_at": datetime.now(timezone.utc).isoformat()}
        except (OSError, ValueError, TypeError, KeyError):
            pass
    return None


def _save_verified_receipt(path, receipt):
    if path is None:
        return
    try:
        write_json_atomic(path, receipt)
    except OSError as exc:
        # Cache persistence is optional; the fresh source check still passed.
        logging.getLogger(__name__).warning("Could not save source-baseline cache: %s", exc)


def ensure_source_baseline(source_file, record, *, probe=None, receipt_path=None,
                           fallback_receipt_paths=()):
    """Bind source + commands to the immutable audited image; probe unknown identities."""
    actual = Path(source_file).read_bytes()
    preparation_steps(record)
    probe = probe or DockerSourceProbe()
    identity = probe.image_id(record["docker_image"])
    for path in (receipt_path, *fallback_receipt_paths):
        cached = verified_receipt(actual, record, identity, path)
        if cached:
            if path != receipt_path:
                _save_verified_receipt(receipt_path, cached)
            return cached
    expected, receipt = inspect_baseline(record, probe)
    if actual != expected:
        raise SourceBaselineError(
            f"源码版本不一致：{record['source_file']}；平台 {sha256(actual)[:12]}，容器 {sha256(expected)[:12]}。"
            "请运行 scripts/sync_case_sources.py --apply 对齐案例后创建新任务；旧诊断与补丁不能沿用。")
    _save_verified_receipt(receipt_path, receipt)
    return receipt


def atomic_bytes(path, content):
    path = Path(path)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content)
    try:
        temporary.chmod(path.stat().st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
