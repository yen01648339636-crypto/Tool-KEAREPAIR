"""Validator for compilation and testing of patches."""

import subprocess
import tempfile
import shutil
import re
import os
import time
import json
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Literal
from loguru import logger
from utils.patches import PatchError, prepare_candidate, target_path
from utils.validation import new_validation, set_stage, finish_validation, text_hash
from utils.telemetry import measure, current_recorder
from utils.experiment_manifest import write_json_atomic
from utils.container_validation import (
    PAYLOAD_PATH, EVIDENCE_PATH, create_payload, read_attestation,
)


class Validator:
    """Validator for compiling and testing patched code."""

    def __init__(
        self,
        compiler: str = "gcc",
        compile_timeout: int = 30,
        test_timeout: int = 600,  # 增加到10分钟（镜像拉取+测试执行）
        execution_mode: Literal["local", "docker"] = "local",
    ):
        """
        Initialize validator.

        Args:
            compiler: Compiler command (gcc, make, etc.)
            compile_timeout: Compilation timeout in seconds
            test_timeout: Test execution timeout in seconds (default 600s for docker pulls)
            execution_mode: Execution mode - "local" or "docker"
        """
        self.compiler = compiler
        self.compile_timeout = compile_timeout
        self.test_timeout = test_timeout
        self.execution_mode = execution_mode
        self._docker_env_cache: Optional[Dict[str, str]] = None

        # Check Docker availability if docker mode
        if self.execution_mode == "docker":
            self._check_docker_available()

    def _probe_docker_env(
        self, env: Dict[str, str], timeout: int = 5
    ) -> tuple[bool, str]:
        """Probe whether docker daemon is reachable under the given env."""
        try:
            result = subprocess.run(
                ["docker", "version"],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
            if result.returncode == 0:
                return True, (result.stdout or "").strip()
            return False, (result.stderr or result.stdout or "").strip()
        except Exception as e:
            return False, str(e)

    def _get_docker_subprocess_env(self) -> Dict[str, str]:
        """
        Resolve docker subprocess environment.

        Prefer the current DOCKER_HOST if reachable; if it points to an unavailable
        dedicated daemon, automatically fall back to the system default docker socket.
        """
        if self._docker_env_cache is not None:
            return self._docker_env_cache

        preferred_env = os.environ.copy()
        preferred_host = preferred_env.get("DOCKER_HOST", "").strip()

        ok, detail = self._probe_docker_env(preferred_env)
        if ok:
            self._docker_env_cache = preferred_env
            if preferred_host:
                logger.info(
                    f"Docker daemon is available via DOCKER_HOST={preferred_host}"
                )
            return self._docker_env_cache

        if preferred_host:
            fallback_env = os.environ.copy()
            fallback_env.pop("DOCKER_HOST", None)
            ok2, detail2 = self._probe_docker_env(fallback_env)
            if ok2:
                logger.warning(
                    f"DOCKER_HOST={preferred_host} 不可用，将自动回退到系统默认 Docker daemon。"
                )
                self._docker_env_cache = fallback_env
                return self._docker_env_cache

        raise RuntimeError(f"Docker check failed: {detail}")

    def validate(self, buggy_code, patch, project_info=None):
        info = project_info or {}
        result = new_validation(buggy_code, patch, info)
        self._begin_progress(result)
        started = time.monotonic()
        self._publish_progress(result, "patch_apply", True, covers=["patch_apply"])
        try:
            with measure("patch_apply"):
                prepared = prepare_candidate(
                    buggy_code, info.get("generated_patch", patch), target_path(info), info.get("source_context")
                )
                if "generated_patch" in info and prepared.patch != patch:
                    raise ValueError("Supplied validation diff differs from deterministic preparation")
                patch, fixed = prepared.patch, prepared.fixed_source
            result["effective_patch_hash"] = text_hash(patch)
            result["generated_patch_hash"] = text_hash(prepared.raw_diff)
            result["corrected_patch_hash"] = text_hash(patch)
            result["patch_correction"] = prepared.correction
            result["validated_source_hash"] = text_hash(fixed)
            set_stage(
                result,
                "patch_apply",
                "passed",
                time.monotonic() - started,
                operation="exact_original_source_application",
            )
        except ValueError as exc:
            if isinstance(exc, PatchError):
                result.update(
                    generated_patch_hash=text_hash(exc.raw_diff) if exc.raw_diff is not None else None,
                    patch_correction=exc.correction,
                )
            set_stage(
                result,
                "patch_apply",
                "failed",
                time.monotonic() - started,
                stderr=str(exc),
            )
            return self._finish_progress(finish_validation(result))
        self._publish_progress(result, "patch_apply", False, covers=["patch_apply"])
        mode = self.execution_mode
        if info.get("docker_image") or self._looks_like_docker_test_command(
            info.get("test_command")
        ):
            mode = "docker"
        if mode == "docker":
            output = self._validate_in_docker(buggy_code, fixed, patch, info, result)
        else:
            output = self._validate_local(fixed, info, result)
        return self._finish_progress(output)

    def _begin_progress(self, result):
        """A display-only snapshot, separate from the four validation metrics.

        Each invocation starts with a fresh identity and empty state. In particular,
        a later candidate cannot inherit a prior candidate's passed preparation.
        """
        recorder = current_recorder()
        self._progress_destination = getattr(self, "progress_path", None) or (
            recorder.directory / "validation_progress.json" if recorder else None
        )
        self._progress_lock = threading.RLock()
        self._progress_sequence = 0
        self._progress_started = datetime.now(timezone.utc).isoformat()
        self._progress_step_key = None
        self._progress_step_started = self._progress_started
        if self._progress_destination and os.environ.get("KEA_STUDIO_EXECUTION_ID"):
            try:
                previous = json.loads(Path(self._progress_destination).read_text())
                if (previous.get("execution_id") == os.environ["KEA_STUDIO_EXECUTION_ID"]
                        and str(previous.get("candidate_id")) == str(result["candidate_id"])):
                    self._progress_sequence = int(previous.get("sequence", 0))
                    self._progress_started = previous.get("started_at") or self._progress_started
            except (OSError, ValueError, TypeError):
                pass
        self._preparation = {"status": "not_run", "duration_seconds": None, "steps": []}

    def _publish_progress(self, result, step, running, *, covers=(), substep=None,
                          status=None, error=None):
        if not hasattr(self, "_progress_lock"):
            self._begin_progress(result)
        with self._progress_lock:
            self._progress_sequence += 1
            stamp = datetime.now(timezone.utc).isoformat()
            step_key = (step, substep, tuple(covers))
            if step_key != self._progress_step_key:
                self._progress_step_key = step_key
                self._progress_step_started = stamp
            states = dict(result.get("stage_status") or {})
            details = deepcopy(result.get("stage_details") or {})
            if self._preparation["status"] != "not_run":
                states["source_prepare"] = self._preparation["status"]
                details["source_prepare"] = deepcopy(self._preparation)
            if running and substep != "source_prepare":
                states.update({name: "running" for name in covers})
            snapshot = dict(
                schema_version=1, execution_id=os.environ.get("KEA_STUDIO_EXECUTION_ID"),
                candidate_id=str(result.get("candidate_id", "unassigned")),
                sequence=self._progress_sequence, started_at=self._progress_started,
                updated_at=stamp, step_started_at=self._progress_step_started, step=step,
                substep=substep, running=running, status=status or ("running" if running else "updated"),
                covers=list(covers), stage_status=states, stage_details=details,
            )
            if error:
                snapshot["error"] = str(error)
            if self._progress_destination:
                try:
                    write_json_atomic(self._progress_destination, snapshot)
                except OSError as exc:
                    logger.warning("Cannot persist display-only validation progress: {}", exc)

    def _finish_progress(self, result):
        if self._preparation["status"] == "running":
            self._preparation.update(status="error", reason=(
                "Validation ended before a valid candidate-install receipt was obtained."
            ))
        if self._preparation["status"] != "not_run":
            result.setdefault("stage_details", {})["source_prepare"] = deepcopy(self._preparation)
        self._publish_progress(result, "complete", False, status=(
            "completed" if result.get("success") else "failed"
        ), error=result.get("error_log"))
        return result

    def _observe_command(self, result, step, attestation, started, stop):
        """Observe existing hash-bound receipts; never alter the test command.

        Preparation includes Docker startup and candidate installation up to the
        observed apply receipt. Observation times are not native test durations.
        A bundled command's covers become running together at its before receipt.
        """
        observed = set()

        def observe():
            try:
                receipt_file, expected, image_id = attestation
                evidence = read_attestation(receipt_file, expected, image_id, complete=False)
            except (OSError, ValueError):
                return
            phases = {item["phase"] for item in evidence["receipts"]}
            with self._progress_lock:
                if "apply" in phases and "apply" not in observed:
                    observed.add("apply")
                    entry = self._preparation["steps"][-1]
                    entry.update(status="passed", duration_seconds=time.monotonic() - started,
                                 boundary="apply", observed_at=datetime.now(timezone.utc).isoformat())
                    self._preparation.update(status="passed", duration_seconds=sum(
                        item.get("duration_seconds") or 0 for item in self._preparation["steps"]
                    ))
                    self._publish_progress(result, step["name"], True,
                                           substep="candidate_installed")
                if "before" in phases and "before" not in observed:
                    observed.add("before")
                    self._publish_progress(result, step["name"], True,
                                           covers=step["covers"], substep="test_command")

        def monitor():
            while not stop.wait(.1):
                try:
                    observe()
                except OSError:
                    # UI observation must never turn successful tests into errors.
                    pass
        thread = threading.Thread(target=monitor, name="kea-validation-receipts", daemon=True)
        thread.start()
        return thread, observe

    def _looks_like_docker_test_command(self, test_command: Optional[object]) -> bool:
        if not test_command:
            return False
        if not isinstance(test_command, str):
            return False
        s = test_command
        if "/workspace/" in s:
            return True
        if re.search(r"^\s*#\s*From\s+ghcr\.io/", s, flags=re.MULTILINE):
            return True
        return False

    def _detect_language(self, project_info: Optional[Dict] = None) -> str:
        """
        Detect programming language from project info.

        Args:
            project_info: Project info with buggy_code_file path

        Returns:
            Language name: 'c', 'cpp', 'python', 'javascript', 'go', etc.
        """
        if not project_info or "buggy_code_file" not in project_info:
            return "c"  # Default to C

        file_path = str(project_info["buggy_code_file"]).lower()

        if file_path.endswith((".py", ".pyw")):
            return "python"
        elif file_path.endswith((".js", ".mjs", ".cjs")):
            return "javascript"
        elif file_path.endswith((".cpp", ".cc", ".cxx", ".hpp", ".hxx")):
            return "cpp"
        elif file_path.endswith((".c", ".h")):
            return "c"
        elif file_path.endswith(".go"):
            return "go"
        elif file_path.endswith((".java",)):
            return "java"
        elif file_path.endswith((".rs",)):
            return "rust"
        elif file_path.endswith((".rb",)):
            return "ruby"
        elif file_path.endswith((".php",)):
            return "php"
        else:
            return "unknown"

    def _steps(self, info):
        supplied = info.get("validation_steps")
        if supplied is not None:
            if not isinstance(supplied, list):
                raise ValueError("validation_steps must be an ordered list")
            steps = supplied
        else:
            steps = [
                dict(name=name, command=info[field], covers=[name])
                for name, field in (
                    ("compile", "compile_command"),
                    ("poc", "poc_test_command"),
                    ("unit", "unit_test_command"),
                )
                if info.get(field)
            ]
            if not steps and info.get("test_command"):
                steps = [
                    dict(name="generic_test", command=info["test_command"], covers=[])
                ]
        seen = set()
        for step in steps:
            if (
                not isinstance(step, dict)
                or set(step) != {"name", "command", "covers"}
                or not isinstance(step["name"], str)
                or not step["name"].strip()
                or not isinstance(step["command"], str)
                or not step["command"].strip()
                or not isinstance(step["covers"], list)
                or any(not isinstance(name, str) for name in step["covers"])
                or (supplied is not None and not step["covers"])
                or not set(step["covers"]) <= {"compile", "poc", "unit"}
                or len(set(step["covers"])) != len(step["covers"])
                or seen & set(step["covers"])
            ):
                raise ValueError("Invalid or overlapping declared validation steps")
            seen.update(step["covers"])
        # Explicit order is required, including inside a bundled success attestation.
        positions = [name for step in steps for name in step["covers"]]
        if positions != sorted(positions, key=("compile", "poc", "unit").index):
            raise ValueError("Validation stages must execute compile -> poc -> unit")
        return steps

    def _command(self, result, step, argv, *, cwd=None, env=None, attestation=None):
        from utils.execution_control import wait_if_paused
        wait_if_paused()
        started = time.monotonic()
        name = step["name"]
        stop = threading.Event()
        observer = None
        if not hasattr(self, "_progress_lock"):
            self._begin_progress(result)
        if attestation is not None:
            self._preparation.update(
                status="running", duration_seconds=None,
                operation="source_preparation_until_candidate_install_receipt",
                scope="Docker startup, source preparation and candidate installation up to a verified apply receipt; observation timing is separate from test metrics.",
            )
            self._preparation["steps"].append(dict(
                step=name, status="running", duration_seconds=None,
                started_at=datetime.now(timezone.utc).isoformat(),
                declared_covers=list(step["covers"]),
            ))
            self._publish_progress(result, name, True, substep="source_prepare",
                                   covers=step["covers"])
            observer = self._observe_command(result, step, attestation, started, stop)
        else:
            self._publish_progress(result, name, True, covers=step["covers"], substep="test_command")
        try:
            with measure(
                step["covers"][0] if len(step["covers"]) == 1 else "validation_command",
                covers=step["covers"],
            ):
                completed = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=(
                        self.compile_timeout
                        if step["covers"] == ["compile"]
                        else self.test_timeout
                    ),
                    cwd=cwd,
                    env=env,
                )
            details = dict(
                command=argv,
                stdout=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                declared_covers=step["covers"],
            )
            status = (
                "passed"
                if completed.returncode == 0
                else "failed" if len(step["covers"]) == 1 else "error"
            )
        except subprocess.TimeoutExpired as exc:

            def output(value):
                return (
                    value.decode("utf-8", errors="replace")
                    if isinstance(value, bytes)
                    else value
                )

            details = dict(
                command=argv,
                stdout=output(exc.stdout),
                stderr=output(exc.stderr),
                reason="Command timed out",
                declared_covers=step["covers"],
            )
            status = "error"
        except Exception as exc:
            details = dict(
                command=argv, stderr=str(exc), declared_covers=step["covers"]
            )
            status = "error"
        finally:
            if observer:
                stop.set()
                observer[0].join(timeout=2)
                observer[1]()
        elapsed = time.monotonic() - started
        if attestation is not None:
            receipt_file, expected, image_id = attestation
            details["step_name"] = name
            try:
                details["source_attestation"] = read_attestation(
                    receipt_file, expected, image_id, complete=status == "passed"
                )
                if not details["source_attestation"]["receipts"]:
                    raise ValueError("Container did not attest candidate application")
            except (OSError, ValueError) as exc:
                details["attestation_error"] = str(exc)
                details["reason"] = str(exc)
                status = "error"
                set_stage(
                    result, "patch_apply", "error", None,
                    reason=str(exc), operation="container_source_attestation",
                )
            if self._preparation["steps"][-1]["status"] == "running":
                self._preparation["steps"][-1].update(
                    status="error", duration_seconds=elapsed,
                    reason="No valid candidate-install receipt was obtained; preparation completion is unknown.",
                )
                self._preparation.update(status="error", duration_seconds=sum(
                    item.get("duration_seconds") or 0 for item in self._preparation["steps"]
                ), reason="No valid candidate-install receipt was obtained.")
        for covered in step["covers"]:
            set_stage(
                result,
                covered,
                status,
                elapsed if len(step["covers"]) == 1 else None,
                command_duration_seconds=elapsed,
                **details,
            )
        if not step["covers"]:
            result["stage_details"]["generic_test"] = dict(
                duration_seconds=elapsed, status=status, **details
            )
        if status != "passed":
            result["docker_step"] = {"poc": "poc_test", "unit": "unit_test"}.get(
                name, name
            )
            result["error_log"] = str(
                details.get("stderr")
                or details.get("reason")
                or details.get("stdout")
                or "Validation command failed"
            )
        self._publish_progress(result, name, False, covers=step["covers"],
                               status=status, error=result.get("error_log"))
        return status == "passed"

    def _validate_local(self, fixed_code, info, result):
        try:
            steps = self._steps(info)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                if info.get("local_project_dir"):
                    shutil.copytree(info["local_project_dir"], root, dirs_exist_ok=True)
                file = root / target_path(info)
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(fixed_code.encode("utf-8"))
                if not any("compile" in step["covers"] for step in steps):
                    language = self._detect_language(info)
                    check = (
                        self._validate_python
                        if language == "python"
                        else (
                            self._validate_javascript
                            if language == "javascript"
                            else self._compile if language in {"c", "cpp"} else None
                        )
                    )
                    if check:
                        started = time.monotonic()
                        self._publish_progress(result, "compile", True, covers=["compile"], substep="syntax_check")
                        with measure("compile"):
                            output = (
                                check(fixed_code, info)
                                if language in {"c", "cpp"}
                                else check(fixed_code)
                            )
                        set_stage(
                            result,
                            "compile",
                            output.get(
                                "status", "passed" if output["success"] else "failed"
                            ),
                            time.monotonic() - started,
                            stdout=output.get("output"),
                            stderr=output.get("stderr", output.get("error_log")),
                            command=output.get("command"),
                            exit_code=output.get("exit_code"),
                            reason=output.get("error_log") or None,
                            kind="single_file_compile_or_syntax_check",
                            checker=output.get("checker"),
                        )
                        self._publish_progress(result, "compile", False, covers=["compile"])
                        if not output["success"]:
                            return finish_validation(result)
                for step in steps:
                    if not self._command(
                        result,
                        step,
                        ["bash", "-lc", step["command"]],
                        cwd=str(root),
                        env=os.environ.copy(),
                    ):
                        break
        except Exception as exc:
            result["error_log"] = str(exc)
        return finish_validation(result)

    def _compile(self, code, project_info=None):
        info = project_info or {}
        mode = info.get("compile_mode", "compile_only")
        if mode not in {"compile_only", "syntax_only", "link"}:
            return dict(success=False, status="error", error_log="Unknown compile mode")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / (
                "code.cpp" if self._detect_language(info) == "cpp" else "code.c"
            )
            source.write_bytes(code.encode("utf-8"))
            command = [self.compiler]
            if mode == "syntax_only":
                command.append("-fsyntax-only")
            elif mode == "compile_only":
                command.append("-c")
            command.append(str(source))
            if mode != "syntax_only":
                command.extend(
                    [
                        "-o",
                        str(root / ("code.o" if mode == "compile_only" else "a.out")),
                    ]
                )
            command.extend(info.get("compile_flags", []))
            try:
                output = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.compile_timeout,
                    cwd=temporary,
                )
                return dict(
                    success=output.returncode == 0,
                    status="passed" if output.returncode == 0 else "failed",
                    command=command,
                    exit_code=output.returncode,
                    output=output.stdout,
                    stderr=output.stderr,
                    error_log=output.stderr if output.returncode else "",
                )
            except subprocess.TimeoutExpired as exc:

                def output(value):
                    return (
                        value.decode("utf-8", errors="replace")
                        if isinstance(value, bytes)
                        else value
                    )

                return dict(
                    success=False,
                    status="error",
                    command=command,
                    output=output(exc.stdout),
                    stderr=output(exc.stderr),
                    error_log=f"Compilation timeout ({self.compile_timeout}s)",
                )
            except Exception as exc:
                return dict(
                    success=False, status="error", command=command, error_log=str(exc)
                )

    def _validate_python(self, code: str) -> Dict:
        """
        Compile Python to bytecode without executing it.

        Args:
            code: Python source code

        Returns:
            Validation result dictionary
        """
        try:
            compile(code, "<candidate>", "exec")
            return {
                "success": True,
                "checker": "python_compile",
            }
        except SyntaxError as e:
            # Include surrounding code context to help LLM locate the exact broken span
            context_lines = ""
            if e.lineno:
                code_lines = code.splitlines()
                lo = max(0, e.lineno - 4)
                hi = min(len(code_lines), e.lineno + 3)
                snippet = "\n".join(
                    f"{'>>>' if i + 1 == e.lineno else '   '} {i + 1:4d}| {code_lines[i]}"
                    for i in range(lo, hi)
                )
                context_lines = f"\n\nCode context:\n{snippet}"
            return {
                "success": False,
                "error_log": f"Python syntax error at line {e.lineno}: {e.msg}{context_lines}",
            }
        except Exception as e:
            return {
                "success": False,
                "status": "error",
                "error_log": f"Python validation error: {str(e)}",
            }

    def _validate_javascript(self, code: str) -> Dict:
        """
        Validate JavaScript code (basic check, requires node if available).

        Args:
            code: JavaScript source code

        Returns:
            Validation result dictionary
        """
        # 尝试使用 node 检查语法
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".js", delete=False, encoding="utf-8"
            ) as f:
                f.write(code)
                temp_file = f.name

            try:
                # node --check 只检查语法，不执行
                result = subprocess.run(
                    ["node", "--check", temp_file],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode == 0:
                    return {
                        "success": True,
                        "output": result.stdout,
                        "stderr": result.stderr,
                        "exit_code": result.returncode,
                        "command": ["node", "--check", temp_file],
                    }
                else:
                    err_msg = result.stderr
                    # Append code context around the reported error line
                    import re as _re_js

                    m = _re_js.search(r":(\d+)\n", err_msg)
                    if m:
                        err_line = int(m.group(1))
                        code_lines = code.splitlines()
                        lo = max(0, err_line - 4)
                        hi = min(len(code_lines), err_line + 3)
                        snippet = "\n".join(
                            f"{'>>>' if i + 1 == err_line else '   '} {i + 1:4d}| {code_lines[i]}"
                            for i in range(lo, hi)
                        )
                        err_msg = err_msg.rstrip() + f"\n\nCode context:\n{snippet}"
                    return {
                        "success": False,
                        "output": result.stdout,
                        "stderr": result.stderr,
                        "exit_code": result.returncode,
                        "command": ["node", "--check", temp_file],
                        "error_log": f"JavaScript syntax error: {err_msg}",
                    }
            finally:
                Path(temp_file).unlink(missing_ok=True)

        except FileNotFoundError:
            # node 不可用，跳过语法检查
            logger.warning("Node.js not available, skipping JavaScript syntax check")
            return {
                "success": False,
                "status": "not_run",
                "error_log": "JavaScript validation skipped (node not available)",
            }
        except Exception as e:
            return {
                "success": False,
                "status": "error",
                "error_log": f"JavaScript validation error: {str(e)}",
            }

    def _check_docker_available(self):
        """Check if Docker is available."""
        try:
            docker_env = self._get_docker_subprocess_env()
            result = subprocess.run(
                ["docker", "version"],
                capture_output=True,
                text=True,
                timeout=5,
                env=docker_env,
            )
            if result.returncode != 0:
                raise RuntimeError("Docker is not available")
            version_summary = (
                (result.stdout or "").splitlines()[0]
                if result.stdout
                else "docker version ok"
            )
            logger.info(f"Docker is available: {version_summary}")
        except Exception as e:
            raise RuntimeError(f"Docker check failed: {e}")

    def _ensure_docker_image(self, image: str):
        """预拉取 Docker 镜像（如果本地不存在）以避免测试超时"""
        try:
            docker_env = self._get_docker_subprocess_env()
            # 检查镜像是否已存在
            check = subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True,
                timeout=10,
                env=docker_env,
            )

            if check.returncode == 0:
                logger.debug(f"Docker 镜像已存在: {image}")
                return

            # 镜像不存在，预拉取
            logger.info(f"预拉取 Docker 镜像: {image}（可能需要几分钟）")
            pull = subprocess.run(
                ["docker", "pull", image],
                capture_output=True,
                text=True,
                timeout=600,  # 10分钟拉取超时
                env=docker_env,
            )

            if pull.returncode == 0:
                logger.info(f"Docker 镜像拉取成功: {image}")
            else:
                logger.warning(
                    f"Docker 镜像拉取失败（将在运行时重试）: {pull.stderr[:200]}"
                )

        except subprocess.TimeoutExpired:
            logger.warning(f"Docker 镜像拉取超时（10分钟），将在运行时重试")
        except Exception as e:
            logger.warning(f"Docker 镜像拉取检查失败: {e}")

    def _image_identity(self, image, env):
        self._ensure_docker_image(image)
        inspected = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        if inspected.returncode != 0:
            raise RuntimeError(inspected.stderr or "Cannot inspect Docker image")
        data = json.loads(inspected.stdout)
        image_id = data["Id"]
        if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
            raise ValueError("Docker image identity is unavailable")
        identity = dict(image_id=image_id, repo_digests=data.get("RepoDigests") or [])
        recorder = current_recorder()
        if recorder and recorder.case_id:
            lock_path = recorder.directory.parents[1] / "docker_images.json"
            locks = json.loads(lock_path.read_text()) if lock_path.exists() else {}
            if image in locks and locks[image] != identity:
                raise ValueError(
                    "Docker tag resolved to another image within this experiment"
                )
            locks[image] = identity
            write_json_atomic(lock_path, locks)
        return identity

    def _validate_in_docker(self, buggy_code, fixed_code, patch, info, result):
        setup_started = time.monotonic()
        self._preparation.update(status="running", duration_seconds=None,
                                 operation="docker_environment_check")
        self._publish_progress(result, "docker_setup", True, substep="source_prepare")
        try:
            image = info.get("docker_image")
            if not image:
                raise ValueError("Docker validation requires an explicit image")
            self._check_docker_available()
            env = self._get_docker_subprocess_env()
            with measure("docker_setup"):
                identity = self._image_identity(image, env)
                if info.get("expected_docker_image_id") and info["expected_docker_image_id"] != identity["image_id"]:
                    raise ValueError("Docker image changed after source preflight; recheck the source baseline")
            result.update(docker_image=image, docker_digest=identity["image_id"])
            steps = self._steps(info)
            with tempfile.TemporaryDirectory() as temporary:
                workdir = info.get("workdir", "/workspace")
                for number, step in enumerate(steps):
                    payload = Path(temporary) / str(number) / "payload"
                    evidence = Path(temporary) / str(number) / "evidence"
                    evidence.mkdir(parents=True)
                    evidence.chmod(0o777)  # The image may run with a non-root UID.
                    expected = create_payload(
                        payload, buggy_code, fixed_code, patch, target_path(info),
                        result["candidate_id"], step["name"],
                    )
                    if info.get("studio_uploaded_tests"):
                        from utils.validation_inputs import stage_uploaded_tests
                        stage_uploaded_tests(payload, info["studio_uploaded_tests"])
                    argv = [
                        "docker",
                        "run",
                        "--rm",
                        "--platform",
                        "linux/amd64",
                        "--security-opt",
                        "seccomp=unconfined",
                        "--cap-add",
                        "SYS_PTRACE",
                        "-v",
                        f"{payload}:{PAYLOAD_PATH}:ro",
                        "-v",
                        f"{evidence}:{EVIDENCE_PATH}:rw",
                    ]
                    for destination, source in info.get("extra_mounts", {}).items():
                        path = Path(destination)
                        if not path.is_absolute() or any(
                            path == Path(reserved) or path in Path(reserved).parents
                            or Path(reserved) in path.parents
                            for reserved in (PAYLOAD_PATH, EVIDENCE_PATH)
                        ):
                            raise ValueError("Extra mount overlaps validation evidence mounts")
                        argv.extend(["-v", f"{source}:{destination}:ro"])
                    argv.extend(
                        [
                            "--workdir",
                            workdir,
                            identity["image_id"],
                            "bash",
                            "-lc",
                            step["command"],
                        ]
                    )
                    if not self._command(
                        result, step, argv, env=env,
                        attestation=(evidence / "receipts.tsv", expected, identity["image_id"]),
                    ):
                        break
        except Exception as exc:
            result["error_log"] = str(exc)
            if self._preparation["status"] == "running":
                self._preparation.update(status="error", reason=str(exc),
                                         duration_seconds=time.monotonic() - setup_started)
                self._publish_progress(result, "docker_setup", False, status="error", error=str(exc))
        return finish_validation(result)
