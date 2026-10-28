#!/usr/bin/env python3
"""批量在线修复：遍历 vul_files 目录下所有 CVE，依次执行在线修复流程。

用法：
  python scripts/run_online.py \\
    --vul-files-dir data/processed/vul_files \\
    --indices-dir data/indices/test_index \\
    --output-dir results/online_batch \\
    --limit 10

断点续跑：
  程序中断后重新运行相同命令即可自动跳过已处理的 CVE。
  使用 --no-resume 强制从头重跑所有 CVE。
  使用 --retry-failed 在已跳过成功 CVE 的同时重跑上次失败的 CVE。
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Load environment variables
from dotenv import load_dotenv

load_dotenv(project_root / ".env")

import argparse
import inspect
import json
import os
import re
import time
from typing import Dict, List, Optional
from loguru import logger

from config.paths import ProjectPaths
from config.runtime import load_config, resolve_online_config
from utils.checkpoints import CheckpointManager
from utils.experiment_manifest import bind_manifest, create_manifest, write_json_atomic, hash_file
from utils.schemas import SCHEMA_VERSION
from utils.validation_scope import validation_mode, scope_commands
from utils.diagnostics import (
    diagnostic_text,
)
from utils.logger import setup_logger
from models import LLMInterface, EmbeddingModel, CodeEncoder
from models.llm_interface import LLMAuthError
from models.chat import create_diagnostic_models
from Offline import VectorStore
from Online.phase1_diagnosis import DiagnosticAgent
from Online.phase2_retrieval import QueryGenerator, Retriever, Reranker
from Online.phase3_repair import RepairAgent, Validator
from Online.phase1_diagnosis.root_cause_report import RootCauseReporter
from utils.source_context import select_source_context
from utils.source_baseline import ensure_source_baseline, select_source, configuration_hash, needs_source_baseline
from utils.experiment_store import ExperimentStore, digest
from utils.diagnosis_readiness import diagnosis_issues
from utils.telemetry import measure, utc_now, load_pricing
from utils.runtime_progress import RuntimeProgress, RetrievalProgress, progress_step


def _detect_patcheval_run(
    output_dir: Path,
    test_cmds: Optional[Dict],
    cve_metadata: Optional[Dict],
    buggy_code_file: Path,
) -> bool:
    """Detect PatchEval dataset runs."""
    path_parts = {part.lower() for part in output_dir.parts}
    path_parts.update(part.lower() for part in buggy_code_file.parts)
    if "patcheval" in path_parts or "patch_eval" in path_parts:
        return True

    meta = cve_metadata or {}
    test_info = test_cmds or {}
    dataset_text = " ".join(
        str(v)
        for v in (
            meta.get("dataset"),
            meta.get("benchmark"),
            meta.get("source"),
            test_info.get("dataset"),
            test_info.get("benchmark"),
        )
        if v
    ).lower()
    return "patcheval" in dataset_text or "patch_eval" in dataset_text


def find_vul_files_in_cve(cve_dir: Path) -> List[Path]:
    """在 CVE 目录下递归查找所有源代码文件。

    返回按文件大小排序的代码文件列表（通常主文件较大）。
    """
    code_extensions = {
        ".py",
        ".go",
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hpp",
        ".hxx",
        ".js",
        ".java",
        ".rs",
        ".rb",
        ".php",
    }
    files = []

    for ext in code_extensions:
        files.extend(cve_dir.rglob(f"*{ext}"))

    # 排除测试文件名常见模式
    filtered = [
        f
        for f in files
        if not any(
            pattern in f.name.lower() for pattern in ["test_", "_test.", "test."]
        )
    ]

    # 按文件大小排序（通常主漏洞文件较大）
    if filtered:
        return sorted(filtered, key=lambda f: f.stat().st_size, reverse=True)
    return sorted(files, key=lambda f: f.stat().st_size, reverse=True)


def load_test_cmds(cve_dir: Path) -> Optional[Dict]:
    """从 CVE 目录加载 test_cmds.json（如果存在）"""
    test_cmds_file = cve_dir / "test_cmds.json"
    if test_cmds_file.exists():
        try:
            with test_cmds_file.open("r", encoding="utf-8") as f:
                value = json.load(f)
            if not isinstance(value, dict) or not value:
                raise ValueError("Expected a nonempty JSON object")
            return scope_commands(value)
        except Exception as e:
            raise ValueError(f"无法读取有效的案例验证配置 {test_cmds_file}: {e}") from e
    return None


def requires_case_baseline(commands, config):
    if validation_mode(commands) == "patch_only":
        return False
    return needs_source_baseline(commands) or bool(commands and
        config["online"]["phase3_repair"]["validation"]["execution_mode"] == "docker")


def extract_docker_image_from_test_cmd(test_cmd: str) -> Optional[str]:
    """从测试命令注释中提取 Docker 镜像名称。

    示例注释格式：
    # From ghcr.io/anonymous2578-data/cve-2023-25173:latest
    """
    import re

    match = re.search(r"#\s*From\s+([\w./:_-]+)", test_cmd)
    if match:
        return match.group(1)
    return None


def load_cve_metadata(cve_id: str, input_json_path: Path) -> Optional[Dict]:
    """从 input.json 加载 CVE 的元数据（repo, commit 等）"""
    if not input_json_path.exists():
        logger.warning(f"input.json 不存在: {input_json_path}")
        return None

    try:
        with input_json_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        # 查找对应的 CVE
        for item in data:
            if item.get("cve_id") == cve_id:
                return item

        logger.warning(f"未在 input.json 中找到 {cve_id}")
        return None
    except Exception as e:
        logger.warning(f"读取 input.json 出错: {e}")
        return None


def load_case_meta(cve_dir: Path) -> Optional[Dict]:
    """从 CVE 目录下的 case_meta.json 加载元数据（Vul4C 等自带 provenance / line_numbers）。"""
    path = cve_dir / "case_meta.json"
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"读取 case_meta.json 失败 {path}: {e}")
        return None


def merge_cve_metadata(
    input_json_meta: Optional[Dict],
    case_meta: Optional[Dict],
) -> Optional[Dict]:
    """合并元数据：case_meta 覆盖 input.json 同名字段（便于 Vul4C 补充 line_numbers）。"""
    if not input_json_meta and not case_meta:
        return None
    merged: Dict = dict(input_json_meta or {})
    if case_meta:
        merged.update(case_meta)
    return merged


def exemplars_for_json_export(exemplars: List[Dict]) -> List[Dict]:
    """Retain the complete scoring, knowledge and source pair without clipping."""
    from copy import deepcopy

    return [
        {**deepcopy(item), "presentation_rank": rank}
        for rank, item in enumerate(exemplars, 1)
    ]


def repair_single_cve(
    cve_id: str,
    buggy_code_file: Path,
    test_cmds: Optional[Dict],
    cve_metadata: Optional[Dict],
    models_dict: Dict,
    config: Dict,
    output_dir: Path,
    use_retrieval: bool = True,
    use_diagnosis: bool = True,
    stage: str = "all",
    defer_validation: bool = False,
) -> Dict:
    """Run one resolved experiment variant, preserving original-file coordinates."""
    execution_trace = []
    if test_cmds is not None:
        test_cmds = scope_commands(test_cmds)
    selected_validation_mode = validation_mode(test_cmds)
    if selected_validation_mode == "patch_only":
        defer_validation = True
    window_info, repair_result = None, None
    retrieval_export, diagnosis_export = None, None
    store = models_dict["store"]

    def _persist_result_snapshot(
        success, iterations, final_patch, repair_history, error=None
    ):
        result = dict(
            cve_id=cve_id,
            success=success,
            iterations=iterations,
            final_patch=final_patch,
            repair_history=repair_history,
            error=error,
            variant=config["experiment"]["variant"],
            execution_trace=execution_trace,
            source_context=window_info,
            selected_candidate=(repair_result or {}).get("selected_candidate"),
        )
        if test_cmds and "studio_validation_mode" in test_cmds:
            result.update({key: (repair_result or {}).get(key) for key in
                           ("validation_mode", "requested_stages", "selected_checks_passed", "termination_reason")})
        if diagnosis_export is not None:
            result["phase1_diagnosis"] = diagnosis_export
        if retrieval_export is not None:
            retrieval_export["rendered_exemplars"] = getattr(
                models_dict["repair_agent"], "last_rendered_exemplars", []
            )
            result["retrieval"] = retrieval_export
            store.write_component(cve_id, "retrieval", retrieval_export)
        status = None
        if defer_validation and error is None:
            if (repair_result or {}).get("termination_reason") == "awaiting_validation":
                status = "patch_ready"
            else:
                error = "未生成可应用的补丁，请检查生成记录后重试。"
        return store.finish_case(cve_id, result, error=error, status=status)

    buggy_code = buggy_code_file.read_bytes().decode("utf-8")
    baseline = None
    if requires_case_baseline(test_cmds, config):
        baseline = models_dict.get("source_baselines", {}).get(cve_id)
        if (not baseline or baseline.get("source_sha256") != digest(buggy_code)
                or baseline.get("configuration_sha256") != configuration_hash(test_cmds)):
            with progress_step("source_check", "source_check", cve_id):
                baseline = ensure_source_baseline(buggy_code_file, test_cmds)
        if baseline["source_sha256"] != digest(buggy_code):
            raise ValueError("Source changed during baseline inspection; create a new snapshot")
        store.write_component(cve_id, "source_baseline", baseline)
        execution_trace.append("source_baseline_verified")
    store.start_source(cve_id, buggy_code, buggy_code_file)
    _, window_info = select_source_context(
        buggy_code, config["online"]["source_context"]
    )

    language_hint = (cve_metadata or {}).get("programming_language") or (
        cve_metadata or {}
    ).get("language")
    if not language_hint:
        language_hint = (test_cmds or {}).get("programming_language")
    component_dir = store.root / "cases" / cve_id

    def saved_component(name):
        path = component_dir / f"{name}.json"
        value = json.loads(path.read_text())
        if value.get("source_hash") != digest(buggy_code):
            raise ValueError(f"Saved {name} does not match this source and experiment")
        if value.get("experiment_id") != store.manifest["experiment_id"]:
            from utils.stage_handoff import is_inherited_component
            if not is_inherited_component(store.root, store.manifest, path):
                raise ValueError(f"Saved {name} does not match this source and experiment")
        return value

    if stage in ("retrieval", "repair"):
        diagnosis_export = saved_component("diagnosis")
        diagnostic_report = diagnosis_export["diagnostic_report"]
        issues = diagnosis_issues(diagnostic_report)
        if issues:
            raise ValueError("；".join(issues))
        execution_trace.append("saved_diagnosis")
    else:
        execution_trace.append("diagnosis_tools" if use_diagnosis else "diagnosis_llm")
        with measure("diagnosis"), progress_step("diagnosis", "diagnosis", cve_id):
            diagnosis_result = models_dict["diagnostic_agent"].diagnose(
                buggy_code,
                file_path=str(buggy_code_file),
                language=language_hint,
                focus_window=window_info if window_info["window_active"] else None,
            )
        diagnostic_report = diagnosis_result["diagnostic_report"]
        diagnosis_export = {
            "enabled": True,
            "tools_enabled": use_diagnosis,
            "diagnostic_report": diagnostic_report,
            "enhanced_context": diagnosis_result["enhanced_context"],
            "sampling": {
                stage: {
                    "requested": config["sampling"][stage],
                    "effective": (
                        models_dict["llm"].effective_sampling(**config["sampling"][stage])
                        if hasattr(models_dict["llm"], "effective_sampling")
                        else config["sampling"][stage]
                    ),
                }
                for stage in (
                    ("diagnosis", "diagnosis_report")
                    if use_diagnosis
                    else ("diagnosis_report",)
                )
            },
        }

        diagnosis_export["source_hash"] = digest(buggy_code)
        store.write_component(cve_id, "diagnosis", diagnosis_export)

    if stage == "diagnosis":
        issues = diagnosis_issues(diagnostic_report)
        return store.finish_case(cve_id, {"iterations": 0, "execution_trace": execution_trace},
                                 status="diagnosis_incomplete" if issues else "diagnosis_ready",
                                 error="；".join(issues) if issues else None)

    if stage == "repair" and use_retrieval:
        retrieval_export = saved_component("retrieval")
        if retrieval_export.get("diagnosis_hash") != hash_file(component_dir / "diagnosis.json"):
            raise ValueError("Saved retrieval does not match the reviewed diagnosis")
        top_exemplars = retrieval_export["final_exemplars"]
        execution_trace.append("saved_retrieval")
    else:
        # Phase 2: Retrieval and Re-ranking（消融实验时跳过）
        if use_retrieval:
            logger.info("=== Phase 2: Retrieval & Re-ranking ===")
            # Partial observations have their own identity-bound file. Final
            # exemplars remain unavailable until the original ranking completes.
            with RetrievalProgress(
                component_dir / "retrieval_progress.json", run_id=store.run_id,
                experiment_id=store.manifest["experiment_id"],
                source_hash=digest(buggy_code),
                diagnosis_hash=hash_file(component_dir / "diagnosis.json"),
            ) as partial:
                execution_trace.append("query_generation")
                with measure("query_generation"), progress_step("retrieval", "query_generation", cve_id):
                    queries = models_dict["query_generator"].generate_queries(diagnostic_report)
                partial.update(step="retrieval", queries=queries)
                logger.info("生成多视角查询")

                completed_views = []

                def observe_view(view, pooled):
                    completed_views.append(view)
                    partial.update(candidates=pooled, completed_views=completed_views)

                final_top_k = config["online"]["phase2_retrieval"]["final_top_k"]
                execution_trace.append("retrieval")
                retrieve = models_dict["retriever"].retrieve
                # Older/custom retrievers keep their original call signature.
                # Never catch TypeError from inside the actual retrieval call.
                supports_observer = "on_view" in inspect.signature(retrieve).parameters
                with measure("retrieval"), progress_step("retrieval", "retrieval", cve_id):
                    candidates = (retrieve(queries, on_view=observe_view)
                                  if supports_observer else retrieve(queries))
                partial.update(step="reranking", candidates=candidates,
                               completed_views=list(queries))
                logger.info(f"检索到 {len(candidates)} 个候选样本")

                execution_trace.append("reranking")
                with measure("reranking"), progress_step("retrieval", "reranking", cve_id):
                    top_exemplars = models_dict["reranker"].rerank(
                        diagnostic_report,
                        buggy_code,
                        candidates,
                        top_k=final_top_k,
                    )
                logger.info(f"重排后选择 top-{len(top_exemplars)} 样例")
                retrieval_export = {
                    "window": window_info,
                    "queries": dict(queries),
                    "num_candidates": len(candidates),
                    "ranking": models_dict["reranker"].last_run,
                    "final_top_k": len(top_exemplars),
                    "final_exemplars": exemplars_for_json_export(top_exemplars),
                }
                retrieval_export.update(source_hash=digest(buggy_code), diagnosis_hash=hash_file(component_dir / "diagnosis.json"))
                store.write_component(cve_id, "retrieval", retrieval_export)
                partial.update(status="completed", step="completed")
        else:
            logger.info("=== Phase 2: SKIPPED (--no-retrieval) ===")
            top_exemplars = []
            retrieval_export = {
                "skipped": True,
                "reason": "use_retrieval=False (e.g. --no-retrieval)",
            }

        if not use_retrieval:
            retrieval_export.update(source_hash=digest(buggy_code), diagnosis_hash=hash_file(component_dir / "diagnosis.json"))
            store.write_component(cve_id, "retrieval", retrieval_export)

    if stage == "retrieval":
        return store.finish_case(cve_id, {"iterations": 0, "execution_trace": execution_trace}, status="retrieval_ready")

    # Phase 3: Iterative Repair
    logger.info("=== Phase 3: Iterative Repair ===")

    # 构建 project_info（包含测试命令和 Docker 信息）
    # 构建 project_info（至少包含文件路径，用于语言检测）
    project_info = {
        "buggy_code_file": str(buggy_code_file),
        "cve_id": cve_id,
        "is_patcheval": _detect_patcheval_run(
            output_dir, test_cmds, cve_metadata, buggy_code_file
        ),
    }
    if test_cmds and "studio_validation_mode" in test_cmds:
        project_info["studio_validation_mode"] = selected_validation_mode

    # 推断仓库内相对路径（PatchEval 容器内 git apply 依赖正确的 relpath）
    # 期望布局: .../<CVE-XXXX-XXXX>/<commit_hash>/<repo_relpath>
    # 例如:
    #   CVEdataset/CVE-2016-10548/da7bce7d/index.js          → index.js
    #   CVEdataset/CVE-2015-8213/710e11d/django/utils/formats.py → django/utils/formats.py
    #   CVEdataset/CVE-2017-0360/5d7c4fa/trytond/tools/misc.py   → trytond/tools/misc.py
    try:
        parts = buggy_code_file.parts
        repo_relpath = buggy_code_file.name  # fallback
        for i, part in enumerate(parts):
            if part.upper().startswith("CVE-"):
                # parts[i] = CVE 目录, parts[i+1] = commit 目录
                # relpath = commit 目录之后的所有部分
                if i + 2 < len(parts):
                    commit_dir = Path(parts[0]).joinpath(*parts[1 : i + 2])
                    repo_relpath = str(buggy_code_file.relative_to(commit_dir)).replace(
                        "\\", "/"
                    )
                break
        project_info["repo_relpath"] = repo_relpath
        logger.debug(f"推断 repo_relpath: {repo_relpath}")
    except Exception as e:
        project_info["repo_relpath"] = buggy_code_file.name
        logger.debug(f"repo_relpath fallback to filename: {e}")

    # test_cmds 的 source_file 是仓库内的权威相对路径（如 libtiff/tif_ojpeg.c），
    # 优先级高于从文件路径推断的 repo_relpath（后者对非 CVE-xxx 命名的 bug_id 会退化为文件名）。
    if test_cmds and test_cmds.get("source_file"):
        _src_file = test_cmds["source_file"].strip().removeprefix("./")
        if _src_file:
            project_info["repo_relpath"] = _src_file
            logger.debug(f"repo_relpath 已从 test_cmds.source_file 覆盖: {_src_file}")

    project_info["source_context"] = window_info
    if baseline:
        project_info["expected_docker_image_id"] = baseline["docker_image_id"]

    if test_cmds:
        poc_test_cmd = test_cmds.get("poc_test_cmd")
        unit_test_cmd = test_cmds.get("unit_test_cmd")
        is_patcheval_run = bool(project_info.get("is_patcheval"))

        test_cmd = unit_test_cmd or poc_test_cmd or test_cmds.get("test_command")
        if poc_test_cmd:
            project_info["poc_test_command"] = poc_test_cmd
        if unit_test_cmd:
            project_info["unit_test_command"] = unit_test_cmd
        if test_cmd:
            project_info["test_command"] = test_cmd
        if test_cmds.get("compile_cmd"):
            project_info["compile_command"] = test_cmds["compile_cmd"]
        for field in (
            "validation_steps",
            "studio_uploaded_tests",
            "local_project_dir",
            "docker_image",
            "workdir",
            "extra_mounts",
            "compile_mode",
            "compile_flags",
        ):
            if field in test_cmds:
                project_info[field] = test_cmds[field]
        if test_cmd or poc_test_cmd or unit_test_cmd:
            project_info["programming_language"] = test_cmds.get("programming_language")

            # 提取 Docker 镜像名（不依赖 execution_mode，Validator 会自动识别并切换）
            docker_cmd_for_image = unit_test_cmd or poc_test_cmd or test_cmd
            docker_image = (
                project_info.get("docker_image")
                or extract_docker_image_from_test_cmd(docker_cmd_for_image)
                if isinstance(docker_cmd_for_image, str)
                else None
            )
            if docker_image:
                project_info["docker_image"] = docker_image
                logger.info(f"Docker 镜像(从 test_cmd 提取): {docker_image}")

            # 从 metadata 中获取 repo/commit/file_path 信息（如存在）
            if cve_metadata:
                repo = cve_metadata.get("repo")
                if repo:
                    project_info["repo"] = repo

                vul_funcs = cve_metadata.get("vul_func", [])
                if vul_funcs:
                    commit = vul_funcs[0].get("commit")
                    file_path = vul_funcs[0].get("file_path")
                    if commit:
                        project_info["commit"] = commit
                    if file_path:
                        project_info["file_path"] = file_path

                logger.info(
                    f"Repo: {repo}, Commit: {project_info.get('commit', 'N/A')}"
                )

            if poc_test_cmd and unit_test_cmd:
                logger.info(f"加载测试命令: poc + unit（先漏洞回归，再功能回归）")
            else:
                preview_cmd = docker_cmd_for_image or test_cmd
                if preview_cmd:
                    logger.info(f"加载测试命令: {preview_cmd[:80]}...")

        # ──────────────────────────────────────────────────────────────────────
        # vulnloc 风格样本：test.sh 只运行已有 binary，不做 setup/apply/build。
        # validator 每次 `docker run --rm` 启动全新容器，需要完整的生命周期命令：
        #   [cp from host OR setup.sh clone] → git apply fix.patch → config+build → test.sh
        #
        # 优化：若宿主机 data/experiment/san2patch-benchmark 已有克隆好的源码，
        # 将其只读挂载为 /host_src，在容器内 cp -r 比 git clone 快 10x 以上。
        # 检测条件：test_cmds 中存在 container_src_dir 且 poc_test_cmd 中不含
        # "fix.patch" / "git apply"（后两者是自包含式 san2patch-selected 的特征）。
        # ──────────────────────────────────────────────────────────────────────
        def _strip_from_header(cmd: str) -> str:
            """去掉 '# From image:tag\\n' 首行注释，返回实际 shell 命令。"""
            if isinstance(cmd, str) and cmd.lstrip().startswith("# From "):
                parts = cmd.split("\n", 1)
                return parts[1].strip() if len(parts) > 1 else ""
            return (cmd or "").strip()

        _case_dir = test_cmds.get("case_dir_in_container", "")
        _src_dir = test_cmds.get("container_src_dir", "")
        _func_dir = test_cmds.get("container_func_src_dir", "")
        _raw_poc = _strip_from_header(poc_test_cmd or "")
        _raw_unit = _strip_from_header(unit_test_cmd or "")

        def _is_runonly(cmd: str) -> bool:
            return bool(cmd and "fix.patch" not in cmd and "git apply" not in cmd)

        if _case_dir and _src_dir and _is_runonly(_raw_poc) and not is_patcheval_run:
            # 尝试使用宿主机已克隆的源码（/experiment/san2patch-benchmark/... → data/experiment/...）
            # container_src_dir 格式: /experiment/san2patch-benchmark/{subject}/{bug_id}/src
            _src_parts = Path(
                _src_dir
            ).parts  # ('/', 'experiment', 'san2patch-benchmark', ...)
            _use_host_src = False
            _host_benchmark_dir = None
            _host_src_rel = (
                None  # 相对于 benchmark 目录的路径，如 "libtiff/bugzilla-2611/src"
            )
            if len(_src_parts) >= 4 and _src_parts[1] == "experiment":
                _benchmark_name = _src_parts[2]  # e.g. "san2patch-benchmark"
                _host_benchmark_dir = (
                    project_root / "data" / "experiment" / _benchmark_name
                )
                _host_src_rel = str(
                    Path(*_src_parts[3:])
                )  # e.g. "libtiff/bugzilla-2611/src"
                _host_src_abs = _host_benchmark_dir / _host_src_rel
                if _host_src_abs.exists():
                    _use_host_src = True
                    logger.info(f"[vulnloc] 检测到宿主机已克隆源码: {_host_src_abs}")

            if _use_host_src:
                # 宿主机源码通过 /host_src 只读挂载进容器，cp 代替 git clone。
                # 用 "mkdir -p dest && cp -a src/. dest/" 而非 "cp -r src dest"：
                # 当 dest 已存在（Docker 镜像预建了空目录）时，cp -r 会在 dest 内
                # 再创建一层 src/，导致 configure 被放到 dest/src/configure 而非 dest/configure。
                # cp -a src/. dest/ 始终把内容平铺到 dest，无论 dest 是否已存在。
                _setup_cmd = (
                    f"mkdir -p {_src_dir} && "
                    f"cp -a /host_src/{_host_src_rel}/. {_src_dir}/"
                )
                project_info.setdefault("extra_mounts", {})["/host_src"] = str(
                    _host_benchmark_dir
                )
            else:
                # 回退：容器内 setup.sh 做完整 git clone
                _setup_cmd = f"cd {_case_dir} && bash setup.sh 2>&1"

            # aclocal 版本兼容：部分旧项目的 Makefile 依赖特定版本号的 aclocal（如 aclocal-1.11）。
            # 当 make 检测到 configure.ac 时间戳更新时会尝试重新运行该版本，找不到就报错退出。
            # 提前为所有常见旧版本建立软链接，指向当前系统安装的 aclocal，使其透明兼容。
            _aclocal_compat = (
                "aclocal_bin=$(which aclocal 2>/dev/null) && "
                'if [ -n "$aclocal_bin" ]; then '
                "  for v in 1.9 1.10 1.11 1.12 1.13 1.14 1.15 1.16; do "
                '    [ -e "/usr/local/bin/aclocal-$v" ] || '
                '    ln -sf "$aclocal_bin" "/usr/local/bin/aclocal-$v" 2>/dev/null || true; '
                "  done; "
                "fi"
            )
            _poc_full = (
                f"{_setup_cmd} && "
                f"cd {_case_dir} && (bash deps.sh 2>&1 || true) && "
                f"{_aclocal_compat} && "
                f"cd {_src_dir} && "
                f"git apply --check /workspace/fix.patch 2>&1 && "
                f"git apply /workspace/fix.patch 2>&1 && "
                f"cd {_case_dir} && bash config.sh && bash build.sh && "
                f"{_raw_poc}"
            )
            project_info["poc_test_command"] = _poc_full
            project_info["test_command"] = _poc_full
            _mode = "cp from host" if _use_host_src else "setup.sh clone"
            logger.info(
                f"[vulnloc] 已构造完整 poc 验证命令（{_mode}→apply→build→test）"
            )

        if _case_dir and _src_dir and _func_dir and _is_runonly(_raw_unit):
            _use_host_src_func = bool(
                project_info.get("extra_mounts", {}).get("/host_src")
            )

            if _use_host_src_func and _host_src_rel:
                # unit test 也复用宿主机源码（函数版本 /experiment_func/...）
                _setup_func_cmd = (
                    f"mkdir -p {_func_dir} && "
                    f"cp -a /host_src/{_host_src_rel}/. {_func_dir}/"
                )
            else:
                # 回退：clone 到 /experiment 再 cp -a 内容到 /experiment_func
                _setup_func_cmd = (
                    f"cd {_case_dir} && bash setup.sh 2>&1 && "
                    f"mkdir -p {_func_dir} && cp -a {_src_dir}/. {_func_dir}/"
                )

            _unit_full = (
                f"{_setup_func_cmd} && "
                f"cd {_case_dir} && (bash deps.sh 2>&1 || true) && "
                f"{_aclocal_compat} && "
                f"cd {_func_dir} && "
                f"git apply --check /workspace/fix.patch 2>&1 && "
                f"git apply /workspace/fix.patch 2>&1 && "
                f"cd {_case_dir} && bash config_func.sh && bash build_func.sh && "
                f"{_raw_unit}"
            )
            project_info["unit_test_command"] = _unit_full
            if is_patcheval_run:
                project_info["test_command"] = _unit_full
            _mode2 = "cp from host" if _use_host_src_func else "setup.sh clone"
            logger.info(
                f"[vulnloc] 已构造完整 unit 验证命令（{_mode2}→apply→build_func→test_func）"
            )

    store.write_component(
        cve_id,
        "inputs",
        dict(
            source_file=str(buggy_code_file),
            metadata=cve_metadata,
            test_commands=test_cmds,
            effective_validation=project_info,
        ),
    )

    try:
        execution_trace.append("repair")
        with measure("repair"), progress_step("repair", "repair", cve_id):
            repair_result = models_dict["repair_agent"].repair(
                buggy_code,
                top_exemplars,  # 消融时为 []，repair_agent 会走"无示例"分支
                diagnostic_report=diagnostic_report,
                project_info=project_info,
                **({"defer_validation": True} if defer_validation else {}),
            )

        for attempt in repair_result.get("history", []):
            execution_trace.append(attempt.get("stage", "generation"))
            if attempt.get("validation_invoked"):
                execution_trace.append("validation")
        logger.info("结果: {}", "待验证" if repair_result.get("termination_reason") == "awaiting_validation"
                    else "所选验证通过" if repair_result.get("selected_checks_passed")
                    else "成功" if repair_result["success"] else "失败")
        logger.info(f"迭代次数: {repair_result['iterations']}")
        return _persist_result_snapshot(
            success=repair_result["success"],
            iterations=repair_result["iterations"],
            final_patch=repair_result.get("final_patch"),
            repair_history=repair_result.get("history", []),
            error=repair_result.get("error"),
        )
    except LLMAuthError as e:
        logger.error(f"repair_single_cve 认证异常，先保存中间结果: {e}")
        partial_history = list(
            getattr(models_dict["repair_agent"], "repair_history", []) or []
        )
        _persist_result_snapshot(
            success=False,
            iterations=len(partial_history),
            final_patch=None,
            repair_history=partial_history,
            error=str(e),
        )
        raise
    except Exception as e:
        logger.error(f"repair_single_cve 异常，尝试保存中间结果: {e}")
        partial_history = list(
            getattr(models_dict["repair_agent"], "repair_history", []) or []
        )
        return _persist_result_snapshot(
            success=False,
            iterations=len(partial_history),
            final_patch=None,
            repair_history=partial_history,
            error=str(e),
        )


def initialize_models(config, indices_dir, store, stage="all", *, defer_validation=False):
    """Initialize once, after the denominator and pending case records exist."""
    llm_config = config["models"]["llm"]
    with progress_step(stage, "model_loading"):
        llm = LLMInterface(
            provider=llm_config["provider"],
            model_name=llm_config["model_name"],
            api_key=llm_config.get("api_key"),
            base_url=llm_config.get("base_url"),
            temperature=llm_config["temperature"],
            max_tokens=llm_config["max_tokens"],
            extra_body=llm_config.get("extra_body"),
            temperature_policy=llm_config["temperature_policy"],
            token_limit_parameter=llm_config["token_limit_parameter"],
        )
    retrieval_config = config["online"]["phase2_retrieval"]
    if retrieval_config["enabled"] and stage in ("all", "retrieval"):
        if not indices_dir.is_dir():
            raise FileNotFoundError(f"Index directory is missing: {indices_dir}")
        with progress_step(stage, "embedding_model_loading"):
            embedding = EmbeddingModel(
                **config["models"]["embeddings"], device=config["experiment"]["device"]
            )
        with progress_step(stage, "code_encoder_loading"):
            encoder = CodeEncoder(
                **config["models"]["code_encoder"], device=config["experiment"]["device"]
            )
        with progress_step(stage, "index_loading"):
            vectors = VectorStore(dimension=config["models"]["embeddings"]["dimension"])
            vectors.load(indices_dir, views=retrieval_config["views"])
            query = QueryGenerator(
                llm, view_types=retrieval_config["views"], sampling=config["sampling"]
            )
            retriever = Retriever(
                vectors, embedding, top_k_per_view=retrieval_config["top_k_per_view"]
            )
            reranker = Reranker(encoder, **retrieval_config["reranking"])
    else:
        embedding = encoder = query = retriever = reranker = None
    agent = None
    if stage in ("all", "diagnosis"):
        if config["online"]["phase1_diagnosis"]["enabled"]:
            model, reporter = create_diagnostic_models(llm_config, config["sampling"])
            diagnosis = config["online"]["phase1_diagnosis"]
            agent = DiagnosticAgent(
                model,
                reporter,
                max_rounds=diagnosis["max_rounds"],
                max_tool_calls=diagnosis["max_tool_calls"],
                history_turns=diagnosis["history_turns"],
                enabled_tools=diagnosis["tools"],
            )
        else:
            agent = RootCauseReporter(
                llm, config["sampling"], views=retrieval_config["views"]
            )
    repair = None
    if stage in ("all", "repair"):
        validation_config = config["online"]["phase3_repair"]["validation"]
        validator = None if defer_validation else Validator(
            compiler=validation_config["compiler"],
            compile_timeout=validation_config["compile_timeout"],
            test_timeout=validation_config["test_timeout"],
            execution_mode=validation_config["execution_mode"],
        )
        repair_config = config["online"]["phase3_repair"]
        repair = RepairAgent(
            llm,
            validator,
            max_iterations=repair_config["max_iterations"],
            single_attempt=repair_config["single_attempt"],
            sampling=config["sampling"],
            max_exemplars=repair_config["max_exemplars"],
        )

    def identity(model):
        if model is None:
            return None
        return {
            name: getattr(model, name, None)
            for name in ("model_name", "revision", "dimension", "protocol")
        }

    write_json_atomic(
        store.root / "runs" / store.run_id / "loaded_models.json",
        dict(
            llm=identity(llm),
            embeddings=identity(embedding),
            code_encoder=identity(encoder),
        ),
    )
    return dict(
        llm=llm,
        diagnostic_agent=agent,
        query_generator=query,
        retriever=retriever,
        reranker=reranker,
        repair_agent=repair,
        experiment_id=store.manifest["experiment_id"],
        store=store,
    )


def main():
    run_started, run_stamp = time.monotonic(), utc_now()
    parser = argparse.ArgumentParser(
        description="KeaRepair: recorded repair experiments"
    )
    parser.add_argument("--config", default="config/online.yaml")
    parser.add_argument("--defer-validation", action="store_true",
                        help="Generate and save a patch for explicit validation; requires --stage repair")
    parser.add_argument("--stage", choices=["all", "diagnosis", "retrieval", "repair"], default="all", help="Studio stage boundary; default retains batch behavior")
    parser.add_argument("--vul-files-dir", default="data/processed/vul_files")
    parser.add_argument("--case-list-file")
    parser.add_argument("--indices-dir")
    parser.add_argument("--index-snapshot", action="store_true", help="Use an already resolved, immutable index generation")
    parser.add_argument("--output-dir", default="results/online_batch")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--llm-provider", choices=["openai", "anthropic", "gemini", "mock"]
    )
    parser.add_argument(
        "--variant",
        choices=[
            "full",
            "df_only",
            "cf_only",
            "no_retrieval",
            "no_diagnosis",
            "no_iteration",
        ],
    )
    parser.add_argument("--no-retrieval", action="store_true")
    parser.add_argument("--no-diagnosis", action="store_true")
    parser.add_argument("--no-iteration", action="store_true")
    parser.add_argument(
        "--retrieval-view", default="all", choices=["all", "data_flow", "control_flow"]
    )
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--retry-failed", action="store_true")
    parser.add_argument("--studio-stage", action="store_true",
                        help="Preserve a prior interactive stage in a new experiment after code changes")
    parser.add_argument(
        "--pricing-snapshot",
        help="User-supplied dated model prices; estimates stay separate from provider billing",
    )
    args = parser.parse_args()
    if args.defer_validation and args.stage != "repair":
        parser.error("--defer-validation requires --stage repair")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    config = resolve_online_config(
        load_config(args.config),
        provider=args.llm_provider,
        variant=args.variant,
        no_diagnosis=args.no_diagnosis,
        no_retrieval=args.no_retrieval,
        no_iteration=args.no_iteration,
        retrieval_view=args.retrieval_view,
    )
    if args.pricing_snapshot:
        config["experiment"]["pricing_snapshot"] = str(
            Path(args.pricing_snapshot).resolve()
        )
    load_pricing(config["experiment"].get("pricing_snapshot"))
    setup_logger(
        log_file=config["logging"]["log_file"], level=config["logging"]["level"]
    )
    output = Path(args.output_dir)
    root = Path(args.vul_files_dir)
    is_case = lambda path: path.is_dir() and path.name.startswith(
        ("CVE-", "bugzilla-", "gnubug-")
    )
    discovered = (
        [root]
        if is_case(root)
        else (
            sorted(
                (path for path in root.iterdir() if is_case(path)),
                key=lambda path: path.name,
            )
            if root.is_dir()
            else []
        )
    )
    by_id = {path.name: path for path in discovered}
    excluded = []
    if args.case_list_file:
        ids = [
            line.strip()
            for line in Path(args.case_list_file).read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if len(ids) != len(set(ids)):
            parser.error("Case list contains duplicate IDs")
        excluded.extend(
            dict(case_id=name, reason="not_in_requested_case_list")
            for name in by_id
            if name not in ids
        )
    else:
        ids = list(by_id)
    if any(Path(name).name != name or name in {".", ".."} for name in ids):
        parser.error("Case IDs must be safe filenames")
    if args.limit:
        excluded.extend(
            dict(case_id=name, reason="explicit_limit") for name in ids[args.limit :]
        )
        ids = ids[: args.limit]
    cases = dict(
        case_ids=ids,
        excluded=excluded,
        selection_source=(
            str(args.case_list_file)
            if args.case_list_file
            else "discovered_directories"
        ),
        missing_at_selection=[name for name in ids if name not in by_id],
    )
    paths = ProjectPaths()
    input_json_path = paths.raw_data / "input.json"
    indices = Path(args.indices_dir or config["data"]["indices_dir"])
    if not args.index_snapshot:
        from utils.knowledge_index import resolve_knowledge_index
        indices = resolve_knowledge_index(indices)
    case_paths = [path for name in ids if (path := by_id.get(name)) is not None]
    # Verification receipts are derived caches, not repair input data.
    cache_paths = [path / "source_baseline.json" for path in case_paths]
    inputs = [file for path in case_paths for file in sorted(path.rglob("*"))
              if file.is_file() and file != path / "source_baseline.json"]
    if input_json_path.exists():
        inputs.append(input_json_path)
    if args.case_list_file:
        inputs.append(Path(args.case_list_file))
    pricing = config["experiment"].get("pricing_snapshot")
    if pricing:
        inputs.append(Path(pricing))
    if config["online"]["phase2_retrieval"]["enabled"] and indices.is_dir():
        inputs.extend(sorted(indices.glob("index_*.faiss")))
        inputs.extend(
            indices / name
            for name in ("metadata.pkl", "manifest.json")
            if (indices / name).exists()
        )
    candidate_manifest = create_manifest(
        "online", config, project_root=project_root, data_paths=inputs,
        parameters=dict(case_selection=cases, indices_dir=str(indices),
                        schema_version=SCHEMA_VERSION),
    )
    if args.studio_stage:
        from utils.stage_handoff import bind_studio_manifest
        cache_keys = [
            path.resolve().relative_to(project_root).as_posix()
            if path.resolve().is_relative_to(project_root) else str(path.resolve())
            for path in cache_paths
        ]
        manifest = bind_studio_manifest(output, candidate_manifest, stage=args.stage,
                                       case_ids=ids, cache_keys=cache_keys)
    else:
        manifest = bind_manifest(output, candidate_manifest)
    store = ExperimentStore(output, manifest, cases, project_root=project_root)
    checkpoint = CheckpointManager(
        output, args.vul_files_dir, manifest["experiment_id"]
    )
    checkpoint.load()
    if args.no_resume:
        checkpoint.reset()
    elif args.retry_failed:
        checkpoint.clear_failed()
    checkpoint._save_atomic()
    pending = [
        name
        for name in ids
        if args.stage != "all" or not checkpoint.is_done(name, skip_failed=not args.retry_failed)
    ]
    store.pending_case_ids = pending
    run_path = output / "runs" / store.run_id / "run.json"
    run = dict(
        run_id=store.run_id,
        started_at=run_stamp,
        status="running",
        pending_case_ids=pending,
        no_resume=args.no_resume,
        retry_failed=args.retry_failed,
        defer_validation=args.defer_validation,
    )
    write_json_atomic(run_path, run)
    run_error = None
    progress_error = None
    models = None
    progress = RuntimeProgress(output / "progress.json", stage=args.stage, run_id=store.run_id)
    try:
        with progress.activate(), store.recorder.activate(), measure(
            "run_total", started_monotonic=run_started, started_at=run_stamp
        ):
            if not pending:
                return
            # Check every requested container baseline before constructing models.
            # An input/environment error must not consume a generation budget.
            source_baselines, baseline_errors = {}, {}
            for case_id in pending:
                case_dir = by_id.get(case_id)
                if case_dir is None:
                    continue
                try:
                    commands = load_test_cmds(case_dir)
                    if not requires_case_baseline(commands, config):
                        continue
                    logger.info(f"[{case_id}] 正在核对容器源码（编译/PoC 与单元测试）")
                    write_json_atomic(output / "source_preflight.json", {"case_id": case_id, "run_id": store.run_id, "status": "running"})
                    with progress_step("source_check", "source_check", case_id):
                        source = select_source(case_dir, commands)
                        source_baselines[case_id] = ensure_source_baseline(
                            source, commands, receipt_path=case_dir / "source_baseline.json",
                            fallback_receipt_paths=(store.root / "cases" / case_id / "source_baseline.json",),
                        )
                    logger.info(f"[{case_id}] 源码一致性检查通过")
                    write_json_atomic(output / "source_preflight.json", {"case_id": case_id, "run_id": store.run_id, "status": "verified"})
                except Exception as exc:
                    baseline_errors[case_id] = exc
                    progress_error = str(exc)
                    logger.error(f"[{case_id}] 源码检查未通过，尚未调用模型：{exc}")
                    write_json_atomic(output / "source_preflight.json", {"case_id": case_id, "run_id": store.run_id, "status": "blocked", "error": str(exc)})
            if all(case_id in baseline_errors for case_id in pending):
                run_error = "All requested cases failed source preflight; no model was initialized"
                for case_id in pending:
                    with store.case(case_id):
                        store.finish_case(case_id, error=baseline_errors[case_id], status="error")
                        if args.stage in ("all", "repair"):
                            checkpoint.mark(case_id, "error", error=baseline_errors[case_id])
                return
            with measure("model_loading"):
                models = initialize_models(config, indices, store, stage=args.stage,
                                           **({"defer_validation": True} if args.defer_validation else {}))
            models["source_baselines"] = source_baselines
            for case_id in pending:
                stop = False
                with store.case(case_id):
                    try:
                        if case_id in baseline_errors:
                            raise baseline_errors[case_id]
                        case_dir = by_id.get(case_id)
                        if case_dir is None:
                            raise FileNotFoundError(
                                f"Requested case directory missing: {case_id}"
                            )
                        source_files = find_vul_files_in_cve(case_dir)
                        if not source_files:
                            raise FileNotFoundError(
                                f"Case contains no source file: {case_id}"
                            )
                        commands = load_test_cmds(case_dir)
                        source_file = select_source(case_dir, commands) if (commands or {}).get("source_file") else source_files[0]
                        metadata = merge_cve_metadata(
                            (
                                load_cve_metadata(case_id, input_json_path)
                                if input_json_path.exists()
                                else None
                            ),
                            load_case_meta(case_dir),
                        )
                        result = repair_single_cve(
                            case_id,
                            source_file,
                            commands,
                            metadata,
                            models,
                            config,
                            output,
                            stage=args.stage,
                            defer_validation=args.defer_validation,
                            use_retrieval=config["online"]["phase2_retrieval"][
                                "enabled"
                            ],
                            use_diagnosis=config["online"]["phase1_diagnosis"][
                                "enabled"
                            ],
                        )
                        if result.get("error"):
                            progress_error = result["error"]
                        if args.stage in ("all", "repair") and result.get("status") != "patch_ready":
                            checkpoint.mark(case_id, "success" if result["success"] else "failed")
                    except Exception as exc:
                        progress_error = str(exc)
                        store.finish_case(case_id, error=exc, status="error")
                        if args.stage in ("all", "repair"):
                            checkpoint.mark(case_id, "error", error=exc)
                        stop = isinstance(exc, LLMAuthError)
                        if stop:
                            run_error = f"{type(exc).__name__}: {exc}"
                if stop:
                    break
    except BaseException as exc:
        run_error = f"{type(exc).__name__}: {exc}"
        if models is None:
            store.startup_failure(exc)
        raise
    finally:
        progress.finish(error=run_error or progress_error)
        run.update(
            status="failed" if run_error else "completed",
            error=run_error,
            finished_at=utc_now(),
        )
        write_json_atomic(run_path, run)
        if args.stage in ("all", "repair"):
            store.summarize()


if __name__ == "__main__":
    main()
