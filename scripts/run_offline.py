#!/usr/bin/env python3
"""离线索引构建主脚本

API 调用流程（默认离线索引）：
============================
1. 用户运行: python scripts/run_offline.py --data-path ... --llm-provider openai
2. 脚本加载 .env 文件，读取 OPENAI_API_KEY 环境变量
3. 初始化 LLMInterface(provider="openai", api_key=从环境变量获取)
4. 对每个样本、每个视角执行：
   a) MultiViewGenerator.extract_knowledge()
      （输入漏洞描述以及已核对的漏洞/修复函数对）
      → self.llm.generate(prompt, ...) → LLMInterface → 网关

   b) ViewDistillation.distill_without_patch()
      → 同样的调用链（泛化标识符并保留全部知识字段）

5. EmbeddingModel 仅编码 abstracted_knowledge.root_cause，其余字段存为元数据。

每个样本、每个视角默认 **2 次** LLM 调用（生成 + 蒸馏）。
"""

import sys
from pathlib import Path

# 添加项目根目录到 path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# 加载环境变量（从 .env 文件）
from dotenv import load_dotenv

load_dotenv(project_root / ".env")

import argparse
import json
import time
from loguru import logger

from config.paths import ProjectPaths
from config.runtime import load_config, resolve_offline_config
from utils.experiment_manifest import (
    bind_manifest,
    create_manifest,
    index_parameters,
    write_json_atomic,
)
from utils.knowledge import prepare_dataset, load_exclusions
from utils.llm_errors import LLMConnectionError
from utils.logger import setup_logger
from utils.experiment_store import snapshot_sources
from utils.telemetry import Recorder, measure, load_pricing, utc_now
from utils.metrics import evaluate_experiment
import yaml
from data_loader import BigVulLoader
from models import LLMInterface, EmbeddingModel
from models.llm_interface import LLMAuthError, LLMError
from Offline import (
    MultiViewGenerator,
    ViewDistillation,
    VectorStore,
    IndexBuilder,
)


def main():
    """离线索引主函数"""
    run_started, run_stamp = time.monotonic(), utc_now()
    parser = argparse.ArgumentParser(description="KeaRepair 离线索引构建")
    parser.add_argument(
        "--config",
        type=str,
        default="config/offline.yaml",
        help="配置文件路径",
    )
    parser.add_argument(
        "--data-path",
        type=str,
        required=True,
        help="Big-Vul 数据集路径",
    )
    parser.add_argument(
        "--exclude-cves",
        type=str,
        default=None,
        help="显式排除的 CVE 清单（每行一个 ID，或 JSON 字符串列表）；清单与排除结果会被记录",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="索引输出目录（默认从配置读取）",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="--output-dir 的别名",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=32,
        help="批处理大小",
    )
    parser.add_argument(
        "--llm-provider",
        type=str,
        default=None,
        choices=["openai", "anthropic", "gemini", "mock"],
        help="LLM 提供商（使用 'mock' 进行离线测试）",
    )
    parser.add_argument(
        "--llm-model",
        type=str,
        default=None,
        help="覆盖 config 中的 models.llm.model_name（网关返回 model_not_found 时改用此参数）",
    )
    parser.add_argument(
        "--llm-base-url",
        type=str,
        default=None,
        help="覆盖 config 中的 models.llm.base_url",
    )
    parser.add_argument(
        "--views",
        type=str,
        default=None,
        help="只构建指定视角（逗号分隔），例如: data_flow 或 data_flow,control_flow",
    )
    # ---- 消融实验 ----
    parser.add_argument(
        "--patch-guided",
        action="store_true",
        default=False,
        help=(
            "兼容旧脚本：与默认流程相同。"
            "离线索引均为「补丁引导多视角 RCA + 无补丁蒸馏 + 建库」。"
        ),
    )
    parser.add_argument(
        "--patch-oracle",
        action="store_true",
        default=False,
        help=(
            "【消融实验】跳过所有 LLM 盲视生成和蒸馏步骤，"
            "直接以数据集中的 ground-truth patch 文本构建所选视角索引。"
            "LLM 接口和 EmbeddingModel 仍会被初始化，但 LLM 不会被调用。"
        ),
    )
    parser.add_argument(
        "--no-view-prefix",
        action="store_true",
        default=False,
        help=(
            "与 --patch-oracle 配合使用。"
            "默认为所选视角的 patch 文本添加视角前缀（如 'Data flow fix:'），"
            "设置此标志则各视角使用相同的原始 patch 文本。"
        ),
    )

    parser.add_argument(
        "--pricing-snapshot", help="Dated exact-model price snapshot for estimates"
    )
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("--batch-size must be positive")

    # 加载配置
    source_config = load_config(args.config)
    if args.patch_oracle:
        source_config["experiment"]["mode"] = "extended"
    config = resolve_offline_config(
        source_config,
        provider=args.llm_provider,
        model_name=args.llm_model,
        base_url=args.llm_base_url,
        views=(
            [v.strip() for v in args.views.split(",") if v.strip()]
            if args.views is not None
            else None
        ),
    )

    if args.pricing_snapshot:
        config["experiment"]["pricing_snapshot"] = str(
            Path(args.pricing_snapshot).resolve()
        )

    load_pricing(config["experiment"].get("pricing_snapshot"))

    # 设置日志
    setup_logger(
        log_file=config["logging"]["log_file"],
        level=config["logging"]["level"],
    )

    logger.info("启动离线索引构建流程")
    logger.info(f"配置文件: {args.config}")
    logger.info(f"数据集: {args.data_path}")

    # 初始化路径
    paths = ProjectPaths()
    output_dir = Path(args.output_dir or args.output or config["data"]["indices_dir"])

    # 加载数据集
    logger.info("加载数据集")
    data_loader = BigVulLoader(args.data_path)
    try:
        dataset = data_loader.load_records()
        exclusions = load_exclusions(args.exclude_cves) if args.exclude_cves else []
        samples, dataset_report = prepare_dataset(
            dataset,
            source=str(Path(args.data_path).resolve()),
            excluded_cve_ids=exclusions,
            max_code_length=config["offline"]["dataset"]["max_code_length"],
        )
    except (ValueError, OSError) as exc:
        report = getattr(exc, "report", None) or {
            "error": str(exc),
            "source_file": args.data_path,
        }
        report_path = output_dir.with_name(output_dir.name + ".dataset_report.json")
        write_json_atomic(report_path, report)
        logger.error(f"输入数据校验失败，详情见 {report_path}: {exc}")
        raise SystemExit(2) from exc
    logger.info(f"输入样本处理统计: {dataset_report['counts']}")

    manifest = create_manifest(
        "offline",
        config,
        project_root=project_root,
        data_paths=[
            args.data_path,
            *([args.exclude_cves] if args.exclude_cves else []),
            *(
                [config["experiment"]["pricing_snapshot"]]
                if config["experiment"].get("pricing_snapshot")
                else []
            ),
        ],
        parameters=index_parameters(
            samples,
            args.batch_size,
            config["offline"]["multiview"]["views"],
            "patch_oracle" if args.patch_oracle else "patch_guided",
            not args.no_view_prefix,
            dataset_report=dataset_report,
        ),
    )
    manifest = bind_manifest(output_dir, manifest)
    write_json_atomic(
        output_dir / "dataset_report.json",
        {**dataset_report, "experiment_id": manifest["experiment_id"]},
    )
    logger.info(f"Experiment: {manifest['experiment_id']}")

    pricing = load_pricing(config["experiment"].get("pricing_snapshot"))
    if pricing is not None:
        write_json_atomic(output_dir / "pricing_snapshot.json", pricing)
    (output_dir / "config_snapshot.yaml").write_text(
        yaml.safe_dump(manifest["config"], allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    snapshot_sources(output_dir, manifest, project_root)
    recorder = Recorder(output_dir, phase="offline", pricing=pricing)
    error = None
    interrupted = False
    build_report = None
    run = dict(
        run_id=recorder.run_id,
        phase="offline",
        started_at=run_stamp,
        status="running",
        error=None,
    )
    run_path = output_dir / "runs" / recorder.run_id / "run.json"
    write_json_atomic(run_path, run)
    try:
        with recorder.activate(), measure(
            "offline_total", started_monotonic=run_started, started_at=run_stamp
        ):
            build_report = build_index(args, config, samples, dataset_report, output_dir, manifest)
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
        interrupted = isinstance(exc, KeyboardInterrupt)
        if interrupted:
            report_path = output_dir / "build_report.json"
            if report_path.exists():
                report = json.loads(report_path.read_text(encoding="utf-8"))
                if report.get("experiment_id") == manifest["experiment_id"] and report.get("status") == "running":
                    write_json_atomic(report_path, {**report, "status": "interrupted"})
        raise
    finally:
        run.update(
            status=("interrupted" if interrupted else "failed" if error else "completed_with_skips"
                    if build_report and build_report["status"] == "complete_with_skips"
                    else "completed"),
            error=error,
            finished_at=utc_now(),
        )
        write_json_atomic(run_path, run)
        write_json_atomic(
            output_dir / "offline_summary.json", evaluate_experiment(output_dir)
        )


def create_index_builder(args, config, *, manifest=None, dataset_report=None):
    # ★★★ 初始化 LLM 接口（这里决定了后续所有 API 调用的配置） ★★★
    logger.info("初始化模型")

    import os

    provider = (args.llm_provider or config["models"]["llm"]["provider"]).lower()
    api_key = config["models"]["llm"].get("api_key") or os.getenv(
        {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "gemini": "GOOGLE_API_KEY",
        }.get(provider, "OPENAI_API_KEY")
    )
    base_url = args.llm_base_url or config["models"]["llm"].get("base_url")
    model_name = args.llm_model or config["models"]["llm"]["model_name"]
    if args.llm_model:
        logger.info(f"使用命令行指定的 LLM 模型: {model_name}")
    if args.llm_base_url:
        logger.info(f"使用命令行指定的 LLM base_url: {base_url}")

    if not api_key and provider in ["openai", "anthropic"]:
        logger.warning("⚠️  未找到 API Key（配置文件或环境变量）")
        logger.warning(
            "   请设置对应提供商的 API Key 环境变量或在离线配置的 models.llm.api_key 中配置"
        )
        logger.warning("   或使用 --llm-provider mock 进行离线自测")

    # 创建 LLM 接口（所有后续的 LLM 调用都通过这个实例）
    with measure("model_loading"):
        llm = LLMInterface(
            provider=provider,
            model_name=model_name,
            api_key=api_key,
            base_url=base_url,
            temperature=config["models"]["llm"]["temperature"],
            max_tokens=config["models"]["llm"]["max_tokens"],
            extra_body=config["models"]["llm"].get("extra_body"),
            temperature_policy=config["models"]["llm"]["temperature_policy"],
            token_limit_parameter=config["models"]["llm"]["token_limit_parameter"],
        )

        # 创建 embedding 模型（用于向量化蒸馏后的视角）
        embedding_model = EmbeddingModel(
            model_name=config["models"]["embeddings"]["model_name"],
            device=config["experiment"]["device"],
            dimension=config["models"]["embeddings"]["dimension"],
            revision=config["models"]["embeddings"].get("revision"),
        )

    # 初始化离线索引组件
    logger.info("初始化离线索引组件")

    # 从已校验的描述与代码对抽取结构化知识，不进行缺失数据回退。
    # 视角选择优先级：命令行 --views > 有效配置的 offline.multiview.views > 默认全部
    selected_views = None
    if args.views:
        selected_views = [x.strip() for x in args.views.split(",") if x.strip()]
    else:
        selected_views = config.get("offline", {}).get("multiview", {}).get("views")

    if selected_views:
        logger.info(f"仅构建视角: {selected_views}")
    else:
        logger.info("构建全部默认视角")

    multiview_gen = MultiViewGenerator(
        llm,
        view_types=selected_views,
        sampling=config["sampling"],
        mode=config["experiment"]["mode"],
        prompt_paths=config["offline"]["multiview"].get("prompts"),
        extraction_prompt_paths=config["offline"]["multiview"].get(
            "extraction_prompts"
        ),
    )

    # 视角蒸馏器（默认路径仅调用无补丁蒸馏）
    distillation = ViewDistillation(
        llm,
        sampling=config["sampling"],
        prompt_path=config["offline"]["distillation"]["prompts"].get("without_patch"),
    )

    # 向量存储（不调用 LLM，只负责 FAISS 索引）
    vector_store = VectorStore(
        dimension=config["models"]["embeddings"]["dimension"],
        index_type=config["offline"]["vector_store"]["index_type"],
        nlist=config["offline"]["vector_store"].get("nlist", 100),
    )

    # 索引构建器（协调整个流程）
    index_builder = IndexBuilder(
        multiview_gen,
        distillation,
        vector_store,
        embedding_model,
        experiment_config=config,
        experiment_manifest=manifest,
        dataset_report=dataset_report,
    )
    return index_builder


def build_index(args, config, samples, dataset_report, output_dir, manifest):
    index_builder = create_index_builder(args, config, manifest=manifest, dataset_report=dataset_report)

    # ★★★ 构建索引 ★★★
    if args.patch_oracle:
        # ---- 消融实验路径：Patch Oracle（无 LLM）----
        # 跳过 MultiViewGenerator 和 ViewDistillation 的所有 LLM 调用，
        # 直接以 ground-truth patch 文本向量化后构建所选视角索引。
        logger.info(
            "[PatchOracle] 消融实验模式：直接以 ground-truth patch 构建所选视角索引，"
            "跳过所有 LLM 调用。"
        )
        add_prefix = not args.no_view_prefix
        logger.info(f"[PatchOracle] 视角前缀: {'启用' if add_prefix else '禁用'}")
        index_builder.build_from_dataset_patch_oracle(
            samples,
            output_dir,
            batch_size=args.batch_size,
            add_view_prefix=add_prefix,
        )

    else:
        if args.patch_guided:
            logger.info(
                "[PatchGuided] 与默认离线索引相同（补丁引导生成 + 无补丁蒸馏）。"
            )
        else:
            logger.info("开始构建索引（每样本每视角约 2 次 LLM 调用：生成 + 蒸馏）...")
        try:
            index_builder.build_from_dataset(
                samples,
                output_dir,
                batch_size=args.batch_size,
            )
        except LLMConnectionError as e:
            logger.error("API 网络连接不可用：{}", e)
            logger.error("已保留缓存并停止后续批次，避免连续跳过。请检查 DNS、代理/TUN 或网络后重跑相同命令。")
            raise SystemExit(2) from e
        except LLMAuthError as e:
            logger.error(f"LLM 认证失败（API Key 无效/过期）: {e}")
            logger.error(
                "修复方法：设置有效的 OPENAI_API_KEY（或切换到 --llm-provider mock）"
            )
            raise SystemExit(2) from e
        except LLMError as e:
            logger.error(f"LLM 生成失败: {e}")
            logger.error("提示：可以稍后重试，或使用 --llm-provider mock 验证管线")
            raise SystemExit(2) from e

    # 打印统计信息
    if index_builder.build_report["status"] == "complete_with_skips":
        logger.warning(
            "本轮构建结束，跳过 {} 个批次；成功批次已保存。详情见 build_report.json，重跑相同命令可补齐。",
            len(index_builder.build_report["skipped_batches"]),
        )
    else:
        logger.info("索引构建完成！")
    stats = index_builder.get_index_statistics()
    for view_type, view_stats in stats.items():
        logger.info(f"{view_type}: {view_stats}")

    logger.info(f"索引已保存到 {output_dir}")

    logger.info("\n" + "=" * 60)
    logger.info("下一步：")
    logger.info("1. 查看生成的索引: ls -lh " + str(output_dir))
    logger.info(
        "2. 运行在线修复: python scripts/run_online.py --vul-files-dir data/processed/Vul4c"
    )
    logger.info("=" * 60)
    return index_builder.build_report


if __name__ == "__main__":
    main()
