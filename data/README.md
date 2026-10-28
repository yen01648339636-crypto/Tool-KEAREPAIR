# 数据准备

本目录只随源码提供说明。原始数据、第三方漏洞源码、PoC、模型权重、生成的向量索引和历史实验结果均未复制。请自行准备有权使用的数据。

## 在线修复案例

平台扫描 `data/processed/PatchEval/` 和 `data/processed/Vul4c/` 下的案例目录。每个案例需要源码与 `test_cmds.json`；仓库 URL 等信息可放在 `case_meta.json` 中：

```text
data/processed/PatchEval/CVE-YYYY-NNNN/
├── src/parser.py
├── test_cmds.json
└── case_meta.json
```

仅生成补丁的案例，`test_cmds.json` 可以从以下结构开始：

```json
{
  "source_file": "src/parser.py",
  "programming_language": "Python"
}
```

`case_meta.json` 示例中的仓库和版本需要替换为对应源码的真实信息：

```json
{
  "repository_url": "https://github.com/example/project",
  "project": "project",
  "revision": "replace-with-the-source-commit",
  "revision_kind": "git"
}
```

`studio/repository_profiles.json` 保留已知公共项目的映射；自备案例可通过 `case_meta.json` 补充信息。没有可信 Git 版本时可以省略 `revision`，平台会使用源码内容快照标识。

若需要 PoC 或单元测试验证，还需准备 `docker_image`、源码准备、编译、PoC 和单元测试命令，并核对容器源码基线。字段与已有命令迁移方式见 [框架文档](../docs/FRAMEWORK.md) 和 `scripts/sync_case_sources.py --help`。`tests/fixtures/container_commands/` 是命令结构的测试夹具，不是可直接运行的完整漏洞数据集。

对于已有完整 PatchEval 元数据的工作区，可将元数据放在 `data/raw/patcheval_dataset.json`；它不是启动平台的必需文件。

## 离线知识库

准备 CSV、JSON 数组或 JSONL。每条记录需要：

- `sample_id`：唯一标识；
- `cve_id`、`language`、`cve_description`：漏洞与语言信息；
- `buggy_code`、`fixed_code`：匹配的漏洞代码与修复代码。

请先配置 `config/offline.yaml` 和相应环境变量，然后在项目根目录执行：

```bash
python scripts/run_offline.py \
  --config config/offline.yaml \
  --data-path data/raw/Offline-dataset.csv \
  --output-dir data/indices/knowledge_index \
  --batch-size 32
```

有效索引包括两个视角的 `.faiss` 文件、`metadata.pkl` 和构建清单。平台默认读取 `data/indices/knowledge_index/`。离线配置中未指定输出目录时使用的默认路径可能不同，以上命令显式指定了平台使用的目录。

首次运行可能下载嵌入模型；在线重排还需要代码编码模型。模型缓存不属于源码目录。
