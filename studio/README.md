# KeaRepair Studio

用于本地漏洞理解、修复执行和结果审阅的 Web 工作台。前端使用本地 HTML、CSS 和 JavaScript，无需构建工具或外部 CDN。

## 启动

先按 [项目说明](../README.md) 创建环境并安装根目录及 Studio 的依赖，然后在项目根目录执行：

```bash
python scripts/run_studio.py
```

打开 <http://127.0.0.1:7860>。服务只监听本机回环地址。

```bash
python scripts/run_studio.py \
  --port 7861 \
  --config config/online.yaml \
  --indices-dir data/indices/knowledge_index \
  --data-dir results/studio
```

任务、上传文件、运行日志与报告默认写入 `results/studio/`，这些运行产物不包含在源码中。

## 工作流程

**Task Center** 展示本工作区产生的任务。新目录的列表为空；内置 walkthrough 是人工编写的路径穿越合成案例，可查看真实静态分析产生的程序事实以及人工示例补丁，不调用模型或运行验证。

**New Repair Task** 使用仓库 URL 匹配本地已准备的源码目标。目标包含漏洞文件、固定版本和测试入口。一个仓库对应多个目标时需要明确选择。案例和知识索引的准备方式见 [数据说明](../data/README.md)。

| 修复范围 | 执行内容 | 测试输入 |
| --- | --- | --- |
| Generate patch | 诊断、检索、重排和补丁生成 | 无 |
| Patch + PoC | 增加补丁应用、编译和 PoC 测试 | 上传 PoC 或使用准备好的入口 |
| Patch + full tests | 增加单元测试，并按预算使用验证反馈迭代 | 上传 PoC 与单元测试脚本，或使用准备好的入口 |

上传入口接受自包含 `.sh` 或 `.py` 测试脚本，每个文件不超过 10 MiB。脚本在准备好的源码目录中运行，退出码 0 表示通过，`KEA_SOURCE_ROOT` 指向源码根目录。支持相应运行器的 Vul4c 目标也可使用原始 PoC 数据。当前不支持单元测试 ZIP 归档。

**Live run** 实际调用修复引擎。**Saved run** 仅在当前工作区存在匹配的成功记录时可用，使用已保存的诊断、检索、补丁和历史验证证据；不执行新的模型调用或测试。新副本没有历史任务，公共仓库映射也不再绑定原工作区的演示任务。显式配置专用回放时，可在案例的 `case_meta.json` 中设置 `demo_source_task_id`。

任务默认自动衔接所请求的阶段，支持暂停、继续、停止和失败重试。诊断页展示原始报告、完整源码和工具事实；检索页展示两路召回与最终重排；补丁页支持统一差异和左右对照。验证页区分源码准备、补丁应用、编译、PoC 与单元测试。

**Repair Report** 汇总输入、执行过程和已有结果，可导出 HTML、JSON 或证据 ZIP。未请求或未执行的检查不会显示为通过。Saved run 的历史验证结果也不代表本次重新验证。

## 知识与模型

平台读取 `config/online.yaml`；离线索引和增量知识构建使用相关离线配置。两份配置都继承 `config/base.yaml`，API 密钥从项目根目录 `.env` 或环境变量读取。

知识索引由 `scripts/run_offline.py` 构建，前端知识浏览使用元数据进行关键词筛选；真实修复使用向量检索与重排。新增知识支持上传源码和补丁，构建成功后发布新的索引代次。没有初始索引时，应先完成离线构建。

## 实现入口

| 文件 | 职责 |
| --- | --- |
| `app.py` | HTTP 接口、同源检查、SSE、静态资源和下载 |
| `engine.py`、`control.py` | CLI 工作进程、阶段推进、暂停与取消 |
| `store.py` | SQLite 任务和顺序事件持久化 |
| `catalog.py`、`repositories.py` | 本地案例、公共仓库映射和知识目录 |
| `replay.py` | 已保存流程的核验与定时回放 |
| `uploads.py` | 测试文件上传与任务输入快照 |
| `knowledge_builds.py` | 增量知识构建与索引发布 |
| `report.py` | 修复报告和导出 |
| `demo.py` | 独立于实验数据的合成演练 |
| `web/` | 前端资源与字体许可证 |

健康检查：`GET /api/health`；工作区概览：`GET /api/overview`；合成演练：`GET /api/walkthrough`。

Python 回归检查使用 `python -m pytest tests/studio -q`，前端逻辑检查使用 `node --test tests/studio/*.cjs`。
