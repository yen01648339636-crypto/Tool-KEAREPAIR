# KeaRepair

KeaRepair 是一个本地漏洞修复工作台。平台将源码诊断、双视角知识检索、补丁生成和验证记录连接起来，支持通过浏览器审阅完整修复过程。

本目录是独立的源码副本，包含前端、后端和运行所需的修复框架。不包含本机虚拟环境、模型权重、实验数据、知识索引或历史任务。

## 快速启动

建议使用 Linux 和 Python 3.10 或更新版本。在本目录执行：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r studio/requirements.txt
python scripts/run_studio.py
```

打开 <http://127.0.0.1:7860>。停止服务使用 `Ctrl+C`。更换端口：

```bash
python scripts/run_studio.py --port 7861
```

初次启动没有任务、案例或知识库属于正常状态。内置合成案例可用于查看源码、静态分析事实和示例补丁，无需 API 密钥或 Docker。该演练不调用模型，也不表示补丁已经通过测试。

## 配置真实修复

1. 复制环境变量模板：`cp .env.example .env`，填入所用服务的 API 密钥。
2. 修改 `config/online.yaml` 的 `models.llm`，设置服务协议、实际模型名称和可选的网关地址。离线知识构建单独使用 `config/offline.yaml`。
3. 按 [数据准备说明](data/README.md) 放置可信的源码案例，并构建知识索引。
4. 在 **New Repair Task** 中输入已准备案例的仓库地址，选择修复范围并提交。

默认配置中的 `your-model-id` 是占位符，必须替换后才能运行真实模型任务。密钥通过 `.env` 或环境变量读取，配置文件中保留 `api_key: null`。`.env` 不应提交到版本库。

平台按照仓库 URL 匹配已经准备好的源码案例，不会仅凭任意 Git URL 自动克隆并修复项目。默认数据目录是 `data/processed/`，默认平台知识索引是 `data/indices/knowledge_index/`。模型权重会在需要时下载；也可以配置已有的本地权重。

仅生成补丁时不需要 Docker。PoC 或完整测试验证需要 Docker、目标镜像和与源码版本匹配的测试入口。Saved run 功能需要在当前工作区产生并保存的匹配记录；本源码副本没有附带历史任务。

## 目录

| 路径 | 内容 |
| --- | --- |
| `studio/` | FastAPI 后端、任务管理、报告导出、回放和 Web 静态资源 |
| `studio/web/` | HTML、CSS、JavaScript、品牌资源与本地字体；无需 Node.js 构建 |
| `Online/` | 诊断、双视角检索与重排、补丁生成及验证 |
| `Offline/` | 知识抽取、蒸馏、向量存储与索引构建 |
| `static_analysis/` | Tree-sitter 解析、数据流与控制流分析 |
| `models/` | 模型接口、嵌入与代码编码 |
| `utils/`、`data_loader/` | 公共数据契约、执行控制、补丁处理与数据加载 |
| `prompts/`、`config/` | 提示词与无密钥的通用配置 |
| `scripts/` | 平台启动、在线修复、离线索引、验证与数据维护入口 |
| `tests/` | Python 和 JavaScript 回归测试及小型测试夹具 |
| `data/README.md` | 外部数据和知识库的准备约定 |

平台用法见 [Studio 文档](studio/README.md)，框架和命令行细节见 [框架文档](docs/FRAMEWORK.md)，此次清理范围见 [导出说明](EXPORT_NOTES.md)。

## 测试

安装上述依赖后，在项目根目录执行：

```bash
python -m pytest tests -q
```

JavaScript 界面逻辑测试另需支持 `node:test` 的 Node.js：

```bash
node --test tests/studio/*.cjs
```

大部分测试使用本地合成数据和模拟模型。依赖外部准备数据的检查会在数据缺失时跳过。测试不代表真实模型服务、外部镜像或完整实验已经通过验证。

## 许可证

主项目许可证尚未指定，正式发布前需由维护者补充 `LICENSE`。本地字体附带各自的许可证，见 [第三方资源说明](THIRD_PARTY_NOTICES.md)。
