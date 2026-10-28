# 离线知识模板

默认流程根据漏洞描述和已核对的漏洞/修复函数对抽取 `data_flow`、`control_flow` 两套知识，再泛化具体标识符。API 名称及行为保留在两个视角各自的 `risky_calls` 字段中，不单独构建 API 视角索引。

| 模板 | 输入占位符 | 输出 |
| --- | --- | --- |
| `patch_guided/data_flow.txt` | `cve_description`、`buggy_code`、`fixed_code`、`patch` | `root_cause`、`risky_calls`、`taint_flow`、`fixing_strategy` |
| `patch_guided/control_flow.txt` | 同上 | `root_cause`、`risky_calls`、`control_branch`、`fixing_strategy` |
| `distill/without_patch.txt` | `view_type`、`knowledge_json` | 保留输入的全部知识字段，泛化项目标识符，保留标准 API 和行为信息 |

抽取模板按“理解代码修改 → 分析漏洞行为 → 总结根因及修复策略”组织。抽象阶段不再输入源码或补丁，不把知识压缩成单段自由文本。两阶段输出均须通过 JSON 与知识契约校验，失败直接报告，不回退为原文或盲视分析。

JSON 示例中的字面花括号必须写为 `{{`、`}}`，占位符使用单花括号。加载模板时会进行格式化校验。模板可直接编辑，也可通过以下配置覆盖；相对路径从仓库根目录解析：

```yaml
offline:
  multiview:
    extraction_prompts:
      data_flow: prompts/offline/patch_guided/data_flow.txt
      control_flow: prompts/offline/patch_guided/control_flow.txt
  distillation:
    prompts:
      without_patch: prompts/offline/distill/without_patch.txt
```

向量仅编码 `abstracted_knowledge.root_cause`。完整抽取知识、抽象知识、代码对、补丁和来源写入索引元数据。修改模板后应使用新的索引输出目录；完整构建命令见仓库根目录 README 的 “Build the Offline Index”。
