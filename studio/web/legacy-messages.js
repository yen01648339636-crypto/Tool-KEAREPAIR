// Display translations for messages saved by earlier Studio releases.
// Apply only to platform messages. Source, reports, patches and exported records
// remain untouched; unknown text is returned verbatim.
const legacyUiMessages = [
  [
    "如果 filename 可由远端用户控制，父目录片段或绝对路径可能使目标超出上传目录。需要输入约束与运行测试支持。",
    "If a remote user controls filename, parent-directory segments or absolute paths may escape the upload directory. Input constraints and runtime tests are needed to confirm this."
  ],
  [
    "用户输入的文件名被直接拼接到上传目录，并交给文件发送函数。探索输入、路径构造与文件读取之间的关系。",
    "A user-provided filename is appended to the upload directory and passed to a file-serving function. Explore the relationship between input, path construction and file access."
  ],
  [
    "演示回放：复用真实历史任务 {bundle['source_task_id']}，不调用模型或容器",
    "Demo replay: using real historical task {bundle['source_task_id']} without model or container calls"
  ],
  [
    "在线模型未配置 API key，请检查 config/online.yaml 或项目 .env",
    "The online model has no API key. Check config/online.yaml or the project .env."
  ],
  [
    "平台仅运行 Docker 验证，请将 execution_mode 配置为 docker",
    "KeaRepair requires Docker validation. Set execution_mode to docker."
  ],
  [
    "示例方案 A：过滤父目录片段。绝对路径仍可能绕过限制；此处为审阅提示，尚无测试结论。",
    "Example A: filter parent-directory segments. Absolute paths may still bypass this restriction. This is a review observation, not a test result."
  ],
  [
    "示例方案 B：解析目标路径，再检查其是否位于上传目录中。运行环境与竞态条件仍需验证。",
    "Example B: resolve the target path, then check that it is within the upload directory. Runtime behavior and race conditions still need validation."
  ],
  [
    "该任务使用的源码与当前已对齐案例不同，请新建修复任务；旧诊断和补丁已保留",
    "This task uses a different source snapshot from the current case. Create a new task; previous diagnosis and patches are retained."
  ],
  [
    "这是人工编写的合成案例；结构事实由框架分析器计算，补丁为教学示例。",
    "This is a manually written synthetic case. Structural facts come from the framework analyzer; patches are educational examples."
  ],
  [
    "函数内结构路径不证明运行时可达性；未执行编译、PoC 或单元测试。",
    "Intraprocedural structural paths do not prove runtime reachability. Build, PoC and unit tests have not run."
  ],
  [
    "验证进程异常退出，返回码 {process.returncode}",
    "Validation worker exited unexpectedly with code {process.returncode}"
  ],
  [
    "阶段进程退出（返回码 {returncode}）：{detail}",
    "Stage worker exited (code {returncode}): {detail}"
  ],
  [
    "路径约束示例未覆盖符号链接竞态，部署时仍需验证实际文件系统行为。",
    "The path-confinement example does not address symlink races. Actual filesystem behavior still needs validation before deployment."
  ],
  [
    "正在验证候选补丁 {job['candidate_id']}",
    "Validating candidate patch {job['candidate_id']}"
  ],
  [
    "候选 {p.parent.name} 的修复与验证记录已保存",
    "Repair and validation records saved for candidate {p.parent.name}"
  ],
  [
    "交互分析限 300 KB 源码；完整修复仍可在任务中运行",
    "Interactive analysis is limited to 300 KB of source. Full repair can still run as a task."
  ],
  [
    "演示回放使用已完成的完整框架记录；其他方案请选择实时运行",
    "Replay requires a completed full-framework record. Use live execution for other variants."
  ],
  [
    "候选补丁 {candidate_id} 已进入验证队列",
    "Candidate patch {candidate_id} queued for validation"
  ],
  [
    "候选 {job['candidate_id']} · ",
    "Candidate {job['candidate_id']} · "
  ],
  [
    "完整流程回放结束；所展示的通过结果来自已保存的真实验证",
    "Workflow replay complete. Passing results come from saved real validation records."
  ],
  [
    "请按诊断报告 → 知识检索 → 修复验证的顺序继续",
    "Continue in order: diagnosis, knowledge retrieval, patch generation, then validation."
  ],
  [
    "历史记录演示回放；本次未调用模型或 Docker。",
    "Historical record replay; no model or Docker calls were made."
  ],
  [
    "服务重启，任务已中断。可创建新运行，已有产物保留。",
    "Service restarted; task interrupted. Start a new run; saved artifacts are retained."
  ],
  [
    "调用现有静态分析器，计算数据流、控制流与调用事实",
    "Ran the static analyzer to extract data-flow, control-flow and call facts"
  ],
  [
    "历史记录缺少完整诊断或检索示例，无法回放完整流程",
    "The historical record lacks complete diagnosis or retrieved examples, so the full workflow cannot be replayed."
  ],
  [
    "回放记录校验失败，请从原始成功任务重新创建回放",
    "Replay record verification failed. Create a new replay from the original successful task."
  ],
  [
    "当前候选没有有效补丁，请选择已生成补丁的候选",
    "This candidate has no valid patch. Select a candidate with a generated patch."
  ],
  [
    "请按诊断、检索、生成补丁、手动验证的顺序回放",
    "Replay in order: diagnosis, retrieval, patch generation, then manual validation."
  ],
  [
    "载入人工编写的 Python 路径穿越案例",
    "Loaded a manually written Python path-traversal case"
  ],
  [
    "补丁回放完成，请审阅差异后点击验证当前补丁",
    "Patch replay complete. Review the diff, then select Validate Patch."
  ],
  [
    "补丁已生成，请审阅差异后点击验证当前补丁",
    "Patch generated. Review the diff, then select Validate Patch."
  ],
  [
    "候选 {candidate_id} · ",
    "Candidate {candidate_id} · "
  ],
  [
    "提供两个人工编写的候选补丁用于界面审阅",
    "Provided two manually written candidate patches for review"
  ],
  [
    "验证尚未执行；所有验证阶段均保持未运行",
    "Validation has not run; all checks remain unexecuted"
  ],
  [
    "服务重启；保留产物，未自动重复调用模型",
    "Service restarted; artifacts retained without automatically repeating model calls"
  ],
  [
    "源码一致性检查通过，继续执行当前阶段",
    "Source consistency verified; continuing the current stage"
  ],
  [
    "知识检索已完成，请审阅样例后生成补丁",
    "Retrieval complete. Review the examples, then generate a patch."
  ],
  [
    "展示 Control flow 召回",
    "Loading control-flow results"
  ],
  [
    "请选择已完成且验证通过的完整框架任务",
    "Select a completed, validated full-framework task"
  ],
  [
    "演示回放已停止，历史原始记录保持不变",
    "Replay stopped; original historical records are unchanged"
  ],
  [
    "知识检索已完成，请审阅样例后开始修复",
    "Retrieval complete. Review the examples, then start repair."
  ],
  [
    "源码准备超时（{duration}）",
    "Source preparation timed out ({duration})"
  ],
  [
    "已启动补丁生成，完成后等待手动验证",
    "Patch generation started; manual validation follows review"
  ],
  [
    "验证产物与当前候选补丁或源码不一致",
    "Validation artifacts do not match the current candidate patch or source"
  ],
  [
    "正在检查容器源码与任务源码的一致性",
    "Checking container source against the task snapshot"
  ],
  [
    "源码检查未通过，已在模型调用前停止",
    "Source verification failed; stopped before calling the model"
  ],
  [
    "诊断报告已生成，请审阅后继续下一步",
    "Diagnosis report ready. Review it before continuing."
  ],
  [
    "诊断未完成，请查看报告中的具体原因",
    "Diagnosis is incomplete. See the report for details."
  ],
  [
    "此案例没有完整且验证通过的历史记录",
    "This case has no complete, validated historical run"
  ],
  [
    "诊断回放完成，请审阅报告后继续检索",
    "Diagnosis replay complete. Review the report, then continue to retrieval."
  ],
  [
    "检索回放完成，请审阅示例后生成补丁",
    "Retrieval replay complete. Review the examples, then generate a patch."
  ],
  [
    "服务重启，验证已中断；已有产物保留",
    "Service restarted; validation interrupted and saved artifacts retained"
  ],
  [
    "修复进程已启动，正在加载配置与模型",
    "Repair worker started; loading configuration and models"
  ],
  [
    "任务正在执行，请等待当前阶段结束",
    "The task is running. Wait for the current stage to finish."
  ],
  [
    "运行完成；尚无通过全部验证的补丁",
    "Run complete; no patch has passed all checks"
  ],
  [
    "请先完成补丁生成回放，再点击验证",
    "Finish patch generation replay before starting validation"
  ],
  [
    "验证超过两小时，已停止执行进程",
    "Validation exceeded two hours. The worker was stopped."
  ],
  [
    "运行超过两小时，已停止执行进程",
    "Execution exceeded two hours. The worker was stopped."
  ],
  [
    "展示 Data flow 召回",
    "Loading data-flow results"
  ],
  [
    "候选源码与平台任务快照不一致",
    "Candidate source does not match the task snapshot"
  ],
  [
    "执行进程已停止，已有产物保留",
    "Worker stopped; saved artifacts retained"
  ],
  [
    "已根据诊断报告启动知识检索",
    "Knowledge retrieval started from the diagnosis report"
  ],
  [
    "知识检索与重排序记录已保存",
    "Retrieval and reranking records saved"
  ],
  [
    "历史记录没有验证通过的补丁",
    "The historical record has no validated patch"
  ],
  [
    "验证报告与阶段凭据不一致",
    "The validation report does not match its stage receipts"
  ],
  [
    "验证结束，部分阶段未通过",
    "Validation finished; some checks did not pass"
  ],
  [
    "历史记录缺少两路检索明细",
    "The historical record lacks details for both retrieval views"
  ],
  [
    "补丁与当前回放记录不一致",
    "The patch does not match the current replay record"
  ],
  [
    "任务已入队，等待执行进程",
    "Task queued; waiting for a worker"
  ],
  [
    "正在加载检索与重排模型",
    "Loading retrieval and reranking models"
  ],
  [
    "运行完成；全部验证通过",
    "Run complete; all checks passed"
  ],
  [
    "当前进程未写入阶段结果",
    "The worker did not write a stage result"
  ],
  [
    "整理工具证据与诊断报告",
    "Preparing tool evidence and the diagnosis report"
  ],
  [
    "原始验证凭据未通过校验",
    "Original validation receipts could not be verified"
  ],
  [
    "请等待当前回放阶段结束",
    "Wait for the current replay stage to finish"
  ],
  [
    "正在启动补丁生成与验证",
    "Starting patch generation and validation"
  ],
  [
    "文件下载中的路径穿越",
    "Path traversal in file downloads"
  ],
  [
    "未找到 Docker",
    "Docker was not found"
  ],
  [
    "双视角知识索引不可用",
    "Dual-view knowledge indexes are unavailable"
  ],
  [
    "查询及检索结果已保存",
    "Queries and retrieval results saved"
  ],
  [
    "历史源码快照校验失败",
    "Historical source snapshot verification failed"
  ],
  [
    "真实历史记录演示回放",
    "Replay of real historical records"
  ],
  [
    "已启动补丁生成与验证",
    "Patch generation and validation started"
  ],
  [
    "请输入要追踪的变量",
    "Enter a variable to trace"
  ],
  [
    "准备并安装验证源码",
    "Preparing and installing validation source"
  ],
  [
    "正在启动诊断智能体",
    "Starting the diagnosis agent"
  ],
  [
    "验证凭据检查失败：",
    "Validation receipt check failed: "
  ],
  [
    "组织诊断与修复示例",
    "Preparing diagnosis and repair examples"
  ],
  [
    "加载代码重排模型",
    "Loading the code reranker"
  ],
  [
    "漏洞回归 PoC",
    "PoC Test"
  ],
  [
    "正在启动补丁生成",
    "Starting patch generation"
  ],
  [
    "正在启动修复进程",
    "Starting the repair worker"
  ],
  [
    "用户请求停止运行",
    "User requested to stop the run"
  ],
  [
    "加载模型与索引",
    "Loading models and indexes"
  ],
  [
    "读取双视角索引",
    "Reading dual-view indexes"
  ],
  [
    "初始化当前阶段",
    "Initializing stage"
  ],
  [
    "生成双视角查询",
    "Generating dual-view queries"
  ],
  [
    "重新诊断已入队",
    "Diagnosis retry queued"
  ],
  [
    "诊断记录已保存",
    "Diagnosis records saved"
  ],
  [
    " · 本地案例",
    " · Local case"
  ],
  [
    "合并候选并重排",
    "Merging and reranking candidates"
  ],
  [
    "生成并验证补丁",
    "Generating and validating patches"
  ],
  [
    "核对容器源码",
    "Checking container source"
  ],
  [
    "加载检索模型",
    "Loading the retrieval model"
  ],
  [
    "加载重排模型",
    "Loading the reranker"
  ],
  [
    "读取知识索引",
    "Reading the knowledge index"
  ],
  [
    "生成诊断报告",
    "Generating the diagnosis report"
  ],
  [
    "检索历史示例",
    "Retrieving historical examples"
  ],
  [
    "重排候选示例",
    "Reranking candidates"
  ],
  [
    "服务正在停止",
    "The service is stopping"
  ],
  [
    "更新运行记录",
    "Updating execution records"
  ],
  [
    "全部验证通过",
    "All checks passed"
  ],
  [
    "读取源码记录",
    "Reading saved source"
  ],
  [
    "准备两路检索",
    "Preparing both retrieval views"
  ],
  [
    "整理代码差异",
    "Preparing the code diff"
  ],
  [
    "源码准备超时",
    "Source preparation timed out"
  ],
  [
    "记录不存在",
    "Record not found"
  ],
  [
    "回放 · ",
    "Replay · "
  ],
  [
    "回放中断：",
    "Replay interrupted: "
  ],
  [
    "PoC测试",
    "PoC Test"
  ],
  [
    "生成补丁",
    "Generating a patch"
  ],
  [
    "应用补丁",
    "Applying the patch"
  ],
  [
    "单元测试",
    "Unit Tests"
  ],
  [
    "分析源码",
    "Analyzing source"
  ],
  [
    "准备源码",
    "Preparing source"
  ],
  [
    "编译检查",
    "Build Check"
  ],
  [
    "源码准备",
    "Source preparation"
  ],
  [
    "执行中",
    "Running"
  ],
  [
    "已完成",
    "Completed"
  ],
  [
    "未完成",
    "Incomplete"
  ],
  [
    "已停止",
    "Stopped"
  ],
  [
    "编译",
    "Building"
  ]
];
const legacyUiExact = new Map(legacyUiMessages);
const escapeUiPattern = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const legacyUiTemplates = legacyUiMessages.filter(([old]) => old.includes('{')).map(([old, english]) => {
 const fields = old.match(/\{[^{}]+\}/g);
 const pieces = old.split(/\{[^{}]+\}/g);
 const pattern = pieces.map(escapeUiPattern).join('(.+?)') + (pieces.at(-1) ? '' : '$');
 return {pattern: new RegExp(pattern, 'g'), fields, english};
});
const legacyUiLiterals = new Map(legacyUiMessages.filter(([old]) => !old.includes('{')));
const legacyUiPattern = new RegExp([...legacyUiLiterals.keys()].map(escapeUiPattern).join('|'), 'g');
function uiMessage(value) {
 let text = String(value ?? '');
 if (/[\u3400-\u9fff]/.test(text)) {
  if (legacyUiExact.has(text)) text = legacyUiExact.get(text);
  else {
   for (const {pattern, fields, english} of legacyUiTemplates) {
    text = text.replace(pattern, (...matches) => english.replace(/\{[^{}]+\}/g, field => matches[fields.indexOf(field) + 1]));
   }
   text = text.replace(legacyUiPattern, match => legacyUiLiterals.get(match));
  }
 }
 // Keep replay provenance in the record; operation labels display just the action.
 return text.replace(/^Replay\s*·\s*/, '');
}
