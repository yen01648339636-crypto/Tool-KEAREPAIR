"""Explicit quality gate shared by staged CLI execution and the workbench."""


def diagnosis_issues(report):
    if not report:
        return ["诊断报告尚未生成"]
    issues = []
    reason = report.get("termination_reason", "")
    if "report_error" in reason:
        issues.append("诊断总结生成失败；工具证据已保留，具体原因见分析局限")
    elif "error" in reason:
        issues.append("诊断模型调用失败，具体原因见分析局限")
    elif reason == "analysis_unavailable":
        issues.append("源码分析不可用，具体原因见分析局限")
    elif not reason:
        issues.append("尚未记录诊断结束状态")
    # Retrieval generates its own perspective-specific queries from this report.
    # Old view hypotheses remain readable, but are never mandatory for diagnosis.
    content = [report.get("summary", ""), *report.get("hypotheses", []),
               *report.get("root_causes_by_view", {}).values()]
    if not issues and not report.get("facts") and not any(isinstance(x, str) and x.strip() for x in content):
        issues.append("诊断未产生可供检索使用的结论或程序事实")
    return issues
