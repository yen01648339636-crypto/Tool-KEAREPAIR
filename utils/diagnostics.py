"""Render the current diagnostic contract for retrieval and repair prompts."""

import json

from utils.schemas import DiagnosticReport


def diagnostic_text(report):
    if isinstance(report, DiagnosticReport):
        report = report.to_dict()
    record = DiagnosticReport.from_dict(report)
    parts = []
    if record.summary:
        parts.extend(["[DIAGNOSTIC SUMMARY — UNVERIFIED]", record.summary, ""])
    parts.append("[FACTS]")
    for fact in record.facts:
        location = fact.location
        parts.append(
            f"- [{fact.evidence_id}] {location.file_path}:{location.start_line}-{location.end_line} ({fact.tool}): {fact.statement}"
        )
        if fact.details:
            parts.append("  Structural evidence: " + json.dumps(fact.details, ensure_ascii=False))
    if not record.facts:
        parts.append("No tool-backed facts were established.")
    parts.append("\n[HYPOTHESES — UNVERIFIED]")
    parts.extend(f"- {hypothesis}" for hypothesis in record.hypotheses)
    parts.extend(
        f"- {view} root-cause hypothesis: {cause}"
        for view, cause in record.root_causes_by_view.items()
    )
    parts.append("\n[LIMITATIONS]")
    parts.extend(f"- {limitation}" for limitation in record.limitations)
    parts.append("\n[SEARCH_KEYWORDS]")
    parts.extend(f"- {keyword}" for keyword in record.keywords)
    return "\n".join(parts)


def enhanced_context(code, report, *, skipped=False):
    prefix = "=== ABLATION ===\nno_diagnosis\n\n" if skipped else ""
    return (
        prefix
        + "=== BUGGY CODE ===\n"
        + code
        + "\n\n=== DIAGNOSTIC REPORT ===\n"
        + diagnostic_text(report)
    )
