"""Diagnosis is a unified evidence report; view queries belong to retrieval."""

import json
from types import SimpleNamespace

from Online.phase2_retrieval import QueryGenerator
from tests.diagnostic_fixtures import diagnostic_report
from utils.diagnosis_readiness import diagnosis_issues
from utils.schemas import DiagnosticReport


def test_report_without_view_roots_is_ready_and_generates_both_queries():
    report = diagnostic_report()
    report.pop("root_causes_by_view")
    report["summary"] = "DIAGNOSIS: input reaches file access before validation"
    assert diagnosis_issues(report) == []
    assert DiagnosticReport.from_dict(report).root_causes_by_view == {}
    prompts = []

    def generate(prompt, **kwargs):
        prompts.append(prompt)
        view = "control_flow" if "Generate a reusable control_flow" in prompt else "data_flow"
        return json.dumps({"view": view, "root_cause": "generated query for " + view})

    queries = QueryGenerator(SimpleNamespace(generate=generate)).generate_queries(report)
    assert set(queries) == {"data_flow", "control_flow"}
    assert all("DIAGNOSIS: input reaches file access before validation" in p for p in prompts)
    assert all(q["source"] == "generated" for q in queries.values())


def test_facts_are_usable_without_model_view_hypotheses():
    report = diagnostic_report()
    report.pop("root_causes_by_view")
    assert diagnosis_issues(report) == []


def test_report_failure_is_not_mislabeled_as_missing_perspectives():
    report = diagnostic_report()
    report["termination_reason"] = "model_finished:report_error"
    issues = diagnosis_issues(report)
    assert len(issues) == 1
    assert "总结生成失败" in issues[0]
    assert all("数据流" not in x and "控制流" not in x for x in issues)


def test_empty_report_cannot_advance():
    assert diagnosis_issues({})
    assert diagnosis_issues({"termination_reason": "model_finished", "facts": [], "hypotheses": []})
