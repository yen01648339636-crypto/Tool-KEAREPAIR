"""Tool-free LLM root-cause reports using the shared diagnostic contract."""

import json
from pathlib import Path
import re

from utils.diagnostics import enhanced_context
from utils.schemas import DiagnosticReport
from utils.telemetry import text_call
from utils.source_context import numbered_source, select_source_context


class RootCauseReporter:
    def __init__(self, llm, sampling, views=("data_flow", "control_flow")):
        self.llm, self.sampling, self.views = llm, sampling, list(views)
        path = (
            Path(__file__).resolve().parents[2]
            / "prompts/online/diagnosis/root_cause_report.txt"
        )
        self.prompt = path.read_text(encoding="utf-8")

    def diagnose(self, full_code, *, file_path, language=None, focus_window=None):
        context = focus_window or select_source_context(full_code)[1]
        prompt = self.prompt.format(
            file_path=file_path,
            language=language or "unspecified",
            views=", ".join(self.views),
            source=numbered_source(full_code, context),
        )
        options = self.sampling["diagnosis_report"]
        response = text_call(self.llm, prompt, "diagnosis_report", **options)
        text = response.strip()
        fence = re.fullmatch(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
        if fence:
            text = fence[1]

        def unique_fields(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"Duplicate report field: {key}")
                result[key] = value
            return result

        value = json.loads(text, object_pairs_hook=unique_fields)
        if not isinstance(value, dict) or set(value) != {
            "root_causes_by_view",
            "hypotheses",
            "keywords",
            "limitations",
        }:
            raise ValueError("Expected a structured tool-free root-cause report")
        roots = value["root_causes_by_view"]
        if (
            not isinstance(roots, dict)
            or set(roots) != set(self.views)
            or any(
                not isinstance(root, str) or not root.strip() for root in roots.values()
            )
        ):
            raise ValueError(
                "Tool-free diagnosis must supply a nonempty root cause for every selected view"
            )
        report = DiagnosticReport(
            mode="llm_only",
            facts=[],
            tool_calls=[],
            termination_reason="report_completed",
            report_call_count=1,
            **value,
        ).to_dict()
        effective = (
            self.llm.effective_sampling(**options)
            if hasattr(self.llm, "effective_sampling")
            else dict(options)
        )
        report["limitations"].append(
            "No diagnostic tools were executed; all root causes are unverified hypotheses."
        )
        report["usage"] = {
            "requested_sampling": dict(options),
            "effective_sampling": effective,
            "provider_parameters": dict(getattr(self.llm, "last_call_parameters", {})),
        }
        return dict(
            diagnostic_report=report,
            enhanced_context=enhanced_context(full_code, report),
        )
