"""Generate structured root-cause queries using the diagnostic contract."""

import json
import re
from pathlib import Path

from utils.diagnostics import diagnostic_text
from utils.schemas import DiagnosticReport
from utils.telemetry import text_call


class QueryGenerator:
    VIEW_TYPES = ("data_flow", "control_flow")

    def __init__(self, llm_interface, view_types=None, sampling=None):
        self.llm = llm_interface
        self.view_types = list(self.VIEW_TYPES if view_types is None else view_types)
        supported = set(self.VIEW_TYPES)
        if (
            not self.view_types
            or len(set(self.view_types)) != len(self.view_types)
            or set(self.view_types) - supported
        ):
            raise ValueError("Query views must be unique supported perspectives")
        self.sampling = sampling or {}
        directory = Path(__file__).resolve().parents[2] / "prompts/online/retrieval"
        self.prompts = {
            view: (directory / f"query_{view}.txt").read_text(encoding="utf-8")
            for view in self.view_types
        }

    def generate_queries(self, diagnostic_report):
        record = (
            DiagnosticReport.from_dict(diagnostic_report)
            if isinstance(diagnostic_report, dict)
            else diagnostic_report
        )
        if not isinstance(record, DiagnosticReport):
            raise TypeError("Query generation requires a DiagnosticReport")
        return {
            view: self.generate_single_query(record, view) for view in self.view_types
        }

    def generate_single_query(self, report, view_type):
        if view_type not in self.prompts:
            raise ValueError(f"Unconfigured query view: {view_type}")
        context = diagnostic_text(report)
        prompt = self.prompts[view_type].format(context=context)
        options = self.sampling.get(
            "query",
            {"max_tokens": 1024, "temperature": getattr(self.llm, "temperature", 0.0)},
        )
        effective = (
            self.llm.effective_sampling(**options)
            if hasattr(self.llm, "effective_sampling")
            else dict(options)
        )
        sampling_record = {"requested": dict(options), "effective": effective}
        try:
            response = text_call(self.llm, prompt, "query:" + view_type, **options)
            sampling_record["provider_parameters"] = dict(
                getattr(self.llm, "last_call_parameters", {})
            )
            text = response.strip()
            fence = re.fullmatch(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
            if fence:
                text = fence.group(1)

            def unique_fields(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError(f"Duplicate query field: {key}")
                    result[key] = value
                return result

            value = json.loads(text, object_pairs_hook=unique_fields)
            if (
                not isinstance(value, dict)
                or set(value) != {"view", "root_cause"}
                or value["view"] != view_type
                or not isinstance(value["root_cause"], str)
                or not value["root_cause"].strip()
            ):
                raise ValueError(
                    "Expected the requested view and a nonempty root_cause"
                )
            return {
                **value,
                "root_cause": value["root_cause"].strip(),
                "source": "generated",
                "sampling": sampling_record,
            }
        except Exception as exc:
            # A labeled diagnostic hypothesis is usable; arbitrary prose/code is not.
            record = (
                report
                if isinstance(report, DiagnosticReport)
                else DiagnosticReport.from_dict(report)
            )
            fallback = record.root_causes_by_view.get(view_type, "").strip()
            if not fallback:
                raise ValueError(
                    f"Cannot produce {view_type} root-cause query"
                ) from exc
            return {
                "view": view_type,
                "root_cause": fallback,
                "source": "diagnostic_hypothesis",
                "generation_error": str(exc),
                "sampling": sampling_record,
            }
