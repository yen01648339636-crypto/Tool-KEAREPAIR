"""Boundary records reject fabricated facts and incomplete success states."""

import json
import unittest

from utils.schemas import (
    ContractError,
    DiagnosticReport,
    KnowledgeRecord,
    RepairResult,
    ValidationResult,
)


class TestSchemas(unittest.TestCase):
    def test_api_root_cause_view_is_rejected(self):
        from tests.diagnostic_fixtures import diagnostic_report

        report = diagnostic_report()
        report["root_causes_by_view"] = {"api_semantic": "API misuse"}
        with self.assertRaises(ContractError):
            DiagnosticReport.from_dict(report)

    def test_knowledge_round_trip_and_nested_validation(self):
        knowledge = dict(
            root_cause="unchecked size",
            risky_calls=["memcpy"],
            fixing_strategy="check bounds",
            taint_flow="input -> length -> copy",
        )
        record = KnowledgeRecord.from_dict(
            dict(
                sample_id="one",
                cve_id="CVE-1",
                project="example",
                language="c",
                source_provenance={"commit": "abc"},
                cve_description="overflow",
                buggy_code="copy();",
                fixed_code="check(); copy();",
                patch="",
                view_type="data_flow",
                extracted_knowledge=knowledge,
                abstracted_knowledge=knowledge,
                extraction_model="model",
                prompt_hash="digest",
            )
        )
        self.assertEqual(
            KnowledgeRecord.from_dict(json.loads(json.dumps(record.to_dict()))), record
        )
        record.abstracted_knowledge.taint_flow = None
        with self.assertRaises(ContractError):
            record.to_dict()

    def test_unknown_fields_versions_and_wrong_types_fail(self):
        for data in (
            {"candidate_id": "1", "raw_patch_hash": "h", "extra": True},
            {"candidate_id": "1", "raw_patch_hash": "h", "schema_version": "99"},
            {"candidate_id": "1", "raw_patch_hash": "h", "poc_status": True},
        ):
            with self.subTest(data=data), self.assertRaises(ContractError):
                ValidationResult.from_dict(data)

    def test_missing_stages_never_count_as_success(self):
        result = ValidationResult(candidate_id="1", raw_patch_hash="h")
        self.assertFalse(result.success)
        self.assertFalse(result.poc_pass)
        with self.assertRaises(ContractError):
            ValidationResult.from_dict(
                {"candidate_id": "1", "raw_patch_hash": "h", "poc_pass": True}
            )
        result.patch_apply_status = result.compile_status = result.poc_status = "passed"
        self.assertFalse(result.to_dict()["success"])
        result.unit_status = "passed"
        with self.assertRaises(ContractError):
            result.to_dict()
        result.effective_patch_hash = "effective"
        serialized = json.loads(json.dumps(result.to_dict()))
        self.assertTrue(ValidationResult.from_dict(serialized).success)
        serialized["success"] = False
        with self.assertRaises(ContractError):
            ValidationResult.from_dict(serialized)

    def test_llm_only_report_cannot_claim_verified_facts(self):
        fact = dict(
            statement="input reaches copy",
            location=dict(file_path="a.c", start_line=1, end_line=2),
            tool="trace_data_flow",
            evidence_id="call-1",
        )
        data = dict(
            mode="llm_only",
            facts=[fact],
            hypotheses=[],
            root_causes_by_view={},
            tool_calls=[],
            termination_reason="complete",
        )
        with self.assertRaises(ContractError):
            DiagnosticReport.from_dict(data)
        data["mode"] = "tool_grounded"
        data["tool_calls"] = [
            {
                "tool": "trace_data_flow",
                "status": "completed",
                "observation": {"facts": [fact]},
            }
        ]
        report = DiagnosticReport.from_dict(data)
        self.assertEqual(report.facts[0].location.start_line, 1)
        data["facts"][0]["location"]["end_line"] = 0
        with self.assertRaises(ContractError):
            DiagnosticReport.from_dict(data)

    def test_repair_requires_patch_and_nonnegative_integer_counters(self):
        data = dict(
            success=False,
            final_patch=None,
            iterations=0,
            history=[],
            generation_count=0,
            validation_count=0,
            llm_call_count=0,
            termination_reason="not_started",
            experiment_id="experiment",
        )
        self.assertEqual(RepairResult.from_dict(data).iterations, 0)
        for update in (
            dict(success=True),
            dict(iterations=-1),
            dict(generation_count=True),
        ):
            with self.subTest(update=update), self.assertRaises(ContractError):
                RepairResult.from_dict({**data, **update})


if __name__ == "__main__":
    unittest.main()
