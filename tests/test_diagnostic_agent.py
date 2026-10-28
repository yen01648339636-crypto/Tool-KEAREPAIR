"""Execute the real LangGraph ReAct graph with native local chat-model messages."""

import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import InMemorySaver

from config.runtime import load_config
from models.chat import create_diagnostic_models
from Online.phase1_diagnosis import DiagnosticAgent
from Online.phase2_retrieval.query_generator import QueryGenerator
from Online.phase2_retrieval.reranker import Reranker
from Online.phase3_repair import RepairAgent
from tests.diagnostic_fixtures import ScriptedChatModel, call
from utils.schemas import DiagnosticReport
from utils.diagnostics import diagnostic_text


CODE = "void f(int x) {\n int y=x;\n if(x) return;\n sink(y);\n}"
SUMMARY = {
    "hypotheses": ["The call may need input validation."],
    "root_causes_by_view": {},
    "keywords": ["input validation"],
    "evidence_ids": [],
}


class TestDiagnosticAgent(unittest.TestCase):
    def test_native_access_path_and_prior_guard_evidence_reach_the_report(self):
        code = 'void f(int secret) {\n if(secret<=0) return;\n struct T s;\n s.a=secret;\n sink(s.a);\n}'
        model = ScriptedChatModel(responses=[
            call('trace_data_flow', {'variable': 's.a', 'statement': {'line': 5}}, 'field'),
            call('is_path_reachable', {'source': {'line': 4}, 'target': {'line': 5}, 'variable': 'secret'}, 'guard'),
            AIMessage(content='Done'),
        ], report_payload=SUMMARY)
        result = DiagnosticAgent(model).diagnose(code, file_path='source.c')['diagnostic_report']
        self.assertTrue(all(entry['status'] == 'completed' for entry in result['tool_calls']))
        payload = json.loads(model.requests[-1][-1].content)
        observations = [fact['details']['result'] for fact in payload['facts'] if fact['details']]
        flow = next(observation for observation in observations if 'definitions' in observation)
        path = next(observation for observation in observations if 'paths' in observation)
        self.assertTrue(any(item['variable'] == 's.a' and item['kind'] == 'memory_write' for item in flow['definitions']))
        self.assertEqual(path['paths'][0]['dominating_conditions'][0]['location']['start_line'], 2)
        self.assertIn('"dominating_conditions"', diagnostic_text(result))

    def test_report_and_downstream_context_preserve_predicate_outcomes(self):
        code = "void f(int x) {\n if (x <= 0) return;\n sink(x);\n}"
        model = ScriptedChatModel(
            responses=[
                call("is_path_reachable", {
                    "source": {"line": 2, "column": 5}, "target": {"line": 3}, "variable": "x",
                }),
                AIMessage(content="Interpretation: the sink is only on the positive-input branch."),
            ], report_payload=SUMMARY,
        )
        result = DiagnosticAgent(model).diagnose(code, file_path="source.c")
        payload = json.loads(model.requests[-1][-1].content)
        observation = result["diagnostic_report"]["tool_calls"][0]["observation"]
        details = payload["facts"][0]["details"]
        self.assertEqual(details["result"], observation["result"])
        self.assertEqual(details["source_hash"], observation["source_hash"])
        self.assertEqual(details["result"]["paths"][0]["predicates"][0]["expression"], "(x <= 0)")
        self.assertFalse(details["result"]["paths"][0]["predicates"][0]["outcome"])
        self.assertTrue(payload["analysis_notes"])
        self.assertIn("x <= 0", payload["source"])
        self.assertIn('"outcome": false', diagnostic_text(result["diagnostic_report"]))
        self.assertIn('"outcome": false', result["enhanced_context"])
        self.assertNotIn("Interpretation:", json.dumps(payload["facts"]))
        prompts = []
        def generate(prompt, **kwargs):
            prompts.append(prompt)
            return '{"view":"control_flow","root_cause":"guarded input"}'
        QueryGenerator(SimpleNamespace(generate=generate), ["control_flow"]).generate_queries(result["diagnostic_report"])
        self.assertIn('"outcome": false', prompts[0])
        reranker = Reranker(SimpleNamespace(protocol={}))
        reranker.rerank(result["diagnostic_report"], code, [])
        self.assertIn('"outcome": false', reranker.last_run["behavioral_query"])
        patch_prompt = RepairAgent(None, None)._build_initial_prompt(
            code, [], result["diagnostic_report"], {"repo_relpath": "source.c"}
        )
        self.assertIn('"outcome": false', patch_prompt)

    def test_large_old_api_observation_survives_message_compaction_and_report(self):
        implementation = "int helper(int x) {/*" + " detail " * 1500 + "*/ return x + 123;}"
        code = implementation + "\nvoid f(int x) {\n int y=helper(x);\n sink(y);\n}"
        model = ScriptedChatModel(
            responses=[
                call("inspect_api_usage", {"call": {"line": 3}}, "api"),
                call("trace_data_flow", {"variable": "y", "statement": {"line": 4}}, "flow"),
                AIMessage(content="Done"),
            ], report_payload=SUMMARY,
        )
        result = DiagnosticAgent(model, history_turns=1).diagnose(code, file_path="source.c")
        payload = json.loads(model.requests[-1][-1].content)
        api = next(fact["details"]["result"] for fact in payload["facts"] if fact["tool"] == "inspect_api_usage" and fact["details"])
        self.assertEqual(api["arguments"], ["x"])
        self.assertEqual(api["return_value"]["binding"], "y")
        self.assertEqual(api["local_definitions"][0]["implementation"], implementation)
        self.assertIn("return x + 123", diagnostic_text(result["diagnostic_report"]))
        # The accumulated evidence also remains available to the next ReAct turn.
        self.assertIn("return x + 123", model.requests[-2][0].content)

    def test_dataflow_edges_and_unresolved_inputs_reach_the_report(self):
        code = "void f(int x) {\n int y=x+external;\n sink(y);\n}"
        model = ScriptedChatModel(
            responses=[call("trace_data_flow", {"variable": "y", "statement": {"line": 3}}), AIMessage(content="Done")],
            report_payload=SUMMARY,
        )
        result = DiagnosticAgent(model).diagnose(code, file_path="source.c")
        payload = json.loads(model.requests[-1][-1].content)
        flow = payload["facts"][0]["details"]["result"]
        self.assertTrue(flow["propagation"])
        self.assertTrue(any("external" in entry for entry in flow["unresolved"]))
        self.assertIn('"propagation"', diagnostic_text(result["diagnostic_report"]))
        self.assertIn('"unresolved"', diagnostic_text(result["diagnostic_report"]))

    def test_native_react_tools_evidence_and_structured_report(self):
        model = ScriptedChatModel(
            responses=[
                call("trace_data_flow", {"variable": "y", "statement": {"line": 4}}),
                call(
                    "is_path_reachable",
                    {"source": {"line": 3, "column": 5}, "target": {"line": 4}},
                    "tool-2",
                ),
                call("inspect_api_usage", {"call": {"line": 4}}, "tool-3"),
                AIMessage(content="Done"),
            ],
            report_payload=SUMMARY,
        )
        agent = DiagnosticAgent(model)
        result = agent.diagnose(CODE, file_path="source.c")
        report = DiagnosticReport.from_dict(result["diagnostic_report"])
        self.assertEqual(report.reasoning_call_count, 4)
        self.assertEqual(report.report_call_count, 1)
        self.assertEqual(report.tool_call_count, 3)
        self.assertEqual(
            {entry["tool"] for entry in report.tool_calls},
            {"trace_data_flow", "is_path_reachable", "inspect_api_usage"},
        )
        self.assertTrue(report.facts)
        self.assertTrue(
            all(fact.location.file_path == "source.c" for fact in report.facts)
        )
        self.assertIn("tools", agent.graph.get_graph().nodes)
        self.assertIn("HYPOTHESES", result["enhanced_context"])

    def test_round_exhaustion_still_calls_the_report_node(self):
        model = ScriptedChatModel(
            responses=[call("inspect_api_usage", {"call": {"line": 4}})],
            report_payload=SUMMARY,
        )
        report = DiagnosticAgent(model, max_rounds=1).diagnose(
            CODE, file_path="source.c"
        )["diagnostic_report"]
        self.assertEqual(report["termination_reason"], "round_budget_exhausted")
        self.assertEqual(report["reasoning_call_count"], 1)
        self.assertEqual(report["report_call_count"], 1)
        self.assertIsNone(report["usage"]["reported_total_tokens"])
        self.assertTrue(
            all(item["simulation"] for item in report["usage"]["model_calls"])
        )

    def test_tool_budget_rejects_an_oversized_batch_before_execution(self):
        response = AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "inspect_api_usage",
                    "args": {"call": {"line": 4}},
                    "id": str(index),
                }
                for index in range(2)
            ],
        )
        model = ScriptedChatModel(responses=[response], report_payload=SUMMARY)
        report = DiagnosticAgent(model, max_tool_calls=1).diagnose(
            CODE, file_path="source.c"
        )["diagnostic_report"]
        self.assertEqual(report["termination_reason"], "tool_budget_exhausted")
        self.assertEqual(report["tool_call_count"], 0)
        self.assertEqual(report["facts"], [])

    def test_tool_errors_never_become_facts(self):
        for name, arguments in (
            ("inspect_api_usage", {"call": {"line": "4"}}),
            ("unknown_tool", {}),
            ("trace_data_flow", {"variable": "y", "statement": {"line": 99}}),
        ):
            with self.subTest(name=name):
                model = ScriptedChatModel(
                    responses=[call(name, arguments), AIMessage(content="Done")],
                    report_payload=SUMMARY,
                )
                report = DiagnosticAgent(model).diagnose(CODE, file_path="source.c")[
                    "diagnostic_report"
                ]
                self.assertEqual(report["facts"], [])
                self.assertEqual(report["tool_calls"][0]["status"], "error")

    def test_message_compaction_preserves_accumulated_evidence(self):
        model = ScriptedChatModel(
            responses=[
                call(
                    "trace_data_flow",
                    {"variable": "y", "statement": {"line": 4}},
                    "first",
                ),
                *[
                    call("inspect_api_usage", {"call": {"line": 4}}, str(index))
                    for index in range(4)
                ],
                AIMessage(content="Done"),
            ],
            report_payload=SUMMARY,
        )
        report = DiagnosticAgent(model, history_turns=1).diagnose(
            CODE, file_path="source.c"
        )["diagnostic_report"]
        first_id = report["tool_calls"][0]["observation"]["facts"][0]["evidence_id"]
        self.assertIn(first_id, model.requests[-2][0].content)
        final_input = json.loads(model.requests[-1][-1].content)
        self.assertIn(first_id, [fact["evidence_id"] for fact in final_input["facts"]])

    def test_fabricated_report_evidence_is_rejected(self):
        model = ScriptedChatModel(
            responses=[
                call("inspect_api_usage", {"call": {"line": 4}}),
                AIMessage(content="Done"),
            ],
            report_payload={**SUMMARY, "evidence_ids": ["invented"]},
        )
        report = DiagnosticAgent(model).diagnose(CODE, file_path="source.c")[
            "diagnostic_report"
        ]
        self.assertTrue(report["facts"])
        self.assertEqual(report["hypotheses"], [])
        self.assertTrue(
            any(
                "nonexistent evidence" in limitation
                for limitation in report["limitations"]
            )
        )

    def test_report_failure_returns_accumulated_facts_without_prose_fallback(self):
        model = ScriptedChatModel(
            responses=[call("inspect_api_usage", {"call": {"line": 4}})],
            report_error=True,
        )
        report = DiagnosticAgent(model, max_rounds=1).diagnose(
            CODE, file_path="source.c"
        )["diagnostic_report"]
        self.assertTrue(report["facts"])
        self.assertEqual(report["report_call_count"], 1)
        self.assertEqual(report["facts"][0]["details"]["result"], report["tool_calls"][0]["observation"]["result"])
        self.assertIn('"arguments"', diagnostic_text(report))
        self.assertFalse(report["usage"]["tokens_complete"])
        self.assertNotIn("cost_usd", report["usage"])

    def test_model_error_and_unknown_language_are_explicit(self):
        model = ScriptedChatModel(
            responses=[RuntimeError("local model failure")], report_payload=SUMMARY
        )
        report = DiagnosticAgent(model).diagnose(CODE, file_path="source.c")[
            "diagnostic_report"
        ]
        self.assertEqual(report["termination_reason"], "model_error")
        other = DiagnosticAgent(ScriptedChatModel()).diagnose(
            CODE, file_path="source.rs"
        )["diagnostic_report"]
        self.assertEqual(other["termination_reason"], "analysis_unavailable")
        self.assertEqual(other["facts"], [])

    def test_checkpoint_identity_and_completed_run_reuse(self):
        model = ScriptedChatModel(
            responses=[
                call("inspect_api_usage", {"call": {"line": 4}}),
                AIMessage(content="Done"),
            ],
            report_payload=SUMMARY,
        )
        agent = DiagnosticAgent(model, checkpointer=InMemorySaver())
        first = agent.diagnose(CODE, file_path="source.c", run_id="case-1")
        count = len(model.requests)
        self.assertEqual(
            agent.diagnose(CODE, file_path="source.c", run_id="case-1"), first
        )
        self.assertEqual(len(model.requests), count)
        with self.assertRaises(ValueError):
            agent.diagnose(
                CODE.replace("sink", "other"), file_path="source.c", run_id="case-1"
            )
        agent.prompt += "\nChanged instructions."
        with self.assertRaises(ValueError):
            agent.diagnose(CODE, file_path="source.c", run_id="case-1")

    def test_legacy_text_actions_are_not_executed(self):
        model = ScriptedChatModel(
            responses=[AIMessage(content="Action: inspect_api_usage 4")],
            report_payload=SUMMARY,
        )
        report = DiagnosticAgent(model).diagnose(CODE, file_path="source.c")[
            "diagnostic_report"
        ]
        self.assertEqual(report["tool_call_count"], 0)
        self.assertEqual(report["facts"], [])

    def test_langchain_model_factory_uses_separate_stage_limits(self):
        config = load_config("config/online.yaml")
        calls = []
        with patch(
            "models.chat.init_chat_model",
            side_effect=lambda model, **kwargs: calls.append((model, kwargs))
            or ScriptedChatModel(),
        ):
            create_diagnostic_models(config["models"]["llm"], config["sampling"])
        self.assertEqual([item[1]["max_tokens"] for item in calls], [16384, 4096])
        self.assertTrue(all(item[1]["max_retries"] == 0 for item in calls))

    def test_focus_window_keeps_full_source_analysis_and_original_locations(self):
        code = "int helper(int x) {return x;}\n" + CODE
        model = ScriptedChatModel(
            responses=[
                call("inspect_api_usage", {"call": {"line": 5}}),
                AIMessage(content="Done"),
            ],
            report_payload=SUMMARY,
        )
        result = DiagnosticAgent(model).diagnose(
            code,
            file_path="source.c",
            focus_window={"window_offset": 4, "window_line_count": 1},
        )
        self.assertIn("5:  sink(y);", model.requests[0][-1].content)
        observation = result["diagnostic_report"]["tool_calls"][0]["observation"]
        self.assertEqual(observation["result"]["enclosing_function"], "f")
        self.assertEqual(observation["facts"][0]["location"]["start_line"], 5)

    def test_native_provider_models_construct_tool_and_report_runnables_without_requests(
        self,
    ):
        from Online.phase1_diagnosis.diagnostic_agent import DiagnosisSummary
        from Online.phase1_diagnosis.tools import create_diagnostic_tools
        from static_analysis.session import AnalysisSession

        config = load_config("config/online.yaml")
        tools = create_diagnostic_tools(
            AnalysisSession(CODE, language="c", file_path="source.c")
        )
        for provider, name in (
            ("openai", "gpt-5-mini-2025-08-07"),
            ("anthropic", "claude-sonnet-4-5"),
            ("gemini", config["models"]["llm"]["model_name"]),
        ):
            with self.subTest(provider=provider):
                model, report = create_diagnostic_models(
                    {
                        "provider": provider,
                        "model_name": name,
                        "api_key": "local-placeholder",
                    },
                    config["sampling"],
                )
                self.assertIsNotNone(model.bind_tools(tools))
                self.assertIsNotNone(
                    report.with_structured_output(DiagnosisSummary, include_raw=True)
                )


if __name__ == "__main__":
    unittest.main()
