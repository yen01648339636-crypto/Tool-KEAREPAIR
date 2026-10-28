"""Real grammar, CFG, lexical scope, and source-evidence regression cases."""

import unittest

import networkx as nx

from Online.phase1_diagnosis.tools import SourcePosition, create_diagnostic_tools
from static_analysis.session import AnalysisSession
from static_analysis.treesitter_wrapper import AnalysisError, infer_language


def position(line, column=None):
    return SourcePosition(line=line, column=column)


class TestStaticAnalysis(unittest.TestCase):
    def session(self, code, language="c"):
        return AnalysisSession(
            code,
            language=language,
            file_path="sample."
            + {"c": "c", "cpp": "cpp", "python": "py", "javascript": "js", "go": "go"}[
                language
            ],
        )

    def test_reassignment_kills_the_earlier_definition(self):
        session = self.session("void f(int x) {\n int y=x;\n y=0;\n sink(y);\n}")
        result = session.trace_data_flow("y", position(4))["result"]
        self.assertEqual(
            [item["location"]["start_line"] for item in result["definitions"]], [3]
        )

    def test_branch_merge_keeps_both_reaching_definitions(self):
        session = self.session(
            "void f(int x) {\n int y=x;\n if(x) {\n  y=0;\n } else {\n  y=1;\n }\n sink(y);\n}"
        )
        result = session.trace_data_flow("y", position(8))["result"]
        self.assertEqual(
            {item["location"]["start_line"] for item in result["definitions"]}, {4, 6}
        )

    def test_conditional_return_preserves_the_false_path(self):
        session = self.session("void f(int x) {\n if(x) return;\n sink(x);\n}")
        result = session.is_path_reachable(position(2, 5), position(3), "x")["result"]
        self.assertEqual(result["status"], "path_found")
        self.assertEqual(result["feasibility"], "unknown")
        self.assertFalse(result["paths"][0]["predicates"][0]["outcome"])
        self.assertEqual(len(result["paths"][0]["checks"]), 1)

    def test_unconditional_return_does_not_reach_the_sink(self):
        session = self.session("void f(int x) {\n return;\n sink(x);\n}")
        result = session.is_path_reachable(position(2), position(3))["result"]
        self.assertEqual(result["status"], "no_cfg_path")

    def test_nested_scopes_do_not_overwrite_outer_bindings(self):
        for language, code in (
            (
                "c",
                "void f(int x) {\n int y=x;\n {\n int y=0;\n sink(y);\n }\n sink(y);\n}",
            ),
            (
                "javascript",
                "function f(x) {\n let y=x;\n {\n let y=0;\n sink(y);\n }\n sink(y);\n}",
            ),
            (
                "go",
                "package main\nfunc f(x int) {\n y:=x\n {\n y:=0\n sink(y)\n }\n sink(y)\n}",
            ),
        ):
            with self.subTest(language=language):
                session = self.session(code, language)
                offset = 1 if language == "go" else 0
                inner = session.trace_data_flow("y", position(5 + offset))["result"][
                    "definitions"
                ]
                outer = session.trace_data_flow("y", position(7 + offset))["result"][
                    "definitions"
                ]
                self.assertEqual(
                    [item["location"]["start_line"] for item in inner], [4 + offset]
                )
                self.assertIn(
                    2 + offset, [item["location"]["start_line"] for item in outer]
                )
                self.assertNotIn(
                    4 + offset, [item["location"]["start_line"] for item in outer]
                )

    def test_loops_have_back_edges_and_break_continue_targets(self):
        session = self.session(
            "void f(int x) {\n int y=0;\n for(int i=0; i<x; i++) {\n if(i==2) continue;\n if(i==3) break;\n y=i;\n }\n sink(y);\n}"
        )
        cfg = session.control_flow.graphs[session.program.functions[0].id]
        self.assertTrue(list(nx.simple_cycles(cfg.graph)))
        self.assertTrue(
            any(statement.kind == "continue" for statement in cfg.statements.values())
        )
        definitions = session.trace_data_flow("y", position(8))["result"]["definitions"]
        self.assertIn(2, [item["location"]["start_line"] for item in definitions])
        self.assertIn(6, [item["location"]["start_line"] for item in definitions])

    def test_dominators_and_control_dependencies_are_not_plain_reachability(self):
        session = self.session(
            "void f(int x) {\n int y=0;\n if(x) {\n y=1;\n }\n sink(y);\n}"
        )
        cfg, branch = session.control_flow.locate(position(3))
        _, inside = session.control_flow.locate(position(4))
        _, sink = session.control_flow.locate(position(6))
        dominators = session.control_flow.dominators(cfg)
        self.assertIn(branch.id, dominators[sink.id])
        self.assertNotIn(inside.id, dominators[sink.id])
        dependencies = session.control_flow.control_dependencies(cfg)
        self.assertIn(branch.id, dependencies[inside.id])
        self.assertNotIn(branch.id, dependencies[sink.id])

    def test_each_supported_language_preserves_definition_and_return_semantics(self):
        cases = {
            "c": ("void f(int x) {\n int y=x;\n y=0;\n if(x) return;\n sink(y);\n}", 0),
            "cpp": (
                "void f(int x) {\n int y=x;\n y=0;\n if(x) return;\n sink(y);\n}",
                0,
            ),
            "javascript": (
                "function f(x) {\n let y=x;\n y=0;\n if(x) return;\n sink(y);\n}",
                0,
            ),
            "python": ("def f(x):\n y=x\n y=0\n if x: return\n sink(y)\n", 0),
            "go": (
                "package main\nfunc f(x int) {\n y:=x\n y=0\n if x>0 {return}\n sink(y)\n}",
                1,
            ),
        }
        for language, (code, offset) in cases.items():
            with self.subTest(language=language):
                session = self.session(code, language)
                result = session.trace_data_flow("y", position(5 + offset))["result"]
                self.assertEqual(
                    [item["location"]["start_line"] for item in result["definitions"]],
                    [3 + offset],
                )
                path = session.is_path_reachable(
                    position(4 + offset, 5), position(5 + offset)
                )["result"]
                self.assertEqual(path["status"], "path_found")

    def test_python_for_loop_and_go_range_bind_the_iterator(self):
        for language, code, line in (
            ("python", "def f(items):\n for item in items:\n  sink(item)\n", 3),
            (
                "go",
                "package main\nfunc f(items []int) {\n for _, item := range items {\n  sink(item)\n }\n}",
                4,
            ),
        ):
            with self.subTest(language=language):
                result = self.session(code, language).trace_data_flow(
                    "item", position(line)
                )["result"]
                self.assertTrue(
                    any(item["variable"] == "item" for item in result["definitions"])
                )

    def test_api_query_preserves_arguments_receiver_binding_and_local_implementation(
        self,
    ):
        session = self.session(
            "int helper(int x) {return x;}\nvoid f(int x) {\n int y=helper(x);\n sink(y);\n}"
        )
        envelope = session.inspect_api_usage(position(3))
        result = envelope["result"]
        self.assertEqual(result["callee"], "helper")
        self.assertEqual(result["arguments"], ["x"])
        self.assertEqual(result["return_value"]["binding"], "y")
        self.assertEqual(result["enclosing_function"], "f")
        self.assertIn("return x", result["local_definitions"][0]["implementation"])
        self.assertTrue(
            all(
                fact["location"]["file_path"] == "sample.c"
                for fact in envelope["facts"]
            )
        )
        member = self.session(
            "function f(x) {\n const y=obj.copy(x);\n}", "javascript"
        ).inspect_api_usage(position(2))["result"]
        self.assertEqual(member["receiver"], "obj")

    def test_a_b_a_analysis_has_no_cross_source_state(self):
        a = self.session("void f() {\n int x=1;\n sink(x);\n}")
        first = a.trace_data_flow("x", position(3))
        self.session("void f() {\n int x=2;\n sink(x);\n}").trace_data_flow(
            "x", position(3)
        )
        self.assertEqual(a.trace_data_flow("x", position(3)), first)

    def test_unknown_language_and_ambiguous_positions_are_explicit(self):
        with self.assertRaises(AnalysisError):
            infer_language("source.rs")
        session = self.session("void f(int x) { sink(x); other(x); }")
        with self.assertRaises(AnalysisError):
            session.inspect_api_usage(position(1))

    def test_structured_tool_rejects_string_line_numbers_and_unknown_arguments(self):
        session = self.session("void f(int x) {\n sink(x);\n}")
        tool = create_diagnostic_tools(session)[0]
        with self.assertRaises(ValueError):
            tool.invoke({"variable": "x", "statement": {"line": "2"}})
        with self.assertRaises(ValueError):
            tool.invoke(
                {"variable": "x", "statement": {"line": 2}, "code": "other source"}
            )

    def test_compound_updates_trace_the_previous_value(self):
        session = self.session(
            "void f(int input) {\n int x=input;\n x+=1;\n sink(x);\n}"
        )
        result = session.trace_data_flow("x", position(4))["result"]
        self.assertEqual(
            {item["location"]["start_line"] for item in result["definitions"]},
            {1, 2, 3},
        )

    def test_pointer_stores_do_not_redefine_the_pointer_value(self):
        session = self.session(
            "void f(int *input) {\n int *p=input;\n *p=0;\n sink(p);\n}"
        )
        result = session.trace_data_flow("p", position(4))["result"]
        self.assertNotIn(
            3, [item["location"]["start_line"] for item in result["definitions"]]
        )

    def test_go_receiver_and_all_parameter_names_are_preserved(self):
        session = self.session(
            "package main\ntype T struct{}\nfunc (t T) f(x, y int) {\n sink(y)\n}", "go"
        )
        function = session.program.functions[0]
        self.assertEqual(
            {session.source.text(node) for node in function.parameters}, {"t", "x", "y"}
        )
        self.assertTrue(
            session.trace_data_flow("y", position(4))["result"]["definitions"]
        )

    def test_python_type_annotations_are_not_parameter_variables(self):
        session = self.session("def f(x: int, y: str = 'a'):\n sink(x)\n", "python")
        self.assertEqual(
            {
                session.source.text(node)
                for node in session.program.functions[0].parameters
            },
            {"x", "y"},
        )

    def test_unicode_columns_select_the_actual_call(self):
        code = 'function f(x) { const label="汉字"; sink(x); }'
        session = self.session(code, "javascript")
        column = code.index("sink") + 1
        result = session.inspect_api_usage(position(1, column))["result"]
        self.assertEqual(result["callee"], "sink")
        self.assertEqual(result["location"]["start_column"], column)


if __name__ == "__main__":
    unittest.main()
