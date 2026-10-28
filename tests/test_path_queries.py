"""Path alternatives, required guard outcomes, and explicit search limits."""

import unittest

from Online.phase1_diagnosis.tools import SourcePosition, create_diagnostic_tools
from static_analysis.session import AnalysisSession
from static_analysis.treesitter_wrapper import AnalysisError


def p(line, column=None):
    return SourcePosition(line=line, column=column)


DIAMOND = 'void f(int x) {\n int y=0;\n if(x) {\n y=1;\n } else {\n y=2;\n }\n sink(y);\n next(y);\n}'


class TestPathQueries(unittest.TestCase):
    def session(self, code):
        return AnalysisSession(code, language='c', file_path='source.c')

    def test_guard_before_source_is_reported_with_its_required_outcome(self):
        session = self.session('void f(int x) {\n if(x<=0) return;\n int y=x;\n sink(y);\n}')
        result = session.is_path_reachable(p(3), p(4), 'x')['result']
        path = result['paths'][0]
        self.assertEqual(path['predicates'], [])
        guard = path['dominating_conditions'][0]
        self.assertFalse(guard['outcome'])
        self.assertEqual(guard['location']['start_line'], 2)
        self.assertIn(4, [item['start_line'] for item in guard['required_for']])
        self.assertEqual(path['control_dependencies'][0]['location']['start_line'], 2)
        self.assertEqual(result['feasibility'], 'unknown')

    def test_diamond_enumerates_both_arms_with_distinct_outcomes(self):
        result = self.session(DIAMOND).is_path_reachable(p(2), p(8), 'x')['result']
        self.assertEqual(len(result['paths']), 2)
        self.assertEqual({path['predicates'][0]['outcome'] for path in result['paths']}, {True, False})
        self.assertFalse(result['search']['truncated'])
        for path in result['paths']:
            for guard in path['dominating_conditions']:
                self.assertNotIn(8, [location['start_line'] for location in guard['required_for']])

    def test_evaluated_condition_is_not_a_required_guard_after_merge(self):
        result = self.session(DIAMOND).is_path_reachable(p(8), p(9), 'x')['result']
        self.assertEqual(result['paths'][0]['dominating_conditions'], [])
        self.assertEqual(result['paths'][0]['control_dependencies'], [])

    def test_variable_filter_excludes_unrelated_prior_guards(self):
        code = 'void f(int x,int flag) {\n if(flag) return;\n if(x<=0) return;\n int y=x;\n sink(y);\n}'
        guards = self.session(code).is_path_reachable(p(4), p(5), 'x')['result']['paths'][0]['dominating_conditions']
        self.assertEqual([guard['location']['start_line'] for guard in guards], [3])

    def test_path_count_limit_reports_omitted_alternatives(self):
        result = self.session(DIAMOND).is_path_reachable(p(2), p(8), max_paths=1)['result']
        self.assertEqual(len(result['paths']), 1)
        self.assertTrue(result['search']['truncated'])
        self.assertIn('path_count_budget', result['search']['reasons'])

    def test_exact_path_limit_does_not_claim_a_nonexistent_third_path(self):
        result = self.session(DIAMOND).is_path_reachable(p(2), p(8), max_paths=2)['result']
        self.assertEqual(len(result['paths']), 2)
        self.assertFalse(result['search']['truncated'])

    def test_repeated_loop_iterations_are_explicitly_omitted(self):
        code = 'void f(int x) {\n int y=0;\n while(x) {\n y++;\n }\n sink(y);\n}'
        result = self.session(code).is_path_reachable(p(2), p(6))['result']
        self.assertEqual(result['status'], 'path_found')
        self.assertEqual(result['search']['loop_policy'], 'simple_paths')
        self.assertIn('loop_iterations_omitted', result['search']['reasons'])
        self.assertTrue(result['limitations'])

    def test_length_and_expansion_limits_do_not_become_no_path_claims(self):
        for field, reason in [('MAX_PATH_NODES', 'path_length_budget'), ('MAX_EXPANSIONS', 'expansion_budget')]:
            with self.subTest(limit=field):
                session = self.session(DIAMOND)
                setattr(session.reachability, field, 1)
                result = session.is_path_reachable(p(2), p(8))['result']
                self.assertEqual(result['status'], 'unknown')
                self.assertIn(reason, result['search']['reasons'])
                self.assertTrue(result['search']['truncated'])

    def test_unreachable_source_and_cross_function_query(self):
        code = 'void f() {\n return;\n sink();\n next();\n}\nvoid g() {\n other();\n}'
        session = self.session(code)
        self.assertEqual(session.is_path_reachable(p(3), p(4))['result']['status'], 'no_cfg_path')
        with self.assertRaises(AnalysisError):
            session.is_path_reachable(p(3), p(7))

    def test_native_tool_validates_bounds_and_exposes_complete_path_evidence(self):
        session = self.session(DIAMOND)
        tool = next(tool for tool in create_diagnostic_tools(session) if tool.name == 'is_path_reachable')
        for value in (0, 33, '2', True):
            with self.assertRaises(ValueError):
                tool.invoke({'source': {'line': 2}, 'target': {'line': 8}, 'max_paths': value})
        result = session.is_path_reachable(p(2), p(8), max_paths=2)
        self.assertEqual(result['facts'][0]['details']['result'], result['result'])
        self.assertEqual(result['arguments']['max_paths'], 2)
