"""Source-level regressions for aliasing, memory updates and uncertain calls."""

import unittest

from Online.phase1_diagnosis.tools import SourcePosition, create_diagnostic_tools
from static_analysis.session import AnalysisSession
from static_analysis.memory import MemoryModel


class TestMemoryDataFlow(unittest.TestCase):
    def session(self, code, language='c'):
        return AnalysisSession(code, language=language, file_path='source')

    def trace(self, code, variable, line, language='c'):
        result = self.session(code, language).trace_data_flow(variable, SourcePosition(line=line))['result']
        self.assertFalse(result['taint_proven'])
        return result

    def lines(self, result):
        return {item['location']['start_line'] for item in result['definitions']}

    def test_pointer_store_reaches_pointee_and_kills_its_old_value(self):
        code = 'void f(int secret) {\n int x=0;\n int *p=&x;\n *p=secret;\n sink(x);\n}'
        result = self.trace(code, 'x', 5)
        self.assertIn(1, self.lines(result))
        self.assertIn(4, self.lines(result))
        self.assertNotIn(2, self.lines(result))
        self.assertTrue(all('target_location' in edge for edge in result['propagation']))

    def test_pointer_identity_does_not_depend_on_stored_pointee_data(self):
        code = 'void f(int secret) {\n int x=0;\n int *p=&x;\n *p=secret;\n sink(p);\n}'
        result = self.trace(code, 'p', 5)
        self.assertEqual(self.lines(result), {3})

    def test_pointer_reassignment_changes_the_store_target(self):
        code = 'void f(int secret) {\n int x=0;\n int y=0;\n int *p=&x;\n p=&y;\n *p=secret;\n sink(x);\n sink(y);\n}'
        self.assertEqual(self.lines(self.trace(code, 'x', 7)), {2})
        self.assertIn(6, self.lines(self.trace(code, 'y', 8)))

    def test_alias_copy_and_pointer_to_pointer_writes(self):
        code = 'void f(int secret) {\n int x=0;\n int *p=&x;\n int **pp=&p;\n **pp=secret;\n sink(x);\n}'
        result = self.trace(code, 'x', 6)
        self.assertIn(5, self.lines(result))
        self.assertIn(1, self.lines(result))
        self.assertNotIn(2, self.lines(result))
        code = code.replace('int **pp=&p;', 'int *q=p;').replace('**pp=secret;', '*q=secret;')
        self.assertIn(5, self.lines(self.trace(code, 'x', 6)))

    def test_branch_merged_aliases_preserve_both_old_and_possible_new_values(self):
        code = 'void f(int secret,int c) {\n int x=0;\n int y=0;\n int *p=&x;\n if(c) p=&y;\n *p=secret;\n sink(x);\n}'
        result = self.trace(code, 'x', 7)
        self.assertTrue({1, 2, 6} <= self.lines(result))
        self.assertTrue(result['unresolved'])
        self.assertEqual(next(item for item in result['definitions'] if item['location']['start_line'] == 6)['certainty'], 'may')

    def test_unknown_pointer_store_may_affect_address_taken_local(self):
        code = 'void f(int secret,int *p) {\n int x=0;\n int *q=&x;\n *p=secret;\n sink(x);\n}'
        result = self.trace(code, 'x', 5)
        self.assertTrue({2, 4} <= self.lines(result))
        self.assertTrue(result['unresolved'])

    def test_distinct_fields_and_pointer_field_accesses_are_separate(self):
        code = 'void f(int secret) {\n struct T s;\n s.a=0;\n s.b=secret;\n sink(s.a);\n}'
        self.assertEqual(self.lines(self.trace(code, 's.a', 5)), {3})
        code = 'void f(int secret) {\n struct T s;\n struct T *p=&s;\n p->a=secret;\n sink(s.a);\n}'
        self.assertTrue({1, 4} <= self.lines(self.trace(code, 's.a', 5)))

    def test_array_constant_indices_do_not_taint_each_other(self):
        code = 'void f(int secret) {\n int a[2];\n a[0]=0;\n a[1]=secret;\n sink(a[0]);\n}'
        self.assertEqual(self.lines(self.trace(code, 'a[0]', 5)), {3})

    def test_array_initializer_elements_keep_separate_dependencies(self):
        code = 'void f(int secret) {\n int a[2]={secret,0};\n sink(a[0]);\n sink(a[1]);\n}'
        self.assertIn(1, self.lines(self.trace(code, 'a[0]', 3)))
        self.assertNotIn(1, self.lines(self.trace(code, 'a[1]', 4)))

    def test_unknown_index_write_is_weak_and_later_exact_write_kills_it(self):
        code = 'void f(int secret,int i) {\n int a[2];\n a[0]=0;\n a[i]=secret;\n sink(a[0]);\n}'
        result = self.trace(code, 'a[0]', 5)
        self.assertTrue({1, 3, 4} <= self.lines(result))
        self.assertTrue(result['unresolved'])
        code = 'void f(int secret,int i) {\n int a[2];\n a[i]=secret;\n a[0]=0;\n sink(a[0]);\n}'
        self.assertEqual(self.lines(self.trace(code, 'a[0]', 5)), {4})

    def test_known_array_pointer_offset_preserves_the_element(self):
        code = 'void f(int secret) {\n int a[3];\n int *p=&a[1];\n p[1]=secret;\n sink(a[2]);\n}'
        self.assertTrue({1, 4} <= self.lines(self.trace(code, 'a[2]', 5)))

    def test_unknown_pointer_arithmetic_does_not_silently_retain_only_old_value(self):
        code = 'void f(int secret,int offset) {\n int x=0;\n int *p=&x;\n *(p+offset)=secret;\n sink(x);\n}'
        result = self.trace(code, 'x', 5)
        self.assertTrue({2, 4} <= self.lines(result))
        self.assertTrue(result['unresolved'])

    def test_custom_output_argument_is_a_possible_source_with_explicit_uncertainty(self):
        code = 'void f() {\n int n=0;\n readU16(&n);\n sink(n);\n}'
        result = self.trace(code, 'n', 4)
        self.assertEqual(self.lines(result), {2, 3})
        self.assertIn('possible_call_write', {item['kind'] for item in result['definitions']})
        self.assertTrue(any('readU16' in note for note in result['unresolved']))

    def test_external_input_and_copy_effects_reach_the_destination(self):
        code = 'void f(int fd) {\n char a[8];\n char b[8];\n read(fd,a,8);\n memcpy(b,a,8);\n sink(b[0]);\n}'
        result = self.trace(code, 'b[0]', 6)
        self.assertTrue({4, 5} <= self.lines(result))
        self.assertTrue({'external_input', 'copy'} <= {item['kind'] for item in result['definitions']})
        self.assertTrue(any('External input' in note for note in result['unresolved']))

    def test_same_file_function_shadowing_does_not_get_a_standard_api_summary(self):
        code = 'int read(int fd,char *a,int n) {return 0;}\nvoid f() {\n char a[8];\n read(0,a,8);\n sink(a[0]);\n}'
        result = self.trace(code, 'a[0]', 5)
        self.assertNotIn('external_input', {item['kind'] for item in result['definitions']})
        self.assertTrue(any('Unknown callee read' in note for note in result['unresolved']))

    def test_macro_and_function_pointer_shadowing_disable_name_based_api_models(self):
        cases = [
            ('#define read(fd,a,n) custom(fd,a,n)\nvoid f() {\n char a[8];\n read(0,a,8);\n sink(a[0]);\n}', 5),
            ('void f(int (*read)(int,char*,int)) {\n char a[8];\n read(0,a,8);\n sink(a[0]);\n}', 4),
        ]
        for code, line in cases:
            with self.subTest(code=code):
                result = self.trace(code, 'a[0]', line)
                self.assertNotIn('external_input', {item['kind'] for item in result['definitions']})
                self.assertTrue(any('Unknown callee read' in note for note in result['unresolved']))

    def test_unknown_call_can_change_a_pointer_passed_by_address(self):
        code = 'void f(int secret) {\n int x=0;\n int y=0;\n int *q=&y;\n int *p=&x;\n alter(&p);\n *p=secret;\n sink(x);\n}'
        result = self.trace(code, 'x', 8)
        self.assertTrue({2, 7} <= self.lines(result))
        self.assertTrue(result['unresolved'])

    def test_later_unknown_call_may_write_previously_escaped_memory(self):
        code = 'void f() {\n int x=0;\n remember(&x);\n touch();\n sink(x);\n}'
        result = self.trace(code, 'x', 5)
        self.assertTrue({2, 3, 4} <= self.lines(result))
        self.assertTrue(any('touch' in note for note in result['unresolved']))

    def test_unknown_method_may_write_receiver_fields(self):
        code = 'function f(secret) {\n let obj={};\n obj.a=0;\n obj.set(secret);\n sink(obj.a);\n}'
        result = self.trace(code, 'obj.a', 5, 'javascript')
        self.assertTrue({1, 3, 4} <= self.lines(result))
        self.assertTrue(result['unresolved'])

    def test_object_reference_aliases_and_go_pointer_writes(self):
        cases = [
            ('javascript', 'function f(secret) {\n let obj={};\n let alias=obj;\n alias.a=secret;\n sink(obj.a);\n}', 'obj.a', 5, 4),
            ('python', 'def f(obj, secret):\n alias=obj\n alias.a=secret\n sink(obj.a)\n', 'obj.a', 4, 3),
            ('go', 'package main\nfunc f(secret int) {\n x:=0\n p:=&x\n *p=secret\n sink(x)\n}', 'x', 6, 5),
            ('cpp', 'void f(int secret) {\n int x=0;\n int *p=&x;\n *p=secret;\n sink(x);\n}', 'x', 5, 4),
        ]
        for language, code, variable, line, store in cases:
            with self.subTest(language=language):
                result = self.trace(code, variable, line, language)
                self.assertIn(store, self.lines(result))
                self.assertTrue(any(item['variable'] == 'secret' for item in result['definitions']))

    def test_trace_and_alias_budgets_report_incomplete_analysis(self):
        code = 'void f(int x) {\n int y=x;\n int z=y;\n sink(z);\n}'
        session = self.session(code)
        session.data_flow.MAX_TRACE_EDGES = 1
        result = session.trace_data_flow('z', SourcePosition(line=4))['result']
        self.assertTrue(result['truncated'])
        self.assertTrue(any('budget' in note for note in result['limitations']))
        old = MemoryModel.MAX_ALIAS_TRANSFERS
        try:
            MemoryModel.MAX_ALIAS_TRANSFERS = 1
            result = self.trace(code, 'z', 4)
            self.assertTrue(any('Alias fixed-point budget' in note for note in result['limitations']))
        finally:
            MemoryModel.MAX_ALIAS_TRANSFERS = old

    def test_access_path_tool_schema_rejects_executable_or_unbounded_queries(self):
        session = self.session('void f() {\n int x=0;\n sink(x);\n}')
        tool = next(tool for tool in create_diagnostic_tools(session) if tool.name == 'trace_data_flow')
        for value in ('x();', 'a[-1]', 'x' * 257, 'x;system(1)'):
            with self.assertRaises(ValueError):
                tool.invoke({'variable': value, 'statement': {'line': 3}})

    def test_union_fields_are_overlapping_memory_not_independent_fields(self):
        code = 'union U {int a; int b;};\nvoid f(int secret) {\n union U u;\n u.a=secret;\n sink(u.b);\n}'
        result = self.trace(code, 'u.b', 5)
        self.assertIn(4, self.lines(result))
        self.assertTrue(result['unresolved'])

    def test_pointer_field_and_nested_array_queries_follow_the_recorded_alias(self):
        code = 'void f(int secret) {\n struct T s;\n int a[2];\n s.ptr=&a[0];\n s.ptr[1]=secret;\n sink(a[1]);\n}'
        result = self.trace(code, 'a[1]', 6)
        self.assertIn(5, self.lines(result))
        code = 'void f(int secret) {\n struct T s;\n struct T *p=&s;\n p->a[0]=secret;\n sink(p->a[0]);\n}'
        result = self.trace(code, 'p->a[0]', 5)
        self.assertIn(4, self.lines(result))

    def test_go_var_pointer_declaration_preserves_the_address_binding(self):
        code = 'package main\nfunc f(secret int) {\n var x int = 0\n var p *int = &x\n *p=secret\n sink(x)\n}'
        result = self.trace(code, 'x', 6, 'go')
        self.assertIn(5, self.lines(result))
        self.assertNotIn(3, self.lines(result))

    def test_incoming_pointer_memory_is_an_unknown_parameter_source(self):
        code = 'void f(int *p) {\n int x=*p;\n sink(x);\n}'
        result = self.trace(code, 'x', 3)
        self.assertIn('parameter_memory', {item['kind'] for item in result['definitions']})
        self.assertTrue(result['unresolved'])

    def test_loop_alias_merge_keeps_both_possible_targets(self):
        code = 'void f(int secret,int c) {\n int x=0;\n int y=0;\n int *p=&x;\n while(c) {\n p=&y;\n c--;\n }\n *p=secret;\n sink(x);\n}'
        result = self.trace(code, 'x', 10)
        self.assertTrue({2, 9} <= self.lines(result))
        self.assertTrue(result['unresolved'])

    def test_memory_cell_limit_does_not_report_a_partial_result_as_complete(self):
        code = 'void f(int x) {\n int y=x;\n sink(y);\n}'
        session = self.session(code)
        session.data_flow.MAX_MEMORY_CELLS = 1
        result = session.trace_data_flow('y', SourcePosition(line=3))['result']
        self.assertEqual(result['status'], 'unknown')
        self.assertTrue(result['truncated'])
        self.assertEqual(result['definitions'], [])
