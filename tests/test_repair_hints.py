"""Generic validation feedback must not inject benchmark-specific repair knowledge."""

import unittest
from Online.phase3_repair.repair_hints import extract_structured_test_feedback


class TestRepairFeedback(unittest.TestCase):
    def test_quotes_actual_compiler_and_assertion_lines(self):
        log = "setup complete\nsource.c:4: error: unknown identifier size\nAssertionError: expected 2, actual 3\n"
        feedback = extract_structured_test_feedback(log)
        self.assertIn("unknown identifier size", feedback)
        self.assertIn("expected 2, actual 3", feedback)
        self.assertNotIn("setup complete", feedback)

    def test_test_names_do_not_create_repair_advice(self):
        log = "Cannot read properties of null (reading 'nes')\nAssertionError: invalid cookie"
        feedback = extract_structured_test_feedback(log, "poc_test")
        self.assertNotIn("state[config.cookie]", feedback)
        self.assertNotIn("statehood", feedback)
        self.assertNotIn("add a guard", feedback)
        self.assertEqual(
            extract_structured_test_feedback("test_function_name_injection"), ""
        )
