"""Tests for PatchEval language filtering in retrieval."""

import unittest

from Online.phase2_retrieval.retriever import (
    _infer_language_from_code,
    _metadata_matches_language,
)


class TestRetrieverLanguageFilter(unittest.TestCase):
    def test_code_language_overrides_wrong_metadata(self):
        metadata = {
            "sample_id": 1,
            "programming_language": "python",
            "buggy_code": "#include <stdio.h>\nstruct item { int x; };\n",
        }
        self.assertFalse(_metadata_matches_language(metadata, "python"))
        self.assertTrue(_metadata_matches_language(metadata, "c/c++"))

    def test_detects_python_and_javascript(self):
        self.assertEqual(_infer_language_from_code("from os import path\nclass A:\n    pass\n"), "python")
        self.assertEqual(
            _infer_language_from_code("const fs = require('fs');\nfunction run() {}\n"),
            "javascript",
        )


if __name__ == "__main__":
    unittest.main()
