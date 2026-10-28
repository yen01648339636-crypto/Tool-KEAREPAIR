"""Explicit language parsing and source locations for structural analysis."""

from dataclasses import dataclass
import importlib
from functools import cached_property
from pathlib import Path

from tree_sitter import Language, Parser


LANGUAGES = {
    "c": "c",
    "cpp": "cpp",
    "python": "python",
    "javascript": "javascript",
    "go": "go",
}
ALIASES = {
    "c++": "cpp",
    "c/c++": "cpp",
    "py": "python",
    "js": "javascript",
    "node": "javascript",
    "nodejs": "javascript",
    "golang": "go",
}
FUNCTION_TYPES = {
    "function_definition",
    "function_declaration",
    "method_definition",
    "method_declaration",
    "function_expression",
    "arrow_function",
    "func_literal",
    "lambda",
}
BLOCK_TYPES = {"compound_statement", "statement_block", "block"}
CALL_TYPES = {"call_expression", "call", "new_expression"}
IDENTIFIER_TYPES = {
    "identifier",
    "shorthand_property_identifier",
    "shorthand_property_identifier_pattern",
}


class AnalysisError(ValueError):
    """A query cannot be answered reliably from the supplied source."""


def infer_language(file_path, hint=None):
    if hint:
        if not isinstance(hint, str):
            raise AnalysisError("Source language must be a string")
        normalized = hint.strip().lower()
        language = ALIASES.get(normalized, normalized)
        if language not in LANGUAGES:
            raise AnalysisError(f"Unsupported source language: {hint}")
        return language
    suffix = Path(file_path).suffix.lower()
    mapping = {
        ".c": "c",
        ".h": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
        ".py": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".jsx": "javascript",
        ".go": "go",
    }
    if suffix not in mapping:
        raise AnalysisError(
            f"Cannot determine source language for {file_path}; supply an explicit language"
        )
    return mapping[suffix]


def walk(node, *, skip_functions=False):
    yield node
    for child in node.named_children:
        if skip_functions and child.type in FUNCTION_TYPES:
            continue
        yield from walk(child, skip_functions=skip_functions)


def field(node, *names):
    for name in names:
        value = node.child_by_field_name(name)
        if value is not None:
            return value
    return None


@dataclass(frozen=True)
class ParsedSource:
    code: str
    language: str
    file_path: str
    line_offset: int
    tree: object

    @cached_property
    def encoded(self):
        return self.code.encode("utf-8")

    @cached_property
    def lines(self):
        return tuple(self.code.splitlines())

    @property
    def root(self):
        return self.tree.root_node

    def text(self, node):
        return self.encoded[node.start_byte : node.end_byte].decode("utf-8")

    def location(self, node):
        end_line, end_column = node.end_point
        if end_column == 0 and end_line > node.start_point.row:
            end_line -= 1
            end_column = len(self.lines[end_line].encode("utf-8"))
        start_column = (
            len(
                self.lines[node.start_point.row]
                .encode("utf-8")[: node.start_point.column]
                .decode("utf-8")
            )
            if node.start_point.row < len(self.lines)
            else 0
        )
        end_column = (
            len(self.lines[end_line].encode("utf-8")[:end_column].decode("utf-8"))
            if end_line < len(self.lines)
            else 0
        )
        return {
            "file_path": self.file_path,
            "start_line": node.start_point.row + 1 + self.line_offset,
            "end_line": end_line + 1 + self.line_offset,
            "start_column": start_column + 1,
            "end_column": end_column + 1,
        }

    def contains(self, node, line, column=None):
        line -= self.line_offset
        if not node.start_point.row + 1 <= line <= node.end_point.row + 1:
            return False
        if column is None:
            return True
        if line < 1 or line > len(self.lines) or column > len(self.lines[line - 1]) + 1:
            return False
        point = (line - 1, len(self.lines[line - 1][: column - 1].encode("utf-8")))
        return tuple(node.start_point) <= point < tuple(node.end_point)

    @property
    def limitations(self):
        result = [
            "Analysis is intraprocedural and structural; aliasing, dynamic dispatch, external effects and path feasibility are not proven."
        ]
        if self.root.has_error:
            result.append(
                "The parser reported incomplete or invalid syntax; affected control-flow conclusions are unknown."
            )
        if any(
            node.type.startswith("preproc_")
            and node.type
            not in {"preproc_include", "preproc_def", "preproc_function_def"}
            for node in walk(self.root)
        ):
            result.append(
                "Conditional compilation and macro expansion are not resolved."
            )
        elif any(
            node.type in {"preproc_def", "preproc_function_def"}
            for node in walk(self.root)
        ):
            result.append("Macro expansion is not evaluated.")
        return result


class TreeSitterAnalyzer:
    def __init__(self, language):
        self.language = infer_language("", language)
        grammar = importlib.import_module(f"tree_sitter_{LANGUAGES[self.language]}")
        self.parser = Parser(Language(grammar.language()))

    def parse(self, code, *, file_path, line_offset=0):
        if not isinstance(code, str) or not code.strip():
            raise AnalysisError("Source code must be nonempty")
        if type(line_offset) is not int or line_offset < 0:
            raise AnalysisError("line_offset must be a nonnegative integer")
        return ParsedSource(
            code,
            self.language,
            str(file_path),
            line_offset,
            self.parser.parse(code.encode("utf-8")),
        )
