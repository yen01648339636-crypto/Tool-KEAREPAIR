"""Source-bound analysis queries and verifiable structural evidence."""

import hashlib

from utils.experiment_manifest import hash_object
from utils.schemas import ProgramFact, SourceLocation

from .control_flow_analyzer import ControlFlowAnalyzer
from .data_flow_analyzer import DataFlowAnalyzer
from .program import Program
from .reachability_checker import ReachabilityChecker
from .treesitter_wrapper import TreeSitterAnalyzer, field


class AnalysisSession:
    def __init__(self, code, *, language, file_path, line_offset=0):
        self.source = TreeSitterAnalyzer(language).parse(
            code, file_path=file_path, line_offset=line_offset
        )
        self.program = Program(self.source)
        self.control_flow = ControlFlowAnalyzer(self.program)
        self.data_flow = DataFlowAnalyzer(self.control_flow)
        self.reachability = ReachabilityChecker(self.control_flow)
        self.code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()

    def _result(self, tool, arguments, result, evidence):
        # Keep unknown/negative results as observations, never as runtime proofs.
        if not evidence:
            position = arguments.get("statement", arguments.get("target", {}))
            line = position.get("line", 1)
            evidence = [
                (
                    f"Structural query returned {result['status']!r}; consult its unresolved inputs and limitations.",
                    {"file_path": self.source.file_path, "start_line": line, "end_line": line},
                )
            ]
        facts = []
        for index, (statement, location) in enumerate(evidence):
            # Store the full query result once, rather than repeating large API
            # implementations for every source location in the same observation.
            details = (
                {"arguments": arguments, "result": result, "source_hash": self.code_hash}
                if index == 0 else {}
            )
            identifier = (
                "evidence-"
                + hash_object(
                    {
                        "source": self.code_hash,
                        "file": self.source.file_path,
                        "tool": tool,
                        "arguments": arguments,
                        "statement": statement,
                        "location": location,
                        "details": details,
                    }
                )[:24]
            )
            facts.append(
                ProgramFact(
                    statement=statement,
                    location=SourceLocation.from_dict(location),
                    tool=tool,
                    evidence_id=identifier,
                    details=details,
                ).to_dict()
            )
        return {
            "tool": tool,
            "arguments": arguments,
            "result": result,
            "facts": facts,
            "limitations": sorted(
                set(self.source.limitations + result.get("limitations", []))
            ),
            "source_hash": self.code_hash,
        }

    def trace_data_flow(self, variable, statement):
        result = self.data_flow.trace(variable, statement)
        evidence = [
            (
                f"{item['kind'].capitalize()} of abstract location {item['variable']!r} ({item['certainty']}): {item['code']}",
                item["location"],
            )
            for item in result["definitions"]
        ]
        return self._result(
            "trace_data_flow",
            {"variable": variable, "statement": statement.model_dump()},
            result,
            evidence,
        )

    def is_path_reachable(self, source, target, variable=None, max_paths=8):
        result = self.reachability.query(source, target, variable, max_paths)
        cfg, statement = self.control_flow.locate(target)
        location = self.source.location(statement.node)
        evidence = []
        if result["status"] == "path_found":
            evidence.append(
                (
                    f"An approximate intraprocedural CFG contains a path from line {source.line} to this statement. Runtime feasibility is unknown: {self.source.text(statement.node)}",
                    location,
                )
            )
        elif result["status"] == "no_cfg_path":
            evidence.append(
                (
                    f"The constructed intraprocedural CFG has no entry-connected path from line {source.line} to this statement; this is a structural result, not a runtime proof: {self.source.text(statement.node)}",
                    location,
                )
            )
        return self._result(
            "is_path_reachable",
            {
                "source": source.model_dump(),
                "target": target.model_dump(),
                "variable": variable,
                "max_paths": max_paths,
            },
            result,
            evidence,
        )

    def inspect_api_usage(self, call):
        node = self.program.call_at(call.line, call.column)
        callee = field(node, "function", "constructor")
        arguments = field(node, "arguments")
        receiver = (
            field(callee, "object", "argument", "operand", "value") if callee else None
        )
        function = self.program.function_at(call.line, call.column)
        binding, parent = None, node.parent
        while parent is not None and parent != function.node:
            if parent.type in {
                "assignment",
                "assignment_expression",
                "assignment_statement",
                "short_var_declaration",
                "init_declarator",
                "variable_declarator",
            }:
                target = field(parent, "left", "declarator", "name")
                binding = self.source.text(target) if target else None
                break
            if parent.type == "return_statement":
                binding = "<function return>"
                break
            parent = parent.parent
        callee_name = self.source.text(callee) if callee else "<dynamic constructor>"
        simple_name = callee_name.split("::")[-1].split(".")[-1].split("->")[-1]
        definitions = [
            item
            for item in self.program.functions
            if item.id != "module" and item.name.split("::")[-1] == simple_name
        ]
        # A member call can be dynamically dispatched; a unique name is only a candidate.
        local = [
            {
                "name": item.name,
                "location": self.source.location(item.node),
                "implementation": self.source.text(item.node),
                "resolution": "same_file_candidate",
            }
            for item in definitions
        ]
        location = self.source.location(node)
        lines = self.source.code.splitlines()
        start = max(0, node.start_point.row - 1)
        stop = min(len(lines), node.end_point.row + 2)
        result = {
            "status": "call_found",
            "callee": callee_name,
            "receiver": self.source.text(receiver) if receiver else None,
            "arguments": (
                [self.source.text(child) for child in arguments.named_children]
                if arguments
                else []
            ),
            "return_value": {
                "binding": binding,
                "context": (
                    self.source.text(parent)
                    if parent is not None and parent != function.node
                    else self.source.text(node)
                ),
            },
            "enclosing_function": function.name,
            "location": location,
            "context": [
                {"line": index + 1 + self.source.line_offset, "code": lines[index]}
                for index in range(start, stop)
            ],
            "local_definitions": local,
            "limitations": [
                "Callee candidates are matched syntactically; dynamic dispatch and library contracts are not inferred."
            ],
        }
        evidence = [
            (
                f"Call expression {self.source.text(node)!r} occurs in {function.name!r}; callee syntax is {callee_name!r}.",
                location,
            )
        ]
        evidence += [
            (
                f"Same-file function candidate {item['name']!r} has the shown implementation; runtime dispatch is not proven.",
                item["location"],
            )
            for item in local
        ]
        return self._result(
            "inspect_api_usage", {"call": call.model_dump()}, result, evidence
        )
