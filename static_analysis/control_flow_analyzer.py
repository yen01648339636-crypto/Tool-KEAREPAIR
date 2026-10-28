"""Statement CFGs with explicit branches, loop exits, and dominance relations."""

from dataclasses import dataclass, field as data_field

import networkx as nx

from .program import Statement
from .treesitter_wrapper import BLOCK_TYPES, FUNCTION_TYPES, AnalysisError, field, walk


@dataclass
class FunctionGraph:
    function: object
    graph: object
    statements: dict
    entry: str
    exit: str
    limitations: list = data_field(default_factory=list)


class ControlFlowAnalyzer:
    def __init__(self, program):
        self.program = program
        self.graphs = {
            function.id: self._build(function) for function in program.functions
        }

    def _build(self, function):
        cfg = FunctionGraph(
            function, nx.DiGraph(), {}, f"{function.id}:ENTRY", f"{function.id}:EXIT"
        )
        cfg.graph.add_nodes_from([cfg.entry, cfg.exit])
        entry = Statement(cfg.entry, function.node, "parameters", function.id)
        cfg.statements[cfg.entry] = self.program.effects(
            entry, function, parameter=True
        )
        if function.node.has_error:
            cfg.limitations.append("Syntax errors affect this function's control flow.")
        unsupported = {
            "go_statement",
            "defer_statement",
            "await_expression",
            "global_statement",
            "nonlocal_statement",
        }
        for node in walk(function.body, skip_functions=True):
            if node.type in unsupported:
                cfg.limitations.append(
                    f"Execution effects of {node.type} are not modeled."
                )

        def atom(node, kind="statement"):
            identifier = f"{function.id}:N{len(cfg.statements)}"
            cfg.statements[identifier] = self.program.effects(
                Statement(identifier, node, kind, function.id), function
            )
            cfg.graph.add_node(identifier)
            return identifier

        def edge(source, target, predicate=None, outcome=None):
            if (
                cfg.graph.has_edge(source, target)
                and cfg.graph[source][target].get("outcome") != outcome
            ):
                predicate, outcome = None, None
            cfg.graph.add_edge(source, target, predicate=predicate, outcome=outcome)

        def sequence(nodes, continuation, break_to=None, continue_to=None):
            current = continuation
            for node in reversed(list(nodes)):
                current = build(node, current, break_to, continue_to)
            return current

        def build(node, continuation, break_to=None, continue_to=None):
            kind = node.type
            if kind in FUNCTION_TYPES or kind in {
                "comment",
                "package_clause",
                "import_declaration",
                "import_statement",
                "import_from_statement",
                "preproc_include",
                "preproc_def",
                "preproc_function_def",
                "empty_statement",
            }:
                return continuation
            if kind in BLOCK_TYPES | {
                "statement_list",
                "translation_unit",
                "program",
                "module",
                "source_file",
                "else_clause",
                "declaration_list",
            }:
                return sequence(
                    node.named_children, continuation, break_to, continue_to
                )
            if kind in {"if_statement", "elif_clause"}:
                condition = field(node, "condition")
                if condition is None:
                    cfg.limitations.append(
                        "A conditional has no supported condition expression."
                    )
                    return continuation
                branch = atom(condition, "condition")
                consequence = field(node, "consequence", "body")
                alternative = field(node, "alternative")
                yes = (
                    build(consequence, continuation, break_to, continue_to)
                    if consequence
                    else continuation
                )
                # Python elif clauses may be repeated alternative children.
                alternatives = [
                    child
                    for child in node.named_children
                    if child.type in {"elif_clause", "else_clause"}
                ]
                no = (
                    sequence(alternatives, continuation, break_to, continue_to)
                    if alternatives
                    else (
                        build(alternative, continuation, break_to, continue_to)
                        if alternative
                        else continuation
                    )
                )
                predicate = self.program.source.text(condition)
                edge(branch, yes, predicate, True)
                edge(branch, no, predicate, False)
                initializer = field(node, "initializer")
                return (
                    build(initializer, branch, break_to, continue_to)
                    if initializer
                    else branch
                )
            if kind in {
                "while_statement",
                "do_statement",
                "for_statement",
                "for_in_statement",
            }:
                body = field(node, "body")
                initializer, condition, update = (
                    field(node, "initializer"),
                    field(node, "condition"),
                    field(node, "update", "increment"),
                )
                clause = next(
                    (
                        child
                        for child in node.named_children
                        if child.type in {"for_clause", "range_clause"}
                    ),
                    None,
                )
                if clause and clause.type == "for_clause":
                    initializer, condition, update = (
                        field(clause, "initializer"),
                        field(clause, "condition"),
                        field(clause, "update"),
                    )
                is_iterator = (
                    self.program.source.language == "python"
                    and kind == "for_statement"
                    or kind == "for_in_statement"
                    or clause is not None
                    and clause.type == "range_clause"
                )
                if is_iterator:
                    iterable = (
                        field(node, "right")
                        if clause is None
                        else field(clause, "right")
                    )
                    condition = iterable or clause or node
                if (
                    self.program.source.language == "go"
                    and condition is None
                    and clause is None
                ):
                    condition = next(
                        (child for child in node.named_children if child != body), None
                    )
                condition_node = condition or node
                header = atom(
                    condition_node, "iterator" if is_iterator else "condition"
                )
                if condition is None:
                    cfg.statements[header].uses.clear()
                    cfg.statements[header].definitions.clear()
                update_entry = (
                    build(update, header, continuation, header) if update else header
                )
                body_entry = (
                    build(body, update_entry, continuation, update_entry)
                    if body
                    else update_entry
                )
                if is_iterator:
                    target = (
                        field(node, "left") if clause is None else field(clause, "left")
                    )
                    binding = atom(target, "iteration_binding") if target else None
                    if binding:
                        statement = cfg.statements[binding]
                        statement.uses = set(cfg.statements[header].uses)
                        statement.definitions = {
                            self.program.resolve(
                                self.program.source.text(identifier),
                                identifier,
                                function,
                            )
                            for identifier in self.program._target_names(target)
                        }
                        edge(binding, body_entry)
                        body_entry = binding
                predicate = (
                    self.program.source.text(condition)
                    if condition is not None
                    else "true"
                )
                edge(header, body_entry, predicate, True)
                alternative = field(node, "alternative")
                normal_exit = (
                    build(alternative, continuation, break_to, continue_to)
                    if alternative
                    else continuation
                )
                if condition is not None:
                    edge(header, normal_exit, predicate, False)
                result = body_entry if kind == "do_statement" else header
                return (
                    build(initializer, result, break_to, continue_to)
                    if initializer
                    else result
                )
            if kind in {"return_statement", "throw_statement", "raise_statement"}:
                current = atom(
                    node, "return" if kind == "return_statement" else "throw"
                )
                edge(current, cfg.exit)
                if kind != "return_statement":
                    cfg.limitations.append(
                        "Exception propagation and handlers are not resolved."
                    )
                return current
            if kind in {"break_statement", "continue_statement"}:
                current = atom(
                    node, "break" if kind == "break_statement" else "continue"
                )
                target = break_to if kind == "break_statement" else continue_to
                if target is None or len(node.named_children) > 0:
                    cfg.limitations.append(
                        "A labeled or out-of-context loop transfer cannot be resolved."
                    )
                    target = continuation
                edge(current, target)
                return current
            if kind in {
                "try_statement",
                "with_statement",
                "match_statement",
                "switch_statement",
                "expression_switch_statement",
                "type_switch_statement",
                "select_statement",
                "goto_statement",
                "labeled_statement",
                "yield",
                "yield_expression",
                "ERROR",
            } or kind.startswith("preproc_"):
                cfg.limitations.append(
                    f"Control flow for {kind} is conservative; reachability conclusions may be unknown."
                )
                # Keep syntactic descendants visible without asserting complete branch semantics.
                children = [
                    child
                    for child in node.named_children
                    if child.type in BLOCK_TYPES or child.type.endswith("statement")
                ]
                if children:
                    return sequence(children, continuation, break_to, continue_to)
            if kind in {
                "class_definition",
                "class_declaration",
                "struct_specifier",
                "type_declaration",
            }:
                return continuation
            if kind in {"declaration", "lexical_declaration", "variable_declaration"}:
                declarators = [
                    child
                    for child in node.named_children
                    if child.type in {"init_declarator", "variable_declarator"}
                ]
                if len(declarators) > 1:
                    return sequence(declarators, continuation, break_to, continue_to)
            current = atom(node)
            edge(current, continuation)
            return current

        first = build(function.body, cfg.exit)
        edge(cfg.entry, first)
        cfg.limitations = sorted(set(cfg.limitations))
        return cfg

    def locate(self, position):
        function = self.program.function_at(position.line, position.column)
        cfg = self.graphs[function.id]
        candidates = [
            statement
            for identifier, statement in cfg.statements.items()
            if identifier != cfg.entry
            and self.program.source.contains(
                statement.node, position.line, position.column
            )
            and not (
                statement.kind == "condition"
                and statement.node.type in {"for_statement", "while_statement"}
                and position.line
                != statement.node.start_point.row + 1 + self.program.source.line_offset
            )
        ]
        if position.column is not None and candidates:
            candidates.sort(key=lambda item: item.node.end_byte - item.node.start_byte)
            return cfg, candidates[0]
        if len(candidates) != 1:
            raise AnalysisError(
                f"Expected one statement at line {position.line}; found {len(candidates)}. Supply a column."
            )
        return cfg, candidates[0]

    @staticmethod
    def dominators(cfg, reverse=False):
        graph, entry = (
            (cfg.graph.reverse(), cfg.exit) if reverse else (cfg.graph, cfg.entry)
        )
        parents = nx.immediate_dominators(graph, entry)
        result = {}
        for node in parents:
            ancestors, current = {node}, node
            while parents[current] != current:
                current = parents[current]
                ancestors.add(current)
            result[node] = ancestors
        return result

    @staticmethod
    def control_dependencies(cfg):
        parents = nx.immediate_dominators(cfg.graph.reverse(), cfg.exit)
        dependencies = {node: set() for node in cfg.graph}
        post = ControlFlowAnalyzer.dominators(cfg, reverse=True)
        for source, target in cfg.graph.edges:
            if source not in parents or target in post.get(source, set()):
                continue
            runner, visited = target, set()
            while (
                runner in parents
                and runner != parents[source]
                and runner not in visited
            ):
                visited.add(runner)
                dependencies[runner].add(source)
                runner = parents[runner]
        return dependencies

    @staticmethod
    def dominating_branches(cfg):
        """Find required branch outcomes by splitting conditional edges into nodes.

        A dominating condition whose two arms rejoin is not itself a guard with
        a required outcome. This graph transformation preserves that distinction.
        """
        graph = nx.DiGraph()
        graph.add_nodes_from(cfg.graph)
        branches = {}
        for source, target, attributes in cfg.graph.edges(data=True):
            if attributes.get("predicate") is None:
                graph.add_edge(source, target)
            else:
                marker = (source, target)
                graph.add_edge(source, marker)
                graph.add_edge(marker, target)
                branches[marker] = (source, attributes)
        parents = nx.immediate_dominators(graph, cfg.entry)
        result = {}
        for node in cfg.graph:
            conditions, current = [], node
            while current in parents and parents[current] != current:
                current = parents[current]
                if current in branches:
                    conditions.append(branches[current])
            result[node] = list(reversed(conditions))
        return result
