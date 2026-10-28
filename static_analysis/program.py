"""Function boundaries, lexical symbols, and per-statement reads and writes."""

from dataclasses import dataclass, field as data_field

from .treesitter_wrapper import (
    BLOCK_TYPES,
    CALL_TYPES,
    FUNCTION_TYPES,
    IDENTIFIER_TYPES,
    AnalysisError,
    field,
    walk,
)

SCOPE_TYPES = BLOCK_TYPES | {
    "for_statement",
    "for_in_statement",
    "if_statement",
    "switch_statement",
    "expression_switch_statement",
}


@dataclass(frozen=True)
class Function:
    id: str
    name: str
    node: object
    body: object
    parameters: tuple


@dataclass(frozen=True)
class Symbol:
    id: str
    name: str
    scope: int
    declaration: int


@dataclass
class Statement:
    id: str
    node: object
    kind: str
    function: str
    definitions: set = data_field(default_factory=set)
    uses: set = data_field(default_factory=set)


class Program:
    """One source snapshot, never reused for another code string."""

    def __init__(self, source):
        self.source = source
        self.functions = []
        self.symbols = {}
        self._bindings = {}
        for node in walk(source.root):
            if node.type not in FUNCTION_TYPES:
                continue
            body = field(node, "body")
            if body is None:
                continue
            name_node = field(node, "name")
            declarator = field(node, "declarator")
            if name_node is None and declarator is not None:
                candidate = declarator
                while field(candidate, "declarator") is not None:
                    candidate = field(candidate, "declarator")
                name_node = candidate
            name = (
                source.text(name_node)
                if name_node
                else f"anonymous@{node.start_point.row + 1}"
            )
            parameters = field(node, "parameters")
            if parameters is None and declarator is not None:
                parameters = next(
                    (
                        field(item, "parameters")
                        for item in walk(declarator)
                        if field(item, "parameters") is not None
                    ),
                    None,
                )
            parameter_nodes = (
                self._parameter_names(parameters) if parameters is not None else []
            )
            receiver = field(node, "receiver")
            if receiver is not None:
                parameter_nodes.extend(self._parameter_names(receiver))
            function = Function(
                f"F{node.start_byte}", name, node, body, tuple(parameter_nodes)
            )
            self.functions.append(function)
            self._collect_bindings(function)
        # Script-level code has a separate lexical frame; function bodies are skipped.
        module = Function("module", "<module>", source.root, source.root, ())
        self.functions.append(module)
        self._collect_bindings(module)

    def _parameter_names(self, node):
        result = []
        if self.source.language == "python":
            for child in node.named_children:
                target = field(child, "name") or (
                    child.named_children[0]
                    if child.type == "typed_parameter" and child.named_children
                    else child
                )
                result.extend(self._target_names(target))
        else:
            for child in node.named_children:
                if child.type in IDENTIFIER_TYPES:
                    result.append(child)
                elif child.type in {
                    "parameter_declaration",
                    "optional_parameter_declaration",
                    "required_parameter",
                    "optional_parameter",
                    "rest_pattern",
                }:
                    targets = [
                        part
                        for index, part in enumerate(child.children)
                        if child.field_name_for_child(index)
                        in {"declarator", "name", "pattern"}
                    ]
                    for target in targets:
                        result.extend(self._target_names(target))
        return result

    def _target_names(self, node):
        if node is None:
            return []
        if node.type in IDENTIFIER_TYPES:
            return [node]
        if node.type in {
            "field_expression",
            "member_expression",
            "attribute",
            "selector_expression",
            "subscript",
            "subscript_expression",
            "index_expression",
            "pointer_expression",
        }:
            return []
        if node.type in {
            "assignment_pattern",
            "default_parameter",
            "typed_default_parameter",
        }:
            return self._target_names(field(node, "left", "name"))
        if node.type == "function_declarator":
            target = field(node, "declarator")
            return (
                []
                if target is None
                or target.type in {"identifier", "qualified_identifier"}
                else self._target_names(target)
            )
        if node.type in {
            "pointer_declarator",
            "reference_declarator",
            "array_declarator",
            "parenthesized_declarator",
        }:
            return self._target_names(
                field(node, "declarator")
                or (node.named_children[0] if node.named_children else None)
            )
        return [
            identifier
            for child in node.named_children
            for identifier in self._target_names(child)
        ]

    def _scope(self, node, function, *, function_scope=False):
        if function_scope or self.source.language == "python":
            return function.node.start_byte if function.id != "module" else -1
        current = node.parent
        while current is not None and current != function.node:
            if current.type in SCOPE_TYPES:
                return current.start_byte
            current = current.parent
        return function.node.start_byte if function.id != "module" else -1

    def _declare(self, target, function, scope=None, hoisted=False):
        scope = self._scope(target, function) if scope is None else scope
        name = self.source.text(target)
        key = function.id, scope, name
        if key not in self._bindings:
            symbol = Symbol(
                f"{function.id}:{scope}:{name}",
                name,
                scope,
                -1 if hoisted else target.start_byte,
            )
            self._bindings[key] = symbol
            self.symbols[symbol.id] = symbol

    def _collect_bindings(self, function):
        for parameter in function.parameters:
            self._declare(
                parameter,
                function,
                self._scope(parameter, function, function_scope=True),
                hoisted=True,
            )
        for node in walk(function.body, skip_functions=True):
            targets = []
            hoisted = self.source.language == "python"
            scope = None
            if node.type in {"init_declarator", "variable_declarator"}:
                targets = self._target_names(field(node, "declarator", "name"))
                if (
                    self.source.language == "javascript"
                    and node.parent
                    and node.parent.type == "variable_declaration"
                ):
                    scope = self._scope(node, function, function_scope=True)
                    hoisted = True
            elif node.type in {"declaration", "parameter_declaration", "var_spec"}:
                for i, child in enumerate(node.children):
                    if (
                        node.field_name_for_child(i) in {"declarator", "name"}
                        and child.type != "init_declarator"
                    ):
                        targets.extend(self._target_names(child))
            elif node.type == "short_var_declaration":
                targets = self._target_names(field(node, "left"))
            elif self.source.language == "python" and node.type in {
                "assignment",
                "augmented_assignment",
                "named_expression",
                "for_statement",
            }:
                targets = self._target_names(field(node, "left", "name"))
            elif self.source.language == "go" and node.type == "range_clause":
                if ":=" in self.source.text(node):
                    targets = self._target_names(field(node, "left"))
            for target in targets:
                if self.source.language != "go" or self.source.text(target) != "_":
                    self._declare(target, function, scope, hoisted)

    def resolve(self, name, node, function):
        scopes = []
        current = node
        while current is not None:
            if current.type in SCOPE_TYPES:
                scopes.append(current.start_byte)
            if current == function.node:
                break
            current = current.parent
        scopes += [self._scope(node, function, function_scope=True)]
        for scope in scopes:
            symbol = self._bindings.get((function.id, scope, name))
            if symbol is not None and symbol.declaration <= node.start_byte:
                return symbol.id
        identifier = f"{function.id}:external:{name}"
        if identifier not in self.symbols:
            self.symbols[identifier] = Symbol(identifier, name, -2, -1)
        return identifier

    def effects(self, statement, function, *, parameter=False):
        if parameter:
            statement.definitions = {
                self.resolve(self.source.text(node), node, function)
                for node in function.parameters
            }
            return statement
        defined, excluded, read_targets = [], set(), set()
        for node in walk(statement.node, skip_functions=True):
            target = None
            if node.type in {
                "assignment",
                "assignment_expression",
                "augmented_assignment",
                "augmented_assignment_expression",
                "assignment_statement",
                "short_var_declaration",
                "named_expression",
            }:
                target = field(node, "left", "name")
                operator = field(node, "operator")
                if "augmented" in node.type or (
                    operator is not None
                    and self.source.text(operator) not in {"=", ":="}
                ):
                    read_targets.update(item.id for item in self._target_names(target))
            elif node.type in {"init_declarator", "variable_declarator"}:
                target = field(node, "declarator", "name")
            elif node.type in {"update_expression", "inc_statement", "dec_statement"}:
                target = field(node, "argument") or (
                    node.named_children[0] if node.named_children else None
                )
                read_targets.update(item.id for item in self._target_names(target))
            elif node.type in {"declaration", "var_spec"}:
                for i, child in enumerate(node.children):
                    if (
                        node.field_name_for_child(i) in {"declarator", "name"}
                        and child.type != "init_declarator"
                    ):
                        defined.extend(self._target_names(child))
            elif node.type in {
                "for_statement",
                "range_clause",
            } and self.source.language in {"python", "go"}:
                target = field(node, "left")
            if target is not None:
                targets = self._target_names(target)
                defined.extend(targets)
        excluded.update(item.id for item in defined)
        for node in defined:
            if self.source.language == "go" and self.source.text(node) == "_":
                continue
            statement.definitions.add(
                self.resolve(self.source.text(node), node, function)
            )
        for node in walk(statement.node, skip_functions=True):
            if node.type not in IDENTIFIER_TYPES or (
                node.id in excluded and node.id not in read_targets
            ):
                continue
            if self.source.language == "go" and self.source.text(node) == "_":
                continue
            parent = node.parent
            if (
                parent
                and parent.type in CALL_TYPES
                and field(parent, "function", "constructor") == node
            ):
                continue
            if (
                parent
                and parent.type == "attribute"
                and field(parent, "attribute") == node
            ):
                continue
            statement.uses.add(self.resolve(self.source.text(node), node, function))
        return statement

    def function_at(self, line, column=None):
        matches = [
            function
            for function in self.functions
            if function.id != "module"
            and self.source.contains(function.node, line, column)
        ]
        return (
            min(
                matches,
                key=lambda function: function.node.end_byte - function.node.start_byte,
            )
            if matches
            else self.functions[-1]
        )

    def call_at(self, line, column=None):
        matches = [
            node
            for node in walk(self.source.root)
            if node.type in CALL_TYPES and self.source.contains(node, line, column)
        ]
        if column is not None and matches:
            return min(matches, key=lambda node: node.end_byte - node.start_byte)
        if len(matches) != 1:
            raise AnalysisError(
                f"Expected exactly one call at line {line}; found {len(matches)}. Supply its column."
            )
        return matches[0]
