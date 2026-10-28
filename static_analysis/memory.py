"""Finite, flow-sensitive access paths and conservative intraprocedural effects.

Locations distinguish variable values, pointees, fields and constant array
indices. Unknown indices/aliases and calls are may effects, never strong kills.
This is not a whole-program heap analysis or a runtime taint proof.
"""

from collections import deque
from dataclasses import dataclass, field as data_field
import re

import networkx as nx

from .treesitter_wrapper import CALL_TYPES, FUNCTION_TYPES, IDENTIFIER_TYPES, field, walk

ACCESS_PATTERN = r"^\*?[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|->)[A-Za-z_][A-Za-z0-9_]*|\[(?:[0-9]+|\*|[A-Za-z_][A-Za-z0-9_]*)\])*$"
FIELDS = {"field_expression", "member_expression", "attribute", "selector_expression"}
INDICES = {"subscript", "subscript_expression", "index_expression"}
ASSIGNMENTS = {"assignment", "assignment_expression", "augmented_assignment",
               "augmented_assignment_expression", "assignment_statement",
               "short_var_declaration", "named_expression"}
DECLARATORS = {"init_declarator", "variable_declarator"}
UPDATES = {"update_expression", "inc_statement", "dec_statement"}
WRAPPERS = {"parenthesized_expression", "parenthesized_declarator", "expression_list"}
OBJECTS = {"object", "array", "dictionary", "list", "set", "new_expression", "composite_literal"}


@dataclass(frozen=True, order=True)
class Cell:
    root: str
    path: tuple = ()

    def child(self, selector):
        return Cell(self.root, self.path + (selector,))

    @property
    def uncertain(self):
        return self.root.startswith("?") or any(part in {"[*]", ".*"} for part in self.path)


@dataclass
class Write:
    target: object
    value: object
    read_old: bool = False
    declaration: bool = False


@dataclass
class Effects:
    reads: set = data_field(default_factory=set)
    writes: dict = data_field(default_factory=dict)
    strong: set = data_field(default_factory=set)
    notes: dict = data_field(default_factory=dict)
    kinds: dict = data_field(default_factory=dict)
    limitations: list = data_field(default_factory=list)


class MemoryModel:
    MAX_ALIAS_TRANSFERS = 20000
    MAX_ACCESS_DEPTH = 6
    MAX_POINTS_TO = 32

    def __init__(self, control_flow, cfg):
        self.control_flow, self.cfg = control_flow, cfg
        self.program, self.source = control_flow.program, control_flow.program.source
        self.dynamic = self.source.language in {"python", "javascript"}
        self.pointers, self.arrays, self.references = set(), set(), set()
        self.unions = set()
        self.labels, self.addressed = {}, set()
        self.escaped = set()
        self.limitations = []
        self.truncated = False
        self.shadowed_apis = {function.name for function in self.program.functions}
        self.shadowed_apis.update(
            self.source.text(field(node, "name"))
            for node in walk(self.source.root)
            if node.type in {"preproc_def", "preproc_function_def"}
            and field(node, "name") is not None
        )
        self.shadowed_apis.update(
            symbol.name for symbol in self.program.symbols.values()
            if symbol.id.startswith("module:") and symbol.scope != -2
        )
        self.specs = {key: self._writes(statement.node) for key, statement in cfg.statements.items() if key != cfg.entry}
        self.calls = {key: [node for node in walk(statement.node, skip_functions=True) if node.type in CALL_TYPES]
                      for key, statement in cfg.statements.items() if key != cfg.entry}
        self._types()
        self.alias_in, self.alias_out = self._aliases()
        # Function-wide escape sets deliberately overapproximate order: a later
        # unknown call may modify memory passed to an earlier call or callback.
        # Recompute pointer states if escaped pointer slots themselves may change.
        for _ in range(3):
            escaped = set(self.escaped)
            for identifier, calls in self.calls.items():
                for call in calls:
                    arguments = field(call, "arguments")
                    for argument in arguments.named_children if arguments else ():
                        points = self._buffer(argument, self.alias_in[identifier])
                        escaped |= {cell.child(".*") if self.dynamic else cell for cell in points}
                    callee = field(call, "function", "constructor")
                    if callee is not None and callee.type in FIELDS:
                        receiver = field(callee, "object", "argument", "operand", "value")
                        escaped |= {cell.child(".*") for cell in self._object(receiver, self.alias_in[identifier], self._operator(callee) == "->")}
            if escaped == self.escaped:
                break
            self.escaped = escaped
            self.alias_in, self.alias_out = self._aliases()
        else:
            self.limitations.append("Escape analysis widened after its iteration budget; escaped aliases remain uncertain.")
            self.truncated = True
            self.escaped |= self.addressed
        self.pointers.update(set().union(*(set(state) for state in self.alias_out.values())))
        self.effects = {key: self._effects(key, statement) for key, statement in cfg.statements.items()}
        self.cells = set().union(*(effect.reads | set(effect.writes) for effect in self.effects.values()))

    def _root(self, node):
        return Cell(self.program.resolve(self.source.text(node), node, self.cfg.function))

    def _unwrap(self, node):
        while node is not None and node.type in WRAPPERS and len(node.named_children) == 1:
            node = node.named_children[0]
        return node

    def _operator(self, node):
        operator = field(node, "operator")
        return self.source.text(operator) if operator else ""

    def _types(self):
        union_names = {
            self.source.text(field(node, "name"))
            for node in walk(self.source.root)
            if node.type == "union_specifier" and field(node, "name") is not None
        }
        for node in walk(self.cfg.function.node, skip_functions=True):
            if node.type not in {"declaration", "parameter_declaration", "var_spec"}:
                continue
            type_node = field(node, "type")
            if type_node is None:
                continue
            for index, child in enumerate(node.children):
                if node.field_name_for_child(index) not in {"declarator", "name"}:
                    continue
                for name in self.program._target_names(child):
                    cell = self._root(name)
                    if type_node.type == "pointer_type" or type_node.type == "slice_type":
                        self.pointers.add(cell)
                    if type_node.type == "array_type":
                        self.arrays.add(cell)
                    if type_node.type == "union_specifier" or self.source.text(type_node) in union_names:
                        self.unions.add(cell.root)
        for node in walk(self.cfg.function.body, skip_functions=True):
            if node.type in {"pointer_expression", "unary_expression"} and self._operator(node) == "&":
                argument = self._unwrap(field(node, "argument", "operand"))
                if argument is not None and argument.type in IDENTIFIER_TYPES:
                    self.addressed.add(self._root(argument))
        for symbol in self.program.symbols.values():
            if self.dynamic and symbol.id.startswith(self.cfg.function.id + ":"):
                self.pointers.add(Cell(symbol.id))
        for node in walk(self.cfg.function.node, skip_functions=True):
            if node.type not in IDENTIFIER_TYPES:
                continue
            current = node.parent
            while current is not None and current != self.cfg.function.node:
                if current.type in {"pointer_declarator", "pointer_type"}:
                    self.pointers.add(self._root(node))
                if current.type == "reference_declarator":
                    self.references.add(self._root(node))
                if current.type == "array_declarator":
                    self.arrays.add(self._root(node))
                if current.type == "parameter_declaration":
                    type_node = field(current, "type")
                    if type_node is not None and type_node.type == "pointer_type":
                        self.pointers.add(self._root(node))
                    break
                if current.type in ASSIGNMENTS | DECLARATORS | {"declaration", "expression_statement"}:
                    break
                current = current.parent
        for writes in self.specs.values():
            for write in writes:
                target = self._declaration_target(write.target) if write.declaration else self._unwrap(write.target)
                value = self._unwrap(write.value)
                if target is not None and target.type in IDENTIFIER_TYPES and value is not None:
                    if self._operator(value) == "&":
                        self.pointers.add(self._root(target))
        if self.references:
            self.limitations.append("C++ reference binding and rebinding effects are not fully resolved.")

    def _declaration_target(self, node):
        while node is not None and node.type in {"pointer_declarator", "reference_declarator", "array_declarator", "parenthesized_declarator"}:
            node = field(node, "declarator") or (node.named_children[0] if node.named_children else None)
        return node

    def _writes(self, node):
        writes = []
        for item in walk(node, skip_functions=True):
            if item.type in ASSIGNMENTS:
                target, value = field(item, "left", "name"), field(item, "right", "value")
                targets = list(target.named_children) if target is not None and target.type == "expression_list" else [target]
                values = list(value.named_children) if value is not None and value.type == "expression_list" else [value]
                old = "augmented" in item.type or self._operator(item) not in {"", "=", ":="}
                for index, target in enumerate(targets):
                    writes.append(Write(target, values[index] if len(values) == len(targets) else value, old))
            elif item.type in DECLARATORS:
                writes.append(Write(field(item, "declarator", "name"), field(item, "value"), declaration=True))
            elif item.type == "var_spec":
                names = [child for index, child in enumerate(item.children) if item.field_name_for_child(index) == "name"]
                value = field(item, "value")
                values = list(value.named_children) if value is not None and value.type == "expression_list" else [value]
                for index, name in enumerate(names):
                    writes.append(Write(name, values[index] if len(values) == len(names) else value, declaration=True))
            elif item.type in UPDATES:
                writes.append(Write(field(item, "argument") or (item.named_children[0] if item.named_children else None), None, True))
        return writes

    def _unknown(self, cell):
        root = "?" + cell.root.lstrip("?")
        self.labels.setdefault(root, "unknown pointee of " + self.display(cell))
        return Cell(root, cell.path)

    def _default(self, cell):
        return frozenset({self._unknown(cell)})

    def _bounded(self, points, cell):
        if len(points) > self.MAX_POINTS_TO or any(len(point.path) > self.MAX_ACCESS_DEPTH for point in points):
            self.limitations.append("Points-to/access-path budget exceeded; affected aliases are unknown.")
            self.truncated = True
            return self._default(cell)
        return frozenset(points)

    def points(self, node, state):
        node = self._unwrap(node)
        if node is None:
            return set()
        if node.type in IDENTIFIER_TYPES:
            cell = self._root(node)
            if cell in self.arrays:
                return {cell.child("[0]")}
            return set(state.get(cell, self._default(cell) if cell in self.pointers else ()))
        if node.type in {"pointer_expression", "unary_expression"} and self._operator(node) == "&":
            return self.locations(field(node, "argument", "operand"), state)
        if node.type in {"pointer_expression", "unary_expression"} and self._operator(node) == "*":
            return set().union(*(state.get(cell, self._default(cell)) for cell in self.locations(node, state)))
        if node.type in FIELDS | INDICES:
            return set().union(*(state.get(cell, ()) for cell in self.locations(node, state)))
        if self.dynamic and node.type in OBJECTS:
            cell = Cell("heap:" + str(node.start_byte))
            self.labels[cell.root] = f"object@{node.start_point.row + 1 + self.source.line_offset}"
            return {cell}
        if node.type in {"binary_expression", "cast_expression"}:
            points = set().union(*(self.points(child, state) for child in node.named_children))
            if points:
                return points | {self._unknown_expression(node)}
        return set()

    def _unknown_expression(self, node):
        cell = Cell("?expression:" + str(node.start_byte))
        self.labels[cell.root] = f"unknown access@{node.start_point.row + 1 + self.source.line_offset}"
        return cell

    def _object(self, node, state, indirect=False):
        node = self._unwrap(node)
        if node is None:
            return set()
        if indirect or self.dynamic or (self.source.language == "go" and node.type in IDENTIFIER_TYPES and self._root(node) in self.pointers):
            points = self.points(node, state)
            if points:
                return points
            cells = self.locations(node, state)
            return {self._unknown(cell) for cell in cells}
        return self.locations(node, state)

    @staticmethod
    def _index(base, index):
        # Pointer arithmetic on a known array element, e.g. (&a[2])[1].
        if base.path and base.path[-1].startswith("["):
            previous = base.path[-1][1:-1]
            value = str(int(previous) + int(index)) if previous.isdecimal() and index.isdecimal() else "*"
            return Cell(base.root, base.path[:-1] + (f"[{value}]",))
        return base.child(f"[{index}]")

    def _field(self, cell, name):
        return cell.child(".*" if cell.root.lstrip("?") in self.unions else "." + name)

    def locations(self, node, state):
        node = self._unwrap(node)
        if node is None:
            return set()
        if node.type in IDENTIFIER_TYPES:
            return {self._root(node)}
        if node.type in {"pointer_expression", "unary_expression"} and self._operator(node) == "*":
            argument = field(node, "argument", "operand")
            points = self.points(argument, state)
            return points or {self._unknown(cell) for cell in self.locations(argument, state)} or {self._unknown_expression(node)}
        if node.type in FIELDS:
            base = field(node, "object", "argument", "operand", "value")
            member = field(node, "field", "attribute", "property")
            if member is None:
                return set()
            return {self._field(cell, self.source.text(member))
                    for cell in self._object(base, state, self._operator(node) == "->")}
        if node.type in INDICES:
            base = field(node, "object", "argument", "operand", "value")
            index = field(node, "index", "subscript")
            text = self.source.text(index) if index else "*"
            text = text if text.isdecimal() else "*"
            base_node = self._unwrap(base)
            array = base_node is not None and base_node.type in IDENTIFIER_TYPES and self._root(base_node) in self.arrays
            indirect = not array and base_node is not None and base_node.type in IDENTIFIER_TYPES and self._root(base_node) in self.pointers and not self.dynamic
            if not array and not self.dynamic and base_node is not None:
                indirect |= any(cell in state for cell in self.locations(base_node, state))
            roots = self._object(base, state, indirect)
            return {self._index(cell, text) if indirect else cell.child(f"[{text}]") for cell in roots}
        return set()

    def _alias_transfer(self, identifier, before):
        state = dict(before)
        for write in self.specs.get(identifier, []):
            target = self._declaration_target(write.target) if write.declaration else write.target
            targets = self.locations(target, before)
            points = self.points(write.value, before)
            for cell in targets:
                if cell not in self.pointers and cell not in state and not points:
                    continue
                updated = points or self._default(cell)
                if len(targets) != 1 or cell.uncertain:
                    updated = set(before.get(cell, self._default(cell))) | set(updated)
                state[cell] = self._bounded(updated, cell)
        # An unknown callee given &p can change the pointer itself, so old precise
        # aliases must not remain the sole target after that call.
        for call in self.calls.get(identifier, []):
            arguments = field(call, "arguments")
            affected = set(self.escaped)
            for argument in arguments.named_children if arguments else ():
                affected |= self._buffer(argument, before)
            for cell in self.pointers | set(state):
                if any(self.overlaps(target, cell) for target in affected):
                    state[cell] = self._bounded(set(state.get(cell, self._default(cell))) | set(self._default(cell)), cell)
        return state

    def _aliases(self):
        graph = self.cfg.graph
        incoming, outgoing = {node: {} for node in graph}, {node: {} for node in graph}
        reachable = nx.descendants(graph, self.cfg.entry) | {self.cfg.entry}
        pending, queued, processed = deque([self.cfg.entry]), {self.cfg.entry}, set()
        transfers = 0
        while pending:
            identifier = pending.popleft()
            queued.remove(identifier)
            transfers += 1
            if transfers > self.MAX_ALIAS_TRANSFERS:
                self.limitations.append("Alias fixed-point budget exceeded; all pointer targets are conservative unknowns.")
                self.truncated = True
                unknown = {cell: self._default(cell) for cell in self.pointers | set().union(*(set(s) for s in outgoing.values()))}
                return ({node: dict(unknown) for node in graph}, {node: dict(unknown) for node in graph})
            predecessors = [outgoing[parent] for parent in graph.predecessors(identifier) if parent in processed]
            keys = set().union(*(set(state) for state in predecessors))
            before = {cell: self._bounded(set().union(*(state.get(cell, self._default(cell)) for state in predecessors)), cell) for cell in keys}
            after = self._alias_transfer(identifier, before)
            changed = identifier not in processed or before != incoming[identifier] or after != outgoing[identifier]
            incoming[identifier], outgoing[identifier] = before, after
            processed.add(identifier)
            if changed:
                for successor in graph.successors(identifier):
                    if successor in reachable and successor not in queued:
                        pending.append(successor)
                        queued.add(successor)
        return incoming, outgoing

    def _address_reads(self, node, state):
        node = self._unwrap(node)
        if node is None or node.type in IDENTIFIER_TYPES:
            return set()
        if node.type in FIELDS:
            base = field(node, "object", "argument", "operand", "value")
            if not self.dynamic and self._operator(node) != "->":
                return self._address_reads(base, state)
            return self.reads(base, state)
        if node.type in INDICES:
            base = self._unwrap(field(node, "object", "argument", "operand", "value"))
            base_reads = set() if base is not None and base.type in IDENTIFIER_TYPES and self._root(base) in self.arrays else self.reads(base, state)
            return base_reads | self.reads(field(node, "index", "subscript"), state)
        if node.type in {"pointer_expression", "unary_expression"}:
            return self.reads(field(node, "argument", "operand"), state)
        return set()

    def reads(self, node, state):
        node = self._unwrap(node)
        if node is None or node.type in FUNCTION_TYPES:
            return set()
        if node.type in IDENTIFIER_TYPES:
            cell = self._root(node)
            return {cell.child("[*]") if cell in self.arrays else cell}
        if node.type in FIELDS | INDICES:
            return self.locations(node, state) | self._address_reads(node, state)
        if node.type in {"pointer_expression", "unary_expression"}:
            if self._operator(node) == "&":
                return self._address_reads(field(node, "argument", "operand"), state)
            if self._operator(node) == "*":
                return self.locations(node, state) | self._address_reads(node, state)
        if node.type in ASSIGNMENTS:
            target = field(node, "left", "name")
            result = self.reads(field(node, "right", "value"), state) | self._address_reads(target, state)
            if "augmented" in node.type or self._operator(node) not in {"", "=", ":="}:
                result |= self.locations(target, state)
            return result
        if node.type in DECLARATORS:
            return self.reads(field(node, "value"), state)
        if node.type == "declaration":
            return set().union(*(self.reads(child, state) for child in node.named_children if child.type in DECLARATORS))
        if node.type in CALL_TYPES:
            arguments = field(node, "arguments")
            return set().union(*(self.reads(argument, state) for argument in arguments.named_children)) if arguments else set()
        if node.type in {"field_identifier", "property_identifier", "type_identifier"}:
            return set()
        return set().union(*(self.reads(child, state) for child in node.named_children))

    def _buffer(self, node, state, assume_pointer=False):
        node = self._unwrap(node)
        if node is None:
            return set()
        if node.type in IDENTIFIER_TYPES and self._root(node) in self.arrays:
            return {self._root(node).child("[*]")}
        points = self.points(node, state)
        if not points and assume_pointer:
            points = {self._unknown(cell) for cell in self.locations(node, state)} or {self._unknown_expression(node)}
        return {Cell(cell.root, cell.path[:-1] + ("[*]",)) if cell.path and cell.path[-1].startswith("[") else cell for cell in points}

    def _call_effects(self, call, state):
        callee, arguments = field(call, "function", "constructor"), field(call, "arguments")
        name = self.source.text(callee) if callee is not None else "<dynamic>"
        arguments = list(arguments.named_children) if arguments else []
        # Name-based external models are intentionally restricted to C/C++ and
        # disabled for same-file definitions that shadow a standard API name.
        external = (
            self.source.language in {"c", "cpp"}
            and callee is not None and callee.type == "identifier"
            and name not in self.shadowed_apis
            and self.program.symbols[self.program.resolve(name, callee, self.cfg.function)].scope == -2
        )
        summary = None
        if external:
            if name in {"read", "recv", "recvfrom"} and len(arguments) >= 3:
                summary = (1, None, "external_input")
            elif name in {"fread", "fgets", "gets"} and arguments:
                summary = (0, None, "external_input")
            elif name in {"memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat"} and len(arguments) >= 2:
                summary = (0, 1, "copy")
            elif name == "memset" and len(arguments) >= 3:
                summary = (0, 1, "fill")
        reads = set().union(*(self.reads(argument, state) for argument in arguments))
        writes, notes = set(), []
        if summary:
            destination, source, kind = summary
            if name not in {"strcat", "strncat"}:
                reads = set()
                for index, argument in enumerate(arguments):
                    argument = self._unwrap(argument)
                    if index == destination and argument.type in IDENTIFIER_TYPES and self._root(argument) in self.arrays:
                        continue
                    reads |= self.reads(argument, state)
            writes = self._buffer(arguments[destination], state, assume_pointer=True)
            if source is not None:
                if kind == "copy":
                    reads |= self._buffer(arguments[source], state, assume_pointer=True)
            notes.append(f"Syntactic external API summary for {name}; write extent, return success and runtime callee binding are not proven.")
            if kind == "external_input":
                notes.append(f"External input may be written by {name}; its value and successful write length are unknown.")
        else:
            kind = "possible_call_write"
            writes |= self.escaped
            if callee is not None and callee.type in FIELDS:
                receiver = field(callee, "object", "argument", "operand", "value")
                writes |= {cell.child(".*") for cell in self._object(receiver, state, self._operator(callee) == "->")}
                reads |= self.reads(receiver, state)
            for argument in arguments:
                if self.dynamic:
                    writes |= {cell.child(".*") for cell in self.points(argument, state)}
                else:
                    writes |= self._buffer(argument, state)
            if writes:
                notes.append(f"Unknown callee {name} may read/write reachable argument memory; its implementation/side effects are not resolved.")
                reads |= writes
        return writes, reads, notes, kind, name

    def _effects(self, identifier, statement):
        effect = Effects()
        if identifier == self.cfg.entry:
            for symbol in statement.definitions:
                cell = Cell(symbol)
                effect.writes[cell] = set()
                effect.strong.add(cell)
                effect.kinds[cell] = "parameter"
            return effect
        state = self.alias_in[identifier]
        effect.reads = self.reads(statement.node, state)
        writes = self.specs.get(identifier, [])
        if statement.kind == "iteration_binding":
            effect.reads = {Cell(symbol) for symbol in statement.uses}
        for write in writes:
            target = self._declaration_target(write.target) if write.declaration else write.target
            targets = self.locations(target, state)
            dependencies = self.reads(write.value, state) | self._address_reads(target, state)
            if write.read_old:
                dependencies |= targets
            for cell in targets:
                effect.writes.setdefault(cell, set()).update(dependencies)
                effect.kinds[cell] = "memory_write" if cell.path or target.type not in IDENTIFIER_TYPES else "definition"
                if len(targets) == 1 and not cell.uncertain and len(writes) == 1:
                    effect.strong.add(cell)
                if cell.uncertain or len(targets) != 1:
                    effect.notes.setdefault(cell, []).append("Write target has an unknown alias/index; earlier definitions remain possible.")
                if write.value is None and not write.read_old:
                    effect.notes.setdefault(cell, []).append("Declaration has no analyzed initializer; value is unknown.")
                if write.declaration and cell in self.arrays and write.value is not None:
                    value = self._unwrap(write.value)
                    if value.type == "initializer_list" and not any(
                        child.type in {"initializer_pair", "initializer_list"} for child in value.named_children
                    ):
                        # C/C++ zero-fill unspecified elements. Bounds are not
                        # inferred, and explicit elements retain separate inputs.
                        aggregate = cell.child("[*]")
                        effect.writes.setdefault(aggregate, set())
                        effect.kinds[aggregate] = "array_initializer"
                        for index, item in enumerate(value.named_children):
                            element = cell.child(f"[{index}]")
                            effect.writes[element] = self.reads(item, state)
                            effect.kinds[element] = "array_initializer"
                            effect.strong.add(element)
                    else:
                        aggregate = cell.child("[*]")
                        effect.writes[aggregate] = set(dependencies)
                        effect.kinds[aggregate] = "array_initializer"
                        effect.notes.setdefault(aggregate, []).append("Array initializer shape/extent is approximated; element bounds are not proven.")
            if not targets:
                effect.limitations.append("An assignment target is unsupported; its memory effects are unknown.")
        # Keep declarations/iteration bindings represented by the CFG but not by
        # an assignment expression (e.g. `int x;` and Python/Go iterator targets).
        represented = {cell.root for cell in effect.writes if not cell.path}
        for symbol in statement.definitions - represented:
            cell = Cell(symbol)
            effect.writes[cell] = set(effect.reads)
            effect.strong.add(cell)
            effect.kinds[cell] = "definition"
            if not writes and statement.kind != "iteration_binding":
                effect.notes[cell] = ["Declaration has no analyzed initializer; value is unknown."]
        for call in self.calls.get(identifier, []):
            targets, dependencies, notes, kind, name = self._call_effects(call, state)
            effect.reads |= dependencies
            for cell in targets:
                effect.writes.setdefault(cell, set()).update(dependencies)
                effect.strong.discard(cell)
                effect.notes.setdefault(cell, []).extend(notes)
                effect.kinds[cell] = kind
            # A call return assigned to a variable is an unresolved value source,
            # even if no pointer/output argument is present.
            if any(write.value is not None and write.value.start_byte <= call.start_byte and call.end_byte <= write.value.end_byte for write in writes):
                for cell in effect.writes:
                    effect.notes.setdefault(cell, []).append(f"Return value of {name} is not evaluated; dependencies are possible inputs only.")
                    effect.writes[cell] |= dependencies
        if any(cell.uncertain for cell in effect.reads):
            effect.limitations.append("Some memory reads use unknown aliases or indices; results are may-dependencies.")
        if len(writes) > 1:
            effect.limitations.append("Multiple writes in one CFG statement use conservative input dependencies; expression evaluation order is not proven.")
        return effect

    def display(self, cell):
        symbol = self.program.symbols.get(cell.root)
        name = symbol.name if symbol else self.labels.get(cell.root, cell.root)
        return name + "".join(cell.path)

    def query(self, expression, statement):
        if not isinstance(expression, str) or not re.fullmatch(ACCESS_PATTERN, expression):
            raise ValueError("Expected a variable, field/index access, or one pointer dereference")
        dereference = expression.startswith("*")
        if dereference:
            expression = expression[1:]
        root = re.match(r"[A-Za-z_][A-Za-z0-9_]*", expression)[0]
        cell = Cell(self.program.resolve(root, statement.node, self.cfg.function))
        state = self.alias_in[statement.id]
        cells = {cell}
        tokens = re.findall(r"->|\.|\[[^]]+\]|[A-Za-z_][A-Za-z0-9_]*", expression[len(root):])
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token in {".", "->"}:
                member = tokens[index + 1]
                if token == "->" or self.dynamic or (self.source.language == "go" and cell in self.pointers):
                    cells = set().union(*(state.get(value, self._default(value)) for value in cells))
                cells = {self._field(value, member) for value in cells}
                index += 2
            else:
                number = token[1:-1]
                number = number if number.isdecimal() else "*"
                if index == 0 and cell in self.pointers and cell not in self.arrays and not self.dynamic:
                    cells = {self._index(value, number) for value in state.get(cell, self._default(cell))}
                elif not self.dynamic and any(value in state for value in cells):
                    cells = {self._index(point, number) for value in cells for point in state.get(value, self._default(value))}
                else:
                    if self.dynamic and not cells.difference({cell}):
                        cells = set(state.get(cell, self._default(cell)))
                    cells = {value.child(f"[{number}]") for value in cells}
                index += 1
        if dereference:
            cells = set().union(*(state.get(value, self._default(value)) for value in cells))
        elif not tokens and cell in self.arrays:
            cells = {cell.child("[*]")}
        return cells

    def overlaps(self, left, right):
        if left.root != right.root:
            if not (left.root.startswith("?") or right.root.startswith("?")):
                return False
            concrete = right if left.root.startswith("?") else left
            if not concrete.root.startswith("?") and not concrete.path and concrete not in self.addressed:
                return False
        for a, b in zip(left.path, right.path):
            if a != b and a not in {"[*]", ".*"} and b not in {"[*]", ".*"}:
                return False
        if len(left.path) == len(right.path):
            return True
        shorter = left.path if len(left.path) < len(right.path) else right.path
        # A whole-object unknown call can affect every contained field.
        return bool(shorter and shorter[-1] == ".*") or (
            left.root != right.root and not shorter
            and (left.root.startswith("?") or right.root.startswith("?"))
        )

    def expand(self, cells, universe):
        return {candidate for cell in cells for candidate in universe if self.overlaps(cell, candidate)}
