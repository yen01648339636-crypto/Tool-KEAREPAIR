"""Intraprocedural may-data-flow over scalar values and abstract memory cells."""

from collections import deque

from .memory import MemoryModel


class DataFlowAnalyzer:
    MAX_TRANSFERS = 30000
    MAX_TRACE_EDGES = 2048
    MAX_MEMORY_CELLS = 2048

    def __init__(self, control_flow):
        self.control_flow = control_flow
        self._models = {}

    @staticmethod
    def _reads(model, cells, universe):
        return set().union(*(model.expand({cell}, universe) if cell.uncertain else {cell} for cell in cells))

    def _reaching(self, model, universe):
        cfg = model.cfg
        generated, strong, dependencies, notes, kinds = {}, {}, {}, {}, {}
        for identifier, effect in model.effects.items():
            generated[identifier], strong[identifier] = set(), set()
            for cell, inputs in effect.writes.items():
                for location in model.expand({cell}, universe):
                    generated[identifier].add((location, identifier))
                    dependencies.setdefault((location, identifier), set()).update(self._reads(model, inputs, universe))
                    notes.setdefault((location, identifier), set()).update(effect.notes.get(cell, []))
                    kinds[location, identifier] = effect.kinds.get(cell, "definition")
                    if cell in effect.strong and location == cell:
                        strong[identifier].add(location)
        parameters = {cell.root for cell in model.effects[cfg.entry].writes}
        for cell in universe:
            if cell.root.lstrip("?") in parameters and (cell.path or cell.root.startswith("?")):
                generated[cfg.entry].add((cell, cfg.entry))
                kinds[cell, cfg.entry] = "parameter_memory"
                notes[cell, cfg.entry] = {"Incoming argument memory has unknown initial contents and possible aliases."}
        incoming, outgoing = {node: set() for node in cfg.graph}, {node: set() for node in cfg.graph}
        pending, queued, processed = deque([cfg.entry]), {cfg.entry}, set()
        transfers = 0
        while pending:
            identifier = pending.popleft()
            queued.remove(identifier)
            transfers += 1
            if transfers > self.MAX_TRANSFERS:
                return None
            before = set().union(*(outgoing[parent] for parent in cfg.graph.predecessors(identifier)))
            after = {(cell, origin) for cell, origin in before if cell not in strong.get(identifier, set())} | generated.get(identifier, set())
            changed = identifier not in processed or incoming[identifier] != before or outgoing[identifier] != after
            incoming[identifier], outgoing[identifier] = before, after
            processed.add(identifier)
            if changed:
                for successor in cfg.graph.successors(identifier):
                    if successor not in queued:
                        pending.append(successor)
                        queued.add(successor)
        return incoming, outgoing, dependencies, notes, kinds

    def trace(self, variable, position):
        cfg, statement = self.control_flow.locate(position)
        if cfg.function.id not in self._models:
            self._models[cfg.function.id] = MemoryModel(self.control_flow, cfg)
        model = self._models[cfg.function.id]
        queried = model.query(variable, statement)
        universe = model.cells | queried
        reads = self._reads(model, model.effects[statement.id].reads, universe)
        writes = model.expand(set(model.effects[statement.id].writes), universe)
        selected = self._reads(model, queried, universe)
        base = dict(status="unknown", definitions=[], propagation=[], unresolved=[],
                    query=variable, queried_locations=sorted(model.display(cell) for cell in queried),
                    analysis="intraprocedural_may_data_flow", taint_proven=False,
                    truncated=model.truncated, limitations=sorted(set(cfg.limitations + model.limitations)))
        if not (selected & (reads | writes)):
            base["unresolved"] = [f"{variable} is not a modeled read or write at the selected statement"]
            return base
        if len(universe) > self.MAX_MEMORY_CELLS:
            base["truncated"] = True
            base["limitations"].append("Abstract memory-cell budget exceeded; no complete data-flow result is available.")
            return base
        reaching = self._reaching(model, universe)
        if reaching is None:
            base["truncated"] = True
            base["limitations"].append("Data-flow fixed-point budget exceeded; no complete dependency result is available.")
            return base
        incoming, outgoing, dependencies, notes, kinds = reaching
        # Reads observe the incoming value, including read-modify-write operations.
        # A write-only query observes its outgoing possible definitions.
        seeds = incoming[statement.id] if selected & reads else outgoing[statement.id]
        definitions, propagation, unresolved, visited = [], [], set(), set()
        limitations = set(base["limitations"])
        program, source = model.program, model.source
        pending = [(cell, origin, statement.id) for cell, origin in sorted(seeds) if cell in selected]
        for cell in selected:
            if not any(candidate == cell for candidate, _ in seeds):
                unresolved.add("No local reaching definition for " + model.display(cell) + " at the selected statement")
        while pending:
            cell, origin, consumer = pending.pop()
            key = cell, origin, consumer
            if key in visited:
                continue
            if len(visited) >= self.MAX_TRACE_EDGES:
                base["truncated"] = True
                limitations.add("Backward data-flow trace budget exceeded; some dependency paths are omitted.")
                break
            visited.add(key)
            producer = cfg.statements[origin]
            location, node = source.location(producer.node), producer.node
            if origin == cfg.entry:
                root = cell.root.lstrip("?")
                node = next((parameter for parameter in cfg.function.parameters
                             if program.resolve(source.text(parameter), parameter, cfg.function) == root), cfg.function.node)
                location = source.location(node)
            kind = kinds.get((cell, origin), "definition")
            certainty = "may" if cell not in model.effects[origin].strong or cell.uncertain else "structural"
            if not any(item["symbol_id"] == repr(cell) and item["statement_id"] == origin for item in definitions):
                definitions.append(dict(
                    variable=model.display(cell), symbol_id=repr(cell), statement_id=origin,
                    kind=kind, certainty=certainty, location=location, code=source.text(node),
                ))
            propagation.append(dict(variable=model.display(cell), **{"from": origin, "to": consumer},
                                    certainty=certainty, kind=kind, location=location,
                                    target_location=source.location(cfg.statements[consumer].node),
                                    target_code=source.text(cfg.statements[consumer].node)))
            unresolved.update(notes.get((cell, origin), set()))
            limitations.update(model.effects[origin].limitations)
            if cell.uncertain:
                unresolved.add("Possible aliases or unknown indices for " + model.display(cell))
            for dependency in sorted(dependencies.get((cell, origin), set())):
                origins = [previous for candidate, previous in incoming[origin] if candidate == dependency]
                if not origins:
                    unresolved.add(f"No local reaching definition for {model.display(dependency)} at line {location['start_line']}")
                pending.extend((dependency, previous, origin) for previous in sorted(origins))
        base.update(
            status="definitions_found" if definitions else "unknown",
            definitions=sorted(definitions, key=lambda item: (item["location"]["start_line"], item["variable"], item["statement_id"])),
            propagation=sorted(propagation, key=lambda item: (item["from"], item["to"], item["variable"])),
            unresolved=sorted(unresolved), limitations=sorted(limitations | set(model.effects[statement.id].limitations)),
        )
        return base
