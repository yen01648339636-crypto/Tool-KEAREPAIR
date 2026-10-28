"""Bounded CFG paths, dominating branch outcomes and control dependencies."""

import networkx as nx

from .treesitter_wrapper import AnalysisError


class ReachabilityChecker:
    MAX_EXPANSIONS = 4096
    MAX_PATH_NODES = 256

    def __init__(self, control_flow):
        self.control_flow = control_flow
        self._relations = {}

    def query(self, source, target, variable=None, max_paths=8):
        if type(max_paths) is not int or not 1 <= max_paths <= 32:
            raise AnalysisError("max_paths must be an integer between 1 and 32")
        cfg, start = self.control_flow.locate(source)
        target_cfg, end = self.control_flow.locate(target)
        if cfg.function.id != target_cfg.function.id:
            raise AnalysisError("Source and target must belong to the same function")
        program = self.control_flow.program
        limitations = list(cfg.limitations)
        search = dict(max_paths=max_paths, max_expansions=self.MAX_EXPANSIONS,
                      max_path_nodes=self.MAX_PATH_NODES, expansions=0,
                      loop_policy="simple_paths", truncated=False, reasons=[])
        result = dict(status="unknown", paths=[], feasibility="unknown",
                      search=search, limitations=limitations)
        reachable = nx.descendants(cfg.graph, cfg.entry) | {cfg.entry}
        if start.id not in reachable or not nx.has_path(cfg.graph, start.id, end.id):
            result["status"] = "unknown" if limitations else "no_cfg_path"
            return result
        relevant = (nx.descendants(cfg.graph, start.id) | {start.id}) & (
            nx.ancestors(cfg.graph, end.id) | {end.id}
        )
        exiting = nx.ancestors(cfg.graph, cfg.exit) | {cfg.exit}
        if relevant - exiting:
            limitations.append("Post-dominator control dependencies are incomplete for regions that cannot reach the modeled function exit.")
        if not nx.is_directed_acyclic_graph(cfg.graph.subgraph(relevant)):
            search["reasons"].append("loop_iterations_omitted")
            limitations.append("Only simple CFG paths are enumerated; repeated loop iterations are omitted.")
        paths, pending = [], [[start.id]]
        while pending:
            if search["expansions"] >= self.MAX_EXPANSIONS:
                search["reasons"].append("expansion_budget")
                break
            path = pending.pop()
            search["expansions"] += 1
            if path[-1] == end.id:
                if len(paths) == max_paths:
                    search["reasons"].append("path_count_budget")
                    break
                paths.append(path)
                continue
            successors = sorted(cfg.graph.successors(path[-1]), reverse=True)
            for successor in successors:
                if successor not in relevant or successor in path:
                    continue
                if len(path) >= self.MAX_PATH_NODES:
                    search["reasons"].append("path_length_budget")
                    continue
                pending.append(path + [successor])
        search["reasons"] = sorted(set(search["reasons"]))
        search["truncated"] = bool(search["reasons"])
        if search["truncated"]:
            limitations.append("Path enumeration is incomplete: " + ", ".join(search["reasons"]) + ".")
        if cfg.function.id not in self._relations:
            self._relations[cfg.function.id] = (
                self.control_flow.dominating_branches(cfg),
                self.control_flow.control_dependencies(cfg),
            )
        dominating, dependencies = self._relations[cfg.function.id]

        def predicate(identifier, attributes):
            statement = cfg.statements[identifier]
            return dict(expression=attributes["predicate"], outcome=attributes["outcome"],
                        location=program.source.location(statement.node),
                        variables=sorted({program.symbols[item].name for item in statement.uses}))

        for path in paths:
            predicates = [
                predicate(before, cfg.graph[before][after])
                for before, after in zip(path, path[1:])
                if cfg.graph[before][after].get("predicate") is not None
            ]
            guards, controls = {}, {}
            for identifier in path:
                if identifier not in cfg.statements:
                    continue
                location = program.source.location(cfg.statements[identifier].node)
                for branch, attributes in dominating[identifier]:
                    item = predicate(branch, attributes)
                    if variable is not None and variable not in item["variables"]:
                        continue
                    key = branch, item["outcome"]
                    guards.setdefault(key, {**item, "required_for": []})["required_for"].append(location)
                for branch in sorted(dependencies[identifier]):
                    statement = cfg.statements[branch]
                    variables = sorted({program.symbols[item].name for item in statement.uses})
                    if variable is not None and variable not in variables:
                        continue
                    controls.setdefault(branch, dict(
                        expression=program.source.text(statement.node),
                        location=program.source.location(statement.node),
                        variables=variables, controls=[],
                    ))["controls"].append(location)
            result["paths"].append(dict(
                statements=[program.source.location(cfg.statements[node].node) for node in path if node in cfg.statements],
                predicates=predicates,
                checks=[item for item in predicates if variable is not None and variable in item["variables"]],
                dominating_conditions=list(guards.values()),
                control_dependencies=list(controls.values()),
            ))
        result["status"] = "path_found" if paths else "unknown"
        result["limitations"] = sorted(set(limitations))
        return result
