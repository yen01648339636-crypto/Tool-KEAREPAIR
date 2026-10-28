"""Routed retrieval from multi-view indices."""

from typing import Dict
import re
from copy import deepcopy
from utils.knowledge import parse_knowledge
from loguru import logger


_LANG_ALIASES: Dict[str, frozenset] = {
    "javascript": frozenset({"javascript", "js", "node", "nodejs", "typescript", "ts"}),
    "python": frozenset({"python", "py", "django"}),
    "go": frozenset({"go", "golang"}),
}


def _canonical_language(value: object) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    for canonical, aliases in _LANG_ALIASES.items():
        if text in aliases or any(alias in text for alias in aliases):
            return canonical
    return text


def _infer_language_from_code(code: str) -> str:
    sample = (code or "")[:8000].lower()
    if re.search(r"^\s*package\s+\w+", sample, re.MULTILINE) and "func " in sample:
        return "go"
    if (
        re.search(r"^\s*(def|class)\s+\w+", sample, re.MULTILINE)
        or re.search(r"^\s*(from|import)\s+[a-zA-Z_][\w.]*", sample, re.MULTILINE)
        or "if __name__ ==" in sample
    ):
        return "python"
    if any(
        token in sample
        for token in ("function ", "const ", "let ", "module.exports", "require(")
    ):
        return "javascript"
    if any(token in sample for token in ("#include", "static ", "struct ", "->", "::")):
        return "c/c++"
    return ""


def _metadata_matches_language(metadata: Dict, target_language: str) -> bool:
    """Return True when retrieved metadata belongs to the requested language."""
    target = _canonical_language(target_language)
    if not target:
        return True

    inferred = _infer_language_from_code(metadata.get("buggy_code") or "")
    if inferred:
        if inferred != target:
            logger.debug(
                "Language filter rejected candidate by code content: "
                f"target={target}, inferred={inferred}, sample_id={metadata.get('sample_id')}, "
                f"metadata_language={metadata.get('programming_language') or metadata.get('language')}"
            )
        return inferred == target

    explicit = _canonical_language(
        metadata.get("programming_language") or metadata.get("language")
    )
    if explicit:
        return explicit == target

    return False


class Retriever:
    """Route root causes to their view, deduplicate, then load full knowledge."""

    def __init__(self, vector_store, embedding_model, top_k_per_view=10):
        if type(top_k_per_view) is not int or top_k_per_view < 1:
            raise ValueError("top_k_per_view must be positive")
        self.vector_store = vector_store
        self.embedding_model = embedding_model
        self.top_k_per_view = top_k_per_view
        self.catalog = {}
        for view, records in vector_store.metadata.items():
            for record in records:
                sample_id = record["sample_id"]
                if not isinstance(sample_id, str) or not sample_id:
                    raise ValueError(
                        "Knowledge metadata requires stable string sample IDs"
                    )
                candidate = self.catalog.setdefault(
                    sample_id, {**deepcopy(record), "views": {}}
                )
                for key in ("buggy_code", "fixed_code", "patch"):
                    if candidate[key] != record[key]:
                        raise ValueError(
                            f"Conflicting {key} across views for {sample_id}"
                        )
                if view in candidate["views"]:
                    raise ValueError(f"Duplicate {view} knowledge for {sample_id}")
                candidate["views"][view] = {
                    name: parse_knowledge(record[name], view).to_dict()
                    for name in ("extracted_knowledge", "abstracted_knowledge")
                }
        # View-specific fields live only under views, avoiding multiple interfaces.
        for candidate in self.catalog.values():
            for key in ("extracted_knowledge", "abstracted_knowledge", "view_type"):
                candidate.pop(key, None)

    def retrieve(self, queries, language_filter=None, *, on_view=None):
        """Retrieve unchanged candidates; optionally observe each completed view.

        The observer receives a deep copy of the pooled candidates, so rendering
        or persistence cannot affect later view hits or the returned ranking input.
        Observer errors propagate explicitly instead of hiding lost telemetry.
        """
        available = set(self.vector_store.get_available_views())
        if not queries:
            raise ValueError("At least one root-cause query is required")
        pooled = {}
        for view, query in queries.items():
            if (
                not isinstance(query, dict)
                or query.get("view") != view
                or not isinstance(query.get("root_cause"), str)
                or not query["root_cause"].strip()
            ):
                raise ValueError(
                    "Retrieval requires structured view/root_cause queries"
                )
            index = view
            if index not in available:
                raise ValueError(f"Missing retrieval index: {index}")
            embedding = self.embedding_model.encode(query["root_cause"])
            search_k = self.top_k_per_view
            if language_filter:
                search_k = min(
                    max(search_k * 20, search_k), len(self.vector_store.metadata[index])
                )
            distances, records = self.vector_store.search(index, embedding, k=search_k)
            if len(distances) != len(records):
                raise ValueError("Retrieval distances and metadata are misaligned")
            hits = [
                (distance, record)
                for distance, record in zip(distances, records)
                if not language_filter
                or _metadata_matches_language(record, language_filter)
            ][: self.top_k_per_view]
            for rank, (distance, record) in enumerate(hits, 1):
                sample_id = record["sample_id"]
                candidate = pooled.setdefault(
                    sample_id,
                    {**deepcopy(self.catalog[sample_id]), "retrieval_hits": []},
                )
                candidate["retrieval_hits"].append(
                    dict(
                        query_view=view,
                        index_view=index,
                        rank=rank,
                        distance=float(distance),
                    )
                )
            if on_view is not None:
                on_view(view, deepcopy([pooled[sample_id] for sample_id in sorted(pooled)]))
        return [pooled[sample_id] for sample_id in sorted(pooled)]
