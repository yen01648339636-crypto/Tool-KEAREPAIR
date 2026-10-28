"""Code cosine and candidate-pool BM25 behavioral ranking."""

from collections import Counter
from copy import deepcopy
import math
import re

import numpy as np

from utils.diagnostics import diagnostic_text
from utils.knowledge import parse_knowledge


BM25_DEFAULTS = dict(
    k1=1.5,
    b=0.75,
    statistics_scope="candidate_pool",
    normalization="min_max",
    equal_scores="zero",
    tokenizer="identifier_words_v1",
)


def behavior_document(candidate):
    """Use all available abstract behavioral fields, never source or fix text."""
    parts = []
    for view, payload in sorted(candidate["views"].items()):
        knowledge = parse_knowledge(payload["abstracted_knowledge"], view).to_dict()
        parts.extend(knowledge["risky_calls"])
        parts.extend(
            knowledge[key]
            for key in ("taint_flow", "control_branch")
            if knowledge.get(key)
        )
    return "\n".join(parts)


def tokenize_behavior(text):
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return re.findall(r"[^\W_]+", text.lower(), flags=re.UNICODE)


def bm25_scores(query, documents, *, k1=1.5, b=0.75):
    tokens = [tokenize_behavior(doc) for doc in documents]
    counts = [Counter(doc) for doc in tokens]
    query_terms = sorted(set(tokenize_behavior(query)))
    size = len(documents)
    average = sum(map(len, tokens)) / size if size else 0.0
    idf = {
        term: math.log1p(
            (size - sum(term in count for count in counts) + 0.5)
            / (sum(term in count for count in counts) + 0.5)
        )
        for term in query_terms
    }
    scores = []
    for doc, count in zip(tokens, counts):
        length_ratio = len(doc) / average if average else 0.0
        scores.append(
            sum(
                idf[term]
                * count[term]
                * (k1 + 1)
                / (count[term] + k1 * (1 - b + b * length_ratio))
                for term in query_terms
                if count[term]
            )
        )
    low, high = (min(scores), max(scores)) if scores else (0.0, 0.0)
    normalized = [
        (score - low) / (high - low) if high > low else 0.0 for score in scores
    ]
    return (
        scores,
        normalized,
        dict(
            document_count=size,
            average_document_length=average,
            document_lengths=list(map(len, tokens)),
            query_terms=query_terms,
            idf=idf,
            raw_min=low,
            raw_max=high,
        ),
    )


class Reranker:
    def __init__(
        self, code_encoder, *, behavior_weight=0.7, code_weight=0.3, bm25=None
    ):
        if any(
            type(v) not in (float, int) or not math.isfinite(v) or not 0 <= v <= 1
            for v in (behavior_weight, code_weight)
        ) or not math.isclose(behavior_weight + code_weight, 1):
            raise ValueError("Ranking weights must be nonnegative and sum to one")
        self.code_encoder = code_encoder
        self.behavior_weight, self.code_weight = behavior_weight, code_weight
        self.bm25 = {**BM25_DEFAULTS, **(bm25 or {})}
        if set(self.bm25) != set(BM25_DEFAULTS) or any(
            self.bm25[key] != BM25_DEFAULTS[key]
            for key in (
                "statistics_scope",
                "normalization",
                "equal_scores",
                "tokenizer",
            )
        ):
            raise ValueError("Unsupported BM25 protocol")
        if (
            type(self.bm25["k1"]) not in (int, float)
            or not math.isfinite(self.bm25["k1"])
            or self.bm25["k1"] <= 0
            or type(self.bm25["b"]) not in (int, float)
            or not math.isfinite(self.bm25["b"])
            or not 0 <= self.bm25["b"] <= 1
        ):
            raise ValueError("BM25 requires k1 > 0 and 0 <= b <= 1")
        self.last_run = {}

    def rerank(self, diagnostic_report, query_code, candidates, top_k=4):
        if type(top_k) is not int or top_k < 1:
            raise ValueError("top_k must be positive")
        ids = [candidate["sample_id"] for candidate in candidates]
        if any(not isinstance(value, str) or not value for value in ids) or len(
            set(ids)
        ) != len(ids):
            raise ValueError("Ranking requires unique stable sample IDs")
        candidates = sorted(deepcopy(candidates), key=lambda item: item["sample_id"])
        query = diagnostic_text(diagnostic_report)
        documents = [behavior_document(candidate) for candidate in candidates]
        raw, normalized, statistics = bm25_scores(
            query, documents, k1=self.bm25["k1"], b=self.bm25["b"]
        )
        protocol = dict(
            bm25=deepcopy(self.bm25),
            code_encoder=deepcopy(self.code_encoder.protocol),
            code_weight=self.code_weight,
            behavior_weight=self.behavior_weight,
            formula="code_weight * code_cosine + behavior_weight * normalized_bm25",
            selection_order="score_desc_id_asc",
            presentation_order="score_asc_id_asc",
        )
        self.last_run = dict(
            protocol=protocol,
            behavioral_query=query,
            bm25_statistics=statistics,
            candidates=[],
            selected_ids=[],
        )
        if not candidates:
            return []
        # One encoder call: only the current and historical vulnerable code.
        codes = [query_code] + [candidate["buggy_code"] for candidate in candidates]
        vectors = np.asarray(self.code_encoder.encode(codes), dtype=np.float64)
        if (
            vectors.ndim != 2
            or vectors.shape[0] != len(codes)
            or not np.isfinite(vectors).all()
            or np.any(np.linalg.norm(vectors, axis=1) == 0)
        ):
            raise ValueError("Invalid code embeddings; ranking cannot continue")
        vectors /= np.linalg.norm(vectors, axis=1, keepdims=True)
        cosine = np.clip(vectors[1:] @ vectors[0], -1.0, 1.0)
        metadata = deepcopy(self.code_encoder.last_encoding_metadata)
        if len(metadata) != len(codes):
            raise ValueError(
                "Code encoder must record selection metadata for every input"
            )
        self.last_run["query_code_encoding"] = metadata[0]
        for index, candidate in enumerate(candidates):
            candidate.update(
                code_cosine=float(cosine[index]),
                bm25_score=raw[index],
                normalized_bm25=normalized[index],
                rerank_score=self.code_weight * float(cosine[index])
                + self.behavior_weight * normalized[index],
                behavior_document=documents[index],
                code_encoding=metadata[index + 1],
            )
        ranked = sorted(
            candidates, key=lambda item: (-item["rerank_score"], item["sample_id"])
        )
        for rank, candidate in enumerate(ranked, 1):
            candidate["selection_rank"] = rank
        self.last_run["candidates"] = deepcopy(ranked)
        selected = sorted(
            ranked[:top_k], key=lambda item: (item["rerank_score"], item["sample_id"])
        )
        self.last_run["selected_ids"] = [
            candidate["sample_id"] for candidate in selected
        ]
        return selected
