"""Validated sentence embeddings without synthetic-vector fallbacks."""

import numpy as np

try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    SentenceTransformer = None


class EmbeddingModel:
    def __init__(self, model_name="all-MiniLM-L6-v2", device="cpu", dimension=384, revision=None):
        self.model_name, self.device = model_name, device
        self.dimension, self.revision = dimension, revision
        if type(dimension) is not int or dimension < 1:
            raise ValueError("Embedding dimension must be positive")
        if SentenceTransformer is None:
            raise ImportError("sentence-transformers is required; synthetic embeddings are disabled")
        options = {"device": device}
        if revision is not None:
            options["revision"] = revision
        self.model = SentenceTransformer(model_name, **options)
        actual = self.model.get_sentence_embedding_dimension()
        if actual != dimension:
            raise ValueError(f"Embedding model dimension {actual} does not match configured dimension {dimension}")

    def encode(self, texts, batch_size=32, show_progress_bar=False, normalize=True):
        if isinstance(texts, str):
            texts = [texts]
        if not isinstance(texts, list) or any(not isinstance(text, str) or not text.strip() for text in texts):
            raise ValueError("Embedding inputs must be a list of nonempty strings")
        if not texts:
            return np.empty((0, self.dimension), dtype=np.float32)
        values = np.asarray(self.model.encode(texts, batch_size=batch_size, show_progress_bar=show_progress_bar, normalize_embeddings=normalize), dtype=np.float32)
        if values.shape != (len(texts), self.dimension) or not np.isfinite(values).all() or np.any(np.linalg.norm(values, axis=1) == 0):
            raise ValueError("Embedding model returned invalid dimensions, nonfinite values, or zero vectors")
        return values

    def encode_queries(self, queries, **kwargs):
        return self.encode(queries, **kwargs)

    def encode_corpus(self, corpus, **kwargs):
        return self.encode(corpus, **kwargs)

    def similarity(self, embeddings1, embeddings2, metric="cosine"):
        first, second = np.asarray(embeddings1), np.asarray(embeddings2)
        if metric == "cosine":
            norms1, norms2 = np.linalg.norm(first, axis=1, keepdims=True), np.linalg.norm(second, axis=1, keepdims=True)
            if np.any(norms1 == 0) or np.any(norms2 == 0):
                raise ValueError("Cosine similarity requires nonzero vectors")
            return (first / norms1) @ (second / norms2).T
        if metric == "dot":
            return first @ second.T
        raise ValueError(f"Unknown metric: {metric}")

    def get_dimension(self):
        return self.dimension

    def save(self, save_path):
        self.model.save(save_path)

    @classmethod
    def load(cls, load_path, device="cpu", dimension=384):
        return cls(model_name=load_path, device=device, dimension=dimension)
