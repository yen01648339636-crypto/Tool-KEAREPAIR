"""Local deterministic fixtures for the structured offline pipeline."""

import json
from pathlib import Path

import numpy as np


def source_sample(identifier="one", code="copy(input);\n", **updates):
    return {"sample_id": identifier, "cve_id": "CVE-2024-1234", "cve_description": "An unchecked input length reaches a destination buffer.", "project": "example", "language": "c", "buggy_code": code, "fixed_code": "check(length);\n" + code, **updates}


def knowledge(view="data_flow", abstracted=False):
    result = {"root_cause": "unchecked input length reaches a buffer" if abstracted else "unsafe n in project_copy", "risky_calls": ["memcpy: input length controls the write"], "fixing_strategy": "validate the length before copying"}
    result["taint_flow" if view == "data_flow" else "control_branch"] = "input length -> unchecked copy" if view == "data_flow" else "missing guard before the copy"
    return result


class KnowledgeLLM:
    provider, model_name, temperature, max_tokens, base_url = "mock", "local", 0.0, 16384, None

    def __init__(self):
        self.calls = []
        self.fail_control = False

    def generate(self, prompt, **kwargs):
        self.calls.append((prompt, kwargs))
        view = "control_flow" if '"view_type": "control_flow"' in prompt or "The view is control_flow" in prompt else "data_flow"
        if self.fail_control and view == "control_flow":
            raise RuntimeError("local control-flow failure")
        return json.dumps(knowledge(view, "[Extracted Knowledge]" in prompt))


class LocalEmbedding:
    model_name, dimension = "local-embedding", 384

    def __init__(self):
        self.texts = []

    def encode(self, texts, **kwargs):
        if isinstance(texts, str):
            texts = [texts]
        self.texts.extend(texts)
        return np.ones((len(texts), self.dimension), dtype=np.float32)


class LocalStore:
    dimension, metric, index_type, nlist = 384, "L2", "Flat", 1

    def __init__(self):
        self.metadata = {}

    @property
    def items(self):
        return [item for records in self.metadata.values() for item in records]

    def create_index(self, view):
        self.metadata[view] = []

    def add_vectors(self, view, embeddings, metadata):
        self.metadata.setdefault(view, []).extend(metadata)

    def save(self, path):
        for view in self.metadata:
            (Path(path) / f"index_{view}.faiss").write_bytes(b"local-test-index")
        (Path(path) / "metadata.pkl").write_text(json.dumps(self.metadata))

    def load(self, path):
        self.metadata = json.loads((Path(path) / "metadata.pkl").read_text())
