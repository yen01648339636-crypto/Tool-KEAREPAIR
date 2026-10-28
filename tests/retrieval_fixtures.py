"""Deterministic structured candidates and code embeddings, without model downloads."""

from copy import deepcopy
import numpy as np

from tests.offline_fixtures import knowledge


def candidate(identifier="a", score=0.5):
    return dict(
        sample_id=identifier,
        buggy_code=f"vulnerable_{identifier}();\n",
        fixed_code=f"checked_{identifier}();\n",
        patch=f"--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n-vulnerable_{identifier}();\n+checked_{identifier}();\n",
        views={
            view: dict(
                extracted_knowledge=knowledge(view),
                abstracted_knowledge=knowledge(view, True),
            )
            for view in ("data_flow", "control_flow")
        },
        rerank_score=score,
    )


class LocalCodeEncoder:
    protocol = {
        "model_name": "local-test",
        "revision": "0" * 40,
        "pooling": "masked_mean",
        "max_length": 2048,
        "truncation_side": "right",
    }

    def __init__(self, vectors=None):
        self.vectors = vectors
        self.calls = []
        self.last_encoding_metadata = []

    def encode(self, codes):
        self.calls.append(deepcopy(codes))
        self.last_encoding_metadata = [
            {"strategy": "full_input", "truncated": False} for _ in codes
        ]
        return np.asarray(
            self.vectors if self.vectors is not None else [[1.0, 0.0]] * len(codes),
            dtype=float,
        )
