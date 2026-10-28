"""FAISS indices with paired result filtering and checked metadata persistence."""

from pathlib import Path
import json
import pickle

import numpy as np

from utils.artifacts import atomic_binary_writer
from utils.schemas import SCHEMA_VERSION

try:
    import faiss
except ImportError:
    faiss = None


INDEX_FORMAT_VERSION = "2.0"


class VectorStore:
    def __init__(self, dimension=384, index_type="Flat", metric="L2", nlist=100):
        if faiss is None:
            raise ImportError("FAISS is required; install faiss-cpu")
        if (
            type(dimension) is not int
            or dimension < 1
            or type(nlist) is not int
            or nlist < 1
        ):
            raise ValueError("dimension and nlist must be positive integers")
        if index_type not in {"Flat", "IVFFlat"} or metric not in {"L2", "IP"}:
            raise ValueError("Unsupported index type or distance metric")
        self.dimension, self.index_type, self.metric, self.nlist = (
            dimension,
            index_type,
            metric,
            nlist,
        )
        self.indices, self.metadata = {}, {}

    def _flat(self):
        return (
            faiss.IndexFlatL2(self.dimension)
            if self.metric == "L2"
            else faiss.IndexFlatIP(self.dimension)
        )

    def create_index(self, view_type):
        if view_type not in {"data_flow", "control_flow"}:
            raise ValueError(f"Unknown view: {view_type}")
        index = self._flat()
        if self.index_type == "IVFFlat":
            metric = (
                faiss.METRIC_L2 if self.metric == "L2" else faiss.METRIC_INNER_PRODUCT
            )
            index = faiss.IndexIVFFlat(index, self.dimension, self.nlist, metric)
        self.indices[view_type], self.metadata[view_type] = index, []

    def _check_view(self, view_type):
        if view_type not in self.indices or view_type not in self.metadata:
            raise ValueError(f"Missing index or metadata for {view_type}")
        index, metadata = self.indices[view_type], self.metadata[view_type]
        if index.d != self.dimension or index.ntotal != len(metadata):
            raise ValueError(
                f"Index dimension or vector/metadata count mismatch for {view_type}"
            )
        expected_metric = (
            faiss.METRIC_L2 if self.metric == "L2" else faiss.METRIC_INNER_PRODUCT
        )
        if getattr(index, "metric_type", expected_metric) != expected_metric:
            raise ValueError(f"Index distance metric mismatch for {view_type}")
        if any(not isinstance(item, dict) for item in metadata):
            raise ValueError(f"Invalid metadata for {view_type}")
        identifiers = [item["sample_id"] for item in metadata if "sample_id" in item]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError(f"Duplicate sample_id in {view_type}")

    def _vectors(self, embeddings):
        values = np.array(embeddings, dtype=np.float32, copy=True)
        if (
            values.ndim != 2
            or values.shape[1] != self.dimension
            or not np.isfinite(values).all()
            or np.any(np.linalg.norm(values, axis=1) == 0)
        ):
            raise ValueError(
                "Expected finite, nonzero vectors with the configured dimension"
            )
        return values

    def add_vectors(self, view_type, embeddings, metadata):
        values = self._vectors(embeddings)
        if (
            not isinstance(metadata, list)
            or len(values) != len(metadata)
            or any(not isinstance(item, dict) for item in metadata)
        ):
            raise ValueError("Vector and metadata rows must match")
        if view_type not in self.indices:
            self.create_index(view_type)
        self._check_view(view_type)
        identifiers = [
            item["sample_id"]
            for item in self.metadata[view_type] + metadata
            if "sample_id" in item
        ]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError(f"Duplicate sample_id in {view_type}")
        index = self.indices[view_type]
        if self.metric == "IP":
            faiss.normalize_L2(values)
        if not index.is_trained:
            if len(values) < self.nlist * 39:
                # Exact search avoids training an undersized IVF index.
                index = self.indices[view_type] = self._flat()
            else:
                index.train(values)
        index.add(values)
        self.metadata[view_type].extend(metadata)
        self._check_view(view_type)

    def search(self, view_type, query_embedding, k=10):
        if view_type not in self.indices:
            raise KeyError(
                f"Missing {view_type} index; rebuild the configured knowledge views"
            )
        self._check_view(view_type)
        if type(k) is not int or k < 1:
            raise ValueError("k must be a positive integer")
        query = np.asarray(query_embedding, dtype=np.float32)
        if query.ndim == 1:
            query = query.reshape(1, -1)
        query = self._vectors(query)
        if len(query) != 1:
            raise ValueError("search expects one query vector")
        if self.metric == "IP":
            faiss.normalize_L2(query)
        distances, positions = self.indices[view_type].search(query, k)
        pairs = [
            (float(distance), self.metadata[view_type][int(position)])
            for distance, position in zip(distances[0], positions[0])
            if 0 <= int(position) < len(self.metadata[view_type])
            and np.isfinite(distance)
        ]
        return np.array([distance for distance, _ in pairs], dtype=np.float32), [
            item for _, item in pairs
        ]

    def save(self, save_dir):
        if set(self.indices) != set(self.metadata):
            raise ValueError("Index views and metadata views do not match")
        save_dir = Path(save_dir)
        save_dir.mkdir(parents=True, exist_ok=True)
        for view, index in self.indices.items():
            self._check_view(view)
            # serialize_index keeps temporary filenames outside FAISS's file API.
            with atomic_binary_writer(save_dir / f"index_{view}.faiss") as stream:
                stream.write(faiss.serialize_index(index).tobytes())
        payload = {
            "index_format_version": INDEX_FORMAT_VERSION,
            "schema_version": SCHEMA_VERSION,
            "dimension": self.dimension,
            "metric": self.metric,
            "views": self.metadata,
        }
        with atomic_binary_writer(save_dir / "metadata.pkl") as stream:
            pickle.dump(payload, stream, protocol=pickle.HIGHEST_PROTOCOL)

    def load(self, load_dir, views=None):
        load_dir = Path(load_dir)
        report_path = load_dir / "build_report.json"
        if report_path.exists():
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if not isinstance(report, dict) or report.get("status") not in {
                "complete", "complete_with_skips"
            }:
                raise ValueError(
                    "Knowledge index construction is incomplete; resume the build before loading"
                )
        with (load_dir / "metadata.pkl").open("rb") as stream:
            payload = pickle.load(stream)
        if (
            not isinstance(payload, dict)
            or payload.get("index_format_version") != INDEX_FORMAT_VERSION
            or payload.get("schema_version") != SCHEMA_VERSION
        ):
            raise ValueError(
                "Unsupported index metadata format; rebuild into a new directory"
            )
        if (
            payload.get("dimension") != self.dimension
            or payload.get("metric") != self.metric
        ):
            raise ValueError(
                "Index dimension or distance metric differs from the runtime configuration"
            )
        metadata = payload.get("views")
        if (
            not isinstance(metadata, dict)
            or not metadata
            or set(metadata) - {"data_flow", "control_flow"}
            or any(not isinstance(items, list) for items in metadata.values())
        ):
            raise ValueError("Invalid index metadata views")
        files = {
            path.stem.removeprefix("index_"): path
            for path in load_dir.glob("index_*.faiss")
        }
        if set(files) != set(metadata):
            raise ValueError("Index files and metadata views do not match")
        selected = list(metadata) if views is None else list(views)
        if (
            not selected
            or len(set(selected)) != len(selected)
            or set(selected) - set(metadata)
        ):
            raise ValueError("Requested knowledge views are missing from the index")
        metadata = {view: metadata[view] for view in selected}
        indices = {view: faiss.read_index(str(files[view])) for view in selected}
        old = self.indices, self.metadata
        self.indices, self.metadata = indices, metadata
        try:
            for view in metadata:
                self._check_view(view)
        except Exception:
            self.indices, self.metadata = old
            raise

    def get_available_views(self):
        return sorted(set(self.indices) & set(self.metadata))

    def get_statistics(self, view_type):
        if view_type not in self.indices:
            return {}
        self._check_view(view_type)
        index = self.indices[view_type]
        return {
            "view_type": view_type,
            "total_vectors": index.ntotal,
            "dimension": index.d,
            "index_type": type(index).__name__,
            "is_trained": index.is_trained,
        }
