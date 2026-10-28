"""Build structured knowledge indices with validated, resumable batch artifacts."""

import hashlib
import json
from pathlib import Path
import pickle

import numpy as np
from loguru import logger

from utils.artifacts import atomic_binary_writer
from utils.experiment_manifest import (
    ManifestMismatchError,
    bind_manifest,
    create_manifest,
    hash_object,
    index_parameters,
    sanitize_config,
    validate_manifest,
    verify_checkpoint,
    write_json_atomic,
)
from utils.knowledge import DatasetError, prepare_dataset
from utils.llm_errors import LLMConnectionError, LLMRetryExhaustedError
from utils.schemas import KnowledgeRecord, SCHEMA_VERSION
from utils.telemetry import request_context


class IndexBuilder:
    def __init__(
        self,
        multiview_generator,
        distillation,
        vector_store,
        embedding_model,
        experiment_config=None,
        experiment_manifest=None,
        dataset_report=None,
        progress_callback=None,
    ):
        self.multiview_gen, self.distillation = multiview_generator, distillation
        self.vector_store, self.embedding_model = vector_store, embedding_model
        self.experiment_config, self.experiment_manifest = (
            experiment_config,
            experiment_manifest,
        )
        self._provided_manifest, self._provided_report = (
            experiment_manifest,
            dataset_report,
        )
        self.experiment_id = None
        self._base_index_id = None
        self.progress_callback = progress_callback or (lambda stage, view: None)

    def _prepare(self, dataset, save_dir):
        maximum = (
            (self.experiment_config or {})
            .get("offline", {})
            .get("dataset", {})
            .get("max_code_length")
        )
        try:
            samples, report = prepare_dataset(dataset, max_code_length=maximum)
        except DatasetError as exc:
            if exc.report is not None:
                target = Path(save_dir).with_name(
                    Path(save_dir).name + ".dataset_report.json"
                )
                write_json_atomic(target, exc.report)
            raise
        self.dataset_report = self._provided_report or report
        if [entry["sample_id"] for entry in self.dataset_report["accepted"]] != [
            sample["sample_id"] for sample in samples
        ]:
            raise DatasetError("Dataset report does not describe the accepted samples")
        return samples

    def _bind_experiment(
        self, dataset, save_dir, batch_size, build_mode, add_view_prefix=True
    ):
        if type(batch_size) is not int or batch_size < 1:
            raise ValueError("batch_size must be positive")
        mode = (
            (self.experiment_config or {})
            .get("experiment", {})
            .get("mode", self.multiview_gen.mode)
        )
        if mode == "standard":
            if (
                set(self.multiview_gen.VIEW_TYPES) - {"data_flow", "control_flow"}
                or self.vector_store.dimension != 384
            ):
                raise ValueError(
                    "standard mode requires data/control views and 384-dimensional vectors"
                )
            if build_mode != "patch_guided":
                raise ValueError("Patch-oracle construction requires extended mode")
        parameters = index_parameters(
            dataset,
            batch_size,
            self.multiview_gen.VIEW_TYPES,
            build_mode,
            add_view_prefix,
            dataset_report=self.dataset_report,
        )
        if self._base_index_id:
            parameters["base_index_id"] = self._base_index_id
        if self._provided_manifest is None:
            llm = self.multiview_gen.llm
            config = self.experiment_config or {
                "experiment": {"mode": mode},
                "models": {
                    "llm": {
                        key: getattr(llm, key, None)
                        for key in (
                            "provider",
                            "model_name",
                            "revision",
                            "base_url",
                            "temperature",
                            "max_tokens",
                        )
                    },
                    "embeddings": {
                        key: getattr(self.embedding_model, key, None)
                        for key in ("model_name", "revision", "device", "dimension")
                    },
                    "abstraction": {
                        key: getattr(self.distillation.llm, key, None)
                        for key in (
                            "provider",
                            "model_name",
                            "revision",
                            "temperature",
                            "max_tokens",
                        )
                    },
                },
                "vector_store": {
                    key: getattr(self.vector_store, key, None)
                    for key in ("dimension", "metric", "index_type", "nlist")
                },
                "sampling": {
                    "generation": self.multiview_gen.sampling,
                    "distillation": self.distillation.sampling,
                },
                "runtime_prompts": {
                    "blind": self.multiview_gen.prompts,
                    "patch_guided": self.multiview_gen._get_patch_guided_prompts(),
                    "distillation": self.distillation._prompts,
                },
            }
            manifest = create_manifest(
                "offline",
                config,
                parameters=parameters,
                data_paths=getattr(self, "_base_index_inputs", ()),
            )
        else:
            manifest = self._provided_manifest
            if manifest["parameters"] != parameters:
                raise ManifestMismatchError(
                    "Offline build arguments do not match the supplied manifest"
                )
            if (
                self.experiment_config is not None
                and sanitize_config(self.experiment_config) != manifest["config"]
            ):
                raise ManifestMismatchError(
                    "Offline configuration does not match the supplied manifest"
                )
        self.experiment_manifest = bind_manifest(save_dir, manifest)
        self.experiment_id = self.experiment_manifest["experiment_id"]

    def _cache_dir(self, save_dir, view_type):
        return Path(save_dir) / "cache" / view_type

    def _batch_cache_paths(self, cache_dir, batch_idx):
        return (
            Path(cache_dir) / f"batch_{batch_idx:05d}.npz",
            Path(cache_dir) / f"batch_{batch_idx:05d}.pkl",
        )

    def _generate_embeddings(self, texts):
        values = np.asarray(
            self.embedding_model.encode(texts, show_progress_bar=False),
            dtype=np.float32,
        )
        if (
            values.shape != (len(texts), self.vector_store.dimension)
            or not np.isfinite(values).all()
            or np.any(np.linalg.norm(values, axis=1) == 0)
        ):
            raise ValueError(
                "Embedding output has invalid dimensions, nonfinite values, or zero vectors"
            )
        return values

    def _save_batch_cache(self, cache_dir, batch_idx, embeddings, metadata):
        if not self.experiment_id:
            raise ManifestMismatchError(
                "Bind an experiment before writing batch artifacts"
            )
        embeddings = np.asarray(embeddings, dtype=np.float32)
        emb_path, meta_path = self._batch_cache_paths(cache_dir, batch_idx)
        payload = {
            "experiment_id": self.experiment_id,
            "schema_version": SCHEMA_VERSION,
            "metadata": metadata,
            "metadata_hash": hash_object(metadata),
            "embeddings_hash": hashlib.sha256(embeddings.tobytes()).hexdigest(),
        }
        with atomic_binary_writer(emb_path) as stream:
            np.savez_compressed(
                stream,
                embeddings=embeddings,
                experiment_id=np.array(self.experiment_id),
            )
        with atomic_binary_writer(meta_path) as stream:
            pickle.dump(payload, stream, protocol=pickle.HIGHEST_PROTOCOL)

    def _load_batch_cache(self, cache_dir, batch_idx):
        emb_path, meta_path = self._batch_cache_paths(cache_dir, batch_idx)
        with np.load(emb_path, allow_pickle=False) as payload:
            if (
                "experiment_id" not in payload
                or str(payload["experiment_id"].item()) != self.experiment_id
            ):
                raise ManifestMismatchError(
                    f"Embedding cache identity mismatch: {emb_path}"
                )
            embeddings = payload["embeddings"]
        with meta_path.open("rb") as stream:
            payload = pickle.load(stream)
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != SCHEMA_VERSION
        ):
            raise ManifestMismatchError(f"Unversioned metadata cache: {meta_path}")
        verify_checkpoint(payload, self.experiment_id)
        metadata = payload.get("metadata")
        if (
            payload.get("metadata_hash") != hash_object(metadata)
            or payload.get("embeddings_hash")
            != hashlib.sha256(embeddings.tobytes()).hexdigest()
        ):
            raise ManifestMismatchError(
                "Batch artifacts are corrupted or do not form a matching pair"
            )
        if (
            embeddings.shape != (len(metadata), self.vector_store.dimension)
            or not np.isfinite(embeddings).all()
            or np.any(np.linalg.norm(embeddings, axis=1) == 0)
        ):
            raise ManifestMismatchError(
                "Cached vectors do not match the metadata or configured dimension"
            )
        return embeddings, metadata

    def _write_report(self, save_dir):
        write_json_atomic(Path(save_dir) / "build_report.json", self.build_report)

    def _failure(self, save_dir, samples, view, stage, exc, *, fatal=True):
        failures = [
            {
                "experiment_id": self.experiment_id,
                "sample_id": sample["sample_id"],
                "view_type": view,
                "stage": stage,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
            for sample in samples
        ]
        if fatal:
            self.build_report["status"] = (
                "network_unavailable" if isinstance(exc, LLMConnectionError) else "failed"
            )
        if isinstance(exc, LLMConnectionError):
            for failure in failures:
                failure.update(reason=exc.reason, attempts=exc.attempts,
                               connection_causes=exc.causes)
        self.build_report["failures"].extend(failures)
        self._write_report(save_dir)
        with (Path(save_dir) / "failures.jsonl").open("a", encoding="utf-8") as stream:
            for failure in failures:
                stream.write(json.dumps(failure, ensure_ascii=False) + "\n")

    def _checkpoint(self, path, view, batch_idx, samples, cached_batches, skipped_batches):
        write_json_atomic(path, {
            "experiment_id": self.experiment_id,
            "current_view": view,
            "batch_idx": batch_idx + 1,
            "total_samples": len(samples),
            "cached_batches": cached_batches,
            "skipped_batches": skipped_batches,
        })

    def _skip_batch(self, save_dir, batch, view, batch_idx, exc):
        failure = self.build_report["failures"][-1]
        skipped = {
            "view_type": view,
            "batch_idx": batch_idx,
            "batch_number": batch_idx + 1,
            "sample_ids": [sample["sample_id"] for sample in batch],
            "failed_sample_id": failure["sample_id"],
            "stage": failure["stage"],
            "attempts": exc.attempts,
            "reason": exc.reason,
            "error": str(exc),
        }
        self.build_report["skipped_batches"].append(skipped)
        self._write_report(save_dir)
        logger.warning(
            "{} 第 {} 批请求尝试 {} 次失败，跳过本批 {} 条样本，继续下一批；续跑时将重试本批。{}",
            view, batch_idx + 1, exc.attempts, len(batch), exc,
        )
        return skipped

    def _knowledge_record(self, sample, view, save_dir):
        with request_context(sample_id=sample["sample_id"], view=view):
            try:
                self.progress_callback("extraction", view)
                extracted = self.multiview_gen.extract_knowledge(sample, view)
            except Exception as exc:
                self._failure(save_dir, [sample], view, "extraction", exc,
                              fatal=not isinstance(exc, LLMRetryExhaustedError))
                raise
            try:
                self.progress_callback("distillation", view)
                abstracted = self.distillation.distill_without_patch(extracted, view)
                return KnowledgeRecord(
                    **sample,
                    view_type=view,
                    extracted_knowledge=extracted,
                    abstracted_knowledge=abstracted,
                    extraction_model=self.multiview_gen.llm.model_name,
                    prompt_hash=hash_object(
                        {
                            "extraction": self.multiview_gen._get_patch_guided_prompts()[
                                view
                            ],
                            "abstraction": self.distillation._prompts["without_patch"],
                        }
                    ),
                ).to_dict()
            except Exception as exc:
                self._failure(save_dir, [sample], view, "abstraction", exc,
                              fatal=not isinstance(exc, LLMRetryExhaustedError))
                raise

    def _build(
        self, dataset, save_dir, batch_size, resume, build_mode, add_view_prefix=True
    ):
        save_dir = Path(save_dir)
        samples = self._prepare(dataset, save_dir)
        self._bind_experiment(
            samples, save_dir, batch_size, build_mode, add_view_prefix
        )
        checkpoint_path = save_dir / "checkpoint.json"
        if checkpoint_path.exists():
            verify_checkpoint(
                json.loads(checkpoint_path.read_text(encoding="utf-8")),
                self.experiment_id,
            )
        write_json_atomic(
            save_dir / "dataset_report.json",
            {**self.dataset_report, "experiment_id": self.experiment_id},
        )
        self.build_report = {
            "experiment_id": self.experiment_id,
            "status": "running",
            "sample_count": len(samples),
            "views": {},
            "failures": [],
            "skipped_batches": [],
            "failure_policy": "skip_batch_on_request_or_knowledge_validation_retry_exhaustion",
        }
        self._write_report(save_dir)
        if self._base_index_id:
            # Always restore the immutable base before appending, including on resume.
            self.vector_store.load(self._base_index_dir)
            existing_ids = {
                item["sample_id"]
                for items in self.vector_store.metadata.values()
                for item in items
            }
            if existing_ids & {sample["sample_id"] for sample in samples}:
                error = DatasetError("Incremental samples overlap the base sample IDs")
                self._failure(save_dir, samples, "", "dataset", error)
                raise error
        else:
            self.vector_store.metadata.clear()
            if hasattr(self.vector_store, "indices"):
                self.vector_store.indices.clear()
        for view in self.multiview_gen.VIEW_TYPES:
            all_vectors, all_metadata = [], []
            view_skips = []
            for batch_idx, start in enumerate(range(0, len(samples), batch_size)):
                batch = samples[start : start + batch_size]
                cache_dir = self._cache_dir(save_dir, view)
                paths = self._batch_cache_paths(cache_dir, batch_idx)
                if resume and all(path.exists() for path in paths):
                    try:
                        vectors, metadata = self._load_batch_cache(cache_dir, batch_idx)
                        if [item.get("sample_id") for item in metadata] != [
                            sample["sample_id"] for sample in batch
                        ]:
                            raise ManifestMismatchError(
                                "Cached sample order does not match the dataset"
                            )
                        if build_mode != "patch_oracle":
                            for item in metadata:
                                if item.get("view_type") != view:
                                    raise ManifestMismatchError(
                                        "Cached knowledge has the wrong view"
                                    )
                                KnowledgeRecord.from_dict(item)
                    except Exception as exc:
                        self._failure(save_dir, batch, view, "cache", exc)
                        raise
                else:
                    if build_mode == "patch_oracle":
                        prefix = (
                            {
                                "data_flow": "Data flow fix:\n",
                                "control_flow": "Control flow fix:\n",
                            }[view]
                            if add_view_prefix
                            else ""
                        )
                        metadata = [
                            {
                                **sample,
                                "view_type": view,
                                "ablation": "patch_oracle",
                                "distilled_view": prefix + sample["patch"],
                            }
                            for sample in batch
                        ]
                        keys = [item["distilled_view"] for item in metadata]
                    else:
                        try:
                            metadata = [
                                self._knowledge_record(sample, view, save_dir)
                                for sample in batch
                            ]
                        except LLMConnectionError:
                            self.build_report["blocked_batch"] = {
                                "view_type": view, "batch_idx": batch_idx,
                                "batch_number": batch_idx + 1,
                                "sample_ids": [sample["sample_id"] for sample in batch],
                            }
                            self._write_report(save_dir)
                            raise
                        except LLMRetryExhaustedError as exc:
                            view_skips.append(self._skip_batch(save_dir, batch, view, batch_idx, exc))
                            self._checkpoint(checkpoint_path, view, batch_idx, samples,
                                             len(all_vectors), len(view_skips))
                            continue
                        keys = [
                            item["abstracted_knowledge"]["root_cause"]
                            for item in metadata
                        ]
                    try:
                        self.progress_callback("embedding", view)
                        vectors = self._generate_embeddings(keys)
                    except Exception as exc:
                        self._failure(save_dir, batch, view, "embedding", exc)
                        raise
                    self._save_batch_cache(cache_dir, batch_idx, vectors, metadata)
                all_vectors.append(vectors)
                all_metadata.extend(metadata)
                self._checkpoint(checkpoint_path, view, batch_idx, samples,
                                 len(all_vectors), len(view_skips))
            try:
                if not self._base_index_id:
                    # Reassemble every view, even when the last checkpoint was in a later view.
                    self.vector_store.create_index(view)
                self.vector_store.add_vectors(
                    view, np.vstack(all_vectors) if all_vectors else
                    np.empty((0, self.vector_store.dimension), dtype=np.float32), all_metadata
                )
            except Exception as exc:
                self._failure(save_dir, samples, view, "index", exc)
                raise
            self.build_report["views"][view] = {
                "sample_ids": [item["sample_id"] for item in all_metadata],
                "count": len(all_metadata),
                "expected_count": len(samples),
                "skipped_count": sum(len(batch["sample_ids"]) for batch in view_skips),
                "skipped_sample_ids": [sid for batch in view_skips for sid in batch["sample_ids"]],
            }
            self._write_report(save_dir)
        try:
            self.progress_callback("saving", "")
            self.vector_store.save(save_dir)
        except Exception as exc:
            self._failure(save_dir, samples, "", "persistence", exc)
            raise
        self.build_report["status"] = (
            "complete_with_skips" if self.build_report["skipped_batches"] else "complete"
        )
        self._write_report(save_dir)
        if not self.build_report["skipped_batches"]:
            checkpoint_path.unlink(missing_ok=True)

    def build_from_dataset(self, dataset, save_dir, batch_size=50, resume=True):
        self._build(dataset, save_dir, batch_size, resume, "patch_guided")

    def build_from_dataset_patch_oracle(
        self, dataset, save_dir, batch_size=50, resume=True, add_view_prefix=True
    ):
        self._build(
            dataset, save_dir, batch_size, resume, "patch_oracle", add_view_prefix
        )

    def build_incremental(self, new_samples, load_dir, save_dir=None):
        if save_dir is None or Path(load_dir).resolve() == Path(save_dir).resolve():
            raise ManifestMismatchError("Incremental builds require a new save_dir")
        load_dir = Path(load_dir)
        base = validate_manifest(
            json.loads((load_dir / "manifest.json").read_text(encoding="utf-8"))
        )
        embedding = base["config"].get("models", {}).get("embeddings", {})
        if (
            base["identity"]["stage"] != "offline"
            or base["parameters"].get("index_format_version") != "2.0"
            or base["parameters"].get("build_mode") != "patch_guided"
        ):
            raise ManifestMismatchError(
                "Incremental builds require a compatible structured knowledge base"
            )
        if (
            embedding.get("model_name")
            != getattr(self.embedding_model, "model_name", None)
            or embedding.get("revision") != getattr(self.embedding_model, "revision", None)
            or embedding.get("dimension") != self.vector_store.dimension
            or base["parameters"]["views"] != self.multiview_gen.VIEW_TYPES
        ):
            raise ManifestMismatchError(
                "Incremental embedding settings or views differ from the base index"
            )
        self._base_index_id, self._base_index_dir = base["experiment_id"], load_dir
        self._base_index_inputs = [
            load_dir / "manifest.json",
            load_dir / "metadata.pkl",
            *sorted(load_dir.glob("index_*.faiss")),
        ]
        self.build_from_dataset(new_samples, save_dir)

    def get_index_statistics(self):
        return {
            view: self.vector_store.get_statistics(view)
            for view in self.multiview_gen.VIEW_TYPES
        }
