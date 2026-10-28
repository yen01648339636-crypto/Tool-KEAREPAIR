"""Validated manual additions, isolated builds and atomic index publication."""

import base64
import binascii
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
from uuid import uuid4

from config.runtime import load_config, resolve_offline_config
from utils.experiment_manifest import validate_manifest, write_json_atomic
from utils.knowledge import normalize_sample
from .catalog import read_json
from .store import now

MAX_FILE_BYTES = 2 * 1024 * 1024
BUSY = {"queued", "running"}


class BuildConflict(ValueError):
    pass


def uploaded_text(upload):
    filename = upload["filename"]
    if not filename.strip() or re.search(r"[/\\\x00-\x1f\x7f]", filename) or filename in {".", ".."}:
        raise ValueError("Upload a file name without directory paths or control characters")
    try:
        raw = base64.b64decode(upload["content_base64"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("The uploaded file is not valid base64") from exc
    if not raw or len(raw) > MAX_FILE_BYTES:
        raise ValueError("Each source or patch file must be nonempty and at most 2 MiB")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Upload UTF-8 text files") from exc
    if "\x00" in text:
        raise ValueError("Binary files are not supported")
    return text.replace("\r\n", "\n"), {
        "filename": filename, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
    }


def index_fingerprint(directory):
    digest = hashlib.sha256()
    for path in [directory / "manifest.json", directory / "metadata.pkl", *sorted(directory.glob("index_*.faiss"))]:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


class KnowledgeBuilds:
    def __init__(self, root, directory, catalog, redact):
        self.root, self.catalog, self._redactor = Path(root), catalog, redact
        self.secrets = set()
        self.directory = Path(directory) / "knowledge_builds"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.config = self.root / "config/offline.yaml"
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="kea-knowledge")
        self.lock = threading.RLock()
        self.stopping = False
        self.process = None

    def redact(self, value):
        value = self._redactor(value)
        if isinstance(value, dict):
            return {key: self.redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, str):
            for secret in self.secrets:
                value = value.replace(secret, "[redacted]")
        return value

    def _lease(self):
        self.catalog.index_root.mkdir(parents=True, exist_ok=True)
        stream = (self.catalog.index_root / ".extension.lock").open("a")
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            stream.close()
            raise BuildConflict("Another knowledge build is running. Wait for it to finish.") from exc
        return stream

    def recover(self):
        try:
            lease = self._lease()
        except BuildConflict:
            return
        with lease:
            for path in self.directory.glob("*/job.json"):
                job = read_json(path, {})
                if job.get("status") in BUSY:
                    published = self.catalog.indices == self.catalog.index_root / "extensions" / job["id"]
                    job.update(status="completed" if published else "interrupted", finished_at=now(),
                               error=None if published else "The service stopped before publication. Submit the files again to retry.")
                    write_json_atomic(path, job)

    def get(self, identity):
        if not re.fullmatch(r"[0-9a-f]{32}", identity):
            raise KeyError(identity)
        job = read_json(self.directory / identity / "job.json")
        if not job:
            raise KeyError(identity)
        progress = read_json(self.directory / identity / "progress.json", {})
        events = [{"time": job["created_at"], "message": "Source and ground-truth patch validated"}, *progress.get("events", [])]
        if job["status"] not in BUSY:
            events.append({"time": job.get("finished_at", job["created_at"]),
                           "message": "Knowledge published; the sample is available for retrieval" if job["status"] == "completed" else job.get("error", "Build stopped")})
        return self.redact({**job, "stage": progress.get("stage", "queued"), "events": events})

    def list(self):
        return sorted([self.get(path.parent.name) for path in self.directory.glob("*/job.json")],
                      key=lambda job: job["created_at"], reverse=True)

    def submit(self, body):
        source, source_info = uploaded_text(body["source"])
        patch, patch_info = uploaded_text(body["patch"])
        config = resolve_offline_config(load_config(self.config))
        from dotenv import dotenv_values
        env = {**dotenv_values(self.root / ".env"), **os.environ}
        keys = [model.get("api_key") for model in config["models"].values() if isinstance(model, dict)]
        keys += [env.get(name) for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY")]
        self.secrets.update(key for key in keys if isinstance(key, str) and len(key) > 5)
        sample = normalize_sample({
            "cve_id": body["cve_id"].strip().upper(), "cve_description": body["cve_description"].strip(),
            "project": body.get("project", "").strip(), "language": body["language"],
            "buggy_code": source, "patch": patch,
            "source_provenance": {"dataset": "manual_upload", "source_file": source_info, "groundtruth_patch": patch_info},
        }, max_code_length=config["offline"]["dataset"]["max_code_length"])
        with self.lock:
            if self.stopping:
                raise BuildConflict("The service is stopping")
            lease = self._lease()
            try:
                base = self.catalog.indices
                manifest = validate_manifest(json.loads((base / "manifest.json").read_text(encoding="utf-8")))
                params = manifest["parameters"]
                embedding = config["models"]["embeddings"]
                previous = manifest["config"]["models"]["embeddings"]
                if (params.get("build_mode") != "patch_guided" or params.get("index_format_version") != "2.0"
                        or params.get("views") != config["offline"]["multiview"]["views"]
                        or set(params.get("views", [])) != {"data_flow", "control_flow"}
                        or any(embedding.get(k) != previous.get(k) for k in ("model_name", "dimension", "revision"))):
                    raise ValueError("The offline embedding model and both knowledge views must match the current index")
                if not self.catalog.knowledge_summary()["ready"]:
                    raise ValueError("A complete dual-view knowledge index is required before extending it")
                for record in self.catalog.records():
                    if record["sample_id"] == sample["sample_id"] or (
                        record["buggy_code"] == sample["buggy_code"] and record["fixed_code"] == sample["fixed_code"]
                    ):
                        raise BuildConflict("This source and patch pair already exists in the knowledge base")
                fingerprint = index_fingerprint(base)
                identity = uuid4().hex
                directory = self.directory / identity
                directory.mkdir(mode=0o700)
                job = {"id": identity, "status": "queued", "created_at": now(), "cve_id": sample["cve_id"],
                       "project": sample["project"], "language": sample["language"], "sample_id": sample["sample_id"],
                       "source": source_info, "patch": patch_info, "error": None}
                write_json_atomic(directory / "input.json", sample)
                write_json_atomic(directory / "job.json", job)
                self.pool.submit(self.run, job, base, fingerprint, lease)
            except Exception:
                lease.close()
                raise
        return self.get(identity)

    def command(self, identity, base, output):
        directory = self.directory / identity
        return [sys.executable, "-u", str(self.root / "scripts/extend_knowledge.py"),
                "--input", str(directory / "input.json"), "--base-index", str(base),
                "--output-dir", str(output), "--progress", str(directory / "progress.json"),
                "--config", str(self.config)]

    def verify(self, base, output, sample_id):
        from Offline.vector_store import VectorStore
        manifest = validate_manifest(read_json(output / "manifest.json"))
        report = read_json(output / "build_report.json", {})
        if report.get("status") != "complete" or manifest["parameters"].get("base_index_id") != read_json(base / "manifest.json")["experiment_id"]:
            raise ValueError("The expanded knowledge index is incomplete or has the wrong base")
        dimension = manifest["config"]["models"]["embeddings"]["dimension"]
        old, new = VectorStore(dimension=dimension), VectorStore(dimension=dimension)
        old.load(base)
        new.load(output)
        if set(new.metadata) != {"data_flow", "control_flow"}:
            raise ValueError("The expanded index must include both knowledge views")
        for view, records in old.metadata.items():
            rows = new.metadata[view]
            if len(rows) != len(records) + 1 or rows[:-1] != records or rows[-1].get("sample_id") != sample_id:
                raise ValueError("The expanded index did not preserve existing records and add the requested sample")
        return {"samples_added": 1, "vectors_added": 2}

    def run(self, job, base, fingerprint, lease):
        directory = self.directory / job["id"]
        output = self.catalog.index_root / "extensions" / job["id"]
        try:
            job.update(status="running", started_at=now())
            write_json_atomic(directory / "job.json", job)
            with (directory / "build.log").open("w", encoding="utf-8") as log:
                with self.lock:
                    if self.stopping:
                        raise RuntimeError("The service stopped before publication")
                    process = self.process = subprocess.Popen(self.command(job["id"], base, output), cwd=self.root,
                                                               stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                deadline = time.monotonic() + 3600
                while process.poll() is None:
                    if self.stopping or time.monotonic() > deadline:
                        self._stop(process)
                        raise RuntimeError("The service stopped before publication" if self.stopping else "Knowledge build exceeded the one-hour time limit")
                    time.sleep(.2)
                if process.returncode:
                    raise RuntimeError(read_json(directory / "error.json", {}).get("error", "Offline construction failed. Check the offline model configuration and uploaded files, then retry."))
            result = self.verify(base, output, job["sample_id"])
            with self.lock:
                if self.stopping:
                    raise RuntimeError("The service stopped before publication")
                if self.catalog.indices != base or index_fingerprint(base) != fingerprint:
                    raise BuildConflict("The knowledge base changed during construction. Submit again against the latest index.")
                write_json_atomic(self.catalog.index_root / "active_index.json", {
                    "generation": "extensions/" + job["id"], "published_at": now(), "sample_id": job["sample_id"],
                })
            job.update(status="completed", **result)
        except Exception as exc:
            job.update(status="interrupted" if self.stopping else "failed", error=self.redact(str(exc)))
        finally:
            job["finished_at"] = now()
            try:
                write_json_atomic(directory / "job.json", job)
            finally:
                with self.lock:
                    self.process = None
                lease.close()

    @staticmethod
    def _stop(process):
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        except ProcessLookupError:
            pass

    def close(self):
        with self.lock:
            self.stopping = True
        self.pool.shutdown(wait=True)
