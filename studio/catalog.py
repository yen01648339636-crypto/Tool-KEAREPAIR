"""Read-only access to trusted repository cases and local knowledge metadata."""

from collections import Counter
import difflib
import io
import json
from pathlib import Path
import pickle
import re
import threading

from utils.knowledge_index import resolve_knowledge_index

EXTENSIONS = {".py", ".go", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".js", ".mjs"}


class DataOnlyUnpickler(pickle.Unpickler):
    """KnowledgeRecord metadata consists only of plain Python containers."""
    def find_class(self, module, name):
        raise ValueError("Knowledge metadata must contain data only")


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


class Catalog:
    def __init__(self, root, indices=None):
        self.root = Path(root).resolve()
        self.index_root = Path(indices or self.root / "data/indices/knowledge_index").resolve()
        self._knowledge_index = None
        self._knowledge_lock = threading.RLock()
        self._knowledge = None
        self.knowledge_error = None
        self._cases = None

    @property
    def indices(self):
        return resolve_knowledge_index(self.index_root)

    def records(self):
        with self._knowledge_lock:
            return self._records()

    def _records(self):
        indices = self.indices
        if self._knowledge is None or self._knowledge_index != indices:
            self.knowledge_error = None
            try:
                raw = DataOnlyUnpickler(io.BytesIO((indices / "metadata.pkl").read_bytes())).load()
                merged = {}
                for view, entries in raw.get("views", {}).items():
                    for entry in entries:
                        sid = entry["sample_id"]
                        if sid not in merged:
                            merged[sid] = {
                                key: entry.get(key, "") for key in
                                ("sample_id", "cve_id", "project", "language",
                                 "cve_description", "buggy_code", "fixed_code", "patch")
                            }
                            merged[sid]["views"] = {}
                        merged[sid]["views"][view] = entry.get("abstracted_knowledge", {})
                self._knowledge = list(merged.values())
            except (OSError, ValueError, TypeError, KeyError, pickle.UnpicklingError, EOFError) as exc:
                self.knowledge_error = str(exc)
                self._knowledge = []
            self._knowledge_index = indices
        return self._knowledge

    def knowledge_summary(self):
        records = self.records()
        return {
            "samples": len(records),
            "vectors": sum(len(x["views"]) for x in records),
            "languages": dict(Counter(x["language"] for x in records)),
            "path": str(self.indices.relative_to(self.root)) if self.indices.is_relative_to(self.root) else str(self.indices),
            "ready": bool(records) and all((self.indices / f"index_{v}.faiss").is_file() for v in ("data_flow", "control_flow")),
            "error": self.knowledge_error,
        }

    def knowledge(self, query="", language="", offset=0, limit=20):
        tokens = re.findall(r"\w+", query.lower())
        rows = []
        for record in self.records():
            if language and record["language"].lower() != language.lower():
                continue
            text = " ".join(str(record[k]) for k in ("cve_id", "project", "cve_description", "views")).lower()
            if tokens and not all(word in text for word in tokens):
                continue
            rows.append(record)
        return {
            "total": len(rows), "offset": offset, "limit": limit,
            "items": [{k: v for k, v in r.items() if k not in ("buggy_code", "fixed_code", "patch")} for r in rows[offset:offset+limit]],
            "search_method": "keyword",
        }

    def record(self, sample_id):
        for record in self.records():
            if record["sample_id"] == sample_id:
                value = dict(record)
                if not value["patch"] and value["fixed_code"]:
                    value["patch"] = "".join(difflib.unified_diff(
                        value["buggy_code"].splitlines(True), value["fixed_code"].splitlines(True),
                        fromfile="a/vulnerable", tofile="b/repaired",
                    ))
                return value
        raise KeyError(sample_id)

    def cases(self):
        if self._cases is None:
            self._cases = {}
            base = self.root / "data/processed"
            for dataset in ("PatchEval", "Vul4c"):
                parent = base / dataset
                if not parent.exists():
                    continue
                for directory in sorted(parent.iterdir()):
                    if not directory.is_dir() or directory.is_symlink():
                        continue
                    commands = read_json(directory / "test_cmds.json", {})
                    if not commands:
                        continue
                    source_name = commands.get("source_file", "")
                    files = [
                        f for f in directory.rglob("*")
                        if f.is_file() and not f.is_symlink()
                        and f.resolve().is_relative_to(directory.resolve())
                        and f.suffix.lower() in EXTENSIONS
                    ]
                    exact = [f for f in files if source_name and f.relative_to(directory).as_posix().endswith("/" + source_name.lstrip("./"))]
                    exact += [f for f in files if f.relative_to(directory).as_posix() == source_name]
                    selected = exact or [f for f in files if not any(s in f.name.lower() for s in ("test_", "_test.", "test."))] or files
                    if not selected:
                        continue
                    source = max(selected, key=lambda f: f.stat().st_size)
                    meta = read_json(directory / "case_meta.json", {})
                    key = f"{dataset}:{directory.name}"
                    self._cases[key] = {
                        "key": key, "case_id": directory.name, "dataset": dataset,
                        "language": commands.get("programming_language", "unknown"),
                        "file": source_name or source.name,
                        "project": meta.get("project", ""),
                        "docker_image": commands.get("docker_image", ""),
                        "_directory": directory, "_source": source,
                    }
        return self._cases

    def public_cases(self, query="", language=""):
        items = []
        for value in self.cases().values():
            public = {k: v for k, v in value.items() if not k.startswith("_")}
            if query.lower() not in json.dumps(public).lower():
                continue
            if language and public["language"].lower() != language.lower():
                continue
            items.append(public)
        return items

    def case(self, key):
        return self.cases()[key]
