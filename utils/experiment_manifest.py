"""Content-based experiment identities and fail-closed artifact ownership."""

from datetime import datetime, timezone
import hashlib
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import platform
import tempfile
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .schemas import SCHEMA_VERSION


MANIFEST_VERSION = "1.0"
MANIFEST_FILENAME = "manifest.json"
_SECRET_KEYS = {
    "apikey",
    "xapikey",
    "authorization",
    "password",
    "secret",
    "clientsecret",
    "accesstoken",
    "refreshtoken",
    "token",
    "cookie",
    "setcookie",
}
_SOURCE_DIRS = (
    "config",
    "Offline",
    "Online",
    "data_loader",
    "models",
    "scripts",
    "static_analysis",
    "utils",
)
_PACKAGES = (
    "numpy",
    "pandas",
    "faiss-cpu",
    "sentence-transformers",
    "transformers",
    "torch",
    "tree-sitter",
    "tree-sitter-c",
    "tree-sitter-cpp",
    "tree-sitter-python",
    "tree-sitter-javascript",
    "tree-sitter-go",
    "networkx",
    "langchain",
    "langchain-core",
    "langgraph",
    "langgraph-prebuilt",
    "langchain-openai",
    "langchain-google-genai",
    "langchain-anthropic",
    "pydantic",
    "openai",
    "anthropic",
    "google-genai",
    "pyyaml",
)


class ManifestMismatchError(ValueError):
    """Existing artifacts belong to a different or unidentifiable experiment."""


def hash_object(value):
    raw = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def hash_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sanitize_config(value):
    """Credentials do not enter snapshots or identities; generation parameters do."""
    if isinstance(value, dict):
        return {
            str(k): sanitize_config(v)
            for k, v in value.items()
            if _key_name(k) not in _SECRET_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_config(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str) and "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme in {"http", "https"}:
            host = parsed.netloc.rsplit("@", 1)[-1]
            query = [
                (k, v)
                for k, v in parse_qsl(parsed.query, keep_blank_values=True)
                if _key_name(k) not in _SECRET_KEYS
            ]
            return urlunsplit((parsed.scheme, host, parsed.path, urlencode(query), ""))
    return value


def _key_name(value):
    return str(value).lower().replace("_", "").replace("-", "")


def file_inventory(paths, root=None):
    root = Path(root).resolve() if root else None
    result = {}
    for supplied in paths:
        supplied = Path(supplied)
        if not supplied.exists():
            raise FileNotFoundError(f"Experiment input does not exist: {supplied}")
        files = sorted(supplied.rglob("*")) if supplied.is_dir() else [supplied]
        for path in files:
            if (
                not path.is_file()
                or "__pycache__" in path.parts
                or path.suffix == ".pyc"
            ):
                continue
            resolved = path.resolve()
            if root and resolved.is_relative_to(root):
                label = resolved.relative_to(root).as_posix()
            else:
                label = resolved.as_posix()
            result[label] = {"sha256": hash_file(path), "size": path.stat().st_size}
    return dict(sorted(result.items()))


def create_manifest(
    stage, config, *, project_root=None, data_paths=(), parameters=None
):
    root = Path(project_root or Path(__file__).resolve().parent.parent).resolve()
    if stage not in {"offline", "online"}:
        raise ValueError(f"Unknown experiment stage: {stage}")
    config = sanitize_config(config)
    prompt_paths = set((root / "prompts").rglob("*.txt"))
    offline = config.get("offline", {})
    multiview = offline.get("multiview", {})
    for configured in (
        multiview.get("prompts", {}),
        multiview.get("extraction_prompts", {}),
        offline.get("distillation", {}).get("prompts", {}),
    ):
        for supplied in configured.values():
            path = Path(supplied)
            prompt_paths.add(path if path.is_absolute() else root / path)
    prompts = file_inventory(sorted(prompt_paths), root)
    # Include every Python implementation file, even when Git metadata is absent.
    sources = [
        p
        for name in _SOURCE_DIRS
        for p in (root / name).rglob("*.py")
        if "__pycache__" not in p.parts
    ]
    sources.extend(
        path
        for name in ("requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock")
        if (path := root / name).exists()
    )
    code = file_inventory(sources, root)
    data = file_inventory(data_paths, root)
    parameters = sanitize_config(parameters or {})
    packages = {}
    for package in _PACKAGES:
        try:
            packages[package] = version(package)
        except PackageNotFoundError:
            packages[package] = None
    runtime = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or None,
        "cpu_count": os.cpu_count(),
        "packages": packages,
        "llm_max_retries": os.getenv("LLM_MAX_RETRIES", "3"),
        "llm_retry_base_delay": os.getenv("LLM_RETRY_BASE_DELAY", "1.5"),
        "python_hash_seed": os.getenv("PYTHONHASHSEED"),
        "api_endpoints": sanitize_config(
            {
                key: os.getenv(key)
                for key in ("OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "HF_ENDPOINT")
            }
        ),
    }
    identity = {
        "manifest_version": MANIFEST_VERSION,
        "schema_version": SCHEMA_VERSION,
        "stage": stage,
        "mode": config.get("experiment", {}).get("mode", "extended"),
        "config_hash": hash_object(config),
        "prompt_hash": hash_object(prompts),
        "data_hash": hash_object(data),
        "code_hash": hash_object(code),
        "parameters_hash": hash_object(parameters),
        "runtime_hash": hash_object(runtime),
    }
    return {
        "experiment_id": hash_object(identity),
        "identity": identity,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "config": config,
        "parameters": parameters,
        "prompts": prompts,
        "data": data,
        "code": code,
        "runtime": runtime,
    }


def validate_manifest(manifest):
    try:
        identity = manifest["identity"]
        if (
            identity["manifest_version"] != MANIFEST_VERSION
            or identity["schema_version"] != SCHEMA_VERSION
        ):
            raise ValueError("unsupported version")
        for content, key in (
            ("config", "config_hash"),
            ("parameters", "parameters_hash"),
            ("prompts", "prompt_hash"),
            ("data", "data_hash"),
            ("code", "code_hash"),
            ("runtime", "runtime_hash"),
        ):
            if hash_object(manifest[content]) != identity[key]:
                raise ValueError(f"invalid {key}")
        if hash_object(identity) != manifest["experiment_id"]:
            raise ValueError("invalid experiment_id")
    except (KeyError, TypeError, ValueError) as exc:
        raise ManifestMismatchError(f"Invalid experiment manifest: {exc}") from exc
    return manifest


def write_json_atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
        Path(temporary).replace(path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def bind_manifest(directory, manifest):
    """Never adopt pre-existing caches/results without a verifiable identity."""
    validate_manifest(manifest)
    directory = Path(directory)
    path = directory / MANIFEST_FILENAME
    if path.exists():
        try:
            existing = validate_manifest(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            raise ManifestMismatchError(f"Cannot validate {path}: {exc}") from exc
        if existing["experiment_id"] != manifest["experiment_id"]:
            changed = [
                key
                for key in manifest["identity"]
                if existing["identity"].get(key) != manifest["identity"][key]
            ]
            raise ManifestMismatchError(
                f"Experiment mismatch in {directory}: {', '.join(changed)}. Use a new output directory."
            )
        return existing
    if directory.exists():
        artifacts = [
            p.name for p in directory.iterdir() if p.name not in {".tmp", "logs"}
        ]
        if artifacts:
            raise ManifestMismatchError(
                f"Unversioned artifacts in {directory}: {', '.join(sorted(artifacts)[:5])}. Use a new output directory."
            )
    write_json_atomic(path, manifest)
    return manifest


def verify_checkpoint(checkpoint, experiment_id):
    if checkpoint.get("experiment_id") != experiment_id:
        raise ManifestMismatchError(
            "Checkpoint experiment_id is missing or does not match. Use a new output directory."
        )


def index_parameters(
    samples, batch_size, views, build_mode, add_view_prefix=True, dataset_report=None
):
    result = {
        "index_format_version": "2.0",
        "retrieval_key": (
            "patch"
            if build_mode == "patch_oracle"
            else "abstracted_knowledge.root_cause"
        ),
        "samples_hash": hash_object(samples),
        "sample_count": len(samples),
        "batch_size": batch_size,
        "views": list(views),
        "build_mode": build_mode,
        "add_view_prefix": (
            bool(add_view_prefix) if build_mode == "patch_oracle" else False
        ),
    }
    if dataset_report is not None:
        result["dataset_report_hash"] = hash_object(dataset_report)
    return result
