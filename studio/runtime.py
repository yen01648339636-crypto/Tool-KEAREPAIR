"""Read display-only progress bound to one Studio worker invocation."""

import hashlib
from pathlib import Path

from .catalog import read_json

STEP_LABELS = {
    "source_check": "Checking container source", "model_loading": "Loading models and indexes",
    "embedding_model_loading": "Loading the retrieval model", "code_encoder_loading": "Loading the code reranker", "index_loading": "Reading dual-view indexes", "initializing": "Initializing stage",
    "embedding_loading": "Loading the retrieval model", "encoder_loading": "Loading the reranker",
    "indices_loading": "Reading the knowledge index", "diagnosis": "Generating the diagnosis report",
    "query_generation": "Generating dual-view queries", "retrieval": "Retrieving historical examples",
    "reranking": "Reranking candidates", "repair": "Generating a patch",
    "source_prepare": "Preparing and installing validation source", "patch_apply": "Applying the patch",
    "compile": "Building", "poc": "PoC Test", "unit": "Unit Tests",
}


def bound_record(path, execution):
    value = read_json(Path(path), {})
    if not isinstance(value, dict) or not execution.get("execution_id"):
        return {}
    if value.get("execution_id") != execution["execution_id"]:
        return {}
    return value


def task_runtime(directory, task, snapshot):
    directory = Path(directory)
    execution = read_json(directory / "runtime_execution.json", {})
    if not isinstance(execution, dict) or execution.get("stage") != task.get("stage"):
        return {}, {}
    if execution.get("task_id") != task["id"]:
        return {}, {}
    case_id = task["case_key"].split(":", 1)[1]
    case_dir = directory / "engine/cases" / case_id
    runtime = dict(execution)
    runtime["progress"] = bound_record(directory / "engine/progress.json", execution)
    if runtime["progress"].get("case_id") not in (None, case_id):
        runtime["progress"] = {}
    if task.get("stage") == "validation":
        job_id = execution.get("validation_id")
        progress_path = directory / "validations" / str(job_id) / "progress.json"
    else:
        progress_path = case_dir / "validation_progress.json"
    runtime["validation_progress"] = bound_record(progress_path, execution)
    partial = bound_record(case_dir / "retrieval_progress.json", execution)
    if partial:
        manifest = read_json(directory / "engine/manifest.json", {})
        diagnosis = case_dir / "diagnosis.json"
        expected_hash = hashlib.sha256(diagnosis.read_bytes()).hexdigest() if diagnosis.is_file() else None
        if (not isinstance(manifest, dict)
                or not snapshot.get("source_hash")
                or task.get("stage") != "retrieval"
                or partial.get("source_hash") != snapshot.get("source_hash")
                or not expected_hash or partial.get("diagnosis_hash") != expected_hash
                or not manifest.get("experiment_id")
                or partial.get("experiment_id") != manifest["experiment_id"]):
            partial = {}
    return runtime, partial
