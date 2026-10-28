"""Preserve an interactive stage's evidence when implementation files change."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
from uuid import uuid4

from utils.diagnosis_readiness import diagnosis_issues
from utils.experiment_manifest import (
    ManifestMismatchError, bind_manifest, hash_file, hash_object, validate_manifest,
    write_json_atomic,
)


def _with_parent(manifest, parent):
    result = deepcopy(manifest)
    result["parameters"]["stage_parent"] = parent
    result["identity"]["parameters_hash"] = hash_object(result["parameters"])
    result["experiment_id"] = hash_object(result["identity"])
    return validate_manifest(result)


def _restore_inputs(output, parent):
    archive = Path(parent["archive"])
    manifest = archive / "manifest.json"
    if hash_file(manifest) != parent["manifest_sha256"]:
        raise ManifestMismatchError("Archived stage manifest changed")
    saved = validate_manifest(json.loads(manifest.read_text()))
    if saved["experiment_id"] != parent["experiment_id"]:
        raise ManifestMismatchError("Archived stage identity changed")
    for relative, expected in parent["inputs"].items():
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            raise ManifestMismatchError("Unsafe inherited artifact path")
        source, target = archive / path, output / path
        if hash_file(source) != expected:
            raise ManifestMismatchError("Archived stage input changed: " + relative)
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        if hash_file(target) != expected:
            raise ManifestMismatchError("Inherited stage input changed: " + relative)


def is_inherited_component(output, manifest, path):
    parent = manifest["parameters"].get("stage_parent")
    if not parent:
        return False
    relative = Path(path).relative_to(output).as_posix()
    expected = parent["inputs"].get(relative)
    if not expected or hash_file(path) != expected:
        return False
    _restore_inputs(Path(output), parent)
    return True


def bind_studio_manifest(output, candidate, *, stage, case_ids, cache_keys=()):
    """Derive a new experiment only for code/cache changes, preserving the parent.

    Config, prompts, runtime and all actual inputs must remain identical. The
    batch CLI keeps using bind_manifest directly and cannot bypass its identity.
    """
    output = Path(output)
    path = output / "manifest.json"
    if not path.exists():
        return bind_manifest(output, candidate)
    existing = validate_manifest(json.loads(path.read_text()))
    previous_parent = existing["parameters"].get("stage_parent")
    if previous_parent:
        candidate = _with_parent(candidate, previous_parent)
        _restore_inputs(output, previous_parent)
    if candidate["experiment_id"] == existing["experiment_id"]:
        return bind_manifest(output, candidate)
    if stage not in {"diagnosis", "retrieval", "repair"}:
        return bind_manifest(output, candidate)
    for key in existing["identity"]:
        if key not in {"code_hash", "data_hash"} and existing["identity"][key] != candidate["identity"][key]:
            raise ManifestMismatchError("Stage handoff requires unchanged configuration, prompts and runtime: " + key)
    ignored = set(cache_keys)
    old_data = {k: v for k, v in existing["data"].items() if k not in ignored}
    new_data = {k: v for k, v in candidate["data"].items() if k not in ignored}
    if old_data != new_data:
        raise ManifestMismatchError("Stage inputs changed; create a new task for the changed source or knowledge")

    required = {"diagnosis": (), "retrieval": ("diagnosis",), "repair": ("diagnosis", "retrieval")}[stage]
    inherited = {}
    for case_id in case_ids:
        if Path(case_id).name != case_id:
            raise ManifestMismatchError("Unsafe case ID")
        case = output / "cases" / case_id
        if not required:
            continue
        source = case / "source.original"
        source_record = json.loads((case / "source.json").read_text())
        digest = hash_file(source)
        if (source_record.get("sha256") != digest
                or candidate["data"].get(source_record.get("manifest_key"), {}).get("sha256") != digest):
            raise ManifestMismatchError("Prior stage source differs from the current input")
        components = {}
        for name in required:
            file = case / (name + ".json")
            component = json.loads(file.read_text())
            if component.get("source_hash") != digest:
                raise ManifestMismatchError("Prior stage report differs from the source: " + name)
            if (component.get("experiment_id") != existing["experiment_id"]
                    and not is_inherited_component(output, existing, file)):
                raise ManifestMismatchError("Prior stage report belongs to another experiment: " + name)
            inherited[file.relative_to(output).as_posix()] = hash_file(file)
            components[name] = component
        if diagnosis_issues(components["diagnosis"].get("diagnostic_report", {})):
            raise ManifestMismatchError("Prior diagnosis is incomplete")
        if "retrieval" in components and components["retrieval"].get("diagnosis_hash") != hash_file(case / "diagnosis.json"):
            raise ManifestMismatchError("Prior retrieval differs from the reviewed diagnosis")

    archive = output.parent / (output.name + "_history") / uuid4().hex
    archive.parent.mkdir(parents=True, exist_ok=True)
    parent = {
        "experiment_id": existing["experiment_id"], "archive": str(archive.resolve()),
        "manifest_sha256": hash_file(path), "inputs": inherited, "stage": stage,
    }
    candidate = _with_parent(candidate, parent)
    output.rename(archive)
    try:
        bound = bind_manifest(output, candidate)
        _restore_inputs(output, parent)
        for case_id in case_ids:
            baseline = archive / "cases" / case_id / "source_baseline.json"
            if baseline.is_file():
                target = output / "cases" / case_id / baseline.name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(baseline, target)
        write_json_atomic(output / "stage_handoff.json", parent)
        return bound
    except BaseException:
        if output.exists():
            output.rename(archive.with_name(archive.name + "-incomplete"))
        archive.rename(output)
        raise
