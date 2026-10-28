import json

import pytest

from utils.experiment_manifest import (
    ManifestMismatchError, bind_manifest, create_manifest, hash_file, validate_manifest,
)
from utils.stage_handoff import bind_studio_manifest


@pytest.fixture
def stage(tmp_path):
    root = tmp_path / "repo"
    case = root / "input/CVE-1"
    case.mkdir(parents=True)
    source = case / "source.c"
    source.write_text("int value;\n")
    cache = case / "source_baseline.json"
    cache.write_text('{"status":"verified"}')
    code = root / "utils/cache.py"
    code.parent.mkdir()
    code.write_text("version = 1\n")
    config = {"experiment": {"mode": "standard"}}
    output = root / "engine"
    original = create_manifest("online", config, project_root=root, data_paths=[case])
    bind_manifest(output, original)
    saved = output / "cases/CVE-1"
    saved.mkdir(parents=True)
    (saved / "source.original").write_bytes(source.read_bytes())
    (saved / "source.json").write_text(json.dumps({
        "manifest_key": "input/CVE-1/source.c", "sha256": hash_file(source),
    }))
    (saved / "diagnosis.json").write_text(json.dumps({
        "source_hash": hash_file(source),
        "diagnostic_report": {"summary": "Input reaches a write", "termination_reason": "model_finished"},
        "experiment_id": original["experiment_id"],
    }))
    return root, case, source, cache, code, output, config, original


def candidate(stage):
    root, case, _, cache, _, _, config, _ = stage
    return create_manifest("online", config, project_root=root,
                           data_paths=[p for p in case.rglob("*") if p.is_file() and p != cache])


def test_code_update_keeps_prior_diagnosis_and_creates_distinct_experiment(stage):
    root, _, _, _, code, output, _, original = stage
    raw = (output / "cases/CVE-1/diagnosis.json").read_bytes()
    code.write_text("version = 2\n")
    current = candidate(stage)
    bound = bind_studio_manifest(output, current, stage="retrieval", case_ids=["CVE-1"],
                                 cache_keys=["input/CVE-1/source_baseline.json"])
    assert bound["experiment_id"] != original["experiment_id"]
    parent = bound["parameters"]["stage_parent"]
    archive = root / parent["archive"]
    assert json.loads((archive / "manifest.json").read_text())["experiment_id"] == original["experiment_id"]
    assert (output / "cases/CVE-1/diagnosis.json").read_bytes() == raw
    validate_manifest(bound)
    # Following stages keep this identity and do not fork again.
    later = bind_studio_manifest(output, current, stage="retrieval", case_ids=["CVE-1"],
                                 cache_keys=["input/CVE-1/source_baseline.json"])
    assert later["experiment_id"] == bound["experiment_id"]
    assert len(list((root / "engine_history").iterdir())) == 1


def test_changed_actual_source_cannot_be_adopted_as_an_existing_diagnosis(stage):
    root, _, source, _, _, output, _, original = stage
    source.write_text("int changed;\n")
    with pytest.raises(ManifestMismatchError, match="Stage inputs changed"):
        bind_studio_manifest(output, candidate(stage), stage="retrieval", case_ids=["CVE-1"],
                             cache_keys=["input/CVE-1/source_baseline.json"])
    assert not (root / "engine_history").exists()
    assert json.loads((output / "manifest.json").read_text())["experiment_id"] == original["experiment_id"]


def test_unbound_diagnosis_cannot_cross_experiments(stage):
    _, _, _, _, _, output, _, _ = stage
    file = output / "cases/CVE-1/diagnosis.json"
    value = json.loads(file.read_text())
    value["source_hash"] = "wrong"
    file.write_text(json.dumps(value))
    with pytest.raises(ManifestMismatchError, match="report differs"):
        bind_studio_manifest(output, candidate(stage), stage="retrieval", case_ids=["CVE-1"],
                             cache_keys=["input/CVE-1/source_baseline.json"])


def test_inherited_report_tampering_is_rejected(stage):
    _, _, _, _, _, output, _, _ = stage
    current = candidate(stage)
    bind_studio_manifest(output, current, stage="retrieval", case_ids=["CVE-1"],
                         cache_keys=["input/CVE-1/source_baseline.json"])
    (output / "cases/CVE-1/diagnosis.json").write_text("{}")
    with pytest.raises(ManifestMismatchError, match="Inherited stage input changed"):
        bind_studio_manifest(output, current, stage="retrieval", case_ids=["CVE-1"],
                             cache_keys=["input/CVE-1/source_baseline.json"])


def test_foreign_report_with_same_source_cannot_be_imported(stage):
    _, _, _, _, _, output, _, _ = stage
    file = output / "cases/CVE-1/diagnosis.json"
    value = json.loads(file.read_text())
    value["experiment_id"] = "foreign experiment"
    file.write_text(json.dumps(value))
    with pytest.raises(ManifestMismatchError, match="another experiment"):
        bind_studio_manifest(output, candidate(stage), stage="retrieval", case_ids=["CVE-1"],
                             cache_keys=["input/CVE-1/source_baseline.json"])
