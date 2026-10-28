"""Repository inputs resolve only to prepared snapshots and bundled tests."""

import json
import hashlib
from pathlib import Path

import pytest

from studio.catalog import Catalog
from studio.repositories import RepositoryCatalog, normalize_repository_url


@pytest.fixture
def repository_catalog(tmp_path):
    raw = []
    for suffix in ("0001", "0002", "0003"):
        case_id = "CVE-2026-" + suffix
        directory = tmp_path / "data/processed/PatchEval" / case_id
        (directory / "src").mkdir(parents=True)
        (directory / "src/parser.py").write_text("def parse(value):\n    return value\n")
        commands = {
            "source_file": "src/parser.py", "programming_language": "Python",
            "poc_test_cmd": "pytest tests/test_parser.py::test_regression",
            "unit_test_cmd": "pytest tests/test_parser.py",
        }
        if suffix == "0003":
            commands["poc_test_cmd"] = ""
            commands["unit_test_cmd"] = ""
        (directory / "test_cmds.json").write_text(json.dumps(commands))
        raw.append({
            "cve_id": case_id, "repo": "https://github.com/Example/Parser.git",
            "vul_func": [{"file_path": "./src/parser.py", "commit": "abcdef1234567"}],
        })
    raw_dir = tmp_path / "data/raw"
    raw_dir.mkdir()
    (raw_dir / "patcheval_dataset.json").write_text(json.dumps(raw))
    return RepositoryCatalog(Catalog(tmp_path))


def request_for(target, mode="full"):
    return {
        "repository_url": target["repository_url"], "target_id": target["id"],
        "vulnerable_file": target["file"], "revision": target["revision"],
        "validation_mode": mode, "poc_file": target["poc_file"], "unit_test": target["unit_test"],
    }


@pytest.mark.parametrize("value", [
    "https://github.com/Example/Parser", "https://github.com/Example/Parser.git/",
    "git@github.com:Example/Parser.git", "ssh://git@github.com/Example/Parser.git",
    "git://github.com/Example/Parser.git", " http://github.com/Example/Parser ",
])
def test_common_clone_url_spellings(value):
    assert normalize_repository_url(value) == "https://github.com/example/parser"


@pytest.mark.parametrize("value", [
    "", "file:///tmp/repo", "https://user:secret@github.com/example/parser",
    "https://token@github.com/example/parser", "https://github.com/example/parser?token=secret",
    "https://github.com/example/parser#main", "https://github.com/example/../parser",
    "https://github.com/example/%2e%2e/parser", "https://github.com/example\\parser",
    "https://github.com/example/par\nser", "https://github.com:invalid/example/parser",
])
def test_rejects_credentials_and_nonrepository_inputs(value):
    with pytest.raises(ValueError):
        normalize_repository_url(value)


def test_repo_grouping_and_stable_explicit_targets(repository_catalog):
    assert repository_catalog.repositories() == [{
        "repository_url": "https://github.com/example/parser", "project": "parser", "target_count": 3,
    }]
    resolved = repository_catalog.resolve("git@github.com:Example/Parser.git")
    assert len(resolved["targets"]) == 3
    assert len({t["id"] for t in resolved["targets"]}) == 3
    assert all(t["file"] == "src/parser.py" for t in resolved["targets"])
    assert all(t["revision"] == "abcdef1234567" for t in resolved["targets"])
    assert "CVE-" not in resolved["targets"][1]["target_label"]
    assert RepositoryCatalog(repository_catalog.catalog).resolve(resolved["repository_url"])["targets"] == resolved["targets"]
    # Returned form data cannot mutate the authoritative mapping.
    resolved["targets"][0]["file"] = "wrong.py"
    assert repository_catalog.target(resolved["targets"][0]["id"])["file"] == "src/parser.py"


def test_unknown_repo_or_target_never_guesses(repository_catalog):
    assert repository_catalog.repository_for_case("PatchEval:CVE-2026-0001") == "https://github.com/example/parser"
    assert repository_catalog.repository_for_case("unknown:case") is None
    with pytest.raises(ValueError, match="no prepared"):
        repository_catalog.resolve("https://github.com/unknown/project")
    with pytest.raises(ValueError, match="prepared repair target"):
        repository_catalog.target("CVE-2026-0001")


def test_matching_references_and_validation_scope(repository_catalog):
    target = repository_catalog.resolve("https://github.com/example/parser")["targets"][0]
    full = repository_catalog.match(**request_for(target))
    assert full["case_key"] == target["case_key"]
    assert full["request"]["poc_file"] == "test_cmds.json#poc_test_cmd"
    assert full["request"]["unit_test"] == "test_cmds.json#unit_test_cmd"
    poc = repository_catalog.match(**request_for(target, "poc"))
    assert poc["request"]["poc_file"] and poc["request"]["unit_test"] == ""
    patch = repository_catalog.match(**request_for(target, "patch_only"))
    assert patch["request"]["poc_file"] == patch["request"]["unit_test"] == ""
    values = request_for(target)
    values["vulnerable_file"] = "./src/parser.py"
    assert repository_catalog.match(**values)["request"]["vulnerable_file"] == "src/parser.py"


@pytest.mark.parametrize("field,value,message", [
    ("repository_url", "https://github.com/other/parser", "does not belong"),
    ("vulnerable_file", "src/other.py", "vulnerable file"),
    ("vulnerable_file", "../src/parser.py", "repository-relative"),
    ("revision", "main", "revision must match"),
    ("poc_file", "", "bundled PoC"),
    ("poc_file", "/tmp/user-exploit", "bundled PoC"),
    ("unit_test", "", "bundled unit test"),
    ("unit_test", "pytest custom.py", "bundled unit test"),
    ("validation_mode", "anything", "validation plan"),
])
def test_changed_or_incomplete_fields_rejected(repository_catalog, field, value, message):
    target = repository_catalog.resolve("https://github.com/example/parser")["targets"][0]
    values = request_for(target)
    values[field] = value
    with pytest.raises(ValueError, match=message):
        repository_catalog.match(**values)


def test_no_validation_available_is_patch_only(repository_catalog):
    target = repository_catalog.resolve("https://github.com/example/parser")["targets"][2]
    assert target["validation_modes"] == ["patch_only"]
    assert target["poc_file"] == target["unit_test"] == ""
    with pytest.raises(ValueError, match="validation plan"):
        repository_catalog.match(**request_for(target))
    assert repository_catalog.match(**request_for(target, "patch_only"))["case_key"] == target["case_key"]


def test_verified_source_receipt_pins_revision(repository_catalog):
    case = repository_catalog.catalog.case("PatchEval:CVE-2026-0001")
    (case["_directory"] / "source_baseline.json").write_text(json.dumps({
        "status": "verified", "steps": [{"commit": "0123456789abcdef"}, {"commit": "0123456789abcdef"}],
    }))
    target = repository_catalog.resolve("https://github.com/example/parser")["targets"][0]
    assert target["revision"] == "0123456789abcdef"


def test_prepared_repository_coverage_and_vul4c_ambiguity():
    root = Path(__file__).resolve().parents[2]
    if not (root / "data/raw/patcheval_dataset.json").exists():
        pytest.skip("Prepared repository datasets are not present in this checkout")
    catalog = Catalog(root)
    mapping = RepositoryCatalog(catalog)
    targets = [t for r in mapping.repositories() for t in mapping.resolve(r["repository_url"])["targets"]]
    assert {t["case_key"] for t in mapping._targets.values()} == set(catalog.cases())
    assert {t["case_key"] for t in targets} == {
        t["case_key"] for t in mapping._targets.values()
        if t["repository_url"] != "https://github.com/vadz/libtiff" or t["case_key"] == "Vul4c:CVE-2016-10267"
    }
    assert all(t["file"] and t["revision"] and t["poc_file"] and t["unit_test"] for t in targets)
    audiofile = mapping.resolve("https://github.com/mpruett/audiofile.git")["targets"]
    ambiguous = [t for t in audiofile if t["file"] == "libaudiofile/WAVE.cpp" and t["revision"].startswith("d19a5ac")]
    assert len(ambiguous) == 4
    assert len({t["id"] for t in ambiguous}) == 4
    assert all(t["poc_file"] == "VUL4C/exploit" for t in ambiguous)
    assert all(mapping.match(**request_for(t))["case_key"] == t["case_key"] for t in ambiguous)


@pytest.fixture
def libtiff_catalog(tmp_path):
    for case_id in ("CVE-2006-2025", "CVE-2016-10267", "CVE-2016-10268"):
        directory = tmp_path / "data/processed/Vul4c" / case_id
        (directory / "libtiff").mkdir(parents=True)
        (directory / "libtiff/tif_ojpeg.c").write_text("int decode(void) { return 0; }\n")
        (directory / "test_cmds.json").write_text(json.dumps({
            "source_file": "libtiff/tif_ojpeg.c", "programming_language": "c",
            "poc_test_cmd": "run-poc", "unit_test_cmd": "run-tests",
        }))
    return RepositoryCatalog(Catalog(tmp_path))


@pytest.mark.parametrize("url", [
    "https://github.com/vadz/libtiff", "https://github.com/vadz/libtiff.git/",
    "git@github.com:VADZ/LIBTIFF.git", "https://github.com/Vadz/LibTiff/",
])
def test_libtiff_url_always_resolves_to_configured_case(libtiff_catalog, url):
    resolved = libtiff_catalog.resolve(url)
    assert len(resolved["targets"]) == 1
    target = resolved["targets"][0]
    assert target["case_key"] == "Vul4c:CVE-2016-10267"
    assert target["file"] == "libtiff/tif_ojpeg.c"
    assert "CVE-" not in target["target_label"]
    assert libtiff_catalog.repositories()[0]["target_count"] == 1
    matched = libtiff_catalog.match(**request_for(target, "patch_only"))
    assert matched["case_key"] == "Vul4c:CVE-2016-10267"
    assert matched["request"]["display_name"] == "libtiff"
    resolved["targets"][0]["case_key"] = "wrong"
    assert libtiff_catalog.resolve(url)["targets"][0]["case_key"] == "Vul4c:CVE-2016-10267"


def test_libtiff_cannot_submit_another_baseline(libtiff_catalog):
    libtiff_catalog.resolve("https://github.com/vadz/libtiff")
    target_id = "target-" + hashlib.sha256(b"Vul4c:CVE-2016-10268").hexdigest()[:20]
    alternate = libtiff_catalog.target(target_id)
    with pytest.raises(ValueError, match="configured source baseline"):
        libtiff_catalog.match(**request_for(alternate, "patch_only"))


def test_missing_libtiff_default_does_not_fall_back_to_another_case(libtiff_catalog):
    del libtiff_catalog.catalog.cases()["Vul4c:CVE-2016-10267"]
    assert libtiff_catalog.repositories() == []
    with pytest.raises(ValueError, match="no prepared"):
        libtiff_catalog.resolve("https://github.com/vadz/libtiff")


def test_libtiff_demo_without_its_saved_run_never_starts_live_execution(libtiff_catalog, monkeypatch):
    from fastapi.testclient import TestClient
    from studio.app import create_app

    case_dir = libtiff_catalog.catalog.root / "data/processed/Vul4c/CVE-2016-10267"
    (case_dir / "case_meta.json").write_text(json.dumps({
        "demo_source_task_id": "fixture-saved-run",
    }))
    app = create_app(libtiff_catalog.catalog.root)
    def forbidden(*args, **kwargs):
        raise AssertionError("The configured demo fell back to live execution")
    monkeypatch.setattr(app.state.engine, "submit", forbidden)
    with TestClient(app) as client:
        for url in ("https://github.com/vadz/libtiff", "https://github.com/vadz/libtiff.git/"):
            resolved = client.post("/api/repositories/resolve", json={"repository_url": url})
            assert resolved.status_code == 200
            target, = resolved.json()["targets"]
            assert target["demo_source_task_id"] == "fixture-saved-run"
            assert target["replay_source_id"] == "fixture-saved-run"
            response = client.post("/api/tasks", json=request_for(target, "patch_only"))
            assert response.status_code == 409, response.text
            assert "configured saved workflow is unavailable" in response.json()["detail"]
        assert client.get("/api/tasks").json()["items"] == []
