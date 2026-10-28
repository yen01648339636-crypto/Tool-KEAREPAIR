"""Repository form requests retain their target and validation scope end to end.

Fixtures use only local subprocesses and frozen evidence: no model, clone, or
Docker invocation is needed to exercise scheduling, APIs, exports and replay.
"""

from copy import deepcopy
import base64
import hashlib
import io
import json
import sys
import zipfile

import pytest

from tests.studio.test_studio import app, client, workspace as base_workspace, wait_task
from tests.studio.test_replay import recorded, wait


@pytest.fixture
def workspace(tmp_path):
    root = base_workspace.__wrapped__(tmp_path)
    case = root / "data/processed/PatchEval/CVE-2026-0001"
    (case / "case_meta.json").write_text(json.dumps({
        "repository_url": "https://github.com/example/downloads", "revision": "abc1234567890", "project": "downloads",
    }))
    commands = json.loads((case / "test_cmds.json").read_text())
    commands.update(
        poc_test_cmd="python -m pytest tests/test_downloads.py::test_regression",
        unit_test_cmd="python -m pytest tests/test_downloads.py",
        validation_steps=[
            {"name": "build_and_poc", "command": "fixture build and PoC", "covers": ["compile", "poc"]},
            {"name": "unit", "command": "fixture unit tests", "covers": ["unit"]},
        ],
    )
    (case / "test_cmds.json").write_text(json.dumps(commands))
    return root


@pytest.fixture
def target(client):
    response = client.post("/api/repositories/resolve", json={"repository_url": "git@github.com:Example/Downloads.git"})
    assert response.status_code == 200, response.text
    return response.json()["targets"][0]


@pytest.fixture
def hold_workers(app, monkeypatch):
    calls = []
    monkeypatch.setattr(app.state.engine.pool, "submit", lambda *args, **kwargs: calls.append((args, kwargs)))
    return calls


def payload(target, mode="full", *, replay=False):
    value = dict(repository_url="https://github.com/Example/Downloads.git/", target_id=target["id"],
                 vulnerable_file="./" + target["file"], revision=target["revision"], validation_mode=mode,
                 mode="replay" if replay else "live")
    if mode != "patch_only":
        value["poc_file"] = target["poc_file"]
    if mode == "full":
        value["unit_test"] = target["unit_test"]
    return value


def test_repository_api_resolves_available_targets(client):
    rows = client.get("/api/repositories").json()["items"]
    assert rows == [{"repository_url": "https://github.com/example/downloads", "project": "downloads", "target_count": 1}]
    resolved = client.post("/api/repositories/resolve", json={"repository_url": rows[0]["repository_url"]}).json()
    target = resolved["targets"][0]
    assert target["file"] == "app/downloads.py"
    assert target["revision"] == "abc1234567890"
    assert target["validation_modes"] == ["patch_only", "poc", "full"]
    assert target["replay_source_id"] is None
    for url in ("https://github.com/unknown/project", "https://token@github.com/example/downloads", "file:///tmp/repo"):
        assert client.post("/api/repositories/resolve", json={"repository_url": url}).status_code == 422


@pytest.mark.parametrize("field,value", [
    ("target_id", None), ("target_id", "wrong"),
    ("vulnerable_file", None), ("vulnerable_file", "other.py"),
    ("vulnerable_file", "../app/downloads.py"),
    ("revision", None), ("revision", "main"),
    ("poc_file", None), ("poc_file", "/tmp/custom.poc"),
    ("unit_test", None), ("unit_test", "pytest /tmp/custom.py"),
    ("repository_url", "https://github.com/another/project"),
])
def test_incomplete_or_mismatched_target_rejected(client, app, target, hold_workers, field, value):
    request = payload(target)
    if value is None:
        request.pop(field)
    else:
        request[field] = value
    response = client.post("/api/tasks", json=request)
    assert response.status_code == 409, response.text
    assert hold_workers == []
    assert app.state.store.tasks() == []


def test_legacy_case_api_retained_without_repository_options(client, app, target, hold_workers):
    response = client.post("/api/tasks", json={"case_key": target["case_key"]})
    assert response.status_code == 201, response.text
    task = response.json()
    assert task["automatic"] is True
    assert app.state.engine.repair_request(task["id"]) == {}
    assert client.post("/api/tasks", json={**payload(target), "case_key": target["case_key"]}).status_code == 422
    assert client.post("/api/tasks", json={"case_key": target["case_key"], "validation_mode": "patch_only"}).status_code == 422


@pytest.mark.parametrize("mode,steps", [("patch_only", []), ("poc", ["build_and_poc"]), ("full", ["build_and_poc", "unit"])])
def test_request_and_scoped_commands_are_saved_per_task(client, app, target, hold_workers, mode, steps):
    original = app.state.catalog.case(target["case_key"])["_directory"] / "test_cmds.json"
    before = original.read_bytes()
    response = client.post("/api/tasks", json=payload(target, mode))
    assert response.status_code == 201, response.text
    identity = response.json()["id"]
    directory = app.state.store.run_dir(identity)
    saved = json.loads((directory / "repair_request.json").read_text())
    assert saved["repository_url"] == "https://github.com/example/downloads"
    assert saved["vulnerable_file"] == "app/downloads.py"
    assert saved["validation_mode"] == mode
    assert saved["poc_file"] == (target["poc_file"] if mode != "patch_only" else "")
    assert saved["unit_test"] == (target["unit_test"] if mode == "full" else "")
    copied = json.loads((directory / "input/CVE-2026-0001/test_cmds.json").read_text())
    assert copied["studio_validation_mode"] == mode
    assert [step["name"] for step in copied["validation_steps"]] == steps
    assert bool(copied.get("poc_test_cmd")) == (mode != "patch_only")
    assert bool(copied.get("unit_test_cmd")) == (mode == "full")
    assert original.read_bytes() == before
    assert client.get(f"/api/tasks/{identity}").json()["repair_request"] == saved


def scoped_worker(app, monkeypatch):
    """Write native-shaped output according to the task's actual scoped snapshot."""
    seen = []
    engine = app.state.engine
    real_command = engine.command

    def command(task, case_dir):
        stage = task["stage"]
        original_command = real_command(task, case_dir)
        commands = json.loads((case_dir / "test_cmds.json").read_text())
        mode = commands["studio_validation_mode"]
        seen.append((stage, mode, original_command))
        files = {}
        status = {"diagnosis": "diagnosis_ready", "retrieval": "retrieval_ready", "repair": "completed"}[stage]
        if stage == "diagnosis":
            files["diagnosis.json"] = {"diagnostic_report": {"summary": "Fixture vulnerability diagnosis", "termination_reason": "model_finished", "facts": [], "tool_calls": []}}
        if stage == "retrieval":
            example = {"sample_id": "fixture", "retrieval_hits": [{"query_view": view, "rank": 1, "distance": .1} for view in ("data_flow", "control_flow")]}
            files["retrieval.json"] = {"queries": {"data_flow": "df", "control_flow": "cf"}, "ranking": {"candidates": [example]}, "final_exemplars": [example]}
        if stage == "repair":
            validation = None
            if mode == "patch_only":
                status = "patch_ready"
                assert "--defer-validation" in original_command
                assert commands["validation_steps"] == []
            else:
                assert "--defer-validation" not in original_command
                validation = {"success": mode == "full", "selected_checks_passed": True,
                              "stage_status": dict(patch_apply="passed", compile="passed", poc="passed", unit="passed" if mode == "full" else "not_run"),
                              "stage_details": {"poc": {"stdout": "requested PoC passed", "returncode": 0}}}
            files["attempts/1/attempt.json"] = {"candidate_id": 1, "patch": "--- a/app/downloads.py\n+++ b/app/downloads.py\n@@ -1 +1 @@\n-old\n+new\n", "validation_invoked": mode != "patch_only", "validation_result": validation}
        files["result.json"] = {"status": status, "success": stage == "repair" and mode == "full", "selected_checks_passed": stage == "repair" and mode == "poc"}
        out = app.state.store.run_dir(task["id"]) / "engine/cases" / case_dir.name
        script = "import json\nfrom pathlib import Path\n" + f"p=Path({str(out)!r})\nfiles=json.loads({json.dumps(files)!r})\n"
        script += "for name,value in files.items():\n q=p/name\n q.parent.mkdir(parents=True,exist_ok=True)\n q.write_text(json.dumps(value))\n"
        return [sys.executable, "-c", script]

    monkeypatch.setattr(engine, "command", command)
    return seen


@pytest.mark.parametrize("mode,outcome", [("patch_only", "patch_generated"), ("poc", "poc_checks_passed"), ("full", "validated")])
def test_live_plan_completes_and_exports_correct_scope(client, app, target, monkeypatch, mode, outcome):
    seen = scoped_worker(app, monkeypatch)
    if mode == "patch_only":
        config = app.state.engine.public_config()
        monkeypatch.setattr(app.state.engine, "public_config", lambda: {**config, "docker_installed": False})
    response = client.post("/api/tasks", json=payload(target, mode))
    assert response.status_code == 201, response.text
    identity = response.json()["id"]
    completed = wait_task(app, identity)
    assert completed["status"] == "completed", completed
    assert [item[0] for item in seen] == ["diagnosis", "retrieval", "repair"]
    assert completed["validated"] == (mode == "full")
    report = client.get(f"/api/tasks/{identity}/report").json()
    assert report["summary"]["outcome"] == outcome
    assert report["summary"]["has_deliverable_patch"]
    assert report["summary"]["has_validated_patch"] == (mode == "full")
    assert report["summary"]["requested_checks_passed"] == (mode != "patch_only")
    assert report["repair_request"]["validation_mode"] == mode
    assert report["patch"]["final_patch"].endswith("+new\n")
    if mode == "patch_only":
        assert report["validation"]["result"] == {}
        assert client.post(f"/api/tasks/{identity}/validate", json={"candidate_id": 1}).status_code == 409
    if mode == "poc":
        assert report["validation"]["result"]["success"] is False
        assert report["validation"]["result"]["selected_checks_passed"] is True
        assert report["validation"]["result"]["stage_status"]["unit"] == "not_run"
    archive = zipfile.ZipFile(io.BytesIO(client.get(f"/api/tasks/{identity}/export").content))
    assert "final.patch" in archive.namelist()
    assert json.loads(archive.read("repair_report.json"))["repair_request"]["validation_mode"] == mode


@pytest.mark.parametrize("mode,outcome", [("patch_only", "patch_generated"), ("poc", "historical_poc_checks_passed"), ("full", "historical_validation_passed")])
def test_replay_plan_uses_only_requested_checks(client, app, recorded, target, monkeypatch, mode, outcome):
    original = deepcopy(recorded[1])
    monkeypatch.setattr(app.state.engine.replay, "time_scale", .003)
    lookup = client.post("/api/repositories/resolve", json={"repository_url": target["repository_url"]}).json()
    assert lookup["targets"][0]["replay_source_id"] == recorded[0]
    response = client.post("/api/tasks", json=payload(target, mode, replay=True))
    assert response.status_code == 201, response.text
    identity = response.json()["id"]
    done = wait(client, identity, lambda row: row["status"] == "completed")
    stages = ["diagnosis", "retrieval", "repair"] + ([] if mode == "patch_only" else ["validation"])
    assert done["replay"]["completed_stages"] == stages
    assert done["repair_request"]["validation_mode"] == mode
    assert done["validated"] is False
    assert done["result"]["success"] is False
    assert recorded[1] == original
    report = client.get(f"/api/tasks/{identity}/report").json()
    assert report["summary"]["outcome"] == outcome
    assert report["summary"]["has_deliverable_patch"] is True
    assert report["provenance"]["new_validation_performed"] is False
    if mode == "patch_only":
        assert done["candidates"][0]["validation_result"] is None
        assert done["replay"]["timings"]["validation"] == 0
        assert client.post(f"/api/tasks/{identity}/validate", json={"candidate_id": 2}).status_code == 409
    else:
        result = done["candidates"][0]["validation_result"]
        assert result["success"] == (mode == "full")
        assert report["summary"]["requested_checks_passed"] is True
        if mode == "poc":
            assert result["selected_checks_passed"] is True
            assert result["stage_status"]["unit"] == "not_run"
            assert "unit" not in result["stage_details"]
            assert not any(e["message"] == "Replay · Unit Tests" for e in done["events"])
            assert done["replay"]["timings"]["validation"] == 24


def test_replay_rejects_a_changed_source_snapshot(client, app, recorded, target):
    case = app.state.catalog.case(target["case_key"])
    case["_source"].write_text(case["_source"].read_text() + "\n# Changed after the recorded run\n")
    response = client.post("/api/tasks", json=payload(target, "full", replay=True))
    assert response.status_code == 409
    assert "different source snapshot" in response.json()["detail"]


def configure_demo(app, source_id):
    case = next(iter(app.state.catalog.cases().values()))
    path = case["_directory"] / "case_meta.json"
    metadata = json.loads(path.read_text())
    metadata["demo_source_task_id"] = source_id
    path.write_text(json.dumps(metadata))


@pytest.mark.parametrize("mode", ["live", "replay"])
def test_configured_demo_can_read_deleted_source_without_restoring_task(client, app, recorded, monkeypatch, mode):
    source_id, original = recorded
    configure_demo(app, source_id)
    monkeypatch.setattr(app.state.engine.replay, "time_scale", .003)
    assert client.delete(f"/api/tasks/{source_id}").status_code == 200
    target, = client.post("/api/repositories/resolve", json={"repository_url": "https://github.com/example/downloads"}).json()["targets"]
    body = payload(target, "full", replay=mode == "replay")
    descriptor = upload(client, "unit", "unit.sh", b"#!/bin/sh\nexit 0\n")
    body.pop("unit_test")
    body["unit_upload_id"] = descriptor["id"]
    response = client.post("/api/tasks", json=body)
    assert response.status_code == 201, response.text
    identity = response.json()["id"]
    done = wait(client, identity, lambda row: row["status"] == "completed")
    assert done["replay"]["source_task_id"] == source_id
    assert done["candidates"][0]["patch"] == original["candidates"][0]["patch"]
    assert done["candidates"][0]["validation_result"]["success"] is True
    assert done["validated"] is False
    assert done["repair_request"]["submitted_test_inputs"]["unit"]["execution_status"] == "not_run"
    assert app.state.store.validations(identity) == []
    assert source_id not in {t["id"] for t in client.get("/api/tasks").json()["items"]}
    assert client.get(f"/api/tasks/{source_id}").status_code == 404
    assert client.post(f"/api/tasks/{source_id}/replay").status_code == 404
    assert client.post(f"/api/tasks/{source_id}/resume").status_code == 404
    report = client.get(f"/api/tasks/{identity}/report").json()
    assert report["provenance"]["new_validation_performed"] is False


def test_deleted_demo_source_still_requires_validated_evidence(client, app, recorded):
    source_id, original = recorded
    configure_demo(app, source_id)
    assert client.delete(f"/api/tasks/{source_id}").status_code == 200
    original["candidates"][0]["validation_result"]["success"] = False
    target, = client.post("/api/repositories/resolve", json={"repository_url": "https://github.com/example/downloads"}).json()["targets"]
    response = client.post("/api/tasks", json=payload(target))
    assert response.status_code == 409
    assert "no validated patch" in response.json()["detail"]
    assert client.get("/api/tasks").json()["items"] == []


@pytest.mark.parametrize("mode", ["live", "replay"])
def test_configured_demo_always_reuses_the_pinned_full_successful_workflow(client, app, recorded, monkeypatch, mode):
    source_id, original = recorded
    configure_demo(app, source_id)
    # A newer run must not change which successful patch this demo presents.
    newer = app.state.store.create(original["case_key"], "full", "Newer source", stage="validation")
    app.state.store.update(newer["id"], "completed", validated=True)
    monkeypatch.setattr(app.state.engine.replay, "time_scale", .003)
    lookup = client.post("/api/repositories/resolve", json={"repository_url": "https://github.com/example/downloads"})
    assert lookup.status_code == 200
    target, = lookup.json()["targets"]
    assert target["demo_source_task_id"] == target["replay_source_id"] == source_id
    body = payload(target, "full", replay=mode == "replay")
    body.update(automatic=False, variant="df_only")
    response = client.post("/api/tasks", json=body)
    assert response.status_code == 201, response.text
    identity = response.json()["id"]
    done = wait(client, identity, lambda row: row["status"] == "completed")
    assert done["mode"] == "replay"
    assert done["automatic"] is True
    assert done["variant"] == "full"
    assert done["replay"]["source_task_id"] == source_id
    assert done["replay"]["completed_stages"] == ["diagnosis", "retrieval", "repair", "validation"]
    assert sum(done["replay"]["timings"].values()) == 75
    request = done["repair_request"]
    assert request["validation_mode"] == "full"
    assert request["demo_source_task_id"] == source_id
    assert request["poc_file"] == target["poc_file"]
    assert request["unit_test"] == target["unit_test"]
    assert done["candidates"][0]["patch"] == original["candidates"][0]["patch"]
    assert all(value == "passed" for value in done["candidates"][0]["validation_result"]["stage_status"].values())
    assert done["validated"] is False
    assert app.state.store.validations(identity) == []
    report = client.get(f"/api/tasks/{identity}/report").json()
    assert report["summary"]["outcome"] == "historical_validation_passed"
    assert report["provenance"]["new_validation_performed"] is False
    assert report["provenance"]["replay"]["source_task_id"] == source_id
    archive = zipfile.ZipFile(io.BytesIO(client.get(f"/api/tasks/{identity}/export").content))
    assert archive.read("final.patch").decode() == original["candidates"][0]["patch"]


@pytest.mark.parametrize("scope,poc_uploaded,unit_uploaded", [("poc", True, False), ("full", True, True), ("full", False, True)])
@pytest.mark.parametrize("mode", ["live", "replay"])
def test_configured_demo_preserves_submitted_inputs_and_historical_test_provenance(client, app, recorded, monkeypatch,
                                                                                scope, poc_uploaded, unit_uploaded, mode):
    configure_demo(app, recorded[0])
    monkeypatch.setattr(app.state.engine.replay, "time_scale", .003)
    target, = client.post("/api/repositories/resolve", json={"repository_url": "https://github.com/example/downloads"}).json()["targets"]
    body = payload(target, scope, replay=mode == "replay")
    contents = {}
    for kind, enabled, filename, content in (("poc", poc_uploaded, "crash.bin", b"\x00uploaded PoC\xff"),
                                            ("unit", unit_uploaded, "unit.sh", b"#!/bin/bash\nexit 42\n")):
        if enabled:
            descriptor = upload(client, kind, filename, content)
            body.pop("poc_file" if kind == "poc" else "unit_test")
            body[kind + "_upload_id"] = descriptor["id"]
            contents[kind] = (descriptor, content)
    response = client.post("/api/tasks", json=body)
    assert response.status_code == 201, response.text
    identity = response.json()["id"]
    done = wait(client, identity, lambda row: row["status"] == "completed")
    assert done["mode"] == "replay"
    assert done["replay"]["source_task_id"] == recorded[0]
    assert done["replay"]["submitted_test_inputs_executed"] is False
    request = done["repair_request"]
    assert request["validation_mode"] == scope
    assert "uploaded_tests" not in request
    assert request["historical_test_inputs"]["source_task_id"] == recorded[0]
    assert request["historical_test_inputs"]["poc_file"] == target["poc_file"]
    assert request["historical_test_inputs"]["unit_test"] == target["unit_test"]
    archive = zipfile.ZipFile(io.BytesIO(client.get(f"/api/tasks/{identity}/export").content))
    directory = app.state.store.run_dir(identity) / "input" / done["case_id"]
    for kind, (metadata, content) in contents.items():
        descriptor = request["submitted_test_inputs"][kind]
        assert descriptor["execution_status"] == "not_run"
        assert descriptor["sha256"] == metadata["sha256"]
        path = directory / descriptor["relative_path"]
        assert path.read_bytes() == content
        assert archive.read(f"submitted-test-inputs/{kind}/{path.name}") == content
        assert request["poc_file" if kind == "poc" else "unit_test"] == metadata["filename"]
        # A second presentation uses the first task's immutable upload snapshot.
        (app.state.store.directory / "uploads" / metadata["id"] / "content.bin").write_bytes(b"changed temporary upload")
    report = client.get(f"/api/tasks/{identity}/report").json()
    assert report["provenance"]["new_validation_performed"] is False
    assert report["provenance"]["replay"]["submitted_test_inputs_executed"] is False
    assert report["patch"]["final_patch"] == recorded[1]["candidates"][0]["patch"]
    assert report["summary"]["outcome"] == ("historical_validation_passed" if scope == "full" else "historical_poc_checks_passed")
    response = client.post(f"/api/tasks/{identity}/replay")
    assert response.status_code == 201, response.text
    repeated = wait(client, response.json()["id"], lambda row: row["status"] == "completed")
    repeated_dir = app.state.store.run_dir(repeated["id"]) / "input" / repeated["case_id"]
    for kind, (_, content) in contents.items():
        assert (repeated_dir / repeated["repair_request"]["submitted_test_inputs"][kind]["relative_path"]).read_bytes() == content
    assert app.state.store.validations(identity) == app.state.store.validations(repeated["id"]) == []


def test_configured_demo_retains_the_selected_scope(client, app, recorded, monkeypatch):
    configure_demo(app, recorded[0])
    monkeypatch.setattr(app.state.engine.replay, "time_scale", .003)
    target, = client.post("/api/repositories/resolve", json={"repository_url": "https://github.com/example/downloads"}).json()["targets"]
    for scope in ("patch_only", "poc", "full"):
        response = client.post("/api/tasks", json=payload(target, scope))
        assert response.status_code == 201, response.text
        done = wait(client, response.json()["id"], lambda row: row["status"] == "completed")
        assert done["repair_request"]["validation_mode"] == scope
        assert bool(done["candidates"][0]["validation_result"]) == (scope != "patch_only")
        if scope == "poc":
            assert done["candidates"][0]["validation_result"]["stage_status"]["unit"] == "not_run"


def test_configured_demo_rejects_an_unavailable_upload_without_creating_a_task(client, app, recorded):
    configure_demo(app, recorded[0])
    target, = client.post("/api/repositories/resolve", json={"repository_url": "https://github.com/example/downloads"}).json()["targets"]
    body = payload(target)
    body.pop("poc_file")
    body["poc_upload_id"] = "f" * 32
    before = len(app.state.store.tasks())
    response = client.post("/api/tasks", json=body)
    assert response.status_code == 409
    assert "uploaded test input" in response.json()["detail"]
    assert len(app.state.store.tasks()) == before


def test_configured_demo_rejects_a_source_run_from_another_case(client, app, recorded):
    other = app.state.store.create("PatchEval:another-case", "full", "Other source", stage="validation")
    app.state.store.update(other["id"], "completed", validated=True)
    configure_demo(app, other["id"])
    target, = client.post("/api/repositories/resolve", json={"repository_url": "https://github.com/example/downloads"}).json()["targets"]
    response = client.post("/api/tasks", json=payload(target))
    assert response.status_code == 409
    assert "different source target" in response.json()["detail"]


@pytest.fixture
def upload_adapter(app, target):
    """A real migrated PatchEval script shape, checked with Bash -n only."""
    from utils.case_commands import migrate_record

    case = app.state.catalog.case(target["case_key"])
    prefix = "#!/bin/bash\n# From example/local-test:latest\nset -e\ncd /workspace/downloads\ngit apply --whitespace=nowarn /workspace/fix.patch\n"
    python = "/workspace/PoC_env/CVE-2026-0001/bin/python"
    record = migrate_record({
        "programming_language": "Python",
        "poc_test_cmd": prefix + python + " -m pytest tests/test_downloads.py::test_regression\n",
        "unit_test_cmd": prefix + python + " -m pytest tests/test_downloads.py\n",
    }, dataset="PatchEval", case_id=case["case_id"], source_file=target["file"])
    (case["_directory"] / "test_cmds.json").write_text(json.dumps(record))
    return record


def upload(client, kind, filename, content):
    response = client.post("/api/test-inputs", json={
        "kind": kind, "filename": filename, "content_base64": base64.b64encode(content).decode(),
    })
    assert response.status_code == 201, response.text
    return response.json()


def test_upload_api_returns_bounded_public_metadata(client, app):
    contents = b"\x00\xff\x80test\x00"
    saved = upload(client, "poc", "regression.tiff", contents)
    assert set(saved) == {"id", "kind", "filename", "size", "sha256"}
    assert saved["size"] == len(contents)
    assert saved["sha256"] == hashlib.sha256(contents).hexdigest()
    assert (app.state.store.directory / "uploads" / saved["id"] / "content.bin").read_bytes() == contents
    assert client.post("/api/test-inputs", json={"kind": "unit", "filename": "custom.zip", "content_base64": "YQ=="}).status_code == 422
    assert client.post("/api/test-inputs", json={"kind": "poc", "filename": "../custom.bin", "content_base64": "YQ=="}).status_code == 422
    assert client.post("/api/test-inputs", json={"kind": "poc", "filename": "custom.bin", "content_base64": "bad!"}).status_code == 422
    assert client.post("/api/test-inputs", content=b"{}", headers={"Content-Type": "application/json", "Content-Length": "14050001"}).status_code == 413


@pytest.mark.parametrize("poc_uploaded,unit_uploaded,mode", [
    (True, False, "poc"), (True, False, "full"), (False, True, "full"), (True, True, "full"),
])
def test_uploaded_tests_are_bound_to_copied_commands_and_report(client, app, target, hold_workers, upload_adapter,
                                                              poc_uploaded, unit_uploaded, mode):
    request = payload(target, mode)
    source_commands = deepcopy(upload_adapter)
    expected = {}
    for kind, enabled, filename, content in (
        ("poc", poc_uploaded, "my regression.py", b"assert 2 + 2 == 4\n"),
        ("unit", unit_uploaded, "my unit.sh", b"set -e\nprintf 'test passed\\n'\n"),
    ):
        if enabled:
            info = upload(client, kind, filename, content)
            expected[kind] = (info, content)
            request.pop("poc_file" if kind == "poc" else "unit_test", None)
            request[kind + "_upload_id"] = info["id"]
    response = client.post("/api/tasks", json=request)
    assert response.status_code == 201, response.text
    identity = response.json()["id"]
    directory = app.state.store.run_dir(identity)
    case = directory / "input/CVE-2026-0001"
    saved = json.loads((directory / "repair_request.json").read_text())
    commands = json.loads((case / "test_cmds.json").read_text())
    assert set(commands["studio_uploaded_tests"]) == set(expected)
    assert set(saved["uploaded_tests"]) == set(expected)
    for kind, (info, content) in expected.items():
        descriptor = saved["uploaded_tests"][kind]
        assert descriptor["sha256"] == info["sha256"]
        assert "path" not in descriptor
        assert (case / descriptor["relative_path"]).read_bytes() == content
        native = commands["studio_uploaded_tests"][kind]
        assert native["input_mode"] == "script"
        assert native["path"] == str(case / descriptor["relative_path"])
        assert native["sha256"] == info["sha256"]
        entry = commands[kind + "_test_cmd"]
        assert info["filename"] not in entry
        assert info["sha256"] in entry
        assert f"/kea-validation/uploaded-{kind}." in entry
        assert "protocol.sh before" in entry and "protocol.sh after" in entry
        # Task snapshots survive deletion or changes to the temporary upload.
        (app.state.store.directory / "uploads" / info["id"] / "content.bin").write_bytes(b"changed after submission")
        assert (case / descriptor["relative_path"]).read_bytes() == content
    if not poc_uploaded:
        assert commands["poc_test_cmd"] == source_commands["poc_test_cmd"]
    if mode == "full" and not unit_uploaded:
        assert commands["unit_test_cmd"] == source_commands["unit_test_cmd"]
    if mode == "poc":
        assert "unit_test_cmd" not in commands
        assert [step["name"] for step in commands["validation_steps"]] == ["build_and_poc"]
    report = client.get(f"/api/tasks/{identity}/report").json()
    assert report["repair_request"]["uploaded_tests"] == saved["uploaded_tests"]
    assert json.loads((app.state.catalog.case(target["case_key"])["_directory"] / "test_cmds.json").read_text()) == source_commands


def test_upload_api_rejects_invalid_id_kind_and_tampering(client, app, target, hold_workers, upload_adapter):
    request = payload(target, "poc")
    request.pop("poc_file")
    assert client.post("/api/tasks", json={**request, "poc_upload_id": "../file"}).status_code == 422
    assert client.post("/api/tasks", json={**request, "poc_upload_id": "0" * 32}).status_code == 409
    wrong_kind = upload(client, "unit", "unit.py", b"assert True\n")
    assert client.post("/api/tasks", json={**request, "poc_upload_id": wrong_kind["id"]}).status_code == 409
    altered = upload(client, "poc", "poc.py", b"assert True\n")
    (app.state.store.directory / "uploads" / altered["id"] / "content.bin").write_bytes(b"assert False\n")
    rejected = client.post("/api/tasks", json={**request, "poc_upload_id": altered["id"]})
    assert rejected.status_code == 409
    assert "integrity" in rejected.json()["detail"]
    assert hold_workers == []


def test_uploads_cannot_conflict_with_plan_or_replay(client, app, target, hold_workers, upload_adapter):
    poc = upload(client, "poc", "poc.py", b"assert True\n")
    unit = upload(client, "unit", "unit.sh", b"exit 0\n")
    conflicts = [
        {**payload(target, "patch_only"), "poc_upload_id": poc["id"]},
        {**payload(target, "poc"), "poc_upload_id": poc["id"]},
        {**payload(target, "poc"), "unit_upload_id": unit["id"]},
        {**payload(target, "full"), "unit_upload_id": unit["id"]},
        {"case_key": target["case_key"], "poc_upload_id": poc["id"]},
    ]
    replay = payload(target, "poc", replay=True)
    replay.pop("poc_file")
    conflicts.append({**replay, "poc_upload_id": poc["id"]})
    for request in conflicts:
        assert client.post("/api/tasks", json=request).status_code == 422
    assert hold_workers == []


def test_unsupported_raw_payload_does_not_create_a_task(client, app, target, hold_workers, upload_adapter):
    poc = upload(client, "poc", "crash.tiff", b"\x00\xffTIFF")
    request = payload(target, "poc")
    request.pop("poc_file")
    response = client.post("/api/tasks", json={**request, "poc_upload_id": poc["id"]})
    assert response.status_code == 409
    assert "raw PoC" in response.json()["detail"]
    assert app.state.store.tasks() == []
    assert hold_workers == []


def test_uploaded_validation_is_not_a_prepared_replay_source(client, app, recorded, target):
    source_id = recorded[0]
    assert app.state.engine.replay.sources()[target["case_key"]]["id"] == source_id
    directory = app.state.store.run_dir(source_id)
    directory.mkdir(parents=True, exist_ok=True)
    descriptor = upload(client, "poc", "poc.py", b"assert True\n")
    (directory / "repair_request.json").write_text(json.dumps({"validation_mode": "full", "uploaded_tests": {"poc": descriptor}}))
    assert target["case_key"] not in app.state.engine.replay.sources()
    case = client.get("/api/cases").json()["items"][0]
    assert case["repository_url"] == target["repository_url"]
    assert case["replay_source_id"] is None
    response = client.post(f"/api/tasks/{source_id}/replay")
    assert response.status_code == 409
    assert "Uploaded tests require live execution" in response.json()["detail"]


def test_export_contains_verified_task_test_inputs(client, app, target, hold_workers, upload_adapter):
    poc_bytes, unit_bytes = b"assert True\n", b"exit 0\n"
    poc = upload(client, "poc", "my poc.py", poc_bytes)
    unit = upload(client, "unit", "my unit.sh", unit_bytes)
    request = payload(target)
    request.pop("poc_file")
    request.pop("unit_test")
    response = client.post("/api/tasks", json={**request, "poc_upload_id": poc["id"], "unit_upload_id": unit["id"]})
    assert response.status_code == 201, response.text
    identity = response.json()["id"]
    archive = zipfile.ZipFile(io.BytesIO(client.get(f"/api/tasks/{identity}/export").content))
    assert archive.read("test-inputs/poc/input.py") == poc_bytes
    assert archive.read("test-inputs/unit/input.sh") == unit_bytes
    report = json.loads(archive.read("repair_report.json"))
    assert report["repair_request"]["uploaded_tests"]["poc"]["sha256"] == hashlib.sha256(poc_bytes).hexdigest()
    assert report["repair_request"]["uploaded_tests"]["unit"]["sha256"] == hashlib.sha256(unit_bytes).hexdigest()
