"""Platform boundaries and worker lifecycle; never call an external model."""

import io
import hashlib
import json
import pickle
from pathlib import Path
import sys
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from studio.app import create_app
from studio.catalog import Catalog, DataOnlyUnpickler
from studio.demo import SOURCE


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "repo"
    case = root / "data/processed/PatchEval/CVE-2026-0001/revision/app"
    case.mkdir(parents=True)
    (case / "downloads.py").write_text(SOURCE)
    (case.parent.parent / "test_cmds.json").write_text(json.dumps({
        "source_file": "app/downloads.py", "programming_language": "Python",
        "docker_image": "example/local-test:latest",
    }))
    index = root / "data/indices/knowledge_index"
    index.mkdir(parents=True)
    record = {
        "sample_id": "sample-1", "cve_id": "CVE-2026-1111", "language": "Python",
        "project": "local/test", "cve_description": "Path traversal",
        "buggy_code": SOURCE, "fixed_code": SOURCE + "# example\n", "patch": "",
        "abstracted_knowledge": {
            "root_cause": "Untrusted path", "fixing_strategy": "Constrain the path",
            "risky_calls": ["send_file"], "taint_flow": "Input reaches file access",
        },
    }
    (index / "metadata.pkl").write_bytes(pickle.dumps({"views": {"data_flow": [record], "control_flow": [record]}}))
    for view in ("data_flow", "control_flow"):
        (index / f"index_{view}.faiss").write_bytes(b"fixture")
    return root


@pytest.fixture
def app(workspace, monkeypatch):
    app = create_app(workspace)
    monkeypatch.setattr(app.state.engine, "public_config", lambda: {
        "provider": "fixture", "model": "local-test", "key_configured": True,
        "execution_mode": "docker", "max_iterations": 2, "docker_installed": True,
        "config_file": "config/online.yaml",
    })
    return app


@pytest.fixture
def client(app):
    with TestClient(app) as client:
        yield client


def wait_task(app, task_id):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        task = app.state.store.task(task_id)
        if task["status"] not in ("queued", "running", "cancelling"):
            return task
        time.sleep(.05)
    raise AssertionError("worker did not finish")


def fake_worker(app, monkeypatch, *, success=False, error=False):
    """A real subprocess writes canonical artifacts, without LLM or Docker."""
    def command(task, case_dir):
        out = app.state.store.run_dir(task["id"]) / "engine/cases" / case_dir.name
        payload = {"status": "error" if error else {"diagnosis": "diagnosis_ready", "retrieval": "retrieval_ready", "repair": "completed"}.get(task["stage"], "completed"), "success": success, "error": "fixture error" if error else None}
        script = (
            "import json;from pathlib import Path;"
            f"p=Path({str(out)!r});p.mkdir(parents=True,exist_ok=True);"
            "(p/'diagnosis.json').write_text(json.dumps({'diagnostic_report':{'facts':[], 'termination_reason':'model_finished', 'summary':'Untrusted input reaches file access without a guard'}}));"
            f"(p/'result.json').write_text(json.dumps({payload!r}));"
        )
        return [sys.executable, "-c", script]
    monkeypatch.setattr(app.state.engine, "command", command)


def test_live_catalog_and_keyword_filter(client):
    overview = client.get("/api/overview").json()
    assert overview["knowledge"]["samples"] == 1
    assert overview["knowledge"]["vectors"] == 2
    assert overview["case_count"] == 1
    assert client.get("/api/knowledge?q=path&language=Python").json()["total"] == 1
    assert client.get("/api/knowledge?language=Go").json()["total"] == 0
    assert client.get("/api/knowledge?offset=-1").status_code == 422
    record = client.get("/api/knowledge/sample-1").json()
    assert record["patch"].startswith("--- a/vulnerable")
    assert client.get("/api/knowledge/missing").status_code == 404


def test_catalog_does_not_expose_private_paths(client):
    case = client.get("/api/cases").json()["items"][0]
    assert not any(k.startswith("_") for k in case)
    assert case["file"] == "app/downloads.py"


def test_walkthrough_is_explicit_and_structural(client):
    data = client.get("/api/walkthrough").json()
    assert data["mode"] == "walkthrough"
    assert data["facts"] and data["observations"]
    assert all(f["location"]["start_line"] >= 1 for f in data["facts"])
    for candidate in data["candidates"]:
        assert set(candidate["validation_result"]["stage_status"].values()) == {"not_run"}
    assert client.get("/api/tasks").json()["items"] == []


@pytest.mark.parametrize("tool,extra,expected", [
    ("trace_data_flow", {"variable": "requested_path"}, "definitions_found"),
    ("is_path_reachable", {"source_line": 9}, "path_found"),
    ("inspect_api_usage", {}, "call_found"),
])
def test_interactive_analysis_uses_real_tools(client, tool, extra, expected):
    response = client.post("/api/tasks/walkthrough/analyze", json={"tool": tool, "line": 10, **extra})
    assert response.status_code == 200
    assert response.json()["result"]["status"] == expected
    assert response.json()["source_hash"]


def test_analysis_rejects_invalid_queries(client):
    assert client.post("/api/tasks/walkthrough/analyze", json={"tool": "inspect_api_usage", "line": 0}).status_code == 422
    assert client.post("/api/tasks/walkthrough/analyze", json={"tool": "trace_data_flow", "line": 9, "variable": ""}).status_code == 422
    assert client.post("/api/tasks/unknown/analyze", json={"tool": "inspect_api_usage", "line": 10}).status_code == 404


def test_export_is_truthful_and_complete(client):
    response = client.get("/api/tasks/walkthrough/export")
    assert response.status_code == 200
    archive = zipfile.ZipFile(io.BytesIO(response.content))
    assert set(archive.namelist()) == {"report.json", "repair_report.json", "repair_report.html", "README.txt", "source.original", "candidate-1.patch", "candidate-2.patch"}
    assert json.loads(archive.read("report.json"))["mode"] == "walkthrough"
    assert archive.read("source.original").decode() == SOURCE


def test_cross_origin_and_host_are_rejected(client):
    assert client.post("/api/tasks", json={"case_key": "x"}, headers={"Origin": "https://unrelated.example"}).status_code == 403
    assert client.get("/api/overview", headers={"Host": "unrelated.example"}).status_code == 400
    assert client.get("/api/overview", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.get("/api/health", headers={"Origin": "http://testserver"}).status_code == 200


def test_config_failure_prevents_execution(client, app, monkeypatch):
    monkeypatch.setattr(app.state.engine, "preflight", lambda: ["API key missing"])
    response = client.post("/api/tasks", json={"case_key": "PatchEval:CVE-2026-0001", "automatic": False})
    assert response.status_code == 409
    assert not app.state.store.tasks()


def test_task_ids_cannot_access_arbitrary_paths(client):
    for path in ("/api/tasks/not-a-task", "/api/tasks/not-a-task/logs", "/api/tasks/not-a-task/export"):
        assert client.get(path).status_code == 404
    assert client.post("/api/tasks", json={"case_key": "../outside"}).status_code == 404
    assert client.post("/api/tasks", json={"case_key": "PatchEval:CVE-2026-0001", "command": "arbitrary"}).status_code == 422


@pytest.mark.parametrize("success,error,status", [(False,False,"completed"), (True,False,"completed"), (False,True,"failed")])
def test_worker_retains_results_and_distinguishes_validation(client, app, monkeypatch, success, error, status):
    fake_worker(app, monkeypatch, success=success, error=error)
    response = client.post("/api/tasks", json={"case_key": "PatchEval:CVE-2026-0001", "automatic": False})
    assert response.status_code == 201
    task_id = response.json()["id"]
    result = wait_task(app, task_id)
    if not error:
        assert result["status"] == "diagnosis_ready" and not result["validated"]
        for stage in ("retrieval", "repair"):
            assert client.post("/api/tasks/" + task_id + "/advance", json={"stage": stage}).status_code == 200
            result = wait_task(app, task_id)
    assert result["status"] == status and result["validated"] is success
    detail = client.get("/api/tasks/" + task_id).json()
    assert detail["source"] == SOURCE
    assert detail["source_hash"] and detail["events"]
    events = client.get("/api/tasks/" + task_id + "/events").text
    assert "event: done" in events and "id: " in events
    last_id = detail["events"][-1]["seq"]
    resumed = client.get("/api/tasks/" + task_id + "/events", headers={"Last-Event-ID": str(last_id)}).text
    assert "id: " not in resumed and "event: done" in resumed
    assert client.get("/api/tasks/" + task_id + "/events", headers={"Last-Event-ID": "bad"}).status_code == 400
    # Source snapshot survives later changes to the original case.
    case = app.state.catalog.case("PatchEval:CVE-2026-0001")
    case["_source"].write_text("changed\n")
    assert client.get("/api/tasks/" + task_id).json()["source"] == SOURCE


def test_running_cancellation_terminates_worker(client, app, monkeypatch):
    monkeypatch.setattr(app.state.engine, "command", lambda task, case: [sys.executable, "-c", "import time;time.sleep(60)"])
    task_id = client.post("/api/tasks", json={"case_key": "PatchEval:CVE-2026-0001", "automatic": False}).json()["id"]
    deadline = time.monotonic() + 3
    while app.state.store.task(task_id)["status"] == "queued" and time.monotonic() < deadline:
        time.sleep(.02)
    assert client.post("/api/tasks/" + task_id + "/cancel").status_code == 200
    assert wait_task(app, task_id)["status"] == "cancelled"


def test_retry_startup_failure_replaces_the_previous_stage_error(client, app, monkeypatch):
    fake_worker(app, monkeypatch)
    task_id = client.post("/api/tasks", json={"case_key": "PatchEval:CVE-2026-0001", "automatic": False}).json()["id"]
    assert wait_task(app, task_id)["status"] == "diagnosis_ready"
    result = app.state.store.run_dir(task_id) / "engine/cases/CVE-2026-0001/result.json"
    result.write_text(json.dumps({"status": "error", "error": "OLD 600s source timeout"}))
    monkeypatch.setattr(app.state.engine, "command", lambda *args: [
        sys.executable, "-c",
        "import sys; print('ManifestMismatchError: NEW identity mismatch', file=sys.stderr); sys.exit(1)",
    ])
    assert client.post("/api/tasks/" + task_id + "/advance", json={"stage": "retrieval"}).status_code == 200
    task = wait_task(app, task_id)
    assert task["status"] == "failed" and "NEW identity mismatch" in task["error"]
    assert "OLD 600s" not in task["error"]
    assert client.get("/api/tasks/" + task_id).json()["result"]["error"] == task["error"]


def test_active_retry_hides_the_previous_result_error(client, app, monkeypatch):
    fake_worker(app, monkeypatch)
    task_id = client.post("/api/tasks", json={"case_key": "PatchEval:CVE-2026-0001", "automatic": False}).json()["id"]
    wait_task(app, task_id)
    result = app.state.store.run_dir(task_id) / "engine/cases/CVE-2026-0001/result.json"
    result.write_text(json.dumps({"status": "error", "error": "OLD 600s source timeout"}))
    monkeypatch.setattr(app.state.engine, "command", lambda *args: [
        sys.executable, "-c", "import time;time.sleep(60)",
    ])
    assert client.post("/api/tasks/" + task_id + "/advance", json={"stage": "retrieval"}).status_code == 200
    detail = client.get("/api/tasks/" + task_id).json()
    assert detail["status"] in {"queued", "running"}
    assert detail["error"] is None and detail["result"]["error"] is None
    client.post("/api/tasks/" + task_id + "/cancel")
    wait_task(app, task_id)


def test_snapshot_preserves_original_line_endings(client, app, monkeypatch):
    raw = SOURCE.replace("\n", "\r\n").encode("utf-8")
    app.state.catalog.case("PatchEval:CVE-2026-0001")["_source"].write_bytes(raw)
    fake_worker(app, monkeypatch)
    task_id = client.post("/api/tasks", json={"case_key": "PatchEval:CVE-2026-0001", "automatic": False}).json()["id"]
    wait_task(app, task_id)
    data = client.get("/api/tasks/" + task_id).json()
    assert data["source"].encode("utf-8") == raw
    assert data["source_hash"] == hashlib.sha256(raw).hexdigest()


def test_restart_marks_unfinished_work_without_rerunning(app):
    task = app.state.store.create("PatchEval:CVE-2026-0001", "full", "test")
    app.state.store.update(task["id"], "running")
    with TestClient(app):
        recovered = app.state.store.task(task["id"])
        assert recovered["status"] == "interrupted"
        assert not app.state.engine.processes


def test_secrets_are_redacted(client, app):
    secret = "test-private-credential-123456"
    app.state.engine.secrets.add(secret)
    task = app.state.store.create("PatchEval:CVE-2026-0001", "full", "test")
    directory = app.state.store.run_dir(task["id"])
    directory.mkdir(parents=True)
    (directory / "engine.log").write_text("error: " + secret)
    assert secret not in client.get("/api/tasks/" + task["id"] + "/logs").text
    assert app.state.engine.redact({"api_key": "hidden", "message": secret}) == {"api_key": "[redacted]", "message": "[redacted]"}


def test_pickle_globals_are_never_executed():
    with pytest.raises(ValueError, match="data only"):
        DataOnlyUnpickler(io.BytesIO(pickle.dumps(Path("/tmp")))).load()


def test_source_symlinks_are_not_catalogued(workspace):
    root = workspace / "data/processed/PatchEval/CVE-2026-0002"
    root.mkdir()
    (root / "test_cmds.json").write_text(json.dumps({"source_file": "outside.py"}))
    outside = workspace / "private.py"
    outside.write_text("secret")
    (root / "outside.py").symlink_to(outside)
    assert "PatchEval:CVE-2026-0002" not in Catalog(workspace).cases()


def test_stages_reject_skip_and_duplicate_and_preserve_waiting_on_restart(client, app, monkeypatch):
    fake_worker(app, monkeypatch)
    task_id = client.post("/api/tasks", json={"case_key": "PatchEval:CVE-2026-0001", "automatic": False}).json()["id"]
    assert wait_task(app, task_id)["status"] == "diagnosis_ready"
    assert client.post(f"/api/tasks/{task_id}/advance", json={"stage": "repair"}).status_code == 409
    app.state.store.recover()
    assert app.state.store.task(task_id)["status"] == "diagnosis_ready"
    monkeypatch.setattr(app.state.engine, "command", lambda task, case: [sys.executable, "-c", "import time;time.sleep(60)"])
    assert client.post(f"/api/tasks/{task_id}/advance", json={"stage": "retrieval"}).status_code == 200
    assert client.post(f"/api/tasks/{task_id}/advance", json={"stage": "retrieval"}).status_code == 409
    client.post(f"/api/tasks/{task_id}/cancel")
    assert wait_task(app, task_id)["status"] == "cancelled"


def test_incomplete_report_cannot_advance_even_if_ready_flag_is_stale(client, app, monkeypatch):
    fake_worker(app, monkeypatch)
    task_id = client.post("/api/tasks", json={"case_key": "PatchEval:CVE-2026-0001", "automatic": False}).json()["id"]
    wait_task(app, task_id)
    path = app.state.store.run_dir(task_id) / "engine/cases/CVE-2026-0001/diagnosis.json"
    path.write_text(json.dumps({"diagnostic_report": {"facts": [], "root_causes_by_view": {}, "termination_reason": "report_error"}}))
    assert client.post(f"/api/tasks/{task_id}/advance", json={"stage": "retrieval"}).status_code == 409
    detail = client.get(f"/api/tasks/{task_id}").json()
    assert detail["diagnosis_issues"] and detail["diagnosis_report"]["termination_reason"] == "report_error"


def test_diagnosis_preflight_does_not_require_docker_or_indices(app, monkeypatch):
    original = app.state.engine.public_config()
    monkeypatch.setattr(app.state.engine, "public_config", lambda: {**original, "docker_installed": False})
    monkeypatch.setattr(app.state.catalog, "knowledge_summary", lambda: {"ready": False})
    assert not app.state.engine.preflight()
    assert app.state.engine.preflight("retrieval")
    assert app.state.engine.preflight("repair")


def saved_candidate(app):
    """A generated candidate with an environment error, eligible for replay."""
    import difflib
    from utils.experiment_store import digest

    task = app.state.store.create("PatchEval:CVE-2026-0001", "full", "fixture", stage="repair")
    app.state.store.update(task["id"], "completed")
    directory = app.state.store.run_dir(task["id"])
    case = directory / "engine/cases/CVE-2026-0001"
    candidate = case / "attempts/8"
    candidate.mkdir(parents=True)
    patch_text = "".join(difflib.unified_diff(SOURCE.splitlines(True), (SOURCE + "# replay\n").splitlines(True),
                                           fromfile="a/app/downloads.py", tofile="b/app/downloads.py"))
    (directory / "input.json").write_text(json.dumps({"source": SOURCE, "source_hash": digest(SOURCE),
        "case_id": case.name, "file": "app/downloads.py", "language": "Python"}))
    (case / "source.original").write_bytes(SOURCE.encode())
    (case / "source.json").write_text(json.dumps({"sha256": digest(SOURCE)}))
    command = '\n'.join(['set -e', 'bash /kea-validation/protocol.sh apply "$PWD"',
                         'bash /kea-validation/protocol.sh before "$PWD"',
                         'bash /kea-validation/protocol.sh after "$PWD"'])
    (case / "inputs.json").write_text(json.dumps({"effective_validation": {
        "cve_id": case.name, "repo_relpath": "app/downloads.py", "docker_image": "fixture:local",
        "compile_command": command, "poc_test_command": command, "unit_test_command": command,
    }}))
    (directory / "engine/config_snapshot.yaml").write_text(
        'online:\n  phase3_repair:\n    validation:\n      compiler: gcc\n      compile_timeout: 10\n      test_timeout: 10\n')
    original = {"candidate_id": 8, "patch": patch_text, "raw_response": patch_text,
        "validation_result": {"success": False, "raw_patch_hash": digest(patch_text),
                              "effective_patch_hash": digest(patch_text)}}
    (candidate / "attempt.json").write_text(json.dumps(original))
    for name in ("raw.patch", "effective.patch"):
        (candidate / name).write_bytes(patch_text.encode())
    return task["id"], case


def replay_worker(app, monkeypatch):
    """Real subprocess + native source protocol; substitute only Docker execution."""
    project_root = Path(__file__).resolve().parents[2]

    def command(task_id, case, job):
        output = app.state.engine.validation_dir(task_id, job)
        script = f'''
import sys
sys.path.insert(0, {str(project_root)!r})
from unittest.mock import patch
from scripts import validate_saved_patch as replay
from tests.container_fixtures import DockerSandbox
validator = replay.ProgressValidator(execution_mode="local")
sandbox = DockerSandbox({SOURCE!r})
with patch.object(replay, "ProgressValidator", return_value=validator), patch.object(validator, "_check_docker_available"), patch.object(validator, "_get_docker_subprocess_env", return_value={{}}), patch.object(validator, "_image_identity", return_value={{"image_id": "sha256:" + "a" * 64}}), patch("Online.phase3_repair.validator.subprocess.run", side_effect=sandbox):
    result = replay.validate_saved({str(case)!r}, {job['candidate_id']!r}, {str(output)!r})
sys.exit(0 if result["success"] else 1)
'''
        return [sys.executable, "-u", "-c", script]

    monkeypatch.setattr(app.state.engine, "validation_command", command)
    monkeypatch.setattr(app.state.engine, "command", lambda *a: pytest.fail("validation must not invoke the online pipeline"))


def test_platform_validates_saved_candidate_and_preserves_history(client, app, monkeypatch):
    task_id, case = saved_candidate(app)
    original = {p.relative_to(case): p.read_bytes() for p in case.rglob("*") if p.is_file()}
    replay_worker(app, monkeypatch)
    monkeypatch.setattr(app.state.engine, "public_config", lambda: (_ for _ in ()).throw(AssertionError("model config is not needed")))
    monkeypatch.setattr(app.state.catalog, "knowledge_summary", lambda: {"ready": False})
    for count in (1, 2):
        response = client.post(f"/api/tasks/{task_id}/validate", json={"candidate_id": 8})
        assert response.status_code == 202, response.text
        finished = wait_task(app, task_id)
        assert finished["status"] == "completed" and finished["validated"]
        detail = client.get(f"/api/tasks/{task_id}").json()
        candidate = detail["candidates"][0]
        assert candidate["validation_result"]["success"]
        assert set(candidate["validation_result"]["stage_status"].values()) == {"passed"}
        assert candidate["original_validation_result"]["success"] is False
        assert len(candidate["validation_runs"]) == count
        assert all(j["status"] == "completed" for j in candidate["validation_runs"])
        assert original == {p.relative_to(case): p.read_bytes() for p in case.rglob("*") if p.is_file()}
    job = app.state.store.validations(task_id)[-1]
    output = app.state.engine.validation_dir(task_id, job)
    assert json.loads((output / "progress.json").read_text())["stage_status"]["unit"] == "passed"
    # Persisted state and result are still visible after constructing a new engine.
    reopened = create_app(app.state.engine.root)
    assert reopened.state.engine.detail(task_id)["validated"]
    reopened.state.engine.close()
    # An altered saved log can no longer support a positive claim in the UI.
    (output / "cases/CVE-2026-0001/attempts/8/unit.log").write_text("changed evidence")
    detail = client.get(f"/api/tasks/{task_id}").json()
    assert not detail["validated"]
    assert detail["candidates"][0]["latest_validation"]["status"] == "failed"


def test_platform_validation_failure_is_not_passed(client, app, monkeypatch):
    task_id, case = saved_candidate(app)
    inputs = json.loads((case / "inputs.json").read_text())
    inputs["effective_validation"]["poc_test_command"] += "\nexit 1\n"
    (case / "inputs.json").write_text(json.dumps(inputs))
    replay_worker(app, monkeypatch)
    assert client.post(f"/api/tasks/{task_id}/validate", json={"candidate_id": 8}).status_code == 202
    finished = wait_task(app, task_id)
    assert finished["status"] == "completed" and not finished["validated"]
    stages = client.get(f"/api/tasks/{task_id}").json()["candidates"][0]["validation_result"]["stage_status"]
    assert stages == {"patch_apply": "passed", "compile": "passed", "poc": "failed", "unit": "not_run"}


def test_platform_validation_rejects_invalid_candidates_and_cancels(client, app, monkeypatch):
    task_id, case = saved_candidate(app)
    for body, status_code in (({"candidate_id": 0}, 422), ({"candidate_id": True}, 422),
                              ({"candidate_id": "8"}, 422), ({"candidate_id": 99}, 409),
                              ({"candidate_id": 8, "command": "arbitrary"}, 422)):
        assert client.post(f"/api/tasks/{task_id}/validate", json=body).status_code == status_code
    assert client.post("/api/tasks/missing/validate", json={"candidate_id": 8}).status_code == 404
    assert client.post("/api/tasks/walkthrough/validate", json={"candidate_id": 1}).status_code == 404
    monkeypatch.setattr(app.state.engine, "validation_command", lambda *a: [sys.executable, "-c", "import time;time.sleep(60)"])
    assert client.post(f"/api/tasks/{task_id}/validate", json={"candidate_id": 8}).status_code == 202
    assert client.post(f"/api/tasks/{task_id}/validate", json={"candidate_id": 8}).status_code == 409
    assert client.post(f"/api/tasks/{task_id}/advance", json={"stage": "repair"}).status_code == 409
    assert client.post(f"/api/tasks/{task_id}/cancel").status_code == 200
    assert wait_task(app, task_id)["status"] == "cancelled"
    assert app.state.store.validations(task_id)[-1]["status"] == "cancelled"


def test_restart_marks_validation_interrupted(app):
    task_id, _ = saved_candidate(app)
    job = app.state.store.create_validation(task_id, 8)
    app.state.store.update(task_id, "running", stage="validation")
    app.state.store.update_validation(job["id"], "running")
    app.state.store.recover()
    assert app.state.store.task(task_id)["status"] == "interrupted"
    assert app.state.store.validations(task_id)[-1]["status"] == "interrupted"
    assert not app.state.engine.processes


def test_old_source_task_cannot_revalidate_after_case_alignment(client, app):
    task_id, _ = saved_candidate(app)
    source = app.state.catalog.case("PatchEval:CVE-2026-0001")["_source"]
    source.write_text(SOURCE + "# aligned container version\n")
    response = client.post(f"/api/tasks/{task_id}/validate", json={"candidate_id": 8})
    assert response.status_code == 409
    assert "Create a new task" in response.json()["detail"]
    assert not app.state.store.validations(task_id)
    assert client.get(f"/api/tasks/{task_id}").json()["source_snapshot_stale"] is True


def test_generated_patch_waits_for_explicit_validation(client, app, monkeypatch):
    from Online.phase3_repair import RepairAgent
    from tests.test_diff_repair import ScriptLLM
    from utils.telemetry import Recorder
    from scripts.validate_saved_patch import load_candidate

    task_id, case = saved_candidate(app)
    old = json.loads((case / "attempts/8/attempt.json").read_text())
    info = json.loads((case / "inputs.json").read_text())["effective_validation"]
    with Recorder(case, case_id=case.name).activate():
        generated = RepairAgent(ScriptLLM([old["patch"]]), None).repair(
            SOURCE, [], project_info=info, defer_validation=True)
    candidate = generated["selected_candidate"]
    app.state.store.update(task_id, "patch_ready", stage="repair", validated=False)
    assert "--defer-validation" in app.state.engine.command(app.state.store.task(task_id), case)
    replay_worker(app, monkeypatch)
    for _ in range(2):
        data = client.get(f"/api/tasks/{task_id}").json()
        assert data["status"] == "patch_ready" and not data["validated"]
        assert data["validation_runs"] == []
        assert data["candidates"][-1]["patch"] == old["patch"]
        assert set(data["candidates"][-1]["validation_result"]["stage_status"].values()) == {"not_run"}
    assert load_candidate(case, candidate)[1] == old["patch"]
    original = (case / f"attempts/{candidate}/effective.patch").read_bytes()
    assert client.post(f"/api/tasks/{task_id}/validate", json={"candidate_id": candidate}).status_code == 202
    finished = wait_task(app, task_id)
    assert finished["status"] == "completed" and finished["validated"]
    assert (case / f"attempts/{candidate}/effective.patch").read_bytes() == original
    data = client.get(f"/api/tasks/{task_id}").json()
    assert data["candidates"][-1]["validation_result"]["success"]
    assert len(data["validation_runs"]) == 1


def test_worker_accepts_patch_ready_as_review_boundary(client, app, monkeypatch):
    fake_worker(app, monkeypatch)
    original_command = app.state.engine.command
    def generation_command(task, case_dir):
        command = original_command(task, case_dir)
        if task["stage"] == "repair":
            command[-1] = command[-1].replace("'status': 'completed'", "'status': 'patch_ready'")
        return command
    monkeypatch.setattr(app.state.engine, "command", generation_command)
    task_id = client.post("/api/tasks", json={"case_key": "PatchEval:CVE-2026-0001", "automatic": False}).json()["id"]
    assert wait_task(app, task_id)["status"] == "diagnosis_ready"
    for stage, status in [("retrieval", "retrieval_ready"), ("repair", "patch_ready")]:
        assert client.post(f"/api/tasks/{task_id}/advance", json={"stage": stage}).status_code == 200
        task = wait_task(app, task_id)
        assert task["status"] == status and not task["validated"]
    assert client.get(f"/api/tasks/{task_id}").json()["validation_runs"] == []
