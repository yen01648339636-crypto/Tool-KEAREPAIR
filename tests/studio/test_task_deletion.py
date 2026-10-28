"""Entry deletion must persist without destroying saved evidence or active work."""

import sqlite3
import json

import pytest

from studio.store import Store
from tests.studio.test_studio import app, client, workspace


def saved_task(app, status="completed", *, mode="live"):
    store = app.state.store
    task = store.create("PatchEval:CVE-2026-0001", "full", "CVE-2026-0001", mode=mode)
    store.update(task["id"], status)
    return task["id"]


def test_delete_removes_only_selected_entry_and_preserves_artifacts(app, client):
    store = app.state.store
    identity, other = saved_task(app), saved_task(app)
    directory = store.run_dir(identity)
    directory.mkdir(parents=True)
    (directory / "report.json").write_text('{"evidence":"original"}')
    source = app.state.catalog.case("PatchEval:CVE-2026-0001")["_source"]
    original_source = source.read_bytes()
    knowledge = client.get("/api/knowledge").json()
    job = store.create_validation(identity, 1)
    store.update_validation(job["id"], "completed")

    response = client.delete(f"/api/tasks/{identity}")
    assert response.status_code == 200
    assert response.json() == {"id": identity, "deleted": True}
    assert [t["id"] for t in client.get("/api/tasks").json()["items"]] == [other]
    assert [t["id"] for t in client.get("/api/overview").json()["tasks"]] == [other]
    for suffix in ("", "/logs", "/events", "/export"):
        assert client.get(f"/api/tasks/{identity}{suffix}").status_code == 404
    assert client.post(f"/api/tasks/{identity}/advance", json={"stage": "diagnosis"}).status_code == 404
    assert client.delete(f"/api/tasks/{identity}").status_code == 404
    assert (directory / "report.json").read_text() == '{"evidence":"original"}'
    assert source.read_bytes() == original_source
    assert client.get("/api/knowledge").json() == knowledge
    assert store.validations(identity)[0]["status"] == "completed"
    assert store.events(identity)

    reopened = Store(store.directory)
    reopened.recover()
    assert [t["id"] for t in reopened.tasks()] == [other]
    with pytest.raises(KeyError):
        reopened.task(identity)


@pytest.mark.parametrize("mode", ["live", "replay"])
@pytest.mark.parametrize("status", ["queued", "running", "cancelling"])
def test_active_entries_cannot_be_deleted(app, client, mode, status):
    identity = saved_task(app, status, mode=mode)
    response = client.delete(f"/api/tasks/{identity}")
    assert response.status_code == 409
    assert "still running" in response.json()["detail"]
    assert app.state.store.task(identity)["status"] == status
    app.state.store.update(identity, "cancelled")


def test_active_validation_and_finishing_worker_block_deletion(app, client):
    identity = saved_task(app)
    job = app.state.store.create_validation(identity, 1)
    assert client.delete(f"/api/tasks/{identity}").status_code == 409
    app.state.store.update_validation(job["id"], "completed")
    app.state.engine.processes[identity] = object()
    try:
        assert client.delete(f"/api/tasks/{identity}").status_code == 409
    finally:
        app.state.engine.processes.pop(identity)
    assert client.delete(f"/api/tasks/{identity}").status_code == 200


def test_cancelled_queued_workers_ignore_deleted_entries(app, client):
    identity = saved_task(app, "cancelled")
    directory = app.state.store.run_dir(identity)
    job = app.state.store.create_validation(identity, 1)
    app.state.store.update_validation(job["id"], "cancelled")
    assert client.delete(f"/api/tasks/{identity}").status_code == 200
    app.state.engine.run(identity, directory)
    app.state.engine.run_validation(identity, directory, job)
    assert app.state.store.tasks() == []


def test_delete_rejects_cross_origin_and_unknown_identifiers(app, client):
    identity = saved_task(app)
    assert client.delete(f"/api/tasks/{identity}", headers={"Origin": "https://unrelated.example"}).status_code == 403
    assert client.delete("/api/tasks/not-a-task").status_code == 404
    assert client.delete("/api/tasks/walkthrough").status_code == 404
    assert app.state.store.task(identity)


def test_migration_keeps_existing_tasks_visible(tmp_path):
    directory = tmp_path / "old-store"
    directory.mkdir()
    with sqlite3.connect(directory / "studio.sqlite3") as con:
        con.executescript("""
            CREATE TABLE tasks (
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                status TEXT NOT NULL, case_key TEXT NOT NULL, variant TEXT NOT NULL,
                title TEXT NOT NULL, error TEXT, validated INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO tasks VALUES('old-task','2026-01-01','2026-01-01','completed','case','full','Saved task',NULL,0);
        """)
    store = Store(directory)
    assert [t["id"] for t in store.tasks()] == ["old-task"]
    store.delete("old-task")
    assert Store(directory).tasks() == []


def test_archived_source_detail_is_read_only_and_not_a_public_task(app, client):
    engine, store = app.state.engine, app.state.store
    identity = saved_task(app)
    directory = store.run_dir(identity)
    directory.mkdir(parents=True)
    (directory / "input.json").write_text(json.dumps({"source": "saved source", "dataset": "PatchEval"}))
    (directory / "repair_request.json").write_text(json.dumps({"validation_mode": "full"}))
    (directory / "task_control.json").write_text(json.dumps({"intervals": []}))
    case = directory / "engine/cases/CVE-2026-0001"
    case.mkdir(parents=True)
    (case / "diagnosis.json").write_text(json.dumps({"diagnostic_report": {"summary": "Saved diagnosis"}}))
    store.delete(identity)
    with store.connect() as con:
        before = dict(con.execute("SELECT * FROM tasks WHERE id=?", (identity,)).fetchone())
    archived = engine.detail(identity, include_deleted=True)
    assert archived["source"] == "saved source"
    assert archived["diagnosis_report"]["summary"] == "Saved diagnosis"
    assert archived["repair_request"] == {"validation_mode": "full"}
    assert archived["pause"] == {"intervals": []}
    with store.connect() as con:
        assert dict(con.execute("SELECT * FROM tasks WHERE id=?", (identity,)).fetchone()) == before
    with pytest.raises(KeyError):
        store.run_dir(identity)
    with pytest.raises(KeyError):
        store.run_dir("../unowned", include_deleted=True)
    assert client.get(f"/api/tasks/{identity}?include_deleted=true").status_code == 404
