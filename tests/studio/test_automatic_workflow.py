"""Exercise real Studio scheduling with local subprocesses and frozen replay data."""

import io
import json
import sys
import time
import zipfile

import pytest

from tests.studio.test_studio import app, client, workspace, wait_task
from tests.studio.test_replay import recorded, wait
from studio.report import build_report, render_report


def worker(app, monkeypatch, *, fail=None, success=True, incomplete=False, delay=.12):
    order = []

    def command(task, case_dir):
        stage = task["stage"]
        order.append(stage)
        directory = app.state.store.run_dir(task["id"]) / "engine/cases" / case_dir.name
        files = {}
        if stage == "diagnosis":
            files["diagnosis.json"] = {"diagnostic_report": {"summary": "Source diagnosis" if not incomplete else "",
                "termination_reason": "model_finished", "facts": [], "tool_calls": []}}
        if stage == "retrieval":
            pool = [dict(sample_id=str(i), cve_id=f"CVE-TEST-{i}", rerank_score=1-i*.01,
                         retrieval_hits=[dict(query_view=v, rank=i+1, distance=i*.1) for v in ("data_flow", "control_flow")]) for i in range(10)]
            files["retrieval.json"] = {"queries": {"data_flow": "df", "control_flow": "cf"}, "ranking": {"candidates": pool}, "final_exemplars": pool[:4]}
        if stage == "repair":
            files["attempts/1/attempt.json"] = {"candidate_id": 1, "patch": "--- a/source\n+++ b/source\n@@ -1 +1 @@\n-old\n+new\n", "validation_invoked": True,
                "validation_result": {"success": success, "stage_status": {"patch_apply": "passed", "compile": "passed", "poc": "passed" if success else "failed", "unit": "passed"},
                "stage_details": {"poc": {"stdout": "test output", "returncode": 0 if success else 1}}}}
        result = {"status": {"diagnosis": "diagnosis_ready", "retrieval": "retrieval_ready", "repair": "completed"}[stage], "success": success and stage == "repair"}
        if stage == fail:
            result.update(status="error", error="Fixture retrieval failure")
        files["result.json"] = result
        script = "import json,time\nfrom pathlib import Path\n" + f"p=Path({str(directory)!r})\ntime.sleep({delay!r})\n"
        script += f"files=json.loads({json.dumps(files)!r})\nfor name,value in files.items():\n q=p/name\n q.parent.mkdir(parents=True,exist_ok=True)\n q.write_text(json.dumps(value))\n"
        return [sys.executable, "-c", script]

    monkeypatch.setattr(app.state.engine, "command", command)
    return order


def test_one_click_runs_all_stages_and_exports_complete_report(client, app, monkeypatch):
    order = worker(app, monkeypatch)
    identity = client.post('/api/tasks', json={"case_key": "PatchEval:CVE-2026-0001"}).json()["id"]
    statuses = []
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        task = app.state.store.task(identity)
        statuses.append(task["status"])
        if task["status"] not in {"queued", "running"}:
            break
        time.sleep(.03)
    else:
        raise AssertionError("Automatic workflow did not finish")
    assert task["automatic"] and task["status"] == "completed" and task["validated"]
    assert order == ["diagnosis", "retrieval", "repair"]
    assert not set(statuses) & {"diagnosis_ready", "retrieval_ready", "patch_ready"}
    report = client.get(f'/api/tasks/{identity}/report').json()
    assert report["diagnosis"]["summary"] == "Source diagnosis"
    assert report["summary"]["retrieved_per_view"] == {"data_flow": 10, "control_flow": 10}
    assert len(report["retrieval"]["selected_after_reranking"]) == 4
    assert report["validation"]["result"]["stage_details"]["poc"]["stdout"] == "test output"
    assert report["patch"]["final_patch"].endswith('+new\n')
    assert report["summary"]["outcome"] == "validated"
    bundle = zipfile.ZipFile(io.BytesIO(client.get(f'/api/tasks/{identity}/export').content))
    assert {"repair_report.html", "repair_report.json", "final.patch"} <= set(bundle.namelist())
    assert 'Data flow · 10 examples' in bundle.read('repair_report.html').decode()
    # The finalizer runs after terminal status; wait for its durable report.
    for _ in range(50):
        if (app.state.store.run_dir(identity) / 'repair_report.json').exists():
            break
        time.sleep(.02)
    assert (app.state.store.run_dir(identity) / 'repair_report.html').is_file()


def test_failed_stage_stops_then_retry_resumes_automatic_chain(client, app, monkeypatch):
    order = worker(app, monkeypatch, fail="retrieval")
    identity = client.post('/api/tasks', json={"case_key": "PatchEval:CVE-2026-0001"}).json()["id"]
    task = wait_task(app, identity)
    assert task["status"] == "failed" and order == ["diagnosis", "retrieval"]
    order = worker(app, monkeypatch)
    assert client.post(f'/api/tasks/{identity}/advance', json={"stage": "retrieval"}).status_code == 200
    assert wait_task(app, identity)["validated"]
    assert order == ["retrieval", "repair"]


@pytest.mark.parametrize("incomplete,success", [(True, True), (False, False)])
def test_incomplete_diagnosis_and_failed_validation_are_not_success(client, app, monkeypatch, incomplete, success):
    order = worker(app, monkeypatch, incomplete=incomplete, success=success)
    identity = client.post('/api/tasks', json={"case_key": "PatchEval:CVE-2026-0001"}).json()["id"]
    task = wait_task(app, identity)
    assert not task["validated"]
    assert task["status"] == ("diagnosis_incomplete" if incomplete else "completed")
    if incomplete:
        assert order == ["diagnosis"]
    report = client.get(f'/api/tasks/{identity}/report').json()
    assert report["patch"]["final_patch"] is None
    assert not report["summary"]["has_validated_patch"]


def test_auto_cancel_does_not_start_following_stages(client, app, monkeypatch):
    order = worker(app, monkeypatch, delay=5)
    identity = client.post('/api/tasks', json={"case_key": "PatchEval:CVE-2026-0001"}).json()["id"]
    time.sleep(.15)
    assert client.post(f'/api/tasks/{identity}/cancel').status_code == 200
    assert wait_task(app, identity)["status"] == "cancelled"
    assert "retrieval" not in order and "repair" not in order


def test_no_retrieval_and_native_validation_command(client, app, monkeypatch):
    from studio.engine import Engine
    order = worker(app, monkeypatch)
    identity = client.post('/api/tasks', json={"case_key": "PatchEval:CVE-2026-0001", "variant": "no_retrieval"}).json()["id"]
    task = wait_task(app, identity)
    assert order == ["diagnosis", "repair"] and task["validated"]
    command = Engine.command(app.state.engine, task, app.state.store.run_dir(identity) / "input")
    assert "--defer-validation" not in command


def test_automatic_replay_runs_to_end_without_exposing_future_results(client, app, recorded):
    source, original = recorded
    identity = client.post(f'/api/tasks/{source}/replay').json()["id"]
    initial = client.get(f'/api/tasks/{identity}/report').json()
    assert not initial["diagnosis"] and initial["patch"]["final_patch"] is None
    assert not initial["validation"]["result"]
    part = wait(client, identity, lambda t: t["stage"] == "validation")
    assert part["status"] in {"queued", "running"} and part["candidates"][0]["patch"]
    done = wait(client, identity, lambda t: t["status"] == "completed")
    assert done["replay"]["completed_stages"] == ["diagnosis", "retrieval", "repair", "validation"]
    assert done["validated"] is False  # Playback never becomes a new live validation.
    report = client.get(f'/api/tasks/{identity}/report').json()
    assert report["summary"]["outcome"] == "historical_validation_passed"
    assert report["patch"]["final_patch"] == original["candidates"][0]["patch"]
    assert not report["provenance"]["new_validation_performed"]


def test_report_html_escapes_untrusted_source_and_model_output():
    data = {"status": "failed", "diagnosis_report": {"summary": '<script>alert("x")</script>'}, "error": '<img src=x onerror=alert(1)>'}
    html = render_report(build_report(data))
    assert '<script>' not in html and '<img' not in html
    assert '&lt;script&gt;' in html and '&lt;img' in html
