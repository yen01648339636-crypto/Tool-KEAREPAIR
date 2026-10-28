"""Pause controls stop execution boundaries, preserve replay position and resume in place."""

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import threading
import time

import pytest

from tests.studio.test_studio import app, client, workspace
from tests.studio.test_replay import recorded, wait

ROOT = Path(__file__).resolve().parents[2]


def live_worker(app, monkeypatch, *, gates=True, steps=5):
    calls = []
    monkeypatch.setattr(app.state.engine, "preflight", lambda *args: [])
    def command(task, case_dir):
        calls.append(task["id"])
        directory = app.state.store.run_dir(task["id"])
        out = directory / "engine/cases" / case_dir.name
        code = f"""
import json,sys,time
from pathlib import Path
sys.path.insert(0,{str(ROOT)!r})
from utils.execution_control import wait_if_paused
directory=Path({str(directory)!r})
for i in range({steps}):
    (directory/'operation.json').write_text(json.dumps({{'step':i,'phase':'inflight'}}))
    time.sleep(.4)
    {'wait_if_paused()' if gates else 'pass'}
    (directory/'operation.json').write_text(json.dumps({{'step':i,'phase':'finished'}}))
out=Path({str(out)!r});out.mkdir(parents=True,exist_ok=True)
(out/'diagnosis.json').write_text(json.dumps({{'diagnostic_report':{{'summary':'Saved source diagnosis','termination_reason':'model_finished','facts':[],'tool_calls':[]}}}}))
(out/'result.json').write_text(json.dumps({{'status':'diagnosis_ready','success':False}}))
"""
        return [sys.executable, "-u", "-c", code]
    monkeypatch.setattr(app.state.engine, "command", command)
    return calls


def start_live(client, app):
    response = client.post('/api/tasks', json={'case_key':next(iter(app.state.catalog.cases())), 'automatic':False})
    assert response.status_code == 201, response.text
    return response.json()['id']


def until(predicate):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.02)
    raise AssertionError('Condition not reached')


def test_live_pause_finishes_current_operation_then_resumes_same_process(client, app, monkeypatch):
    calls = live_worker(app, monkeypatch)
    identity = start_live(client, app)
    marker = app.state.store.run_dir(identity) / 'operation.json'
    until(marker.exists)
    process = app.state.engine.processes[identity]
    response = client.post(f'/api/tasks/{identity}/pause')
    assert response.json()['status'] == 'pausing'
    paused = wait(client, identity, lambda t:t['status']=='paused')
    assert paused['pause']['paused_at'] and len(paused['pause']['intervals']) == 1
    original = marker.read_bytes()
    time.sleep(.8)
    assert marker.read_bytes() == original
    assert client.delete(f'/api/tasks/{identity}').status_code == 409
    assert client.post(f'/api/tasks/{identity}/advance', json={'stage':'diagnosis'}).status_code == 409
    assert client.post(f'/api/tasks/{identity}/pause').json()['status'] == 'paused'
    assert client.post(f'/api/tasks/{identity}/resume').json()['status'] == 'running'
    assert app.state.engine.processes[identity] is process
    assert client.post(f'/api/tasks/{identity}/pause').status_code == 200
    wait(client, identity, lambda t:t['status']=='paused')
    assert client.post(f'/api/tasks/{identity}/resume').status_code == 200
    result = wait(client, identity, lambda t:t['status']=='diagnosis_ready')
    assert len(result['pause']['intervals']) == 2
    assert all(i['finished_at'] for i in result['pause']['intervals'])
    assert calls == [identity]
    assert result['diagnosis_report']['summary'] == 'Saved source diagnosis'


def test_queued_task_can_pause_before_worker_launch(client, app, monkeypatch):
    calls = live_worker(app, monkeypatch, steps=1)
    blocker = threading.Event()
    app.state.engine.pool.submit(lambda:blocker.wait(6))
    identity = start_live(client, app)
    try:
        assert client.post(f'/api/tasks/{identity}/pause').json()['status'] == 'paused'
        blocker.set()
        time.sleep(.15)
        assert calls == [] and identity not in app.state.engine.processes
        assert client.post(f'/api/tasks/{identity}/resume').json()['status'] == 'queued'
        wait(client, identity, lambda t:t['status']=='diagnosis_ready')
        assert calls == [identity]
    finally:
        blocker.set()


def test_pause_at_subprocess_completion_defers_stage_commit(client, app, monkeypatch):
    live_worker(app, monkeypatch, gates=False, steps=1)
    identity = start_live(client, app)
    until(lambda:identity in app.state.engine.processes)
    client.post(f'/api/tasks/{identity}/pause')
    paused = wait(client, identity, lambda t:t['status']=='paused')
    assert app.state.engine.processes[identity].poll() == 0
    time.sleep(.2)
    assert client.get(f'/api/tasks/{identity}').json()['status'] == 'paused'
    client.post(f'/api/tasks/{identity}/resume')
    wait(client, identity, lambda t:t['status']=='diagnosis_ready')


def test_cancel_paused_live_task_exits_and_cannot_resume(client, app, monkeypatch):
    live_worker(app, monkeypatch)
    identity = start_live(client, app)
    until(lambda:(app.state.store.run_dir(identity)/'operation.json').exists())
    client.post(f'/api/tasks/{identity}/pause')
    wait(client, identity, lambda t:t['status']=='paused')
    process = app.state.engine.processes[identity]
    client.post(f'/api/tasks/{identity}/cancel')
    wait(client, identity, lambda t:t['status']=='cancelled')
    until(lambda:process.poll() is not None)
    assert client.post(f'/api/tasks/{identity}/resume').status_code == 409


def test_replay_freezes_milestones_and_sse_remains_open_until_resume(client, app, recorded):
    identity = client.post(f'/api/tasks/{recorded[0]}/replay').json()['id']
    wait(client, identity, lambda t:t['status']=='running')
    assert client.post(f'/api/tasks/{identity}/pause').json()['status'] == 'paused'
    before = client.get(f'/api/tasks/{identity}').json()
    time.sleep(.8)  # Longer than the entire scaled diagnosis stage.
    after = client.get(f'/api/tasks/{identity}').json()
    assert after['status'] == 'paused'
    assert after['runtime'] == before['runtime'] and after['events'] == before['events']
    assert after['replay']['completed_stages'] == before['replay']['completed_stages']
    with ThreadPoolExecutor(max_workers=1) as executor:
        events = executor.submit(client.get, f'/api/tasks/{identity}/events')
        time.sleep(.15)
        assert not events.done()
        client.post(f'/api/tasks/{identity}/resume')
        finished = wait(client, identity, lambda t:t['status']=='completed')
        assert 'event: done' in events.result(timeout=5).text
    assert finished['candidates'][0]['patch'] == recorded[1]['candidates'][0]['patch']
    assert finished['replay']['completed_stages'] == ['diagnosis','retrieval','repair','validation']
    assert finished['pause']['intervals'][0]['finished_at']


def test_cancel_paused_replay_does_not_advance(client, app, recorded):
    identity = client.post(f'/api/tasks/{recorded[0]}/replay').json()['id']
    client.post(f'/api/tasks/{identity}/pause')
    before = client.get(f'/api/tasks/{identity}').json()
    client.post(f'/api/tasks/{identity}/cancel')
    time.sleep(.15)
    after = client.get(f'/api/tasks/{identity}').json()
    assert after['status'] == 'cancelled'
    assert before['replay']['completed_stages'] == after['replay']['completed_stages']
    assert identity not in app.state.engine.replay.stops
    assert client.post(f'/api/tasks/{identity}/resume').status_code == 409


@pytest.mark.parametrize('stage', ['retrieval','repair','validation'])
def test_replay_can_pause_in_every_later_stage(client, app, recorded, stage):
    identity = client.post(f'/api/tasks/{recorded[0]}/replay').json()['id']
    wait(client, identity, lambda t:t['stage']==stage and t['status']=='running')
    client.post(f'/api/tasks/{identity}/pause')
    before = client.get(f'/api/tasks/{identity}').json()
    time.sleep(.2)
    after = client.get(f'/api/tasks/{identity}').json()
    assert after['status']=='paused' and after['stage']==stage
    assert after['runtime']==before['runtime']
    assert after['replay']['completed_stages']==before['replay']['completed_stages']
    client.post(f'/api/tasks/{identity}/resume')
    wait(client, identity, lambda t:t['status']=='completed')


def test_pause_rejects_terminal_or_unknown_tasks(client, app):
    task = app.state.store.create('fixture:case', 'full', 'fixture')
    app.state.store.update(task['id'],'completed')
    for action in ('pause','resume'):
        assert client.post(f"/api/tasks/{task['id']}/{action}").status_code == 409
        assert client.post('/api/tasks/unknown/'+action).status_code == 404


def test_recovery_marks_paused_tasks_and_validation_jobs_interrupted(app):
    task = app.state.store.create('fixture:case', 'full', 'fixture', stage='validation')
    job = app.state.store.create_validation(task['id'],1)
    app.state.store.update(task['id'],'paused')
    app.state.store.update_validation(job['id'],'paused')
    app.state.store.recover()
    assert app.state.store.task(task['id'])['status'] == 'interrupted'
    assert app.state.store.validations(task['id'])[0]['status'] == 'interrupted'
