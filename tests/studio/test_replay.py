"""Paced historical playback must not run the engine or expose future results."""

from copy import deepcopy
import hashlib
import io
import json
import time
import zipfile

import pytest

from tests.studio.test_studio import app, client, workspace
from studio.replay import TIMINGS


@pytest.fixture
def recorded(app, monkeypatch):
    engine, store = app.state.engine, app.state.store
    key = next(iter(engine.catalog.cases()))
    case = engine.catalog.case(key)
    task = store.create(key, "full", case["case_id"], stage="validation")
    store.update(task["id"], "completed", validated=True)
    source = case["_source"].read_text()
    pool = [dict(sample_id=str(i), cve_id=f"CVE-2026-{i:04d}", views={}, rerank_score=.8,
                 retrieval_hits=[dict(query_view=v, rank=i+1, distance=.2) for v in ("data_flow", "control_flow")])
            for i in range(10)]
    report = dict(summary="Historical diagnosis", termination_reason="model_finished",
                  facts=[{"statement": "Historical fact"}], tool_calls=[{"tool": "trace_data_flow"}])
    validation = dict(success=True, stage_status=dict.fromkeys(("patch_apply", "compile", "poc", "unit"), "passed"),
                      stage_details={name: {"stdout": f"saved {name} output", "duration_seconds": 123}
                                     for name in ("patch_apply", "compile", "poc", "unit")})
    data = dict(**store.task(task["id"]), case_id=case["case_id"], language="Python", file=case["file"], dataset="PatchEval",
                source=source, source_hash=hashlib.sha256(source.encode()).hexdigest(), diagnosis_issues=[],
                diagnosis_report=report, retrieval=dict(queries={"data_flow": "df query", "control_flow": "cf query"},
                ranking={"candidates": pool}, final_exemplars=pool[:4]),
                candidates=[dict(candidate_id=2, patch="saved diff", explanation="saved explanation",
                                 validation_result=validation, latest_validation={"status": "completed"})])
    real_detail = engine.detail
    def detail(identity, **options):
        store.task(identity, include_deleted=options.get("include_deleted", False))
        return deepcopy(data) if identity == task["id"] else real_detail(identity, **options)
    monkeypatch.setattr(engine, "detail", detail)
    monkeypatch.setattr(engine.replay, "time_scale", .04)
    def forbidden(*args, **kwargs):
        raise AssertionError("Replay called a live execution entry point")
    for method in ("submit", "run", "run_validation", "command", "validation_command", "preflight"):
        monkeypatch.setattr(engine, method, forbidden)
    return task["id"], data


def wait(client, identity, predicate):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        response = client.get('/api/tasks/' + identity)
        assert response.status_code == 200, response.text
        data = response.json()
        if predicate(data):
            return data
        time.sleep(.015)
    raise AssertionError(f"Replay did not reach milestone: {data['status']}, {data['stage']}")


def test_repository_replay_retains_its_display_name_and_internal_case(app, client, recorded):
    source_id, original = recorded
    request = {"display_name": "libtiff", "validation_mode": "patch_only"}
    task = app.state.engine.replay.submit(source_id, repair_request=request)
    assert task["title"] == "libtiff"
    assert task["case_key"] == original["case_key"]
    detail = client.get(f"/api/tasks/{task['id']}").json()
    assert detail["case_id"] == original["case_id"]
    assert detail["repair_request"] == request


def test_full_replay_gates_real_records_and_requires_manual_validation(app, client, recorded):
    source_id, original = recorded
    before = json.dumps(original, sort_keys=True)
    response = client.post('/api/tasks/' + source_id + '/replay?automatic=false')
    assert response.status_code == 201, response.text
    identity = response.json()['id']
    start = client.get('/api/tasks/' + identity).json()
    assert start['mode'] == 'replay'
    assert start['diagnosis_report'] == {} and start['retrieval'] == {} and start['candidates'] == []
    assert start['replay']['timings'] == TIMINGS
    assert client.post(f'/api/tasks/{identity}/advance', json={'stage': 'repair'}).status_code == 409
    assert client.post(f'/api/tasks/{identity}/validate', json={'candidate_id': 2}).status_code == 409
    ready = wait(client, identity, lambda t: t['status'] == 'diagnosis_ready')
    assert ready['diagnosis_report'] == original['diagnosis_report']
    assert client.post(f'/api/tasks/{identity}/advance', json={'stage': 'retrieval'}).status_code == 200
    part = wait(client, identity, lambda t: t['retrieval_progress'].get('completed_views') == ['data_flow'])
    assert part['exemplars'] == [] and part['retrieval'] == {} and part['candidates'] == []
    assert len(part['retrieval_progress']['candidates']) == 10
    assert all('rerank_score' not in c and [h['query_view'] for h in c['retrieval_hits']] == ['data_flow']
               for c in part['retrieval_progress']['candidates'])
    both = wait(client, identity, lambda t: len(t['retrieval_progress'].get('completed_views', [])) == 2)
    assert both['exemplars'] == []
    ready = wait(client, identity, lambda t: t['status'] == 'retrieval_ready')
    assert len(ready['exemplars']) == 4
    assert ready['retrieval'] == original['retrieval']
    assert client.post(f'/api/tasks/{identity}/advance', json={'stage': 'repair'}).status_code == 200
    ready = wait(client, identity, lambda t: t['status'] == 'patch_ready')
    assert ready['candidates'][0]['patch'] == 'saved diff'
    assert ready['candidates'][0]['validation_result'] is None
    time.sleep(.1)
    assert client.get(f'/api/tasks/{identity}').json()['status'] == 'patch_ready'
    assert client.post(f'/api/tasks/{identity}/validate', json={'candidate_id': 99}).status_code == 409
    assert client.post(f'/api/tasks/{identity}/validate', json={'candidate_id': 2}).status_code == 202
    live = wait(client, identity, lambda t: t['runtime'].get('validation_progress', {}).get('step') == 'compile')
    progress = live['runtime']['validation_progress']
    assert progress['stage_status']['source_prepare'] == 'passed'
    assert progress['stage_status']['patch_apply'] == 'passed'
    assert progress['stage_status']['compile'] == 'running'
    assert progress['stage_status']['poc'] == 'not_run'
    assert 'saved poc output' not in json.dumps(live)
    done = wait(client, identity, lambda t: t['status'] == 'completed')
    assert done['candidates'][0]['validation_result'] == original['candidates'][0]['validation_result']
    assert done['validated'] is False and done['result']['success'] is False
    assert done['result']['historical_success'] is True
    assert app.state.store.validations(identity) == []
    assert not (app.state.store.run_dir(identity) / 'engine').exists()
    archive = zipfile.ZipFile(io.BytesIO(client.get(f'/api/tasks/{identity}/export').content))
    assert json.loads(archive.read('report.json'))['mode'] == 'replay'
    assert b'performs no new validation' in archive.read('README.txt')
    assert json.dumps(original, sort_keys=True) == before


def test_cancel_retry_refresh_and_repeat_keep_frozen_record(app, client, recorded):
    source_id, original = recorded
    identity = client.post(f'/api/tasks/{source_id}/replay?automatic=false').json()['id']
    assert client.post(f'/api/tasks/{identity}/cancel').json()['status'] == 'cancelled'
    # Changing source task contents cannot change an existing playback snapshot.
    original['diagnosis_report']['summary'] = 'CHANGED ORIGINAL'
    assert client.get(f'/api/tasks/{identity}').json()['diagnosis_report'] == {}
    assert client.post(f'/api/tasks/{identity}/advance', json={'stage': 'diagnosis'}).status_code == 200
    ready = wait(client, identity, lambda t: t['status'] == 'diagnosis_ready')
    assert ready['diagnosis_report']['summary'] == 'Historical diagnosis'
    again = client.post(f'/api/tasks/{identity}/replay?automatic=false').json()['id']
    assert again != identity
    assert client.get(f'/api/tasks/{again}').json()['candidates'] == []
    ready = wait(client, again, lambda t: t['status'] == 'diagnosis_ready')
    assert ready['diagnosis_report']['summary'] == 'Historical diagnosis'


def test_case_entry_defaults_are_available_without_online_preflight(app, client, recorded):
    source_id, original = recorded
    case = client.get('/api/cases').json()['items'][0]
    assert case['replay_source_id'] == source_id
    response = client.post('/api/tasks', json={'case_key': case['key'], 'mode': 'replay', 'automatic': False})
    assert response.status_code == 201 and response.json()['mode'] == 'replay'
    identity = response.json()['id']
    client.post(f'/api/tasks/{identity}/cancel')
    assert client.post('/api/tasks', json={'case_key': case['key'], 'mode': 'replay', 'variant': 'df_only'}).status_code == 409
    assert client.post('/api/tasks', json={'case_key': case['key'], 'mode': 'unknown'}).status_code == 422


def test_incomplete_or_unverified_sources_are_rejected(app, client, recorded):
    source_id, original = recorded
    original['candidates'][0]['validation_result']['success'] = False
    assert client.post(f'/api/tasks/{source_id}/replay?automatic=false').status_code == 409
    original['candidates'][0]['validation_result']['success'] = True
    original['retrieval']['ranking']['candidates'] = []
    assert client.post(f'/api/tasks/{source_id}/replay?automatic=false').status_code == 409
    app.state.store.update(source_id, 'failed')
    assert client.post(f'/api/tasks/{source_id}/replay?automatic=false').status_code == 409


def test_changed_bundle_is_rejected_and_restart_keeps_stage_boundary(app, client, recorded):
    identity = client.post(f'/api/tasks/{recorded[0]}/replay?automatic=false').json()['id']
    client.post(f'/api/tasks/{identity}/cancel')
    app.state.store.update(identity, 'running')
    app.state.store.recover()
    assert client.get(f'/api/tasks/{identity}').json()['status'] == 'interrupted'
    assert client.post(f'/api/tasks/{identity}/advance', json={'stage': 'diagnosis'}).status_code == 200
    wait(client, identity, lambda t: t['status'] == 'diagnosis_ready')
    path = app.state.store.run_dir(identity) / 'replay_bundle.json'
    path.write_text(path.read_text() + ' ')
    assert client.get(f'/api/tasks/{identity}').status_code == 409
