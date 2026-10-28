"""Manual additions use real incremental FAISS persistence with local model fixtures."""

import base64
import json
from pathlib import Path
import sys
import time

from fastapi.testclient import TestClient
import numpy as np
import pytest

from Offline import IndexBuilder, MultiViewGenerator, VectorStore, ViewDistillation
from studio.app import create_app
from tests.offline_fixtures import KnowledgeLLM, LocalEmbedding, source_sample
from utils.knowledge import normalize_sample
from utils.knowledge_index import resolve_knowledge_index
from utils.experiment_manifest import write_json_atomic

ROOT = Path(__file__).resolve().parents[2]


def sample_builder():
    llm = KnowledgeLLM()
    return IndexBuilder(MultiViewGenerator(llm), ViewDistillation(llm), VectorStore(), LocalEmbedding())


def fixture_workspace(directory):
    (directory / "config").mkdir(parents=True)
    (directory / "config/offline.yaml").write_text(
        f"extends: {ROOT / 'config/base.yaml'}\nmodels:\n  llm:\n    provider: mock\n    model_name: local\n  embeddings:\n    model_name: local-embedding\n"
    )
    index = directory / "data/indices/knowledge_index"
    sample_builder().build_from_dataset([source_sample("base")], index)
    return directory


def local_command(service, identity, base, output, *, delay=0):
    # Exercise the exact worker entry point and incremental builder, replacing only models.
    directory = service.directory / identity
    code = (
        "import sys,time;sys.path.insert(0," + repr(str(ROOT)) + ");"
        "from tests.offline_fixtures import KnowledgeLLM,LocalEmbedding;"
        "import scripts.run_offline as pipeline;"
        "pipeline.LLMInterface=lambda **kwargs:KnowledgeLLM();"
        "pipeline.EmbeddingModel=lambda **kwargs:LocalEmbedding();"
        "from scripts.extend_knowledge import build_extension;"
        f"time.sleep({delay});"
        f"build_extension({str(directory / 'input.json')!r},{str(base)!r},{str(output)!r},"
        f"{str(directory / 'progress.json')!r},{str(service.config)!r})"
    )
    return [sys.executable, "-c", code]


def addition(code="copy(new_input);\n", cve="CVE-2026-5555"):
    pair = normalize_sample(source_sample(code=code))
    upload = lambda name, text: {"filename": name, "content_base64": base64.b64encode(text.encode()).decode()}
    return {"cve_id": cve, "cve_description": pair["cve_description"], "project": "manual/project", "language": "c",
            "source": upload("source.c", code), "patch": upload("fix.patch", pair["patch"])}


@pytest.fixture
def service(tmp_path, monkeypatch):
    root = fixture_workspace(tmp_path)
    app = create_app(root)
    manager = app.state.knowledge_builds
    monkeypatch.setattr(manager, "command", lambda identity, base, output: local_command(manager, identity, base, output))
    monkeypatch.setattr(app.state.engine, "public_config", lambda: {})
    monkeypatch.setattr(app.state.engine, "preflight", lambda: [])
    with TestClient(app) as client:
        yield app, manager, client


def wait_build(client, identity):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        job = client.get("/api/knowledge-builds/" + identity).json()
        if job["status"] not in {"queued", "running"}:
            return job
        time.sleep(.1)
    raise AssertionError("Knowledge worker did not finish")


def test_success_preserves_base_searches_new_sample_and_extends_again(service):
    app, manager, client = service
    base = app.state.catalog.indices
    original = {p.name: p.read_bytes() for p in base.iterdir() if p.is_file() and p.name != ".extension.lock"}
    assert client.get("/api/knowledge").json()["total"] == 1  # warm cache
    for n in (1, 2):
        response = client.post("/api/knowledge-builds", json=addition(f"copy(input_{n});\n", f"CVE-2026-555{n}"))
        assert response.status_code == 202, response.text
        job = wait_build(client, response.json()["id"])
        assert job["status"] == "completed", job
        assert job["samples_added"] == 1 and job["vectors_added"] == 2
        assert len(job["events"]) >= 9
        assert client.get("/api/knowledge").json()["total"] == n + 1
        assert client.get("/api/overview").json()["knowledge"]["samples"] == n + 1
        assert client.get("/api/knowledge?q=" + job["cve_id"]).json()["total"] == 1
        record = client.get("/api/knowledge/" + job["sample_id"]).json()
        assert record["fixed_code"] == "check(length);\n" + f"copy(input_{n});\n"
        vectors = VectorStore()
        vectors.load(resolve_knowledge_index(base))
        for view in ("data_flow", "control_flow"):
            _, rows = vectors.search(view, np.ones(384), k=10)
            assert job["sample_id"] in {row["sample_id"] for row in rows}
    assert all((base / name).read_bytes() == data for name, data in original.items())
    assert len(client.get("/api/knowledge-builds").json()["items"]) == 2
    duplicate = client.post("/api/knowledge-builds", json=addition("copy(input_1);\n", "CVE-2026-5551"))
    assert duplicate.status_code == 409


@pytest.mark.parametrize("kind", ["mismatched_patch", "binary", "oversized", "empty", "filename", "invalid_cve", "missing_description", "base64"])
def test_invalid_inputs_do_not_start_a_build(service, kind):
    app, manager, client = service
    body = addition()
    if kind == "mismatched_patch":
        body["source"]["content_base64"] = base64.b64encode(b"different();\n").decode()
    elif kind == "binary":
        body["source"]["content_base64"] = base64.b64encode(b"code\0\xff").decode()
    elif kind == "oversized":
        body["source"]["content_base64"] = base64.b64encode(b"a" * (2 * 1024 * 1024 + 1)).decode()
    elif kind == "empty":
        body["source"]["content_base64"] = ""
    elif kind == "filename":
        body["source"]["filename"] = "../outside.c"
    elif kind == "invalid_cve":
        body["cve_id"] = "arbitrary"
    elif kind == "missing_description":
        body["cve_description"] = "   "
    else:
        body["source"]["content_base64"] = "!not-base64"
    response = client.post("/api/knowledge-builds", json=body)
    assert response.status_code == 422, response.text
    assert client.get("/api/knowledge-builds").json()["items"] == []
    assert not (app.state.catalog.index_root / "active_index.json").exists()


def test_worker_failure_keeps_original_index_and_allows_retry(service, monkeypatch):
    app, manager, client = service
    command = manager.command
    monkeypatch.setattr(manager, "command", lambda *args: [sys.executable, "-c", "raise RuntimeError('local failure')"])
    job = client.post("/api/knowledge-builds", json=addition()).json()
    failed = wait_build(client, job["id"])
    assert failed["status"] == "failed" and failed["error"]
    assert client.get("/api/knowledge").json()["total"] == 1
    assert not (app.state.catalog.index_root / "active_index.json").exists()
    monkeypatch.setattr(manager, "command", command)
    retry = client.post("/api/knowledge-builds", json=addition()).json()
    assert wait_build(client, retry["id"])["status"] == "completed"


def test_concurrent_submission_is_rejected(service, monkeypatch):
    _, manager, client = service
    monkeypatch.setattr(manager, "command", lambda *args: [sys.executable, "-c", "import time;time.sleep(1);raise RuntimeError('fixture')"])
    first = client.post("/api/knowledge-builds", json=addition())
    assert first.status_code == 202
    assert client.post("/api/knowledge-builds", json=addition("other();\n")).status_code == 409
    assert wait_build(client, first.json()["id"])["status"] == "failed"


def test_partial_build_is_not_published(service, monkeypatch):
    app, manager, client = service
    def command(identity, base, output):
        cmd = local_command(manager, identity, base, output)
        cmd[-1] += f";from pathlib import Path;Path({str(output / 'index_control_flow.faiss')!r}).unlink()"
        return cmd
    monkeypatch.setattr(manager, "command", command)
    job = client.post("/api/knowledge-builds", json=addition()).json()
    assert wait_build(client, job["id"])["status"] == "failed"
    assert app.state.catalog.indices == app.state.catalog.index_root


def test_changed_base_is_not_overwritten(service, monkeypatch):
    app, manager, client = service
    def command(identity, base, output):
        cmd = local_command(manager, identity, base, output)
        cmd[-1] += f";from pathlib import Path;p=Path({str(base / 'manifest.json')!r});p.write_text(p.read_text()+'\\n')"
        return cmd
    monkeypatch.setattr(manager, "command", command)
    job = client.post("/api/knowledge-builds", json=addition()).json()
    failed = wait_build(client, job["id"])
    assert failed["status"] == "failed" and "changed during construction" in failed["error"]
    assert app.state.catalog.indices == app.state.catalog.index_root


def test_worker_errors_redact_offline_credentials(service, monkeypatch):
    _, manager, client = service
    secret = "offline-fixture-secret-1234"
    manager.secrets.add(secret)
    def command(identity, base, output):
        return [sys.executable, "-c", f"from pathlib import Path;Path({str(manager.directory / identity / 'error.json')!r}).write_text({json.dumps({'error': 'Failed with ' + secret})!r});raise SystemExit(1)"]
    monkeypatch.setattr(manager, "command", command)
    job = client.post("/api/knowledge-builds", json=addition()).json()
    failed = wait_build(client, job["id"])
    assert failed["status"] == "failed" and "[redacted]" in failed["error"]
    assert secret not in json.dumps(failed)


def test_incompatible_embedding_fails_before_launch(service):
    _, manager, client = service
    manager.config.write_text(manager.config.read_text().replace("local-embedding", "different-embedding"))
    response = client.post("/api/knowledge-builds", json=addition())
    assert response.status_code == 422
    assert "embedding" in response.json()["detail"]
    assert manager.list() == []


def test_restart_marks_unpublished_job_interrupted_and_retains_inputs(service):
    _, manager, client = service
    identity = "1" * 32
    directory = manager.directory / identity
    write_json_atomic(directory / "job.json", {"id": identity, "status": "running", "created_at": "2026-01-01T00:00:00Z"})
    write_json_atomic(directory / "input.json", {"buggy_code": "retained"})
    manager.recover()
    assert client.get("/api/knowledge-builds/" + identity).json()["status"] == "interrupted"
    assert json.loads((directory / "input.json").read_text())["buggy_code"] == "retained"


def test_running_repair_keeps_pinned_index(service):
    app, manager, client = service
    task = app.state.store.create("fixture", "full", "fixture", stage="diagnosis")
    original = app.state.engine.command(task, Path("/tmp/source-fixture"))
    pinned = original[original.index("--indices-dir") + 1]
    job = client.post("/api/knowledge-builds", json=addition()).json()
    assert wait_build(client, job["id"])["status"] == "completed"
    subsequent = app.state.engine.command({**task, "stage": "retrieval"}, Path("/tmp/source-fixture"))
    assert subsequent[subsequent.index("--indices-dir") + 1] == pinned
    assert "--index-snapshot" in subsequent
    new_task = app.state.store.create("fixture", "full", "new", stage="diagnosis")
    fresh = app.state.engine.command(new_task, Path("/tmp/source-fixture"))
    assert fresh[fresh.index("--indices-dir") + 1] == str(app.state.catalog.indices) != pinned


def test_api_origin_limits_and_unknown_id(service):
    _, manager, client = service
    assert client.post("/api/knowledge-builds", json=addition(), headers={"Origin": "https://example.org"}).status_code == 403
    assert client.post("/api/knowledge-builds", content=b" " * 5_700_001).status_code == 413
    assert client.get("/api/knowledge-builds/not-valid").status_code == 404
