"""Local-only HTTP API and self-contained web assets."""

import asyncio
from contextlib import asynccontextmanager
import io
import json
from pathlib import Path
from typing import Literal
import zipfile

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .catalog import Catalog
from .demo import Position, walkthrough
from .engine import ACTIVE, Engine
from .store import Store

ROOT = Path(__file__).resolve().parents[1]


class NewTask(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_key: str | None = Field(default=None, min_length=1, max_length=150)
    repository_url: str | None = Field(default=None, max_length=2048)
    target_id: str | None = Field(default=None, max_length=150)
    vulnerable_file: str | None = Field(default=None, max_length=1024)
    revision: str | None = Field(default=None, max_length=150)
    validation_mode: Literal["patch_only", "poc", "full"] = "full"
    poc_file: str | None = Field(default=None, max_length=2048)
    unit_test: str | None = Field(default=None, max_length=2048)
    poc_upload_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    unit_upload_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    variant: Literal["full", "df_only", "cf_only", "no_retrieval", "no_diagnosis", "no_iteration"] = "full"
    mode: Literal["live", "replay"] = "live"
    automatic: bool = True

    @model_validator(mode="after")
    def input_source(self):
        if bool(self.case_key) == bool(self.repository_url):
            raise ValueError("Provide either a repository target or a legacy case key")
        if self.case_key and (self.target_id or self.vulnerable_file or self.revision or self.poc_file or self.unit_test or self.poc_upload_id or self.unit_upload_id or self.validation_mode != "full"):
            raise ValueError("Repository repair options require a resolved repository target")
        if self.poc_upload_id and (self.validation_mode == "patch_only" or self.poc_file):
            raise ValueError("Choose one PoC input for a plan that includes validation")
        if self.unit_upload_id and (self.validation_mode != "full" or self.unit_test):
            raise ValueError("Choose one unit-test input for the full test plan")
        return self


class RepositoryLookup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_url: str = Field(min_length=1, max_length=2048)


class TestInputUpload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["poc", "unit"]
    filename: str = Field(min_length=1, max_length=255)
    content_base64: str = Field(max_length=14_000_000)


class KnowledgeFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str = Field(min_length=1, max_length=255)
    content_base64: str = Field(min_length=1, max_length=2_800_000)


class KnowledgeAddition(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    cve_id: str = Field(pattern=r"(?i)^CVE-\d{4}-\d{4,}$", max_length=40)
    cve_description: str = Field(min_length=1, max_length=20000)
    project: str = Field(default="", max_length=200)
    language: Literal["c", "cpp", "Python", "Go", "JavaScript", "TypeScript", "Java", "Rust", "C#", "PHP", "Ruby", "Other"]
    source: KnowledgeFile
    patch: KnowledgeFile


class AnalysisQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: Literal["trace_data_flow", "is_path_reachable", "inspect_api_usage"]
    line: int = Field(ge=1)
    column: int | None = Field(default=None, ge=1)
    variable: str = Field(default="", max_length=256)
    source_line: int = Field(default=1, ge=1)


class NextStage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stage: Literal["diagnosis", "retrieval", "repair"]


class ValidateCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_id: int = Field(ge=1, strict=True)


def create_app(root=ROOT, data_dir=None, indices=None, config=None):
    root = Path(root).resolve()
    catalog = Catalog(root, indices)
    store = Store(data_dir or root / "results/studio")
    engine = Engine(root, store, catalog, config or root / "config/online.yaml")
    from .repositories import RepositoryCatalog
    from .uploads import TestInputStore
    repositories = RepositoryCatalog(catalog)
    uploads = TestInputStore(store.directory)
    from .knowledge_builds import BuildConflict, KnowledgeBuilds
    knowledge_builds = KnowledgeBuilds(root, store.directory, catalog, engine.redact)

    @asynccontextmanager
    async def lifespan(app):
        store.recover()
        knowledge_builds.recover()
        yield
        await asyncio.to_thread(knowledge_builds.close)
        await asyncio.to_thread(engine.close)

    app = FastAPI(title="KeaRepair", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.store, app.state.catalog, app.state.engine = store, catalog, engine
    app.state.knowledge_builds = knowledge_builds
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"])

    @app.middleware("http")
    async def local_origin(request, call_next):
        # The launcher binds to loopback. Reject browser requests from other origins.
        origin = request.headers.get("origin")
        if origin and origin != f"{request.url.scheme}://{request.headers.get('host')}":
            return JSONResponse({"detail": "Only same-origin requests are accepted"}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Cross-site requests are not accepted"}, status_code=403)
        if request.url.path == "/api/test-inputs":
            length = request.headers.get("content-length", "0")
            if not length.isdigit() or int(length) > 14_050_000:
                return JSONResponse({"detail": "Each uploaded file must be at most 10 MiB"}, status_code=413)
        if request.url.path == "/api/knowledge-builds" and request.method == "POST":
            data = bytearray()
            async for chunk in request.stream():
                data.extend(chunk)
                if len(data) > 5_700_000:
                    return JSONResponse({"detail": "Each source or patch file must be at most 2 MiB"}, status_code=413)
            request._body = bytes(data)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(KeyError)
    async def not_found(request, exc):
        return JSONResponse({"detail": "Record not found"}, status_code=404)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/api/overview")
    def overview():
        try:
            config_info = engine.public_config()
            issues = engine.preflight()
        except Exception as exc:
            config_info, issues = {}, [engine.redact(str(exc))]
        tasks = store.tasks()
        return {
            "knowledge": catalog.knowledge_summary(),
            "case_count": len(catalog.cases()), "tasks": tasks,
            "config": config_info, "preflight_issues": issues,
            "version": "0.1.0",
        }

    @app.get("/api/walkthrough")
    def demo():
        return walkthrough()

    @app.get("/api/cases")
    def cases(q: str = "", language: str = ""):
        sources = engine.replay.sources()
        return {"items": [{**case, "repository_url": repositories.repository_for_case(case["key"]),
                           "replay_source_id": sources.get(case["key"], {}).get("id")}
                          for case in catalog.public_cases(q, language)]}

    @app.get("/api/repositories")
    def repository_list():
        return {"items": repositories.repositories()}

    @app.post("/api/repositories/resolve")
    def resolve_repository(body: RepositoryLookup):
        try:
            result = repositories.resolve(body.repository_url)
            sources = engine.replay.sources()
            for target in result["targets"]:
                target["replay_source_id"] = target.get("demo_source_task_id") or sources.get(target["case_key"], {}).get("id")
                target["uploaded_poc_data"] = target["case_key"].startswith("Vul4c:")
            return result
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    @app.post("/api/test-inputs", status_code=201)
    def upload_test_input(body: TestInputUpload):
        try:
            return uploads.create(body.kind, body.filename, body.content_base64)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    @app.get("/api/knowledge")
    def knowledge(q: str = "", language: str = "", offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=50)):
        return catalog.knowledge(q, language, offset, limit)

    @app.get("/api/knowledge/{sample_id}")
    def knowledge_item(sample_id: str):
        return catalog.record(sample_id)

    @app.get("/api/knowledge-builds")
    def list_knowledge_builds():
        return {"items": knowledge_builds.list()}

    @app.post("/api/knowledge-builds", status_code=202)
    def extend_knowledge(body: KnowledgeAddition):
        try:
            return knowledge_builds.submit(body.model_dump())
        except BuildConflict as exc:
            raise HTTPException(status_code=409, detail=engine.redact(str(exc)))
        except (ValueError, OSError) as exc:
            raise HTTPException(status_code=422, detail=engine.redact(str(exc)))

    @app.get("/api/knowledge-builds/{build_id}")
    def knowledge_build(build_id: str):
        return knowledge_builds.get(build_id)

    @app.get("/api/tasks")
    def tasks():
        return {"items": store.tasks()}

    @app.post("/api/tasks", status_code=201)
    def create_task(body: NewTask):
        try:
            repair_request = None
            case_key = body.case_key
            demo_source_id = None
            if body.repository_url:
                target = repositories.target(body.target_id)
                demo_source_id = target.get("demo_source_task_id")
                if not demo_source_id and (body.poc_upload_id or body.unit_upload_id) and body.mode != "live":
                    raise HTTPException(status_code=422, detail="Uploaded tests require live execution")
                uploaded = {kind: uploads.metadata(identity, kind=kind)
                            for kind, identity in (("poc", body.poc_upload_id), ("unit", body.unit_upload_id)) if identity}
                resolved = repositories.match(
                    repository_url=body.repository_url, target_id=body.target_id,
                    vulnerable_file=body.vulnerable_file, revision=body.revision,
                    poc_file=target["poc_file"] if "poc" in uploaded else body.poc_file,
                    unit_test=target["unit_test"] if "unit" in uploaded else body.unit_test,
                    validation_mode=body.validation_mode)
                case_key, repair_request = resolved["case_key"], resolved["request"]
                if demo_source_id:
                    repair_request["demo_source_task_id"] = demo_source_id
                    repair_request["historical_test_inputs"] = {
                        "source_task_id": demo_source_id,
                        "poc_file": target["poc_file"],
                        "unit_test": target["unit_test"],
                    }
                if uploaded:
                    if demo_source_id:
                        repair_request["submitted_test_inputs"] = uploaded
                    else:
                        from utils.validation_inputs import validate_uploaded_tests
                        from utils.validation_scope import scope_commands
                        commands = json.loads((catalog.case(case_key)["_directory"] / "test_cmds.json").read_text())
                        validate_uploaded_tests(scope_commands(commands, body.validation_mode), uploaded)
                        repair_request["uploaded_tests"] = uploaded
                    for kind, descriptor in uploaded.items():
                        repair_request["poc_file" if kind == "poc" else "unit_test"] = descriptor["filename"]
            options = {"repair_request": repair_request} if repair_request is not None else {}
            if demo_source_id:
                return engine.replay.submit_case(case_key, "full", automatic=True, source_task_id=demo_source_id, **options)
            if body.mode == "replay":
                return engine.replay.submit_case(case_key, body.variant, automatic=body.automatic, **options)
            return engine.submit(case_key, body.variant, automatic=body.automatic, **options)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=engine.redact(str(exc)))

    @app.post("/api/tasks/{task_id}/replay", status_code=201)
    def replay(task_id: str, automatic: bool = True):
        try:
            return engine.replay.submit(task_id, automatic=automatic)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=engine.redact(str(exc)))

    @app.get("/api/tasks/{task_id}")
    def task(task_id: str):
        try:
            return engine.detail(task_id)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=engine.redact(str(exc)))

    @app.post("/api/tasks/{task_id}/cancel")
    def cancel(task_id: str):
        return engine.cancel(task_id)

    @app.post("/api/tasks/{task_id}/pause")
    def pause_task(task_id: str):
        try:
            return engine.pause(task_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=engine.redact(str(exc)))

    @app.post("/api/tasks/{task_id}/resume")
    def resume_task(task_id: str):
        try:
            return engine.resume(task_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=engine.redact(str(exc)))

    @app.delete("/api/tasks/{task_id}")
    def delete_task(task_id: str):
        try:
            return engine.delete_task(task_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=engine.redact(str(exc)))

    @app.post("/api/tasks/{task_id}/advance")
    def advance(task_id: str, body: NextStage):
        try:
            return engine.advance(task_id, body.stage)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=engine.redact(str(exc)))

    @app.get("/api/tasks/{task_id}/logs")
    def logs(task_id: str):
        return {"text": engine.logs(task_id)}

    @app.post("/api/tasks/{task_id}/validate", status_code=202)
    def validate(task_id: str, body: ValidateCandidate):
        try:
            return engine.validate_candidate(task_id, body.candidate_id)
        except (OSError, ValueError, KeyError) as exc:
            if isinstance(exc, KeyError) and exc.args == (task_id,):
                raise
            raise HTTPException(status_code=409, detail=engine.redact(str(exc)))

    @app.get("/api/tasks/{task_id}/events")
    async def events(task_id: str, request: Request, after: int = Query(0, ge=0)):
        store.task(task_id)
        try:
            after = max(after, int(request.headers.get("last-event-id", "0")))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Last-Event-ID")
        async def stream():
            cursor = after
            while not await request.is_disconnected():
                values = await asyncio.to_thread(store.events, task_id, cursor)
                for value in values:
                    cursor = value["seq"]
                    yield f"id: {cursor}\ndata: {json.dumps(value, ensure_ascii=False)}\n\n"
                try:
                    task = await asyncio.to_thread(store.task, task_id)
                except KeyError:
                    yield "event: done\ndata: {}\n\n"
                    break
                if task["status"] not in ACTIVE:
                    yield "event: done\ndata: {}\n\n"
                    break
                yield ": heartbeat\n\n"
                await asyncio.sleep(1)
        return StreamingResponse(stream(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})

    @app.post("/api/tasks/{task_id}/analyze")
    def analyze(task_id: str, query: AnalysisQuery):
        from static_analysis.session import AnalysisSession
        data = walkthrough() if task_id == "walkthrough" else engine.detail(task_id)
        code = data.get("source", "")
        if len(code) > 300000:
            raise HTTPException(status_code=413, detail="Interactive analysis is limited to 300 KB of source. Full repair can still run as a task.")
        try:
            session = AnalysisSession(code, language=data["language"], file_path=data["file"])
            point = Position(query.line, query.column)
            if query.tool == "trace_data_flow":
                if not query.variable.strip():
                    raise ValueError("Enter a variable to trace")
                return session.trace_data_flow(query.variable, point)
            if query.tool == "is_path_reachable":
                return session.is_path_reachable(Position(query.source_line), point, query.variable or None)
            return session.inspect_api_usage(point)
        except (ValueError, KeyError, IndexError) as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    @app.get("/api/tasks/{task_id}/report")
    def repair_report(task_id: str, format: Literal["json", "html"] = "json"):
        from .report import build_report, render_report
        data = walkthrough() if task_id == "walkthrough" else engine.detail(task_id)
        report = build_report(data)
        body = render_report(report) if format == "html" else json.dumps(report, ensure_ascii=False, indent=2)
        return Response(body, media_type="text/html" if format == "html" else "application/json",
                        headers={"Content-Disposition": f'attachment; filename="kearepair-{task_id}-repair-report.{format}"'})

    @app.get("/api/tasks/{task_id}/export")
    def export(task_id: str):
        from .report import build_report, render_report
        data = walkthrough() if task_id == "walkthrough" else engine.detail(task_id)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("report.json", json.dumps(data, ensure_ascii=False, indent=2))
            report = build_report(data)
            archive.writestr("repair_report.json", json.dumps(report, ensure_ascii=False, indent=2))
            archive.writestr("repair_report.html", render_report(report))
            if report["patch"]["final_patch"]:
                archive.writestr("final.patch", report["patch"]["final_patch"])
            archive.writestr("source.original", data.get("source", ""))
            archive.writestr("README.txt", "KeaRepair evidence bundle\nMode: " + data["mode"] + "\nSee report.json for explicit validation states. A walkthrough is synthetic, not an experiment. Replay displays historical evidence, performs no new validation, and is excluded from live experiment results. Replay pacing is not measured execution time.\n")
            for i, candidate in enumerate(data.get("candidates", []), 1):
                archive.writestr(f"candidate-{i}.patch", candidate.get("patch") or "")
            if task_id != "walkthrough":
                archive.writestr("engine.log", engine.logs(task_id))
                for field, folder in (("uploaded_tests", "test-inputs"), ("submitted_test_inputs", "submitted-test-inputs")):
                    for kind, item in data.get("repair_request", {}).get(field, {}).items():
                        from utils.validation_inputs import _input_bytes
                        case_dir = store.run_dir(task_id) / "input" / data["case_id"]
                        path = case_dir / item["relative_path"]
                        content = _input_bytes({**item, "path": str(path)})
                        archive.writestr(f"{folder}/{kind}/{path.name}", content)
        return Response(buffer.getvalue(), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="kearepair-{task_id}.zip"'})

    web = Path(__file__).parent / "web"
    app.mount("/assets", StaticFiles(directory=web), name="assets")

    @app.get("/")
    def index():
        return FileResponse(web / "index.html")

    return app
