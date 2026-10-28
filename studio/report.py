"""Portable repair reports assembled exclusively from saved execution evidence."""

from copy import deepcopy
from html import escape
import json

from .store import now


def build_report(data):
    candidates = data.get("candidates", [])
    patches = [c for c in candidates if isinstance(c.get("patch"), str) and c["patch"].strip()]
    passed = [c for c in patches if (c.get("validation_result") or {}).get("success") is True]
    scoped_passed = [c for c in patches if (c.get("validation_result") or {}).get("selected_checks_passed") is True]
    selected = passed[-1] if passed else scoped_passed[-1] if scoped_passed else patches[-1] if patches else None
    mode = data.get("mode", "live")
    request = data.get("repair_request") or {}
    validation_mode = request.get("validation_mode", "full")
    retrieval = data.get("retrieval") or {}
    pool = retrieval.get("ranking", {}).get("candidates", [])
    views = {}
    for view in ("data_flow", "control_flow"):
        hits = []
        for candidate in pool:
            for hit in candidate.get("retrieval_hits", []):
                if hit.get("query_view") == view:
                    hits.append({"rank": hit.get("rank"), "distance": hit.get("distance"),
                                 "example": deepcopy(candidate)})
        views[view] = sorted(hits, key=lambda h: h.get("rank") or 0)
    validation = deepcopy((selected or {}).get("validation_result") or {})
    complete = data.get("status") == "completed"
    outcome = ("historical_validation_passed" if mode == "replay" else "validated") if passed and complete else (
        "finished_without_validated_patch" if complete else data.get("status", "unknown"))
    if complete and validation_mode == "patch_only" and selected:
        outcome = "patch_generated"
    elif complete and validation_mode == "poc" and scoped_passed:
        outcome = "historical_poc_checks_passed" if mode == "replay" else "poc_checks_passed"
    deliverable = bool(selected and complete and (passed or scoped_passed or validation_mode == "patch_only"))
    return dict(
        schema_version=1, report_type="repair_report", generated_at=now(),
        task={k: data.get(k) for k in ("id", "case_id", "case_key", "variant", "status", "stage", "automatic", "created_at", "updated_at", "error")},
        provenance=dict(mode=mode, new_validation_performed=mode == "live" and any(c.get("validation_invoked") or c.get("validation_runs") for c in candidates),
                        replay=deepcopy(data.get("replay")),
                        note="Historical records; replay performs no new model calls or validation." if mode == "replay" else
                             "Synthetic walkthrough; not a live repair." if mode == "walkthrough" else "Results from the task's recorded live execution."),
        summary=dict(outcome=outcome, completed=complete, has_validated_patch=bool(passed),
                     has_deliverable_patch=deliverable, validation_mode=validation_mode,
                     requested_checks_passed=bool(passed or scoped_passed),
                     fact_count=len(data.get("facts", [])), tool_call_count=len(data.get("tool_calls", [])),
                     retrieved_per_view={v: len(h) for v, h in views.items()},
                     unique_candidates=len(pool), selected_examples=len(retrieval.get("final_exemplars", [])),
                     patch_attempts=len(candidates)),
        source=dict({k: data.get(k) for k in ("file", "language", "dataset", "source_hash", "source_snapshot_stale")},
                    preflight=deepcopy(data.get("source_preflight") or {})),
        repair_request=deepcopy(request),
        diagnosis=deepcopy(data.get("diagnosis_report") or {}),
        diagnosis_issues=deepcopy(data.get("diagnosis_issues") or []),
        retrieval=dict(queries=deepcopy(retrieval.get("queries", {})), retrieved_by_view=views,
                       selected_after_reranking=deepcopy(retrieval.get("final_exemplars", [])),
                       record=deepcopy(retrieval), partial=deepcopy(data.get("retrieval_progress") or {})),
        patch=dict(selected_candidate_id=(selected or {}).get("candidate_id"),
                   final_patch=selected["patch"] if deliverable else None,
                   latest_patch=(selected or {}).get("patch"), attempts=deepcopy(candidates)),
        validation=dict(result=validation, runs=deepcopy(data.get("validation_runs", [])),
                        progress=deepcopy(data.get("runtime", {}).get("validation_progress") or {})),
        execution=dict(events=deepcopy(data.get("events", [])), current=deepcopy(data.get("runtime") or {}),
                       history=deepcopy(data.get("runtime_history") or []),
                       engine_result=deepcopy(data.get("engine_result") or {})),
    )


def render_report(report):
    def esc(value):
        return escape(str(value if value is not None else "—"), quote=True)

    def raw(title, value):
        return f'<details><summary>{esc(title)}</summary><pre>{esc(json.dumps(value, ensure_ascii=False, indent=2))}</pre></details>'

    def table(headers, rows):
        return '<div class="table"><table><thead><tr>' + ''.join(f'<th>{esc(h)}</th>' for h in headers) + '</tr></thead><tbody>' + (
            ''.join('<tr>' + ''.join(f'<td>{esc(v)}</td>' for v in row) + '</tr>' for row in rows) or f'<tr><td colspan="{len(headers)}">No saved records</td></tr>') + '</tbody></table></div>'

    task, summary, retrieval = report["task"], report["summary"], report["retrieval"]
    diagnosis, validation = report["diagnosis"], report["validation"]["result"]
    sections = f'<section><h2>01 · Diagnosis</h2><p class="prose">{esc(diagnosis.get("summary") or "No diagnosis report saved.")}</p>'
    sections += table(["Evidence", "Location", "Observation"], [(f.get("evidence_id"), (f.get("location") or {}).get("start_line"), f.get("statement")) for f in diagnosis.get("facts", [])])
    sections += raw("Full diagnosis, tool calls and analysis limitations", diagnosis) + '</section>'
    sections += '<section><h2>02 · Retrieval and reranking</h2>'
    for view, hits in retrieval["retrieved_by_view"].items():
        query = retrieval["queries"].get(view)
        sections += f'<h3>{"Data flow" if view == "data_flow" else "Control flow"} · {len(hits)} examples</h3><p class="prose">{esc(query)}</p>'
        sections += table(["Rank", "CVE / sample", "Distance"], [(h["rank"], h["example"].get("cve_id") or h["example"].get("sample_id"), h["distance"]) for h in hits])
    sections += '<h3>Selected after reranking</h3>' + table(["Selection", "CVE / sample", "Rerank score"], [(i, c.get("cve_id") or c.get("sample_id"), c.get("rerank_score")) for i, c in enumerate(retrieval["selected_after_reranking"], 1)])
    sections += raw("Full examples, scores, queries and ranking protocol", retrieval) + '</section>'
    patch_label = 'Validated patch' if summary['has_validated_patch'] else 'Patch generated · validation not requested' if summary['validation_mode'] == 'patch_only' else 'Patch · requested PoC checks passed' if summary['requested_checks_passed'] else 'Latest generated patch · not fully validated'
    sections += '<section><h2>03 · Patch</h2><p>' + patch_label + '</p><pre>' + esc(report["patch"]["latest_patch"] or "No patch generated.") + '</pre>' + raw("Generation and validation attempts", report["patch"]["attempts"]) + '</section>'
    labels = dict(source_prepare="Source preparation", patch_apply="Patch application", compile="Build check", poc="PoC Test", unit="Unit tests")
    sections += '<section><h2>04 · Validation</h2><p>Plan: ' + esc(summary['validation_mode']) + '</p>' + table(["Check", "Result"], [(labels.get(k, k), 'Not requested' if summary['validation_mode'] == 'patch_only' or (k == 'unit' and summary['validation_mode'] == 'poc') else v) for k, v in validation.get("stage_status", {}).items()])
    sections += raw("Validation commands, output, errors and receipts", report["validation"]) + '</section>'
    sections += '<section><h2>05 · Execution record</h2>' + raw("Repository target and requested test inputs", report['repair_request']) + table(["Time", "Stage", "Event"], [(e.get("at"), e.get("stage"), e.get("message")) for e in report["execution"]["events"]]) + raw("Source identity and provenance", dict(source=report["source"], provenance=report["provenance"])) + raw("Full execution details", report["execution"]) + '</section>'
    error = f'<p class="error">{esc(task["error"])}</p>' if task.get("error") else ''
    cards = ''.join(f'<div><b>{esc(v)}</b><span>{esc(k)}</span></div>' for k, v in (("Program facts", summary["fact_count"]), ("Tool calls", summary["tool_call_count"]), ("Retrieved hits", sum(summary["retrieved_per_view"].values())), ("Selected examples", summary["selected_examples"])))
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(task.get("case_id"))} · Repair report</title>
<style>body{{margin:0;background:#0b1220;color:#e5edf8;font:15px/1.65 system-ui,sans-serif}}main{{max-width:1120px;margin:auto;padding:48px 28px}}header,section{{border:1px solid #293b50;border-radius:16px;padding:28px;margin:20px 0;background:#111d2c}}h1{{font-size:32px;letter-spacing:-1px;margin:8px 0}}h2{{font-size:21px;color:#71dfce}}h3{{font-size:16px;margin-top:28px}}p{{color:#b7c7db}}.prose{{white-space:pre-wrap}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}}.stats b{{display:block;font-size:28px;color:#71dfce}}.stats span{{font-size:13px;color:#9db1ca}}.table{{overflow:auto}}table{{width:100%;border-collapse:collapse}}td,th{{padding:12px;text-align:left;border-bottom:1px solid #293b50;vertical-align:top;overflow-wrap:anywhere}}th{{color:#9db1ca;font-size:12px;text-transform:uppercase}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;padding:18px;background:#09111c;border-radius:10px;font:12px/1.8 ui-monospace,monospace;max-height:600px;overflow:auto}}details{{margin-top:18px}}summary{{cursor:pointer;color:#71dfce}}.error{{color:#ffaaa0}}small{{color:#9db1ca}}@media(max-width:600px){{main{{padding:12px}}header,section{{padding:18px}}.stats{{grid-template-columns:repeat(2,1fr)}}}}@media print{{body,header,section{{background:white;color:#142235}}p,small,th{{color:#33485c}}h2,.stats b,summary{{color:#00796b}}pre{{background:#f1f5f9;max-height:none}}section{{break-inside:avoid}}}}</style>
<main><header><small>KEAREPAIR / REPAIR REPORT</small><h1>{esc(task.get("case_id"))}</h1><p>{esc(summary["outcome"].replace("_", " ").title())} · {esc(task.get("id"))}</p><p>{esc(report["provenance"]["note"])}</p>{error}<div class="stats">{cards}</div><p>Started {esc(task.get("created_at"))}<br>Last updated {esc(task.get("updated_at"))}</p></header>{sections}<small>Generated {esc(report["generated_at"])} · Saved evidence, including incomplete or failed checks, is retained in the report.</small></main></html>'''
