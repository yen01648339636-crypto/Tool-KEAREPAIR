#!/usr/bin/env python3
"""Validate a saved candidate without invoking models or replacing its history."""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml
from Online.phase3_repair import Validator
from utils.experiment_manifest import write_json_atomic
from utils.experiment_store import digest, persist_attempt
from utils.metrics import verify_attempt
from utils.patches import prepare_candidate, target_path
from utils.telemetry import Recorder, measure


def read_object(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def load_candidate(case_dir, candidate_id):
    if type(candidate_id) is not int or candidate_id < 1:
        raise ValueError("candidate-id must be a positive integer")
    case_dir = Path(case_dir).resolve()
    source = (case_dir / "source.original").read_bytes().decode("utf-8")
    if read_object(case_dir / "source.json").get("sha256") != digest(source):
        raise ValueError("Saved original source hash does not match")
    directory = case_dir / "attempts" / str(candidate_id)
    attempt = read_object(directory / "attempt.json")
    patch = (directory / "effective.patch").read_bytes().decode("utf-8")
    if not patch.strip() or patch != attempt.get("patch"):
        raise ValueError("Candidate has no matching saved effective patch")
    raw = (directory / "raw.patch").read_bytes().decode("utf-8")
    if raw != attempt.get("raw_response"):
        raise ValueError("Saved raw response differs from the attempt record")
    previous = attempt.get("validation_result") or {}
    if previous.get("raw_patch_hash") != digest(raw) or previous.get("effective_patch_hash") != digest(patch):
        raise ValueError("Saved candidate hashes do not match its validation record")
    inputs = read_object(case_dir / "inputs.json")
    info = deepcopy(inputs["effective_validation"])
    if not info.get("docker_image"):
        raise ValueError("Saved validation must declare a Docker image")
    prepared = prepare_candidate(source, raw, target_path(info), info.get("source_context"))
    if prepared.patch != patch:
        raise ValueError("Saved patch differs from deterministic preparation")
    # Reuse the same source, patch and validation commands; no new generation.
    info.update(candidate_id=str(candidate_id), raw_patch_hash=digest(raw),
                generated_patch=prepared.raw_diff)
    snapshot = case_dir.parents[1] / "config_snapshot.yaml"
    settings = yaml.safe_load(snapshot.read_text(encoding="utf-8"))["online"]["phase3_repair"]["validation"]
    return source, patch, raw, prepared, inputs, info, settings


class ProgressValidator(Validator):
    def _command(self, result, step, argv, **kwargs):
        print(f"START {step['name']} ({', '.join(step['covers'])})", flush=True)
        started = time.monotonic()
        ok = super()._command(result, step, argv, **kwargs)
        print(f"END {step['name']}: {'passed' if ok else 'failed/error'} ({time.monotonic() - started:.1f}s)", flush=True)
        return ok


def validate_saved(case_dir, candidate_id, output_dir=None):
    case_dir = Path(case_dir).resolve()
    source, patch, raw, prepared, inputs, info, settings = load_candidate(case_dir, candidate_id)
    case_id = info.get("cve_id") or case_dir.name
    if Path(case_id).name != case_id or case_id in {".", ".."}:
        raise ValueError("Unsafe case ID")
    output = Path(output_dir).resolve() if output_dir else ROOT / "results/validation_replay" / (
        f"{datetime.now():%Y%m%d-%H%M%S}-{case_id}-candidate-{candidate_id}-{uuid4().hex[:6]}"
    )
    if output.exists():
        raise ValueError("Use a new output directory to preserve existing validation evidence")
    output.mkdir(parents=True, exist_ok=False)
    saved_case = output / "cases" / case_id
    recorder = Recorder(saved_case, case_id=case_id)
    (saved_case / "source.original").write_bytes(source.encode("utf-8"))
    write_json_atomic(saved_case / "source.json", {"manifest_key": None, "sha256": digest(source)})
    write_json_atomic(saved_case / "inputs.json", inputs)
    origin = dict(operation="validation_only", original_case_dir=str(case_dir),
                  candidate_id=candidate_id, model_calls=0, source_hash=digest(source),
                  patch_hash=digest(patch), validation_settings=settings)
    write_json_atomic(output / "revalidation.json", {**origin, "status": "running"})
    print(f"OUTPUT_DIR={output}", flush=True)
    attempt = dict(iteration=1, candidate_id=candidate_id, raw_response=raw,
                   generated_patch=prepared.raw_diff, corrected_patch=patch, patch=patch,
                   hunk_ranges=prepared.ranges, patch_correction=prepared.correction,
                   generation_reused=True, origin=origin, validation_invoked=False)
    progress_started = datetime.now(timezone.utc).isoformat()
    preflight_sequence = 0

    def preflight_progress(status, *, error=None):
        # Baseline preflight and candidate installation are separate operations.
        # A cached source check cannot establish that this validation prepared it.
        nonlocal preflight_sequence
        preflight_sequence += 1
        value = dict(schema_version=1, execution_id=os.environ.get("KEA_STUDIO_EXECUTION_ID"),
                     candidate_id=str(candidate_id), sequence=preflight_sequence,
                     started_at=progress_started, updated_at=datetime.now(timezone.utc).isoformat(),
                     step="source_check", substep="baseline_preflight", status=status,
                     running=status == "running", covers=[],
                     stage_status={name: "not_run" for name in ("patch_apply", "compile", "poc", "unit")},
                     stage_details={"source_check": {"status": status, "reason": error}})
        if error:
            value["error"] = str(error)
        write_json_atomic(output / "progress.json", value)

    preflight_progress("running")
    try:
        with recorder.activate(), measure("validation_only"):
            from utils.source_baseline import ensure_source_baseline, needs_source_baseline
            if needs_source_baseline(inputs.get("test_commands")):
                print("START source_baseline (before validation)", flush=True)
                receipt = ensure_source_baseline(case_dir / "source.original", inputs["test_commands"], receipt_path=case_dir / "source_baseline.json")
                info["expected_docker_image_id"] = receipt["docker_image_id"]
                write_json_atomic(output / "source_baseline.json", receipt)
                print("END source_baseline: passed", flush=True)
            preflight_progress("completed")
            validator = ProgressValidator(compiler=settings["compiler"],
                                          compile_timeout=settings["compile_timeout"],
                                          test_timeout=settings["test_timeout"], execution_mode="docker")
            validator.progress_path = output / "progress.json"
            attempt["validation_invoked"] = True
            attempt["validation_result"] = validator.validate(source, patch, info)
            persist_attempt(attempt)
        checked = verify_attempt(saved_case, saved_case / "attempts" / str(candidate_id))
    except Exception as exc:
        if not attempt["validation_invoked"]:
            preflight_progress("failed", error=str(exc))
        else:
            # Even an archive verification error must clear the last running UI
            # state; its existing stage evidence remains available for inspection.
            progress = read_object(output / "progress.json") if (output / "progress.json").exists() else {}
            progress.update(running=False, status="failed", error=str(exc),
                            updated_at=datetime.now(timezone.utc).isoformat(),
                            sequence=int(progress.get("sequence", 0)) + 1)
            write_json_atomic(output / "progress.json", progress)
        write_json_atomic(output / "revalidation.json", {**origin, "status": "failed", "error": str(exc)})
        raise
    summary = {**origin, "status": "completed", "success": checked["success"],
               "stage_status": checked["stage_status"], "error_log": checked["error_log"],
               "case_dir": str(saved_case)}
    write_json_atomic(output / "revalidation.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", type=Path, required=True, help="Saved engine/cases/<CVE> directory")
    parser.add_argument("--candidate-id", type=int, required=True)
    parser.add_argument("--output-dir", type=Path, help="New independent output directory")
    args = parser.parse_args()
    try:
        result = validate_saved(args.case_dir, args.candidate_id, args.output_dir)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        parser.exit(2, f"Validation could not complete: {exc}\n")
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
