"""Evidence-based evaluation from immutable case lists and candidate artifacts."""

from collections import Counter
import hashlib
import json
from pathlib import Path

from utils.telemetry import read_jsonl, request_records, accounted_requests, number
from utils.experiment_manifest import validate_manifest

STAGES = ("patch_apply", "compile", "poc", "unit")


def fully_validated(validation):
    states = validation.get("stage_status", {})
    return isinstance(states, dict) and all(
        states.get(name) == "passed" for name in STAGES
    )


def summarize_calls(records):
    result = dict(
        request_attempt_count=(
            None if any(item.get("count_unknown") for item in records) else len(records)
        ),
        known_request_attempt_count=sum(
            not item.get("count_unknown", False) for item in records
        ),
        failed_request_attempt_count=sum(
            item.get("status") == "failed" for item in records
        ),
        incomplete_request_attempt_count=sum(
            item.get("status") == "incomplete" for item in records
        ),
        retry_attempt_count=sum(
            (number(item.get("retry_index")) or 0) > 0 for item in records
        ),
        by_stage=dict(
            Counter(
                item.get("stage") if isinstance(item.get("stage"), str) else "unknown"
                for item in records
            )
        ),
    )
    for key in (
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cached_input_tokens",
        "cache_write_input_tokens",
        "reasoning_tokens",
    ):
        values = [
            (
                number(
                    item["usage"].get(
                        "total_input_tokens" if key == "input_tokens" else key
                    )
                )
                if isinstance(item.get("usage"), dict)
                else None
            )
            for item in records
        ]
        result[key] = (
            sum(values) if all(value is not None for value in values) else None
        )
        result["known_" + key] = sum(value for value in values if value is not None)
        result["unknown_" + key + "_calls"] = sum(value is None for value in values)
    result["input_token_semantics"] = (
        "includes_reported_cache_reads_and_writes; unknown_when_required_counts_missing"
    )
    for key in ("provider_cost", "estimated_cost"):
        values = [
            (
                value
                if isinstance(value := item.get(key), dict)
                and number(value.get("amount")) is not None
                and isinstance(value.get("currency"), str)
                and value["currency"].strip()
                else None
            )
            for item in records
        ]
        totals = Counter()
        for value in values:
            if value is not None:
                totals[value["currency"]] += value["amount"]
        result[key] = dict(
            total=(
                next(iter(totals.values()))
                if len(totals) == 1 and all(value is not None for value in values)
                else None
            ),
            currency=next(iter(totals)) if len(totals) == 1 else None,
            known_subtotals=dict(totals),
            unknown_calls=sum(value is None for value in values),
            coverage_complete=bool(values)
            and all(value is not None for value in values),
        )
    return result


def _json(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object: " + str(path))
    return value


def verify_attempt(case_dir, directory, manifest=None):
    """Only matching source/raw/effective hashes can support a positive claim."""
    validation = _json(directory / "validation.json")
    source = (case_dir / "source.original").read_bytes()
    source_info = _json(case_dir / "source.json")
    if source_info.get("manifest_key") is not None and not isinstance(
        source_info["manifest_key"], str
    ):
        raise ValueError("Invalid original source binding")
    source_hash = hashlib.sha256(source).hexdigest()
    if source_info.get("sha256") != source_hash:
        raise ValueError("Original source differs from its saved identity")
    if (
        manifest
        and manifest["data"]
        and manifest["data"].get(source_info.get("manifest_key"), {}).get("sha256")
        != source_hash
    ):
        raise ValueError("Original source differs from the manifest input")
    raw = (directory / "raw.patch").read_bytes()
    if (
        validation.get("original_source_hash") != source_hash
        or validation.get("raw_patch_hash") != hashlib.sha256(raw).hexdigest()
    ):
        raise ValueError("Candidate evidence hashes do not match saved artifacts")
    states = validation.get("stage_status", {})
    if (
        not isinstance(states, dict)
        or set(states) != set(STAGES)
        or any(
            not isinstance(status, str)
            or status not in {"passed", "failed", "error", "not_run"}
            for status in states.values()
        )
    ):
        raise ValueError("Invalid validation stage states")
    if validation.get("candidate_id") != directory.name:
        raise ValueError("Candidate directory and validation IDs differ")
    if (
        validation.get("docker_image")
        and any(states[name] != "not_run" for name in ("compile", "poc", "unit"))
        and not str(validation.get("docker_digest") or "").startswith("sha256:")
    ):
        raise ValueError("Container validation is missing an immutable image identity")
    if not isinstance(validation.get("artifacts"), dict):
        raise ValueError("Validation is missing its log inventory")
    for name in ("compile.log", "poc.log", "unit.log"):
        if (validation.get("artifacts") or {}).get(name) != hashlib.sha256(
            (directory / name).read_bytes()
        ).hexdigest():
            raise ValueError("Validation log missing or changed: " + name)
    from utils.patches import PatchError, extract_diff, prepare_candidate, prepare_patch, target_path

    preparation = validation.get("patch_correction")
    inputs = None
    if preparation:
        record_file = directory / "patch_correction.json"
        if validation["artifacts"].get(record_file.name) != hashlib.sha256(record_file.read_bytes()).hexdigest():
            raise ValueError("Patch correction record missing or changed")
        if _json(record_file) != preparation:
            raise ValueError("Validation and saved patch correction records differ")
        if preparation.get("raw_diff_hash") is None:
            # A non-diff response fails before target/window inspection and may
            # be archived before validation inputs have been materialized.
            replay_path, replay_context = "file.txt", None
        else:
            inputs = _json(case_dir / "inputs.json")["effective_validation"]
            if not isinstance(inputs, dict):
                raise ValueError("Invalid candidate validation inputs")
            replay_path, replay_context = target_path(inputs), inputs.get("source_context")
        try:
            replay = prepare_candidate(source.decode("utf-8"), raw.decode("utf-8"),
                                       replay_path, replay_context)
        except PatchError as exc:
            if exc.correction != preparation or preparation.get("status") != "rejected":
                raise ValueError("Patch correction rejection cannot be replayed") from exc
            if (any(status == "passed" for status in states.values())
                    or validation.get("effective_patch_hash") is not None
                    or validation.get("corrected_patch_hash") is not None):
                raise ValueError("Rejected correction cannot support a validation pass")
            if exc.raw_diff is not None:
                generated = (directory / "generated.patch").read_bytes()
                if generated != exc.raw_diff.encode("utf-8") or validation.get("generated_patch_hash") != hashlib.sha256(generated).hexdigest():
                    raise ValueError("Rejected diff differs from its saved source response")
            elif validation.get("generated_patch_hash") is not None:
                raise ValueError("Rejected response has no generated diff")
            return validation
        if replay.correction != preparation:
            raise ValueError("Patch correction does not match deterministic replay")
        for filename, expected, field in (
            ("generated.patch", replay.raw_diff, "generated_patch_hash"),
            ("corrected.patch", replay.patch, "corrected_patch_hash"),
        ):
            supplied = (directory / filename).read_bytes()
            if supplied != expected.encode("utf-8") or validation.get(field) != hashlib.sha256(supplied).hexdigest():
                raise ValueError("Patch preparation artifact differs from deterministic replay: " + filename)
    elif (validation.get("generated_patch_hash") is not None
          or validation.get("corrected_patch_hash") is not None
          or "patch_correction.json" in validation["artifacts"]):
        raise ValueError("Missing patch correction provenance")
    if (
        states["patch_apply"] != "passed"
        and validation.get("effective_patch_hash") is None
    ):
        return validation
    effective = (directory / "effective.patch").read_bytes()
    if validation.get("effective_patch_hash") != hashlib.sha256(effective).hexdigest():
        raise ValueError("Effective patch hash differs from saved artifact")
    # Reapply the actual saved patch, not only trust a serialized success flag.
    inputs = inputs if inputs is not None else _json(case_dir / "inputs.json")["effective_validation"]
    if not isinstance(inputs, dict):
        raise ValueError("Invalid candidate validation inputs")
    if preparation:
        if effective != replay.patch.encode("utf-8"):
            raise ValueError("Validated diff differs from the corrected candidate")
    elif extract_diff(raw.decode("utf-8")).encode("utf-8") != effective:
        raise ValueError("Unrecorded changes between raw and effective patches")
    _, fixed, _ = prepare_patch(
        source.decode("utf-8"),
        effective.decode("utf-8"),
        target_path(inputs),
        inputs.get("source_context"),
        allow_correction=False,
    )
    fixed_hash = hashlib.sha256(fixed.encode("utf-8")).hexdigest()
    if validation.get("validated_source_hash") not in (None, fixed_hash):
        raise ValueError("Validated source hash differs from the saved candidate")
    if validation.get("docker_image"):
        from utils.container_validation import verify_attestation

        for name in ("compile", "poc", "unit"):
            if states[name] != "passed":
                continue
            details = validation.get("stage_details", {}).get(name, {})
            filename = name + ".source.json"
            if validation.get("artifacts", {}).get(filename) != hashlib.sha256(
                (directory / filename).read_bytes()
            ).hexdigest():
                raise ValueError("Container source receipt missing or changed: " + filename)
            evidence = _json(directory / filename)
            if evidence != details.get("source_attestation"):
                raise ValueError("Stage and archived container source receipts differ")
            if validation.get("validated_source_hash") != fixed_hash:
                raise ValueError("Container validation has no tested-source identity")
            verify_attestation(
                evidence, candidate_id=directory.name, step_name=details.get("step_name"),
                target=target_path(inputs), patch_hash=validation["effective_patch_hash"],
                original_hash=source_hash, fixed_hash=fixed_hash,
                image_id=validation["docker_digest"],
            )
    return validation


def evaluate_experiment(directory):
    root = Path(directory)
    manifest = validate_manifest(_json(root / "manifest.json"))
    if manifest["identity"]["stage"] == "offline":
        timings, observations = Counter(), Counter()
        for event in read_jsonl(root / "timings.jsonl"):
            if number(event.get("duration_seconds")) is not None and isinstance(
                event.get("stage"), str
            ):
                timings[event["stage"]] += event["duration_seconds"]
                observations[event["stage"]] += 1
        return dict(
            experiment_id=manifest["experiment_id"],
            phase="offline",
            metrics=dict(
                offline_calls=summarize_calls(
                    request_records(root / "llm_calls.jsonl")
                ),
                measured_stage_seconds=dict(timings),
                stage_observations=dict(observations),
            ),
            runs=[_json(path) for path in sorted((root / "runs").glob("*/run.json"))],
        )
    if manifest["identity"]["stage"] != "online":
        raise ValueError("Repair evaluation requires an online experiment")
    cases = _json(root / "cases.json")
    if cases["experiment_id"] != manifest["experiment_id"]:
        raise ValueError("Case list and experiment identities differ")
    if {
        key: value for key, value in cases.items() if key != "experiment_id"
    } != manifest["parameters"].get("case_selection"):
        raise ValueError("Fixed case denominator differs from the manifest")
    ids = cases["case_ids"]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate case IDs in denominator")
    evaluations, calls = [], []
    timing_totals, timing_observations = Counter(), Counter()
    for case_id in ids:
        if Path(case_id).name != case_id or case_id in {".", ".."}:
            raise ValueError("Unsafe case ID")
        case_dir = root / "cases" / case_id
        status, error, result = "missing_result", None, {}
        try:
            result = _json(case_dir / "result.json")
            if (
                result["experiment_id"] != manifest["experiment_id"]
                or result["cve_id"] != case_id
            ):
                raise ValueError("Case result identity mismatch")
            claimed_status = result.get("status", "unknown")
            if not isinstance(claimed_status, str):
                raise ValueError("Invalid case result status")
            status = claimed_status
        except (OSError, ValueError, KeyError) as exc:
            error = str(exc)
            result = {}
        case_calls = accounted_requests(
            case_dir / "llm_calls.jsonl",
            result.get("llm_call_count"),
            evidence_of_calls=any((case_dir / "attempts").glob("*/attempt.json")),
        )
        calls.extend(case_calls)
        passed, poc, both, invalid, candidate_evidence = [], [], [], [], []
        directories = sorted(
            (case_dir / "attempts").glob("*"),
            key=lambda path: int(path.name) if path.name.isdigit() else -1,
        )
        evaluation_count = 0
        for attempt in directories:
            if not attempt.is_dir():
                continue
            try:
                attempt_record = _json(attempt / "attempt.json")
                if attempt_record.get("run_id") != result.get("run_id"):
                    continue
                evaluation_count += 1
                if attempt_record.get("generation_error") and not attempt_record.get(
                    "validation_result"
                ):
                    candidate_evidence.append(
                        dict(
                            candidate_id=attempt.name,
                            outcome="generation_error",
                            error=attempt_record["generation_error"],
                        )
                    )
                    continue
                validation = verify_attempt(case_dir, attempt, manifest)
                states = validation["stage_status"]
                candidate_evidence.append(
                    dict(
                        candidate_id=attempt.name,
                        outcome="validated",
                        stage_status=states,
                    )
                )
                if states["patch_apply"] == "passed" and states["poc"] == "passed":
                    poc.append(attempt.name)
                    if states["unit"] == "passed":
                        both.append(attempt.name)
                if fully_validated(validation):
                    passed.append(attempt.name)
            except (OSError, ValueError, KeyError) as exc:
                invalid.append(dict(candidate_id=attempt.name, reason=str(exc)))
        timings, wall_runs = Counter(), set()
        for event in read_jsonl(case_dir / "timings.jsonl"):
            if number(event.get("duration_seconds")) is not None and isinstance(
                event.get("stage"), str
            ):
                timings[event["stage"]] += event["duration_seconds"]
                timing_totals[event["stage"]] += event["duration_seconds"]
                timing_observations[event["stage"]] += 1
                if event["stage"] == "case_total":
                    wall_runs.add(event.get("run_id"))
        expected_wall_runs = {
            path.parents[2].name
            for path in (root / "runs").glob(f"*/cases/{case_id}/result.json")
        }
        if isinstance(result.get("run_id"), str):
            expected_wall_runs.add(result["run_id"])
        wall_complete = bool(expected_wall_runs) and expected_wall_runs <= wall_runs
        evaluations.append(
            dict(
                case_id=case_id,
                status=status,
                error=error,
                repaired=bool(passed),
                poc_pass=bool(poc),
                poc_and_unit_pass=bool(both),
                full_pass_candidate_ids=passed,
                poc_pass_candidate_ids=poc,
                poc_and_unit_candidate_ids=both,
                selected_candidate_id=result.get("selected_candidate"),
                candidate_count=evaluation_count,
                lifetime_candidate_count=len(directories),
                candidate_evidence=candidate_evidence,
                invalid_candidate_evidence=invalid,
                calls=summarize_calls(case_calls),
                timings_seconds=dict(timings),
                case_wall_seconds=timings["case_total"] if wall_complete else None,
            )
        )
    total = len(ids)
    count = lambda key: sum(item[key] for item in evaluations)
    unassigned_calls = [
        record
        for path in (root / "runs").glob("*/llm_calls.jsonl")
        for record in request_records(path)
    ]
    costs = summarize_calls(calls + unassigned_calls)
    run_timings = [
        event
        for path in (root / "runs").glob("*/timings.jsonl")
        for event in read_jsonl(path)
    ]
    for event in run_timings:
        if number(event.get("duration_seconds")) is not None and isinstance(
            event.get("stage"), str
        ):
            timing_totals[event["stage"]] += event["duration_seconds"]
            timing_observations[event["stage"]] += 1
    measured_runs = {
        event.get("run_id")
        for event in run_timings
        if event.get("stage") == "run_total"
        and number(event.get("duration_seconds")) is not None
    }
    expected_runs = {path.parent.name for path in (root / "runs").glob("*/run.json")}
    run_wall_complete = bool(expected_runs) and expected_runs <= measured_runs
    stages = (
        "model_loading",
        "diagnosis",
        "query_generation",
        "retrieval",
        "reranking",
        "generation",
        "repair",
        "patch_prepare",
        "patch_apply",
        "compile",
        "poc",
        "unit",
        "case_total",
        "run_total",
    )
    metrics = dict(
        denominator=total,
        repaired_cases=count("repaired"),
        repair_rate=count("repaired") / total if total else None,
        poc_pass_cases=count("poc_pass"),
        poc_pass_rate=count("poc_pass") / total if total else None,
        poc_and_unit_pass_cases=count("poc_and_unit_pass"),
        poc_and_unit_pass_rate=count("poc_and_unit_pass") / total if total else None,
        status_counts=dict(Counter(item["status"] for item in evaluations)),
        online_calls=costs,
        measured_stage_seconds={
            name: timing_totals[name] if timing_observations[name] else None
            for name in sorted(set(stages) | set(timing_totals))
        },
        stage_observations=dict(timing_observations),
        average_case_wall_seconds=(
            timing_totals["case_total"] / total
            if total
            and all(item["case_wall_seconds"] is not None for item in evaluations)
            else None
        ),
        average_run_wall_seconds_per_case=(
            timing_totals["run_total"] / total if total and run_wall_complete else None
        ),
        accounting_scope="latest_case_run_candidates; lifetime_request_costs_and_timings",
        run_wall_time_complete=run_wall_complete,
    )
    for key in ("provider_cost", "estimated_cost"):
        value = costs[key]["total"]
        metrics["average_" + key + "_per_case"] = (
            value / total if total and value is not None else None
        )
    metrics["unassigned_online_calls"] = summarize_calls(unassigned_calls)
    metrics["average_request_attempts_per_case"] = (
        costs["request_attempt_count"] / total
        if total and costs["request_attempt_count"] is not None
        else None
    )
    # Offline call accounting is independent and never silently added to online cost.
    return dict(
        experiment_id=manifest["experiment_id"],
        phase="online",
        metrics=metrics,
        cases=evaluations,
        exclusions=cases.get("excluded", []),
    )
