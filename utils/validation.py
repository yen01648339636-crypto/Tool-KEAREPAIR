"""Explicit validation states; absent stages never imply a successful repair."""

import hashlib
from utils.schemas import ValidationResult
from utils.metrics import STAGES


def text_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_validation(original, patch, info=None):
    info = info or {}
    return dict(
        candidate_id=str(info.get("candidate_id", "unassigned")),
        raw_patch_hash=info.get("raw_patch_hash") or text_hash(patch),
        original_source_hash=text_hash(original),
        effective_patch_hash=None,
        stage_status={stage: "not_run" for stage in STAGES},
        stage_details={
            stage: dict(
                duration_seconds=None,
                stdout=None,
                stderr=None,
                reason="Stage not executed",
            )
            for stage in STAGES
        },
        error_log="",
        docker_image=info.get("docker_image"),
        docker_digest=None,
    )


def set_stage(result, name, status, duration, **details):
    result["stage_status"][name] = status
    result["stage_details"][name] = dict(duration_seconds=duration, **details)
    if status in {"failed", "error"}:
        result["error_log"] = str(
            details.get("stderr")
            or details.get("reason")
            or details.get("stdout")
            or status
        )


def finish_validation(result):
    states = result["stage_status"]
    failed = next(
        (stage for stage in STAGES if states[stage] in {"failed", "error"}), None
    )
    kwargs = {key: value for key, value in result.items() if key != "stage_status"}
    kwargs.update({stage + "_status": status for stage, status in states.items()})
    kwargs["failed_stage"] = failed
    kwargs["stage"] = {
        "patch_apply": "patch_application",
        "compile": "compilation",
        "poc": "poc_test",
        "unit": "unit_test",
    }.get(
        failed,
        (
            "complete"
            if all(value == "passed" for value in states.values())
            else "validation_incomplete"
        ),
    )
    return ValidationResult(**kwargs).to_dict()
