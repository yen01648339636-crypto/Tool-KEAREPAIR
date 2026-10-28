"""Bounded generation and validation of diffs against one immutable source snapshot."""

from copy import deepcopy
import time
from pathlib import Path

from utils.diagnostics import diagnostic_text
from utils.exemplars import render_exemplars
from utils.patches import PatchError, prepare_candidate, target_path
from utils.source_context import numbered_source, select_source_context
from .repair_hints import extract_structured_test_feedback
from utils.telemetry import (
    text_call,
    current_recorder,
    stage as telemetry_stage,
    measure,
)
from utils.experiment_store import persist_attempt, digest
from utils.metrics import fully_validated
from utils.validation import new_validation, finish_validation, set_stage
from utils.runtime_progress import progress_event
from utils.validation_scope import validation_mode, requested_stages, decorate_validation


class RepairAgent:
    def __init__(
        self,
        llm_interface,
        validator,
        max_iterations=5,
        single_attempt=False,
        sampling=None,
        max_exemplars=4,
    ):
        if type(max_iterations) is not int or max_iterations < 1:
            raise ValueError("max_iterations must be positive")
        self.llm, self.validator = llm_interface, validator
        self.max_iterations, self.single_attempt = max_iterations, single_attempt
        self.sampling = sampling or {}
        self.max_exemplars = max_exemplars
        self.repair_history = []
        self.last_rendered_exemplars = []
        self.last_generation = {}
        directory = Path(__file__).resolve().parents[2] / "prompts/online/repair"
        self.prompts = {
            name: (directory / f"{name}.txt").read_text(encoding="utf-8")
            for name in ("initial_repair", "refine_repair", "exemplar_template")
        }

    def _context(self, code, project_info):
        context = (project_info or {}).get("source_context")
        if context is None:
            _, context = select_source_context(code)
        settings = {"strategy": context["strategy"]}
        if context["strategy"] == "line_range":
            settings.update(
                start_line=context["window_start"],
                end_line=context["window_end"],
                line_hint_source=context["selection_source"],
            )
        canonical = select_source_context(code, settings)[1]
        if canonical != context:
            raise ValueError(
                "Source context does not describe the current original source"
            )
        return context

    def _build_initial_prompt(
        self, buggy_code, exemplars, diagnostic_report=None, project_info=None
    ):
        examples, records = render_exemplars(exemplars, self.max_exemplars)
        self.last_rendered_exemplars.clear()
        self.last_rendered_exemplars.extend(records)
        section = (
            self.prompts["exemplar_template"].format(examples=examples)
            if records
            else "No retrieved examples."
        )
        context = self._context(buggy_code, project_info)
        return self.prompts["initial_repair"].format(
            target_path=target_path(project_info),
            diagnostic_report=(
                diagnostic_text(diagnostic_report)
                if diagnostic_report
                else "No diagnostic report supplied."
            ),
            exemplars_section=section,
            buggy_code=numbered_source(buggy_code, context),
            source_context=self._context_note(context),
        )

    @staticmethod
    def _context_note(context):
        return f"Original-file lines {context['window_start']}-{context['window_end']} of {context['total_lines']}; source selection: {context['strategy']} ({context['selection_source']}). Original line endings: {context['line_ending_style']}; final newline: {context['final_newline']}. Use the standard no-newline marker where needed. Display prefixes are original line numbers, not source text. Diff line numbers MUST use this original-file coordinate system."

    def _generate(self, prompt, stage):
        options = dict(
            self.sampling.get(
                stage,
                {
                    "temperature": getattr(self.llm, "temperature", 0.0),
                    "max_tokens": getattr(self.llm, "max_tokens", 16384),
                },
            )
        )
        effective = (
            self.llm.effective_sampling(**options)
            if hasattr(self.llm, "effective_sampling")
            else options
        )
        self.last_generation = dict(
            stage=stage,
            requested_sampling=options,
            effective_sampling=deepcopy(effective),
            raw_response=None,
        )
        response = text_call(self.llm, prompt, stage, **options)
        self.last_generation["raw_response"] = response
        self.last_generation["provider_parameters"] = deepcopy(
            getattr(self.llm, "last_call_parameters", {})
        )
        return response

    def _generate_initial_patch(
        self, buggy_code, exemplars, diagnostic_report=None, project_info=None
    ):
        return self._generate(
            self._build_initial_prompt(
                buggy_code, exemplars, diagnostic_report, project_info
            ),
            "initial_repair",
        )

    def _refine_patch(
        self,
        buggy_code,
        previous_patch,
        error_log,
        iteration,
        project_info=None,
        diagnostic_report=None,
    ):
        context = self._context(buggy_code, project_info)
        prompt = self.prompts["refine_repair"].format(
            target_path=target_path(project_info),
            buggy_code=numbered_source(buggy_code, context),
            previous_patch=previous_patch,
            error_log=error_log,
            structured_feedback=extract_structured_test_feedback(error_log),
            diagnostic_report=(
                diagnostic_text(diagnostic_report)
                if diagnostic_report
                else "No diagnostic report supplied."
            ),
            source_context=self._context_note(context),
            iteration=iteration,
        )
        return self._generate(prompt, "refine_repair")

    def repair(self, buggy_code, exemplars, diagnostic_report=None, project_info=None,
               *, defer_validation=False):
        mode = validation_mode(project_info)
        scoped = "studio_validation_mode" in (project_info or {})
        defer_validation = defer_validation or mode == "patch_only"
        self.repair_history = []
        self.last_rendered_exemplars.clear()
        budget = 1 if self.single_attempt else self.max_iterations
        recorder = current_recorder()
        calls_before = getattr(self.llm, "request_attempt_count", None)
        result = dict(
            success=False,
            buggy_code=buggy_code,
            final_patch=None,
            iterations=0,
            history=self.repair_history,
            rendered_exemplars=self.last_rendered_exemplars,
            generation_count=0,
            validation_count=0,
            llm_call_count=0,
            termination_reason="budget_exhausted",
            source_context=self._context(buggy_code, project_info),
        )
        if scoped:
            result.update(validation_mode=mode, requested_stages=list(requested_stages(mode)),
                          selected_checks_passed=False)
        previous, feedback = "", ""
        for number in range(1, budget + 1):
            candidate_id = (recorder.attempt_offset if recorder else 0) + number
            progress_event(f"Generating patch · attempt {number} of {budget}", "running", kind="generation", candidate_id=candidate_id, iteration=number)
            attempt = dict(
                iteration=number,
                candidate_id=candidate_id,
                patch=None,
                raw_response=None,
                validation_result=None,
                validation_invoked=False,
            )
            self.repair_history.append(attempt)
            result["iterations"] = number
            result["generation_count"] += 1
            result["llm_call_count"] += 1
            with telemetry_stage("repair", candidate_id=candidate_id):
                try:
                    try:
                        raw = (
                            self._generate_initial_patch(
                                buggy_code, exemplars, diagnostic_report, project_info
                            )
                            if number == 1
                            else self._refine_patch(
                                buggy_code,
                                previous,
                                feedback,
                                number,
                                project_info,
                                diagnostic_report,
                            )
                        )
                        attempt.update(deepcopy(self.last_generation))
                    except BaseException as exc:
                        attempt.update(deepcopy(self.last_generation))
                        attempt["generation_error"] = str(exc)
                        result["termination_reason"] = "generation_error"
                        raise
                    previous = raw
                    info = {
                        **(project_info or {}),
                        "candidate_id": str(candidate_id),
                        "raw_patch_hash": digest(raw),
                    }
                    patch_started = time.monotonic()
                    try:
                        with measure("patch_prepare"):
                            prepared = prepare_candidate(
                                buggy_code,
                                raw,
                                target_path(project_info),
                                result["source_context"],
                            )
                        patch = prepared.patch
                        attempt.update(
                            patch=patch, corrected_patch=patch,
                            generated_patch=prepared.raw_diff, hunk_ranges=prepared.ranges,
                            patch_correction=prepared.correction,
                        )
                        info["generated_patch"] = prepared.raw_diff
                        previous = patch
                    except PatchError as exc:
                        attempt.update(generated_patch=exc.raw_diff, patch_correction=exc.correction)
                        validation = new_validation(buggy_code, raw, info)
                        validation.update(
                            generated_patch_hash=digest(exc.raw_diff) if exc.raw_diff is not None else None,
                            patch_correction=exc.correction,
                        )
                        set_stage(
                            validation,
                            "patch_apply",
                            "failed",
                            time.monotonic() - patch_started,
                            stderr=str(exc),
                        )
                        validation = finish_validation(validation)
                    else:
                        if defer_validation:
                            # Persist the exact prepared diff for explicit validation later.
                            # No compilation, PoC or unit test runs at this boundary.
                            pending = new_validation(buggy_code, raw, info)
                            pending.update(
                                effective_patch_hash=digest(patch),
                                generated_patch_hash=digest(prepared.raw_diff),
                                corrected_patch_hash=digest(patch),
                                patch_correction=prepared.correction,
                            )
                            attempt["validation_result"] = finish_validation(pending)
                            if scoped:
                                attempt["validation_result"] = decorate_validation(attempt["validation_result"], mode)
                            result.update(selected_candidate=candidate_id,
                                          termination_reason="awaiting_validation")
                            break
                        result["validation_count"] += 1
                        attempt["validation_invoked"] = True
                        # Publish the prepared patch before a potentially long validation.
                        # Its validation_result remains absent until actual checks finish.
                        persist_attempt(attempt)
                        progress_event(f"Patch {candidate_id} generated; starting validation", kind="patch", candidate_id=candidate_id)
                        validation = self.validator.validate(buggy_code, patch, info)
                        validation.update(
                            candidate_id=str(candidate_id),
                            raw_patch_hash=digest(raw),
                            effective_patch_hash=digest(patch),
                            original_source_hash=digest(buggy_code),
                            generated_patch_hash=digest(prepared.raw_diff),
                            corrected_patch_hash=digest(patch),
                            patch_correction=prepared.correction,
                        )
                        # A legacy boolean is insufficient evidence for complete validation.
                        validation["success"] = fully_validated(validation)
                        result["final_patch"] = patch
                        result["selected_candidate"] = candidate_id
                    if scoped:
                        validation = decorate_validation(validation, mode)
                        result["selected_checks_passed"] = validation["selected_checks_passed"]
                    attempt["validation_result"] = validation
                    checks_passed = validation["success"] or (scoped and validation["selected_checks_passed"])
                    label = "selected validation checks" if mode == "poc" else "validation"
                    progress_event(f"Patch {candidate_id} {label} " + ("passed" if checks_passed else "did not pass"),
                                   "completed" if checks_passed else "failed", kind="validation", candidate_id=candidate_id)
                    if validation["success"]:
                        result.update(success=True, termination_reason="validated")
                        break
                    if mode == "poc" and checks_passed:
                        result["termination_reason"] = "requested_checks_passed"
                        break
                    error = str(validation.get("error_log") or "")
                    if ("container original differs from saved source" in error
                            or "image changed after source preflight" in error
                            or "Docker tag resolved to another image within this experiment" in error):
                        # A changed input/environment cannot be fixed by asking
                        # the model for four more versions of the same patch.
                        result.update(termination_reason="source_baseline_mismatch",
                                      error="源码或镜像在前置检查后发生变化，请重新检查案例并新建任务。\n" + error)
                        break
                    feedback = "\n".join(
                        str(validation.get(key, ""))
                        for key in (
                            "stage",
                            "failed_stage",
                            "docker_step",
                            "error_log",
                            "error_message",
                        )
                        if validation.get(key)
                    )
                finally:
                    persist_attempt(attempt)
                    if calls_before is not None:
                        result["llm_call_count"] = (
                            self.llm.request_attempt_count - calls_before
                        )
        return result
