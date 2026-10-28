"""Deterministic candidate preparation followed by exact original-source application."""

from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath
import re
import shlex

from utils.knowledge import apply_unified_diff
from utils.patch_correction import ALGORITHM, correct_diff, edit_fingerprint, parse_diff


class PatchError(ValueError):
    def __init__(self, message, *, raw_diff=None, correction=None):
        super().__init__(message)
        self.raw_diff, self.correction = raw_diff, correction or {}


@dataclass(frozen=True)
class PreparedPatch:
    raw_diff: str
    patch: str
    fixed_source: str
    ranges: list
    correction: dict


def _hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def target_path(project_info=None):
    info = project_info or {}
    supplied = info.get("repo_relpath") or info.get("file_path")
    if not supplied:
        supplied = (
            str(info.get("buggy_code_file") or "file.txt")
            .replace("\\", "/")
            .rsplit("/", 1)[-1]
        )
    value = str(supplied).replace("\\", "/")
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or any(part in {"..", "."} for part in value.split("/"))
        or any(char in value for char in "\n\r\t\x00")
    ):
        raise PatchError("Target must be a safe repository-relative path")
    return str(path)


def extract_diff(response):
    if not isinstance(response, str):
        raise PatchError("Expected text containing one unified diff")
    text = response.lstrip("\r\n")
    if text.startswith("```"):
        fence = re.fullmatch(
            r"```(?:diff|patch)?\r?\n(.*?)^```[ \t]*(?:\r?\n)?",
            text,
            re.DOTALL | re.MULTILINE,
        )
        if not fence:
            raise PatchError("Expected one complete diff fence")
        text = fence.group(1)
    if not text.startswith(("--- ", "diff --git ")):
        raise PatchError(
            "Return only a complete unified diff; full source, prose and XML are unsupported"
        )
    return text if text.endswith("\n") else text + "\n"


def _validate_target(patch, path):
    # Header-looking source lines inside a hunk begin with an extra +/- marker;
    # parse actual headers before the first hunk, leaving hunk contents untouched.
    prefix = patch.split("@@ ", 1)[0].splitlines()
    headers = [line for line in prefix if line.startswith(("--- ", "+++ "))]
    if headers != [f"--- a/{path}", f"+++ b/{path}"]:
        raise PatchError(f"Expected exactly --- a/{path} and +++ b/{path}")
    for line in prefix:
        if line.startswith("diff --git "):
            try:
                tokens = shlex.split(line)
            except ValueError as exc:
                raise PatchError("Malformed diff git header") from exc
            if tokens != ["diff", "--git", f"a/{path}", f"b/{path}"]:
                raise PatchError("Diff git header targets another file")


def _prepare_exact(original, response, path, source_context=None):
    path = target_path({"repo_relpath": path})
    patch = extract_diff(response)
    _validate_target(patch, path)
    ranges = []
    for match in re.finditer(
        r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", patch, re.MULTILINE
    ):
        start, count = int(match[1]), int(match[2]) if match[2] is not None else 1
        ranges.append(
            dict(
                old_start=start,
                old_count=count,
                new_start=int(match[3]),
                new_count=int(match[4]) if match[4] is not None else 1,
            )
        )
        if source_context and source_context.get("window_active"):
            low, high = source_context["window_start"], source_context["window_end"]
            if (
                count
                and (start < low or start + count - 1 > high)
                or not count
                and not low - 1 <= start <= high
            ):
                raise PatchError(
                    f"Hunk is outside visible original-file lines {low}-{high}; do not use window-local line numbers"
                )
    try:
        fixed = apply_unified_diff(original, patch)
    except ValueError as exc:
        raise PatchError(str(exc)) from exc
    if fixed == original:
        raise PatchError("Patch makes no change to the original source")
    return patch, fixed, ranges


def prepare_candidate(original, response, path, source_context=None):
    """Correct context/coordinates without changing any candidate edit bytes."""
    patch = None
    report = dict(algorithm=ALGORITHM, status="rejected", raw_diff_hash=None,
                  corrected_patch_hash=None, preserved_edits_hash=None,
                  strict_error=None, hunks=[], search={})
    try:
        patch = extract_diff(response)
        report["raw_diff_hash"] = _hash(patch)
        path = target_path({"repo_relpath": path})
        _validate_target(patch, path)
        _, hunks = parse_diff(patch)
        report["preserved_edits_hash"] = edit_fingerprint(hunks)
        try:
            effective, fixed, ranges = _prepare_exact(original, patch, path, source_context)
        except PatchError as exc:
            report["strict_error"] = str(exc)
            corrected, report["hunks"], report["search"] = correct_diff(original, patch, source_context)
            effective, fixed, ranges = _prepare_exact(original, corrected, path, source_context)
        else:
            report["hunks"] = [dict(hunk=index, original=hunk.ranges(), corrected=hunk.ranges(),
                                    edit_distance=0, context_changes=[]) for index, hunk in enumerate(hunks, 1)]
        report.update(status="unchanged" if effective == patch else "corrected",
                      corrected_patch_hash=_hash(effective))
        return PreparedPatch(patch, effective, fixed, ranges, report)
    except ValueError as exc:
        report["reason"] = str(exc)
        raise PatchError(str(exc), raw_diff=patch, correction=report) from exc


def prepare_patch(original, response, path, source_context=None, *, allow_correction=True):
    """Return the effective diff/source/ranges; archived effective diffs use strict mode."""
    if not allow_correction:
        return _prepare_exact(original, response, path, source_context)
    prepared = prepare_candidate(original, response, path, source_context)
    return prepared.patch, prepared.fixed_source, prepared.ranges
