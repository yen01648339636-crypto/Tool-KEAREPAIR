"""Canonical source pairs and validated knowledge at offline boundaries."""

import difflib
import hashlib
import json
import math
import re
from pathlib import Path

from utils.experiment_manifest import hash_object
from utils.schemas import ContractError, KnowledgeItems


class DatasetError(ValueError):
    def __init__(self, message, report=None):
        super().__init__(message)
        self.report = report


def load_exclusions(path):
    text = Path(path).read_text(encoding="utf-8")
    values = (
        json.loads(text)
        if Path(path).suffix.lower() == ".json"
        else [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    )
    if not isinstance(values, list) or any(
        not isinstance(value, str)
        or not re.fullmatch(r"CVE-\d{4}-\d+", value.strip(), re.IGNORECASE)
        for value in values
    ):
        raise DatasetError(
            "Exclusion file must contain a list of CVE-YYYY-NNNN identifiers"
        )
    return sorted({value.strip().upper() for value in values})


def apply_unified_diff(source, patch):
    """Apply one complete, exact unified diff; never guess offsets or drop hunks."""
    original = source.splitlines(keepends=True)
    lines = patch.splitlines(keepends=True)
    # A no-newline marker modifies the preceding logical diff line.
    cleaned = []
    for line in lines:
        if line.rstrip("\r\n") == "\\ No newline at end of file":
            if not cleaned or cleaned[-1][:1] not in {" ", "+", "-"}:
                raise DatasetError("Misplaced no-newline marker")
            cleaned[-1] = cleaned[-1].rstrip("\r\n")
        else:
            cleaned.append(line)
    lines = cleaned
    output, cursor, index, hunks, headers = [], 0, 0, 0, 0
    while index < len(lines):
        line = lines[index]
        if not line.startswith("@@ "):
            if hunks:
                raise DatasetError("Unexpected content after a diff hunk")
            if line.startswith("--- "):
                headers += 1
                if (
                    headers > 1
                    or index + 1 >= len(lines)
                    or not lines[index + 1].startswith("+++ ")
                ):
                    raise DatasetError("Expected a single-file unified diff")
                if "/dev/null" in line or "/dev/null" in lines[index + 1]:
                    raise DatasetError(
                        "File creation/deletion cannot repair a source pair"
                    )
                index += 2
                continue
            if not line.startswith(("diff --git ", "index ")):
                raise DatasetError("Expected unified diff headers or a hunk")
            index += 1
            continue
        match = re.match(
            r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\r\n]*(?:\r?\n)?$", line
        )
        if not match:
            raise DatasetError("Malformed diff hunk header")
        old_start, old_count, new_start, new_count = match.groups()
        old_start, new_start = int(old_start), int(new_start)
        old_count = 1 if old_count is None else int(old_count)
        new_count = 1 if new_count is None else int(new_count)
        offset = old_start - 1 if old_count else old_start
        new_offset = new_start - 1 if new_count else new_start
        if offset < cursor or offset > len(original):
            raise DatasetError(
                "Diff hunk is outside the supplied source or overlaps another hunk"
            )
        output.extend(original[cursor:offset])
        if len(output) != new_offset:
            raise DatasetError(
                "Diff target position does not match the reconstructed source"
            )
        cursor = offset
        index += 1
        consumed = produced = 0
        while consumed < old_count or produced < new_count:
            if index >= len(lines) or lines[index][:1] not in {" ", "+", "-"}:
                raise DatasetError("Incomplete diff hunk")
            marker, content = lines[index][0], lines[index][1:]
            if marker in {" ", "-"}:
                if cursor >= len(original) or original[cursor] != content:
                    raise DatasetError(
                        "Diff context does not exactly match the supplied source"
                    )
                cursor += 1
                consumed += 1
            if marker in {" ", "+"}:
                output.append(content)
                produced += 1
            if consumed > old_count or produced > new_count:
                raise DatasetError("Diff hunk line counts are inconsistent")
            index += 1
        hunks += 1
    if not hunks:
        raise DatasetError(
            "Patch contains no unified diff hunks; supply fixed_code instead"
        )
    output.extend(original[cursor:])
    return "".join(output)


def _text(row, *names):
    for name in names:
        value = row.get(name)
        if value is None or (isinstance(value, float) and math.isnan(value)):
            continue
        if not isinstance(value, str):
            raise DatasetError(f"{name} must be text")
        if value.strip():
            return value
    return ""


def normalize_sample(row, *, source=None, row_index=None, max_code_length=None):
    if not isinstance(row, dict):
        raise DatasetError("Dataset rows must be objects")
    sample = {
        "cve_id": _text(row, "cve_id", "cve", "CVE_ID").strip(),
        "project": _text(row, "project", "project_name"),
        "language": _text(row, "language", "programming_language", "lang"),
        "cve_description": _text(row, "cve_description", "description", "summary"),
        "buggy_code": _text(row, "buggy_code", "vulnerable_code", "func_before"),
        "fixed_code": _text(row, "fixed_code", "patched_code", "func_after"),
        "patch": _text(row, "patch", "diff"),
    }
    for name in ("cve_description", "buggy_code"):
        if not sample[name].strip():
            raise DatasetError(f"Missing required {name}")
    if not (sample["fixed_code"].strip() or sample["patch"].strip()):
        raise DatasetError("A fixed function or a complete unified diff is required")
    if sample["patch"].strip():
        reconstructed = apply_unified_diff(sample["buggy_code"], sample["patch"])
        if sample["fixed_code"].strip() and sample["fixed_code"] != reconstructed:
            raise DatasetError("fixed_code disagrees with the applied diff")
        sample["fixed_code"] = reconstructed
    if not sample["fixed_code"].strip() or sample["fixed_code"] == sample["buggy_code"]:
        raise DatasetError(
            "The repaired function must be nonempty and differ from the vulnerable function"
        )
    if (
        max_code_length is not None
        and max(len(sample[k]) for k in ("buggy_code", "fixed_code")) > max_code_length
    ):
        raise DatasetError(
            f"Source pair exceeds the explicit max_code_length={max_code_length}"
        )
    if not sample["patch"]:
        # Ensure difflib emits distinct lines even when a function has no final newline.
        parts = difflib.unified_diff(
            sample["buggy_code"].splitlines(keepends=True),
            sample["fixed_code"].splitlines(keepends=True),
            fromfile="a/source",
            tofile="b/source",
        )
        sample["patch"] = "".join(
            line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
            for line in parts
        )
    provenance = row.get("source_provenance") or {}
    if isinstance(provenance, str):
        try:
            provenance = json.loads(provenance)
        except ValueError as exc:
            raise DatasetError("source_provenance must be a JSON object") from exc
    if not isinstance(provenance, dict):
        raise DatasetError("source_provenance must be an object")
    provenance = dict(provenance)
    for name in (
        "dataset",
        "source",
        "repository",
        "repo_url",
        "commit_id",
        "commit_hash",
        "file_path",
        "source_url",
    ):
        if row.get(name) is not None:
            provenance.setdefault(name, row[name])
    if source is not None:
        provenance.setdefault("source_file", str(source))
    if row_index is not None:
        provenance.setdefault("source_row", row_index)
    sample["source_provenance"] = provenance
    identity = row.get("sample_id", row.get("id"))
    if (
        identity is None
        or (isinstance(identity, float) and math.isnan(identity))
        or identity == ""
    ):
        identity = "sample-" + hash_object(
            {
                k: sample[k]
                for k in ("cve_id", "project", "language", "buggy_code", "fixed_code")
            }
        )
    if type(identity) not in (str, int) or not str(identity).strip():
        raise DatasetError("sample_id must be a nonempty string or integer")
    sample["sample_id"] = str(identity).strip()
    # Also verifies provenance is serializable and contains no NaN.
    hash_object(sample)
    return sample


def prepare_dataset(rows, *, source=None, excluded_cve_ids=(), max_code_length=None):
    excluded = {value.strip().upper() for value in excluded_cve_ids}
    report = {
        "input": [],
        "accepted": [],
        "duplicates": [],
        "excluded": [],
        "failed": [],
        "exclusion_cve_ids": sorted(excluded),
        "max_code_length": max_code_length,
    }
    samples, identities, content = [], {}, {}
    for index, row in enumerate(rows):
        try:
            input_hash = hash_object(row)
        except (TypeError, ValueError):
            input_hash = hashlib.sha256(repr(row).encode("utf-8")).hexdigest()
        entry = {"row": index, "input_hash": input_hash}
        report["input"].append(entry)
        try:
            sample = normalize_sample(
                row, source=source, row_index=index, max_code_length=max_code_length
            )
            entry = {
                **entry,
                "sample_id": sample["sample_id"],
                "cve_id": sample["cve_id"],
            }
            report["input"][-1] = entry
            if sample["cve_id"].upper() in excluded:
                report["excluded"].append({**entry, "reason": "explicit_cve_exclusion"})
                continue
            pair_hash = hash_object(
                {key: sample[key] for key in ("buggy_code", "fixed_code")}
            )
            identifier = sample["sample_id"]
            if identifier in identities and identities[identifier] != pair_hash:
                raise DatasetError(
                    f"Conflicting source pairs share sample_id={identifier}"
                )
            identities[identifier] = pair_hash
            if pair_hash in content:
                report["duplicates"].append(
                    {**entry, "kept_sample_id": content[pair_hash]}
                )
                continue
            content[pair_hash] = identifier
            samples.append(sample)
            report["accepted"].append(entry)
        except (ValueError, TypeError) as exc:
            report["failed"].append({**entry, "error": str(exc)})
    report["counts"] = {
        key: len(report[key])
        for key in ("input", "accepted", "duplicates", "excluded", "failed")
    }
    if report["failed"] or not samples:
        raise DatasetError(
            f"Dataset validation failed: {len(report['failed'])} invalid rows, {len(samples)} eligible samples",
            report,
        )
    return samples, report


def parse_knowledge(value, view_type):
    """Accept a single JSON object, optionally fenced, then enforce the view contract."""
    if view_type not in {"data_flow", "control_flow"}:
        raise ContractError("Unknown knowledge view")
    if isinstance(value, KnowledgeItems):
        value = value.to_dict()
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("```"):
            match = re.fullmatch(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
            if not match:
                raise ContractError("Expected one fenced JSON object")
            text = match.group(1)
        try:

            def unique_fields(pairs):
                result = {}
                for name, item in pairs:
                    if name in result:
                        raise ValueError(f"Duplicate JSON field: {name}")
                    result[name] = item
                return result

            value = json.loads(text, object_pairs_hook=unique_fields)
        except ValueError as exc:
            raise ContractError(f"Knowledge output is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError("Knowledge output must be an object")
    value = dict(value)
    if value.pop("view_type", view_type) != view_type:
        raise ContractError("Knowledge output has the wrong view_type")
    result = KnowledgeItems.from_dict(value)
    required = {"data_flow": "taint_flow", "control_flow": "control_branch"}.get(
        view_type
    )
    if required and not (getattr(result, required) or "").strip():
        raise ContractError(
            f"{required} must describe the view, including when no flow is applicable"
        )
    return result
