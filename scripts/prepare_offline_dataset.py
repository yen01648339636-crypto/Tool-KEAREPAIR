#!/usr/bin/env python3
"""Convert nested reference function pairs into audited offline training CSV.

No model, network, pandas or benchmark execution is required. Only pairs with
unique matching vul_/fix_ ID suffixes and identical repository file paths are
accepted. The original snippets are preserved byte-for-byte as UTF-8 text.
"""

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from utils.experiment_manifest import hash_object
from utils.knowledge import DatasetError, apply_unified_diff, load_exclusions, normalize_sample, prepare_dataset


FIELDS = ["sample_id", "cve_id", "project", "language", "cve_description",
          "buggy_code", "fixed_code", "patch", "source_provenance"]


def evaluation_cases(roots):
    """Explicitly audit the supplied local evaluation roots, never assume a split."""
    listings, identifiers = [], set()
    for supplied in roots:
        root = Path(supplied).expanduser().resolve(strict=True)
        paths = [root / "test_cmds.json"] if (root / "test_cmds.json").is_file() else sorted(root.glob("*/test_cmds.json"))
        if not paths:
            raise ValueError(f"No evaluation cases found under {root}")
        cases = []
        for path in paths:
            case_id = path.parent.name.upper()
            if not re.fullmatch(r"CVE-\d{4}-\d+", case_id):
                raise ValueError(f"Evaluation case has no unambiguous CVE ID: {path}")
            commands = json.loads(path.read_text(encoding="utf-8"))
            recorded = commands.get("cve_id")
            if recorded and str(recorded).strip().upper() != case_id:
                raise ValueError(f"Evaluation directory and recorded CVE disagree: {path}")
            cases.append(case_id)
            identifiers.add(case_id)
        listings.append(dict(root=str(root), case_ids=sorted(cases)))
    return identifiers, listings


def function_map(functions, prefix, base, report):
    if not isinstance(functions, list):
        raise ValueError(prefix + "func must be a list")
    groups = defaultdict(list)
    for position, function in enumerate(functions):
        identity = function.get("id") if isinstance(function, dict) else None
        if not isinstance(identity, str) or not identity.startswith(prefix) or identity == prefix:
            report["unmatched_functions"].append(dict(
                **base, side=prefix.rstrip("_"), function_position=position,
                function_id=identity, reason="missing_or_unsupported_function_id"))
            continue
        groups[identity[len(prefix):]].append((position, function))
    return dict(groups)


def convert(rows, *, input_path, input_sha256, excluded_cves=(), evaluation_roots=()):
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("The input JSON must be a list of vulnerability objects")
    excluded = {value.strip().upper() for value in excluded_cves}
    report = dict(
        schema_version="1.0", preparation_version="1.0",
        source=dict(path=str(input_path), sha256=input_sha256, record_count=len(rows)),
        policy=dict(pairing="unique_exact_vul_fix_id_suffix_and_same_file_path",
                    snippets="preserved_without_stripping_or_reformatting",
                    patch="generated_from_the_supplied_function_pair_then_exactly_reapplied",
                    validation="structural_and_diff_consistency_only_not_semantic_repair_validation",
                    exclusions="explicit_CVE_matches_only_not_a_complete_leakage_audit"),
        evaluation_exclusions=dict(roots=list(evaluation_roots), cve_ids=sorted(excluded),
                                   cve_list_sha256=hash_object(sorted(excluded))),
        excluded_records=[], rejected_records=[], unmatched_functions=[], rejected_pairs=[],
        paired_records=[], duplicate_pairs=[], accepted_samples=[],
    )
    validated = []
    origins = {}
    for row_number, row in enumerate(rows):
        cve = row.get("cve_id")
        base = dict(source_row=row_number, cve_id=cve)
        if not isinstance(cve, str) or not re.fullmatch(r"CVE-\d{4}-\d+", cve.strip(), re.I):
            report["rejected_records"].append(dict(**base, reason="missing_or_invalid_cve_id"))
            continue
        cve = cve.strip().upper()
        base["cve_id"] = cve
        if cve in excluded:
            report["excluded_records"].append(dict(**base, reason="explicit_evaluation_cve_exclusion"))
            continue
        description = row.get("cve_description")
        if not isinstance(description, str) or not description.strip():
            report["rejected_records"].append(dict(**base, reason="missing_cve_description"))
            continue
        try:
            before = function_map(row.get("vul_func"), "vul_", base, report)
            after = function_map(row.get("fix_func"), "fix_", base, report)
        except ValueError as exc:
            report["rejected_records"].append(dict(**base, reason="invalid_function_lists", detail=str(exc)))
            continue
        for key in sorted(set(before) | set(after)):
            old, new = before.get(key, []), after.get(key, [])
            if len(old) != 1 or len(new) != 1:
                reason = "ambiguous_duplicate_id" if len(old) > 1 or len(new) > 1 else "no_matching_counterpart"
                for side, functions in (("vul", old), ("fix", new)):
                    for position, function in functions:
                        report["unmatched_functions"].append(dict(
                            **base, side=side, function_position=position,
                            function_id=function["id"], reason=reason))
                continue
            old_position, original = old[0]
            new_position, fixed = new[0]
            pair = dict(**base, vulnerable_id=original["id"], fixed_id=fixed["id"],
                        vulnerable_position=old_position, fixed_position=new_position)
            file_path = original.get("file_path")
            if not isinstance(file_path, str) or not file_path.strip() or file_path != fixed.get("file_path"):
                report["rejected_pairs"].append(dict(**pair, reason="missing_or_different_file_paths",
                    vulnerable_path=file_path, fixed_path=fixed.get("file_path")))
                continue
            try:
                supplied = dict(
                    cve_id=cve, cve_description=description,
                    project=row.get("repo") or "", language=row.get("programming_language") or "",
                    buggy_code=original.get("snippet"), fixed_code=fixed.get("snippet"),
                    source_provenance=dict(
                        source_file=str(input_path), source_sha256=input_sha256, source_row=row_number,
                        repository=row.get("repo"), patch_urls=row.get("patch_url", []),
                        vulnerable_function={k: v for k, v in original.items() if k != "snippet"},
                        fixed_function={k: v for k, v in fixed.items() if k != "snippet"},
                        original_patch_handling="function_pair_is_authoritative_external_patch_not_used",
                    ),
                )
                sample = normalize_sample(supplied)
                if apply_unified_diff(sample["buggy_code"], sample["patch"]) != sample["fixed_code"]:
                    raise DatasetError("Generated patch does not reproduce the supplied fixed function")
            except (TypeError, ValueError) as exc:
                report["rejected_pairs"].append(dict(**pair, reason="invalid_source_pair", detail=str(exc)))
                continue
            validated.append(sample)
            pair.update(sample_id=sample["sample_id"], file_path=file_path)
            report["paired_records"].append(pair)
            origins.setdefault(sample["sample_id"], pair)
    if validated:
        samples, checked = prepare_dataset(validated)
        report["duplicate_pairs"] = [dict(**item, source_pair=report["paired_records"][item["row"]])
                                     for item in checked["duplicates"]]
    else:
        samples = []
    report["accepted_samples"] = [dict(sample_id=s["sample_id"], cve_id=s["cve_id"],
                                       source_pair=origins[s["sample_id"]]) for s in samples]
    report["counts"] = dict(
        input_records=len(rows), excluded_records=len(report["excluded_records"]),
        rejected_records=len(report["rejected_records"]),
        unmatched_functions=len(report["unmatched_functions"]), rejected_pairs=len(report["rejected_pairs"]),
        valid_pairs_before_deduplication=len(validated), duplicate_pairs=len(report["duplicate_pairs"]),
        accepted_samples=len(samples), accepted_cves=len({s["cve_id"] for s in samples}),
    )
    report["language_counts"] = dict(sorted(Counter(s["language"] for s in samples).items()))
    return samples, report


def encode_csv(samples):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=FIELDS)
    writer.writeheader()
    for sample in samples:
        row = {key: sample[key] for key in FIELDS}
        row["source_provenance"] = json.dumps(row["source_provenance"], ensure_ascii=False, sort_keys=True)
        writer.writerow(row)
    content = stream.getvalue()
    # Verify the exact CSV bytes/quoting that the offline loader will read.
    decoded = list(csv.DictReader(io.StringIO(content, newline="")))
    reconstructed, _ = prepare_dataset(decoded)
    if reconstructed != samples:
        raise ValueError("CSV round trip changed a source pair or its metadata")
    return content.encode("utf-8")


def write_new_or_identical(path, content):
    path = Path(path)
    if path.exists():
        if path.read_bytes() == content:
            return False
        raise ValueError(f"Refusing to replace an existing different output: {path}; choose a new path")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".offline-dataset-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
        # Linking publishes a complete file and fails if another writer won.
        os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "data/raw/Offline-dataset.csv")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--exclude-evaluation-root", type=Path, action="append", default=[])
    parser.add_argument("--exclude-cves", type=Path)
    parser.add_argument("--write", action="store_true", help="Write the validated CSV and audit report; otherwise only print the audit summary")
    args = parser.parse_args(argv)
    try:
        source = args.input.expanduser().resolve(strict=True)
        output = args.output.expanduser().resolve()
        audit_path = (args.report or output.with_suffix(".report.json")).expanduser().resolve()
        if output.suffix.lower() != ".csv" or audit_path.suffix.lower() != ".json":
            raise ValueError("Output must be .csv and report must be .json")
        if source in {output, audit_path}:
            raise ValueError("Outputs must not overwrite the input JSON")
        raw = source.read_bytes()
        excluded, roots = evaluation_cases(args.exclude_evaluation_root)
        if args.exclude_cves:
            excluded.update(load_exclusions(args.exclude_cves))
        samples, report = convert(json.loads(raw.decode("utf-8-sig")), input_path=source,
                                  input_sha256=hashlib.sha256(raw).hexdigest(),
                                  excluded_cves=excluded, evaluation_roots=roots)
        content = encode_csv(samples) if samples else None
        report["output"] = dict(path=str(output), sha256=hashlib.sha256(content).hexdigest() if content else None)
        report_content = (json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
        # Preflight all destinations before creating either artifact.
        if args.write:
            for path, data in ((audit_path, report_content), (output, content)):
                if data is not None and path.exists() and path.read_bytes() != data:
                    raise ValueError(f"Refusing to replace an existing different output: {path}")
            write_new_or_identical(audit_path, report_content)
            if content is not None:
                write_new_or_identical(output, content)
        print(json.dumps(dict(counts=report["counts"], language_counts=report["language_counts"],
                              output=str(output), report=str(audit_path), written=bool(args.write and content)),
                         ensure_ascii=False, indent=2))
        return 0 if samples else 2
    except (ValueError, OSError) as exc:
        print(json.dumps(dict(error=str(exc)), ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
