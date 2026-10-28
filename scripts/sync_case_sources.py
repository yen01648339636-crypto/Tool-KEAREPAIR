#!/usr/bin/env python3
"""Audit both container preparation paths and optionally align prepared case sources."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from utils.source_baseline import DockerSourceProbe, inspect_baseline, select_source, atomic_bytes, sha256, verified_receipt
from utils.experiment_manifest import write_json_atomic


def audit_case(path, output, apply=False, timeout=600, reuse_verified=False):
    key = path.parent.parent.name + ":" + path.parent.name
    directory = output / "cases" / path.parent.parent.name / path.parent.name
    directory.mkdir(parents=True, exist_ok=True)
    try:
        commands = json.loads(path.read_text())
        source_file = select_source(path.parent, commands)
        original = source_file.read_bytes()
        probe = DockerSourceProbe(timeout=timeout)
        cached = verified_receipt(original, commands, probe.image_id(commands["docker_image"]), path.parent / "source_baseline.json") if reuse_verified else None
        baseline, receipt = (original, cached) if cached else inspect_baseline(commands, probe)
        (directory / "source.before").write_bytes(original)
        (directory / "source.container").write_bytes(baseline)
        changed = original != baseline
        receipt.update(original_sha256=sha256(original), changed=changed, case=key)
        write_json_atomic(directory / "baseline.json", receipt)
        if apply:
            if source_file.read_bytes() != original:
                raise ValueError("Case changed during inspection; refusing overwrite")
            if changed:
                atomic_bytes(source_file, baseline)
            if not cached:
                write_json_atomic(path.parent / "source_baseline.json", receipt)
            meta_file = path.parent / "case_meta.json"
            if meta_file.is_file():
                raw_meta = meta_file.read_bytes()
                metadata = json.loads(raw_meta)
                (directory / "case_meta.before.json").write_bytes(raw_meta)
                metadata["source_authority"] = "prepared_container"
                metadata["container_source_baseline"] = {
                    "receipt": "source_baseline.json", "sha256": receipt["source_sha256"],
                    "docker_image_id": receipt["docker_image_id"],
                    "configuration_sha256": receipt["configuration_sha256"],
                }
                atomic_bytes(meta_file, (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode())
        return dict(case=key, status="aligned" if apply and changed else "mismatch" if changed else "matched",
                    changed=changed, cache_reused=bool(cached), receipt=str(directory / "baseline.json"))
    except Exception as exc:
        result = dict(case=key, status="blocked", error=str(exc))
        write_json_atomic(directory / "error.json", result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=ROOT / "data/processed")
    parser.add_argument("--dataset", choices=["Vul4c", "PatchEval", "all"], default="all")
    parser.add_argument("--case", action="append", help="Optional CVE ID; may repeat")
    parser.add_argument("--apply", action="store_true", help="Align source and save receipt; archive original first")
    parser.add_argument("--workers", type=int, choices=range(1, 9), default=3)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--reuse-verified", action="store_true", help="Resume an audit using matching immutable-image/source/recipe receipts")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    output = args.output_dir or ROOT / "results/source_baseline_audit" / datetime.now().strftime("%Y%m%d-%H%M%S")
    output.mkdir(parents=True, exist_ok=False)
    paths = [p for dataset in ([args.dataset] if args.dataset != "all" else ["PatchEval", "Vul4c"])
             for p in sorted((args.data_root / dataset).glob("*/test_cmds.json"))
             if not args.case or p.parent.name in args.case]
    results = []
    if not paths:
        parser.error("No matching prepared cases")
    print(f"AUDIT_DIR={output} CASES={len(paths)}", flush=True)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        jobs = [pool.submit(audit_case, path, output, args.apply, args.timeout, args.reuse_verified) for path in paths]
        for future in as_completed(jobs):
            result = future.result()
            results.append(result)
            print(f"[{len(results)}/{len(paths)}] {result['case']} {result['status']}" + (" " + result['error'][-300:] if result.get('error') else ""), flush=True)
            write_json_atomic(output / "report.json", {"total": len(paths), "finished": len(results), "apply": args.apply,
                "audit_scope": "prepared_container_source", "model_calls": 0,
                "counts": {s: sum(r['status'] == s for r in results) for s in ("matched", "mismatch", "aligned", "blocked")},
                "cases": sorted(results, key=lambda r: r['case'])})
    return 1 if any(r['status'] in {"blocked", "mismatch"} for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
