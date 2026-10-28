#!/usr/bin/env python3
"""Recompute an experiment from its fixed cases, requests and validation artifacts."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils.experiment_manifest import write_json_atomic
from utils.metrics import evaluate_experiment


def main():
    parser = argparse.ArgumentParser(description="Evidence-based repair evaluation")
    parser.add_argument("--experiment-dir", required=True)
    parser.add_argument("--output", help="Defaults to <experiment-dir>/summary.json")
    args = parser.parse_args()
    root = Path(args.experiment_dir)
    result = evaluate_experiment(root)
    default = "offline_summary.json" if result["phase"] == "offline" else "summary.json"
    write_json_atomic(Path(args.output) if args.output else root / default, result)
    print(json.dumps(result["metrics"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
