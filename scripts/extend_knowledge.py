#!/usr/bin/env python3
"""Build one uploaded source pair using the project's offline pipeline."""

import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.run_offline import create_index_builder
from config.runtime import load_config, resolve_offline_config
from utils.experiment_manifest import write_json_atomic
from utils.telemetry import Recorder, utc_now


def build_extension(input_path, base_index, output_dir, progress_path, config_path):
    events = []

    def progress(stage, view=""):
        subject = {"data_flow": "data-flow", "control_flow": "control-flow"}.get(view, "")
        message = {
            "models": "Loading the configured offline models",
            "extraction": f"Extracting {subject} repair knowledge",
            "distillation": f"Distilling {subject} knowledge",
            "embedding": f"Embedding {subject} knowledge",
            "saving": "Saving and checking the expanded index",
            "built": "Both knowledge views are ready for publication",
        }[stage]
        events.append({"time": utc_now(), "message": message})
        write_json_atomic(progress_path, {"stage": stage, "view": view, "events": events})

    config = resolve_offline_config(load_config(config_path))
    sample = json.loads(Path(input_path).read_text(encoding="utf-8"))
    args = SimpleNamespace(llm_provider=None, llm_base_url=None, llm_model=None, views=None)
    progress("models")
    builder = create_index_builder(args, config)
    builder.progress_callback = progress
    with Recorder(output_dir, phase="offline").activate():
        builder.build_incremental([sample], base_index, output_dir)
        # A skipped view is a failed extension, even if the batch CLI can keep it.
        if builder.build_report["status"] != "complete" or any(
            item["sample_ids"] != [sample["sample_id"]]
            for item in builder.build_report["views"].values()
        ):
            raise ValueError("The sample could not be built in both views. Check the offline model output and retry.")
    progress("built")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input", "base-index", "output-dir", "progress", "config"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        build_extension(args.input, args.base_index, args.output_dir, args.progress, args.config)
    except Exception as exc:
        write_json_atomic(args.progress.with_name("error.json"), {"error": f"{type(exc).__name__}: {exc}"})
        raise


if __name__ == "__main__":
    main()
