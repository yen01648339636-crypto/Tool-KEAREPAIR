#!/usr/bin/env python3
"""Start KeaRepair on the local computer."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description="KeaRepair · local repair workbench")
    parser.add_argument("--port", type=int, default=7860)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "results/studio")
    parser.add_argument("--indices-dir", type=Path, default=ROOT / "data/indices/knowledge_index")
    parser.add_argument("--config", type=Path, default=ROOT / "config/online.yaml")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        import uvicorn
        from studio.app import create_app
    except ImportError as exc:
        parser.exit(1, f"Missing dependency: {exc}\nInstall: {sys.executable} -m pip install -r studio/requirements.txt\n")
    print(f"\n  KeaRepair  →  http://127.0.0.1:{args.port}\n", flush=True)
    app = create_app(ROOT, args.data_dir, args.indices_dir, args.config)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
