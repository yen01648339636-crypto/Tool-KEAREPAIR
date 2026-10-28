"""Resolve the atomically published generation of a local knowledge index."""

import json
from pathlib import Path
import re


def resolve_knowledge_index(directory):
    root = Path(directory).resolve()
    pointer = root / "active_index.json"
    if not pointer.exists():
        return root
    value = json.loads(pointer.read_text(encoding="utf-8"))
    generation = value.get("generation", "")
    if not re.fullmatch(r"extensions/[0-9a-f]{32}", generation):
        raise ValueError("Invalid active knowledge index generation")
    target = (root / generation).resolve()
    if not target.is_relative_to(root) or not target.is_dir():
        raise ValueError("Active knowledge index generation is unavailable")
    return target
