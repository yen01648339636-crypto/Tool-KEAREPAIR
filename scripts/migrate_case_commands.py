#!/usr/bin/env python3
"""Audit or migrate prepared benchmark commands without models or Docker."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils.case_commands import CommandMigrationError, migrate_record


def source_file(case_dir, record, dataset):
    if dataset == "Vul4c":
        target = record.get("source_file", "")
        if not target or not (case_dir / target).is_file():
            raise CommandMigrationError("Vul4C source_file is missing")
        return target
    suffix = {"python": ".py", "javascript": ".js", "go": ".go"}.get(
        str(record.get("programming_language", "")).lower()
    )
    files = [p for p in case_dir.rglob("*" + (suffix or ".unsupported"))
             if p.is_file() and "__pycache__" not in p.parts]
    if len(files) != 1:
        raise CommandMigrationError("Expected one unambiguous PatchEval source file")
    relative = files[0].relative_to(case_dir)
    if len(relative.parts) < 2 or not re.fullmatch(r"[0-9a-f]{7,40}", relative.parts[0]):
        raise CommandMigrationError("Expected a commit directory before the source path")
    return Path(*relative.parts[1:]).as_posix()


def atomic_write(path, content):
    mode = path.stat().st_mode & 0o777
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=Path(__file__).resolve().parents[1] / "data/processed")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="Back up originals, then migrate all validated records")
    mode.add_argument("--check", action="store_true", help="Exit nonzero if any record still needs migration")
    parser.add_argument("--backup-dir", type=Path)
    args = parser.parse_args(argv)
    plans, errors, counts = [], [], Counter()
    for dataset in ("Vul4c", "PatchEval"):
        root = args.data_root / dataset
        paths = sorted(root.glob("*/test_cmds.json"))
        if not paths:
            errors.append(f"{root}: no case command records found")
        for path in paths:
            try:
                original = path.read_bytes()
                record = json.loads(original)
                migrated = migrate_record(record, dataset=dataset, case_id=path.parent.name,
                                          source_file=source_file(path.parent, record, dataset))
                counts[dataset] += 1
                if migrated != record:
                    content = (json.dumps(migrated, ensure_ascii=False, indent=2) + "\n").encode()
                    plans.append((path, original, content))
            except (ValueError, OSError, KeyError) as exc:
                errors.append(f"{path}: {exc}")
    report = dict(cases=dict(counts), needs_migration=len(plans), errors=errors,
                  written=0, backup_dir=None)
    if errors:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 2
    if args.write and plans:
        backup = args.backup_dir or args.data_root.parent / "validation_migration" / uuid4().hex
        backup.mkdir(parents=True, exist_ok=False)
        entries = []
        for path, original, content in plans:
            target = backup / path.relative_to(args.data_root)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(original)
            entries.append(dict(path=path.relative_to(args.data_root).as_posix(),
                                original_sha256=hashlib.sha256(original).hexdigest(),
                                migrated_sha256=hashlib.sha256(content).hexdigest()))
        (backup / "manifest.json").write_text(json.dumps(entries, indent=2) + "\n")
        written = []
        try:
            for path, original, content in plans:
                if path.read_bytes() != original:
                    raise CommandMigrationError(f"Case changed during migration: {path}")
                atomic_write(path, content)
                written.append((path, original))
        except BaseException:
            for path, original in reversed(written):
                atomic_write(path, original)
            raise
        report.update(written=len(plans), backup_dir=str(backup))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if args.check and plans else 0


if __name__ == "__main__":
    raise SystemExit(main())
