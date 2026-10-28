"""Local, bounded storage for test inputs uploaded through Studio.

File names are display metadata only. Opaque IDs choose storage locations, and
the task receives a verified, private byte-for-byte copy. This module never
executes, imports, extracts, or fetches uploaded content.
"""

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
from uuid import uuid4


MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_BASE64_CHARS = 4 * ((MAX_FILE_BYTES + 2) // 3)
KINDS = {"poc", "unit"}
UNIT_SUFFIXES = {".py", ".sh"}
_ID = re.compile(r"[0-9a-f]{32}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _kind(value):
    if not isinstance(value, str) or value not in KINDS:
        raise ValueError("Test input kind must be poc or unit.")
    return value


def _filename(value, kind):
    if (not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 255
            or value in {".", ".."} or re.search(r"[/\\\x00-\x1f\x7f]", value)):
        raise ValueError("Provide a file name without directory paths or control characters.")
    if kind == "unit" and Path(value).suffix.lower() not in UNIT_SUFFIXES:
        raise ValueError("Upload a Python (.py) or shell (.sh) unit test entry point.")
    return value


def _safe_directory(path):
    """Create one private directory while refusing a symlink at that position."""
    if path.is_symlink():
        raise ValueError("The test input storage location is invalid.")
    try:
        path.mkdir(mode=0o700, exist_ok=True)
        if not path.is_dir():
            raise ValueError("The test input storage location is invalid.")
    except OSError as exc:
        raise ValueError("The test input storage location is unavailable.") from exc


def _write_new(path, content):
    """Never overwrite or follow an existing file, even if a retry races."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def _read_regular(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("The saved test input is invalid or exceeds 10 MiB.")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("The saved test input exceeds 10 MiB.")
    return value


class TestInputStore:
    """Pass the Studio Store.directory as root; data is stored in root/uploads."""

    __test__ = False

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.directory = self.root / "uploads"
        _safe_directory(self.directory)

    def create(self, kind, filename, content_base64):
        kind = _kind(kind)
        filename = _filename(filename, kind)
        if not isinstance(content_base64, str):
            raise ValueError("Provide the file contents as a base64 string.")
        if len(content_base64) > MAX_BASE64_CHARS:
            raise ValueError("Each uploaded test input must be at most 10 MiB.")
        try:
            content = base64.b64decode(content_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("The uploaded file contents are not valid base64.") from exc
        if len(content) > MAX_FILE_BYTES:
            raise ValueError("Each uploaded test input must be at most 10 MiB.")
        if kind == "unit" and not content:
            raise ValueError("The unit test entry point must not be empty.")
        identity = uuid4().hex
        metadata = dict(id=identity, filename=filename, size=len(content),
                        sha256=hashlib.sha256(content).hexdigest(), kind=kind)
        directory = self.directory / identity
        # The public API has no path argument; user-supplied filenames are never
        # used for host paths, command names, or executable permissions.
        directory.mkdir(mode=0o700)
        try:
            _write_new(directory / "content.bin", content)
            _write_new(directory / "metadata.json", json.dumps(metadata, ensure_ascii=False).encode("utf-8"))
        except Exception:
            shutil.rmtree(directory)
            raise
        return metadata

    def _read(self, identity, kind=None):
        if not isinstance(identity, str) or not _ID.fullmatch(identity):
            raise ValueError("Select an uploaded test input.")
        if kind is not None:
            _kind(kind)
        directory = self.directory / identity
        try:
            if self.directory.is_symlink() or directory.is_symlink() or not directory.is_dir():
                raise ValueError("The uploaded test input is unavailable. Upload the file again.")
            metadata = json.loads(_read_regular(directory / "metadata.json", 8192))
            if (not isinstance(metadata, dict) or metadata.get("id") != identity
                    or type(metadata.get("size")) is not int or not 0 <= metadata["size"] <= MAX_FILE_BYTES
                    or not isinstance(metadata.get("sha256"), str) or not _HASH.fullmatch(metadata["sha256"])):
                raise ValueError("The uploaded test input metadata is invalid. Upload the file again.")
            _kind(metadata.get("kind"))
            _filename(metadata.get("filename"), metadata["kind"])
            if kind is not None and metadata["kind"] != kind:
                raise ValueError(f"Select an uploaded {kind} test input for this option.")
            content = _read_regular(directory / "content.bin", MAX_FILE_BYTES)
            if len(content) != metadata["size"] or hashlib.sha256(content).hexdigest() != metadata["sha256"]:
                raise ValueError("The uploaded test input failed its integrity check. Upload the file again.")
            if metadata["kind"] == "unit" and not content:
                raise ValueError("The unit test entry point must not be empty.")
            return {key: metadata[key] for key in ("id", "filename", "size", "sha256", "kind")}, content
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("The uploaded test input is unavailable or invalid. Upload the file again.") from exc

    def metadata(self, identity, kind=None):
        """Return metadata only after rechecking the saved file's kind and hash."""
        return self._read(identity, kind)[0]

    def copy_to_case(self, identity, case_dir, kind):
        """Stage bytes under a task-owned case directory; return a relative path.

        Consumers must use relative_path, not filename, when constructing a
        container mount/entry. A repeated identical staging call is idempotent.
        """
        metadata, content = self._read(identity, _kind(kind))
        case = Path(case_dir)
        if case.is_symlink() or not case.is_dir():
            raise ValueError("The task input directory is unavailable.")
        case = case.resolve()
        base = case / ".kea-test-inputs"
        _safe_directory(base)
        directory = base / identity
        _safe_directory(directory)
        suffix = Path(metadata["filename"]).suffix.lower()
        if not re.fullmatch(r"\.[a-z0-9]{1,16}", suffix):
            suffix = ".bin"
        path = directory / ("input" + suffix)
        try:
            if path.exists() or path.is_symlink():
                if path.is_symlink() or _read_regular(path, MAX_FILE_BYTES) != content:
                    raise ValueError("The task's staged test input does not match the uploaded file.")
            else:
                _write_new(path, content)
        except OSError as exc:
            raise ValueError("The uploaded test input could not be copied into this task.") from exc
        return {**metadata, "relative_path": path.relative_to(case).as_posix()}
