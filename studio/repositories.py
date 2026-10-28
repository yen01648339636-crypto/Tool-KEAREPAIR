"""Resolve repository form inputs to prepared cases, without cloning or executing input.

The public URL identifies a known project; its target ID pins one prepared CVE
snapshot. File paths and bundled test references must agree with that target.
"""

from collections import defaultdict
from copy import deepcopy
import hashlib
from pathlib import Path, PurePosixPath
import re
from urllib.parse import urlsplit

from studio.catalog import read_json


def normalize_repository_url(value):
    """Accept common Git clone spellings, but never credentials or URL subpaths."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter a repository URL.")
    value = value.strip()
    if len(value) > 2048 or re.search(r"[\s\x00-\x1f\x7f]", value):
        raise ValueError("Enter a valid repository URL.")
    scp = re.fullmatch(r"git@([A-Za-z0-9.-]+):(.+)", value)
    if scp:
        value = "ssh://git@" + scp[1] + "/" + scp[2]
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid repository URL.") from exc
    if (parsed.scheme not in {"https", "http", "ssh", "git"}
            or not parsed.hostname or parsed.query or parsed.fragment
            or parsed.password is not None
            or (parsed.username is not None and not (parsed.scheme == "ssh" and parsed.username == "git"))
            or port not in {None, 80, 443, 22, 9418}):
        raise ValueError("Use a repository URL without credentials, query parameters, or fragments.")
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not path or any(part in {"", ".", ".."} for part in path.split("/")) or re.search(r"[%\\<>]", path):
        raise ValueError("Enter a valid repository URL.")
    host = parsed.hostname.lower()
    # GitHub repository paths are case-insensitive. Other hosts may not be.
    if host == "github.com":
        path = path.lower()
    return "https://" + host + "/" + path


def _file_path(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter the vulnerable file path relative to the repository.")
    value = value.strip()
    while value.startswith("./"):
        value = value[2:]
    if (not value or value.startswith("/") or "\\" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or re.search(r"[\x00-\x1f\x7f]", value)):
        raise ValueError("Use the repository-relative vulnerable file path for this target.")
    return PurePosixPath(value).as_posix()


class RepositoryCatalog:
    """Repository-first view of the existing trusted Catalog."""

    def __init__(self, catalog):
        self.catalog = catalog
        self._targets = None
        self._repositories = None
        self._defaults = {}

    def _load(self):
        if self._targets is not None:
            return
        settings = read_json(Path(__file__).with_name("repository_profiles.json"), {})
        profiles = settings.get("profiles", {})
        self._defaults = {normalize_repository_url(url): case_key
                          for url, case_key in settings.get("repository_defaults", {}).items()}
        raw = read_json(self.catalog.root / "data/raw/patcheval_dataset.json", [])
        raw_by_cve = defaultdict(list)
        if isinstance(raw, list):
            for row in raw:
                if isinstance(row, dict):
                    raw_by_cve[row.get("cve_id")].append(row)
        targets = {}
        repositories = defaultdict(list)
        for case in self.catalog.cases().values():
            directory = case["_directory"]
            commands = read_json(directory / "test_cmds.json", {})
            meta = read_json(directory / "case_meta.json", {})
            profile = dict(profiles.get(case["key"], {}))
            # Explicit local metadata also supports independently prepared cases.
            for key in ("repository_url", "revision", "revision_kind", "project", "poc_file", "poc_label", "unit_test", "unit_label", "demo_source_task_id"):
                if meta.get(key):
                    profile[key] = meta[key]
            try:
                file = _file_path(case["file"])
            except ValueError:
                continue
            matching_rows = []
            for row in raw_by_cve[case["case_id"]]:
                functions = [f for f in row.get("vul_func", [])
                             if isinstance(f, dict) and str(f.get("file_path", "")).removeprefix("./") == file]
                if functions:
                    matching_rows.append((row, functions))
            if not profile.get("repository_url") and matching_rows:
                choices = {row.get("repo") for row, _ in matching_rows if row.get("repo")}
                if len(choices) != 1:
                    continue
                profile["repository_url"] = choices.pop()
            if not profile.get("revision") and matching_rows:
                commits = {f.get("commit") for _, functions in matching_rows for f in functions if f.get("commit")}
                if len(commits) == 1:
                    profile["revision"] = commits.pop()
                    profile["revision_kind"] = "git"
            receipt = read_json(directory / "source_baseline.json", {})
            if receipt.get("status") == "verified":
                commits = {s.get("commit") for s in receipt.get("steps", []) if isinstance(s, dict) and s.get("commit")}
                if len(commits) == 1:
                    profile["revision"] = commits.pop()
            if not profile.get("repository_url"):
                continue
            try:
                repository_url = normalize_repository_url(profile["repository_url"])
            except ValueError:
                continue
            revision = str(profile.get("revision", "")).strip()
            if not revision:
                # A content snapshot is preferable to inventing a branch/commit.
                revision = "snapshot:" + hashlib.sha256(case["_source"].read_bytes()).hexdigest()[:16]
                profile["revision_kind"] = "snapshot"
            case_key = case["key"]
            target_id = "target-" + hashlib.sha256(case_key.encode()).hexdigest()[:20]
            poc_available = bool(commands.get("poc_test_cmd"))
            unit_available = bool(commands.get("unit_test_cmd"))
            modes = ["patch_only"]
            if poc_available:
                modes.append("poc")
                if unit_available:
                    modes.append("full")
            project = profile.get("project") or repository_url.rsplit("/", 1)[-1]
            target = {
                "id": target_id,
                "case_key": case_key,
                "repository_url": repository_url,
                "project": project,
                "file": file,
                "revision": revision,
                "revision_kind": profile.get("revision_kind", "git"),
                "language": case["language"],
                "target_label": f"{file} · {revision[:12]}",
                "case_id": case["case_id"],
                "poc_file": (profile.get("poc_file") or "test_cmds.json#poc_test_cmd") if poc_available else "",
                "poc_label": profile.get("poc_label") or "Bundled PoC test entry",
                "unit_test": (profile.get("unit_test") or "test_cmds.json#unit_test_cmd") if unit_available else "",
                "unit_label": profile.get("unit_label") or "Bundled unit test entry",
                "validation_modes": modes,
                **({"demo_source_task_id": profile["demo_source_task_id"]} if profile.get("demo_source_task_id") else {}),
            }
            targets[target_id] = target
            repositories[repository_url].append(target)
        self._targets = targets
        self._repositories = dict(repositories)

    def repositories(self):
        self._load()
        return [{"repository_url": url, "project": items[0]["project"], "target_count": len(items)}
                for url in sorted(self._repositories)
                if (items := self._available_targets(url))]

    def _available_targets(self, repository_url):
        items = self._repositories.get(repository_url, [])
        default = self._defaults.get(repository_url)
        return [item for item in items if item["case_key"] == default] if default else items

    def repository_for_case(self, case_key):
        """Return a known case's repository URL, or None when metadata is absent."""
        self._load()
        return next((target["repository_url"] for target in self._targets.values()
                     if target["case_key"] == case_key), None)

    def resolve(self, repository_url):
        self._load()
        url = normalize_repository_url(repository_url)
        items = self._available_targets(url)
        if not items:
            raise ValueError("This repository has no prepared repair targets. Select a supported repository.")
        return {"repository_url": url, "project": items[0]["project"], "targets": deepcopy(items)}

    def target(self, target_id):
        self._load()
        if not isinstance(target_id, str) or target_id not in self._targets:
            raise ValueError("Select a prepared repair target for this repository.")
        return deepcopy(self._targets[target_id])

    def match(self, repository_url, target_id, vulnerable_file, revision, poc_file, unit_test, validation_mode):
        target = self.target(target_id)
        url = normalize_repository_url(repository_url)
        if url != target["repository_url"]:
            raise ValueError("The selected target does not belong to this repository.")
        if url in self._defaults and target["case_key"] != self._defaults[url]:
            raise ValueError("The selected target does not match this repository's configured source baseline. Reconnect the repository.")
        file = _file_path(vulnerable_file)
        if file != target["file"]:
            raise ValueError("The vulnerable file must match the selected repair target.")
        if not isinstance(revision, str) or revision.strip() != target["revision"]:
            raise ValueError("The revision must match the selected prepared source snapshot.")
        if validation_mode not in target["validation_modes"]:
            raise ValueError("Select an available validation plan for this target.")
        required = {"poc_file": validation_mode in {"poc", "full"}, "unit_test": validation_mode == "full"}
        references = {"poc_file": poc_file, "unit_test": unit_test}
        for field, value in references.items():
            if value is None and not required[field]:
                value = ""
            if not isinstance(value, str):
                raise ValueError("Select the bundled test entry for this target.")
            expected = target[field]
            if (required[field] and value.strip() != expected) or (value.strip() and value.strip() != expected):
                name = "PoC" if field == "poc_file" else "unit test"
                raise ValueError(f"Select the bundled {name} entry for this target.")
        return {
            "case_key": target["case_key"],
            "request": {
                "repository_url": url,
                "target_id": target["id"],
                "vulnerable_file": file,
                "revision": target["revision"],
                "validation_mode": validation_mode,
                "poc_file": target["poc_file"] if required["poc_file"] else "",
                "unit_test": target["unit_test"] if required["unit_test"] else "",
                **({"display_name": target["project"]} if url in self._defaults else {}),
            },
        }
