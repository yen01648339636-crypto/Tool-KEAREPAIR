"""An explicitly synthetic, hand-authored walkthrough; never an experiment result."""

import difflib
import hashlib

SOURCE = '''from pathlib import Path
from flask import abort, send_file

UPLOAD_ROOT = Path("/srv/uploads").resolve()


def download_file(filename):
    """Serve a file from the upload directory."""
    requested_path = UPLOAD_ROOT / filename
    return send_file(requested_path)
'''

FIRST = SOURCE.replace(
    '    requested_path =',
    '    if ".." in filename:\n        abort(403)\n    requested_path =',
)
FIXED = SOURCE.replace(
    '    requested_path = UPLOAD_ROOT / filename',
    '    requested_path = (UPLOAD_ROOT / filename).resolve()\n'
    '    if not requested_path.is_relative_to(UPLOAD_ROOT):\n'
    '        abort(403)',
)


class Position:
    def __init__(self, line, column=None):
        self.line, self.column = line, column

    def model_dump(self):
        return {"line": self.line, "column": self.column}


def diff(source, fixed):
    return "".join(difflib.unified_diff(
        source.splitlines(True), fixed.splitlines(True),
        fromfile="a/app/downloads.py", tofile="b/app/downloads.py",
    ))


def walkthrough():
    from static_analysis.session import AnalysisSession

    session = AnalysisSession(SOURCE, language="python", file_path="app/downloads.py")
    observations = [
        session.trace_data_flow("requested_path", Position(10)),
        session.is_path_reachable(Position(9), Position(10)),
        session.inspect_api_usage(Position(10)),
    ]
    return {
        "id": "walkthrough", "mode": "walkthrough", "status": "example",
        "title": "Path traversal in file downloads", "case_id": "DEMO-001",
        "language": "Python", "file": "app/downloads.py",
        "description": "A user-provided filename is appended to the upload directory and passed to a file-serving function. Explore the relationship between input, path construction and file access.",
        "source": SOURCE, "source_hash": hashlib.sha256(SOURCE.encode()).hexdigest(),
        "facts": [f for o in observations for f in o["facts"]],
        "observations": observations,
        "hypotheses": [
            {"statement": "If a remote user controls filename, parent-directory segments or absolute paths may escape the upload directory. Input constraints and runtime tests are needed to confirm this.",
             "evidence_ids": [observations[0]["facts"][0]["evidence_id"]]},
        ],
        "limitations": [
            "This is a manually written synthetic case. Structural facts come from the framework analyzer; patches are educational examples.",
            "Intraprocedural structural paths do not prove runtime reachability. Build, PoC and unit tests have not run.",
            "The path-confinement example does not address symlink races. Actual filesystem behavior still needs validation before deployment.",
        ],
        "candidates": [
            {"candidate_id": 1, "patch": diff(SOURCE, FIRST), "fixed_code": FIRST,
             "explanation": "Example A: filter parent-directory segments. Absolute paths may still bypass this restriction. This is a review observation, not a test result.",
             "validation_result": {"stage_status": {s: "not_run" for s in ("patch_apply", "compile", "poc", "unit")}}},
            {"candidate_id": 2, "patch": diff(SOURCE, FIXED), "fixed_code": FIXED,
             "explanation": "Example B: resolve the target path, then check that it is within the upload directory. Runtime behavior and race conditions still need validation.",
             "validation_result": {"stage_status": {s: "not_run" for s in ("patch_apply", "compile", "poc", "unit")}}},
        ],
        "exemplars": [],
        "events": [
            {"seq": 1, "stage": "source", "message": "Loaded a manually written Python path-traversal case"},
            {"seq": 2, "stage": "diagnosis", "message": "Ran the static analyzer to extract data-flow, control-flow and call facts"},
            {"seq": 3, "stage": "review", "message": "Provided two manually written candidate patches for review"},
            {"seq": 4, "stage": "validation", "message": "Validation has not run; all checks remain unexecuted"},
        ],
    }
