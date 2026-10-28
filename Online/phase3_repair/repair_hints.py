"""Generic observations from validation logs, without project-specific repair advice."""

import re


def extract_structured_test_feedback(error_log, docker_step=""):
    """Quote diagnostic lines; do not infer a repair from a test name or project."""
    patterns = r"error:|fatal error:|AssertionError|assert\b|Error:|Exception:|FAILED|Failed:|expected|actual|undefined|cannot import|SyntaxError|Traceback"
    lines = [
        line
        for line in (error_log or "").splitlines()
        if re.search(patterns, line, re.IGNORECASE)
    ]
    return "\n".join(dict.fromkeys(lines))
