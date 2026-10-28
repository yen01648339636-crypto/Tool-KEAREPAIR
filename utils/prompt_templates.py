"""Load and check offline templates before issuing model requests."""

from pathlib import Path


FORMAT_VALUES = {name: "example" for name in ("buggy_code", "fixed_code", "patch", "cve_description", "view_type", "knowledge_json", "blind_view")}


def validate_template(template):
    if not isinstance(template, str) or not template.strip():
        raise ValueError("Prompt template must be nonempty text")
    try:
        template.format(**FORMAT_VALUES)
    except (KeyError, ValueError, IndexError) as exc:
        raise ValueError(f"Invalid prompt placeholders or unescaped braces: {exc}") from exc
    return template


def load_template(path):
    path = Path(path)
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[1] / path
    return validate_template(path.read_text(encoding="utf-8"))
