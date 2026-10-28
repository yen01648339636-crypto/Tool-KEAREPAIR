"""Task-selected checks without weakening the full-validation evidence contract."""

from copy import deepcopy

from utils.metrics import STAGES, fully_validated


MODES = ("patch_only", "poc", "full")


def validation_mode(value=None):
    """Read the explicit Studio profile; existing benchmark cases remain full."""
    if isinstance(value, dict):
        value = value.get("studio_validation_mode", value.get("validation_mode", "full"))
    elif value is None:
        value = "full"
    if not isinstance(value, str) or value not in MODES:
        raise ValueError("Validation mode must be patch_only, poc, or full")
    return value


def requested_stages(value=None):
    mode = validation_mode(value)
    return () if mode == "patch_only" else STAGES[:3] if mode == "poc" else STAGES


def scope_commands(commands, mode=None):
    """Copy bundled commands and remove checks outside the selected profile.

    This selects existing adapters only. It never accepts executable input or
    changes a command's declared coverage to claim fewer checks than it runs.
    """
    if not isinstance(commands, dict):
        raise ValueError("Validation commands must be an object")
    selected = validation_mode(commands if mode is None else mode)
    value = deepcopy(commands)
    if mode is not None or "studio_validation_mode" in commands:
        value["studio_validation_mode"] = selected
    if selected == "full":
        return value
    for key in ("unit_test_cmd", "unit_test_command", "test_command"):
        value.pop(key, None)
    if selected == "patch_only":
        for key in ("poc_test_cmd", "poc_test_command", "compile_cmd", "compile_command"):
            value.pop(key, None)
        value["validation_steps"] = []
        return value
    if "validation_steps" in value:
        if not isinstance(value["validation_steps"], list):
            raise ValueError("validation_steps must be an ordered list")
        selected_steps = []
        for step in value["validation_steps"]:
            if not isinstance(step, dict) or not isinstance(step.get("covers"), list):
                raise ValueError("Invalid declared validation step")
            covers = set(step["covers"])
            if "unit" in covers:
                if covers != {"unit"}:
                    raise ValueError("PoC-only validation cannot split a command that also runs unit tests")
                continue
            if not covers or not covers <= {"compile", "poc"}:
                raise ValueError("PoC-only validation requires explicit build and PoC coverage")
            selected_steps.append(step)
        if {name for step in selected_steps for name in step["covers"]} != {"compile", "poc"}:
            raise ValueError("PoC-only validation requires bundled build and PoC checks")
        value["validation_steps"] = selected_steps
    return value


def decorate_validation(result, mode=None):
    """Add scoped outcome metadata while preserving all original stage evidence."""
    value = deepcopy(result)
    stages = requested_stages(mode)
    states = value.get("stage_status") or {}
    value.update(
        validation_mode=validation_mode(mode),
        requested_stages=list(stages),
        selected_checks_passed=bool(stages) and all(states.get(name) == "passed" for name in stages),
        success=fully_validated(value),
    )
    return value
