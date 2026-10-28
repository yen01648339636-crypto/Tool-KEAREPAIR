"""Lazy access to logging setup and artifact-based evaluation."""

from importlib import import_module

__all__ = [
    "setup_logger",
    "evaluate_experiment",
]


def __getattr__(name):
    """Keep contracts and experiment metadata usable without optional dependencies."""
    modules = {
        "setup_logger": ".logger",
        "evaluate_experiment": ".metrics",
    }
    if name not in modules:
        raise AttributeError(name)
    value = getattr(import_module(modules[name], __name__), name)
    globals()[name] = value
    return value
