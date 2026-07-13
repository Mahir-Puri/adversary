"""Adversary — a red-teaming CI harness for LLM agents.

Public API surface for programmatic use::

    from adversary import run_attacks, RunConfig, load_all_suites
    from adversary.targets import CallableTarget

    target = CallableTarget(my_agent_fn)
    summary = run_attacks(target, load_all_suites())
    print(summary.passed, "/", summary.total)
"""

from .attacks import load_all_suites, load_suite
from .models import Attack, Category, Result, Severity, TargetResponse, Verdict
from .runners import RunConfig, RunSummary, run_attacks

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "Attack",
    "Category",
    "Result",
    "Severity",
    "TargetResponse",
    "Verdict",
    "RunConfig",
    "RunSummary",
    "run_attacks",
    "load_suite",
    "load_all_suites",
]
