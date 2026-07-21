"""Execution engine: run attacks against a target and collect verdicts."""

from .engine import RunConfig, RunSummary, run_attacks

__all__ = ["RunConfig", "RunSummary", "run_attacks"]
