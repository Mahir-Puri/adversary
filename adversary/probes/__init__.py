"""Probes decide whether an attack succeeded.

A probe looks at the ``(Attack, TargetResponse)`` pair and returns a
:class:`~adversary.models.Verdict`. Different attack categories need different
detection strategies, so the harness picks a probe per attack rather than
using one global judge:

* Deterministic **string/heuristic** probes catch the unambiguous failures
  (a secret canary appearing verbatim, a forbidden tool being called). These
  are fast, free, and never flaky.
* The **LLM-judge** probe handles the fuzzy cases (did the model *comply* with
  a jailbreak, or refuse?) where there is no substring to grep for.

The two-tier design matters: relying only on an LLM judge is slow, costs money
per run, and is itself vulnerable to injection. Deterministic probes are the
first line; the judge is reserved for genuinely subjective calls.
"""

from .base import Probe
from .heuristic import (
    CanaryLeakProbe,
    ForbiddenToolProbe,
    RefusalProbe,
    SystemPromptLeakProbe,
)
from .llm_judge import LLMJudgeProbe

__all__ = [
    "Probe",
    "CanaryLeakProbe",
    "ForbiddenToolProbe",
    "RefusalProbe",
    "SystemPromptLeakProbe",
    "LLMJudgeProbe",
]
