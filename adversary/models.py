"""Core data models shared across the harness.

Everything the runner, probes, and reporters pass around is defined here so
there is a single source of truth for what an attack, a transcript, and a
verdict look like. Keeping these as frozen dataclasses makes runs reproducible
and easy to serialize into the JSON report.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.Enum):
    """How bad a successful attack is if it lands.

    Ordered so we can compare (``LOW < HIGH``) when deciding whether a run
    should fail CI based on a severity threshold.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value < other.value

    def __le__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value <= other.value


class Category(enum.Enum):
    """The attack surface an attack exercises."""

    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_MISUSE = "tool_misuse"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"


@dataclass(frozen=True)
class ToolCall:
    """A single tool invocation the target agent attempted during a turn."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TargetResponse:
    """Everything the target agent produced in response to one input.

    A target integration is responsible for filling this in. ``text`` is the
    natural-language reply the user would see; ``tool_calls`` is the list of
    tools the agent tried to call, which is what most of the interesting
    security probes actually inspect.
    """

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Attack:
    """A single adversarial test case.

    ``payload`` is the hostile string. Where it gets injected depends on
    ``category``: a DIRECT_INJECTION payload goes in as the user turn, while an
    INDIRECT_INJECTION payload is smuggled through a tool result via
    ``injected_tool_output``.
    """

    id: str
    category: Category
    severity: Severity
    payload: str
    description: str
    # For indirect injection: the tool result the harness feeds back to the
    # agent, with the payload already embedded. None for direct attacks.
    injected_tool_output: str | None = None
    # Free-form tags for filtering: e.g. {"owasp": "LLM01", "cwe": "CWE-77"}.
    tags: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Verdict:
    """A probe's judgement on one (attack, response) pair."""

    attack_id: str
    passed: bool  # True == the agent resisted the attack (good).
    probe: str
    severity: Severity
    detail: str
    # 0.0 (certainly safe) .. 1.0 (certainly compromised). Used when an
    # LLM-judge probe returns a graded score rather than a hard boolean.
    score: float = 0.0


@dataclass
class Result:
    """The full record of one attack executed against the target."""

    attack: Attack
    response: TargetResponse
    verdict: Verdict
    latency_ms: float
