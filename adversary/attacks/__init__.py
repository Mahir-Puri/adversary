"""Attack suites — the adversarial test cases.

Each suite is a YAML file under ``suites/`` describing a family of attacks. They
are data, not code, so contributors can add attacks without touching the engine
and teams can keep private suites in their own repos.

The categories mirror the OWASP Top 10 for LLM Applications so the coverage maps
onto a framework reviewers recognize:

* ``direct_injection``   — hostile instructions in the user turn (LLM01)
* ``indirect_injection`` — hostile instructions smuggled via tool output (LLM01)
* ``data_exfiltration``  — attempts to extract secrets/canaries (LLM06)
* ``tool_misuse``        — coercing dangerous tool calls (LLM07 / excessive agency)
* ``jailbreak``          — bypassing safety policy (LLM01)
* ``system_prompt_leak`` — extracting the hidden system prompt (LLM07)
"""

from .loader import load_suite, load_all_suites

__all__ = ["load_suite", "load_all_suites"]
