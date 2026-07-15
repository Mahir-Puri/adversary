"""Target adapters — the seam between the harness and *your* agent.

Adversary does not care how your agent is built. It only needs an object with a
``send`` method that takes an :class:`Attack` and returns a
:class:`TargetResponse`. Implement that once and every attack suite works
against your system.

Two adapters ship in the box:

* :class:`CallableTarget` wraps a plain Python function, which is what the
  example vulnerable agent and most unit tests use.
* :class:`HTTPTarget` posts to an HTTP endpoint, which is how you would point
  the harness at a real running service in CI.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Protocol, runtime_checkable

import httpx

from .models import Attack, TargetResponse, ToolCall


@runtime_checkable
class Target(Protocol):
    """Anything the harness can attack.

    A target receives the *fully assembled* prompt for an attack (the harness
    handles deciding whether the payload is a user turn or a poisoned tool
    result) and returns what the agent did.
    """

    def send(self, attack: Attack) -> TargetResponse:  # pragma: no cover
        ...


class CallableTarget:
    """Adapt a Python callable into a :class:`Target`.

    The callable receives ``(user_input, injected_tool_output)`` and returns
    either a plain string or a ``(text, tool_calls)`` tuple. This keeps the
    example agent and the test suite dependency-free.
    """

    def __init__(
        self,
        fn: Callable[[str, str | None], Any],
        name: str = "callable",
    ) -> None:
        self._fn = fn
        self.name = name

    def send(self, attack: Attack) -> TargetResponse:
        out = self._fn(attack.payload, attack.injected_tool_output)
        if isinstance(out, tuple):
            text, calls = out
            tool_calls = [
                c if isinstance(c, ToolCall) else ToolCall(**c) for c in calls
            ]
            return TargetResponse(text=text, tool_calls=tool_calls)
        return TargetResponse(text=str(out))


class HTTPTarget:
    """Adapt an HTTP JSON endpoint into a :class:`Target`.

    Expects the endpoint to accept a JSON body of the form::

        {"input": "...", "tool_output": "..."}

    and to reply with::

        {"text": "...", "tool_calls": [{"name": "...", "arguments": {...}}]}

    That contract is deliberately tiny so wiring up an existing agent is a few
    lines rather than a rewrite.
    """

    def __init__(self, url: str, *, timeout: float = 30.0, name: str | None = None) -> None:
        self.url = url
        self.name = name or url
        self._client = httpx.Client(timeout=timeout)

    def send(self, attack: Attack) -> TargetResponse:
        body = {"input": attack.payload, "tool_output": attack.injected_tool_output}
        resp = self._client.post(self.url, json=body)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        tool_calls = [ToolCall(**c) for c in data.get("tool_calls", [])]
        return TargetResponse(
            text=data.get("text", ""),
            tool_calls=tool_calls,
            raw=data,
        )

    def close(self) -> None:
        self._client.close()


def load_target_from_spec(spec: str) -> Target:
    """Build a target from a CLI string.

    ``http://localhost:8000/chat`` -> :class:`HTTPTarget`.
    ``mymodule:build_target``      -> import the module, call the factory.
    """

    if spec.startswith("http://") or spec.startswith("https://"):
        return HTTPTarget(spec)

    if ":" in spec:
        module_name, _, attr = spec.partition(":")
        import importlib

        module = importlib.import_module(module_name)
        factory = getattr(module, attr)
        target = factory()
        if not isinstance(target, Target):
            raise TypeError(f"{spec} did not return a Target (got {type(target)!r})")
        return target

    raise ValueError(
        f"Cannot interpret target spec {spec!r}. "
        "Use an http(s) URL or 'module:factory'."
    )


def _pretty(obj: Any) -> str:
    """Small helper used by verbose logging to render tool calls readably."""
    return json.dumps(obj, indent=2, default=str)
