"""Human-readable terminal output.

Kept dependency-free (raw ANSI) so the harness prints nicely in CI logs without
pulling in a rendering library. A single ``NO_COLOR`` env var disables colour
for log scrapers, following the community convention.
"""

from __future__ import annotations

import os

from ..models import Severity
from ..runners.engine import RunSummary

_USE_COLOR = os.environ.get("NO_COLOR") is None


def _c(text: str, code: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


_SEV_COLOR = {
    Severity.CRITICAL: "1;31",  # bold red
    Severity.HIGH: "31",  # red
    Severity.MEDIUM: "33",  # yellow
    Severity.LOW: "36",  # cyan
    Severity.INFO: "37",  # grey
}


def render_console(summary: RunSummary, *, fail_at: Severity) -> str:
    """Return the full terminal report as a string."""

    lines: list[str] = []
    lines.append(_c("\n  ADVERSARY — LLM agent red-team report", "1;35"))
    lines.append("  " + "─" * 46)

    for result in summary.results:
        v = result.verdict
        if v.passed:
            badge = _c("PASS", "32")
        else:
            badge = _c("LAND", _SEV_COLOR.get(v.severity, "31"))
        sev = _c(f"{v.severity.name:<8}", _SEV_COLOR.get(v.severity, "37"))
        lines.append(
            f"  [{badge}] {sev} {result.attack.id:<10} "
            f"{result.attack.category.value:<20} "
            f"({result.latency_ms:6.0f} ms)"
        )
        if not v.passed:
            lines.append(f"         └─ {v.detail}")

    lines.append("  " + "─" * 46)
    landed = len(summary.landed)
    summary_line = (
        f"  {summary.passed}/{summary.total} resisted, "
        f"{landed} landed"
    )
    lines.append(_c(summary_line, "1;32" if landed == 0 else "1;31"))

    if summary.landed:
        by_sev = summary.landed_by_severity()
        parts = [f"{name}={count}" for name, count in by_sev.items()]
        lines.append("  landed by severity: " + ", ".join(parts))
        by_cat = summary.landed_by_category()
        parts = [f"{name}={count}" for name, count in by_cat.items()]
        lines.append("  landed by category: " + ", ".join(parts))

    gate = "FAIL" if summary.should_fail(fail_at) else "OK"
    gate_col = "1;31" if gate == "FAIL" else "1;32"
    lines.append(
        _c(f"  CI gate (fail at >= {fail_at.name}): {gate}", gate_col)
    )
    lines.append("")
    return "\n".join(lines)
