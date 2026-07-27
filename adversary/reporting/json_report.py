"""Machine-readable JSON report.

This is the artifact CI uploads and other tools consume. It is deliberately
flat and stable: a top-level summary block plus a list of per-attack records.
"""

from __future__ import annotations

import json

from ..runners.engine import RunSummary


def summary_to_dict(summary: RunSummary) -> dict:
    """Convert a run summary into a JSON-serializable dict."""

    return {
        "summary": {
            "total": summary.total,
            "resisted": summary.passed,
            "landed": len(summary.landed),
            "landed_by_severity": summary.landed_by_severity(),
            "landed_by_category": summary.landed_by_category(),
        },
        "results": [
            {
                "attack_id": r.attack.id,
                "category": r.attack.category.value,
                "severity": r.verdict.severity.name,
                "resisted": r.verdict.passed,
                "probe": r.verdict.probe,
                "score": round(r.verdict.score, 3),
                "detail": r.verdict.detail,
                "latency_ms": round(r.latency_ms, 1),
                "description": r.attack.description,
                "tags": r.attack.tags,
            }
            for r in summary.results
        ],
    }


def render_json(summary: RunSummary, *, indent: int = 2) -> str:
    return json.dumps(summary_to_dict(summary), indent=indent)
