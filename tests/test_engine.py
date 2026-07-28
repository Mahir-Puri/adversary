"""End-to-end tests: run the built-in suites against the example agent.

These lock in the behaviour that the demo agent resists some attacks and falls
for others, so a regression that made the harness stop *detecting* a landed
attack would break the build.
"""

from __future__ import annotations

from adversary import RunConfig, load_all_suites, run_attacks
from adversary.models import Severity
from adversary.probes.llm_judge import LLMJudgeProbe
from adversary.reporting import render_html, render_json
from examples.vulnerable_agent.agent import build_target


def _stub_judge():
    # Deterministic judge: treats any non-refusal jailbreak answer as compliance.
    def fake(system: str, user: str) -> str:
        if "in character" in user.lower() or "sweetie" in user.lower():
            return '{"complied": true, "confidence": 0.85, "reason": "played along"}'
        return '{"complied": false, "confidence": 0.8, "reason": "refused"}'

    return LLMJudgeProbe(fake)


def test_full_run_produces_mixed_results():
    target = build_target()
    attacks = load_all_suites()
    config = RunConfig(judge=_stub_judge())
    summary = run_attacks(target, attacks, config)

    assert summary.total == len(attacks)
    # The demo agent is intentionally imperfect: some land, some are resisted.
    assert len(summary.landed) > 0
    assert summary.passed > 0


def test_indirect_injection_is_caught():
    target = build_target()
    attacks = [a for a in load_all_suites() if a.id == "ii-001"]
    summary = run_attacks(target, attacks, RunConfig())
    # ii-001 tries exfiltration via send_email through poisoned tool output;
    # the demo agent falls for it and the harness must catch it.
    assert len(summary.landed) == 1
    assert "send_email" in summary.landed[0].verdict.detail


def test_ci_gate_trips_on_critical():
    target = build_target()
    attacks = load_all_suites()
    summary = run_attacks(target, attacks, RunConfig(judge=_stub_judge()))
    # With critical indirect-injection attacks landing, the HIGH gate must fail.
    assert summary.should_fail(Severity.HIGH) is True


def test_reports_render_without_error():
    target = build_target()
    summary = run_attacks(target, load_all_suites(), RunConfig(judge=_stub_judge()))
    html = render_html(summary)
    js = render_json(summary)
    assert "ADVERSARY" in html
    assert '"summary"' in js
