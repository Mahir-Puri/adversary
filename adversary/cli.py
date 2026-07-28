"""Command-line entry point.

    adversary run --target module:factory [--suite path] [--fail-at HIGH]
                  [--judge] [--html out.html] [--json out.json]

The exit code is the CI contract: 0 when no attack at or above the gate
severity landed, 1 when the gate is tripped. That single integer is what makes
this dropp-able into any pipeline.
"""

from __future__ import annotations

import argparse
import sys

from .attacks import load_all_suites, load_suite
from .models import Severity
from .probes.llm_judge import LLMJudgeProbe, anthropic_judge
from .reporting import render_console, render_html, render_json
from .runners import RunConfig, run_attacks
from .targets import load_target_from_spec


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adversary",
        description="Red-team an LLM agent with a suite of adversarial attacks.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run attacks against a target.")
    run.add_argument(
        "--target",
        required=True,
        help="Target spec: an http(s) URL or 'module:factory'.",
    )
    run.add_argument(
        "--suite",
        action="append",
        help="Path to a suite YAML. Repeatable. Defaults to the built-in suites.",
    )
    run.add_argument(
        "--fail-at",
        default="HIGH",
        choices=[s.name for s in Severity],
        help="Fail CI if a landed attack is at or above this severity.",
    )
    run.add_argument(
        "--judge",
        action="store_true",
        help="Use the Anthropic LLM judge for jailbreak/direct-injection calls.",
    )
    run.add_argument("--judge-model", default="claude-sonnet-4-5")
    run.add_argument("--html", help="Write a standalone HTML report to this path.")
    run.add_argument("--json", help="Write a JSON report to this path.")
    run.add_argument(
        "--canary",
        default=None,
        help="Override the secret canary token the exfil probes look for.",
    )

    listcmd = sub.add_parser("list", help="List the attacks in the loaded suites.")
    listcmd.add_argument("--suite", action="append")
    return parser


def _load_attacks(suite_paths: list[str] | None):
    if suite_paths:
        attacks = []
        for path in suite_paths:
            attacks.extend(load_suite(path))
        return attacks
    return load_all_suites()


def _cmd_run(args: argparse.Namespace) -> int:
    attacks = _load_attacks(args.suite)
    target = load_target_from_spec(args.target)

    judge = None
    if args.judge:
        judge = LLMJudgeProbe(anthropic_judge(args.judge_model))

    config = RunConfig(fail_at=Severity[args.fail_at], judge=judge)
    if args.canary:
        config.canary = args.canary

    summary = run_attacks(target, attacks, config)

    print(render_console(summary, fail_at=config.fail_at))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(render_json(summary))
        print(f"  JSON report written to {args.json}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(summary))
        print(f"  HTML report written to {args.html}")

    return 1 if summary.should_fail(config.fail_at) else 0


def _cmd_list(args: argparse.Namespace) -> int:
    attacks = _load_attacks(args.suite)
    for a in attacks:
        print(f"  {a.id:<10} {a.severity.name:<8} {a.category.value:<20} {a.description[:60]}")
    print(f"\n  {len(attacks)} attacks total.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "list":
        return _cmd_list(args)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
