"""Measure how much the LLM judge agrees with human labels.

This is the module that separates a serious eval tool from a toy. Any project
can call an LLM "judge"; the question a reviewer will ask is *how do you know
the judge is right?* This runs the judge over a set of examples a human has
already labelled and reports agreement, precision, and recall, so the judge's
verdicts carry a known error rate.

Run it with::

    python -m adversary.probes.calibration labels.jsonl

where each line is ``{"payload": ..., "response": ..., "human_complied": bool}``.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass

from ..models import Attack, Category, Severity, TargetResponse
from .llm_judge import LLMJudgeProbe, anthropic_judge


@dataclass
class CalibrationReport:
    """Agreement metrics between the judge and the human labels."""

    total: int
    agreements: int
    true_positive: int  # judge said complied, human agreed
    false_positive: int  # judge said complied, human said resisted
    true_negative: int
    false_negative: int

    @property
    def accuracy(self) -> float:
        return self.agreements / self.total if self.total else 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return self.true_positive / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.true_positive / denom if denom else 0.0

    def render(self) -> str:
        return (
            f"Judge calibration over {self.total} labelled examples\n"
            f"  accuracy : {self.accuracy:6.1%}\n"
            f"  precision: {self.precision:6.1%}  "
            f"(when the judge flags compliance, how often it's right)\n"
            f"  recall   : {self.recall:6.1%}  "
            f"(of real compliances, how many the judge caught)\n"
            f"  confusion: TP={self.true_positive} FP={self.false_positive} "
            f"TN={self.true_negative} FN={self.false_negative}"
        )


def calibrate(labels_path: str, probe: LLMJudgeProbe) -> CalibrationReport:
    """Run ``probe`` over human-labelled examples and score its agreement."""

    tp = fp = tn = fn = 0
    with open(labels_path, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]

    for row in rows:
        attack = Attack(
            id=row.get("id", "calib"),
            category=Category.JAILBREAK,
            severity=Severity.HIGH,
            payload=row["payload"],
            description="calibration example",
        )
        response = TargetResponse(text=row["response"])
        verdict = probe.evaluate(attack, response)
        judge_complied = not verdict.passed
        human_complied = bool(row["human_complied"])

        if judge_complied and human_complied:
            tp += 1
        elif judge_complied and not human_complied:
            fp += 1
        elif not judge_complied and not human_complied:
            tn += 1
        else:
            fn += 1

    return CalibrationReport(
        total=len(rows),
        agreements=tp + tn,
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
    )


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m adversary.probes.calibration <labels.jsonl>")
        return 2
    probe = LLMJudgeProbe(anthropic_judge())
    report = calibrate(argv[0], probe)
    print(report.render())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
