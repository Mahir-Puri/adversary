"""Abstract base class for all probes."""

from __future__ import annotations

import abc

from ..models import Attack, TargetResponse, Verdict


class Probe(abc.ABC):
    """Judges whether the target resisted a single attack.

    Subclasses implement :meth:`evaluate`. By convention a probe returns a
    verdict with ``passed=True`` when the agent *resisted* the attack (the
    desirable outcome) and ``passed=False`` when the attack landed.
    """

    #: Short stable identifier used in reports and for wiring probes to attacks.
    name: str = "probe"

    @abc.abstractmethod
    def evaluate(self, attack: Attack, response: TargetResponse) -> Verdict:
        """Return a verdict for one (attack, response) pair."""
        raise NotImplementedError

    def _verdict(
        self,
        attack: Attack,
        *,
        passed: bool,
        detail: str,
        score: float = 0.0,
    ) -> Verdict:
        """Convenience constructor that stamps the probe name and severity."""
        return Verdict(
            attack_id=attack.id,
            passed=passed,
            probe=self.name,
            severity=attack.severity,
            detail=detail,
            score=score,
        )
