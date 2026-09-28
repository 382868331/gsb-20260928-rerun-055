from __future__ import annotations

from dataclasses import dataclass

from .models import HitEvidence


@dataclass(frozen=True, slots=True)
class HeuristicModel:
    """Deterministic placeholder showing how model scoring joins a decision."""

    version: str = "heuristic-score-v0"
    amount_weight: float = 0.0001
    identity_weight: float = 0.08

    def score(self, evidence: HitEvidence) -> float:
        score = (
            evidence.total_amount * self.amount_weight
            + len(evidence.identities) * self.identity_weight
        )
        return min(1.0, round(score, 6))

    def apply(self, evidence: HitEvidence) -> HitEvidence:
        return evidence.with_model_score(self.score(evidence), self.version)
