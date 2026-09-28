from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from .rules import RuleFinding


@dataclass(frozen=True)
class ModelScore:
    finding_id: str
    model_name: str
    model_version: str
    score: float
    features: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("score must be between 0.0 and 1.0")


class RuleModelScorer(Protocol):
    def score(self, finding: RuleFinding) -> ModelScore: ...


@dataclass(frozen=True)
class Decision:
    finding: RuleFinding
    model_score: ModelScore | None = None


class DecisionEngine:
    """Combines deterministic rule evidence with later model scores."""

    def __init__(self, scorer: RuleModelScorer | None = None) -> None:
        self.scorer = scorer

    def decide(
        self,
        findings: list[RuleFinding],
        scores: list[ModelScore] | None = None,
    ) -> list[Decision]:
        if self.scorer is not None:
            generated = [self.scorer.score(finding) for finding in findings]
        else:
            generated = []
        provided = list(scores or []) + generated
        by_finding = {score.finding_id: score for score in provided}
        return [
            Decision(finding=finding, model_score=by_finding.get(finding.finding_id))
            for finding in findings
        ]
