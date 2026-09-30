from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping


class DecisionStatus(str, Enum):
    OPEN = "open"
    UPDATED = "updated"
    REVOKED = "revoked"
    SEALED = "sealed"
    REVISED = "revised"


class ChangeCause(str, Enum):
    EVIDENCE = "evidence"
    MANUAL = "manual"
    RULE = "rule"
    SEAL = "seal"


class ManualJudgmentKind(str, Enum):
    FALSE_POSITIVE = "false_positive"
    IDENTITY_SPLIT = "identity_split"
    RULE_EXCEPTION = "rule_exception"


@dataclass(frozen=True, slots=True)
class RuleVersion:
    rule_id: str
    version: str

    @property
    def qualified_name(self) -> str:
        return f"{self.rule_id}@{self.version}"


@dataclass(frozen=True, slots=True)
class EventSource:
    system: str
    producer: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TriggerEvent:
    event_id: str
    event_type: str
    occurred_at: int
    source: EventSource
    payload: Mapping[str, Any]

    @classmethod
    def from_envelope(cls, envelope: "EventEnvelope") -> "TriggerEvent":
        return cls(
            event_id=envelope.event_id,
            event_type=envelope.event_type,
            occurred_at=envelope.occurred_at,
            source=envelope.source,
            payload=envelope.payload_dict(),
        )


@dataclass(frozen=True, slots=True)
class ManualEvidenceJudgment:
    event_id: str
    reason: str
    operator: str
    decided_at: int
    judgment_id: str | None = None
    kind: ManualJudgmentKind = ManualJudgmentKind.FALSE_POSITIVE
    rule_id: str | None = None
    withdrawn_at: int | None = None
    withdrawal_reason: str | None = None

    @property
    def id(self) -> str:
        return self.judgment_id or self.event_id

    @property
    def active(self) -> bool:
        return self.withdrawn_at is None

    def withdrawn(
        self, timestamp: int, reason: str | None = None
    ) -> "ManualEvidenceJudgment":
        return replace(
            self,
            withdrawn_at=timestamp,
            withdrawal_reason=reason,
        )


@dataclass(frozen=True, slots=True)
class HitEvidence:
    hit_id: str
    rule: RuleVersion
    window_start: int
    window_end: int
    identities: tuple[str, ...]
    transaction_ids: tuple[str, ...]
    association_ids: tuple[str, ...]
    trigger_events: tuple[TriggerEvent, ...]
    total_amount: float
    model_score: float | None = None
    model_version: str | None = None
    status: DecisionStatus = DecisionStatus.OPEN
    excluded_event_ids: tuple[str, ...] = ()
    manual_judgments: tuple[ManualEvidenceJudgment, ...] = ()
    original_trigger_events: tuple[TriggerEvent, ...] = ()
    original_transaction_ids: tuple[str, ...] = ()
    original_association_ids: tuple[str, ...] = ()
    original_total_amount: float | None = None
    active_manual_judgments: tuple[ManualEvidenceJudgment, ...] = ()

    @property
    def logical_key(self) -> tuple[str, int, tuple[str, ...]]:
        return (self.rule.rule_id, self.window_start, self.identities)

    def sealed(self) -> "HitEvidence":
        return replace(self, status=DecisionStatus.SEALED)

    def revoked(self) -> "HitEvidence":
        return replace(self, status=DecisionStatus.REVOKED)

    def with_model_score(
        self, score: float, model_version: str
    ) -> "HitEvidence":
        return replace(self, model_score=score, model_version=model_version)


@dataclass(frozen=True, slots=True)
class HitExplanation:
    hit: HitEvidence
    rule: RuleVersion
    original_transactions: tuple[TriggerEvent, ...]
    effective_transactions: tuple[TriggerEvent, ...]
    original_associations: tuple[TriggerEvent, ...]
    effective_associations: tuple[TriggerEvent, ...]
    active_manual_judgments: tuple[ManualEvidenceJudgment, ...]
