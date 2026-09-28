from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping


class DecisionStatus(str, Enum):
    OPEN = "open"
    UPDATED = "updated"
    REVOKED = "revoked"
    SEALED = "sealed"


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

    def sealed(self) -> "HitEvidence":
        return replace(self, status=DecisionStatus.SEALED)

    def revoked(self) -> "HitEvidence":
        return replace(self, status=DecisionStatus.REVOKED)

    def with_model_score(
        self, score: float, model_version: str
    ) -> "HitEvidence":
        return replace(self, model_score=score, model_version=model_version)
