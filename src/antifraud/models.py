from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping


class DecisionStatus(str, Enum):
    OPEN = "open"
    UPDATED = "updated"
    REVOKED = "revoked"
    SEALED = "sealed"


class ChangeCause(str, Enum):
    """Why a decision / revision was produced."""

    EVIDENCE = "evidence"  # late data or source-side revocation
    MANUAL = "manual"  # analyst exclusion / withdrawal
    RULE = "rule"  # rule revision triggered historical re-evaluation
    SEAL = "seal"  # open window reached its sealing boundary


class ReviewAction(str, Enum):
    EXCLUDE = "exclude"
    WITHDRAW = "withdraw"


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
class ManualReview:
    """Analyst judgement about a single piece of evidence.

    Excluding evidence never deletes the underlying event: the original event
    stays in the event log and the exclusion is recorded with a reason so the
    decision can be restored when the review is withdrawn.
    """

    reviewed_event_id: str
    action: ReviewAction
    reviewer: str
    reason: str
    reviewed_at: int
    review_id: str | None = None


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
    revision: int = 1
    change_cause: ChangeCause | None = None
    supersedes_revision: int | None = None
    manual_reviews: tuple[ManualReview, ...] = ()

    def sealed(self) -> "HitEvidence":
        return replace(self, status=DecisionStatus.SEALED)

    def revoked(self) -> "HitEvidence":
        return replace(self, status=DecisionStatus.REVOKED)

    @property
    def line_key(self) -> str:
        """Stable identity of a decision line across rule versions.

        The ``hit_id`` carries the rule's qualified name (with version) and is
        therefore unique per revision; the line key strips the version so all
        re-evaluations of the same window/component stay grouped together.
        """
        version_sep = "|"
        rule_part, _, rest = self.hit_id.partition(version_sep)
        rule_id, _, _version = rule_part.partition("@")
        return f"{rule_id}|{rest}"

    @property
    def excluded_event_ids(self) -> frozenset[str]:
        return frozenset(
            review.reviewed_event_id
            for review in self.manual_reviews
            if review.action == ReviewAction.EXCLUDE
        )

    def with_model_score(
        self, score: float, model_version: str
    ) -> "HitEvidence":
        return replace(self, model_score=score, model_version=model_version)
