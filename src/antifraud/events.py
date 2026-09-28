from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .models import EventSource


@dataclass(frozen=True, slots=True)
class Transaction:
    transaction_id: str
    from_identity: str
    to_identity: str
    amount: float
    currency: str = "FC"

    @property
    def identities(self) -> tuple[str, str]:
        return tuple(sorted((self.from_identity, self.to_identity)))

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "Transaction":
        return cls(**payload)


@dataclass(frozen=True, slots=True)
class IdentityAssociation:
    association_id: str
    identity_a: str
    identity_b: str
    valid_from: int
    valid_to: int | None = None
    confidence: float = 1.0

    def active_at(self, timestamp: int) -> bool:
        return self.valid_from <= timestamp and (
            self.valid_to is None or timestamp <= self.valid_to
        )

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "IdentityAssociation":
        return cls(**payload)


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    event_id: str
    event_type: str
    occurred_at: int
    source: EventSource
    payload: Transaction | IdentityAssociation | dict[str, Any]
    revokes_event_id: str | None = None

    def payload_dict(self) -> dict[str, Any]:
        if isinstance(self.payload, dict):
            return dict(self.payload)
        return self.payload.as_payload()

    @property
    def is_revocation(self) -> bool:
        return self.revokes_event_id is not None


def transaction_event(
    transaction: Transaction,
    *,
    occurred_at: int,
    source: EventSource,
    event_id: str | None = None,
) -> EventEnvelope:
    return EventEnvelope(
        event_id=event_id or f"evt-{transaction.transaction_id}",
        event_type="fictitious_transaction",
        occurred_at=occurred_at,
        source=source,
        payload=transaction,
    )


def association_event(
    association: IdentityAssociation,
    *,
    source: EventSource,
    event_id: str | None = None,
) -> EventEnvelope:
    return EventEnvelope(
        event_id=event_id or f"evt-{association.association_id}",
        event_type="identity_association",
        occurred_at=association.valid_from,
        source=source,
        payload=association,
    )


def revocation_event(
    revoked_event_id: str,
    *,
    occurred_at: int,
    source: EventSource,
    event_id: str,
) -> EventEnvelope:
    return EventEnvelope(
        event_id=event_id,
        event_type="revocation",
        occurred_at=occurred_at,
        source=source,
        payload={},
        revokes_event_id=revoked_event_id,
    )
