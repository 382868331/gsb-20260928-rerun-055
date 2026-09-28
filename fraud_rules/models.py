from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class DataClassification(str, Enum):
    FICTIONAL = "fictional"


@dataclass(frozen=True)
class EventSource:
    """Provenance for an inbound event."""

    system: str
    record_id: str
    topic: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TemporalEvent:
    event_id: str
    source: EventSource
    occurred_at: datetime
    classification: DataClassification = DataClassification.FICTIONAL

    def __post_init__(self) -> None:
        if self.classification is not DataClassification.FICTIONAL:
            raise ValueError("the first platform version accepts fictional data only")
        if self.occurred_at.tzinfo is None:
            raise ValueError("event timestamps must be timezone-aware")


@dataclass(frozen=True)
class Transaction(TemporalEvent):
    transaction_id: str = ""
    sender_id: str = ""
    recipient_id: str = ""
    amount_cents: int = 0
    currency: str = "CNY"

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.transaction_id or not self.sender_id or not self.recipient_id:
            raise ValueError("transaction_id, sender_id and recipient_id are required")
        if self.sender_id == self.recipient_id:
            raise ValueError("sender and recipient must be different identities")
        if self.amount_cents <= 0:
            raise ValueError("amount_cents must be positive")


@dataclass(frozen=True)
class IdentityAssociation(TemporalEvent):
    left_identity_id: str = ""
    right_identity_id: str = ""
    association_type: str = "unspecified"

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.left_identity_id or not self.right_identity_id:
            raise ValueError("both association identities are required")
        if self.left_identity_id == self.right_identity_id:
            raise ValueError("an identity cannot be associated with itself")


@dataclass(frozen=True)
class TransactionRetraction(TemporalEvent):
    transaction_id: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.transaction_id:
            raise ValueError("transaction_id is required")
