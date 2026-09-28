from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from .models import IdentityAssociation, Transaction


@dataclass(frozen=True)
class RuleVersion:
    name: str
    version: str

    def __str__(self) -> str:
        return f"{self.name}/{self.version}"


@dataclass(frozen=True)
class Evidence:
    transactions: tuple[Transaction, ...]
    associations: tuple[IdentityAssociation, ...]


@dataclass(frozen=True)
class RuleFinding:
    finding_id: str
    rule: RuleVersion
    identity_id: str
    window_started_at: datetime
    window_ended_at: datetime
    evidence: Evidence
    rationale: str
    parameters: dict[str, object] = field(default_factory=dict)


class TemporalRule(Protocol):
    def evaluate(
        self,
        transactions: list[Transaction],
        associations: list[IdentityAssociation],
        watermark: datetime,
        unsealed_after: datetime,
    ) -> list[RuleFinding]:
        ...


class CrossIdentityFlowRule:
    """Detect one identity rapidly transacting with several linked identities.

    The rule is intentionally explainable: every finding retains the exact
    transactions and identity-association events that satisfied its thresholds.
    """

    def __init__(
        self,
        window: timedelta = timedelta(hours=1),
        min_linked_counterparties: int = 2,
        grace_period: timedelta = timedelta(minutes=5),
    ) -> None:
        if min_linked_counterparties < 2:
            raise ValueError("min_linked_counterparties must be at least 2")
        self.version = RuleVersion("cross_identity_linked_flow", "1.0.0")
        self.window = window
        self.min_linked_counterparties = min_linked_counterparties
        self.grace_period = grace_period

    def evaluate(
        self,
        transactions: list[Transaction],
        associations: list[IdentityAssociation],
        watermark: datetime,
        unsealed_after: datetime,
    ) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        seen_clusters: set[tuple[str, str, tuple[str, ...]]] = set()

        for focus in self._focus_identities(transactions):
            focus_transactions = sorted(
                (
                    transaction
                    for transaction in transactions
                    if focus in (transaction.sender_id, transaction.recipient_id)
                ),
                key=lambda item: (item.occurred_at, item.event_id),
            )

            for anchor in focus_transactions:
                window_end = anchor.occurred_at + self.window
                if window_end <= unsealed_after or anchor.occurred_at > watermark:
                    continue
                in_window = [
                    transaction
                    for transaction in focus_transactions
                    if anchor.occurred_at
                    <= transaction.occurred_at
                    <= window_end
                ]

                by_counterparty = self._group_by_linked_counterparty(
                    focus, in_window, associations
                )
                counterparties = tuple(sorted(by_counterparty))
                if len(counterparties) < self.min_linked_counterparties:
                    continue

                triggering = sorted(
                    {
                        transaction.event_id: transaction
                        for grouped in by_counterparty.values()
                        for transaction, _association in grouped
                    }.values(),
                    key=lambda item: (item.occurred_at, item.event_id),
                )
                evidence_associations = sorted(
                    {
                        association.event_id: association
                        for grouped in by_counterparty.values()
                        for _transaction, association in grouped[:1]
                    }.values(),
                    key=lambda item: (item.occurred_at, item.event_id),
                )
                event_ids = tuple(item.event_id for item in triggering)
                dedupe_key = (focus, str(self.version), event_ids)
                if dedupe_key in seen_clusters:
                    continue
                seen_clusters.add(dedupe_key)

                findings.append(
                    RuleFinding(
                        finding_id=self._finding_id(focus, event_ids),
                        rule=self.version,
                        identity_id=focus,
                        window_started_at=triggering[0].occurred_at,
                        window_ended_at=window_end,
                        evidence=Evidence(
                            transactions=tuple(triggering),
                            associations=tuple(evidence_associations),
                        ),
                        rationale=(
                            f"{focus} transacted with {len(counterparties)} linked "
                            f"identities within {self.window}"
                        ),
                        parameters={
                            "window_seconds": self.window.total_seconds(),
                            "min_linked_counterparties": self.min_linked_counterparties,
                            "counterparties": counterparties,
                        },
                    )
                )

        return sorted(findings, key=lambda item: item.finding_id)

    @staticmethod
    def _focus_identities(transactions: list[Transaction]) -> list[str]:
        identities = {
            identity
            for transaction in transactions
            for identity in (transaction.sender_id, transaction.recipient_id)
        }
        return sorted(identities)

    def _group_by_linked_counterparty(
        self,
        focus: str,
        transactions: list[Transaction],
        associations: list[IdentityAssociation],
    ) -> dict[str, list[tuple[Transaction, IdentityAssociation]]]:
        grouped: dict[str, list[tuple[Transaction, IdentityAssociation]]] = {}
        for transaction in transactions:
            counterparty = (
                transaction.recipient_id
                if transaction.sender_id == focus
                else transaction.sender_id
            )
            association = self._association_before(
                focus, counterparty, transaction.occurred_at, associations
            )
            if association is not None:
                grouped.setdefault(counterparty, []).append((transaction, association))
        return grouped

    @staticmethod
    def _association_before(
        left: str,
        right: str,
        when: datetime,
        associations: list[IdentityAssociation],
    ) -> IdentityAssociation | None:
        matches = [
            association
            for association in associations
            if {association.left_identity_id, association.right_identity_id}
            == {left, right}
            and association.occurred_at <= when
        ]
        return max(matches, key=lambda item: item.occurred_at, default=None)

    @staticmethod
    def _finding_id(focus: str, event_ids: tuple[str, ...]) -> str:
        fingerprint = "|".join(event_ids)
        return f"finding:{focus}:{hashlib_sha256(fingerprint)}"


def hashlib_sha256(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
