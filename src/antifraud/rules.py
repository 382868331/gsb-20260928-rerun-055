from __future__ import annotations

from dataclasses import dataclass

from .events import EventEnvelope, IdentityAssociation, Transaction
from .models import (
    DecisionStatus,
    HitEvidence,
    RuleVersion,
    TriggerEvent,
)


@dataclass(frozen=True, slots=True)
class RuleDecision:
    evidence: HitEvidence
    previous_status: DecisionStatus | None

    @property
    def is_new(self) -> bool:
        return self.previous_status is None


class CrossIdentityFlowRule:
    """Detect connected transactions spanning several identities in a window."""

    def __init__(
        self,
        *,
        window_seconds: int,
        min_identities: int,
        min_total_amount: float,
        rule_id: str = "cross_identity_flow",
        version: str = "v1",
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if min_identities < 2:
            raise ValueError("min_identities must be at least 2")
        if min_total_amount < 0:
            raise ValueError("min_total_amount cannot be negative")
        self.window_seconds = window_seconds
        self.min_identities = min_identities
        self.min_total_amount = min_total_amount
        self.version_info = RuleVersion(rule_id, version)

    @property
    def qualified_name(self) -> str:
        return self.version_info.qualified_name

    def evaluate(
        self, events: list[EventEnvelope]
    ) -> dict[str, HitEvidence]:
        transactions = [
            event
            for event in events
            if isinstance(event.payload, Transaction)
        ]
        associations = [
            event
            for event in events
            if isinstance(event.payload, IdentityAssociation)
        ]
        transactions.sort(key=lambda event: (event.occurred_at, event.event_id))

        hits: dict[str, HitEvidence] = {}
        observed_slots = sorted(
            {
                event.occurred_at // self.window_seconds
                for event in transactions
            }
        )
        for window_slot in observed_slots:
            window_start = window_slot * self.window_seconds
            window_end = window_start + self.window_seconds
            window_events = [
                event
                for event in transactions
                if event.occurred_at <= window_end
                and event.occurred_at >= window_start
            ]
            evidence = self._evidence_for_window(
                window_events=window_events,
                associations=associations,
                window_start=window_start,
                window_end=window_end,
            )
            for group_evidence in evidence:
                hits[group_evidence.hit_id] = group_evidence
        return hits

    def _evidence_for_window(
        self,
        *,
        window_events: list[EventEnvelope],
        associations: list[EventEnvelope],
        window_start: int,
        window_end: int,
    ) -> list[HitEvidence]:
        active_associations: list[EventEnvelope] = []
        parent: dict[str, str] = {}

        def find(identity: str) -> str:
            parent.setdefault(identity, identity)
            while parent[identity] != identity:
                parent[identity] = parent[parent[identity]]
                identity = parent[identity]
            return identity

        def union(left: str, right: str) -> None:
            left_root = find(left)
            right_root = find(right)
            if left_root != right_root:
                parent[max(left_root, right_root)] = min(
                    left_root, right_root
                )

        for event in associations:
            association = event.payload
            assert isinstance(association, IdentityAssociation)
            if not self._association_overlaps_window(
                association, window_start, window_end
            ):
                continue
            active_associations.append(event)
            union(association.identity_a, association.identity_b)

        selected_by_component: dict[str, list[EventEnvelope]] = {}
        associations_by_component: dict[str, list[EventEnvelope]] = {}

        for event in window_events:
            transaction = event.payload
            assert isinstance(transaction, Transaction)
            if transaction.amount <= 0:
                continue
            source_root = find(transaction.from_identity)
            target_root = find(transaction.to_identity)
            if source_root != target_root:
                continue
            component = find(source_root)
            selected_by_component.setdefault(component, []).append(event)

        for event in active_associations:
            association = event.payload
            assert isinstance(association, IdentityAssociation)
            component = find(association.identity_a)
            associations_by_component.setdefault(component, []).append(event)

        evidence: list[HitEvidence] = []
        for component, selected in sorted(selected_by_component.items()):
            selected_nodes = {
                identity
                for event in selected
                for identity in event.payload.identities
            }
            total_amount = sum(event.payload.amount for event in selected)
            if (
                len(selected_nodes) < self.min_identities
                or total_amount < self.min_total_amount
            ):
                continue
            selected.sort(
                key=lambda event: (event.occurred_at, event.event_id)
            )
            component_associations = sorted(
                associations_by_component.get(component, []),
                key=lambda event: (event.occurred_at, event.event_id),
            )
            transaction_ids = tuple(
                event.payload.transaction_id for event in selected
            )
            association_ids = tuple(
                event.payload.association_id
                for event in component_associations
            )
            trigger_events = tuple(
                TriggerEvent.from_envelope(event)
                for event in component_associations + selected
            )
            identities = tuple(sorted(selected_nodes))
            evidence.append(
                HitEvidence(
                    hit_id=self._hit_id(
                        window_start=window_start,
                        component=component,
                    ),
                    rule=self.version_info,
                    window_start=window_start,
                    window_end=window_end,
                    identities=identities,
                    transaction_ids=transaction_ids,
                    association_ids=association_ids,
                    trigger_events=trigger_events,
                    total_amount=round(total_amount, 10),
                )
            )
        return evidence

    def _association_overlaps_window(
        self,
        association: IdentityAssociation,
        window_start: int,
        window_end: int,
    ) -> bool:
        starts_before_end = association.valid_from <= window_end
        ends_after_start = (
            association.valid_to is None
            or association.valid_to >= window_start
        )
        return starts_before_end and ends_after_start

    def _hit_id(
        self,
        *,
        window_start: int,
        component: str,
    ) -> str:
        window_slot = window_start // self.window_seconds
        return (
            f"{self.qualified_name}|window:{window_slot}|component:{component}"
        )
