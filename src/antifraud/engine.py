from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from .events import EventEnvelope
from .models import DecisionStatus, HitEvidence
from .rules import CrossIdentityFlowRule, RuleDecision


class RuleEngine:
    """Ingest events and maintain mutable, unsealed rule decisions."""

    def __init__(
        self,
        rules: Iterable[CrossIdentityFlowRule] | None = None,
        *,
        sealing_grace_seconds: int = 0,
    ) -> None:
        self.rules = list(rules or [CrossIdentityFlowRule(
            window_seconds=300,
            min_identities=3,
            min_total_amount=1000.0,
        )])
        if sealing_grace_seconds < 0:
            raise ValueError("sealing_grace_seconds cannot be negative")
        self.sealing_grace_seconds = sealing_grace_seconds
        self._events_by_id: dict[str, EventEnvelope] = {}
        self._revoked_event_ids: set[str] = set()
        self._latest_seen_at = 0
        self._evidence: dict[str, HitEvidence] = {}

    def ingest(self, event: EventEnvelope) -> list[RuleDecision]:
        if event.event_id in self._events_by_id:
            return []
        self._events_by_id[event.event_id] = event
        self._latest_seen_at = max(self._latest_seen_at, event.occurred_at)
        if event.is_revocation:
            assert event.revokes_event_id is not None
            self._revoked_event_ids.add(event.revokes_event_id)
        return self._recompute()

    def ingest_many(
        self, events: Iterable[EventEnvelope]
    ) -> list[RuleDecision]:
        decisions: list[RuleDecision] = []
        for event in events:
            decisions.extend(self.ingest(event))
        return decisions

    @property
    def watermark(self) -> int:
        return self._latest_seen_at

    def active_hits(self) -> list[HitEvidence]:
        return [
            evidence
            for evidence in self._evidence.values()
            if evidence.status != DecisionStatus.REVOKED
        ]

    def all_hits(self) -> list[HitEvidence]:
        return list(self._evidence.values())

    def hit(self, hit_id: str) -> HitEvidence | None:
        return self._evidence.get(hit_id)

    def _recompute(self) -> list[RuleDecision]:
        seal_before = self._latest_seen_at - self.sealing_grace_seconds
        active_events = [
            event
            for event in self._events_by_id.values()
            if not event.is_revocation
            and event.event_id not in self._revoked_event_ids
        ]

        current: dict[str, HitEvidence] = {}
        for rule in self.rules:
            for hit_id, evidence in rule.evaluate(active_events).items():
                if evidence.window_end < seal_before:
                    evidence = evidence.sealed()
                current[hit_id] = evidence

        decisions: list[RuleDecision] = []
        previous_ids = set(self._evidence)

        for hit_id in previous_ids.difference(current):
            previous = self._evidence[hit_id]
            if previous.status == DecisionStatus.SEALED:
                current[hit_id] = previous
                continue
            revoked = previous.revoked()
            current[hit_id] = revoked
            decisions.append(
                RuleDecision(
                    evidence=revoked,
                    previous_status=previous.status,
                )
            )

        for hit_id, evidence in current.items():
            previous = self._evidence.get(hit_id)
            if (
                previous is not None
                and previous.status == DecisionStatus.SEALED
            ):
                current[hit_id] = previous
                continue
            if previous is None:
                decisions.append(
                    RuleDecision(evidence=evidence, previous_status=None)
                )
            elif (
                previous.status != DecisionStatus.SEALED
                and evidence.status == DecisionStatus.SEALED
            ):
                decisions.append(
                    RuleDecision(
                        evidence=evidence,
                        previous_status=previous.status,
                    )
                )
            elif self._content_changed(previous, evidence):
                updated_evidence = evidence
                if updated_evidence.status == DecisionStatus.OPEN:
                    updated_evidence = replace(
                        updated_evidence,
                        status=DecisionStatus.UPDATED,
                    )
                decisions.append(
                    RuleDecision(
                        evidence=updated_evidence,
                        previous_status=previous.status,
                    )
                )

        self._evidence = current
        return decisions

    @staticmethod
    def _content_changed(
        previous: HitEvidence, current: HitEvidence
    ) -> bool:
        compared_fields = (
            "rule",
            "window_start",
            "window_end",
            "identities",
            "transaction_ids",
            "association_ids",
            "trigger_events",
            "total_amount",
        )
        return any(
            getattr(previous, field) != getattr(current, field)
            for field in compared_fields
        )
