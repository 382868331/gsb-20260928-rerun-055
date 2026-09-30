from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from .events import EventEnvelope
from .models import (
    ChangeCause,
    DecisionStatus,
    HitEvidence,
    ManualEvidenceJudgment,
)
from .rules import CrossIdentityFlowRule, RuleDecision


class RuleEngine:
    """Ingest events and maintain current and historical rule decisions."""

    def __init__(
        self,
        rules: Iterable[CrossIdentityFlowRule] | None = None,
        *,
        sealing_grace_seconds: int = 0,
    ) -> None:
        self.rules = list(
            rules
            or [
                CrossIdentityFlowRule(
                    window_seconds=300,
                    min_identities=3,
                    min_total_amount=1000.0,
                )
            ]
        )
        if sealing_grace_seconds < 0:
            raise ValueError("sealing_grace_seconds cannot be negative")
        self.sealing_grace_seconds = sealing_grace_seconds
        self._events_by_id: dict[str, EventEnvelope] = {}
        self._revoked_event_ids: set[str] = set()
        self._manual_judgments: dict[str, ManualEvidenceJudgment] = {}
        self._latest_seen_at = 0
        self._evidence: dict[str, HitEvidence] = {}
        self._revision_sequence = 0
        self.revisions: list[dict[str, object]] = []

    def ingest(self, event: EventEnvelope) -> list[RuleDecision]:
        if event.event_id in self._events_by_id:
            return []
        self._events_by_id[event.event_id] = event
        self._latest_seen_at = max(self._latest_seen_at, event.occurred_at)
        if event.is_revocation:
            assert event.revokes_event_id is not None
            self._revoked_event_ids.add(event.revokes_event_id)
        return self._recompute(
            cause=ChangeCause.EVIDENCE,
            changed_at=event.occurred_at,
        )

    def ingest_many(
        self, events: Iterable[EventEnvelope]
    ) -> list[RuleDecision]:
        decisions: list[RuleDecision] = []
        for event in events:
            decisions.extend(self.ingest(event))
        return decisions

    def exclude_evidence(
        self,
        event_id: str,
        reason: str,
        *,
        operator: str,
        decided_at: int,
    ) -> list[RuleDecision]:
        if not reason:
            raise ValueError("reason is required")
        if not operator:
            raise ValueError("operator is required")
        existing = self._manual_judgments.get(event_id)
        if existing is not None and existing.active:
            return []
        self._manual_judgments[event_id] = ManualEvidenceJudgment(
            event_id=event_id,
            reason=reason,
            operator=operator,
            decided_at=decided_at,
        )
        self._latest_seen_at = max(self._latest_seen_at, decided_at)
        return self._recompute(
            cause=ChangeCause.MANUAL,
            changed_at=decided_at,
            actor=operator,
            reason=reason,
        )

    def withdraw_evidence_judgment(
        self,
        event_id: str,
        *,
        withdrawn_at: int,
        reason: str | None = None,
    ) -> list[RuleDecision]:
        existing = self._manual_judgments.get(event_id)
        if existing is None or not existing.active:
            return []
        self._manual_judgments[event_id] = existing.withdrawn(
            withdrawn_at,
            reason,
        )
        self._latest_seen_at = max(self._latest_seen_at, withdrawn_at)
        return self._recompute(
            cause=ChangeCause.MANUAL,
            changed_at=withdrawn_at,
            actor=existing.operator,
            reason=reason or f"withdraw:{event_id}",
        )

    def replace_rule(
        self,
        rule_id: str,
        replacement: CrossIdentityFlowRule,
        *,
        effective_at: int | None = None,
    ) -> list[RuleDecision]:
        if replacement.version_info.rule_id != rule_id:
            raise ValueError("replacement must keep the same rule_id")
        index = next(
            (
                index
                for index, rule in enumerate(self.rules)
                if rule.version_info.rule_id == rule_id
            ),
            None,
        )
        if index is None:
            raise KeyError(rule_id)
        previous = self.rules[index]
        if previous.qualified_name == replacement.qualified_name:
            return []
        self.rules[index] = replacement
        changed_at = (
            self._latest_seen_at if effective_at is None else effective_at
        )
        self._latest_seen_at = max(self._latest_seen_at, changed_at)
        return self._recompute(
            cause=ChangeCause.RULE,
            changed_at=changed_at,
        )

    @property
    def watermark(self) -> int:
        return self._latest_seen_at

    def raw_events(self) -> list[EventEnvelope]:
        return list(self._events_by_id.values())

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

    def hit_history(self) -> list[dict[str, object]]:
        return list(self.revisions)

    def manual_judgments(self) -> list[ManualEvidenceJudgment]:
        return list(self._manual_judgments.values())

    def _recompute(
        self,
        *,
        cause: ChangeCause,
        changed_at: int,
        actor: str | None = None,
        reason: str | None = None,
    ) -> list[RuleDecision]:
        seal_before = self._latest_seen_at - self.sealing_grace_seconds
        raw_active_events = [
            event
            for event in self._events_by_id.values()
            if not event.is_revocation
            and event.event_id not in self._revoked_event_ids
        ]
        excluded_event_ids = {
            event_id
            for event_id, judgment in self._manual_judgments.items()
            if judgment.active
        }
        effective_events = [
            event
            for event in raw_active_events
            if event.event_id not in excluded_event_ids
        ]

        evaluated: dict[str, HitEvidence] = {}
        for rule in self.rules:
            for hit_id, evidence in rule.evaluate(effective_events).items():
                evidence = self._apply_manual_context(
                    evidence,
                    excluded_event_ids=excluded_event_ids,
                )
                if evidence.window_end < seal_before:
                    evidence = evidence.sealed()
                evaluated[hit_id] = evidence

        current: dict[str, HitEvidence] = {}
        consumed_previous_ids: set[str] = set()
        decisions: list[RuleDecision] = []

        for hit_id, evidence in evaluated.items():
            previous = self._evidence.get(hit_id)
            if previous is not None and "|revision:" in previous.hit_id:
                previous = None

            output_hit_id = hit_id
            if previous is None:
                next_evidence = evidence
            elif previous.status == DecisionStatus.SEALED:
                if self._same_revision_content(previous, evidence):
                    current[previous.hit_id] = previous
                    consumed_previous_ids.add(previous.hit_id)
                    continue
                revision_hit_id = hit_id
                if revision_hit_id == previous.hit_id:
                    revision_hit_id = (
                        f"{hit_id}|revision:{self._revision_sequence + 1}"
                    )
                next_evidence = replace(
                    evidence,
                    hit_id=revision_hit_id,
                    status=DecisionStatus.REVISED,
                )
                output_hit_id = revision_hit_id
                current[previous.hit_id] = previous
            elif previous.status == DecisionStatus.REVISED:
                next_evidence = evidence
            else:
                next_evidence = self._open_revision_status(
                    previous=previous,
                    evidence=evidence,
                    requested_cause=cause,
                )

            if previous is not None:
                consumed_previous_ids.add(previous.hit_id)
                next_evidence = self._carry_model_score(previous, next_evidence)
                next_evidence = self._apply_manual_context(
                    next_evidence,
                    excluded_event_ids=excluded_event_ids,
                )
            decision_cause = cause
            if (
                previous is not None
                and previous.status != DecisionStatus.SEALED
                and next_evidence.status == DecisionStatus.SEALED
                and cause != ChangeCause.RULE
            ):
                decision_cause = ChangeCause.SEAL
            decision = RuleDecision(
                evidence=next_evidence,
                previous_status=(
                    None if previous is None else previous.status
                ),
                cause=decision_cause,
            )
            current[output_hit_id] = next_evidence
            if previous is None or self._revision_changed(
                previous,
                next_evidence,
            ):
                decisions.append(decision)
                self._record_revision(
                    previous=previous,
                    current=next_evidence,
                    cause=decision_cause,
                    changed_at=changed_at,
                    actor=actor,
                    reason=reason,
                )

        for previous in self._evidence.values():
            if previous.hit_id in consumed_previous_ids:
                continue
            if previous.hit_id in current:
                continue
            if previous.status == DecisionStatus.SEALED:
                current[previous.hit_id] = previous
                decision_cause = (
                    ChangeCause.MANUAL
                    if excluded_event_ids.intersection(
                        self._evidence_event_ids(previous)
                    )
                    else cause
                )
                revision_hit_id = (
                    f"{previous.hit_id}|revision:{self._revision_sequence + 1}"
                )
                next_evidence = self._apply_manual_context(
                    previous.revoked(),
                    excluded_event_ids=excluded_event_ids,
                )
                next_evidence = replace(
                    next_evidence,
                    hit_id=revision_hit_id,
                )
                decisions.append(
                    RuleDecision(
                        evidence=next_evidence,
                        previous_status=previous.status,
                        cause=decision_cause,
                    )
                )
                self._record_revision(
                    previous=previous,
                    current=next_evidence,
                    cause=decision_cause,
                    changed_at=changed_at,
                    actor=actor,
                    reason=reason,
                )
                continue
            if previous.status in (
                DecisionStatus.REVOKED,
                DecisionStatus.REVISED,
            ):
                current[previous.hit_id] = previous
                continue
            next_evidence = self._apply_manual_context(
                previous.revoked(),
                excluded_event_ids=excluded_event_ids,
            )
            decision_cause = (
                ChangeCause.MANUAL
                if excluded_event_ids.intersection(
                    self._evidence_event_ids(previous)
                )
                else cause
            )
            current[previous.hit_id] = next_evidence
            decisions.append(
                RuleDecision(
                    evidence=next_evidence,
                    previous_status=previous.status,
                    cause=decision_cause,
                )
            )
            self._record_revision(
                previous=previous,
                current=next_evidence,
                cause=decision_cause,
                changed_at=changed_at,
                actor=actor,
                reason=reason,
            )

        self._evidence = current
        return decisions

    def _apply_manual_context(
        self,
        evidence: HitEvidence,
        *,
        excluded_event_ids: set[str],
    ) -> HitEvidence:
        evidence_event_ids = self._evidence_event_ids(evidence)
        applied_exclusions = tuple(
            sorted(excluded_event_ids.intersection(evidence_event_ids))
        )
        judgments = tuple(
            judgment
            for event_id, judgment in sorted(self._manual_judgments.items())
            if event_id in evidence_event_ids
        )
        return replace(
            evidence,
            excluded_event_ids=applied_exclusions,
            manual_judgments=judgments,
        )

    @staticmethod
    def _evidence_event_ids(evidence: HitEvidence) -> set[str]:
        return {event.event_id for event in evidence.trigger_events}

    def _open_revision_status(
        self,
        *,
        previous: HitEvidence,
        evidence: HitEvidence,
        requested_cause: ChangeCause,
    ) -> HitEvidence:
        rule_changed = previous.rule != evidence.rule
        manual_changed = (
            previous.excluded_event_ids != evidence.excluded_event_ids
            or previous.manual_judgments != evidence.manual_judgments
        )
        if rule_changed:
            return replace(evidence, status=DecisionStatus.REVISED)
        if manual_changed and requested_cause == ChangeCause.MANUAL:
            return replace(evidence, status=DecisionStatus.REVISED)
        if evidence.status == DecisionStatus.SEALED:
            return evidence
        if self._same_revision_content(previous, evidence):
            return evidence
        return replace(evidence, status=DecisionStatus.UPDATED)

    @staticmethod
    def _carry_model_score(
        previous: HitEvidence, evidence: HitEvidence
    ) -> HitEvidence:
        if previous.rule != evidence.rule:
            return evidence
        return replace(
            evidence,
            model_score=previous.model_score,
            model_version=previous.model_version,
        )

    def _revision_changed(
        self, previous: HitEvidence | None, current: HitEvidence
    ) -> bool:
        if previous is None:
            return True
        return (
            self._revision_payload(previous) != self._revision_payload(current)
            or previous.status != current.status
        )

    def _same_revision_content(
        self, previous: HitEvidence, current: HitEvidence
    ) -> bool:
        return self._revision_payload(previous) == self._revision_payload(current)

    @staticmethod
    def _revision_payload(evidence: HitEvidence) -> tuple[object, ...]:
        return (
            evidence.rule,
            evidence.window_start,
            evidence.window_end,
            evidence.identities,
            evidence.transaction_ids,
            evidence.association_ids,
            tuple(
                (event.event_id, event.occurred_at)
                for event in evidence.trigger_events
            ),
            evidence.total_amount,
            evidence.model_score,
            evidence.model_version,
            evidence.excluded_event_ids,
            tuple(
                (
                    judgment.event_id,
                    judgment.reason,
                    judgment.operator,
                    judgment.decided_at,
                    judgment.withdrawn_at,
                )
                for judgment in evidence.manual_judgments
            ),
        )

    def _record_revision(
        self,
        *,
        previous: HitEvidence | None,
        current: HitEvidence,
        cause: ChangeCause,
        changed_at: int,
        actor: str | None,
        reason: str | None,
    ) -> None:
        self._revision_sequence += 1
        self.revisions.append(
            {
                "revision_id": self._revision_sequence,
                "hit_id": current.hit_id,
                "logical_key": current.logical_key,
                "cause": cause,
                "changed_at": changed_at,
                "actor": actor,
                "reason": reason,
                "previous": previous,
                "current": current,
            }
        )
