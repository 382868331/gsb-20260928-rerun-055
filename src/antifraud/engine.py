from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from .events import EventEnvelope
from .models import (
    ChangeCause,
    DecisionStatus,
    HitEvidence,
    ManualReview,
    ReviewAction,
)
from .reviews import ReviewRequest
from .rules import CrossIdentityFlowRule, RuleDecision


class RuleEngine:
    """Ingest events and maintain versioned rule decisions.

    Decision lines are identified by ``HitEvidence.line_key`` (rule id plus
    window and component). Every material change appends a new revision:

    * late events / source revocations while a window is open update the
      current revision (``ChangeCause.EVIDENCE``);
    * analyst exclusions or withdrawals recompute affected lines
      (``ChangeCause.MANUAL``) without deleting any original event;
    * rule revisions re-evaluate history (``ChangeCause.RULE``);
    * crossing the sealing boundary seals the open revision
      (``ChangeCause.SEAL``); late data afterwards is never merged into the
      sealed snapshot but creates a separate revision.
    """

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
        self._latest_seen_at = 0
        # line_key -> revisions in chronological order
        self._lines: dict[str, list[HitEvidence]] = {}
        # audit log of every analyst judgement, keyed by reviewed event
        self._reviews_by_event: dict[str, list[ManualReview]] = {}

    # ------------------------------------------------------------------ ingest

    def ingest(self, event: EventEnvelope) -> list[RuleDecision]:
        if event.event_id in self._events_by_id:
            return []
        self._events_by_id[event.event_id] = event
        self._latest_seen_at = max(self._latest_seen_at, event.occurred_at)
        if event.is_revocation:
            assert event.revokes_event_id is not None
            self._revoked_event_ids.add(event.revokes_event_id)
        return self._recompute(ChangeCause.EVIDENCE)

    def ingest_many(
        self, events: Iterable[EventEnvelope]
    ) -> list[RuleDecision]:
        decisions: list[RuleDecision] = []
        for event in events:
            decisions.extend(self.ingest(event))
        return decisions

    # ------------------------------------------------------------------ review

    def review_evidence(self, request: ReviewRequest) -> list[RuleDecision]:
        """Record an analyst exclusion/withdrawal and recompute hits.

        The referenced original event is never removed: exclusions are kept
        as reviews attached to affected evidence, and withdrawing a review
        restores the event into subsequent recomputation.
        """
        if request.reviewed_event_id not in self._events_by_id:
            raise KeyError(
                f"unknown event for review: {request.reviewed_event_id!r}"
            )
        if not request.reason.strip():
            raise ValueError("manual review requires a non-empty reason")
        record = request.to_record()
        history = self._reviews_by_event.setdefault(
            request.reviewed_event_id, []
        )
        if request.action == ReviewAction.EXCLUDE:
            if history and history[-1].action == ReviewAction.EXCLUDE:
                raise ValueError(
                    f"event {request.reviewed_event_id!r} is already excluded"
                )
        elif history and history[-1].action == ReviewAction.WITHDRAW:
            raise ValueError(
                f"no active exclusion to withdraw for event "
                f"{request.reviewed_event_id!r}"
            )
        history.append(record)
        self._latest_seen_at = max(
            self._latest_seen_at, request.reviewed_at
        )
        return self._recompute(ChangeCause.MANUAL)

    def is_excluded(self, event_id: str) -> bool:
        history = self._reviews_by_event.get(event_id)
        return bool(
            history and history[-1].action == ReviewAction.EXCLUDE
        )

    def review_history(self, event_id: str) -> tuple[ManualReview, ...]:
        return tuple(self._reviews_by_event.get(event_id, ()))

    # -------------------------------------------------------------------- rules

    def revise_rule(
        self, revised: CrossIdentityFlowRule, *, revised_at: int
    ) -> list[RuleDecision]:
        """Replace a rule with a new version and re-evaluate history.

        Open windows are updated in place; sealed windows keep every prior
        revision and get an additional revision carrying the new rule version.
        """
        target = next(
            (rule for rule in self.rules if rule.rule_id() == revised.rule_id()),
            None,
        )
        if target is None:
            raise KeyError(
                f"unknown rule to revise: {revised.rule_id()!r}"
            )
        if target.qualified_name == revised.qualified_name:
            raise ValueError(
                "revised rule must carry a new version: "
                f"{revised.qualified_name}"
            )
        self.rules[self.rules.index(target)] = revised
        self._latest_seen_at = max(self._latest_seen_at, revised_at)
        return self._recompute(ChangeCause.RULE)

    # ------------------------------------------------------------------- views

    @property
    def watermark(self) -> int:
        return self._latest_seen_at

    def active_hits(self) -> list[HitEvidence]:
        return [
            revisions[-1]
            for revisions in self._lines.values()
            if revisions[-1].status != DecisionStatus.REVOKED
        ]

    def all_hits(self) -> list[HitEvidence]:
        """Latest revision of every decision line."""
        return [
            revisions[-1] for revisions in self._lines.values()
        ]

    def all_revisions(self) -> list[HitEvidence]:
        """Every revision, oldest first, across all decision lines."""
        revisions: list[HitEvidence] = []
        for line in self._lines.values():
            revisions.extend(line)
        return revisions

    def hit_history(self, line_key: str) -> tuple[HitEvidence, ...]:
        return tuple(self._lines.get(line_key, ()))

    def hit(self, hit_id: str) -> HitEvidence | None:
        for revisions in self._lines.values():
            for evidence in reversed(revisions):
                if evidence.hit_id == hit_id:
                    return evidence
        return None

    def latest_for_line(self, line_key: str) -> HitEvidence | None:
        revisions = self._lines.get(line_key)
        return revisions[-1] if revisions else None

    # -------------------------------------------------------------- recompute

    def _active_events(self) -> list[EventEnvelope]:
        return [
            event
            for event in self._events_by_id.values()
            if not event.is_revocation
            and event.event_id not in self._revoked_event_ids
            and not self.is_excluded(event.event_id)
        ]

    def _reviews_for(
        self, evidence: HitEvidence | None
    ) -> tuple[ManualReview, ...]:
        if evidence is None:
            return ()
        touched = {trigger.event_id for trigger in evidence.trigger_events}
        touched.update(
            review.reviewed_event_id for review in evidence.manual_reviews
        )
        result = [
            review
            for event_id in touched
            for review in self._reviews_by_event.get(event_id, ())
        ]
        result.sort(
            key=lambda review: (
                review.reviewed_at,
                review.reviewed_event_id,
                review.action.value,
            )
        )
        return tuple(result)

    def _candidates(self) -> dict[str, HitEvidence]:
        """Evaluate all current rules over active (non-revoked, non-excluded) events."""
        active_events = self._active_events()
        seal_before = self._latest_seen_at - self.sealing_grace_seconds
        candidates: dict[str, HitEvidence] = {}
        for rule in self.rules:
            for hit_id, evidence in rule.evaluate(active_events).items():
                key = evidence.line_key
                previous = self.latest_for_line(key)
                reviews = self._reviews_for_candidate(evidence, previous)
                evidence = replace(evidence, manual_reviews=reviews)
                if evidence.window_end < seal_before:
                    evidence = evidence.sealed()
                candidates[key] = evidence
        return candidates

    def _reviews_for_candidate(
        self,
        candidate: HitEvidence,
        previous: HitEvidence | None,
    ) -> tuple[ManualReview, ...]:
        touched = {trigger.event_id for trigger in candidate.trigger_events}
        if previous is not None:
            touched.update(
                review.reviewed_event_id
                for review in previous.manual_reviews
            )
        result = [
            review
            for event_id in touched
            for review in self._reviews_by_event.get(event_id, ())
        ]
        result.sort(
            key=lambda review: (
                review.reviewed_at,
                review.reviewed_event_id,
                review.action.value,
            )
        )
        return tuple(result)

    def _recompute(self, cause: ChangeCause) -> list[RuleDecision]:
        candidates = self._candidates()
        decisions: list[RuleDecision] = []
        all_keys = set(self._lines) | set(candidates)

        for key in all_keys:
            previous = self.latest_for_line(key)
            candidate = candidates.get(key)

            if previous is None and candidate is not None:
                decisions.append(self._append(key, candidate, None, cause))
                continue

            assert previous is not None  # candidate lines handled above

            if candidate is None:
                if previous.status == DecisionStatus.REVOKED:
                    continue
                # The hit no longer holds. Open hits are revoked in place;
                # sealed conclusions stay immutable and the new judgement
                # (also revoked) is appended as a separate revision.
                derived = self._derived_revocation(previous, cause)
                # original conclusion is always retained, even while the
                # window is still open; the revocation is a new revision
                decision = self._append(key, derived, previous, cause)
                decisions.append(decision)
                continue

            change = self._classify_change(previous, candidate, cause)
            if change is None:
                continue
            next_status, next_cause, append_as_revision = change
            candidate = replace(
                candidate,
                status=next_status,
                change_cause=next_cause,
            )
            if append_as_revision:
                decisions.append(self._append(key, candidate, previous, next_cause))
            else:
                decisions.append(self._update_current(key, candidate, previous, next_cause))

        return decisions

    def _classify_change(
        self,
        previous: HitEvidence,
        candidate: HitEvidence,
        cause: ChangeCause,
    ) -> tuple[DecisionStatus, ChangeCause, bool] | None:
        rule_changed = candidate.rule != previous.rule
        content_changed = self._content_changed(previous, candidate)
        reviews_changed = candidate.manual_reviews != previous.manual_reviews
        now_sealed = (
            candidate.status == DecisionStatus.SEALED
            and previous.status != DecisionStatus.SEALED
        )

        if now_sealed:
            return DecisionStatus.SEALED, ChangeCause.SEAL, False

        if previous.status == DecisionStatus.SEALED:
            # Never mutate a sealed snapshot: any later judgement creates a
            # new revision, even if only the rule version differs.
            if rule_changed or content_changed or reviews_changed:
                status = (
                    DecisionStatus.SEALED
                    if candidate.status == DecisionStatus.SEALED
                    else candidate.status
                )
                return status, cause, True
            return None

        if rule_changed:
            return candidate.status, ChangeCause.RULE, True
        if cause == ChangeCause.MANUAL and (content_changed or reviews_changed):
            # Analyst action always keeps the prior conclusion: the new
            # judgement is a separate revision, even inside an open window.
            return candidate.status, ChangeCause.MANUAL, True
        if content_changed:
            status = (
                DecisionStatus.UPDATED
                if candidate.status == DecisionStatus.OPEN
                else candidate.status
            )
            return status, ChangeCause.EVIDENCE, False
        return None

    def _append(
        self,
        key: str,
        evidence: HitEvidence,
        previous: HitEvidence | None,
        cause: ChangeCause,
    ) -> RuleDecision:
        revision_number = 1 if previous is None else previous.revision + 1
        evidence = replace(
            evidence,
            revision=revision_number,
            supersedes_revision=None if previous is None else previous.revision,
            change_cause=cause,
        )
        self._lines.setdefault(key, []).append(evidence)
        return RuleDecision(
            evidence=evidence,
            previous_status=None if previous is None else previous.status,
            change_cause=cause,
        )

    def _update_current(
        self,
        key: str,
        evidence: HitEvidence,
        previous: HitEvidence,
        cause: ChangeCause,
    ) -> RuleDecision:
        evidence = replace(
            evidence,
            revision=previous.revision,
            supersedes_revision=previous.supersedes_revision,
            change_cause=cause,
        )
        self._lines[key][-1] = evidence
        return RuleDecision(
            evidence=evidence,
            previous_status=previous.status,
            change_cause=cause,
        )

    def _derived_revocation(
        self, previous: HitEvidence, cause: ChangeCause
    ) -> HitEvidence:
        # When a rule revision removes the hit, the new revision still belongs
        # to the revised rule so the change is attributed to RULE rather than
        # being mistaken for the historical snapshot.
        rule = previous.rule
        if cause == ChangeCause.RULE:
            revised = next(
                (
                    candidate.version_info
                    for candidate in self.rules
                    if candidate.rule_id() == previous.rule.rule_id
                ),
                previous.rule,
            )
            rule = revised
        evidence = replace(
            previous,
            rule=rule,
            status=DecisionStatus.REVOKED,
            trigger_events=previous.trigger_events,
        )
        reviews = self._reviews_for(previous)
        if reviews:
            evidence = replace(evidence, manual_reviews=reviews)
        return evidence

    @staticmethod
    def _content_changed(
        previous: HitEvidence, current: HitEvidence
    ) -> bool:
        compared_fields = (
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
