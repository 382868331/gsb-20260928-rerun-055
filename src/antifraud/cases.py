from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping

from .engine import RuleEngine
from .models import ChangeCause, DecisionStatus


class CaseStatus(str, Enum):
    OPEN = "open"
    SEALED = "sealed"
    REVISED = "revised"
    MERGED = "merged"


class ShareState(str, Enum):
    CONFIRMED = "confirmed"
    DISPUTED = "disputed"


class ProposalKind(str, Enum):
    ALLOCATE = "allocate"
    MERGE_CASES = "merge_cases"
    MOVE_SHARE = "move_share"


class ProposalStatus(str, Enum):
    PENDING = "pending"
    ADOPTED = "adopted"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class TransactionRecord:
    transaction_id: str
    amount: float
    occurred_at: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AttributionDecision:
    decision_id: str
    case_id: str
    transaction_id: str
    amount: float
    operator: str
    decided_at: int
    reason: str
    sequence: int
    offset: float = 0.0
    proposal_id: str | None = None
    withdrawn_at: int | None = None
    withdrawal_reason: str | None = None

    @property
    def active(self) -> bool:
        return self.withdrawn_at is None

    def withdrawn(
        self, timestamp: int, reason: str | None = None
    ) -> "AttributionDecision":
        return replace(
            self,
            withdrawn_at=timestamp,
            withdrawal_reason=reason,
        )


@dataclass(frozen=True, slots=True)
class ShareView:
    case_id: str
    transaction_id: str
    decision_id: str
    state: ShareState
    amount: float


@dataclass(frozen=True, slots=True)
class CaseView:
    case_id: str
    status: CaseStatus
    confirmed_total: float
    disputed_total: float
    shares: tuple[ShareView, ...]

    @property
    def transaction_ids(self) -> tuple[str, ...]:
        return tuple(sorted({share.transaction_id for share in self.shares}))


@dataclass(frozen=True, slots=True)
class TransactionReconciliation:
    transaction_id: str
    original_amount: float
    confirmed_total: float
    disputed_total: float
    unallocated: float
    shares: tuple[ShareView, ...]

    @property
    def reconciles(self) -> bool:
        return abs(
            self.confirmed_total
            + self.disputed_total
            + self.unallocated
            - self.original_amount
        ) < 1e-9


@dataclass(frozen=True, slots=True)
class AffectedRuleHit:
    hit_id: str
    rule: str
    status: DecisionStatus


@dataclass(frozen=True, slots=True)
class AffectedManualJudgment:
    judgment_id: str
    event_id: str
    kind: str
    active: bool


@dataclass(frozen=True, slots=True)
class ProposalPreview:
    affected_transaction_ids: tuple[str, ...]
    affected_case_ids: tuple[str, ...]
    before: tuple[TransactionReconciliation, ...]
    after: tuple[TransactionReconciliation, ...]
    case_totals_before: Mapping[str, float]
    case_totals_after: Mapping[str, float]
    rule_hits: tuple[AffectedRuleHit, ...]
    manual_judgments: tuple[AffectedManualJudgment, ...]


@dataclass(frozen=True, slots=True)
class CaseProposal:
    proposal_id: str
    kind: ProposalKind
    operator: str
    proposed_at: int
    reason: str
    payload: Mapping[str, Any]
    preview: ProposalPreview
    status: ProposalStatus = ProposalStatus.PENDING
    resolved_at: int | None = None


@dataclass(frozen=True, slots=True)
class CaseRevision:
    revision_id: str
    case_id: str
    cause: ChangeCause
    changed_at: int
    view: CaseView
    actor: str | None = None
    reason: str | None = None


class CaseLedger:
    """Track per-case loss attributions over shared transactions.

    Only explicitly attributed, uncontested shares count toward a case
    total. Overlapping claims on the same transaction surface as disputed
    shares and are never counted in more than one case.
    """

    def __init__(self, engine: RuleEngine | None = None) -> None:
        self.engine = engine
        self._cases: dict[str, CaseStatus] = {}
        self._transactions: dict[str, TransactionRecord] = {}
        self._decisions: dict[str, AttributionDecision] = {}
        self._decision_sequence = 0
        self._proposals: dict[str, CaseProposal] = {}
        self._proposal_sequence = 0
        self._revision_sequence = 0
        self._revisions: list[CaseRevision] = []
        self._sealed_snapshots: dict[str, CaseView] = {}

    # -- registration -------------------------------------------------

    def register_case(self, case_id: str) -> None:
        if not case_id:
            raise ValueError("case_id is required")
        if case_id in self._cases:
            raise ValueError(f"duplicate case id: {case_id}")
        self._cases[case_id] = CaseStatus.OPEN

    def register_transaction(
        self,
        transaction_id: str,
        amount: float,
        *,
        occurred_at: int = 0,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        if amount < 0:
            raise ValueError("amount cannot be negative")
        existing = self._transactions.get(transaction_id)
        record = TransactionRecord(
            transaction_id=transaction_id,
            amount=amount,
            occurred_at=occurred_at,
            metadata=dict(metadata or {}),
        )
        self._transactions[transaction_id] = record
        if existing is not None and existing.amount != amount:
            # Late evidence correcting a transaction already attributed.
            for case_id in self._cases_touching_transaction(transaction_id):
                self._record_revision(
                    case_id,
                    cause=ChangeCause.EVIDENCE,
                    changed_at=occurred_at,
                    reason=f"late evidence updated {transaction_id}",
                )

    def register_transactions_from_engine(self) -> None:
        if self.engine is None:
            raise ValueError("engine is required")
        for event in self.engine.raw_events():
            if event.event_type != "fictitious_transaction":
                continue
            payload = event.payload_dict()
            self.register_transaction(
                payload["transaction_id"],
                float(payload["amount"]),
                occurred_at=event.occurred_at,
                metadata={"event_id": event.event_id},
            )

    # -- proposals ----------------------------------------------------

    def propose_allocation(
        self,
        *,
        case_id: str,
        transaction_id: str,
        amount: float,
        operator: str,
        proposed_at: int,
        reason: str,
    ) -> CaseProposal:
        self._require_case(case_id)
        self._require_transaction(transaction_id)
        if amount <= 0:
            raise ValueError("amount must be positive")
        if not operator:
            raise ValueError("operator is required")
        if not reason:
            raise ValueError("reason is required")
        payload = {
            "case_id": case_id,
            "transaction_id": transaction_id,
            "amount": float(amount),
        }
        return self._make_proposal(
            ProposalKind.ALLOCATE,
            payload,
            operator=operator,
            proposed_at=proposed_at,
            reason=reason,
        )

    def propose_merge(
        self,
        *,
        source_case_id: str,
        target_case_id: str,
        operator: str,
        proposed_at: int,
        reason: str,
    ) -> CaseProposal:
        self._require_case(source_case_id)
        self._require_case(target_case_id)
        if source_case_id == target_case_id:
            raise ValueError("cannot merge a case into itself")
        payload = {
            "source_case_id": source_case_id,
            "target_case_id": target_case_id,
        }
        return self._make_proposal(
            ProposalKind.MERGE_CASES,
            payload,
            operator=operator,
            proposed_at=proposed_at,
            reason=reason,
        )

    def propose_move(
        self,
        *,
        decision_id: str,
        target_case_id: str,
        operator: str,
        proposed_at: int,
        reason: str,
        amount: float | None = None,
    ) -> CaseProposal:
        decision = self._decisions.get(decision_id)
        if decision is None or not decision.active:
            raise KeyError(decision_id)
        self._require_case(target_case_id)
        if decision.case_id == target_case_id:
            raise ValueError("decision already belongs to target case")
        move_amount = decision.amount if amount is None else float(amount)
        if move_amount <= 0 or move_amount > decision.amount:
            raise ValueError("move amount must be within the decision amount")
        payload = {
            "decision_id": decision_id,
            "target_case_id": target_case_id,
            "amount": move_amount,
        }
        return self._make_proposal(
            ProposalKind.MOVE_SHARE,
            payload,
            operator=operator,
            proposed_at=proposed_at,
            reason=reason,
        )
        return self._make_proposal(
            ProposalKind.MOVE_SHARE,
            payload,
            operator=operator,
            proposed_at=proposed_at,
            reason=reason,
        )

    def adopt_proposal(
        self, proposal_id: str, *, adopted_at: int
    ) -> CaseProposal:
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError(proposal_id)
        if proposal.status != ProposalStatus.PENDING:
            raise ValueError(f"proposal already {proposal.status.value}")
        payload = dict(proposal.payload)
        if proposal.kind == ProposalKind.ALLOCATE:
            self._add_decision(
                case_id=payload["case_id"],
                transaction_id=payload["transaction_id"],
                amount=payload["amount"],
                operator=proposal.operator,
                decided_at=adopted_at,
                reason=proposal.reason,
                proposal_id=proposal_id,
            )
            affected_cases = [payload["case_id"]]
        elif proposal.kind == ProposalKind.MERGE_CASES:
            source = payload["source_case_id"]
            target = payload["target_case_id"]
            for decision_id, decision in list(self._decisions.items()):
                if decision.case_id == source and decision.active:
                    self._decisions[decision_id] = replace(
                        decision, case_id=target
                    )
            self._cases[source] = CaseStatus.MERGED
            affected_cases = [source, target]
        else:
            decision = self._decisions[payload["decision_id"]]
            move_amount = payload["amount"]
            self._decisions[decision.decision_id] = replace(
                decision, amount=decision.amount - move_amount
            )
            self._add_decision(
                case_id=payload["target_case_id"],
                transaction_id=decision.transaction_id,
                amount=move_amount,
                operator=proposal.operator,
                decided_at=adopted_at,
                reason=proposal.reason,
                proposal_id=proposal_id,
                offset=decision.offset + decision.amount - move_amount,
            )
            affected_cases = [decision.case_id, payload["target_case_id"]]
        resolved = replace(
            proposal,
            status=ProposalStatus.ADOPTED,
            resolved_at=adopted_at,
        )
        self._proposals[proposal_id] = resolved
        for case_id in affected_cases:
            self._record_revision(
                case_id,
                cause=ChangeCause.MANUAL,
                changed_at=adopted_at,
                actor=proposal.operator,
                reason=f"adopt:{proposal_id}",
            )
        return resolved

    def reject_proposal(
        self, proposal_id: str, *, rejected_at: int
    ) -> CaseProposal:
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError(proposal_id)
        if proposal.status != ProposalStatus.PENDING:
            raise ValueError(f"proposal already {proposal.status.value}")
        resolved = replace(
            proposal,
            status=ProposalStatus.REJECTED,
            resolved_at=rejected_at,
        )
        self._proposals[proposal_id] = resolved
        return resolved

    def proposal(self, proposal_id: str) -> CaseProposal | None:
        return self._proposals.get(proposal_id)

    # -- withdrawal ---------------------------------------------------

    def withdraw_attribution(
        self,
        decision_id: str,
        *,
        withdrawn_at: int,
        reason: str | None = None,
    ) -> None:
        decision = self._decisions.get(decision_id)
        if decision is None or not decision.active:
            return
        self._decisions[decision_id] = decision.withdrawn(
            withdrawn_at, reason
        )
        self._record_revision(
            decision.case_id,
            cause=ChangeCause.MANUAL,
            changed_at=withdrawn_at,
            actor=decision.operator,
            reason=reason or f"withdraw:{decision_id}",
        )

    # -- sealing and replay --------------------------------------------

    def seal_case(self, case_id: str, *, sealed_at: int) -> CaseView:
        self._require_case(case_id)
        if self._cases[case_id] == CaseStatus.MERGED:
            raise ValueError("cannot seal a merged case")
        self._cases[case_id] = CaseStatus.SEALED
        view = self.case_view(case_id)
        self._sealed_snapshots[case_id] = view
        self._record_revision(
            case_id,
            cause=ChangeCause.SEAL,
            changed_at=sealed_at,
            reason="case sealed",
        )
        return view

    def replay_case(self, case_id: str) -> CaseView:
        """Recompute the current view from the decision log."""
        self._require_case(case_id)
        return self.case_view(case_id)

    def replay(self) -> list[TransactionReconciliation]:
        """Recompute every reconciliation; each must total the original."""
        reconciliations = [
            self.transaction_reconciliation(transaction_id)
            for transaction_id in sorted(self._transactions)
        ]
        for reconciliation in reconciliations:
            if not reconciliation.reconciles:
                raise AssertionError(
                    f"reconciliation broken for "
                    f"{reconciliation.transaction_id}"
                )
        return reconciliations

    def case_history(self, case_id: str) -> list[CaseRevision]:
        return [
            revision
            for revision in self._revisions
            if revision.case_id == case_id
        ]

    def history(self) -> list[CaseRevision]:
        return list(self._revisions)

    def sealed_snapshot(self, case_id: str) -> CaseView | None:
        return self._sealed_snapshots.get(case_id)
    def sealed_snapshot(self, case_id: str) -> CaseView | None:
        return self._sealed_snapshots.get(case_id)

    # -- views ---------------------------------------------------------

    def case_view(self, case_id: str) -> CaseView:
        self._require_case(case_id)
        shares: list[ShareView] = []
        for transaction_id in sorted(self._transactions):
            shares.extend(
                share
                for share in self._allocate_transaction(
                    transaction_id, self._decisions
                )
                if share.case_id == case_id
            )
        confirmed = sum(
            share.amount
            for share in shares
            if share.state == ShareState.CONFIRMED
        )
        disputed = sum(
            share.amount
            for share in shares
            if share.state == ShareState.DISPUTED
        )
        return CaseView(
            case_id=case_id,
            status=self._cases[case_id],
            confirmed_total=confirmed,
            disputed_total=disputed,
            shares=tuple(shares),
        )

    def transaction_reconciliation(
        self, transaction_id: str
    ) -> TransactionReconciliation:
        self._require_transaction(transaction_id)
        record = self._transactions[transaction_id]
        shares = tuple(
            self._allocate_transaction(transaction_id, self._decisions)
        )
        confirmed, disputed = self._coverage_split(
            transaction_id, self._decisions
        )
        return TransactionReconciliation(
            transaction_id=transaction_id,
            original_amount=record.amount,
            confirmed_total=confirmed,
            disputed_total=disputed,
            unallocated=record.amount - confirmed - disputed,
            shares=shares,
        )

    # -- internals -----------------------------------------------------

    def _require_case(self, case_id: str) -> None:
        if case_id not in self._cases:
            raise KeyError(case_id)

    def _require_transaction(self, transaction_id: str) -> None:
        if transaction_id not in self._transactions:
            raise KeyError(transaction_id)

    def _cases_touching_transaction(self, transaction_id: str) -> list[str]:
        return sorted(
            {
                decision.case_id
                for decision in self._decisions.values()
                if decision.transaction_id == transaction_id
                and decision.active
            }
        )

    @staticmethod
    def _active_decisions(
        transaction_id: str,
        decisions: Mapping[str, AttributionDecision],
    ) -> list[AttributionDecision]:
        active = [
            decision
            for decision in decisions.values()
            if decision.transaction_id == transaction_id
            and decision.active
            and decision.amount > 0
        ]
        active.sort(key=lambda d: (d.decided_at, d.sequence))
        return active

    def _segments(
        self,
        transaction_id: str,
        decisions: Mapping[str, AttributionDecision],
    ) -> list[tuple[float, float, AttributionDecision]]:
        # A claim covers [offset, offset + amount) of the transaction
        # loss, clipped to the original amount. Plain allocations
        # default to offset zero, so competing claims on the same
        # money overlap; moved shares carry explicit offsets and form
        # complementary slices.
        record = self._transactions[transaction_id]
        segments: list[tuple[float, float, AttributionDecision]] = []
        for decision in self._active_decisions(transaction_id, decisions):
            start = min(decision.offset, record.amount)
            end = min(start + decision.amount, record.amount)
            if end > start:
                segments.append((start, end, decision))
        return segments

    def _coverage_split(
        self,
        transaction_id: str,
        decisions: Mapping[str, AttributionDecision],
    ) -> tuple[float, float]:
        # Return (confirmed, disputed) coverage lengths.
        segments = self._segments(transaction_id, decisions)
        boundaries = sorted(
            {point for segment in segments for point in segment[:2]}
        )
        confirmed = 0.0
        disputed = 0.0
        for start, end in zip(boundaries, boundaries[1:]):
            cases = {
                decision.case_id
                for seg_start, seg_end, decision in segments
                if seg_start < end and seg_end > start
            }
            if len(cases) > 1:
                disputed += end - start
            elif cases:
                confirmed += end - start
        return confirmed, disputed

    def _allocate_transaction(
        self,
        transaction_id: str,
        decisions: Mapping[str, AttributionDecision],
    ) -> list[ShareView]:
        segments = self._segments(transaction_id, decisions)
        boundaries = sorted(
            {point for segment in segments for point in segment[:2]}
        )
        confirmed: dict[str, float] = {}
        disputed: dict[str, float] = {}
        decision_by_case: dict[str, AttributionDecision] = {}
        for start, end in zip(boundaries, boundaries[1:]):
            covering = [
                decision
                for seg_start, seg_end, decision in segments
                if seg_start < end and seg_end > start
            ]
            cases = {decision.case_id for decision in covering}
            for decision in covering:
                decision_by_case.setdefault(decision.case_id, decision)
                target = disputed if len(cases) > 1 else confirmed
                target[decision.case_id] = (
                    target.get(decision.case_id, 0.0) + (end - start)
                )
        shares: list[ShareView] = []
        for case_id in sorted(decision_by_case):
            decision = decision_by_case[case_id]
            if confirmed.get(case_id):
                shares.append(
                    ShareView(
                        case_id=case_id,
                        transaction_id=transaction_id,
                        decision_id=decision.decision_id,
                        state=ShareState.CONFIRMED,
                        amount=confirmed[case_id],
                    )
                )
            if disputed.get(case_id):
                shares.append(
                    ShareView(
                        case_id=case_id,
                        transaction_id=transaction_id,
                        decision_id=decision.decision_id,
                        state=ShareState.DISPUTED,
                        amount=disputed[case_id],
                    )
                )
        return shares

    def _add_decision(
        self,
        *,
        case_id: str,
        transaction_id: str,
        amount: float,
        operator: str,
        decided_at: int,
        reason: str,
        proposal_id: str | None,
        offset: float = 0.0,
    ) -> AttributionDecision:
        self._decision_sequence += 1
        decision = AttributionDecision(
            decision_id=f"attr-{self._decision_sequence}",
            case_id=case_id,
            transaction_id=transaction_id,
            amount=float(amount),
            operator=operator,
            decided_at=decided_at,
            reason=reason,
            sequence=self._decision_sequence,
            offset=offset,
            proposal_id=proposal_id,
        )
        self._decisions[decision.decision_id] = decision
        return decision

    def _make_proposal(
        self,
        kind: ProposalKind,
        payload: Mapping[str, Any],
        *,
        operator: str,
        proposed_at: int,
        reason: str,
    ) -> CaseProposal:
        if not operator:
            raise ValueError("operator is required")
        if not reason:
            raise ValueError("reason is required")
        self._proposal_sequence += 1
        proposal_id = f"proposal-{self._proposal_sequence}"
        preview = self._build_preview(kind, payload, proposed_at)
        proposal = CaseProposal(
            proposal_id=proposal_id,
            kind=kind,
            operator=operator,
            proposed_at=proposed_at,
            reason=reason,
            payload=dict(payload),
            preview=preview,
        )
        self._proposals[proposal_id] = proposal
        return proposal

    def _simulate(
        self, kind: ProposalKind, payload: Mapping[str, Any]
    ) -> dict[str, AttributionDecision]:
        simulated = dict(self._decisions)
        if kind == ProposalKind.ALLOCATE:
            self._decision_sequence += 1
            sequence = self._decision_sequence
            self._decision_sequence -= 1
            decision = AttributionDecision(
                decision_id="__preview__",
                case_id=payload["case_id"],
                transaction_id=payload["transaction_id"],
                amount=float(payload["amount"]),
                operator="__preview__",
                decided_at=10**18,
                reason="",
                sequence=sequence,
            )
            simulated[decision.decision_id] = decision
        elif kind == ProposalKind.MERGE_CASES:
            source = payload["source_case_id"]
            target = payload["target_case_id"]
            for decision_id, decision in list(simulated.items()):
                if decision.case_id == source and decision.active:
                    simulated[decision_id] = replace(
                        decision, case_id=target
                    )
        else:
            decision = simulated[payload["decision_id"]]
            move_amount = payload["amount"]
            simulated[decision.decision_id] = replace(
                decision, amount=decision.amount - move_amount
            )
            self._decision_sequence += 1
            sequence = self._decision_sequence
            self._decision_sequence -= 1
            moved = AttributionDecision(
                decision_id="__preview__",
                case_id=payload["target_case_id"],
                transaction_id=decision.transaction_id,
                amount=move_amount,
                operator="__preview__",
                decided_at=10**18,
                reason="",
                sequence=sequence,
                offset=decision.offset + decision.amount - move_amount,
            )
            simulated[moved.decision_id] = moved
        return simulated

    def _build_preview(
        self,
        kind: ProposalKind,
        payload: Mapping[str, Any],
        proposed_at: int,
    ) -> ProposalPreview:
        simulated = self._simulate(kind, payload)
        if kind == ProposalKind.ALLOCATE:
            transaction_ids = {payload["transaction_id"]}
            case_ids = {payload["case_id"]}
        elif kind == ProposalKind.MERGE_CASES:
            source = payload["source_case_id"]
            case_ids = {source, payload["target_case_id"]}
            transaction_ids = {
                decision.transaction_id
                for decision in self._decisions.values()
                if decision.case_id in case_ids and decision.active
            }
        else:
            decision = self._decisions[payload["decision_id"]]
            transaction_ids = {decision.transaction_id}
            case_ids = {decision.case_id, payload["target_case_id"]}

        def reconciliation_with(
            decisions: Mapping[str, AttributionDecision],
            transaction_id: str,
        ) -> TransactionReconciliation:
            record = self._transactions[transaction_id]
            shares = tuple(
                self._allocate_transaction(transaction_id, decisions)
            )
            confirmed, disputed = self._coverage_split(
                transaction_id, decisions
            )
            return TransactionReconciliation(
                transaction_id=transaction_id,
                original_amount=record.amount,
                confirmed_total=confirmed,
                disputed_total=disputed,
                unallocated=record.amount - confirmed - disputed,
                shares=shares,
            )

        def confirmed_total(
            decisions: Mapping[str, AttributionDecision], case_id: str
        ) -> float:
            total = 0.0
            for transaction_id in sorted(self._transactions):
                for share in self._allocate_transaction(
                    transaction_id, decisions
                ):
                    if (
                        share.case_id == case_id
                        and share.state == ShareState.CONFIRMED
                    ):
                        total += share.amount
            return total

        ordered_transactions = tuple(sorted(transaction_ids))
        return ProposalPreview(
            affected_transaction_ids=ordered_transactions,
            affected_case_ids=tuple(sorted(case_ids)),
            before=tuple(
                reconciliation_with(self._decisions, transaction_id)
                for transaction_id in ordered_transactions
            ),
            after=tuple(
                reconciliation_with(simulated, transaction_id)
                for transaction_id in ordered_transactions
            ),
            case_totals_before={
                case_id: confirmed_total(self._decisions, case_id)
                for case_id in sorted(case_ids)
            },
            case_totals_after={
                case_id: confirmed_total(simulated, case_id)
                for case_id in sorted(case_ids)
            },
            rule_hits=self._engine_hits(ordered_transactions),
            manual_judgments=self._engine_judgments(ordered_transactions),
        )

    def _engine_hits(
        self, transaction_ids: tuple[str, ...]
    ) -> tuple[AffectedRuleHit, ...]:
        if self.engine is None:
            return ()
        wanted = set(transaction_ids)
        hits = []
        for hit in self.engine.all_hits():
            transaction_ids_of_hit = set(
                hit.original_transaction_ids or hit.transaction_ids
            )
            if transaction_ids_of_hit & wanted:
                hits.append(
                    AffectedRuleHit(
                        hit_id=hit.hit_id,
                        rule=hit.rule.qualified_name,
                        status=hit.status,
                    )
                )
        return tuple(hits)

    def _engine_judgments(
        self, transaction_ids: tuple[str, ...]
    ) -> tuple[AffectedManualJudgment, ...]:
        if self.engine is None:
            return ()
        wanted = set(transaction_ids)
        event_ids: set[str] = set()
        for hit in self.engine.all_hits():
            transaction_ids_of_hit = set(
                hit.original_transaction_ids or hit.transaction_ids
            )
            if transaction_ids_of_hit & wanted:
                for event in hit.original_trigger_events or hit.trigger_events:
                    event_ids.add(event.event_id)
        judgments = []
        for judgment in self.engine.manual_judgments():
            if judgment.event_id in event_ids:
                judgments.append(
                    AffectedManualJudgment(
                        judgment_id=judgment.id,
                        event_id=judgment.event_id,
                        kind=judgment.kind.value,
                        active=judgment.active,
                    )
                )
        return tuple(judgments)

    def _record_revision(
        self,
        case_id: str,
        *,
        cause: ChangeCause,
        changed_at: int,
        actor: str | None = None,
        reason: str | None = None,
    ) -> None:
        if self._cases.get(case_id) == CaseStatus.SEALED:
            self._cases[case_id] = CaseStatus.REVISED
        self._revision_sequence += 1
        view = self.case_view(case_id)
        self._revisions.append(
            CaseRevision(
                revision_id=f"case-rev-{self._revision_sequence}",
                case_id=case_id,
                cause=cause,
                changed_at=changed_at,
                view=view,
                actor=actor,
                reason=reason,
            )
        )
