from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Mapping

from .engine import RuleEngine
from .models import HitEvidence, ManualEvidenceJudgment


class CaseStatus(str, Enum):
    OPEN = "open"
    SEALED = "sealed"
    MERGED = "merged"


class AttributionKind(str, Enum):
    SHARE = "share"
    TRANSFER = "transfer"
    MERGE = "merge"


@dataclass(frozen=True, slots=True)
class ShareAllocation:
    case_id: str
    claimed_amount: float
    confirmed_amount: float
    disputed_amount: float
    decision_id: str


@dataclass(frozen=True, slots=True)
class TransactionAttributionLine:
    event_id: str
    transaction_id: str
    original_amount: float
    allocations: tuple[ShareAllocation, ...]
    unattributed_amount: float

    @property
    def confirmed_total(self) -> float:
        return round(
            sum(item.confirmed_amount for item in self.allocations), 10
        )

    @property
    def disputed_total(self) -> float:
        return round(
            sum(item.disputed_amount for item in self.allocations), 10
        )


@dataclass(frozen=True, slots=True)
class HitImpact:
    hit_id: str
    rule: str
    hit_status: str
    total_amount: float
    transaction_ids: tuple[str, ...]
    active_manual_judgment_ids: tuple[str, ...]

    @classmethod
    def from_hit(cls, hit: HitEvidence) -> "HitImpact":
        return cls(
            hit_id=hit.hit_id,
            rule=hit.rule.qualified_name,
            hit_status=hit.status.value,
            total_amount=hit.total_amount,
            transaction_ids=hit.transaction_ids,
            active_manual_judgment_ids=tuple(
                judgment.id for judgment in hit.active_manual_judgments
            ),
        )


@dataclass(frozen=True, slots=True)
class ManualJudgmentImpact:
    judgment_id: str
    event_id: str
    kind: str
    operator: str
    reason: str
    active: bool

    @classmethod
    def from_judgment(
        cls, judgment: ManualEvidenceJudgment
    ) -> "ManualJudgmentImpact":
        return cls(
            judgment_id=judgment.id,
            event_id=judgment.event_id,
            kind=judgment.kind.value,
            operator=judgment.operator,
            reason=judgment.reason,
            active=judgment.active,
        )


@dataclass(frozen=True, slots=True)
class AttributionImpact:
    kind: AttributionKind
    operator: str
    rationale: str
    lines: tuple[TransactionAttributionLine, ...]
    affected_hits: tuple[HitImpact, ...]
    affected_manual_judgments: tuple[ManualJudgmentImpact, ...]
    case_totals: Mapping[str, float] = field(default_factory=dict)

    def confirmed_total_for(self, case_id: str) -> float:
        return round(
            sum(
                allocation.confirmed_amount
                for line in self.lines
                for allocation in line.allocations
                if allocation.case_id == case_id
            ),
            10,
        )

    def disputed_total_for(self, case_id: str) -> float:
        return round(
            sum(
                allocation.disputed_amount
                for line in self.lines
                for allocation in line.allocations
                if allocation.case_id == case_id
            ),
            10,
        )


@dataclass(frozen=True, slots=True)
class AttributionEntry:
    entry_id: str
    decision_id: str
    case_id: str
    event_id: str
    amount: float
    sequence: int
    active: bool = True


@dataclass(frozen=True, slots=True)
class AttributionDecision:
    decision_id: str
    kind: AttributionKind
    operator: str
    decided_at: int
    rationale: str
    event_ids: tuple[str, ...]
    target_case_id: str
    source_case_id: str | None
    entries: tuple[AttributionEntry, ...]
    sealed_late: bool = False
    active: bool = True
    withdrawn_at: int | None = None
    withdrawal_reason: str | None = None
    impact_snapshot: AttributionImpact | None = None


@dataclass(frozen=True, slots=True)
class CaseSnapshot:
    case_id: str
    status: CaseStatus
    revision: int
    decided_at: int
    confirmed_total: float
    disputed_total: float
    lines: tuple[TransactionAttributionLine, ...]
    decision_ids: tuple[str, ...]


class CaseBook:
    """Maintain loss-share attributions of rule hits across investigation cases.

    Each original transaction can appear in several cases, but only the
    explicitly attributed share counts towards a case total. Overlapping
    claims are kept as disputed shares instead of overwriting each other.
    """

    def __init__(self, engine: RuleEngine) -> None:
        self.engine = engine
        self.cases: dict[str, CaseStatus] = {}
        self._entries: list[AttributionEntry] = []
        self._decisions: dict[str, AttributionDecision] = {}
        self._snapshots: dict[str, list[CaseSnapshot]] = {}
        self._case_decisions: dict[str, list[str]] = {}
        self._sequence = 0

    def open_case(self, case_id: str) -> str:
        if not case_id:
            raise ValueError("case_id is required")
        if case_id in self.cases:
            raise ValueError(f"case already exists: {case_id}")
        self.cases[case_id] = CaseStatus.OPEN
        self._case_decisions[case_id] = []
        self._snapshots[case_id] = []
        return case_id

    def seal_case(self, case_id: str, *, sealed_at: int) -> CaseSnapshot:
        self._require_case(case_id)
        if self.cases[case_id] != CaseStatus.OPEN:
            raise ValueError(f"case {case_id} is not open")
        self.cases[case_id] = CaseStatus.SEALED
        snapshot = self._snapshot(case_id, sealed_at)
        self._snapshots[case_id].append(snapshot)
        return snapshot

    def case_status(self, case_id: str) -> CaseStatus:
        return self.cases[case_id]

    def propose_share(
        self,
        case_id: str,
        shares: Mapping[str, float],
        *,
        operator: str,
        rationale: str,
        decided_at: int = 0,
        decision_id: str | None = None,
    ) -> AttributionImpact:
        return self._build_impact(
            kind=AttributionKind.SHARE,
            target_case_id=case_id,
            source_case_id=None,
            shares={case_id: dict(shares)},
            operator=operator,
            rationale=rationale,
        )

    def adopt_share(
        self,
        case_id: str,
        shares: Mapping[str, float],
        *,
        operator: str,
        rationale: str,
        decided_at: int,
        decision_id: str | None = None,
    ) -> AttributionImpact:
        return self._adopt(
            kind=AttributionKind.SHARE,
            target_case_id=case_id,
            source_case_id=None,
            shares={case_id: dict(shares)},
            operator=operator,
            rationale=rationale,
            decided_at=decided_at,
            decision_id=decision_id,
        )

    def propose_transfer(
        self,
        source_case_id: str,
        target_case_id: str,
        shares: Mapping[str, float],
        *,
        operator: str,
        rationale: str,
        decided_at: int = 0,
    ) -> AttributionImpact:
        return self._build_impact(
            kind=AttributionKind.TRANSFER,
            target_case_id=target_case_id,
            source_case_id=source_case_id,
            shares={
                source_case_id: {
                    event_id: -amount for event_id, amount in shares.items()
                },
                target_case_id: dict(shares),
            },
            operator=operator,
            rationale=rationale,
        )

    def adopt_transfer(
        self,
        source_case_id: str,
        target_case_id: str,
        shares: Mapping[str, float],
        *,
        operator: str,
        rationale: str,
        decided_at: int,
        decision_id: str | None = None,
    ) -> AttributionImpact:
        return self._adopt(
            kind=AttributionKind.TRANSFER,
            target_case_id=target_case_id,
            source_case_id=source_case_id,
            shares={
                source_case_id: {
                    event_id: -amount for event_id, amount in shares.items()
                },
                target_case_id: dict(shares),
            },
            operator=operator,
            rationale=rationale,
            decided_at=decided_at,
            decision_id=decision_id,
        )

    def propose_merge(
        self,
        source_case_id: str,
        target_case_id: str,
        *,
        operator: str,
        rationale: str,
    ) -> AttributionImpact:
        shares = self._shares_to_take_all(source_case_id)
        return self.propose_transfer(
            source_case_id,
            target_case_id,
            shares,
            operator=operator,
            rationale=rationale,
        )

    def adopt_merge(
        self,
        source_case_id: str,
        target_case_id: str,
        *,
        operator: str,
        rationale: str,
        decided_at: int,
        decision_id: str | None = None,
    ) -> AttributionImpact:
        shares = self._shares_to_take_all(source_case_id)
        impact = self._adopt(
            kind=AttributionKind.MERGE,
            target_case_id=target_case_id,
            source_case_id=source_case_id,
            shares={
                source_case_id: {
                    event_id: -amount for event_id, amount in shares.items()
                },
                target_case_id: dict(shares),
            },
            operator=operator,
            rationale=rationale,
            decided_at=decided_at,
            decision_id=decision_id,
        )
        self.cases[source_case_id] = CaseStatus.MERGED
        return impact

    def withdraw_decision(
        self,
        decision_id: str,
        *,
        withdrawn_at: int,
        reason: str | None = None,
    ) -> AttributionImpact:
        decision = self._decisions.get(decision_id)
        if decision is None:
            raise KeyError(decision_id)
        if not decision.active:
            raise ValueError(f"decision already withdrawn: {decision_id}")
        was_late = decision.sealed_late
        self._decisions[decision_id] = replace(
            decision,
            active=False,
            withdrawn_at=withdrawn_at,
            withdrawal_reason=reason,
        )
        withdrawn_entry_ids = {
            entry.entry_id for entry in decision.entries
        }
        self._entries = [
            replace(entry, active=False)
            if entry.entry_id in withdrawn_entry_ids
            else entry
            for entry in self._entries
        ]
        if decision.kind == AttributionKind.MERGE:
            source_case_id = decision.source_case_id
            if (
                source_case_id is not None
                and self.cases[source_case_id] == CaseStatus.MERGED
            ):
                self.cases[source_case_id] = (
                    CaseStatus.SEALED if was_late else CaseStatus.OPEN
                )
        impact = self._impact_for(
            kind=decision.kind,
            operator=decision.operator,
            rationale=reason or f"withdraw:{decision_id}",
            additional_entries=(),
            event_ids=decision.event_ids,
        )
        if was_late:
            affected_cases = {decision.target_case_id}
            if decision.source_case_id is not None:
                affected_cases.add(decision.source_case_id)
            for sealed_case_id in affected_cases:
                if self.cases[sealed_case_id] == CaseStatus.SEALED:
                    self._snapshots[sealed_case_id].append(
                        self._snapshot(sealed_case_id, withdrawn_at)
                    )
        return impact

    def decisions(self) -> list[AttributionDecision]:
        return list(self._decisions.values())

    def decision(self, decision_id: str) -> AttributionDecision | None:
        return self._decisions.get(decision_id)

    def case_explanation(
        self, case_id: str, *, revision: int | None = None
    ) -> CaseSnapshot | None:
        snapshots = self._snapshots.get(case_id, [])
        if revision is not None:
            if 1 <= revision <= len(snapshots):
                return snapshots[revision - 1]
            return None
        if snapshots:
            return snapshots[-1]
        if case_id not in self.cases:
            return None
        return self._snapshot(case_id, 0)

    def case_history(self, case_id: str) -> list[CaseSnapshot]:
        return list(self._snapshots.get(case_id, []))

    def attribution_lines(
        self, event_ids: tuple[str, ...] | None = None
    ) -> list[TransactionAttributionLine]:
        return list(self._ledger(event_ids).values())

    def case_totals(self) -> dict[str, float]:
        totals = {case_id: 0.0 for case_id in self.cases}
        for line in self._ledger(None).values():
            for allocation in line.allocations:
                totals[allocation.case_id] = round(
                    totals.get(allocation.case_id, 0.0)
                    + allocation.confirmed_amount,
                    10,
                )
        return totals

    def reconcile(self) -> list[tuple[str, float, float, float, float]]:
        """Return (event, original, confirmed, disputed, unattributed) rows."""
        rows = []
        transaction_event_ids = tuple(
            event.event_id
            for event in self.engine.raw_events()
            if hasattr(event.payload, "amount")
        )
        for line in self._ledger(transaction_event_ids).values():
            rows.append(
                (
                    line.event_id,
                    line.original_amount,
                    line.confirmed_total,
                    line.disputed_total,
                    line.unattributed_amount,
                )
            )
        return rows

    def _adopt(
        self,
        *,
        kind: AttributionKind,
        target_case_id: str,
        source_case_id: str | None,
        shares: Mapping[str, Mapping[str, float]],
        operator: str,
        rationale: str,
        decided_at: int,
        decision_id: str | None = None,
    ) -> AttributionImpact:
        if not operator:
            raise ValueError("operator is required")
        if not rationale:
            raise ValueError("rationale is required")
        self._require_case(target_case_id)
        if source_case_id is not None:
            self._require_case(source_case_id)
        flat_shares = {
            case_id: dict(entries)
            for case_id, entries in shares.items()
            if entries
        }
        self._validate_shares(flat_shares)
        self._sequence += 1
        decision_key = decision_id or f"attribution-{self._sequence}"
        if decision_key in self._decisions:
            raise ValueError(f"duplicate decision id: {decision_key}")
        sealed_late = self._touches_sealed_case(flat_shares)
        event_ids = tuple(
            sorted(
                {
                    event_id
                    for entries in flat_shares.values()
                    for event_id in entries
                }
            )
        )
        entries: list[AttributionEntry] = []
        entry_sequence = self._sequence * 1000
        for case_id in sorted(flat_shares):
            for event_id in event_ids:
                amount = flat_shares[case_id].get(event_id, 0.0)
                if amount == 0.0:
                    continue
                entry_sequence += 1
                entries.append(
                    AttributionEntry(
                        entry_id=f"{decision_key}:entry:{entry_sequence}",
                        decision_id=decision_key,
                        case_id=case_id,
                        event_id=event_id,
                        amount=round(amount, 10),
                        sequence=entry_sequence,
                    )
                )
        impact = self._impact_for(
            kind=kind,
            operator=operator,
            rationale=rationale,
            additional_entries=tuple(entries),
            event_ids=event_ids,
        )
        decision = AttributionDecision(
            decision_id=decision_key,
            kind=kind,
            operator=operator,
            decided_at=decided_at,
            rationale=rationale,
            event_ids=event_ids,
            target_case_id=target_case_id,
            source_case_id=source_case_id,
            entries=tuple(entries),
            sealed_late=sealed_late,
            impact_snapshot=impact,
        )
        self._decisions[decision_key] = decision
        self._entries.extend(entries)
        for case_id in flat_shares:
            self._case_decisions.setdefault(case_id, []).append(decision_key)
            if self.cases[case_id] == CaseStatus.SEALED:
                self._snapshots[case_id].append(
                    self._snapshot(case_id, decided_at)
                )
        return impact

    def _build_impact(
        self,
        *,
        kind: AttributionKind,
        target_case_id: str,
        source_case_id: str | None,
        shares: Mapping[str, Mapping[str, float]],
        operator: str,
        rationale: str,
    ) -> AttributionImpact:
        flat_shares = {
            case_id: dict(entries)
            for case_id, entries in shares.items()
            if entries
        }
        self._validate_shares(flat_shares)
        event_ids = tuple(
            sorted(
                {
                    event_id
                    for entries in flat_shares.values()
                    for event_id in entries
                }
            )
        )
        additional_entries = tuple(
            AttributionEntry(
                entry_id=f"preview:{case_id}:{event_id}",
                decision_id="preview",
                case_id=case_id,
                event_id=event_id,
                amount=round(amount, 10),
                sequence=10**12,
            )
            for case_id in sorted(flat_shares)
            for event_id, amount in sorted(flat_shares[case_id].items())
            if amount != 0.0
        )
        return self._impact_for(
            kind=kind,
            operator=operator,
            rationale=rationale,
            additional_entries=additional_entries,
            event_ids=event_ids,
        )

    def _impact_for(
        self,
        *,
        kind: AttributionKind,
        operator: str,
        rationale: str,
        additional_entries: tuple[AttributionEntry, ...],
        event_ids: tuple[str, ...],
    ) -> AttributionImpact:
        ledger = self._ledger(None, additional_entries=additional_entries)
        affected_event_ids = set(event_ids)
        for entry in additional_entries:
            affected_event_ids.add(entry.event_id)
        lines = tuple(
            line
            for event_id, line in sorted(ledger.items())
            if event_id in affected_event_ids
        )
        affected_case_ids = {
            allocation.case_id
            for line in lines
            for allocation in line.allocations
        }
        affected_case_ids.update(
            entry.case_id for entry in additional_entries
        )
        return AttributionImpact(
            kind=kind,
            operator=operator,
            rationale=rationale,
            lines=lines,
            affected_hits=self._hits_for(affected_event_ids),
            affected_manual_judgments=self._judgments_for(
                affected_event_ids
            ),
            case_totals={
                case_id: self._confirmed_total(case_id, ledger)
                for case_id in sorted(affected_case_ids)
            },
        )

    def _ledger(
        self,
        event_ids: tuple[str, ...] | None,
        *,
        additional_entries: tuple[AttributionEntry, ...] = (),
    ) -> dict[str, TransactionAttributionLine]:
        entries = [
            entry
            for entry in (*self._entries, *additional_entries)
            if entry.active
        ]
        wanted = set(event_ids) if event_ids is not None else None
        claims_by_event: dict[str, list[AttributionEntry]] = {}
        for entry in entries:
            if wanted is not None and entry.event_id not in wanted:
                continue
            claims_by_event.setdefault(entry.event_id, []).append(entry)
        lines: dict[str, TransactionAttributionLine] = {}
        event_ids_to_build = set(claims_by_event)
        if wanted is not None:
            event_ids_to_build.update(
                event_id
                for event_id in wanted
                if event_id in self.engine.raw_events_map
                and hasattr(
                    self.engine.raw_events_map[event_id].payload, "amount"
                )
            )
        for event_id in sorted(event_ids_to_build):
            claims = claims_by_event.get(event_id, [])
            amount_by_case: dict[str, float] = {}
            first_sequence: dict[str, int] = {}
            decision_by_case: dict[str, str] = {}
            for claim in claims:
                amount_by_case[claim.case_id] = round(
                    amount_by_case.get(claim.case_id, 0.0) + claim.amount,
                    10,
                )
                if (
                    claim.case_id not in first_sequence
                    or claim.sequence < first_sequence[claim.case_id]
                ):
                    first_sequence[claim.case_id] = claim.sequence
                    decision_by_case[claim.case_id] = claim.decision_id
            original_amount = self._transaction_amount(event_id)
            allocations: list[ShareAllocation] = []
            remaining = original_amount
            ordered_cases = sorted(
                amount_by_case,
                key=lambda case_id: (
                    first_sequence[case_id],
                    case_id,
                ),
            )
            for case_id in ordered_cases:
                claimed = max(0.0, amount_by_case[case_id])
                confirmed = min(claimed, max(0.0, remaining))
                disputed = round(claimed - confirmed, 10)
                remaining = round(remaining - confirmed, 10)
                allocations.append(
                    ShareAllocation(
                        case_id=case_id,
                        claimed_amount=round(claimed, 10),
                        confirmed_amount=round(confirmed, 10),
                        disputed_amount=round(disputed, 10),
                        decision_id=decision_by_case[case_id],
                    )
                )
            lines[event_id] = TransactionAttributionLine(
                event_id=event_id,
                transaction_id=self._transaction_id(event_id),
                original_amount=original_amount,
                allocations=tuple(allocations),
                unattributed_amount=round(max(0.0, remaining), 10),
            )
        return lines

    def _hits_for(
        self, event_ids: set[str]
    ) -> tuple[HitImpact, ...]:
        impacts = []
        for hit in self.engine.all_hits():
            hit_event_ids = {
                event.event_id for event in hit.trigger_events
            } | {event.event_id for event in hit.original_trigger_events}
            if hit_event_ids.intersection(event_ids):
                impacts.append(HitImpact.from_hit(hit))
        return tuple(
            sorted(impacts, key=lambda impact: (impact.hit_id,))
        )

    def _judgments_for(
        self, event_ids: set[str]
    ) -> tuple[ManualJudgmentImpact, ...]:
        return tuple(
            ManualJudgmentImpact.from_judgment(judgment)
            for judgment in self.engine.manual_judgments()
            if judgment.event_id in event_ids
        )

    def _transaction_amount(self, event_id: str) -> float:
        event = self.engine.raw_events_map.get(event_id)
        if event is None or not hasattr(event.payload, "amount"):
            raise KeyError(f"unknown transaction event: {event_id}")
        return round(float(event.payload.amount), 10)

    def _transaction_id(self, event_id: str) -> str:
        event = self.engine.raw_events_map.get(event_id)
        if event is not None and hasattr(event.payload, "transaction_id"):
            return str(event.payload.transaction_id)
        return event_id

    def _validate_shares(
        self, shares: Mapping[str, Mapping[str, float]]
    ) -> None:
        for case_id, entries in shares.items():
            self._require_case(case_id)
            for event_id, amount in entries.items():
                if amount == 0.0:
                    continue
                self._transaction_amount(event_id)
        if not shares:
            return
        projected: dict[tuple[str, str], float] = {}
        for entry in self._entries:
            if entry.active:
                projected[(entry.case_id, entry.event_id)] = round(
                    projected.get((entry.case_id, entry.event_id), 0.0)
                    + entry.amount,
                    10,
                )
        for case_id, entries in shares.items():
            for event_id, amount in entries.items():
                total = projected.get((case_id, event_id), 0.0) + amount
                if total < -1e-9:
                    raise ValueError(
                        f"case {case_id} cannot give up {amount} from {event_id}: "
                        f"only {projected.get((case_id, event_id), 0.0)} claimed"
                    )

    def _touches_sealed_case(
        self, shares: Mapping[str, Mapping[str, float]]
    ) -> bool:
        return any(
            self.cases[case_id] == CaseStatus.SEALED
            for case_id in shares
        )

    def _shares_to_take_all(
        self, source_case_id: str
    ) -> dict[str, float]:
        shares: dict[str, float] = {}
        for entry in self._entries:
            if entry.active and entry.case_id == source_case_id:
                shares[entry.event_id] = round(
                    shares.get(entry.event_id, 0.0) + entry.amount,
                    10,
                )
        return {event_id: amount for event_id, amount in shares.items() if amount}

    def _confirmed_total(
        self,
        case_id: str,
        ledger: Mapping[str, TransactionAttributionLine],
    ) -> float:
        return round(
            sum(
                allocation.confirmed_amount
                for line in ledger.values()
                for allocation in line.allocations
                if allocation.case_id == case_id
            ),
            10,
        )

    def _snapshot(self, case_id: str, decided_at: int) -> CaseSnapshot:
        ledger = self._ledger(None)
        lines = tuple(
            line
            for line in sorted(ledger.values(), key=lambda item: item.event_id)
            if any(
                allocation.case_id == case_id
                for allocation in line.allocations
            )
        )
        confirmed = round(
            sum(
                allocation.confirmed_amount
                for line in lines
                for allocation in line.allocations
                if allocation.case_id == case_id
            ),
            10,
        )
        disputed = round(
            sum(
                allocation.disputed_amount
                for line in lines
                for allocation in line.allocations
                if allocation.case_id == case_id
            ),
            10,
        )
        decision_ids = tuple(self._case_decisions.get(case_id, []))
        revision = len(self._snapshots.get(case_id, [])) + 1
        return CaseSnapshot(
            case_id=case_id,
            status=self.cases[case_id],
            revision=revision,
            decided_at=decided_at,
            confirmed_total=confirmed,
            disputed_total=disputed,
            lines=lines,
            decision_ids=decision_ids,
        )

    def _require_case(self, case_id: str) -> None:
        if case_id not in self.cases:
            raise KeyError(f"unknown case: {case_id}")
