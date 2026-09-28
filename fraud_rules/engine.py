from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .models import IdentityAssociation, TemporalEvent, Transaction, TransactionRetraction
from .rules import CrossIdentityFlowRule, RuleFinding, TemporalRule


@dataclass(frozen=True)
class RejectedEvent:
    event_id: str
    reason: str


@dataclass
class ProcessingResult:
    watermark: datetime
    upserted_findings: list[RuleFinding] = field(default_factory=list)
    retracted_finding_ids: list[str] = field(default_factory=list)
    sealed_findings: list[RuleFinding] = field(default_factory=list)
    rejected_events: list[RejectedEvent] = field(default_factory=list)

    @property
    def open_findings(self) -> list[RuleFinding]:
        return list(self._open_findings.values())

    _open_findings: dict[str, RuleFinding] = field(default_factory=dict)


class TemporalRuleEngine:
    """Event-time rule engine with event sourcing, watermarks, and corrections."""

    def __init__(
        self,
        rule: TemporalRule | None = None,
        grace_period: timedelta = timedelta(minutes=5),
    ) -> None:
        self.rule = rule or CrossIdentityFlowRule(grace_period=grace_period)
        self.grace_period = grace_period
        self.transactions: dict[str, Transaction] = {}
        self.associations: dict[str, IdentityAssociation] = {}
        self.retractions: dict[str, TransactionRetraction] = {}
        self.open_findings: dict[str, RuleFinding] = {}
        self.sealed_findings: dict[str, RuleFinding] = {}
        self._watermark: datetime | None = None

    @property
    def watermark(self) -> datetime | None:
        return self._watermark

    def process_event(self, event: TemporalEvent) -> ProcessingResult:
        next_watermark = (
            event.occurred_at
            if self._watermark is None
            else max(self._watermark, event.occurred_at)
        )
        result = ProcessingResult(watermark=next_watermark)
        rejected = self._ingest(event)
        if rejected is not None:
            result.rejected_events.append(rejected)
            result._open_findings = dict(self.open_findings)
            return result

        self._watermark = next_watermark
        self._seal_due_findings(result)
        self._recompute_open_findings(result)
        result._open_findings = dict(self.open_findings)
        return result

    def advance_watermark(self, watermark: datetime) -> ProcessingResult:
        if watermark.tzinfo is None:
            raise ValueError("watermark must be timezone-aware")
        if self._watermark is not None and watermark < self._watermark:
            raise ValueError("watermark cannot move backwards")
        self._watermark = watermark
        result = ProcessingResult(watermark=watermark)
        self._seal_due_findings(result)
        self._recompute_open_findings(result)
        result._open_findings = dict(self.open_findings)
        return result

    def _ingest(self, event: TemporalEvent) -> RejectedEvent | None:
        seal_cutoff = self._seal_cutoff()
        if isinstance(event, Transaction):
            window = self._rule_window()
            if (
                seal_cutoff is not None
                and window is not None
                and event.occurred_at + window <= seal_cutoff
            ):
                return RejectedEvent(
                    event.event_id,
                    "transaction arrived after its event-time window was sealed",
                )
            existing = self.transactions.get(event.transaction_id)
            if existing is not None and existing.event_id != event.event_id:
                return RejectedEvent(
                    event.event_id,
                    "transaction_id is already used by another event",
                )
            self.transactions[event.transaction_id] = event
        elif isinstance(event, IdentityAssociation):
            window = self._rule_window()
            if (
                seal_cutoff is not None
                and window is not None
                and event.occurred_at + window <= seal_cutoff
            ):
                return RejectedEvent(
                    event.event_id,
                    "association arrived after its event-time window was sealed",
                )
            self.associations[event.event_id] = event
        elif isinstance(event, TransactionRetraction):
            target = self.transactions.get(event.transaction_id)
            window = self._rule_window()
            if (
                seal_cutoff is not None
                and target is not None
                and window is not None
                and target.occurred_at + window <= seal_cutoff
            ):
                return RejectedEvent(
                    event.event_id,
                    "retraction arrived after the dependent window was sealed",
                )
            self.retractions[event.transaction_id] = event
            self.transactions.pop(event.transaction_id, None)
        else:
            raise TypeError(f"unsupported event type: {type(event)!r}")
        return None

    def _recompute_open_findings(self, result: ProcessingResult) -> None:
        cutoff = self._seal_cutoff()
        active_transactions = [
            transaction
            for transaction in self.transactions.values()
            if transaction.transaction_id not in self.retractions
        ]
        current = {
            finding.finding_id: finding
            for finding in self.rule.evaluate(
                active_transactions,
                list(self.associations.values()),
                self._watermark,
                cutoff,
            )
            if finding.finding_id not in self.sealed_findings
        }
        result.retracted_finding_ids.extend(
            finding_id
            for finding_id in self.open_findings
            if finding_id not in current
        )
        result.upserted_findings.extend(
            finding
            for finding_id, finding in current.items()
            if self.open_findings.get(finding_id) != finding
        )
        self.open_findings = current

    def _seal_due_findings(self, result: ProcessingResult) -> None:
        cutoff = self._seal_cutoff()
        if cutoff is None:
            return
        due = [
            finding
            for finding in self.open_findings.values()
            if finding.window_ended_at <= cutoff
        ]
        for finding in due:
            self.sealed_findings[finding.finding_id] = finding
            self.open_findings.pop(finding.finding_id, None)
            result.sealed_findings.append(finding)

    def _seal_cutoff(self) -> datetime | None:
        if self._watermark is None:
            return None
        return self._watermark - self.grace_period

    def _rule_window(self) -> timedelta | None:
        return getattr(self.rule, "window", None)
