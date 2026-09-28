from datetime import datetime, timedelta, timezone

from fraud_rules import (
    CrossIdentityFlowRule,
    DecisionEngine,
    EventSource,
    IdentityAssociation,
    ModelScore,
    TemporalRuleEngine,
    Transaction,
    TransactionRetraction,
)


UTC = timezone.utc
ZERO = datetime(2026, 1, 1, 12, tzinfo=UTC)
GRACE = timedelta(minutes=5)


def source(event_id: str) -> EventSource:
    return EventSource(
        system="fictional-payment-lab",
        record_id=event_id,
        topic="fictional.transactions.v1",
    )


def tx(event_id: str, minute: int, sender: str, recipient: str) -> Transaction:
    return Transaction(
        event_id=event_id,
        source=source(event_id),
        occurred_at=ZERO + timedelta(minutes=minute),
        transaction_id=f"tx-{event_id}",
        sender_id=sender,
        recipient_id=recipient,
        amount_cents=1000,
    )


def association(event_id: str, minute: int, left: str, right: str) -> IdentityAssociation:
    return IdentityAssociation(
        event_id=event_id,
        source=EventSource("fictional-identity-lab", event_id, "fictional.identity.v1"),
        occurred_at=ZERO + timedelta(minutes=minute),
        left_identity_id=left,
        right_identity_id=right,
        association_type="shared_synthetic_device",
    )


def retraction(event_id: str, minute: int, transaction_id: str) -> TransactionRetraction:
    return TransactionRetraction(
        event_id=event_id,
        source=source(event_id),
        occurred_at=ZERO + timedelta(minutes=minute),
        transaction_id=transaction_id,
        reason="fictional lab correction",
    )


def test_out_of_order_association_corrects_open_result():
    engine = TemporalRuleEngine(
        CrossIdentityFlowRule(timedelta(hours=1), 2, GRACE), GRACE
    )

    first = engine.process_event(tx("t1", 0, "A", "B"))
    assert first.open_findings == []

    second = engine.process_event(tx("t2", 10, "A", "C"))
    assert second.open_findings == []

    corrected = engine.process_event(association("a1", -5, "A", "B"))
    corrected = engine.process_event(association("a2", -4, "A", "C"))

    assert len(corrected.open_findings) == 1
    finding = corrected.open_findings[0]
    assert [item.event_id for item in finding.evidence.transactions] == ["t1", "t2"]
    assert {item.event_id for item in finding.evidence.associations} == {"a1", "a2"}
    assert finding.rule.version == "1.0.0"


def test_retraction_removes_dependent_open_finding():
    engine = TemporalRuleEngine(
        CrossIdentityFlowRule(timedelta(hours=1), 2, GRACE), GRACE
    )

    for event in (
        association("a1", -1, "A", "B"),
        association("a2", -1, "A", "C"),
        tx("t1", 0, "A", "B"),
        tx("t2", 10, "A", "C"),
    ):
        result = engine.process_event(event)

    assert len(result.open_findings) == 1

    corrected = engine.process_event(retraction("r1", 12, "tx-t1"))

    assert corrected.open_findings == []
    assert corrected.retracted_finding_ids == [result.open_findings[0].finding_id]


def test_similar_but_unlinked_normal_behavior_does_not_hit():
    engine = TemporalRuleEngine(
        CrossIdentityFlowRule(timedelta(hours=1), 2, GRACE), GRACE
    )

    events = [
        association("a1", -1, "B", "C"),
        tx("t1", 0, "A", "B"),
        tx("t2", 10, "A", "C"),
    ]
    for event in events:
        result = engine.process_event(event)
    result = engine.advance_watermark(ZERO + timedelta(minutes=30))

    assert result.open_findings == []
    assert result.sealed_findings == []


def test_window_is_sealed_and_late_events_cannot_change_it():
    engine = TemporalRuleEngine(
        CrossIdentityFlowRule(timedelta(hours=1), 2, GRACE), GRACE
    )

    for event in (
        association("a1", -1, "A", "B"),
        association("a2", -1, "A", "C"),
        tx("t1", 0, "A", "B"),
        tx("t2", 10, "A", "C"),
    ):
        engine.process_event(event)

    sealed = engine.advance_watermark(ZERO + timedelta(minutes=65, seconds=1))
    assert len(sealed.sealed_findings) == 1

    late = engine.process_event(retraction("r-late", 12, "tx-t1"))
    assert late.rejected_events[0].reason.endswith("was sealed")
    assert len(engine.sealed_findings) == 1


def test_model_score_joins_without_hiding_rule_evidence():
    finding = CrossIdentityFlowRule(timedelta(hours=1), 2).evaluate(
        [tx("t1", 0, "A", "B"), tx("t2", 10, "A", "C")],
        [association("a1", -1, "A", "B"), association("a2", -1, "A", "C")],
        ZERO + timedelta(minutes=20),
        ZERO - timedelta(days=1),
    )[0]

    decisions = DecisionEngine().decide(
        [finding],
        [
            ModelScore(
                finding_id=finding.finding_id,
                model_name="fictional-graph-scorer",
                model_version="0.1.0",
                score=0.72,
                features={"linked_counterparties": 2},
            ),
        ],
    )

    assert decisions[0].model_score.score == 0.72
    assert len(decisions[0].finding.evidence.transactions) == 2


def test_repeated_transactions_with_same_counterparty_do_not_count_as_multiple_identities():
    finding = CrossIdentityFlowRule(timedelta(hours=1), 2).evaluate(
        [
            tx("t1", 0, "A", "B"),
            tx("t2", 5, "A", "B"),
        ],
        [association("a1", -1, "A", "B")],
        ZERO + timedelta(minutes=20),
        ZERO - timedelta(days=1),
    )

    assert finding == []
