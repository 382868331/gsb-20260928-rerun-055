from __future__ import annotations

from antifraud.engine import RuleEngine
from antifraud.rules import CrossIdentityFlowRule
from antifraud.events import (
    IdentityAssociation,
    Transaction,
    association_event,
    revocation_event,
    transaction_event,
)
from antifraud.models import EventSource, JudgmentKind
from antifraud.scoring import HeuristicModel


SOURCE = EventSource(system="fictitious-lab", producer="demo")


def main() -> None:
    engine = RuleEngine(
        rules=[],
        sealing_grace_seconds=0,
    )
    engine.rules.append(
        CrossIdentityFlowRule(
            window_seconds=300,
            min_identities=3,
            min_total_amount=900,
        )
    )
    model = HeuristicModel()
    events = [
        association_event(
            IdentityAssociation("link-ab", "A", "B", 0), source=SOURCE
        ),
        association_event(
            IdentityAssociation("link-bc", "B", "C", 10), source=SOURCE
        ),
        transaction_event(
            Transaction("t1", "A", "B", 500),
            occurred_at=100,
            source=SOURCE,
        ),
        transaction_event(
            Transaction("t2", "B", "C", 500),
            occurred_at=200,
            source=SOURCE,
        ),
    ]
    for decision in engine.ingest_many(events):
        scored = model.apply(decision.evidence)
        print(decision.evidence.status.value, scored.hit_id, scored.model_score)

    manual_decisions = engine.exclude_evidence(
        "evt-t1",
        "transaction disputed by analyst",
        operator="analyst-demo",
        decided_at=250,
    )
    for decision in manual_decisions:
        print("manual", decision.cause.value, decision.evidence.status.value)

    restored_decisions = engine.withdraw_evidence_judgment(
        "evt-t1",
        withdrawn_at=260,
        reason="evidence verified",
    )
    for decision in restored_decisions:
        print("restored", decision.cause.value, decision.evidence.status.value)

    engine.exclude_evidence(
        "evt-t1",
        "false positive review",
        operator="analyst-demo",
        decided_at=270,
        kind=JudgmentKind.FALSE_POSITIVE,
        judgment_id="j-fp",
    )
    engine.exclude_evidence(
        "evt-t1",
        "rule exception granted",
        operator="analyst-demo-2",
        decided_at=271,
        kind=JudgmentKind.RULE_EXCEPTION,
        judgment_id="j-ex",
    )
    engine.withdraw_evidence_judgment(
        "j-fp", withdrawn_at=280, reason="review overturned"
    )
    print(
        "active hits after partial withdrawal:",
        len(engine.active_hits()),
    )
    for hit in engine.all_hits():
        explanation = engine.explain_hit(hit.hit_id)
        assert explanation is not None
        print(
            "explain",
            explanation["hit_id"],
            explanation["rule"],
            [
                judgment.effective_id
                for judgment in explanation["active_manual_judgments"]
            ],
        )

    engine.replace_rule(
        "cross_identity_flow",
        CrossIdentityFlowRule(
            version="v2",
            window_seconds=300,
            min_identities=3,
            min_total_amount=1200,
        ),
    )
    print("revision causes:", [
        revision["cause"].value for revision in engine.hit_history()
    ])
    print("raw events retained:", len(engine.raw_events()))
    print("active hits:", len(engine.active_hits()))
    print(
        "manual judgments:",
        [
            (judgment.event_id, judgment.withdrawn_at)
            for judgment in engine.manual_judgments()
        ],
    )

    engine.ingest(
        revocation_event(
            "evt-t1",
            occurred_at=250,
            source=SOURCE,
            event_id="revoke-t1",
        )
    )
    print("active hits after revocation:", len(engine.active_hits()))


if __name__ == "__main__":
    main()
