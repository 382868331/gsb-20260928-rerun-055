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
from antifraud.models import EventSource
from antifraud.scoring import HeuristicModel
from antifraud.cases import CaseBook


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
        association_event(
            IdentityAssociation("link-ca", "C", "A", 20), source=SOURCE
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
        transaction_event(
            Transaction("t3", "C", "A", 500),
            occurred_at=210,
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

    engine.grant_rule_exception(
        "evt-t2",
        "accepted merchant exception",
        operator="analyst-demo",
        decided_at=270,
        judgment_id="demo-exception-t2",
    )
    active_hit = engine.active_hits()[0] if engine.active_hits() else None
    if active_hit is None:
        raise RuntimeError("demo expected an active overlapping hit")
    explanation = engine.explain_hit(active_hit.hit_id)
    print("rule:", explanation.rule.qualified_name)
    print("raw amount:", explanation.hit.original_total_amount)
    print("effective amount:", explanation.hit.total_amount)
    print(
        "active judgments:",
        [judgment.id for judgment in explanation.active_manual_judgments],
    )
    engine.withdraw_manual_judgment(
        "demo-exception-t2",
        withdrawn_at=280,
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

    book = CaseBook(engine)
    book.open_case("case-alpha")
    book.open_case("case-beta")
    preview = book.propose_share(
        "case-alpha",
        {"evt-t2": 500.0},
        operator="analyst-demo",
        rationale="alpha claims t2",
    )
    print(
        "preview affected rules:",
        sorted({hit.rule for hit in preview.affected_hits}),
    )
    book.adopt_share(
        "case-alpha",
        {"evt-t2": 500.0},
        operator="analyst-demo",
        rationale="alpha claims t2",
        decided_at=300,
        decision_id="alpha-t2",
    )
    book.adopt_share(
        "case-beta",
        {"evt-t3": 300.0},
        operator="analyst-demo",
        rationale="beta claims part of t3",
        decided_at=310,
        decision_id="beta-t3",
    )
    sealed = book.seal_case("case-alpha", sealed_at=400)
    print("sealed alpha total:", sealed.confirmed_total)
    book.adopt_share(
        "case-alpha",
        {"evt-t3": 100.0},
        operator="late-analyst",
        rationale="late evidence for alpha",
        decided_at=500,
        decision_id="alpha-late",
    )
    print(
        "alpha revisions:",
        [snapshot.revision for snapshot in book.case_history("case-alpha")],
    )
    print("case totals:", book.case_totals())
    print("reconciliation:", book.reconcile())


if __name__ == "__main__":
    main()
