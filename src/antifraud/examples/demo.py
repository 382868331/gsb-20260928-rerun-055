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
