from __future__ import annotations

from antifraud.engine import RuleEngine
from antifraud.rules import CrossIdentityFlowRule
from antifraud.events import (
    IdentityAssociation,
    Transaction,
    association_event,
    transaction_event,
)
from antifraud.models import EventSource
from antifraud.reviews import exclude_request, withdraw_request
from antifraud.scoring import HeuristicModel


SOURCE = EventSource(system="fictitious-lab", producer="demo")


def _summarise(label: str, engine: RuleEngine) -> None:
    print(f"-- {label}")
    for hit in engine.all_revisions():
        print(
            f"   rev={hit.revision} {hit.status.value:7} "
            f"{hit.rule.qualified_name} {hit.identities} "
            f"amount={hit.total_amount} cause={hit.change_cause.value}"
        )


def main() -> None:
    rule_v1 = CrossIdentityFlowRule(
        window_seconds=300,
        min_identities=3,
        min_total_amount=900,
    )
    engine = RuleEngine(rules=[rule_v1])
    model = HeuristicModel()

    engine.ingest_many(
        [
            association_event(
                IdentityAssociation("link-ab", "A", "B", 0),
                source=SOURCE,
            ),
            association_event(
                IdentityAssociation("link-bc", "B", "C", 0),
                source=SOURCE,
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
    )
    for decision in engine.active_hits():
        model.apply(decision)
    _summarise("initial hit", engine)

    # analyst rejects one association: hit is recomputed, original event stays
    engine.review_evidence(
        exclude_request(
            "evt-link-ab",
            reviewer="analyst-7",
            reason="identity link was a data merge error",
            reviewed_at=240,
        )
    )
    _summarise("after manual exclusion", engine)

    # analyst withdraws the judgement: original computation is restored
    engine.review_evidence(
        withdraw_request(
            "evt-link-ab",
            reviewer="lead-3",
            reason="merge error allegation rejected",
            reviewed_at=260,
        )
    )
    _summarise("after review withdrawal", engine)

    # seal the window, then tighten the rule: history is re-versioned
    engine.ingest(
        transaction_event(
            Transaction("seal", "X", "Y", 1),
            occurred_at=301,
            source=SOURCE,
        )
    )
    engine.revise_rule(
        CrossIdentityFlowRule(
            window_seconds=300,
            min_identities=3,
            min_total_amount=1500,
            rule_id="cross_identity_flow",
            version="v2",
        ),
        revised_at=320,
    )
    _summarise("after rule revision over sealed history", engine)


if __name__ == "__main__":
    main()
