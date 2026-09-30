from __future__ import annotations

import unittest

from antifraud.engine import RuleEngine
from antifraud.events import (
    IdentityAssociation,
    Transaction,
    association_event,
    revocation_event,
    transaction_event,
)
from antifraud.models import (
    ChangeCause,
    DecisionStatus,
    EventSource,
    JudgmentKind,
)
from antifraud.rules import CrossIdentityFlowRule


SOURCE = EventSource(
    system="synthetic-transaction-lab",
    producer="unit-test",
)


def build_engine() -> RuleEngine:
    return RuleEngine(
        [
            CrossIdentityFlowRule(
                window_seconds=300,
                min_identities=3,
                min_total_amount=900,
            )
        ]
    )


def tx(
    transaction_id: str,
    sender: str,
    receiver: str,
    amount: float,
    timestamp: int,
):
    return transaction_event(
        Transaction(transaction_id, sender, receiver, amount),
        occurred_at=timestamp,
        source=SOURCE,
    )


def link(association_id: str, left: str, right: str, valid_from: int = 0):
    return association_event(
        IdentityAssociation(association_id, left, right, valid_from),
        source=SOURCE,
    )


class CrossIdentityFlowRuleTest(unittest.TestCase):
    def test_out_of_order_events_correct_unsealed_result(self) -> None:
        engine = build_engine()

        first_decisions = engine.ingest_many(
            [
                tx("t1", "A", "B", 500, 100),
                tx("t2", "B", "C", 500, 200),
                link("link-ab", "A", "B"),
                link("link-bc", "B", "C"),
            ]
        )

        self.assertEqual(len(first_decisions), 1)
        hit = first_decisions[0].evidence
        self.assertEqual(hit.status, DecisionStatus.OPEN)
        self.assertEqual(hit.identities, ("A", "B", "C"))
        self.assertEqual(hit.transaction_ids, ("t1", "t2"))
        self.assertEqual(hit.total_amount, 1000.0)
        self.assertEqual(
            tuple(event.event_id for event in hit.trigger_events),
            ("evt-link-ab", "evt-link-bc", "evt-t1", "evt-t2"),
        )

        update_decisions = engine.ingest(
            tx("t0", "C", "A", 100, 50)
        )
        self.assertEqual(len(update_decisions), 1)
        updated = update_decisions[0].evidence
        self.assertEqual(updated.status, DecisionStatus.UPDATED)
        self.assertEqual(
            updated.transaction_ids, ("t0", "t1", "t2")
        )
        self.assertEqual(updated.total_amount, 1100.0)

    def test_revoking_transaction_revokes_dependent_hit(self) -> None:
        engine = build_engine()
        engine.ingest_many(
            [
                link("link-ab", "A", "B"),
                link("link-bc", "B", "C"),
                tx("t1", "A", "B", 500, 100),
                tx("t2", "B", "C", 500, 200),
            ]
        )
        self.assertEqual(len(engine.active_hits()), 1)

        decisions = engine.ingest(
            revocation_event(
                "evt-t1",
                occurred_at=250,
                source=SOURCE,
                event_id="revoke-t1",
            )
        )

        self.assertEqual(len(decisions), 1)
        self.assertEqual(
            decisions[0].evidence.status, DecisionStatus.REVOKED
        )
        self.assertIn(
            "t1", decisions[0].evidence.transaction_ids
        )
        self.assertEqual(engine.active_hits(), [])
        self.assertEqual(len(engine.all_hits()), 1)

    def test_similar_normal_chain_is_not_flagged_when_amount_is_ordinary(
        self,
    ) -> None:
        engine = build_engine()

        decisions = engine.ingest_many(
            [
                link("normal-ab", "normal-A", "normal-B"),
                link("normal-bc", "normal-B", "normal-C"),
                tx(
                    "normal-t1",
                    "normal-A",
                    "normal-B",
                    12.50,
                    100,
                ),
                tx(
                    "normal-t2",
                    "normal-B",
                    "normal-C",
                    12.50,
                    200,
                ),
            ]
        )

        self.assertEqual(decisions, [])
        self.assertEqual(engine.active_hits(), [])

    def test_independent_identity_components_keep_separate_evidence(self) -> None:
        engine = build_engine()

        engine.ingest_many(
            [
                link("link-ab", "A", "B"),
                link("link-bc", "B", "C"),
                link("link-de", "D", "E"),
                link("link-ef", "E", "F"),
                tx("risk-1", "A", "B", 500, 100),
                tx("risk-2", "B", "C", 500, 200),
                tx("risk-3", "D", "E", 600, 150),
                tx("risk-4", "E", "F", 600, 250),
            ]
        )

        hits = sorted(engine.active_hits(), key=lambda hit: hit.identities)
        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0].identities, ("A", "B", "C"))
        self.assertEqual(hits[0].transaction_ids, ("risk-1", "risk-2"))
        self.assertEqual(hits[1].identities, ("D", "E", "F"))
        self.assertEqual(hits[1].transaction_ids, ("risk-3", "risk-4"))

    def test_sealed_results_are_not_modified(self) -> None:
        engine = RuleEngine(
            [
                CrossIdentityFlowRule(
                    window_seconds=60,
                    min_identities=3,
                    min_total_amount=900,
                )
            ]
        )
        engine.ingest_many(
            [
                link("link-ab", "A", "B"),
                link("link-bc", "B", "C"),
                tx("t1", "A", "B", 500, 0),
                tx("t2", "B", "C", 500, 10),
            ]
        )

        decisions = engine.ingest(
            tx("seal-marker", "X", "Y", 1, 61)
        )
        late_decisions = engine.ingest(tx("late-t0", "C", "A", 100, 20))

        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].evidence.status, DecisionStatus.SEALED)
        self.assertEqual(len(late_decisions), 1)
        self.assertEqual(
            late_decisions[0].evidence.status, DecisionStatus.REVISED
        )
        self.assertEqual(
            late_decisions[0].cause, ChangeCause.EVIDENCE
        )
        sealed = next(
            hit
            for hit in engine.all_hits()
            if hit.status == DecisionStatus.SEALED
        )
        self.assertEqual(sealed.status, DecisionStatus.SEALED)
        self.assertEqual(sealed.transaction_ids, ("t1", "t2"))
        self.assertIn("late-t0", late_decisions[0].evidence.transaction_ids)

    def test_manual_evidence_exclusion_keeps_event_and_can_be_restored(self) -> None:
        engine = build_engine()
        engine.ingest_many(
            [
                link("link-ab", "A", "B"),
                link("link-bc", "B", "C"),
                tx("t1", "A", "B", 500, 100),
                tx("t2", "B", "C", 500, 200),
            ]
        )

        decisions = engine.exclude_evidence(
            "evt-link-bc",
            "association not verified",
            operator="analyst-1",
            decided_at=250,
        )

        self.assertEqual(len(decisions), 1)
        revoked = decisions[0].evidence
        self.assertEqual(revoked.status, DecisionStatus.REVOKED)
        self.assertEqual(decisions[0].cause, ChangeCause.MANUAL)
        self.assertEqual(revoked.association_ids, ("link-ab", "link-bc"))
        self.assertEqual(revoked.excluded_event_ids, ("evt-link-bc",))
        self.assertEqual(
            revoked.manual_judgments[0].reason,
            "association not verified",
        )
        self.assertIn("evt-link-bc", {
            event.event_id for event in engine.raw_events()
        })
        self.assertEqual(engine.active_hits(), [])

        restored = engine.withdraw_evidence_judgment(
            "evt-link-bc",
            withdrawn_at=260,
            reason="verified",
        )

        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].evidence.status, DecisionStatus.REVISED)
        self.assertEqual(
            restored[0].evidence.transaction_ids, ("t1", "t2")
        )
        self.assertEqual(restored[0].cause, ChangeCause.MANUAL)
        self.assertEqual(
            restored[0].evidence.excluded_event_ids, ()
        )
        self.assertEqual(
            restored[0].evidence.manual_judgments[0].withdrawal_reason,
            "verified",
        )

    def test_shared_identity_exclusion_only_affects_dependent_chain(self) -> None:
        engine = RuleEngine(
            [
                CrossIdentityFlowRule(
                    window_seconds=300,
                    min_identities=3,
                    min_total_amount=1200,
                )
            ]
        )
        engine.ingest_many(
            [
                link("abnormal-sa", "S", "A"),
                link("abnormal-ab", "A", "B"),
                link("abnormal-bc", "B", "C"),
                tx("abn-1", "S", "A", 500, 100),
                tx("abn-2", "C", "B", 400, 200),
                tx("abn-3", "B", "C", 400, 210),
            ]
        )

        hits = {hit.identities: hit for hit in engine.active_hits()}
        self.assertEqual(
            set(hits),
            {("A", "B", "C", "S")},
        )

        decisions = engine.exclude_evidence(
            "evt-abn-3",
            "transaction not verified",
            operator="analyst-2",
            decided_at=250,
        )

        engine.ingest_many(
            [
                association_event(
                    IdentityAssociation("normal-ad", "A", "D", 400),
                    source=SOURCE,
                ),
                association_event(
                    IdentityAssociation("normal-de", "D", "E", 400),
                    source=SOURCE,
                ),
                tx("norm-1", "A", "D", 600, 400),
                tx("norm-2", "D", "E", 600, 450),
            ]
        )

        self.assertEqual(len(decisions), 1)
        self.assertEqual(
            decisions[0].evidence.identities, ("A", "B", "C", "S")
        )
        self.assertEqual(
            decisions[0].evidence.status, DecisionStatus.REVOKED
        )
        active = {hit.identities: hit for hit in engine.active_hits()}
        self.assertEqual(set(active), {("A", "D", "E")})
        self.assertEqual(active[("A", "D", "E")].transaction_ids, (
            "norm-1",
            "norm-2",
        ))

    def test_rule_change_is_separate_from_evidence_and_manual_changes(self) -> None:
        engine = build_engine()
        engine.ingest_many(
            [
                link("link-ab", "A", "B"),
                link("link-bc", "B", "C"),
                tx("t1", "A", "B", 500, 100),
                tx("t2", "B", "C", 500, 200),
            ]
        )

        decisions = engine.replace_rule(
            "cross_identity_flow",
            CrossIdentityFlowRule(
                version="v2",
                window_seconds=300,
                min_identities=3,
                min_total_amount=1200,
            ),
        )

        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].cause, ChangeCause.RULE)
        self.assertEqual(
            decisions[0].evidence.status, DecisionStatus.REVOKED
        )
        causes = [revision["cause"] for revision in engine.hit_history()]
        self.assertIn(ChangeCause.EVIDENCE, causes)
        self.assertIn(ChangeCause.RULE, causes)

    def test_manual_change_after_seal_creates_new_version(self) -> None:
        engine = RuleEngine(
            [
                CrossIdentityFlowRule(
                    window_seconds=60,
                    min_identities=3,
                    min_total_amount=900,
                )
            ]
        )
        engine.ingest_many(
            [
                link("link-ab", "A", "B"),
                link("link-bc", "B", "C"),
                tx("t1", "A", "B", 500, 0),
                tx("t2", "B", "C", 500, 10),
                tx("marker", "X", "Y", 1, 61),
            ]
        )

        decisions = engine.exclude_evidence(
            "evt-t1",
            "sealed hit evidence disputed",
            operator="analyst-3",
            decided_at=100,
        )

        self.assertEqual(len(decisions), 1)
        revised = decisions[0].evidence
        self.assertEqual(revised.status, DecisionStatus.REVOKED)
        self.assertEqual(decisions[0].cause, ChangeCause.MANUAL)
        sealed = next(
            hit for hit in engine.all_hits()
            if hit.status == DecisionStatus.SEALED
        )
        self.assertEqual(sealed.transaction_ids, ("t1", "t2"))
        self.assertEqual(sealed.excluded_event_ids, ())


class OverlappingManualJudgmentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.events = [
            link("link-ab", "A", "B"),
            link("link-bc", "B", "C"),
            tx("t1", "A", "B", 500, 100),
            tx("t2", "B", "C", 500, 200),
        ]

    def test_overlapping_judgments_withdraw_independently(self) -> None:
        engine = build_engine()
        engine.ingest_many(self.events)
        self.assertEqual(len(engine.active_hits()), 1)

        engine.exclude_evidence(
            "evt-t1",
            "false positive review",
            operator="analyst-1",
            decided_at=250,
            kind=JudgmentKind.FALSE_POSITIVE,
            judgment_id="j-fp",
        )
        engine.exclude_evidence(
            "evt-t1",
            "rule exception granted",
            operator="analyst-2",
            decided_at=251,
            kind=JudgmentKind.RULE_EXCEPTION,
            judgment_id="j-ex",
        )
        self.assertEqual(engine.active_hits(), [])
        judgments = {
            judgment.effective_id: judgment
            for judgment in engine.manual_judgments()
        }
        self.assertEqual(set(judgments), {"j-fp", "j-ex"})

        # Withdrawing the false-positive judgment must not restore the
        # hit: the rule exception is still in effect.
        decisions = engine.withdraw_evidence_judgment(
            "j-fp", withdrawn_at=260, reason="review overturned"
        )
        self.assertEqual(decisions, [])
        self.assertEqual(engine.active_hits(), [])

        # Withdrawing the remaining judgment restores the hit.
        restored = engine.withdraw_evidence_judgment(
            "j-ex", withdrawn_at=270, reason="exception expired"
        )
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].cause, ChangeCause.MANUAL)
        self.assertEqual(restored[0].evidence.status, DecisionStatus.REVISED)
        self.assertEqual(restored[0].evidence.transaction_ids, ("t1", "t2"))
        self.assertEqual(restored[0].evidence.excluded_event_ids, ())
        active_judgments = [
            judgment
            for judgment in engine.manual_judgments()
            if judgment.active
        ]
        self.assertEqual(active_judgments, [])

    def test_ambiguous_event_withdrawal_requires_judgment_id(self) -> None:
        engine = build_engine()
        engine.ingest_many(self.events)
        engine.exclude_evidence(
            "evt-t1",
            "first",
            operator="analyst-1",
            decided_at=250,
            judgment_id="j-1",
        )
        engine.exclude_evidence(
            "evt-t1",
            "second",
            operator="analyst-2",
            decided_at=251,
            judgment_id="j-2",
        )
        with self.assertRaises(ValueError):
            engine.withdraw_evidence_judgment("evt-t1", withdrawn_at=260)

    def test_withdrawal_order_does_not_change_final_state(self) -> None:
        def run(order: tuple[str, ...]) -> RuleEngine:
            engine = build_engine()
            engine.ingest_many(self.events)
            engine.exclude_evidence(
                "evt-t1",
                "false positive review",
                operator="analyst-1",
                decided_at=250,
                kind=JudgmentKind.FALSE_POSITIVE,
                judgment_id="j-fp",
            )
            engine.exclude_evidence(
                "evt-link-bc",
                "identity split",
                operator="analyst-2",
                decided_at=251,
                kind=JudgmentKind.IDENTITY_SPLIT,
                judgment_id="j-split",
            )
            self.assertEqual(engine.active_hits(), [])
            for index, judgment_id in enumerate(order):
                engine.withdraw_evidence_judgment(
                    judgment_id,
                    withdrawn_at=260 + index,
                )
            return engine

        first = run(("j-fp", "j-split"))
        second = run(("j-split", "j-fp"))

        def snapshot(engine: RuleEngine):
            return sorted(
                (
                    hit.hit_id,
                    hit.status,
                    hit.transaction_ids,
                    hit.total_amount,
                    hit.excluded_event_ids,
                )
                for hit in engine.all_hits()
            )

        self.assertEqual(snapshot(first), snapshot(second))
        self.assertEqual(len(first.active_hits()), 1)
        self.assertEqual(
            first.active_hits()[0].transaction_ids, ("t1", "t2")
        )

    def test_rule_exception_scoped_to_single_rule(self) -> None:
        engine = RuleEngine(
            [
                CrossIdentityFlowRule(
                    window_seconds=300,
                    min_identities=3,
                    min_total_amount=900,
                    rule_id="cross_identity_flow",
                ),
                CrossIdentityFlowRule(
                    window_seconds=300,
                    min_identities=3,
                    min_total_amount=900,
                    rule_id="cross_identity_flow_audit",
                    version="v1",
                ),
            ]
        )
        engine.ingest_many(self.events)
        self.assertEqual(len(engine.active_hits()), 2)

        engine.exclude_evidence(
            "evt-t1",
            "exception for main rule only",
            operator="analyst-1",
            decided_at=250,
            kind=JudgmentKind.RULE_EXCEPTION,
            rule_id="cross_identity_flow",
            judgment_id="j-scoped",
        )

        active = engine.active_hits()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].rule.rule_id, "cross_identity_flow_audit")

        restored = engine.withdraw_evidence_judgment(
            "j-scoped", withdrawn_at=260
        )
        self.assertEqual(len(restored), 1)
        self.assertEqual(len(engine.active_hits()), 2)

    def test_explain_hit_lists_context_and_effective_judgments(self) -> None:
        engine = build_engine()
        engine.ingest_many(self.events)
        hit = engine.active_hits()[0]

        engine.exclude_evidence(
            "evt-t1",
            "false positive review",
            operator="analyst-1",
            decided_at=250,
            kind=JudgmentKind.FALSE_POSITIVE,
            judgment_id="j-fp",
        )
        engine.exclude_evidence(
            "evt-t1",
            "rule exception granted",
            operator="analyst-2",
            decided_at=251,
            kind=JudgmentKind.RULE_EXCEPTION,
            judgment_id="j-ex",
        )
        engine.withdraw_evidence_judgment("j-ex", withdrawn_at=260)

        explanation = engine.explain_hit(hit.hit_id)
        self.assertIsNotNone(explanation)
        assert explanation is not None
        self.assertEqual(explanation["rule"], "cross_identity_flow@v1")
        self.assertEqual(explanation["status"], DecisionStatus.REVOKED)
        self.assertEqual(
            explanation["transaction_ids"], ("t1", "t2")
        )
        original_ids = {
            event.event_id for event in explanation["original_events"]
        }
        self.assertEqual(
            original_ids,
            {"evt-link-ab", "evt-link-bc", "evt-t1", "evt-t2"},
        )
        self.assertEqual(
            explanation["excluded_event_ids"], ("evt-t1",)
        )
        active = explanation["active_manual_judgments"]
        self.assertEqual(
            [judgment.effective_id for judgment in active], ["j-fp"]
        )
        self.assertEqual(active[0].kind, JudgmentKind.FALSE_POSITIVE)
        all_judgments = explanation["manual_judgments"]
        self.assertEqual(
            {judgment.effective_id for judgment in all_judgments},
            {"j-fp", "j-ex"},
        )
        withdrawn = next(
            judgment
            for judgment in all_judgments
            if judgment.effective_id == "j-ex"
        )
        self.assertEqual(withdrawn.withdrawn_at, 260)
        self.assertTrue(explanation["revision_ids"])
        self.assertIsNone(engine.explain_hit("missing-hit"))


if __name__ == "__main__":
    unittest.main()
