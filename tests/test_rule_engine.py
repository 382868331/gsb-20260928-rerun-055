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
from antifraud.models import ChangeCause, DecisionStatus, EventSource
from antifraud.reviews import exclude_request, withdraw_request
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
    def _ingest_chains(self, engine: RuleEngine) -> None:
        """Abnormal and normal chains sharing identity "B" in one window.

        The abnormal chain A-B-C exceeds the amount threshold; the ordinary
        chain B-G-H does not. They share node B, so they form one component.
        A separate independent chain D-E-F acts as an unaffected control.
        """
        engine.ingest_many(
            [
                link("link-ab", "A", "B"),
                link("link-bc", "B", "C"),
                link("link-bg", "B", "G"),
                link("link-gh", "G", "H"),
                link("link-de", "D", "E"),
                link("link-ef", "E", "F"),
                # abnormal chain
                tx("risk-1", "A", "B", 500, 100),
                tx("risk-2", "B", "C", 500, 200),
                # ordinary chain sharing node B
                tx("normal-1", "B", "G", 12.5, 120),
                tx("normal-2", "G", "H", 12.5, 220),
                # independent control component
                tx("ctrl-1", "D", "E", 500, 110),
                tx("ctrl-2", "E", "F", 500, 210),
            ]
        )

    def test_manual_exclusion_keeps_event_and_records_reason(self) -> None:
        engine = build_engine()
        self._ingest_chains(engine)

        hits = {tuple(hit.identities): hit for hit in engine.active_hits()}
        # A-B-C-G-H is one component (shared B); D-E-F is the control
        self.assertEqual(
            sorted(hits),
            [("A", "B", "C", "G", "H"), ("D", "E", "F")],
        )
        merged = hits[("A", "B", "C", "G", "H")]
        self.assertIn("risk-1", merged.transaction_ids)
        self.assertIn("normal-1", merged.transaction_ids)

        decisions = engine.review_evidence(
            exclude_request(
                "evt-link-ab",
                reviewer="analyst-7",
                reason="identity link proven to be a data merge error",
                reviewed_at=240,
            )
        )

        # original event still present in the event log, not deleted
        self.assertIn("evt-link-ab", engine._events_by_id)
        self.assertTrue(engine.is_excluded("evt-link-ab"))

        # A breaks away from the component: A-B-C-G-H chain drops below
        # the 3-identity threshold for the remaining B-C-G-H group
        self.assertEqual(len(decisions), 1)
        decision = decisions[0]
        self.assertEqual(
            decision.evidence.status, DecisionStatus.REVOKED
        )
        self.assertEqual(decision.change_cause, ChangeCause.MANUAL)
        self.assertEqual(
            decision.evidence.association_ids,
            ("link-ab", "link-bc", "link-bg", "link-gh"),
        )
        review = decision.evidence.manual_reviews[-1]
        self.assertEqual(review.reviewed_event_id, "evt-link-ab")
        self.assertEqual(review.reviewer, "analyst-7")
        self.assertIn("merge error", review.reason)

    def test_manual_exclusion_impact_is_limited_to_dependent_chain(
        self,
    ) -> None:
        engine = build_engine()
        self._ingest_chains(engine)

        before = {
            tuple(hit.identities): hit for hit in engine.active_hits()
        }
        self.assertEqual(len(before), 2)
        control_line = before[("D", "E", "F")].line_key

        engine.review_evidence(
            exclude_request(
                "evt-risk-2",
                reviewer="analyst-7",
                reason="transaction disputed as legitimate refund",
                reviewed_at=245,
            )
        )

        # independent component keeps its original hit untouched
        control = engine.latest_for_line(control_line)
        self.assertIsNotNone(control)
        self.assertEqual(control.transaction_ids, ("ctrl-1", "ctrl-2"))
        self.assertEqual(control.identities, ("D", "E", "F"))

    def test_withdrawing_manual_judgement_restores_original_computation(
        self,
    ) -> None:
        engine = build_engine()
        self._ingest_chains(engine)
        merged = next(
            hit
            for hit in engine.active_hits()
            if "A" in hit.identities
        )
        line_key = merged.line_key
        original_amount = merged.total_amount
        original_tx = merged.transaction_ids

        engine.review_evidence(
            exclude_request(
                "evt-risk-2",
                reviewer="analyst-7",
                reason="disputed",
                reviewed_at=240,
            )
        )
        self.assertEqual(
            engine.latest_for_line(line_key).status,
            DecisionStatus.REVOKED,
        )

        decisions = engine.review_evidence(
            withdraw_request(
                "evt-risk-2",
                reviewer="lead-3",
                reason="dispute rejected, evidence restored",
                reviewed_at=260,
            )
        )

        self.assertFalse(engine.is_excluded("evt-risk-2"))
        restored = engine.latest_for_line(line_key)
        self.assertEqual(restored.status, DecisionStatus.OPEN)
        self.assertEqual(restored.total_amount, original_amount)
        self.assertEqual(restored.transaction_ids, original_tx)
        self.assertEqual(decisions[0].change_cause, ChangeCause.MANUAL)
        history = engine.hit_history(line_key)
        actions = [
            (revision.revision, revision.status)
            for revision in history
        ]
        self.assertEqual(
            actions,
            [
                (1, DecisionStatus.UPDATED),
                (2, DecisionStatus.REVOKED),
                (3, DecisionStatus.OPEN),
            ],
        )

    def test_rule_revision_updates_open_window_and_versions_sealed(self) -> None:
        engine = RuleEngine(
            [
                CrossIdentityFlowRule(
                    rule_id="cross_identity_flow",
                    version="v1",
                    window_seconds=300,
                    min_identities=3,
                    min_total_amount=900,
                )
            ]
        )
        # sealed historical window
        engine.ingest_many(
            [
                link("h-ab", "HA", "HB"),
                link("h-bc", "HB", "HC"),
                tx("h-t1", "HA", "HB", 500, 0),
                tx("h-t2", "HB", "HC", 500, 10),
            ]
        )
        engine.ingest(tx("h-seal", "X", "Y", 1, 301))
        # still-open window
        engine.ingest_many(
            [
                link("o-ab", "OA", "OB"),
                link("o-bc", "OB", "OC"),
                tx("o-t1", "OA", "OB", 500, 400),
                tx("o-t2", "OB", "OC", 500, 410),
            ]
        )

        decisions = engine.revise_rule(
            CrossIdentityFlowRule(
                rule_id="cross_identity_flow",
                version="v2",
                window_seconds=300,
                min_identities=3,
                min_total_amount=800,
            ),
            revised_at=420,
        )

        causes = {decision.change_cause for decision in decisions}
        self.assertEqual(causes, {ChangeCause.RULE})

        # both the sealed historical window and the open window are
        # re-evaluated under v2, producing one new revision each
        self.assertEqual(len(decisions), 2)
        for decision in decisions:
            self.assertEqual(decision.evidence.rule.version, "v2")

        sealed_line = next(
            decision.evidence.line_key
            for decision in decisions
            if decision.evidence.status == DecisionStatus.SEALED
        )
        history = engine.hit_history(sealed_line)
        versions = [
            (revision.rule.version, revision.status, revision.revision)
            for revision in history
        ]
        # sealed v1 snapshot retained, v2 re-evaluation appended
        self.assertEqual(
            versions,
            [
                ("v1", DecisionStatus.SEALED, 1),
                ("v2", DecisionStatus.SEALED, 2),
            ],
        )
        self.assertEqual(history[1].supersedes_revision, 1)

    def test_change_causes_are_distinguished(self) -> None:
        engine = build_engine()
        opened = engine.ingest_many(
            [
                link("ab", "A", "B"),
                link("bc", "B", "C"),
                tx("t1", "A", "B", 500, 100),
            ]
        )
        self.assertEqual(opened, [])

        evidence_decisions = engine.ingest(tx("t2", "B", "C", 500, 200))
        self.assertEqual(
            evidence_decisions[0].change_cause, ChangeCause.EVIDENCE
        )

        seal_decisions = engine.ingest(tx("marker", "X", "Y", 1, 301))
        self.assertEqual(seal_decisions[0].change_cause, ChangeCause.SEAL)

        rule_decisions = engine.revise_rule(
            CrossIdentityFlowRule(
                rule_id="cross_identity_flow",
                version="v2",
                window_seconds=300,
                min_identities=3,
                min_total_amount=900,
            ),
            revised_at=310,
        )
        self.assertEqual(
            rule_decisions[0].change_cause, ChangeCause.RULE
        )

        manual_decisions = engine.review_evidence(
            exclude_request(
                "evt-t1",
                reviewer="a",
                reason="bad evidence",
                reviewed_at=320,
            )
        )
        self.assertEqual(
            manual_decisions[0].change_cause, ChangeCause.MANUAL
        )

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

    def test_sealed_snapshot_is_immutable_but_late_data_forms_new_revision(
        self,
    ) -> None:
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
        late_decisions = engine.ingest_many(
            [
                tx("late-t0", "C", "A", 100, 20),
            ]
        )

        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].evidence.status, DecisionStatus.SEALED)
        self.assertEqual(decisions[0].evidence.revision, 1)

        # late data after sealing is not dropped; it becomes a new version
        self.assertEqual(len(late_decisions), 1)
        revalued = late_decisions[0].evidence
        self.assertEqual(revalued.status, DecisionStatus.SEALED)
        self.assertEqual(revalued.revision, 2)
        self.assertEqual(
            revalued.supersedes_revision, 1
        )
        self.assertEqual(
            revalued.change_cause, ChangeCause.EVIDENCE
        )
        self.assertEqual(
            revalued.transaction_ids, ("t1", "t2", "late-t0")
        )

        # the original sealed snapshot is retained unchanged
        history = engine.hit_history(revalued.line_key)
        self.assertEqual(len(history), 2)
        original = history[0]
        self.assertEqual(original.status, DecisionStatus.SEALED)
        self.assertEqual(original.transaction_ids, ("t1", "t2"))
        latest = next(
            hit
            for hit in engine.all_revisions()
            if hit.revision == 2
        )
        self.assertEqual(latest.transaction_ids, ("t1", "t2", "late-t0"))


if __name__ == "__main__":
    unittest.main()
