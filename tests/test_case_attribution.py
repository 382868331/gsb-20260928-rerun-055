from __future__ import annotations

import unittest

from antifraud.cases import (
    AttributionKind,
    CaseBook,
    CaseStatus,
)
from antifraud.events import (
    IdentityAssociation,
    Transaction,
    association_event,
    transaction_event,
)
from antifraud.models import EventSource
from antifraud.rules import CrossIdentityFlowRule
from antifraud.engine import RuleEngine


SOURCE = EventSource(system="case-lab", producer="unit-test")


def build_book() -> tuple[RuleEngine, CaseBook]:
    engine = RuleEngine(
        [
            CrossIdentityFlowRule(
                window_seconds=300,
                min_identities=3,
                min_total_amount=900,
            )
        ]
    )
    engine.ingest_many(
        [
            association_event(
                IdentityAssociation("l1", "A", "B", 0), source=SOURCE
            ),
            association_event(
                IdentityAssociation("l2", "B", "C", 0), source=SOURCE
            ),
            transaction_event(
                Transaction("t1", "A", "B", 600),
                occurred_at=100,
                source=SOURCE,
            ),
            transaction_event(
                Transaction("t2", "B", "C", 400),
                occurred_at=200,
                source=SOURCE,
            ),
        ]
    )
    book = CaseBook(engine)
    book.open_case("case-x")
    book.open_case("case-y")
    return engine, book


class PartialClaimTest(unittest.TestCase):
    def test_partial_shares_reconcile_back_to_original(self) -> None:
        _, book = build_book()

        impact = book.adopt_share(
            "case-x",
            {"evt-t1": 600.0},
            operator="analyst-1",
            rationale="case X claims all of t1",
            decided_at=300,
            decision_id="share-x-t1",
        )

        self.assertEqual(impact.kind, AttributionKind.SHARE)
        self.assertEqual(impact.case_totals["case-x"], 600.0)
        line = next(line for line in impact.lines if line.event_id == "evt-t1")
        self.assertEqual(line.original_amount, 600.0)
        self.assertEqual(line.confirmed_total, 600.0)
        self.assertEqual(line.unattributed_amount, 0.0)

        book.adopt_share(
            "case-y",
            {"evt-t2": 400.0},
            operator="analyst-2",
            rationale="case Y claims t2",
            decided_at=310,
            decision_id="share-y-t2",
        )

        totals = book.case_totals()
        self.assertEqual(totals, {"case-x": 600.0, "case-y": 400.0})
        rows = {row[0]: row[1:] for row in book.reconcile()}
        self.assertEqual(
            rows["evt-t1"], (600.0, 600.0, 0.0, 0.0)
        )
        self.assertEqual(
            rows["evt-t2"], (400.0, 400.0, 0.0, 0.0)
        )

    def test_overlapping_claims_show_disputed_share_separately(self) -> None:
        _, book = build_book()

        book.adopt_share(
            "case-x",
            {"evt-t1": 400.0},
            operator="analyst-1",
            rationale="X partial claim",
            decided_at=300,
            decision_id="x-1",
        )
        preview = book.propose_share(
            "case-y",
            {"evt-t1": 500.0},
            operator="analyst-2",
            rationale="Y also claims t1",
            decided_at=315,
        )

        line = next(line for line in preview.lines if line.event_id == "evt-t1")
        by_case = {item.case_id: item for item in line.allocations}
        self.assertEqual(by_case["case-x"].confirmed_amount, 400.0)
        self.assertEqual(by_case["case-y"].confirmed_amount, 200.0)
        self.assertEqual(by_case["case-y"].disputed_amount, 300.0)
        self.assertEqual(line.confirmed_total, 600.0)
        self.assertEqual(line.disputed_total, 300.0)

        impact = book.adopt_share(
            "case-y",
            {"evt-t1": 500.0},
            operator="analyst-2",
            rationale="Y also claims t1",
            decided_at=320,
            decision_id="y-1",
        )
        self.assertEqual(impact.confirmed_total_for("case-x"), 400.0)
        self.assertEqual(impact.confirmed_total_for("case-y"), 200.0)
        self.assertEqual(impact.disputed_total_for("case-y"), 300.0)

        withdrawal = book.withdraw_decision(
            "y-1", withdrawn_at=340, reason="Y retracts claim"
        )
        line = next(
            line for line in withdrawal.lines if line.event_id == "evt-t1"
        )
        self.assertEqual(line.confirmed_total, 400.0)
        self.assertEqual(line.disputed_total, 0.0)
        self.assertEqual(line.unattributed_amount, 200.0)
        self.assertEqual(book.case_totals()["case-x"], 400.0)

    def test_withdraw_one_attribution_keeps_other_case_scope(self) -> None:
        _, book = build_book()
        book.adopt_share(
            "case-x",
            {"evt-t1": 600.0, "evt-t2": 200.0},
            operator="analyst-1",
            rationale="X claims t1 and part of t2",
            decided_at=300,
            decision_id="x-both",
        )
        book.adopt_share(
            "case-y",
            {"evt-t2": 400.0},
            operator="analyst-2",
            rationale="Y claims all of t2",
            decided_at=310,
            decision_id="y-t2",
        )

        impact = book.withdraw_decision(
            "x-both", withdrawn_at=330, reason="reassigned"
        )

        self.assertEqual(impact.confirmed_total_for("case-y"), 400.0)
        self.assertEqual(impact.confirmed_total_for("case-x"), 0.0)
        self.assertEqual(book.case_totals()["case-y"], 400.0)
        rows = {row[0]: row[1:] for row in book.reconcile()}
        self.assertEqual(rows["evt-t1"], (600.0, 0.0, 0.0, 600.0))
        self.assertEqual(rows["evt-t2"], (400.0, 400.0, 0.0, 0.0))


class TransferAndMergeTest(unittest.TestCase):
    def test_preview_and_move_part_of_transaction(self) -> None:
        engine, book = build_book()
        engine.grant_rule_exception(
            "evt-t2",
            "manual exception recorded",
            operator="analyst-9",
            decided_at=290,
            judgment_id="manual-t2",
        )
        book.adopt_share(
            "case-x",
            {"evt-t1": 600.0, "evt-t2": 400.0},
            operator="analyst-1",
            rationale="X owns everything initially",
            decided_at=300,
            decision_id="x-all",
        )

        preview = book.propose_transfer(
            "case-x",
            "case-y",
            {"evt-t2": 150.0},
            operator="analyst-3",
            rationale="split t2 with Y",
        )
        self.assertEqual(preview.kind, AttributionKind.TRANSFER)
        hit_ids = {hit.hit_id for hit in preview.affected_hits}
        self.assertTrue(hit_ids)
        manual_ids = {
            judgment.judgment_id
            for judgment in preview.affected_manual_judgments
        }
        self.assertIn("manual-t2", manual_ids)
        self.assertEqual(preview.case_totals["case-x"], 850.0)
        self.assertEqual(preview.case_totals["case-y"], 150.0)

        impact = book.adopt_transfer(
            "case-x",
            "case-y",
            {"evt-t2": 150.0},
            operator="analyst-3",
            rationale="split t2 with Y",
            decided_at=350,
            decision_id="move-t2",
        )
        totals = impact.case_totals
        self.assertEqual(totals["case-x"], 850.0)
        self.assertEqual(totals["case-y"], 150.0)

        book.withdraw_decision(
            "move-t2", withdrawn_at=360, reason="move cancelled"
        )
        self.assertEqual(
            book.case_totals(),
            {"case-x": 1000.0, "case-y": 0.0},
        )

    def test_merge_moves_all_confirmed_scope_and_can_be_undone(self) -> None:
        _, book = build_book()
        book.open_case("case-z")
        book.adopt_share(
            "case-x",
            {"evt-t1": 600.0},
            operator="analyst-1",
            rationale="X t1",
            decided_at=300,
            decision_id="x-t1",
        )
        book.adopt_share(
            "case-y",
            {"evt-t2": 400.0},
            operator="analyst-2",
            rationale="Y t2",
            decided_at=310,
            decision_id="y-t2",
        )

        preview = book.propose_merge(
            "case-y",
            "case-z",
            operator="lead",
            rationale="consolidate Y into Z",
        )
        self.assertEqual(preview.case_totals["case-z"], 400.0)
        self.assertEqual(preview.case_totals["case-y"], 0.0)

        impact = book.adopt_merge(
            "case-y",
            "case-z",
            operator="lead",
            rationale="consolidate Y into Z",
            decided_at=320,
            decision_id="merge-y-z",
        )
        self.assertEqual(book.case_status("case-y"), CaseStatus.MERGED)
        self.assertEqual(impact.case_totals["case-z"], 400.0)
        self.assertEqual(book.case_totals()["case-z"], 400.0)

        book.withdraw_decision(
            "merge-y-z", withdrawn_at=330, reason="merge reversed"
        )
        self.assertEqual(book.case_status("case-y"), CaseStatus.OPEN)
        self.assertEqual(
            book.case_totals(),
            {"case-x": 600.0, "case-y": 400.0, "case-z": 0.0},
        )


class SealedLateEvidenceTest(unittest.TestCase):
    def test_late_evidence_forms_new_revision_while_snapshot_stays(self) -> None:
        _, book = build_book()
        book.adopt_share(
            "case-x",
            {"evt-t1": 600.0, "evt-t2": 400.0},
            operator="analyst-1",
            rationale="X initial scope",
            decided_at=300,
            decision_id="x-initial",
        )
        sealed = book.seal_case("case-x", sealed_at=400)

        self.assertEqual(sealed.status, CaseStatus.SEALED)
        self.assertEqual(sealed.confirmed_total, 1000.0)
        self.assertEqual(sealed.revision, 1)

        impact = book.adopt_share(
            "case-x",
            {"evt-t1": -250.0},
            operator="late-analyst",
            rationale="late evidence reduces X share",
            decided_at=500,
            decision_id="x-late",
        )
        decision = book.decision("x-late")
        assert decision is not None
        self.assertTrue(decision.sealed_late)
        self.assertEqual(impact.case_totals["case-x"], 750.0)

        original = book.case_explanation("case-x", revision=1)
        current = book.case_explanation("case-x")
        assert original is not None and current is not None
        self.assertEqual(original.confirmed_total, 1000.0)
        self.assertEqual(current.revision, 2)
        self.assertEqual(current.confirmed_total, 750.0)

        book.withdraw_decision(
            "x-late", withdrawn_at=520, reason="late evidence rejected"
        )
        self.assertEqual(book.case_status("case-x"), CaseStatus.SEALED)
        latest = book.case_explanation("case-x")
        assert latest is not None
        self.assertEqual(latest.confirmed_total, 1000.0)
        self.assertEqual(len(book.case_history("case-x")), 3)


if __name__ == "__main__":
    unittest.main()
