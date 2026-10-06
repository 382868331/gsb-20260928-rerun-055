from __future__ import annotations

import unittest

from antifraud.cases import (
    CaseLedger,
    CaseStatus,
    ProposalKind,
    ProposalStatus,
    ShareState,
)
from antifraud.engine import RuleEngine
from antifraud.events import (
    IdentityAssociation,
    Transaction,
    association_event,
    transaction_event,
)
from antifraud.models import ChangeCause, EventSource
from antifraud.rules import CrossIdentityFlowRule


SOURCE = EventSource(system="synthetic-transaction-lab", producer="unit-test")


def build_ledger() -> CaseLedger:
    ledger = CaseLedger()
    ledger.register_case("case-a")
    ledger.register_case("case-b")
    ledger.register_transaction("tx-1", 500.0, occurred_at=100)
    ledger.register_transaction("tx-2", 300.0, occurred_at=200)
    return ledger


def allocate(
    ledger: CaseLedger,
    case_id: str,
    transaction_id: str,
    amount: float,
    at: int,
) -> str:
    proposal = ledger.propose_allocation(
        case_id=case_id,
        transaction_id=transaction_id,
        amount=amount,
        operator="analyst",
        proposed_at=at,
        reason="loss attribution",
    )
    ledger.adopt_proposal(proposal.proposal_id, adopted_at=at)
    decisions = [
        decision
        for decision in ledger._decisions.values()
        if decision.proposal_id == proposal.proposal_id
    ]
    return decisions[0].decision_id


class AllocationTest(unittest.TestCase):
    def test_single_case_full_claim_confirmed(self) -> None:
        ledger = build_ledger()
        allocate(ledger, "case-a", "tx-1", 500.0, at=10)
        view = ledger.case_view("case-a")
        self.assertEqual(view.confirmed_total, 500.0)
        self.assertEqual(view.disputed_total, 0.0)
        reconciliation = ledger.transaction_reconciliation("tx-1")
        self.assertTrue(reconciliation.reconciles)
        self.assertEqual(reconciliation.unallocated, 0.0)

    def test_partial_claim_leaves_unallocated(self) -> None:
        ledger = build_ledger()
        allocate(ledger, "case-a", "tx-1", 200.0, at=10)
        reconciliation = ledger.transaction_reconciliation("tx-1")
        self.assertEqual(reconciliation.confirmed_total, 200.0)
        self.assertEqual(reconciliation.unallocated, 300.0)
        self.assertTrue(reconciliation.reconciles)

    def test_overlapping_claims_become_disputed_not_double_counted(
        self,
    ) -> None:
        ledger = build_ledger()
        allocate(ledger, "case-a", "tx-1", 500.0, at=10)
        allocate(ledger, "case-b", "tx-1", 500.0, at=20)
        view_a = ledger.case_view("case-a")
        view_b = ledger.case_view("case-b")
        self.assertEqual(view_a.confirmed_total, 0.0)
        self.assertEqual(view_b.confirmed_total, 0.0)
        self.assertEqual(view_a.disputed_total, 500.0)
        self.assertEqual(view_b.disputed_total, 500.0)
        reconciliation = ledger.transaction_reconciliation("tx-1")
        self.assertEqual(reconciliation.confirmed_total, 0.0)
        self.assertEqual(reconciliation.disputed_total, 500.0)
        self.assertTrue(reconciliation.reconciles)

    def test_partial_overlap_disputes_only_shared_portion(self) -> None:
        ledger = build_ledger()
        allocate(ledger, "case-a", "tx-1", 300.0, at=10)
        allocate(ledger, "case-b", "tx-1", 400.0, at=20)
        view_a = ledger.case_view("case-a")
        view_b = ledger.case_view("case-b")
        self.assertEqual(view_a.confirmed_total, 0.0)
        self.assertEqual(view_a.disputed_total, 300.0)
        self.assertEqual(view_b.confirmed_total, 100.0)
        self.assertEqual(view_b.disputed_total, 300.0)
        reconciliation = ledger.transaction_reconciliation("tx-1")
        self.assertEqual(reconciliation.confirmed_total, 100.0)
        self.assertEqual(reconciliation.disputed_total, 300.0)
        self.assertEqual(reconciliation.unallocated, 100.0)
        self.assertTrue(reconciliation.reconciles)

    def test_withdrawal_keeps_other_cases_and_resolves_dispute(
        self,
    ) -> None:
        ledger = build_ledger()
        first = allocate(ledger, "case-a", "tx-1", 500.0, at=10)
        allocate(ledger, "case-b", "tx-1", 500.0, at=20)
        ledger.withdraw_attribution(
            first, withdrawn_at=30, reason="duplicate claim"
        )
        view_b = ledger.case_view("case-b")
        self.assertEqual(view_b.confirmed_total, 500.0)
        self.assertEqual(view_b.disputed_total, 0.0)
        view_a = ledger.case_view("case-a")
        self.assertEqual(view_a.confirmed_total, 0.0)
        self.assertEqual(view_a.disputed_total, 0.0)

    def test_withdrawal_is_targeted_and_idempotent(self) -> None:
        ledger = build_ledger()
        keep = allocate(ledger, "case-a", "tx-1", 200.0, at=10)
        drop = allocate(ledger, "case-a", "tx-2", 300.0, at=11)
        ledger.withdraw_attribution(drop, withdrawn_at=12)
        ledger.withdraw_attribution(drop, withdrawn_at=13)
        view = ledger.case_view("case-a")
        self.assertEqual(view.confirmed_total, 200.0)
        self.assertIn(keep, ledger._decisions)


class ProposalTest(unittest.TestCase):
    def test_preview_shows_amounts_rules_and_judgments(self) -> None:
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
                    Transaction("tx-1", "A", "B", 500.0),
                    occurred_at=100,
                    source=SOURCE,
                ),
                transaction_event(
                    Transaction("tx-2", "B", "C", 500.0),
                    occurred_at=200,
                    source=SOURCE,
                ),
            ]
        )
        engine.exclude_evidence(
            "evt-tx-1",
            "disputed",
            operator="analyst-1",
            decided_at=250,
        )
        ledger = CaseLedger(engine)
        ledger.register_case("case-a")
        ledger.register_transactions_from_engine()
        proposal = ledger.propose_allocation(
            case_id="case-a",
            transaction_id="tx-1",
            amount=500.0,
            operator="analyst-2",
            proposed_at=300,
            reason="attribute loss",
        )
        preview = proposal.preview
        self.assertEqual(preview.affected_transaction_ids, ("tx-1",))
        self.assertEqual(preview.case_totals_before["case-a"], 0.0)
        self.assertEqual(preview.case_totals_after["case-a"], 500.0)
        self.assertTrue(preview.rule_hits)
        self.assertTrue(
            any(
                judgment.event_id == "evt-tx-1"
                for judgment in preview.manual_judgments
            )
        )
        # Nothing applied before adoption.
        self.assertEqual(ledger.case_view("case-a").confirmed_total, 0.0)
        ledger.adopt_proposal(proposal.proposal_id, adopted_at=301)
        self.assertEqual(ledger.case_view("case-a").confirmed_total, 500.0)

    def test_rejected_proposal_has_no_effect(self) -> None:
        ledger = build_ledger()
        proposal = ledger.propose_allocation(
            case_id="case-a",
            transaction_id="tx-1",
            amount=100.0,
            operator="analyst",
            proposed_at=1,
            reason="try",
        )
        ledger.reject_proposal(proposal.proposal_id, rejected_at=2)
        self.assertEqual(
            ledger.proposal(proposal.proposal_id).status,
            ProposalStatus.REJECTED,
        )
        self.assertEqual(ledger.case_view("case-a").confirmed_total, 0.0)
        with self.assertRaises(ValueError):
            ledger.adopt_proposal(proposal.proposal_id, adopted_at=3)

    def test_merge_cases_moves_attributions(self) -> None:
        ledger = build_ledger()
        allocate(ledger, "case-a", "tx-1", 500.0, at=10)
        proposal = ledger.propose_merge(
            source_case_id="case-a",
            target_case_id="case-b",
            operator="lead",
            proposed_at=20,
            reason="same investigation",
        )
        self.assertEqual(proposal.kind, ProposalKind.MERGE_CASES)
        self.assertEqual(proposal.preview.case_totals_after["case-b"], 500.0)
        ledger.adopt_proposal(proposal.proposal_id, adopted_at=21)
        self.assertEqual(ledger.case_view("case-b").confirmed_total, 500.0)
        self.assertEqual(ledger.case_view("case-a").confirmed_total, 0.0)
        self.assertEqual(
            ledger.case_view("case-a").status, CaseStatus.MERGED
        )

    def test_move_partial_share_to_other_case(self) -> None:
        ledger = build_ledger()
        decision_id = allocate(ledger, "case-a", "tx-1", 500.0, at=10)
        proposal = ledger.propose_move(
            decision_id=decision_id,
            target_case_id="case-b",
            amount=200.0,
            operator="lead",
            proposed_at=20,
            reason="split ownership",
        )
        ledger.adopt_proposal(proposal.proposal_id, adopted_at=21)
        self.assertEqual(ledger.case_view("case-a").confirmed_total, 300.0)
        self.assertEqual(ledger.case_view("case-b").confirmed_total, 200.0)
        reconciliation = ledger.transaction_reconciliation("tx-1")
        self.assertTrue(reconciliation.reconciles)
        self.assertEqual(reconciliation.confirmed_total, 500.0)


class SealingAndReplayTest(unittest.TestCase):
    def test_sealed_case_keeps_snapshot_after_late_revision(self) -> None:
        ledger = build_ledger()
        allocate(ledger, "case-a", "tx-1", 500.0, at=10)
        sealed = ledger.seal_case("case-a", sealed_at=100)
        self.assertEqual(sealed.status, CaseStatus.SEALED)
        allocate(ledger, "case-a", "tx-2", 300.0, at=110)
        view = ledger.case_view("case-a")
        self.assertEqual(view.status, CaseStatus.REVISED)
        self.assertEqual(view.confirmed_total, 800.0)
        snapshot = ledger.sealed_snapshot("case-a")
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.confirmed_total, 500.0)
        causes = [
            revision.cause for revision in ledger.case_history("case-a")
        ]
        self.assertIn(ChangeCause.SEAL, causes)
        self.assertIn(ChangeCause.MANUAL, causes)

    def test_late_evidence_on_sealed_case_revises(self) -> None:
        ledger = build_ledger()
        allocate(ledger, "case-a", "tx-1", 500.0, at=10)
        ledger.seal_case("case-a", sealed_at=100)
        ledger.register_transaction("tx-1", 450.0, occurred_at=120)
        view = ledger.case_view("case-a")
        self.assertEqual(view.status, CaseStatus.REVISED)
        reconciliation = ledger.transaction_reconciliation("tx-1")
        self.assertEqual(reconciliation.original_amount, 450.0)
        self.assertTrue(reconciliation.reconciles)

    def test_replay_reconciles_to_original_amounts(self) -> None:
        ledger = build_ledger()
        allocate(ledger, "case-a", "tx-1", 200.0, at=10)
        allocate(ledger, "case-b", "tx-1", 500.0, at=20)
        allocate(ledger, "case-b", "tx-2", 300.0, at=30)
        ledger.seal_case("case-b", sealed_at=100)
        allocate(ledger, "case-a", "tx-2", 300.0, at=110)
        reconciliations = ledger.replay()
        by_id = {item.transaction_id: item for item in reconciliations}
        self.assertEqual(
            by_id["tx-1"].confirmed_total + by_id["tx-1"].disputed_total
            + by_id["tx-1"].unallocated,
            500.0,
        )
        self.assertEqual(
            by_id["tx-2"].confirmed_total + by_id["tx-2"].disputed_total
            + by_id["tx-2"].unallocated,
            300.0,
        )
        # Cross-case duplicate material stays disputed, never double counted.
        self.assertEqual(by_id["tx-1"].disputed_total, 200.0)
        self.assertEqual(by_id["tx-1"].confirmed_total, 300.0)
        self.assertEqual(by_id["tx-2"].disputed_total, 300.0)
        # Historical explanations remain independently viewable.
        history_b = ledger.case_history("case-b")
        self.assertTrue(history_b)
        sealed_views = [
            revision.view
            for revision in history_b
            if revision.cause == ChangeCause.SEAL
        ]
        self.assertEqual(sealed_views[0].confirmed_total, 600.0)


if __name__ == "__main__":
    unittest.main()
