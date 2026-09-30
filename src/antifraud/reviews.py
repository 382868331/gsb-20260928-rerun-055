from __future__ import annotations

from dataclasses import dataclass

from .models import ManualReview, ReviewAction


@dataclass(frozen=True, slots=True)
class ReviewRequest:
    """Input for an analyst evidence review."""

    reviewed_event_id: str
    action: ReviewAction
    reviewer: str
    reason: str
    reviewed_at: int
    review_id: str | None = None

    def to_record(self) -> ManualReview:
        return ManualReview(
            reviewed_event_id=self.reviewed_event_id,
            action=self.action,
            reviewer=self.reviewer,
            reason=self.reason,
            reviewed_at=self.reviewed_at,
            review_id=self.review_id,
        )


def exclude_request(
    reviewed_event_id: str,
    *,
    reviewer: str,
    reason: str,
    reviewed_at: int,
) -> ReviewRequest:
    return ReviewRequest(
        reviewed_event_id=reviewed_event_id,
        action=ReviewAction.EXCLUDE,
        reviewer=reviewer,
        reason=reason,
        reviewed_at=reviewed_at,
    )


def withdraw_request(
    reviewed_event_id: str,
    *,
    reviewer: str,
    reason: str,
    reviewed_at: int,
) -> ReviewRequest:
    return ReviewRequest(
        reviewed_event_id=reviewed_event_id,
        action=ReviewAction.WITHDRAW,
        reviewer=reviewer,
        reason=reason,
        reviewed_at=reviewed_at,
    )
