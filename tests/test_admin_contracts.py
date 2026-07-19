import uuid

import pytest
from pydantic import ValidationError

from app.routes.admin_routes import (
    BulkApprovalRequest,
    CommunicationRequest,
    FindingUpdateRequest,
    SavedViewRequest,
    UserLimitRequest,
    UserSubscriptionRequest,
)


def test_admin_limits_are_bounded() -> None:
    assert UserLimitRequest(scan_limit=0).scan_limit == 0
    assert UserLimitRequest(scan_limit=99999).scan_limit == 99999
    with pytest.raises(ValidationError):
        UserLimitRequest(scan_limit=100000)
    with pytest.raises(ValidationError):
        UserLimitRequest(scan_limit=-1)


def test_subscription_and_communication_contracts_reject_unknown_values() -> None:
    assert UserSubscriptionRequest(subscription_tier="team", subscription_status="active").subscription_tier == "team"
    with pytest.raises(ValidationError):
        UserSubscriptionRequest(subscription_tier="unlimited")
    with pytest.raises(ValidationError):
        CommunicationRequest(title="", message="A message")


def test_admin_mutation_contracts_keep_reason_comment_and_saved_view_bounded() -> None:
    user_id = uuid.uuid4()
    request = BulkApprovalRequest(user_ids=[user_id], is_approved=False, reason="manual review")
    assert request.reason == "manual review"
    finding = FindingUpdateRequest(status="resolved", comment="Reviewed by admin")
    assert finding.status == "resolved"
    view = SavedViewRequest(name="Critical queue", path="/admin/findings", filters={"severity": "Critical"})
    assert view.filters["severity"] == "Critical"
