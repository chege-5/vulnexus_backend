from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models.db_models import public_ai_review_status
from app.routes import scan_routes
from app import rate_limit
from app import main


@pytest.mark.parametrize(
    ("stored", "public"),
    [
        ("completed", "completed"),
        ("completed_ai", "completed"),
        ("partial", "partial"),
        ("failed", "failed"),
        ("not_required", "skipped"),
        ("unknown_legacy_value", "pending"),
    ],
)
def test_public_ai_review_status_contract(stored, public):
    assert public_ai_review_status(stored) == public


class _Result:
    def __init__(self, scan):
        self.scan = scan

    def scalar_one_or_none(self):
        return self.scan


class _Session:
    def __init__(self, scan):
        self.scan = scan

    async def execute(self, _statement):
        return _Result(self.scan)


def _scan(owner_id, status, workflow=None):
    return SimpleNamespace(
        id=uuid4(),
        user_id=owner_id,
        ai_review_status=status,
        ai_review_error="provider_final_failure" if status == "failed" else None,
        result_metadata={
            "ai_review": {
                "summary": "AI-assisted remediation is available for every eligible finding.",
                "findings_reviewed": 16,
                "total_eligible_findings": 16,
                "ai_completed_count": 16,
                "ai_pending_retrying_count": 0,
                "ai_failed_final_count": 0,
                "provider": "nvidia",
            },
            "ai_remediation": workflow or {
                "ai_completed_count": 16,
                "total_eligible_findings": 16,
                "ai_pending_retrying_count": 0,
                "ai_failed_final_count": 0,
            },
        },
    )


@pytest.mark.asyncio
async def test_owner_reads_legacy_completed_ai_as_completed_with_summary_counts():
    owner = SimpleNamespace(id=uuid4())
    scan = _scan(owner.id, "completed_ai")

    response = await scan_routes.ai_review_status.__wrapped__(scan.id, None, _Session(scan), owner)

    assert response.ai_review_status == "completed"
    assert response.review["provider"] == "nvidia"
    assert response.ai_completed_count == 16
    assert response.total_eligible_findings == 16
    assert response.ai_failed_final_count == 0


@pytest.mark.asyncio
async def test_partial_and_failed_states_are_not_reported_as_completed():
    owner = SimpleNamespace(id=uuid4())
    partial = _scan(owner.id, "partial", {
        "ai_completed_count": 12,
        "total_eligible_findings": 16,
        "ai_pending_retrying_count": 0,
        "ai_failed_final_count": 4,
    })
    partial_response = await scan_routes.ai_review_status.__wrapped__(partial.id, None, _Session(partial), owner)
    assert partial_response.ai_review_status == "partial"
    assert partial_response.ai_completed_count == 12
    assert partial_response.ai_failed_final_count == 4

    failed = _scan(owner.id, "failed")
    failed_response = await scan_routes.ai_review_status.__wrapped__(failed.id, None, _Session(failed), owner)
    assert failed_response.ai_review_status == "failed"
    assert failed_response.review is None


@pytest.mark.asyncio
async def test_non_owner_cannot_read_ai_remediation_status():
    owner = SimpleNamespace(id=uuid4())
    scan = _scan(owner.id, "completed")
    with pytest.raises(HTTPException) as exc_info:
        await scan_routes.ai_review_status.__wrapped__(scan.id, None, _Session(scan), SimpleNamespace(id=uuid4()))
    assert exc_info.value.status_code == 403


def test_authenticated_scan_rate_limit_key_is_partitioned_by_user_and_scan(monkeypatch):
    request = SimpleNamespace(
        headers={"Authorization": "Bearer signed-access-token"},
        path_params={"scan_id": "scan-123"},
        client=SimpleNamespace(host="203.0.113.10"),
    )
    monkeypatch.setattr(rate_limit, "decode_token_subject", lambda token: "user-123")
    assert rate_limit.authenticated_scan_key(request) == "user:user-123:scan:scan-123"


def test_invalid_token_rate_limit_key_falls_back_to_ip_and_scan(monkeypatch):
    request = SimpleNamespace(
        headers={"Authorization": "Bearer invalid"},
        path_params={"scan_id": "scan-123"},
        client=SimpleNamespace(host="203.0.113.10"),
    )
    monkeypatch.setattr(rate_limit, "decode_token_subject", lambda token: (_ for _ in ()).throw(ValueError("bad token")))
    assert rate_limit.authenticated_scan_key(request) == "ip:203.0.113.10:scan:scan-123"


def test_rate_limit_response_always_has_retry_after(monkeypatch):
    from fastapi.responses import JSONResponse

    monkeypatch.setattr(main, "_rate_limit_exceeded_handler", lambda request, exc: JSONResponse({"detail": "limited"}, status_code=429))
    response = main.rate_limit_exceeded_handler(SimpleNamespace(), SimpleNamespace())
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "10"
