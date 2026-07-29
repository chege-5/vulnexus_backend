from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.models.db_models import ScanStatus
from app.services.ai.explanations import AIRemediationResult, AIRemediationRetryable, FindingRemediation
from app.services.orchestration.scan_orchestrator import ScanOrchestrator


def _remediation(finding_id: str) -> FindingRemediation:
    return FindingRemediation(
        finding_id=finding_id,
        risk_explanation="The finding can weaken the target security posture if left unresolved.",
        mitigation_steps=["Apply the documented secure configuration."],
        short_example_scenario="An attacker could target the insecure configuration in an exposed environment.",
        safe_guidance="Validate the change in a controlled environment before production deployment.",
        validation_steps=["Rerun the same scan and confirm the rule is no longer present."],
        limitations="This remediation does not prove exploitability or verify the deployed change.",
    )


def _scan_and_vulnerabilities(count: int = 8):
    scan_id = uuid4()
    scan = SimpleNamespace(
        id=scan_id,
        status=ScanStatus.COMPLETED.value,
        ai_review_status="pending",
        ai_review_error=None,
        result_metadata={"ai_remediation": {"attempts": 0, "provider_attempts": []}},
        type="url",
        target="https://example.com",
    )
    vulnerabilities = [
        SimpleNamespace(
            id=uuid4(), rule_id=f"RULE-{index}", severity="Medium", evidence={}, cwe_ids=[],
            owasp_category=None, file_path=None, line_number=None, remediation="Apply the documented secure setting.",
            ai_explanation=None, ai_explanation_updated_at=None,
        )
        for index in range(count)
    ]
    return scan, vulnerabilities


class _Result:
    def __init__(self, scan=None, vulnerabilities=None):
        self.scan = scan
        self.vulnerabilities = vulnerabilities

    def scalar_one_or_none(self):
        return self.scan

    def scalars(self):
        return self

    def all(self):
        return self.vulnerabilities


class _Session:
    def __init__(self, scan, vulnerabilities):
        self.scan = scan
        self.vulnerabilities = vulnerabilities
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def execute(self, _statement):
        self.calls += 1
        return _Result(scan=self.scan) if self.calls == 1 else _Result(vulnerabilities=self.vulnerabilities)

    async def commit(self):
        return None

    async def rollback(self):
        return None


@pytest.mark.asyncio
async def test_sixteen_finding_scan_is_completed_only_when_all_sixteen_validate(monkeypatch):
    scan, vulnerabilities = _scan_and_vulnerabilities(16)
    session = _Session(scan, vulnerabilities)
    calls = []

    async def remediate(*, payload):
        ids = [item["finding_id"] for item in payload["findings"]]
        calls.append(ids)
        return AIRemediationResult("nvidia", [_remediation(finding_id) for finding_id in ids], [{"provider": "nvidia", "model": "test", "result_count": len(ids), "invalid_count": 0}], [])

    monkeypatch.setattr("app.services.orchestration.scan_orchestrator.database.async_session_maker", lambda: session)
    monkeypatch.setattr("app.services.orchestration.scan_orchestrator.ai_explanation_service.remediate", remediate)
    monkeypatch.setattr("app.services.orchestration.scan_orchestrator.settings.AI_REMEDIATION_BATCH_SIZE", 2)

    result = await ScanOrchestrator().run_ai_review(scan.id)

    workflow = scan.result_metadata["ai_remediation"]
    assert result["ai_review_status"] == "completed"
    assert scan.status == ScanStatus.COMPLETED.value
    assert [len(batch) for batch in calls] == [2, 2, 2, 2, 2, 2, 2, 2]
    assert workflow["total_eligible_findings"] == 16
    assert workflow["ai_completed_count"] == 16
    assert workflow["ai_pending_retrying_count"] == 0
    assert workflow["ai_failed_final_count"] == 0
    assert {state["status"] for state in workflow["finding_states"].values()} == {"ai_completed"}
    assert all(item.ai_explanation for item in vulnerabilities)


@pytest.mark.asyncio
async def test_one_valid_of_eight_requeues_only_the_seven_unresolved_ids(monkeypatch):
    scan, vulnerabilities = _scan_and_vulnerabilities()
    session = _Session(scan, vulnerabilities)

    async def partial(*, payload):
        ids = [item["finding_id"] for item in payload["findings"]]
        return AIRemediationResult(
            "nvidia", [_remediation(ids[0])],
            [{"provider": "nvidia", "model": "test", "result_count": 1, "invalid_count": 7, "error_category": "partial_invalid_response"}],
            ids[1:], "partial_invalid_response", True,
        )

    monkeypatch.setattr("app.services.orchestration.scan_orchestrator.database.async_session_maker", lambda: session)
    monkeypatch.setattr("app.services.orchestration.scan_orchestrator.ai_explanation_service.remediate", partial)
    monkeypatch.setattr("app.services.orchestration.scan_orchestrator.settings.AI_REMEDIATION_BATCH_SIZE", 8)

    with pytest.raises(AIRemediationRetryable):
        await ScanOrchestrator().run_ai_review(scan.id)

    workflow = scan.result_metadata["ai_remediation"]
    states = workflow["finding_states"]
    assert scan.status == ScanStatus.COMPLETED.value
    assert scan.ai_review_status == "retrying"
    assert workflow["ai_completed_count"] == 1
    assert workflow["ai_pending_retrying_count"] == 7
    assert workflow["ai_failed_final_count"] == 0
    assert sum(state["status"] == "ai_completed" for state in states.values()) == 1
    assert sum(state["status"] == "ai_retrying" for state in states.values()) == 7
    assert sum(item.ai_explanation is not None for item in vulnerabilities) == 1
