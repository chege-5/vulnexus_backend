from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.models.db_models import ScanStatus
from app.models.pydantic_models import ReportAIQuestionRequest
from app.routes import report_routes


class _Result:
    def __init__(self, *, scalar=None, items=None):
        self.scalar = scalar
        self.items = items or []

    def scalar_one_or_none(self):
        return self.scalar

    def scalars(self):
        return SimpleNamespace(all=lambda: self.items)


class _Session:
    def __init__(self, scan, vulnerabilities):
        self._results = [_Result(scalar=scan), _Result(items=vulnerabilities)]

    async def execute(self, _statement):
        return self._results.pop(0)


def test_report_ai_question_requires_non_whitespace_text():
    with pytest.raises(ValueError, match="question must contain text"):
        ReportAIQuestionRequest(question="   ")


@pytest.mark.asyncio
async def test_report_ai_question_uses_only_owned_completed_scan_context(monkeypatch):
    user_id = uuid4()
    scan = SimpleNamespace(
        id=uuid4(),
        user_id=user_id,
        status=ScanStatus.COMPLETED.value,
        target="https://example.com",
        type="url",
        overall_score=75,
    )
    vulnerability = SimpleNamespace(
        rule_id="missing-hsts",
        description="Strict-Transport-Security header is missing",
        severity="High",
        cve_id=None,
        cvss_score=None,
        remediation="Add a Strict-Transport-Security header",
        cwe_ids=["CWE-319"],
        owasp_category="A02:2021-Cryptographic Failures",
        known_exploit=False,
    )
    captured = {}

    def answer_report_question(*, question, report_context):
        captured["question"] = question
        captured["context"] = report_context
        return {"answer": "Prioritize HSTS.", "provider": "test", "label": "AI-assisted answer; validate against the scan evidence.", "title": "Security report"}

    monkeypatch.setattr(report_routes.llm_engine, "answer_report_question", answer_report_question)
    response = await report_routes.ask_report_ai.__wrapped__(
        scan.id,
        SimpleNamespace(question="What should I fix first?"),
        None,
        _Session(scan, [vulnerability]),
        SimpleNamespace(id=user_id),
    )

    assert response["answer"] == "Prioritize HSTS."
    assert captured["question"] == "What should I fix first?"
    assert captured["context"]["target"] == "https://example.com"
    assert captured["context"]["evidence"][0]["rule_id"] == "missing-hsts"


@pytest.mark.asyncio
async def test_report_ai_question_rejects_another_users_scan():
    owner_id = uuid4()
    scan = SimpleNamespace(id=uuid4(), user_id=owner_id, status=ScanStatus.COMPLETED.value)

    with pytest.raises(report_routes.HTTPException) as exc_info:
        await report_routes.ask_report_ai.__wrapped__(
            scan.id,
            SimpleNamespace(question="Summarize this report"),
            None,
            _Session(scan, []),
            SimpleNamespace(id=uuid4()),
        )

    assert exc_info.value.status_code == 403
