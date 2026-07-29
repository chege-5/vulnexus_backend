from __future__ import annotations

import logging
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import BaseModel

from app.models.db_models import ComplianceCheck, Vulnerability
from app.services.correlation.engine import CorrelationEngine
from app.services.models.pipeline import CorrelatedFinding, EnrichedFinding, RawFinding, RiskScore
from app.services.orchestration.scan_orchestrator import ScanOrchestrator, ScanPersistenceError


WINDOWS_SAMPLE_PATH = (
    r"C:\Users\JIMM\OneDrive\Desktop\4th_project\system\vulnexus_Backend"
    r"\uploads\019f2d60-0000-7000-8000-000000000001\weak_crypto_modes_sample.py"
)


def _enriched(incident: CorrelatedFinding, *, cve_id: str | None = None) -> EnrichedFinding:
    return EnrichedFinding(finding=incident, cve_id=cve_id, references=["https://example.test/ref"])


def _incident(
    *,
    rule_id: str,
    group_key: str | None = None,
    file_path: str = WINDOWS_SAMPLE_PATH,
    line_number: int = 1,
) -> CorrelatedFinding:
    raw = RawFinding(
        type="secret",
        title=rule_id,
        description="Weak cryptographic mode detected",
        severity="High",
        evidence={
            "rule_id": rule_id,
            "source_rule_id": rule_id,
            "file_path": file_path,
            "line_number": line_number,
            "line_preview": "cipher = AES.MODE_ECB",
        },
        location=f"{file_path}:{line_number}",
        raw_data={"rule_id": rule_id, "source_rule_id": rule_id},
        tags=["secrets", "source", "cryptography"],
    )
    return CorrelatedFinding(
        group_key=group_key or f"{file_path}:{line_number}:transport:tls_pki_crypto_posture",
        correlation_id="VN-CORR-CRYPTO-001",
        contributing_rule_ids=[rule_id],
        title="Weak cryptographic mode detected",
        description="Weak cryptographic mode detected",
        severity="High",
        cwe_ids=["CWE-327"],
        evidence={
            "file_path": file_path,
            "line_number": line_number,
            "line_preview": "cipher = AES.MODE_ECB",
        },
        raw_findings=[raw],
    )


def test_yaml_rule_id_persists_unchanged_even_when_group_key_contains_path() -> None:
    orchestrator = ScanOrchestrator()
    incident = _incident(rule_id="WEAK_CIPHER_AES-ECB")
    diagnostics: dict = {}

    rule_id = orchestrator._normalize_rule_id(incident, 1, diagnostics)

    assert rule_id == "WEAK_CIPHER_AES-ECB"
    assert WINDOWS_SAMPLE_PATH not in rule_id
    assert diagnostics == {}


def test_long_windows_path_is_file_path_not_rule_id() -> None:
    orchestrator = ScanOrchestrator()
    incident = _incident(rule_id="WEAK_CIPHER_AES-ECB")
    record = orchestrator._validated_vulnerability_record(
        scan_id=uuid4(),
        finding_index=1,
        rule_id=orchestrator._normalize_rule_id(incident, 1, {}),
        incident=incident,
        finding=_enriched(incident),
        risk_score=72.0,
        remediation="Use authenticated encryption.",
        profile={"owasp_category": "A02 Cryptographic Failures", "nist_control": "SC-13", "mitre_technique": "T1573"},
        diagnostics={},
    )

    assert record["rule_id"] == "WEAK_CIPHER_AES-ECB"
    assert record["file_path"] == WINDOWS_SAMPLE_PATH
    assert len(record["file_path"]) > 128
    assert record["line_number"] == 1


@pytest.mark.asyncio
async def test_correlation_preserves_contributing_rule_ids() -> None:
    findings = [
        RawFinding(
            type="secret",
            title="Weak mode",
            description="Weak mode",
            severity="High",
            correlation_group="crypto-source-group",
            raw_data={"rule_id": "WEAK_CIPHER_AES-ECB"},
        ),
        RawFinding(
            type="secret",
            title="Static IV",
            description="Static IV",
            severity="Medium",
            correlation_group="crypto-source-group",
            raw_data={"rule_id": "STATIC_IV"},
        ),
    ]

    correlated = await CorrelationEngine().correlate(findings)

    assert len(correlated) == 1
    assert correlated[0].correlation_id.startswith("VN-CORR-")
    assert correlated[0].contributing_rule_ids == ["WEAK_CIPHER_AES-ECB", "STATIC_IV"]


def test_malformed_oversized_rule_id_gets_safe_fallback_and_diagnostics(caplog: pytest.LogCaptureFixture) -> None:
    orchestrator = ScanOrchestrator()
    bad_rule_id = WINDOWS_SAMPLE_PATH + r":1:transport:tls_pki_crypto_posture:SECRET=super-sensitive-value"
    incident = _incident(rule_id=bad_rule_id, group_key=bad_rule_id)
    diagnostics: dict = {}

    with caplog.at_level(logging.WARNING):
        normalized = orchestrator._normalize_rule_id(incident, 1, diagnostics)

    assert normalized.startswith("VN-FALLBACK-")
    assert len(normalized) <= 255
    assert diagnostics["rule_id_normalized_from"] == "malformed_rule_id"
    assert "original_rule_id_hash" in diagnostics
    assert bad_rule_id not in caplog.text
    assert "super-sensitive-value" not in caplog.text


def test_multiple_findings_validate_for_one_transaction() -> None:
    orchestrator = ScanOrchestrator()
    incidents = [
        _incident(rule_id="WEAK_CIPHER_AES-ECB", line_number=1),
        _incident(rule_id="STATIC_IV", line_number=2),
    ]

    records = []
    for index, incident in enumerate(incidents, 1):
        records.append(
            orchestrator._validated_vulnerability_record(
                scan_id=uuid4(),
                finding_index=index,
                rule_id=orchestrator._normalize_rule_id(incident, index, {}),
                incident=incident,
                finding=_enriched(incident),
                risk_score=64.0,
                remediation=None,
                profile={},
                diagnostics={},
            )
        )

    assert [record["rule_id"] for record in records] == ["WEAK_CIPHER_AES-ECB", "STATIC_IV"]
    assert [record["line_number"] for record in records] == [1, 2]


def test_frontend_failure_reason_is_sanitized_and_useful() -> None:
    orchestrator = ScanOrchestrator()
    error = RuntimeError("persistence failed for token=super-sensitive-value")

    message = orchestrator._persistence_error_message(error)

    assert "persistence failed" in message
    assert "super-sensitive-value" not in message


def test_postgresql_rule_id_schema_matches_model_length() -> None:
    assert Vulnerability.__table__.c.rule_id.type.length == 255


class _ProbeState(str, Enum):
    READY = "ready"


class _ProbeModel(BaseModel):
    observed_at: datetime
    scan_id: object


class _RecordingSession:
    def __init__(self, *, fail_commit: bool = False) -> None:
        self.added = []
        self.executed = []
        self.flushed = 0
        self.committed = 0
        self.rolled_back = 0
        self.fail_commit = fail_commit

    def add(self, item) -> None:
        self.added.append(item)

    async def execute(self, statement):
        self.executed.append(statement)

    async def merge(self, item):
        return item

    async def flush(self) -> None:
        self.flushed += 1

    async def commit(self) -> None:
        self.committed += 1
        if self.fail_commit:
            raise TypeError("Object of type datetime is not JSON serializable")

    async def rollback(self) -> None:
        self.rolled_back += 1


def test_json_columns_normalize_nested_datetime_uuid_enum_decimal_set_bytes_and_pydantic() -> None:
    orchestrator = ScanOrchestrator()
    scan_id = uuid4()
    observed_at = datetime(2026, 7, 28, 10, 30, tzinfo=timezone.utc)

    encoded = orchestrator._json_column({
        "nested": {
            "observed_at": observed_at,
            "scan_id": scan_id,
            "state": _ProbeState.READY,
            "amount": Decimal("12.3400"),
            "labels": {"tls", "certificate"},
            "certificate_bytes": b"\xff\x00",
            "model": _ProbeModel(observed_at=observed_at, scan_id=scan_id),
        }
    })

    nested = encoded["nested"]
    assert nested["observed_at"] == "2026-07-28T10:30:00+00:00"
    assert nested["scan_id"] == str(scan_id)
    assert nested["state"] == "ready"
    assert nested["amount"] == "12.3400"
    assert nested["labels"] == ["certificate", "tls"]
    assert nested["certificate_bytes"] == "/wA="
    assert nested["model"]["observed_at"] in {"2026-07-28T10:30:00+00:00", "2026-07-28T10:30:00Z"}
    assert nested["model"]["scan_id"] == str(scan_id)


def test_oversized_provider_payload_is_replaced_by_a_compact_evidence_summary() -> None:
    orchestrator = ScanOrchestrator()
    incident = _incident(rule_id="URLSCAN_REPUTATION")
    incident.evidence = {
        "provider": "URLSCAN",
        "summary": "urlscan.io search result",
        "raw": {
            "results": [{"page": {"html": "x" * 25000}}],
            "submitted_at": datetime(2026, 7, 28, tzinfo=timezone.utc),
        },
    }
    record = orchestrator._validated_vulnerability_record(
        scan_id=uuid4(),
        finding_index=1,
        rule_id="URLSCAN_REPUTATION",
        incident=incident,
        finding=_enriched(incident),
        risk_score=55.0,
        remediation=None,
        profile={},
        diagnostics={},
    )

    provider_payload = record["evidence"]["raw"]
    assert provider_payload["provider"] == "URLSCAN"
    assert provider_payload["raw_response_omitted"] is True
    assert provider_payload["collection_counts"] == {"results": 1}
    assert "x" * 100 not in str(record["evidence"])


@pytest.mark.asyncio
async def test_failed_persistence_rolls_back_without_reusing_orm_attributes(monkeypatch) -> None:
    orchestrator = ScanOrchestrator()
    scan_id = uuid4()
    db = _RecordingSession(fail_commit=True)
    scan = SimpleNamespace(
        id=scan_id,
        target="https://expired.example.test",
        type="url",
        started_at=datetime.now(timezone.utc),
        result_metadata={},
    )
    incident = _incident(rule_id="EXPIRED_CERT", file_path="https://expired.example.test")
    finding = _enriched(incident)
    context = SimpleNamespace(options={})
    risk = RiskScore(score=82, severity="High", rationale="test")
    monkeypatch.setattr("app.services.orchestration.scan_orchestrator.build_report", lambda **_kwargs: None)

    with pytest.raises(ScanPersistenceError):
        await orchestrator._persist_results(db, scan, context, [finding], risk)

    assert db.flushed == 1
    assert db.rolled_back == 1


@pytest.mark.asyncio
async def test_live_url_finding_persists_with_json_safe_certificate_evidence(monkeypatch) -> None:
    orchestrator = ScanOrchestrator()
    scan_id = uuid4()
    db = _RecordingSession()
    scan = SimpleNamespace(
        id=scan_id,
        target="https://expired.example.test",
        type="url",
        started_at=datetime.now(timezone.utc),
        result_metadata={"reputation": {"provider_statuses": [{"provider": "SHODAN", "status_code": 403, "status": "skipped"}]}},
    )
    incident = _incident(rule_id="EXPIRED_CERT", file_path="https://expired.example.test")
    incident.evidence = {
        "not_after": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "certificate_serial": uuid4(),
        "provider": "VIRUSTOTAL",
        "raw": {"data": {"attributes": {"verbose": "x" * 10000}}},
    }
    finding = _enriched(incident)
    context = SimpleNamespace(options={"scan_result_metadata": {"provider": "CENSYS", "raw": {"services": ["x" * 10000]}}})
    risk = RiskScore(score=82, severity="High", rationale="expired certificate")
    monkeypatch.setattr("app.services.orchestration.scan_orchestrator.build_report", lambda **_kwargs: None)

    async def ignore_progress(*_args, **_kwargs) -> None:
        return None

    monkeypatch.setattr(orchestrator, "_store_progress", ignore_progress)

    await orchestrator._persist_results(db, scan, context, [finding], risk)

    vulnerability = next(item for item in db.added if isinstance(item, Vulnerability))
    assert vulnerability.evidence["not_after"] == "2025-01-01T00:00:00+00:00"
    assert vulnerability.evidence["raw"]["raw_response_omitted"] is True
    assert scan.result_metadata["raw"]["raw_response_omitted"] is True
    assert db.committed == 1
    assert all(
        field is None or __import__("json").dumps(field)
        for field in (
            vulnerability.evidence,
            vulnerability.compliance_results,
            vulnerability.cwe_ids,
            vulnerability.references,
            *(item.details for item in db.added if isinstance(item, ComplianceCheck)),
        )
    )
