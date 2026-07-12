from __future__ import annotations

import logging
from uuid import uuid4

import pytest

from app.models.db_models import Vulnerability
from app.services.correlation.engine import CorrelationEngine
from app.services.models.pipeline import CorrelatedFinding, EnrichedFinding, RawFinding
from app.services.orchestration.scan_orchestrator import ScanOrchestrator


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
