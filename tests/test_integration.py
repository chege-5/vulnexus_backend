import pytest
import os
import uuid
from unittest.mock import patch, AsyncMock, MagicMock
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.models.pydantic_models import CryptoFeatures
from app.services.rule_engine import evaluate_rules, compute_rule_score
from app.services.report_generator import generate_html_report, get_remediation


@pytest.fixture
def sample_features():
    return CryptoFeatures(
        uses_md5=True,
        uses_des=True,
        hardcoded_key=True,
        rule_score=60,
    )


def test_rule_engine(sample_features):
    vulns, score = evaluate_rules([sample_features])
    assert len(vulns) > 0
    assert score > 0
    rule_ids = [v.rule_id for v in vulns]
    assert "USES_MD5" in rule_ids
    assert "USES_DES" in rule_ids
    assert "HARDCODED_KEY" in rule_ids


def test_compute_rule_score(sample_features):
    score = compute_rule_score(sample_features)
    assert score >= 50


def test_report_generation():
    html = generate_html_report(
        scan_id="test-123",
        target="https://example.com",
        scan_type="url",
        overall_score=75.5,
        vulnerabilities=[
            {
                "rule_id": "USES_MD5",
                "description": "MD5 hash detected",
                "severity": "Medium",
                "ml_score": 60,
                "cve_id": None,
                "file_path": None,
                "line_number": None,
                "remediation": "Replace MD5 with SHA-256",
            }
        ],
        cve_details=[
            {"cve_id": "CVE-2004-2761", "cvss_score": 5.0, "summary": "MD5 collision", "published_date": "2008-01-01"}
        ],
    )
    assert "VulNexus" in html
    assert "test-123" in html
    assert "MD5" in html
    assert "75.5" in html


def test_remediation_map():
    assert "SHA-256" in get_remediation("USES_MD5")
    assert "AES" in get_remediation("USES_DES")
    assert len(get_remediation("UNKNOWN_RULE")) > 0


@pytest.mark.asyncio
async def test_healthz():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_upload_invalid_file():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/upload-file",
            files={"file": ("test.exe", b"binary content", "application/octet-stream")},
        )
        # Endpoint requires authentication, so expect 401 without token
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_scan_status_not_found():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        fake_id = str(uuid.uuid4())
        r = await client.get(f"/api/v1/scan-status/{fake_id}")
        # Endpoint requires authentication, so expect 401 without token
        assert r.status_code == 401
