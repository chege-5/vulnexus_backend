from __future__ import annotations

import importlib

import pytest

from app.services.correlation.engine import CorrelationEngine
from app.services.finding_classifier import FindingClassification, classify_raw_finding
from app.services.integrations.base import ProviderSettings
from app.services.integrations.providers.censys import CensysProvider
from app.services.integrations.providers.shodan import ShodanProvider
from app.services.intelligence.service import IntelligenceService
from app.services.models.pipeline import RawFinding
from app.services.report_generator import get_finding_title


knowledge_engine_module = importlib.import_module("app.services.intelligence.knowledge_engine")
intelligence_service_module = importlib.import_module("app.services.intelligence.service")
knowledge_engine = knowledge_engine_module.knowledge_engine


def _raw(rule_id: str, title: str, *, finding_type: str = "tls", evidence: dict | None = None, raw_data: dict | None = None) -> RawFinding:
    return RawFinding(
        type=finding_type,
        title=title,
        description=title,
        severity="Medium",
        evidence=evidence or {},
        raw_data={"rule_id": rule_id, **(raw_data or {})},
        source="test",
        tags=["tls"],
    )


@pytest.mark.asyncio
async def test_crypto_and_certificate_findings_do_not_trigger_cve_lookup(monkeypatch):
    raw_findings = [
        _raw("MISSING_MODERN_TLS", "TLSv1.3 is not supported"),
        _raw("EXPIRED_CERT", "Expired TLS certificate"),
        _raw("CERT_HOSTNAME_MISMATCH", "TLS certificate hostname mismatch"),
        _raw("WEAK_CIPHER_SUITE", "Weak TLS cipher suites accepted"),
    ]

    correlated = await CorrelationEngine().correlate(raw_findings)
    calls = []

    async def fake_lookup(*args, **kwargs):
        calls.append((args, kwargs))
        return []

    async def no_cache_get(*args, **kwargs):
        return None

    async def no_cache_set(*args, **kwargs):
        return None

    monkeypatch.setattr(knowledge_engine_module.cache, "get_json", no_cache_get)
    monkeypatch.setattr(knowledge_engine_module.cache, "set_json", no_cache_set)
    monkeypatch.setattr(knowledge_engine_module.integration_manager, "lookup", fake_lookup)

    for finding in correlated:
        assert finding.requires_cve_lookup is False
        assert finding.classification in {
            FindingClassification.PROTOCOL_SUPPORT_ISSUE.value,
            FindingClassification.CERTIFICATE_TRUST_FAILURE.value,
            FindingClassification.CRYPTOGRAPHIC_CONFIG_WEAKNESS.value,
        }
        await knowledge_engine.enrich(finding)

    assert calls == []


@pytest.mark.asyncio
async def test_openssl_version_finding_triggers_cve_lookup(monkeypatch):
    raw_finding = RawFinding(
        type="technology",
        title="OpenSSL 1.0.2u installed",
        description="Detected OpenSSL 1.0.2u on the target host",
        severity="High",
        evidence={"product": "OpenSSL", "version": "1.0.2u"},
        raw_data={"product": "OpenSSL", "version": "1.0.2u"},
        source="technology",
        tags=["technology"],
    )
    correlated = (await CorrelationEngine().correlate([raw_finding]))[0]
    calls = []

    async def fake_lookup(query, *, providers=None, context=None, limit=5):
        calls.append({"query": query, "providers": providers, "context": context})
        return []

    async def no_cache_get(*args, **kwargs):
        return None

    async def no_cache_set(*args, **kwargs):
        return None

    monkeypatch.setattr(knowledge_engine_module.cache, "get_json", no_cache_get)
    monkeypatch.setattr(knowledge_engine_module.cache, "set_json", no_cache_set)
    monkeypatch.setattr(knowledge_engine_module.integration_manager, "lookup", fake_lookup)

    assert correlated.classification == FindingClassification.SOFTWARE_VULNERABILITY.value
    assert correlated.requires_cve_lookup is True
    await knowledge_engine.enrich(correlated)

    assert calls
    assert calls[0]["query"] == "OpenSSL 1.0.2u"
    assert {"nvd", "epss", "cisa", "mitre"}.issubset(set(calls[0]["providers"]))


@pytest.mark.asyncio
async def test_intelligence_service_sanitizes_external_lookup_context(monkeypatch):
    calls = []

    async def fake_enrich(query, *, context=None, providers=None, limit=5):
        calls.append({"query": query, "context": context, "providers": providers})
        return []

    async def no_cache_get(*args, **kwargs):
        return None

    async def no_cache_set(*args, **kwargs):
        return None

    monkeypatch.setattr(intelligence_service_module.cache, "get", no_cache_get)
    monkeypatch.setattr(intelligence_service_module.cache, "set", no_cache_set)
    monkeypatch.setattr(intelligence_service_module.integration_manager, "enrich_intelligence", fake_enrich)

    service = IntelligenceService()
    await service.map_finding(
        "OpenSSL 1.0.2u installed",
        description="Detected OpenSSL 1.0.2u",
        metadata={
            "product": "OpenSSL",
            "version": "1.0.2u",
            "san_dns_names": ["a.example", "b.example"],
            "validation_error": "certificate verify failed with a long raw error",
            "raw_evidence": {"certificate": "full dump"},
        },
    )

    assert calls[0]["query"] == "OpenSSL 1.0.2u"
    assert calls[0]["context"] == {
        "product": "OpenSSL",
        "version": "1.0.2u",
        "classification": FindingClassification.SOFTWARE_VULNERABILITY.value,
    }


@pytest.mark.asyncio
async def test_shodan_403_and_censys_401_are_provider_failures():
    class Response:
        def __init__(self, status_code: int, text: str):
            self.status_code = status_code
            self.text = text

    class Client:
        def __init__(self, response: Response):
            self.response = response

        async def get(self, *args, **kwargs):
            return self.response

    shodan = ShodanProvider(ProviderSettings(name="shodan", api_key="key", endpoint="https://shodan.example"))
    censys = CensysProvider(ProviderSettings(name="censys", api_key="secret", endpoint="https://censys.example", extra={"api_id": "id"}))

    shodan_response = await shodan.lookup(Client(Response(403, "forbidden")), "203.0.113.10")
    censys_response = await censys.lookup(Client(Response(401, "unauthorized")), "203.0.113.10")

    assert shodan_response.success is False
    assert shodan_response.status_code == 403
    assert censys_response.success is False
    assert censys_response.status_code == 401


def test_classifier_and_report_titles_are_human_readable():
    expired = _raw("EXPIRED_CERT", "Expired TLS certificate")
    mismatch = _raw("CERT_HOSTNAME_MISMATCH", "TLS certificate hostname mismatch")
    weak_cipher = _raw("WEAK_CIPHER_SUITE", "Weak TLS cipher suites accepted")

    assert classify_raw_finding(expired) == FindingClassification.CERTIFICATE_TRUST_FAILURE
    assert classify_raw_finding(mismatch) == FindingClassification.CERTIFICATE_TRUST_FAILURE
    assert classify_raw_finding(weak_cipher) == FindingClassification.CRYPTOGRAPHIC_CONFIG_WEAKNESS
    assert get_finding_title({"rule_id": "EXPIRED_CERT", "title": None}) == "Expired X.509 Certificate"
    assert get_finding_title({"rule_id": "CERT_HOSTNAME_MISMATCH", "title": None}) == "Certificate Hostname Validation Failed"
