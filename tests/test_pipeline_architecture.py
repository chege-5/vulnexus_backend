from __future__ import annotations

import pytest

from app.services.ai.risk_engine import AIRiskEngine
from app.services.correlation.engine import CorrelationEngine
from app.services.integrations.cache import IntegrationCache
from app.services.models.pipeline import CorrelatedFinding, EnrichedFinding, RawFinding


def test_integration_cache_key_structure():
    cache = IntegrationCache(default_ttl=120)
    key = cache.build_key("provider:nvd", "CVE-2024-1234", limit=5, vendor="apache")
    assert key.startswith("vulnexus:provider:nvd:")
    assert "cve-2024-1234" in key
    assert "limit=5" in key
    assert "vendor=apache" in key


@pytest.mark.asyncio
async def test_correlation_engine_maps_configuration_weaknesses():
    engine = CorrelationEngine()
    raw_finding = RawFinding(
        type="header",
        title="Missing CSP",
        description="Content Security Policy header missing",
        severity="Low",
        source="headers",
        tags=["headers"],
    )

    correlated = await engine.correlate([raw_finding])

    assert len(correlated) == 1
    assert correlated[0].finding.cwe_ids == ["CWE-693"]
    assert correlated[0].finding.requires_cve_lookup is False


class _StaticRiskModel:
    def predict(self, features):
        from app.models.pydantic_models import MLPrediction

        return MLPrediction(score=80, severity="High")


def test_ai_risk_engine_hybrid_scoring():
    finding = EnrichedFinding(
        finding=CorrelatedFinding(
            group_key="header:example.com:missing csp",
            title="Missing CSP",
            description="Content Security Policy header missing",
            severity="Medium",
            cwe_ids=["CWE-693"],
            confidence=0.9,
        ),
        references=["https://example.com/security"],
        cvss_score=7.5,
        epss_score=0.4,
        kev=True,
    )

    engine = AIRiskEngine(model=_StaticRiskModel())
    risk = engine.evaluate([finding], asset_exposure=0.7, business_impact=0.8)

    assert risk.model == "hybrid"
    assert risk.score > 0
    assert risk.severity in {"Medium", "High", "Critical"}