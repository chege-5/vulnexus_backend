from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from app.services.integrations.manager import integration_manager
from app.services.intelligence.mapping import MappingDecision, build_decision
from app.services.models.pipeline import IntelligenceResult as PipelineIntelligenceResult
from app.utils.cache import cache


@dataclass(slots=True)
class IntelligenceResult:
    finding_key: str
    decision: MappingDecision
    requires_cve_lookup: bool
    cve_id: str | None = None
    cvss_score: float | None = None
    provider_hits: list[dict[str, Any]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source: str | None = None
    summary: str | None = None
    published_date: str | None = None


class IntelligenceService:
    async def map_finding(
        self,
        finding_key: str | None,
        *,
        rule_id: str | None = None,
        severity: str | None = None,
        description: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IntelligenceResult:
        decision = build_decision(finding_key, rule_id=rule_id, severity=severity, description=description, metadata=metadata)
        if not decision.requires_cve_lookup:
            return IntelligenceResult(
                finding_key=decision.finding_key,
                decision=decision,
                requires_cve_lookup=False,
                references=decision.references,
            )

        cache_key = self._build_cache_key(decision.finding_key, rule_id, description, metadata)
        cached = await cache.get("intelligence", cache_key)
        if cached:
            return self._deserialize_result(cached, decision)

        provider_results = await integration_manager.enrich_intelligence(
            decision.finding_key,
            context=metadata or {},
            providers=["nvd", "circl", "epss", "cisa", "mitre"],
        )
        provider_hits = [self._result_to_hit(item) for item in provider_results]
        best = self._select_best_hit(provider_hits)
        result = IntelligenceResult(
            finding_key=decision.finding_key,
            decision=decision,
            requires_cve_lookup=True,
            cve_id=best.get("identifier") if best else None,
            cvss_score=best.get("cvss_score") if best else None,
            provider_hits=provider_hits,
            references=self._collect_references(provider_hits, decision.references),
            source=best.get("source") if best else None,
            summary=best.get("summary") if best else None,
            published_date=best.get("published_date") if best else None,
        )
        await cache.set("intelligence", cache_key, self._serialize_result(result))
        return result

    async def enrich_many(self, findings: Iterable[dict[str, Any]]) -> list[IntelligenceResult]:
        return await asyncio.gather(
            *(
                self.map_finding(
                    finding.get("finding_key") or finding.get("rule_id") or finding.get("crypto_feature"),
                    rule_id=finding.get("rule_id"),
                    severity=finding.get("severity"),
                    description=finding.get("description"),
                    metadata=finding,
                )
                for finding in findings
            )
        )

    def _select_best_hit(self, hits: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not hits:
            return None
        ranked = sorted(
            hits,
            key=lambda item: (
                item.get("cvss_score") or 0,
                1 if item.get("source") == "NVD" else 0,
                1 if item.get("identifier") else 0,
            ),
            reverse=True,
        )
        return ranked[0]

    def _collect_references(self, hits: list[dict[str, Any]], fallback: list[str]) -> list[str]:
        references = list(dict.fromkeys(fallback))
        for hit in hits:
            for ref in hit.get("references") or []:
                if ref and ref not in references:
                    references.append(ref)
        return references

    def _build_cache_key(self, finding_key: str, rule_id: str | None, description: str | None, metadata: dict[str, Any] | None) -> str:
        payload = {"finding_key": finding_key, "rule_id": rule_id, "description": description, "metadata": metadata or {}}
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _serialize_result(self, result: IntelligenceResult) -> dict[str, Any]:
        return {
            "finding_key": result.finding_key,
            "decision": {
                "finding_key": result.decision.finding_key,
                "cwe_ids": result.decision.cwe_ids,
                "owasp_category": result.decision.owasp_category,
                "nist_control": result.decision.nist_control,
                "requires_cve_lookup": result.decision.requires_cve_lookup,
                "risk_level": result.decision.risk_level,
                "technical_explanation": result.decision.technical_explanation,
                "remediation": result.decision.remediation,
                "references": result.decision.references,
                "classification": result.decision.classification,
            },
            "requires_cve_lookup": result.requires_cve_lookup,
            "cve_id": result.cve_id,
            "cvss_score": result.cvss_score,
            "provider_hits": result.provider_hits,
            "references": result.references,
            "source": result.source,
            "summary": result.summary,
            "published_date": result.published_date,
        }

    def _deserialize_result(self, payload: dict[str, Any], default_decision: MappingDecision) -> IntelligenceResult:
        decision_payload = payload.get("decision") or {}
        decision = MappingDecision(
            finding_key=decision_payload.get("finding_key") or default_decision.finding_key,
            cwe_ids=list(decision_payload.get("cwe_ids") or default_decision.cwe_ids),
            owasp_category=decision_payload.get("owasp_category") or default_decision.owasp_category,
            nist_control=decision_payload.get("nist_control") or default_decision.nist_control,
            requires_cve_lookup=bool(decision_payload.get("requires_cve_lookup", default_decision.requires_cve_lookup)),
            risk_level=decision_payload.get("risk_level") or default_decision.risk_level,
            technical_explanation=decision_payload.get("technical_explanation") or default_decision.technical_explanation,
            remediation=decision_payload.get("remediation") or default_decision.remediation,
            references=list(decision_payload.get("references") or default_decision.references),
            classification=decision_payload.get("classification") or default_decision.classification,
        )
        return IntelligenceResult(
            finding_key=payload.get("finding_key") or decision.finding_key,
            decision=decision,
            requires_cve_lookup=bool(payload.get("requires_cve_lookup", decision.requires_cve_lookup)),
            cve_id=payload.get("cve_id"),
            cvss_score=payload.get("cvss_score"),
            provider_hits=list(payload.get("provider_hits") or []),
            references=list(payload.get("references") or []),
            source=payload.get("source"),
            summary=payload.get("summary"),
            published_date=payload.get("published_date"),
        )

    def _result_to_hit(self, result: PipelineIntelligenceResult) -> dict[str, Any]:
        return {
            "source": result.provider,
            "identifier": result.identifier,
            "summary": result.summary,
            "cvss_score": result.cvss_score,
            "severity": None,
            "published_date": None,
            "references": result.references,
            "raw": result.raw,
        }


_service = IntelligenceService()


async def map_vulnerability_to_cves(vuln_keyword: str, *, rule_id: str | None = None, severity: str | None = None, description: str | None = None, metadata: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    result = await _service.map_finding(vuln_keyword, rule_id=rule_id, severity=severity, description=description, metadata=metadata)
    if not result.requires_cve_lookup:
        return []
    return result.provider_hits


async def map_finding_intelligence(*args, **kwargs) -> IntelligenceResult:
    return await _service.map_finding(*args, **kwargs)