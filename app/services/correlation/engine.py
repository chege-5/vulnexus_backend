from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.services.audit_engine import RULE_PROFILE_MAP
from app.services.integrations.manager import integration_manager
from app.services.intelligence.mapping import build_decision
from app.services.models.pipeline import CorrelatedFinding, EnrichedFinding, IntelligenceResult, RawFinding
from app.utils.logger import get_logger

logger = get_logger(__name__)


class CorrelationEngine:
    async def correlate(self, findings: list[RawFinding]) -> list[EnrichedFinding]:
        grouped = self._group_findings(findings)
        correlated: list[CorrelatedFinding] = []
        for group_key, items in grouped.items():
            primary = items[0]
            decision_key = primary.raw_data.get("rule_id") or primary.title or primary.type
            decision = build_decision(decision_key, rule_id=primary.raw_data.get("rule_id"), severity=primary.severity, description=primary.description, metadata=primary.raw_data)
            correlated.append(CorrelatedFinding(
                group_key=group_key,
                title=primary.title,
                description=primary.description,
                severity=self._severity_from_items(items),
                cwe_ids=list(decision.cwe_ids),
                requires_cve_lookup=decision.requires_cve_lookup,
                primary_source=primary.source,
                sources=sorted({item.source for item in items}),
                evidence=self._merge_evidence(items),
                related_finding_ids=[item.id for item in items[1:]],
                tags=sorted({tag for item in items for tag in item.tags}),
                confidence=max(item.confidence for item in items),
                raw_findings=items,
            ))

        enriched: list[EnrichedFinding] = []
        for item in correlated:
            intelligence = await self._enrich_correlated_finding(item)
            enriched.append(self._merge_enriched(item, intelligence))
        return enriched

    def _group_findings(self, findings: list[RawFinding]) -> dict[str, list[RawFinding]]:
        groups: dict[str, list[RawFinding]] = defaultdict(list)
        for finding in findings:
            key = self._group_key(finding)
            if finding not in groups[key]:
                groups[key].append(finding)
        return groups

    def _group_key(self, finding: RawFinding) -> str:
        location = finding.location or finding.target or "global"
        title = finding.title.lower().strip()
        return f"{finding.type}:{location}:{title}"

    def _severity_from_items(self, findings: list[RawFinding]) -> str:
        order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        reverse = {value: key for key, value in order.items()}
        max_value = max(order.get(item.severity, 2) for item in findings)
        return reverse[max_value]

    def _merge_evidence(self, findings: list[RawFinding]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for finding in findings:
            merged.update(finding.evidence)
            merged.setdefault("sources", []).append(finding.source)
        return merged

    async def _enrich_correlated_finding(self, finding: CorrelatedFinding) -> list[IntelligenceResult]:
        query = finding.evidence.get("cve_id") or finding.evidence.get("version") or finding.title
        providers = []
        if finding.requires_cve_lookup:
            providers.extend(["nvd", "circl", "epss", "cisa", "mitre"])
        if finding.group_key.startswith("reputation"):
            providers.extend(["shodan", "censys", "abuseipdb", "greynoise", "ipinfo"])
        if finding.group_key.startswith("technology"):
            providers.extend(["builtwith", "wappalyzer", "urlscan"])
        if not providers and query:
            if self._looks_like_version(query):
                providers.extend(["nvd", "circl", "epss", "cisa"])

        if not providers:
            return []

        results = await integration_manager.enrich_intelligence(str(query), providers=providers, limit=5, context=finding.evidence)
        if finding.requires_cve_lookup and not any(result.cve_id for result in results):
            logger.debug("CVE lookup requested but no CVE was resolved for %s", finding.group_key)
        return results

    def _merge_enriched(self, correlated: CorrelatedFinding, intelligence: list[IntelligenceResult]) -> EnrichedFinding:
        cve_id = next((item.cve_id for item in intelligence if item.cve_id), None)
        cvss_score = next((item.cvss_score for item in intelligence if item.cvss_score is not None), None)
        epss_score = next((item.epss_score for item in intelligence if item.epss_score is not None), None)
        kev = any(item.kev for item in intelligence if item.kev is not None)
        references = self._collect_references(intelligence)
        return EnrichedFinding(
            finding=correlated,
            intelligence=intelligence,
            cve_id=cve_id,
            cvss_score=cvss_score,
            epss_score=epss_score,
            kev=kev,
            vendor=next((item.vendor for item in intelligence if item.vendor), None),
            references=references,
            exploitability=next((item.exploitability for item in intelligence if item.exploitability), None),
            risk_factors={"finding_count": float(len(correlated.raw_findings)), "confidence": correlated.confidence},
        )

    def _collect_references(self, intelligence: list[IntelligenceResult]) -> list[str]:
        references: list[str] = []
        for item in intelligence:
            for reference in item.references:
                if reference and reference not in references:
                    references.append(reference)
        return references

    def _looks_like_version(self, value: str) -> bool:
        return any(char.isdigit() for char in value) and any(token in value.lower() for token in ("version", "v", "release", "package", "dependency", "."))