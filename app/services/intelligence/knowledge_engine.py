from __future__ import annotations

"""Deterministic security intelligence enrichment service for correlated findings."""

import hashlib
from typing import Any

from app.services.integrations.cache import cache
from app.services.integrations.manager import integration_manager
from app.services.integrations.base import to_intelligence_result
from app.services.finding_classifier import build_software_lookup_query, is_software_vulnerability_classification, safe_intelligence_context
from app.services.intelligence.graph import GraphNode, threat_graph
from app.services.intelligence.llm_engine import llm_engine
from app.services.intelligence.mapping import build_decision
from app.services.intelligence.rag_store import knowledge_store
from app.services.models.pipeline import CorrelatedFinding, EnrichedFinding, IntelligenceResult


class SecurityIntelligenceKnowledgeEngine:
    async def enrich(self, finding: CorrelatedFinding, *, risk: dict[str, Any] | None = None, asset_context: dict[str, Any] | None = None) -> EnrichedFinding:
        cache_key = self._cache_key(finding, risk=risk, asset_context=asset_context)
        cached = await cache.get_json(cache_key)
        if cached:
            return EnrichedFinding.model_validate(cached)

        decision = build_decision(finding.group_key, rule_id=finding.evidence.get("rule_id"), severity=finding.severity, description=finding.description, metadata=finding.evidence)
        query = " ".join(filter(None, [finding.title, finding.description, finding.threat_category, finding.attack_surface_category]))
        retrieved = knowledge_store.retrieve(query, topics=[finding.threat_category, finding.attack_surface_category], limit=5)

        provider_results = []
        provider_statuses = []
        provider_names = self._providers_for(finding)
        if provider_names:
            lookup_query = self._lookup_query_for(finding, decision)
            safe_context = safe_intelligence_context({**finding.evidence, **(asset_context or {}), "classification": decision.classification})
            provider_responses = await integration_manager.lookup(lookup_query, providers=provider_names, context=safe_context, limit=5)
            provider_statuses = [
                {
                    "provider": response.provider,
                    "success": response.success,
                    "status_code": response.status_code,
                    "error": self._provider_error_label(response.provider, response.status_code, response.error),
                }
                for response in provider_responses
                if not response.success
            ]
            provider_results = [to_intelligence_result(response, query=lookup_query) for response in provider_responses if response.success or response.cached]

        intelligence = list(provider_results)
        cve_id = next((item.cve_id for item in intelligence if item.cve_id), None)
        cvss_score = next((item.cvss_score for item in intelligence if item.cvss_score is not None), None)
        epss_score = next((item.epss_score for item in intelligence if item.epss_score is not None), None)
        kev = any(item.kev for item in intelligence if item.kev is not None)
        references = self._collect_references(intelligence, decision.references, retrieved)

        knowledge = {
            "basic": {
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "category": decision.classification,
                "scanner_source": finding.primary_source,
                "discovery_time": finding.created_at.isoformat(),
                "affected_assets": finding.related_assets,
                "classification": finding.classification,
            },
            "technical": {
                "root_cause": decision.technical_explanation,
                "technical_explanation": decision.technical_explanation,
                "affected_versions": finding.evidence.get("versions") or finding.evidence.get("version"),
                "affected_technologies": finding.related_technologies,
                "affected_components": finding.evidence.get("components") or [],
                "attack_preconditions": finding.possible_attack_scenarios,
                "internet_exposure": finding.evidence.get("internet_exposure"),
                "detection_method": finding.evidence.get("detection_method") or finding.primary_source,
            },
            "threat": {
                "cves": [cve_id] if cve_id else list(finding.related_cves),
                "cwes": list(finding.cwe_ids or decision.cwe_ids),
                "capec": list(finding.capec),
                "mitre_attack": list(finding.mitre_attack),
                "cisa_kev": kev,
                "epss": epss_score,
                "vendor_advisories": [item.get("url") for item in retrieved if item.get("source") == "Vendor guidance"],
                "provider_statuses": provider_statuses,
                "exploitdb_references": finding.evidence.get("exploitdb") or [],
                "github_pocs": finding.evidence.get("github_pocs") or [],
                "known_threat_actors": finding.evidence.get("threat_actors") or [],
                "known_campaigns": finding.evidence.get("campaigns") or [],
                "ransomware_associations": finding.evidence.get("ransomware") or [],
            },
            "business": {
                "business_impact": risk.get("business_impact") if risk else None,
                "financial_impact": finding.evidence.get("financial_impact"),
                "operational_impact": risk.get("operational_impact") if risk else None,
                "compliance_impact": finding.evidence.get("compliance_impact"),
                "reputation_impact": finding.evidence.get("reputation_impact"),
                "confidentiality": risk.get("confidentiality_impact") if risk else None,
                "integrity": risk.get("integrity_impact") if risk else None,
                "availability": risk.get("availability_impact") if risk else None,
            },
            "attack": {
                "attack_story": self._attack_story(finding, decision, risk),
                "possible_attack_path": list(finding.possible_attack_paths),
                "kill_chain_stage": finding.evidence.get("kill_chain_stage") or self._kill_chain_stage(finding),
                "privilege_escalation": finding.evidence.get("privilege_escalation") or [],
                "persistence": finding.evidence.get("persistence") or [],
                "data_exfiltration": finding.evidence.get("data_exfiltration") or [],
                "lateral_movement": list(finding.potential_lateral_movement),
                "detection_opportunities": finding.evidence.get("detection_opportunities") or [],
                "likelihood": risk.get("likelihood") if risk else None,
                "attack_difficulty": finding.exploitation_difficulty,
            },
            "mitigation": {
                "immediate_actions": self._immediate_actions(finding, decision),
                "temporary_workarounds": finding.evidence.get("temporary_workarounds") or [],
                "permanent_fix": decision.remediation,
                "configuration_changes": finding.evidence.get("configuration_changes") or [],
                "patch_information": finding.evidence.get("patch_information") or [],
                "firewall_recommendations": finding.evidence.get("firewall_recommendations") or [],
                "waf_recommendations": finding.evidence.get("waf_recommendations") or [],
                "ids_recommendations": finding.evidence.get("ids_recommendations") or [],
                "validation_steps": finding.evidence.get("validation_steps") or [],
                "rollback_strategy": finding.evidence.get("rollback_strategy") or [],
            },
            "compliance": {
                "owasp": decision.owasp_category,
                "nist": decision.nist_control,
                "pci_dss": finding.evidence.get("pci_dss") or [],
                "iso_27001": finding.evidence.get("iso_27001") or [],
                "cis_controls": finding.evidence.get("cis_controls") or [],
            },
            "learning": {
                "official_documentation": [item.get("url") for item in retrieved if item.get("source") == "OWASP"],
                "mitre_references": [item.get("url") for item in retrieved if item.get("source") == "MITRE"],
                "nvd_references": [item.get("url") for item in retrieved if item.get("source") == "NVD"],
                "vendor_documentation": [item.get("url") for item in retrieved if item.get("source") == "Vendor guidance"],
                "research_articles": finding.evidence.get("research_articles") or [],
            },
        }

        graph_id = self._graph_id(finding)
        await self._seed_graph(graph_id, finding, retrieved)
        graph_context = await threat_graph.query(graph_id)

        llm_context = llm_engine.explain(
            title=finding.title,
            audience="analyst",
            knowledge={**knowledge["basic"], **knowledge["business"], "threat_category": finding.threat_category, "attack_surface_category": finding.attack_surface_category},
            risk=risk or {},
            evidence=finding.evidence_items or [{"title": raw.title, "rule_id": raw.raw_data.get("rule_id"), "severity": raw.severity} for raw in finding.raw_findings],
            recommendations=[decision.remediation, *[item.get("content", "") for item in retrieved[:2]]],
        )

        enriched = EnrichedFinding(
            finding=finding,
            intelligence=intelligence,
            knowledge=knowledge,
            graph_context={"graph_id": graph_id, "graph": graph_context},
            llm_context=llm_context,
            cve_id=cve_id,
            cvss_score=cvss_score,
            epss_score=epss_score,
            kev=kev,
            vendor=next((item.vendor for item in intelligence if item.vendor), None),
            references=references,
            exploitability=next((item.exploitability for item in intelligence if item.exploitability), None),
            risk_factors={"finding_count": float(len(finding.raw_findings)), "confidence": finding.confidence},
        )
        await cache.set_json(cache_key, enriched.model_dump(mode="json"))
        return enriched

    async def explain(self, finding: CorrelatedFinding, *, audience: str = "analyst", risk: dict[str, Any] | None = None, asset_context: dict[str, Any] | None = None) -> dict[str, Any]:
        enriched = await self.enrich(finding, risk=risk, asset_context=asset_context)
        explanation = dict(enriched.llm_context)
        explanation["audience"] = audience
        return explanation

    def _providers_for(self, finding: CorrelatedFinding) -> list[str]:
        providers: list[str] = []
        if finding.requires_cve_lookup and is_software_vulnerability_classification(finding.classification):
            providers.extend(["nvd", "circl", "epss", "cisa", "mitre"])
        if finding.threat_category in {"exposure", "reputation"}:
            providers.extend(["shodan", "censys", "abuseipdb", "greynoise", "ipinfo"])
        if finding.threat_category in {"technology", "browser"}:
            providers.extend(["builtwith", "wappalyzer", "urlscan"])
        return providers

    def _lookup_query_for(self, finding: CorrelatedFinding, decision) -> str:
        if finding.requires_cve_lookup and is_software_vulnerability_classification(finding.classification):
            return build_software_lookup_query(finding.title or decision.finding_key, finding.evidence)
        return str(finding.related_assets[0] if finding.related_assets else finding.evidence.get("ip_address") or finding.evidence.get("host") or finding.title)

    def _provider_error_label(self, provider: str, status_code: int | None, error: str | None) -> str:
        text = (error or "").lower()
        if status_code in {401, 403} or "auth" in text or "api key" in text or "unauthorized" in text or "forbidden" in text:
            return f"{provider} unavailable (authentication)"
        if status_code == 429 or "rate limit" in text:
            return f"{provider} unavailable (rate limit)"
        if error:
            return f"{provider} unavailable ({error})"
        return f"{provider} unavailable"

    def _collect_references(self, intelligence: list[IntelligenceResult], decision_references: list[str], retrieved: list[dict[str, Any]]) -> list[str]:
        references = list(dict.fromkeys([*decision_references, *[url for item in retrieved for url in [item.get("url")] if url]]))
        for item in intelligence:
            for reference in item.references:
                if reference and reference not in references:
                    references.append(reference)
        return references

    def _attack_story(self, finding: CorrelatedFinding, decision, risk: dict[str, Any] | None) -> str:
        score = risk.get("score") if risk else None
        return (
            f"An attacker can leverage {finding.threat_category} weaknesses in the affected assets to contribute to the attack chain. "
            f"The finding maps to {', '.join(decision.cwe_ids) or 'no direct CWE'} and the current deterministic risk score is {score if score is not None else 'unavailable'}."
        )

    def _kill_chain_stage(self, finding: CorrelatedFinding) -> str:
        if finding.threat_category in {"exposure", "reputation"}:
            return "reconnaissance"
        if finding.threat_category in {"browser", "transport"}:
            return "initial access"
        if finding.threat_category in {"secret", "dependency"}:
            return "exploitation"
        return "delivery"

    def _immediate_actions(self, finding: CorrelatedFinding, decision) -> list[str]:
        actions = [decision.remediation]
        if finding.attack_surface_category != "unknown":
            actions.append(f"Reduce the {finding.attack_surface_category} attack surface before re-testing.")
        return actions

    def _cache_key(self, finding: CorrelatedFinding, *, risk: dict[str, Any] | None, asset_context: dict[str, Any] | None) -> str:
        payload = {"finding": finding.model_dump(mode="json"), "risk": risk or {}, "asset_context": asset_context or {}}
        digest = hashlib.sha256(str(payload).encode("utf-8")).hexdigest()
        return cache.build_key("security-intelligence", digest)

    def _graph_id(self, finding: CorrelatedFinding) -> str:
        return hashlib.sha256(finding.group_key.encode("utf-8")).hexdigest()[:24]

    async def _seed_graph(self, graph_id: str, finding: CorrelatedFinding, retrieved: list[dict[str, Any]]) -> None:
        target = finding.related_assets[0] if finding.related_assets else finding.evidence.get("target") or finding.group_key
        target_node = GraphNode(id=f"target:{target}", kind="target", label=target, metadata={"threat_category": finding.threat_category})
        finding_node = GraphNode(id=f"finding:{finding.id}", kind="finding", label=finding.title, metadata={"severity": finding.severity, "risk_category": finding.risk_category})
        await threat_graph.link(graph_id, target_node, finding_node, "produces", metadata={"group_key": finding.group_key})

        for cwe in finding.cwe_ids:
            await threat_graph.link(graph_id, finding_node, GraphNode(id=f"cwe:{cwe}", kind="cwe", label=cwe), "maps-to")
        for cve in finding.related_cves:
            await threat_graph.link(graph_id, finding_node, GraphNode(id=f"cve:{cve}", kind="cve", label=cve), "linked-to")
        for tech in finding.related_technologies:
            await threat_graph.link(graph_id, target_node, GraphNode(id=f"tech:{tech}", kind="technology", label=tech), "uses")
        for reference in retrieved:
            await threat_graph.link(graph_id, finding_node, GraphNode(id=f"ref:{reference['doc_id']}", kind="reference", label=reference["title"], metadata={"source": reference["source"], "url": reference["url"]}), "grounded-by")


knowledge_engine = SecurityIntelligenceKnowledgeEngine()
