from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.services.audit_engine import RULE_PROFILE_MAP
from app.services.intelligence.mapping import build_decision
from app.services.models.pipeline import CorrelatedFinding, RawFinding


class CorrelationEngine:
    async def correlate(self, findings: list[RawFinding]) -> list[CorrelatedFinding]:
        groups: dict[str, list[RawFinding]] = defaultdict(list)
        for finding in findings:
            groups[self._group_key(finding)].append(finding)

        correlated: list[CorrelatedFinding] = []
        for group_key, items in groups.items():
            correlated.append(self._build_correlated_finding(group_key, items))
        return correlated

    def _build_correlated_finding(self, group_key: str, findings: list[RawFinding]) -> CorrelatedFinding:
        primary = findings[0]
        profile = self._profile_for(primary)
        evidence = self._merge_evidence(findings)
        evidence_items = [self._evidence_item(item) for item in findings]
        assets = self._collect_assets(findings)
        technologies = self._collect_technologies(findings, evidence)
        cves = self._collect_cves(findings, evidence)

        return CorrelatedFinding(
            group_key=group_key,
            title=self._incident_title(primary, profile["threat_category"]),
            description=self._incident_description(primary, findings),
            severity=self._severity_from_items(findings),
            threat_category=profile["threat_category"],
            attack_surface_category=profile["attack_surface_category"],
            risk_category=profile["risk_category"],
            cwe_ids=list(profile["cwe_ids"]),
            related_cves=cves,
            related_assets=assets,
            related_technologies=technologies,
            mitre_attack=list(profile["mitre_attack"]),
            capec=list(profile["capec"]),
            possible_attack_paths=list(profile["possible_attack_paths"]),
            possible_attack_scenarios=list(profile["possible_attack_scenarios"]),
            potential_lateral_movement=list(profile["potential_lateral_movement"]),
            exploitation_difficulty=profile["exploitation_difficulty"],
            detection_difficulty=profile["detection_difficulty"],
            attack_chain_contribution=profile["attack_chain_contribution"],
            requires_cve_lookup=profile["requires_cve_lookup"],
            primary_source=primary.source,
            sources=sorted({item.source for item in findings}),
            evidence=evidence,
            evidence_items=evidence_items,
            related_finding_ids=[item.id for item in findings[1:]],
            tags=sorted({tag for item in findings for tag in item.tags}),
            confidence=round(sum(item.confidence for item in findings) / len(findings), 2),
            raw_findings=findings,
        )

    def _profile_for(self, finding: RawFinding) -> dict[str, Any]:
        decision = build_decision(finding.title, rule_id=finding.raw_data.get("rule_id"), severity=finding.severity, description=finding.description, metadata=finding.raw_data)
        threat_category = self._threat_category(finding, decision.finding_key)
        attack_surface = self._attack_surface_category(finding, decision.finding_key)
        return {
            "threat_category": threat_category,
            "attack_surface_category": attack_surface,
            "risk_category": self._risk_category(threat_category, attack_surface, finding.severity),
            "cwe_ids": decision.cwe_ids,
            "mitre_attack": self._mitre_attack(threat_category, decision.finding_key),
            "capec": self._capec(threat_category, decision.finding_key),
            "possible_attack_paths": self._attack_paths(threat_category),
            "possible_attack_scenarios": self._attack_scenarios(threat_category, finding),
            "potential_lateral_movement": self._lateral_movement(threat_category),
            "exploitation_difficulty": self._difficulty(finding.severity, threat_category, "exploit"),
            "detection_difficulty": self._difficulty(finding.severity, threat_category, "detect"),
            "attack_chain_contribution": self._attack_chain_contribution(threat_category, finding.severity),
            "requires_cve_lookup": decision.requires_cve_lookup or self._looks_like_software_version(finding),
        }

    def _group_key(self, finding: RawFinding) -> str:
        profile = self._profile_for(finding)
        anchor = finding.location or finding.target or finding.raw_data.get("host") or finding.raw_data.get("domain") or "global"
        return f"{anchor}:{profile['threat_category']}:{profile['attack_surface_category']}"

    def _threat_category(self, finding: RawFinding, finding_key: str) -> str:
        haystack = " ".join([finding.title, finding.description, finding.source, finding.type, finding_key, " ".join(finding.tags)]).lower()
        if any(token in haystack for token in ("csp", "hsts", "xfo", "referrer", "permissions policy", "header")):
            return "browser"
        if any(token in haystack for token in ("tls", "ssl", "certificate", "cipher", "openssl", "forward secrecy")):
            return "transport"
        if any(token in haystack for token in ("dns", "whois", "shodan", "censys", "virustotal", "reputation", "abuseipdb", "ipinfo")):
            return "reputation"
        if any(token in haystack for token in ("technology", "wappalyzer", "builtwith", "urlscan", "stack")):
            return "technology"
        if any(token in haystack for token in ("secret", "credential", "token", "key", "password", "hardcoded")):
            return "secret"
        if any(token in haystack for token in ("dependency", "package", "version", "library", "supply chain")):
            return "dependency"
        if any(token in haystack for token in ("port", "service", "exposed", "public", "internet")):
            return "exposure"
        return "general"

    def _attack_surface_category(self, finding: RawFinding, finding_key: str) -> str:
        category = self._threat_category(finding, finding_key)
        return {
            "browser": "web_application",
            "transport": "transport_layer",
            "reputation": "external_exposure",
            "technology": "stack_visibility",
            "secret": "credential_surface",
            "dependency": "supply_chain",
            "exposure": "internet_exposure",
        }.get(category, "application")

    def _risk_category(self, threat_category: str, attack_surface_category: str, severity: str) -> str:
        if severity == "Critical" or threat_category in {"secret", "transport"}:
            return "critical"
        if severity == "High" or attack_surface_category in {"internet_exposure", "external_exposure"}:
            return "high"
        if severity == "Medium":
            return "medium"
        return "low"

    def _incident_title(self, primary: RawFinding, threat_category: str) -> str:
        mapping = {
            "browser": "Browser Security Weakness",
            "transport": "Transport Security Weakness",
            "reputation": "Exposure and Reputation Weakness",
            "technology": "Technology Exposure",
            "secret": "Secret Exposure",
            "dependency": "Dependency Risk",
            "exposure": "Internet Exposure",
        }
        return mapping.get(threat_category, primary.title)

    def _incident_description(self, primary: RawFinding, findings: list[RawFinding]) -> str:
        if len(findings) == 1:
            return primary.description
        return f"{len(findings)} findings correlate into a single incident anchored on {primary.target or primary.location or primary.title}."

    def _merge_evidence(self, findings: list[RawFinding]) -> dict[str, Any]:
        merged: dict[str, Any] = {"sources": [], "locations": [], "raw_evidence": []}
        for finding in findings:
            merged["sources"].append(finding.source)
            if finding.location:
                merged["locations"].append(finding.location)
            merged["raw_evidence"].append(finding.evidence)
            for key, value in finding.evidence.items():
                if key not in merged:
                    merged[key] = value
                elif isinstance(merged[key], list):
                    if isinstance(value, list):
                        merged[key].extend(value)
                    else:
                        merged[key].append(value)
        return merged

    def _collect_assets(self, findings: list[RawFinding]) -> list[str]:
        assets = []
        for finding in findings:
            for candidate in [finding.target, finding.location, finding.raw_data.get("asset"), finding.raw_data.get("host")]:
                if candidate and candidate not in assets:
                    assets.append(candidate)
        return assets

    def _collect_technologies(self, findings: list[RawFinding], evidence: dict[str, Any]) -> list[str]:
        technologies: list[str] = []
        for finding in findings:
            for candidate in finding.raw_data.get("technologies", []) or finding.raw_data.get("technology", []) or []:
                if candidate and candidate not in technologies:
                    technologies.append(candidate)
        for candidate in evidence.get("technology", []) if isinstance(evidence.get("technology"), list) else []:
            if candidate and candidate not in technologies:
                technologies.append(candidate)
        return technologies

    def _collect_cves(self, findings: list[RawFinding], evidence: dict[str, Any]) -> list[str]:
        cves: list[str] = []
        for finding in findings:
            for candidate in [finding.raw_data.get("cve_id"), finding.raw_data.get("cve"), evidence.get("cve_id")]:
                if candidate and candidate not in cves:
                    cves.append(candidate)
        return cves

    def _evidence_item(self, finding: RawFinding) -> dict[str, Any]:
        return {
            "id": str(finding.id),
            "title": finding.title,
            "description": finding.description,
            "source": finding.source,
            "severity": finding.severity,
            "location": finding.location,
            "target": finding.target,
            "evidence": finding.evidence,
            "tags": finding.tags,
            "rule_id": finding.raw_data.get("rule_id"),
        }

    def _severity_from_items(self, findings: list[RawFinding]) -> str:
        order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        reverse = {value: key for key, value in order.items()}
        return reverse[max(order.get(item.severity, 2) for item in findings)]

    def _mitre_attack(self, threat_category: str, finding_key: str) -> list[str]:
        mapping = {
            "browser": ["T1059", "T1189"],
            "transport": ["T1040", "T1573"],
            "reputation": ["T1595"],
            "technology": ["T1046"],
            "secret": ["T1552"],
            "dependency": ["T1195"],
            "exposure": ["T1595"],
        }
        return mapping.get(threat_category, ["T1003" if finding_key else "T1040"])

    def _capec(self, threat_category: str, finding_key: str) -> list[str]:
        mapping = {
            "browser": ["CAPEC-63", "CAPEC-591"],
            "transport": ["CAPEC-17", "CAPEC-90"],
            "reputation": ["CAPEC-406"],
            "technology": ["CAPEC-541"],
            "secret": ["CAPEC-37"],
            "dependency": ["CAPEC-439"],
            "exposure": ["CAPEC-88"],
        }
        return mapping.get(threat_category, ["CAPEC-1"])

    def _attack_paths(self, threat_category: str) -> list[str]:
        return {
            "browser": ["Malicious script injection -> browser trust abuse -> session compromise"],
            "transport": ["Weak transport controls -> downgrade attack -> credential interception"],
            "reputation": ["External exposure discovery -> targeted exploitation -> pivot to host intelligence"],
            "technology": ["Fingerprinting -> exploit matching -> public service abuse"],
            "secret": ["Secret discovery -> authentication bypass -> lateral movement"],
            "dependency": ["Known vulnerable package -> code execution -> downstream compromise"],
            "exposure": ["Open service discovery -> brute force or exploit -> foothold"],
        }.get(threat_category, ["Discovery -> validation -> exploitation"])

    def _attack_scenarios(self, threat_category: str, finding: RawFinding) -> list[str]:
        return {
            "browser": ["An attacker chains missing browser controls to stage a cross-site attack."],
            "transport": ["Traffic can be intercepted or downgraded because modern transport protections are incomplete."],
            "secret": ["A leaked secret could be reused to impersonate a trusted service or operator."],
            "dependency": ["A vulnerable dependency may allow remote exploitation after fingerprinting."],
            "exposure": ["An internet-exposed service may be probed and abused with commodity tooling."],
        }.get(threat_category, [finding.description])

    def _lateral_movement(self, threat_category: str) -> list[str]:
        return {
            "browser": ["Session theft", "User impersonation"],
            "transport": ["Credential replay", "MITM into adjacent services"],
            "reputation": ["Targeted follow-on attacks"],
            "technology": ["Service pivoting"],
            "secret": ["Credential reuse across services"],
            "dependency": ["Shared package compromise"],
            "exposure": ["Pivot from exposed service to internal assets"],
        }.get(threat_category, [])

    def _difficulty(self, severity: str, threat_category: str, mode: str) -> str:
        if severity == "Critical" or threat_category in {"secret", "dependency"}:
            return "low" if mode == "exploit" else "moderate"
        if severity == "High":
            return "moderate"
        return "high" if mode == "detect" else "moderate"

    def _attack_chain_contribution(self, threat_category: str, severity: str) -> float:
        base = {"Critical": 0.95, "High": 0.8, "Medium": 0.55, "Low": 0.25}.get(severity, 0.5)
        multiplier = {"secret": 1.15, "dependency": 1.1, "transport": 1.05, "browser": 1.0, "reputation": 0.9, "technology": 0.85}.get(threat_category, 0.8)
        return round(min(1.0, base * multiplier), 2)

    def _looks_like_software_version(self, finding: RawFinding) -> bool:
        haystack = " ".join([finding.title, finding.description, finding.raw_data.get("version", ""), finding.raw_data.get("product", "")]).lower()
        return any(char.isdigit() for char in haystack) and any(marker in haystack for marker in ("version", "release", "package", "dependency", "v"))
