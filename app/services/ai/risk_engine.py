from __future__ import annotations

"""Deterministic threat risk assessment engine with explainable factor scoring."""

from statistics import mean
from typing import Any

from app.services.models.pipeline import CorrelatedFinding, EnrichedFinding, RiskScore


class ThreatRiskAssessmentEngine:
    def __init__(self, weights: dict[str, float] | None = None, model: Any | None = None) -> None:
        self.legacy_model = model
        self.weights = {
            "severity": 0.18,
            "cvss": 0.16,
            "epss": 0.12,
            "kev": 0.10,
            "exposure": 0.10,
            "business": 0.10,
            "auth": 0.05,
            "complexity": 0.05,
            "confidence": 0.05,
            "threat_intel": 0.08,
            "attack_chain": 0.05,
            "asset": 0.06,
        }
        if weights:
            self.weights.update(weights)

    def evaluate(
        self,
        findings: list[CorrelatedFinding] | list[EnrichedFinding],
        *,
        asset_exposure: float = 0.5,
        business_impact: float = 0.5,
        business_criticality: float = 0.5,
        service_importance: float = 0.5,
        asset_importance: float = 0.5,
    ) -> RiskScore:
        enriched_inputs: list[EnrichedFinding] = [item for item in findings if isinstance(item, EnrichedFinding)]
        correlated_findings: list[CorrelatedFinding] = [item.finding if isinstance(item, EnrichedFinding) else item for item in findings]

        if not correlated_findings:
            return RiskScore(
                score=0.0,
                severity="Low",
                rationale="No correlated incidents were produced.",
                factors={"asset_exposure": asset_exposure, "business_impact": business_impact},
                likelihood=0.0,
                priority="low",
                business_impact=0.0,
                technical_impact=0.0,
                operational_impact=0.0,
                confidentiality_impact=0.0,
                integrity_impact=0.0,
                availability_impact=0.0,
                fix_complexity="low",
                urgency="low",
                estimated_time_to_exploit="unknown",
                estimated_time_to_remediate="unknown",
                breakdown={},
                confidence=1.0,
            )

        top_severity = max(self._severity_value(item.severity) for item in correlated_findings)
        avg_confidence = mean(item.confidence for item in correlated_findings)
        avg_chain = mean(item.attack_chain_contribution for item in correlated_findings)
        severity_score = self._normalize(top_severity, 4)
        cvss_score = self._normalize(self._average_metric(correlated_findings, "cvss_score"), 10)
        epss_score = self._normalize(self._average_metric(correlated_findings, "epss_score"), 1)
        if enriched_inputs:
            cvss_score = max(cvss_score, self._normalize(mean([item.cvss_score or 0 for item in enriched_inputs]), 10))
            epss_score = max(epss_score, self._normalize(mean([item.epss_score or 0 for item in enriched_inputs]), 1))
        kev_score = 100.0 if self._any_evidence(correlated_findings, "kev") or any(item.kev for item in enriched_inputs) else 0.0
        exposure_score = self._exposure_score(correlated_findings, asset_exposure)
        auth_score = self._authentication_score(correlated_findings)
        complexity_score = self._attack_complexity_score(correlated_findings)
        threat_intel_score = self._threat_intelligence_score(correlated_findings)
        business_score = self._business_score(correlated_findings, business_impact, business_criticality, service_importance, asset_importance)
        asset_score = self._asset_score(correlated_findings, asset_exposure, asset_importance)
        confidence_score = avg_confidence * 100
        attack_chain_score = avg_chain * 100

        score = self._weighted_score(
            severity=severity_score,
            cvss=cvss_score,
            epss=epss_score,
            kev=kev_score,
            exposure=exposure_score,
            business=business_score,
            auth=auth_score,
            complexity=complexity_score,
            confidence=confidence_score,
            threat_intel=threat_intel_score,
            attack_chain=attack_chain_score,
            asset=asset_score,
        )

        likelihood = self._weighted_likelihood(epss_score, kev_score, exposure_score, complexity_score, confidence_score)
        severity = self._score_to_severity(score)
        priority = self._score_to_priority(score, business_score, correlated_findings)
        urgency = self._urgency(score, likelihood, correlated_findings)
        fix_complexity = self._fix_complexity(correlated_findings)

        model_name = "deterministic"
        if self.legacy_model is not None:
            score = round(min(100.0, (score * 0.75) + 20.0), 2)
            severity = self._score_to_severity(score)
            model_name = "hybrid"

        rationale = self._build_rationale(correlated_findings, score, severity, likelihood, business_score, exposure_score, kev_score)
        breakdown = {
            "severity_score": round(severity_score, 2),
            "cvss_score": round(cvss_score, 2),
            "epss_score": round(epss_score, 2),
            "kev_score": round(kev_score, 2),
            "exposure_score": round(exposure_score, 2),
            "business_score": round(business_score, 2),
            "auth_score": round(auth_score, 2),
            "complexity_score": round(complexity_score, 2),
            "confidence_score": round(confidence_score, 2),
            "threat_intel_score": round(threat_intel_score, 2),
            "attack_chain_score": round(attack_chain_score, 2),
            "asset_score": round(asset_score, 2),
            "weights": self.weights,
        }

        return RiskScore(
            score=round(score, 2),
            severity=severity,
            rationale=rationale,
            factors={
                "top_severity": float(top_severity),
                "average_confidence": round(avg_confidence, 2),
                "average_attack_chain_contribution": round(avg_chain, 2),
                "asset_exposure": round(asset_exposure, 2),
                "business_impact": round(business_impact, 2),
                "business_criticality": round(business_criticality, 2),
                "service_importance": round(service_importance, 2),
                "asset_importance": round(asset_importance, 2),
            },
            likelihood=round(likelihood, 2),
            priority=priority,
            business_impact=round(business_score, 2),
            technical_impact=round((severity_score * 0.45) + (exposure_score * 0.35) + (attack_chain_score * 0.2), 2),
            operational_impact=round((business_score * 0.5) + (asset_score * 0.5), 2),
            confidentiality_impact=round(min(100.0, severity_score * 0.6 + exposure_score * 0.4), 2),
            integrity_impact=round(min(100.0, severity_score * 0.55 + complexity_score * 0.45), 2),
            availability_impact=round(min(100.0, severity_score * 0.5 + exposure_score * 0.5), 2),
            fix_complexity=fix_complexity,
            urgency=urgency,
            estimated_time_to_exploit=self._time_to_exploit(likelihood, complexity_score),
            estimated_time_to_remediate=self._time_to_remediate(score, fix_complexity),
            breakdown=breakdown,
            model=model_name,
            confidence=max(0.1, min(1.0, avg_confidence)),
        )

    def _weighted_score(self, **scores: float) -> float:
        total = 0.0
        total += scores["severity"] * self.weights["severity"]
        total += scores["cvss"] * self.weights["cvss"]
        total += scores["epss"] * self.weights["epss"]
        total += scores["kev"] * self.weights["kev"]
        total += scores["exposure"] * self.weights["exposure"]
        total += scores["business"] * self.weights["business"]
        total += scores["auth"] * self.weights["auth"]
        total += scores["complexity"] * self.weights["complexity"]
        total += scores["confidence"] * self.weights["confidence"]
        total += scores["threat_intel"] * self.weights["threat_intel"]
        total += scores["attack_chain"] * self.weights["attack_chain"]
        total += scores["asset"] * self.weights["asset"]
        return min(100.0, max(0.0, total))

    def _weighted_likelihood(self, epss: float, kev: float, exposure: float, complexity: float, confidence: float) -> float:
        return min(100.0, (epss * 0.35) + (kev * 0.25) + (exposure * 0.2) + ((100 - complexity) * 0.1) + (confidence * 0.1))

    def _severity_value(self, severity: str) -> int:
        return {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(severity, 2)

    def _score_to_severity(self, score: float) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"

    def _score_to_priority(self, score: float, business_score: float, findings: list[CorrelatedFinding]) -> str:
        if score >= 80 or business_score >= 75:
            return "p1"
        if score >= 60 or len(findings) > 3:
            return "p2"
        if score >= 35:
            return "p3"
        return "p4"

    def _urgency(self, score: float, likelihood: float, findings: list[CorrelatedFinding]) -> str:
        if score >= 80 or likelihood >= 80 or any(item.severity == "Critical" for item in findings):
            return "immediate"
        if score >= 60 or likelihood >= 60:
            return "high"
        if score >= 35:
            return "medium"
        return "low"

    def _fix_complexity(self, findings: list[CorrelatedFinding]) -> str:
        if any(item.threat_category in {"secret", "transport"} for item in findings):
            return "medium"
        if len(findings) > 4:
            return "high"
        return "low"

    def _time_to_exploit(self, likelihood: float, complexity_score: float) -> str:
        if likelihood >= 80 and complexity_score <= 40:
            return "hours"
        if likelihood >= 60:
            return "days"
        if likelihood >= 35:
            return "weeks"
        return "months"

    def _time_to_remediate(self, score: float, fix_complexity: str) -> str:
        if score >= 80:
            return "same day"
        if score >= 60:
            return "1-3 days" if fix_complexity == "low" else "up to 1 week"
        if score >= 35:
            return "1-2 weeks"
        return "scheduled"

    def _average_metric(self, findings: list[CorrelatedFinding], attribute: str) -> float:
        values = [self._coerce_number(self._evidence_value(item, attribute)) for item in findings if self._coerce_number(self._evidence_value(item, attribute)) is not None]
        return mean(values) if values else 0.0

    def _evidence_value(self, finding: CorrelatedFinding, attribute: str) -> Any:
        if attribute in finding.evidence:
            return finding.evidence.get(attribute)
        for item in finding.raw_findings:
            if attribute in item.raw_data:
                return item.raw_data.get(attribute)
        return getattr(finding, attribute, None)

    def _coerce_number(self, value: Any) -> float | None:
        if isinstance(value, bool):
            return 100.0 if value else 0.0
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return None
        return None

    def _normalize(self, value: float, maximum: float) -> float:
        if maximum <= 0:
            return 0.0
        return max(0.0, min(100.0, (value / maximum) * 100.0))

    def _any_evidence(self, findings: list[CorrelatedFinding], key: str) -> bool:
        return any(bool(self._evidence_value(item, key)) for item in findings)

    def _exposure_score(self, findings: list[CorrelatedFinding], asset_exposure: float) -> float:
        exposure_signals = 100.0 if any(item.attack_surface_category in {"internet_exposure", "external_reputation", "web_application", "tls_pki_crypto_posture"} for item in findings) else 50.0
        return min(100.0, (asset_exposure * 55) + (exposure_signals * 0.45))

    def _authentication_score(self, findings: list[CorrelatedFinding]) -> float:
        if any(self._bool_value(item, "auth_required") is True for item in findings):
            return 25.0
        return 80.0

    def _attack_complexity_score(self, findings: list[CorrelatedFinding]) -> float:
        values = []
        for item in findings:
            raw = self._evidence_value(item, "attack_complexity") or self._evidence_value(item, "complexity")
            if isinstance(raw, str):
                raw = raw.lower()
                values.append(20.0 if raw in {"low", "simple", "trivial"} else 60.0 if raw in {"medium", "moderate"} else 80.0)
            elif isinstance(raw, (int, float)):
                values.append(float(raw))
        return mean(values) if values else 60.0

    def _threat_intelligence_score(self, findings: list[CorrelatedFinding]) -> float:
        score = 0.0
        if any(self._bool_value(item, "kev") for item in findings):
            score += 40.0
        if any(((self._coerce_number(self._evidence_value(item, "epss_score")) or 0.0) >= 0.5) for item in findings):
            score += 25.0
        if any(self._bool_value(item, "exploit_available") for item in findings):
            score += 20.0
        if any(item.related_cves for item in findings):
            score += 15.0
        return min(100.0, score)

    def _business_score(self, findings: list[CorrelatedFinding], business_impact: float, business_criticality: float, service_importance: float, asset_importance: float) -> float:
        related_asset_signal = 100.0 if any(item.related_assets for item in findings) else 40.0
        return min(100.0, (business_impact * 35) + (business_criticality * 25) + (service_importance * 20) + (asset_importance * 20) + (related_asset_signal * 0.2))

    def _asset_score(self, findings: list[CorrelatedFinding], asset_exposure: float, asset_importance: float) -> float:
        related = 100.0 if any(item.related_assets for item in findings) else 50.0
        return min(100.0, (asset_exposure * 50) + (asset_importance * 40) + (related * 0.1))

    def _bool_value(self, finding: CorrelatedFinding, key: str) -> bool | None:
        value = self._evidence_value(finding, key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "y", "enabled"}
        return None

    def _build_rationale(self, findings: list[CorrelatedFinding], score: float, severity: str, likelihood: float, business_score: float, exposure_score: float, kev_score: float) -> str:
        drivers = []
        if kev_score:
            drivers.append("KEV signals are present")
        if exposure_score >= 70:
            drivers.append("the attack surface is externally exposed")
        if business_score >= 70:
            drivers.append("the affected asset is business critical")
        drivers.append(f"{len(findings)} correlated incident(s)")
        return f"Risk score {score:.1f}/100 classified as {severity}. Likelihood {likelihood:.1f}/100. " + "; ".join(drivers) + "."


AIRiskEngine = ThreatRiskAssessmentEngine
