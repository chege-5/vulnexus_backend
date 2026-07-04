from __future__ import annotations

from collections import Counter
from typing import Any

from app.models.pydantic_models import CryptoFeatures
from app.services.ai_risk_model import AIRiskModel
from app.services.models.pipeline import EnrichedFinding, RiskScore


class AIRiskEngine:
    def __init__(self, model: AIRiskModel | None = None) -> None:
        self.model = model or AIRiskModel()

    def evaluate(self, findings: list[EnrichedFinding], *, asset_exposure: float = 0.5, business_impact: float = 0.5) -> RiskScore:
        if not findings:
            return RiskScore(score=0.0, severity="Low", rationale="No correlated findings were produced.", factors={"asset_exposure": asset_exposure, "business_impact": business_impact}, confidence=1.0)

        severity_order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        top_severity = max(severity_order.get(item.finding.severity, 2) for item in findings)
        average_confidence = sum(item.finding.confidence for item in findings) / len(findings)
        cve_bonus = sum(1 for item in findings if item.cve_id)
        kev_bonus = sum(1 for item in findings if item.kev)
        epss_bonus = sum(item.epss_score or 0 for item in findings) / max(len(findings), 1)
        cvss_bonus = sum(item.cvss_score or 0 for item in findings) / max(len(findings), 1)

        synthetic = self._build_features(findings)
        ml_prediction = self.model.predict(synthetic)

        deterministic_score = (
            top_severity * 16.0
            + min(cve_bonus * 4.0, 12.0)
            + min(kev_bonus * 8.0, 16.0)
            + min(epss_bonus * 25.0, 20.0)
            + min(cvss_bonus * 2.5, 25.0)
            + asset_exposure * 8.0
            + business_impact * 10.0
            + average_confidence * 8.0
        )
        final_score = min(100.0, round((deterministic_score * 0.6) + (ml_prediction.score * 0.4), 2))
        severity = self._score_to_severity(final_score)
        rationale = (
            f"{len(findings)} correlated findings, top severity {severity}, "
            f"{cve_bonus} CVE-linked, {kev_bonus} KEV-linked, ML score {ml_prediction.score:.1f}."
        )
        return RiskScore(
            score=final_score,
            severity=severity,
            rationale=rationale,
            factors={
                "deterministic_score": round(deterministic_score, 2),
                "ml_score": ml_prediction.score,
                "asset_exposure": asset_exposure,
                "business_impact": business_impact,
                "average_confidence": round(average_confidence, 2),
                "cve_bonus": float(cve_bonus),
                "kev_bonus": float(kev_bonus),
            },
            model="hybrid",
            confidence=min(1.0, max(0.1, average_confidence)),
        )

    def _build_features(self, findings: list[EnrichedFinding]) -> CryptoFeatures:
        severity_weight = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        strongest = max(severity_weight.get(item.finding.severity, 2) for item in findings)
        return CryptoFeatures(
            hardcoded_key=any("secret" in tag for item in findings for tag in item.finding.tags),
            uses_md5=any("md5" in item.finding.title.lower() for item in findings),
            uses_sha1=any("sha1" in item.finding.title.lower() for item in findings),
            uses_des=any("des" in item.finding.title.lower() for item in findings),
            uses_rc2=any("rc2" in item.finding.title.lower() for item in findings),
            uses_ecb=any("ecb" in item.finding.title.lower() for item in findings),
            rsa_key_small=any("rsa" in item.finding.title.lower() for item in findings),
            aes_key_small=any("aes" in item.finding.title.lower() and item.finding.severity in {"High", "Critical"} for item in findings),
            insecure_random=any("random" in item.finding.title.lower() for item in findings),
            tls_version="TLSv1.1" if strongest >= 3 else "TLSv1.3",
            cert_valid_days=365 if strongest < 3 else 30,
            forward_secrecy=not any("forward secrecy" in item.finding.title.lower() for item in findings),
            has_hsts=not any("hsts" in item.finding.title.lower() for item in findings),
            self_signed=any("self-signed" in item.finding.title.lower() for item in findings),
            rule_score=min(100, strongest * 20),
        )

    def _score_to_severity(self, score: float) -> str:
        if score >= 75:
            return "Critical"
        if score >= 50:
            return "High"
        if score >= 25:
            return "Medium"
        return "Low"