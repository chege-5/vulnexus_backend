from __future__ import annotations

"""Legacy compatibility shim for the removed ML risk model.

The platform now uses a deterministic threat risk assessment engine. This shim
keeps older imports working while avoiding any black-box model loading or
training.
"""

from dataclasses import dataclass

from app.models.pydantic_models import CryptoFeatures, MLPrediction


@dataclass(slots=True)
class AIRiskModel:
    def predict(self, features: CryptoFeatures) -> MLPrediction:
        score = 0.0
        score += 22 if features.uses_md5 or features.uses_sha1 else 0
        score += 18 if features.uses_des or features.uses_rc2 else 0
        score += 16 if features.uses_ecb else 0
        score += 14 if features.hardcoded_key else 0
        score += 12 if features.insecure_random else 0
        score += 10 if features.self_signed else 0
        score += 8 if features.has_hsts is False else 0
        score += 8 if features.forward_secrecy is False else 0
        score += min(max(features.rule_score, 0), 100) * 0.2
        score = min(100.0, round(score, 2))
        return MLPrediction(score=score, severity=self._score_to_severity(score), feature_importances=self._feature_importances(features))

    def train_model(self) -> None:
        return None

    def _score_to_severity(self, score: float) -> str:
        if score >= 75:
            return "Critical"
        if score >= 50:
            return "High"
        if score >= 25:
            return "Medium"
        return "Low"

    def _feature_importances(self, features: CryptoFeatures) -> dict[str, float]:
        return {
            "uses_md5": 22.0 if features.uses_md5 else 0.0,
            "uses_sha1": 22.0 if features.uses_sha1 else 0.0,
            "uses_des": 18.0 if features.uses_des else 0.0,
            "uses_rc2": 18.0 if features.uses_rc2 else 0.0,
            "uses_ecb": 16.0 if features.uses_ecb else 0.0,
            "hardcoded_key": 14.0 if features.hardcoded_key else 0.0,
            "insecure_random": 12.0 if features.insecure_random else 0.0,
        }
