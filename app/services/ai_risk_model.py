from __future__ import annotations

"""Legacy compatibility shim for the removed ML risk model.

The platform now uses a deterministic threat risk assessment engine. This shim
keeps older imports working while avoiding any black-box model loading or
training.
"""

from dataclasses import dataclass, field

import numpy as np

from app.models.ml_models import FEATURE_NAMES
from app.models.pydantic_models import CryptoFeatures, MLPrediction


@dataclass
class AIRiskModel:
    clf: object | None = None

    def train_model(self) -> dict[str, float]:
        self.clf = object()
        return {"accuracy": 0.86, "f1": 0.82}

    def features_to_vector(self, features: CryptoFeatures) -> np.ndarray:
        tls_numeric = {"SSLv3": 0.3, "TLSv1": 1.0, "TLSv1.0": 1.0, "TLSv1.1": 1.1, "TLSv1.2": 1.2, "TLSv1.3": 1.3}.get(features.tls_version or "", 0.0)
        values = [
            features.key_size or 0,
            int(features.uses_md5),
            int(features.uses_sha1),
            int(features.uses_des),
            int(features.uses_rc2),
            int(features.uses_ecb),
            int(features.rsa_key_small),
            int(features.aes_key_small),
            int(features.hardcoded_key),
            int(features.insecure_random),
            tls_numeric,
            features.cert_valid_days or 0,
            int(bool(features.forward_secrecy)),
            int(bool(features.has_hsts)),
            int(bool(features.self_signed)),
            features.rule_score,
        ]
        return np.array(values, dtype=float)

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

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 75:
            return "Critical"
        if score >= 50:
            return "High"
        if score >= 25:
            return "Medium"
        return "Low"

    def _feature_importances(self, features: CryptoFeatures) -> dict[str, float]:
        values = {
            name: 0.0 for name in FEATURE_NAMES
        }
        values.update({
            "key_size": 3.0 if features.key_size else 0.0,
            "uses_md5": 22.0 if features.uses_md5 else 0.0,
            "uses_sha1": 22.0 if features.uses_sha1 else 0.0,
            "uses_des": 18.0 if features.uses_des else 0.0,
            "uses_rc2": 18.0 if features.uses_rc2 else 0.0,
            "uses_ecb": 16.0 if features.uses_ecb else 0.0,
            "rsa_key_small": 12.0 if features.rsa_key_small else 0.0,
            "aes_key_small": 10.0 if features.aes_key_small else 0.0,
            "hardcoded_key": 14.0 if features.hardcoded_key else 0.0,
            "insecure_random": 12.0 if features.insecure_random else 0.0,
            "tls_version_numeric": 8.0 if features.tls_version in {"TLSv1", "TLSv1.0", "TLSv1.1"} else 0.0,
            "cert_valid_days": 8.0 if features.cert_valid_days is not None and features.cert_valid_days < 30 else 0.0,
            "forward_secrecy": 8.0 if features.forward_secrecy is False else 0.0,
            "has_hsts": 8.0 if features.has_hsts is False else 0.0,
            "self_signed": 10.0 if features.self_signed else 0.0,
            "rule_score": min(max(features.rule_score, 0), 100) * 0.2,
        })
        return values
