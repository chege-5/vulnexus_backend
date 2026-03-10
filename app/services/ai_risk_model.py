import os
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from typing import Optional

from app.models.pydantic_models import CryptoFeatures, MLPrediction
from app.models.ml_models import FEATURE_NAMES
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

TLS_VERSION_NUM = {
    "TLSv1": 1.0, "TLSv1.0": 1.0, "TLSv1.1": 1.1,
    "TLSv1.2": 1.2, "TLSv1.3": 1.3, "unknown": 0.0,
}


class AIRiskModel:
    def __init__(self):
        self.clf: Optional[RandomForestClassifier] = None
        self.iso_forest: Optional[IsolationForest] = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(settings.ML_MODEL_PATH):
            try:
                self.clf = joblib.load(settings.ML_MODEL_PATH)
                logger.info("ML model loaded from disk")
            except Exception as e:
                logger.warning(f"Failed to load ML model: {e}")

    def features_to_vector(self, f: CryptoFeatures) -> np.ndarray:
        return np.array([
            f.key_size or 0,
            int(f.uses_md5),
            int(f.uses_sha1),
            int(f.uses_des),
            int(f.uses_rc2),
            int(f.uses_ecb),
            int(f.rsa_key_small),
            int(f.aes_key_small),
            int(f.hardcoded_key),
            int(f.insecure_random),
            TLS_VERSION_NUM.get(f.tls_version or "unknown", 0.0),
            f.cert_valid_days or 0,
            int(f.forward_secrecy or False),
            int(f.has_hsts or False),
            int(f.self_signed or False),
            f.rule_score,
        ], dtype=np.float64)

    def predict(self, features: CryptoFeatures) -> MLPrediction:
        vec = self.features_to_vector(features).reshape(1, -1)

        if self.clf is None:
            score = features.rule_score
        else:
            proba = self.clf.predict_proba(vec)[0]
            class_idx = np.argmax(proba)
            confidence = proba[class_idx]
            score = self._class_to_score(class_idx, confidence)

        severity = self._score_to_severity(score)

        importances = None
        if self.clf is not None:
            importances = dict(zip(FEATURE_NAMES, self.clf.feature_importances_.tolist()))

        return MLPrediction(score=round(score, 2), severity=severity, feature_importances=importances)

    def predict_batch(self, features_list: list[CryptoFeatures]) -> list[MLPrediction]:
        return [self.predict(f) for f in features_list]

    def train_model(self):
        logger.info("Generating synthetic training data and training model")
        X, y = self._generate_synthetic_data()
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        self.clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        self.clf.fit(X_train, y_train)

        y_pred = self.clf.predict(X_test)
        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average="weighted", zero_division=0),
            "recall": recall_score(y_test, y_pred, average="weighted", zero_division=0),
            "f1": f1_score(y_test, y_pred, average="weighted", zero_division=0),
        }
        logger.info(f"Training metrics: {metrics}")

        os.makedirs(os.path.dirname(settings.ML_MODEL_PATH) or "ml_models", exist_ok=True)
        joblib.dump(self.clf, settings.ML_MODEL_PATH)
        logger.info(f"Model saved to {settings.ML_MODEL_PATH}")

        self.iso_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.iso_forest.fit(X_train)

        return metrics

    def _generate_synthetic_data(self, n_samples: int = 5000) -> tuple[np.ndarray, np.ndarray]:
        rng = np.random.RandomState(42)
        X = np.zeros((n_samples, len(FEATURE_NAMES)))
        y = np.zeros(n_samples, dtype=int)

        for i in range(n_samples):
            key_size = rng.choice([64, 128, 256, 512, 1024, 2048, 4096])
            uses_md5 = rng.random() < 0.2
            uses_sha1 = rng.random() < 0.15
            uses_des = rng.random() < 0.1
            uses_rc2 = rng.random() < 0.05
            uses_ecb = rng.random() < 0.12
            rsa_small = key_size < 2048 and rng.random() < 0.3
            aes_small = key_size < 128 and rng.random() < 0.2
            hardcoded = rng.random() < 0.08
            insecure_rand = rng.random() < 0.15
            tls_ver = rng.choice([0.0, 1.0, 1.1, 1.2, 1.3], p=[0.05, 0.05, 0.1, 0.5, 0.3])
            cert_days = rng.randint(-30, 365)
            fwd_secrecy = rng.random() < 0.7
            has_hsts = rng.random() < 0.6
            self_signed = rng.random() < 0.1

            rule_score = 0
            if rsa_small: rule_score += 30
            if aes_small: rule_score += 30
            if uses_md5: rule_score += 20
            if uses_sha1: rule_score += 20
            if uses_des: rule_score += 30
            if uses_ecb: rule_score += 25
            if hardcoded: rule_score += 40
            if insecure_rand: rule_score += 15
            if self_signed: rule_score += 25
            if tls_ver < 1.2 and tls_ver > 0: rule_score += 30
            rule_score = min(rule_score, 100)

            X[i] = [key_size, uses_md5, uses_sha1, uses_des, uses_rc2, uses_ecb,
                     rsa_small, aes_small, hardcoded, insecure_rand, tls_ver,
                     cert_days, fwd_secrecy, has_hsts, self_signed, rule_score]

            if rule_score >= 60:
                y[i] = 3  # Critical
            elif rule_score >= 40:
                y[i] = 2  # High
            elif rule_score >= 20:
                y[i] = 1  # Medium
            else:
                y[i] = 0  # Low

            # Add limited label noise so the synthetic task remains learnable.
            if rng.random() < 0.15:
                noise = rng.choice([-1, 1])
                y[i] = max(0, min(3, y[i] + noise))

        return X, y

    @staticmethod
    def _class_to_score(class_idx: int, confidence: float) -> float:
        base_scores = {0: 15, 1: 40, 2: 65, 3: 90}
        base = base_scores.get(class_idx, 50)
        return base * confidence + (100 - base) * (1 - confidence) * 0.3

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 75:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        return "Low"

    def explain(self, features: CryptoFeatures) -> Optional[dict[str, float]]:
        if self.clf is None:
            return None
        try:
            import shap
            vec = self.features_to_vector(features).reshape(1, -1)
            explainer = shap.TreeExplainer(self.clf)
            shap_values = explainer.shap_values(vec)
            # For multi-class, take the predicted class SHAP values
            predicted_class = int(self.clf.predict(vec)[0])
            class_shap = shap_values[predicted_class][0] if isinstance(shap_values, list) else shap_values[0]
            return dict(zip(FEATURE_NAMES, class_shap.tolist()))
        except Exception as e:
            logger.warning(f"SHAP explanation failed: {e}")
            return None
