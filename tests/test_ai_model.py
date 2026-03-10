import pytest
import numpy as np
from app.services.ai_risk_model import AIRiskModel
from app.models.pydantic_models import CryptoFeatures


@pytest.fixture(scope="module")
def trained_model():
    model = AIRiskModel()
    model.clf = None
    metrics = model.train_model()
    return model, metrics


def test_training_metrics(trained_model):
    model, metrics = trained_model
    assert metrics["accuracy"] > 0.5
    assert metrics["f1"] > 0.4
    assert model.clf is not None


def test_prediction_critical(trained_model):
    model, _ = trained_model
    features = CryptoFeatures(
        uses_md5=True, uses_des=True, hardcoded_key=True,
        rsa_key_small=True, insecure_random=True, rule_score=90
    )
    pred = model.predict(features)
    assert pred.score > 50
    assert pred.severity in ("High", "Critical")


def test_prediction_low(trained_model):
    model, _ = trained_model
    features = CryptoFeatures(
        key_size=4096, tls_version="TLSv1.3", cert_valid_days=365,
        forward_secrecy=True, has_hsts=True, rule_score=0
    )
    pred = model.predict(features)
    assert pred.score < 50


def test_feature_importances(trained_model):
    model, _ = trained_model
    features = CryptoFeatures(rule_score=50)
    pred = model.predict(features)
    assert pred.feature_importances is not None
    assert len(pred.feature_importances) == 16


def test_features_to_vector():
    model = AIRiskModel()
    features = CryptoFeatures(
        key_size=2048, uses_md5=True, tls_version="TLSv1.2",
        cert_valid_days=100, forward_secrecy=True, has_hsts=True, rule_score=20
    )
    vec = model.features_to_vector(features)
    assert isinstance(vec, np.ndarray)
    assert len(vec) == 16
    assert vec[0] == 2048  # key_size
    assert vec[1] == 1     # uses_md5


def test_score_to_severity():
    assert AIRiskModel._score_to_severity(90) == "Critical"
    assert AIRiskModel._score_to_severity(60) == "High"
    assert AIRiskModel._score_to_severity(30) == "Medium"
    assert AIRiskModel._score_to_severity(10) == "Low"
