#!/usr/bin/env python3
"""Standalone ML model training script."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.services.ai_risk_model import AIRiskModel


def main():
    print("Training VulNexus AI Risk Scoring Model...")
    model = AIRiskModel()
    metrics = model.train_model()
    print(f"\nTraining Results:")
    for k, v in metrics.items():
        print(f"  {k}: {v:.4f}")
    print(f"\nModel saved to {os.environ.get('ML_MODEL_PATH', './ml_models/risk_model.joblib')}")


if __name__ == "__main__":
    main()
