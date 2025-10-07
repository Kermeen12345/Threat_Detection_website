# threat_model.py
import os
import joblib
import numpy as np
from features import RegexFeatures

# Path to trained model
MODEL_PATH = "models/threat_pipeline.pkl"

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Pipeline not found at {MODEL_PATH}. Train the model first!")

# Load pipeline
pipeline = joblib.load(MODEL_PATH)

# -----------------------------
# Prediction function
def predict_threat(file_path):
    """
    Predict if a file is malicious or safe.
    Returns a dictionary: message, probability_malicious, label
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception as e:
        return {
            "message": f"Failed to read file: {str(e)}",
            "probability_malicious": 0,
            "label": "Unknown"
        }

    pred = pipeline.predict([text])[0]
    proba = pipeline.predict_proba([text])[0][pred] * 100
    label = "Malicious" if pred else "Safe"
    msg = "Malicious Log Detected" if pred else "File is safe"

    return {
        "message": msg,
        "probability_malicious": round(proba, 2),
        "label": label
    }
