import os
import joblib
import numpy as np
from features import RegexFeatures

# Additional libraries for file reading
from PyPDF2 import PdfReader
from docx import Document

# Path to trained model
MODEL_PATH = "models/threat_pipeline.pkl"

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Pipeline not found at {MODEL_PATH}. Train the model first!")

# Load pipeline
pipeline = joblib.load(MODEL_PATH)

# -----------------------------
# Helper function to extract text from various file types
def extract_text(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    text = ""

    try:
        # 1️⃣ For TXT or LOG files
        if ext in [".txt", ".log"]:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()

        # 2️⃣ For PDF files
        elif ext == ".pdf":
            reader = PdfReader(file_path)
            for page in reader.pages:
                text += page.extract_text() or ""

        # 3️⃣ For DOCX files
        elif ext == ".docx":
            doc = Document(file_path)
            for para in doc.paragraphs:
                text += para.text + "\n"

        else:
            raise ValueError("Unsupported file format. Please upload .txt, .log, .pdf, or .docx file.")

    except Exception as e:
        raise RuntimeError(f"Error reading {ext} file: {str(e)}")

    return text.strip()

# -----------------------------
# Prediction function
def predict_threat(file_path):
    """
    Predict if a file is malicious or safe.
    Returns a dictionary: message, probability_malicious, label
    """
    try:
        text = extract_text(file_path)
        if not text.strip():
            return {
                "message": "No readable text found in file.",
                "probability_malicious": 0,
                "label": "Unknown"
            }

        pred = pipeline.predict([text])[0]
        proba = pipeline.predict_proba([text])[0][pred] * 100
        label = "Malicious" if pred else "Safe"
        msg = "⚠️ Malicious File Detected" if pred else "✅ File is Safe"

        return {
            "message": msg,
            "probability_malicious": round(proba, 2),
            "label": label
        }

    except Exception as e:
        return {
            "message": f"Failed to analyze file: {str(e)}",
            "probability_malicious": 0,
            "label": "Unknown"
        }
