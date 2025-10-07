# train_threat_model.py
import os
import joblib
import numpy as np
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from features import RegexFeatures

# -----------------------------
# Sample dataset
texts = [
    # Safe files
    "This is a normal text file. Nothing suspicious.",
    "User activity log for system monitoring.",
    "Regular report of system usage. All tasks completed successfully.",
    "Meeting notes and project documentation for Q4.",
    "Daily backup report completed successfully on 2025-10-05.",
    "Invoice report for October 2025.",
    "Test file with harmless logs.",
    
    # Malicious files
    "Malware detected: trojan found in system.",
    "Virus found in downloaded files.",
    "Suspicious executable detected: file.exe flagged by heuristics.",
    "Warning: ransomware activity detected. Encrypted files found, payment demanded.",
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    "CONNECT_BACK: 192.0.2.123:4444",
    "EXFIL_ENDPOINT: http://mal.example.com/upload",
    "C2_KEY: SIMULATED_KEY_ABC123"
]

labels = [
    0, 0, 0, 0, 0, 0, 0,   # Safe
    1, 1, 1, 1, 1, 1, 1, 1  # Malicious
]

# -----------------------------
# Build pipeline
tfidf = TfidfVectorizer(ngram_range=(1, 2), lowercase=True, max_features=5000)
features = FeatureUnion([
    ("tfidf", tfidf),
    ("regex", RegexFeatures())
])
clf = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
pipeline = Pipeline([
    ("features", features),
    ("clf", clf)
])

# -----------------------------
# Train / test split
X_train, X_test, y_train, y_test = train_test_split(
    texts, labels, test_size=0.25, random_state=42, stratify=labels
)

pipeline.fit(X_train, y_train)

# Evaluate
y_pred = pipeline.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred, digits=4))

# Save the pipeline
os.makedirs("models", exist_ok=True)
joblib.dump(pipeline, "models/threat_pipeline.pkl")
print("Pipeline saved to models/threat_pipeline.pkl")
