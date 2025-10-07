# features.py
import re
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

class RegexFeatures(BaseEstimator, TransformerMixin):
    """
    Custom transformer to extract regex-based features from text.
    """
    def __init__(self):
        self.patterns = {
            "has_eicar": re.compile(r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", re.IGNORECASE),
            "has_ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            "has_url": re.compile(r"https?://\S+"),
            "has_base64": re.compile(r"^[A-Za-z0-9+/=]{40,}$"),
            "has_ransom": re.compile(r"ransom|encrypt(ed)? files|payment|demand", re.IGNORECASE),
            "has_exec": re.compile(r"\.exe\b|executable|shellcode", re.IGNORECASE)
        }

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for doc in X:
            doc_features = [int(bool(pat.search(doc))) for pat in self.patterns.values()]
            features.append(doc_features)
        return np.array(features)
