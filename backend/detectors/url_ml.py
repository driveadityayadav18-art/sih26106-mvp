"""
TraceShield Machine Learning URL Detector (Scikit-Learn Random Forest)
Extracts 20 lexical/structural URL features and calculates phishing probability using
a pre-trained Random Forest Classifier.
"""

import os
import sys
from typing import Any, Dict, List, Optional
import numpy as np
import joblib

# Ensure imports work across package roots
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from backend.scripts.train_url_model import (
    FEATURE_NAMES,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_KEYWORDS,
    POPULAR_BRANDS,
    calculate_shannon_entropy,
    is_ip_address,
    extract_url_features,
    feature_dict_to_vector,
    train_and_save_model,
)

__all__ = [
    "URLRiskClassifier",
    "predict_url_risk",
    "get_url_classifier",
    "extract_url_features",
    "calculate_shannon_entropy",
    "is_ip_address",
    "FEATURE_NAMES",
]

DEFAULT_MODEL_PATH = os.path.join(backend_dir, "models", "rf_url_model.joblib")


class URLRiskClassifier:
    """
    Random Forest URL Risk Classifier for Phishing and Malicious Link Detection.
    Loads trained artifact or automatically trains if absent.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.model = None
        self.feature_names = FEATURE_NAMES
        self.metadata = {}
        self._load_or_train()

    def _load_or_train(self) -> None:
        """Loads the serialized model artifact or triggers automatic training if missing."""
        if not os.path.exists(self.model_path):
            print(f"[!] Model artifact not found at {self.model_path}. Initiating automatic training...")
            res = train_and_save_model(output_path=self.model_path)
            print(f"[+] Model trained automatically. Accuracy: {res['accuracy'] * 100:.2f}%")

        try:
            artifact = joblib.load(self.model_path)
            if isinstance(artifact, dict) and "model" in artifact:
                self.model = artifact["model"]
                self.feature_names = artifact.get("feature_names", FEATURE_NAMES)
                self.metadata = {k: v for k, v in artifact.items() if k != "model"}
            else:
                self.model = artifact
        except Exception as e:
            print(f"[!] Failed to load model artifact ({e}). Retraining...")
            res = train_and_save_model(output_path=self.model_path)
            artifact = joblib.load(self.model_path)
            self.model = artifact["model"] if isinstance(artifact, dict) else artifact

    def _identify_top_risk_factors(self, url: str, features: Dict[str, float]) -> List[str]:
        """Identifies human-readable explanations of elevated risk factors based on extracted features."""
        factors: List[str] = []

        if features.get("has_ip_address", 0) == 1.0:
            factors.append("Host is an IP literal address instead of a registered domain")

        if features.get("has_punycode", 0) == 1.0:
            factors.append("Host uses IDN Punycode ('xn--'), indicative of domain homograph spoofing")

        if features.get("suspicious_tld", 0) == 1.0:
            factors.append("Domain uses a high-abuse top-level domain (TLD)")

        kw_count = int(features.get("suspicious_keyword_count", 0))
        if kw_count > 0:
            found_kws = [k for k in SUSPICIOUS_KEYWORDS if k in url.lower()]
            kw_str = ", ".join(found_kws[:3])
            factors.append(f"Contains {kw_count} suspicious security/login keywords ('{kw_str}')")

        if features.get("brand_name_in_subdomain", 0) == 1.0:
            factors.append("Major brand name impersonated in subdomain prefix")

        if features.get("hyphen_in_domain", 0) == 1.0 and features.get("count_hyphens", 0) >= 2:
            factors.append("Multiple hyphens in domain name (common typo-squatting pattern)")

        if features.get("port_present", 0) == 1.0:
            factors.append("URL explicitly targets a non-standard network port")

        if features.get("shannon_entropy", 0) > 4.3:
            factors.append(f"High character entropy ({features.get('shannon_entropy', 0):.2f}), indicating token obfuscation")

        if features.get("digit_to_letter_ratio", 0) > 0.35 and features.get("count_digits", 0) > 8:
            factors.append("Abnormally high digit-to-letter ratio in URL")

        if features.get("url_length", 0) > 100:
            factors.append(f"Excessive URL character length ({int(features.get('url_length', 0))} chars)")

        if features.get("count_at", 0) > 0:
            factors.append("URL contains '@' credential delimiter symbol")

        if features.get("is_https", 1) == 0.0:
            factors.append("Insecure plain HTTP connection")

        if not factors and features.get("count_subdomains", 0) >= 3:
            factors.append("Deeply nested subdomain hierarchy")

        return factors

    def predict_url_risk(self, url: str) -> Dict[str, Any]:
        """
        Extracts 20 features and predicts risk metrics using Random Forest Classifier.

        Returns:
            {
                "phishing_probability": float (0.0 to 1.0),
                "is_malicious": bool,
                "features_extracted": dict (20 features),
                "top_risk_factors": list of strings
            }
        """
        features = extract_url_features(url)
        vector = feature_dict_to_vector(features)
        X = np.array([vector], dtype=np.float32)

        try:
            proba = self.model.predict_proba(X)[0]
            # Index 1 is probability of phishing (class 1)
            phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
        except Exception:
            # Fallback if prediction fails
            pred = self.model.predict(X)[0]
            phishing_prob = float(pred)

        phishing_prob = round(phishing_prob, 4)
        is_malicious = bool(phishing_prob >= 0.50)
        top_risk_factors = self._identify_top_risk_factors(url, features)

        return {
            "phishing_probability": phishing_prob,
            "is_malicious": is_malicious,
            "features_extracted": features,
            "top_risk_factors": top_risk_factors,
        }


# Global singleton instance for high-performance reuse
_default_classifier: Optional[URLRiskClassifier] = None


def get_url_classifier() -> URLRiskClassifier:
    """Returns or initializes the global URL Risk Classifier singleton."""
    global _default_classifier
    if _default_classifier is None:
        _default_classifier = URLRiskClassifier()
    return _default_classifier


def predict_url_risk(url: str) -> Dict[str, Any]:
    """
    Public API function to extract 20 features and predict phishing risk for a URL.
    """
    classifier = get_url_classifier()
    return classifier.predict_url_risk(url)
