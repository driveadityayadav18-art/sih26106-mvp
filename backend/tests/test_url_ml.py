"""
Unit tests for the Scikit-Learn Random Forest URL Detector and 20 Feature Extraction.
"""

import os
import pytest
from backend.detectors.url_ml import (
    URLRiskClassifier,
    predict_url_risk,
    extract_url_features,
    calculate_shannon_entropy,
    is_ip_address,
    FEATURE_NAMES,
)
from backend.parser.models import ParsedEmail, URLMetadata
from backend.detection.detection import ThreatDetector
from backend.detection.rules.urls_attachments import check_url_ml_risk


def test_20_features_extracted_and_complete():
    """Verify that feature extraction yields exactly 20 named features."""
    url = "https://secure-login.auth-portal.xyz/verify/account?session_id=12345&token=98765"
    features = extract_url_features(url)
    assert len(features) == 20
    assert len(FEATURE_NAMES) == 20
    for feat_name in FEATURE_NAMES:
        assert feat_name in features
        assert isinstance(features[feat_name], (int, float))


def test_shannon_entropy_calculation():
    """Verify Shannon entropy responds to character variation."""
    assert calculate_shannon_entropy("") == 0.0
    # Single character has 0 entropy
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    # Diverse character distribution has high entropy (> 3.0)
    high_ent = calculate_shannon_entropy("aB3$kL9@zX#1qW7!")
    assert high_ent > 3.5


def test_is_ip_address_detector():
    """Verify IPv4 and IPv6 detection."""
    assert is_ip_address("192.168.1.1") == 1
    assert is_ip_address("10.0.0.1:8080") == 1
    assert is_ip_address("google.com") == 0
    assert is_ip_address("paypal.security-update.xyz") == 0


def test_predict_url_risk_benign_urls():
    """Verify that known benign URLs return low risk and is_malicious False."""
    benign_samples = [
        "https://google.com/search?q=cybersecurity+defense",
        "https://github.com/torvalds/linux/pull/123",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://cisa.gov/resources-tools",
    ]
    for url in benign_samples:
        res = predict_url_risk(url)
        assert res["phishing_probability"] < 0.50
        assert res["is_malicious"] is False
        assert isinstance(res["features_extracted"], dict)
        assert len(res["features_extracted"]) == 20
        assert isinstance(res["top_risk_factors"], list)


def test_predict_url_risk_phishing_urls():
    """Verify that phishing-lured URLs return elevated risk and is_malicious True."""
    phishing_samples = [
        "http://paypal-security-verification.login-auth.xyz/verify/account?user=paypal&session_id=892348234&auth_token=893247923749",
        "http://192.168.1.50:8080/secure/bankofamerica/login.php?token=982347923&id=98765",
        "http://secure-chase-update-account-99.top/portal/auth?redirect=https%3A%2F%2Fchase.com&code=9823",
        "http://login-verify-account-security-update-center.work/auth/checkpoint/step/2?uid=987234&token=8923749823",
    ]
    for url in phishing_samples:
        res = predict_url_risk(url)
        assert res["phishing_probability"] >= 0.50
        assert res["is_malicious"] is True
        assert len(res["top_risk_factors"]) > 0


def test_classifier_loads_and_evaluates():
    """Verify URLRiskClassifier instance methods and properties."""
    clf = URLRiskClassifier()
    assert clf.model is not None
    assert len(clf.feature_names) == 20
    test_url = "https://example.com"
    out = clf.predict_url_risk(test_url)
    assert "phishing_probability" in out
    assert "is_malicious" in out
    assert "features_extracted" in out
    assert "top_risk_factors" in out


def test_integration_threat_detector_triggers_ml_phishing_rule():
    """Verify ThreatDetector raises ML_PHISHING_URL_DETECTED on malicious URLs."""
    email = ParsedEmail()
    email.message.urls.append(
        URLMetadata(
            raw="http://paypal-security-verification.login-auth.xyz/verify/account?user=paypal&session_id=892348234&auth_token=893247923749",
            host="paypal-security-verification.login-auth.xyz",
            scheme="http",
            parse_status="parsed",
        )
    )
    email.authentication.spf.result = "pass"
    email.authentication.dkim.result = "pass"

    detector = ThreatDetector()
    result = detector.analyze(email)

    codes = [rc["code"] for rc in result["reason_codes"]]
    assert "ML_PHISHING_URL_DETECTED" in codes
    assert result["score"] >= 25
