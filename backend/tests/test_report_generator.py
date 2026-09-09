"""
Test suite for TraceShield Forensic Report Generation and Export Endpoint.

Validates:
1. Scikit-Learn Random Forest URL Classification (probability, verdict, 20 structural features).
2. Tor & Proxy Intelligence (Tor exit node identification across trace hops and origin).
3. Privacy & PII Sanitization Audit (explicit confirmation that phone/card/aadhaar data was redacted).
4. Mitigation & Firewall Status (IMAP quarantine action log and iptables rule).
5. HTML, Markdown, and JSON report generation for all persisted cases without 500 errors.
"""

import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db import get_all_cases, get_case
from backend.reporting.report_generator import (
    generate_html_report,
    generate_markdown_report,
    generate_json_report,
    _get_url_ml_intelligence,
    _get_tor_proxy_intelligence,
    _get_privacy_audit_intelligence,
    _get_mitigation_intelligence,
)
from backend.services.report_generator import (
    generate_html_report as service_generate_html,
    generate_json_report as service_generate_json,
    generate_markdown_report as service_generate_md,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sample_case():
    return {
        "case_id": "TS-TEST-REPORT-001",
        "created_at": "2026-09-09T14:30:00Z",
        "status": "QUARANTINED",
        "artifact": {
            "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "byte_length": 4096,
        },
        "message": {
            "subject": "Urgent: Verify Your Banking KYC",
            "from": {"name": "Security Team", "address": "alerts@bank-verification.com"},
            "reply_to": "attacker@darknet-node.org",
            "return_path": "bounce@bank-verification.com",
            "origin_ip": "185.220.101.5",  # Known Tor exit node in demo intel
            "urls": [
                {
                    "raw": "http://secure-login.bank-verification.com:8080/kyc/update?token=xyz123",
                    "host": "secure-login.bank-verification.com",
                }
            ],
        },
        "authentication": {
            "spf": {"result": "fail"},
            "dkim": {"result": "fail"},
            "dmarc": {"result": "fail"},
        },
        "risk": {
            "score": 85,
            "band": "HIGH",
            "reason_codes": [
                {
                    "code": "AUTH_DMARC_FAIL",
                    "title": "DMARC authentication failed",
                    "weight": 35,
                    "evidence_path": "authentication.dmarc.result",
                }
            ],
            "limitations": [],
            "url_ml_analysis": [
                {
                    "url": "http://secure-login.bank-verification.com:8080/kyc/update?token=xyz123",
                    "host": "secure-login.bank-verification.com",
                    "phishing_probability": 0.9420,
                    "is_malicious": True,
                    "top_risk_factors": [
                        "Insecure plain HTTP connection",
                        "Targeting non-standard network port",
                        "High character entropy token",
                    ],
                    "features": {
                        "url_length": 72.0,
                        "count_dots": 3.0,
                        "count_hyphens": 2.0,
                        "count_at": 0.0,
                        "count_subdomains": 2.0,
                        "has_ip_address": 0.0,
                        "count_digits": 6.0,
                        "digit_to_letter_ratio": 0.12,
                        "shannon_entropy": 4.65,
                        "is_https": 0.0,
                        "count_params": 1.0,
                        "count_queries": 1.0,
                        "count_slashes": 3.0,
                        "has_punycode": 0.0,
                        "suspicious_tld": 0.0,
                        "suspicious_keyword_count": 2.0,
                        "brand_name_in_subdomain": 1.0,
                        "path_length": 11.0,
                        "hyphen_in_domain": 1.0,
                        "port_present": 1.0,
                    },
                }
            ],
        },
        "trace": {
            "hops": [
                {
                    "index": 1,
                    "from_ip": "185.220.101.5",
                    "from_host": "tor-exit-node.example.org",
                    "by_host": "mx1.victim-corp.com",
                    "with_protocol": "ESMTP",
                    "timestamp": "2026-09-09T14:29:45Z",
                    "is_tor": True,
                    "is_proxy": False,
                    "trust": "untrusted",
                }
            ]
        },
        "privacy_audit": {
            "pii_sanitized": True,
            "masked_entities_count": 7,
            "cards_redacted": 2,
            "phones_redacted": 3,
            "emails_redacted": 1,
            "aadhaar_redacted": 1,
            "pii_detected": True,
        },
        "mitigation": {
            "action": "IMAP_STORE_FLAGS_DELETED",
            "target_message_id": "<MSG-TEST-001@bank-verification.com>",
            "originating_ip_firewall_rule": "iptables -A INPUT -s 185.220.101.5 -j DROP",
            "status": "APPLIED_SUCCESSFULLY",
            "timestamp": "2026-09-09T14:31:00Z",
        },
        "ai_review": {
            "analyst_summary": "High risk phishing campaign leveraging Tor exit relay and credential harvest landing page."
        },
    }


def test_service_re_export_parity():
    """Verify that backend.services.report_generator re-exports all public API symbols."""
    assert service_generate_html is generate_html_report
    assert service_generate_json is generate_json_report
    assert service_generate_md is generate_markdown_report


def test_url_ml_intelligence_extraction(sample_case):
    """Verify Scikit-Learn Random Forest URL Classification extraction and features."""
    url_intel = _get_url_ml_intelligence(sample_case)
    assert len(url_intel) == 1
    eval_item = url_intel[0]

    assert eval_item["phishing_probability"] == 0.9420
    assert eval_item["risk_verdict"] == "MALICIOUS / PHISHING"
    assert eval_item["is_malicious"] is True
    assert "features" in eval_item
    assert len(eval_item["features"]) == 20
    assert eval_item["features"]["port_present"] == 1.0
    assert eval_item["features"]["shannon_entropy"] == 4.65
    assert len(eval_item["top_risk_factors"]) == 3
    assert "timestamp" in eval_item


def test_tor_proxy_intelligence_extraction(sample_case):
    """Verify Tor exit node detection across trace hops."""
    tor_intel = _get_tor_proxy_intelligence(sample_case)
    assert tor_intel["has_tor_exit_node"] is True
    assert "CRITICAL" in tor_intel["verdict"]
    assert len(tor_intel["tor_exit_nodes"]) >= 1
    assert tor_intel["tor_exit_nodes"][0]["ip"] == "185.220.101.5"
    assert "timestamp" in tor_intel


def test_privacy_audit_intelligence_extraction(sample_case):
    """Verify Privacy & PII Sanitization confirmation and entity breakdown."""
    privacy_intel = _get_privacy_audit_intelligence(sample_case)
    assert privacy_intel["pii_sanitized"] is True
    assert "Confirmed: All phone numbers, credit/debit card numbers, and Indian Aadhaar ID data" in privacy_intel["confirmation"]
    assert privacy_intel["cards_redacted"] == 2
    assert privacy_intel["phones_redacted"] == 3
    assert privacy_intel["aadhaar_redacted"] == 1
    assert privacy_intel["total_masked_entities"] == 7
    assert "timestamp" in privacy_intel


def test_mitigation_intelligence_extraction(sample_case):
    """Verify IMAP quarantine action log and iptables rule extraction."""
    mit_intel = _get_mitigation_intelligence(sample_case)
    assert mit_intel["is_quarantined"] is True
    assert mit_intel["action"] == "IMAP_STORE_FLAGS_DELETED"
    assert mit_intel["target_message_id"] == "<MSG-TEST-001@bank-verification.com>"
    assert mit_intel["originating_ip_firewall_rule"] == "iptables -A INPUT -s 185.220.101.5 -j DROP"
    assert mit_intel["execution_status"] == "APPLIED_SUCCESSFULLY"
    assert "timestamp" in mit_intel


def test_html_report_generation(sample_case):
    """Verify HTML report includes visual summary boxes, timestamps, and core modules."""
    html = generate_html_report(sample_case)

    assert "<!DOCTYPE html>" in html
    assert "Scikit-Learn Random Forest URL Classification" in html
    assert "Tor &amp; Proxy Intelligence" in html or "Tor & Proxy Intelligence" in html
    assert "Privacy &amp; PII Sanitization Audit" in html or "Privacy & PII Sanitization Audit" in html
    assert "Mitigation &amp; Firewall Status" in html or "Mitigation & Firewall Status" in html
    assert "All phone numbers, credit/debit card numbers, and Indian Aadhaar ID data" in html
    assert "IMAP_STORE_FLAGS_DELETED" in html
    assert "iptables -A INPUT -s 185.220.101.5 -j DROP" in html
    assert "timestamp-pill" in html
    assert "action-bar" in html
    assert "window.print()" in html


def test_markdown_report_generation(sample_case):
    """Verify Markdown report includes headers and structured details."""
    md = generate_markdown_report(sample_case)

    assert "## Scikit-Learn Random Forest URL Classification" in md
    assert "## Tor & Proxy Intelligence" in md
    assert "## Privacy & PII Sanitization Audit" in md
    assert "## Mitigation & Firewall Status" in md
    assert "Confirmed: All phone numbers, credit/debit card numbers, and Indian Aadhaar ID data" in md
    assert "IMAP_STORE_FLAGS_DELETED" in md
    assert "iptables -A INPUT -s 185.220.101.5 -j DROP" in md


def test_json_report_generation(sample_case):
    """Verify JSON report contains all required top-level forensic intelligence keys."""
    report_dict = generate_json_report(sample_case)

    assert report_dict["case_id"] == "TS-TEST-REPORT-001"
    assert "scikit_learn_random_forest_url_classification" in report_dict
    assert "tor_and_proxy_intelligence" in report_dict
    assert "privacy_and_pii_sanitization_audit" in report_dict
    assert "mitigation_and_firewall_status" in report_dict

    # Check structural features in JSON
    url_evals = report_dict["scikit_learn_random_forest_url_classification"]["evaluations"]
    assert len(url_evals) == 1
    assert len(url_evals[0]["features"]) == 20
    assert url_evals[0]["phishing_probability"] == 0.9420

    # Check Tor
    assert report_dict["tor_and_proxy_intelligence"]["has_tor_exit_node"] is True

    # Check PII
    assert report_dict["privacy_and_pii_sanitization_audit"]["pii_sanitized"] is True
    assert report_dict["privacy_and_pii_sanitization_audit"]["aadhaar_redacted"] == 1

    # Check IMAP Quarantine
    assert report_dict["mitigation_and_firewall_status"]["action"] == "IMAP_STORE_FLAGS_DELETED"


def test_api_report_endpoints_for_all_existing_cases(client):
    """Verify GET /api/v1/cases/{case_id}/report returns 200 without 500 on all cases in DB."""
    cases = get_all_cases()
    assert len(cases) > 0, "Database should contain at least one case"

    for c in cases:
        case_id = c.get("case_id")

        # 1. Test HTML format
        r_html = client.get(f"/api/v1/cases/{case_id}/report?format=html")
        assert r_html.status_code == 200, f"HTML export failed for case {case_id}: {r_html.text}"
        assert "text/html" in r_html.headers["content-type"]
        assert len(r_html.text) > 1000
        assert "Scikit-Learn Random Forest URL Classification" in r_html.text
        assert "Privacy &amp; PII Sanitization Audit" in r_html.text or "Privacy & PII Sanitization Audit" in r_html.text
        assert "Mitigation &amp; Firewall Status" in r_html.text or "Mitigation & Firewall Status" in r_html.text

        # 2. Test JSON format
        r_json = client.get(f"/api/v1/cases/{case_id}/report?format=json")
        assert r_json.status_code == 200, f"JSON export failed for case {case_id}: {r_json.text}"
        assert "application/json" in r_json.headers["content-type"]
        json_data = r_json.json()
        assert json_data["case_id"] == case_id
        assert "scikit_learn_random_forest_url_classification" in json_data
        assert "tor_and_proxy_intelligence" in json_data
        assert "privacy_and_pii_sanitization_audit" in json_data
        assert "mitigation_and_firewall_status" in json_data

        # 3. Test Markdown format
        r_md = client.get(f"/api/v1/cases/{case_id}/report?format=markdown")
        assert r_md.status_code == 200, f"Markdown export failed for case {case_id}: {r_md.text}"
        assert "text/markdown" in r_md.headers["content-type"]
        assert len(r_md.text) > 500


def test_api_report_404_for_nonexistent_case(client):
    """Verify 404 is returned for nonexistent case ID."""
    r = client.get("/api/v1/cases/NONEXISTENT-CASE-ID-999/report?format=html")
    assert r.status_code == 404
