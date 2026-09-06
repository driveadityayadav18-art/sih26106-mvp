import asyncio
import io
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

backend_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(backend_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from fastapi import UploadFile
import main
from main import analyze_risk, create_case, enrich_and_correlate, parse_email, tier_2_llm_review, case_db


class TestRiskDetectionEngine(unittest.TestCase):
    def setUp(self):
        main.case_db.clear()

    def test_phishing_fixture_triggers_all_rules(self):
        fixture_path = os.path.join(os.path.dirname(__file__), "..", "data", "fixtures", "test_phishing.eml")
        with open(fixture_path, "rb") as f:
            raw_bytes = f.read()
        parsed = parse_email(raw_bytes)
        result = analyze_risk(parsed)
        
        self.assertEqual(result["score"], 43)
        self.assertEqual(result["band"], "REVIEW")
        codes = [rc["code"] for rc in result["reason_codes"]]
        self.assertIn("REPLY_TO_MISMATCH", codes)
        self.assertIn("URGENT_PAYMENT_REQUEST", codes)
        
        # Verify evidence paths are present
        for rc in result["reason_codes"]:
            self.assertTrue(rc["evidence_path"].startswith("message.") or rc["evidence_path"].startswith("authentication."))

    def test_clean_email_low_risk(self):
        clean_email = {
            "from": {"name": "Alice", "address": "alice@company.example"},
            "reply_to": "alice@company.example",
            "return_path": "alice@company.example",
            "subject": "Monthly status report",
            "urls": ["https://company.example/reports/august"],
        }
        result = analyze_risk(clean_email)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["band"], "LOW")
        self.assertEqual(len(result["reason_codes"]), 0)

    def test_reply_to_mismatch_only(self):
        email_data = {
            "from": {"name": "Support", "address": "support@service.example"},
            "reply_to": "attacker@evil.example",
            "subject": "Meeting notes",
            "urls": ["https://service.example/help"],
        }
        result = analyze_risk(email_data)
        self.assertEqual(result["score"], 50)
        self.assertEqual(result["band"], "REVIEW")
        self.assertEqual(len(result["reason_codes"]), 1)
        self.assertEqual(result["reason_codes"][0]["code"], "REPLY_TO_MISMATCH")

    def test_urgent_subject_only(self):
        email_data = {
            "from": {"name": "Manager", "address": "boss@company.example"},
            "reply_to": "boss@company.example",
            "subject": "URGENT review needed by 5pm",
            "urls": ["https://company.example/doc"],
        }
        result = analyze_risk(email_data)
        self.assertEqual(result["score"], 20)
        self.assertEqual(result["band"], "LOW")
        self.assertEqual(len(result["reason_codes"]), 1)
        self.assertEqual(result["reason_codes"][0]["code"], "URGENT_SUBJECT")

    def test_suspicious_url_only(self):
        email_data = {
            "from": {"name": "Billing", "address": "billing@company.example"},
            "reply_to": "billing@company.example",
            "subject": "Invoice attached",
            "urls": ["https://malicious-external.example/login"],
        }
        result = analyze_risk(email_data)
        self.assertEqual(result["score"], 20)
        self.assertEqual(result["band"], "LOW")
        self.assertEqual(len(result["reason_codes"]), 1)
        self.assertEqual(result["reason_codes"][0]["code"], "SUSPICIOUS_URL")

    def test_authenticated_esp_reply_to_mismatch(self):
        # Authenticated ESP sending on behalf of brand with reply-to pointing to ESP domain
        email_data_spf = {
            "from": {"name": "Newsletter", "address": "news@techbrand.example"},
            "reply_to": "author@beehiiv.com",
            "subject": "Weekly Tech Digest",
            "urls": ["https://techbrand.example/article"],
            "spf": "pass",
            "dkim": "none",
        }
        result_spf = analyze_risk(email_data_spf)
        self.assertEqual(result_spf["score"], 5)
        self.assertEqual(result_spf["band"], "LOW")
        self.assertEqual(len(result_spf["reason_codes"]), 1)
        self.assertEqual(result_spf["reason_codes"][0]["code"], "REPLY_TO_ESP_MISMATCH")
        self.assertIn("authenticated ESP relay", result_spf["reason_codes"][0]["evidence_path"])

        email_data_dkim = {
            "from": {"name": "Newsletter", "address": "news@techbrand.example"},
            "reply_to": "author@mailchimp.com",
            "subject": "Weekly Tech Digest",
            "urls": ["https://techbrand.example/article"],
            "spf": "none",
            "dkim": "pass",
        }
        result_dkim = analyze_risk(email_data_dkim)
        self.assertEqual(result_dkim["score"], 5)
        self.assertEqual(result_dkim["band"], "LOW")
        self.assertEqual(result_dkim["reason_codes"][0]["code"], "REPLY_TO_ESP_MISMATCH")

    def test_trusted_url_exclusions(self):
        # URLs to known trusted domains (e.g. YouTube, Twitter, LinkedIn, TechCrunch)
        email_data = {
            "from": {"name": "Writer", "address": "writer@techbrand.example"},
            "reply_to": "writer@techbrand.example",
            "subject": "Check out these resources",
            "urls": [
                "https://youtube.com/watch?v=123",
                "https://twitter.com/techfeed",
                "https://linkedin.com/in/author",
                "https://techcrunch.com/2026/08/article",
            ],
        }
        result = analyze_risk(email_data)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["band"], "LOW")
        self.assertEqual(len(result["reason_codes"]), 0)

    def test_missing_and_malformed_fields_safe(self):
        empty_data = {}
        result = analyze_risk(empty_data)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["band"], "LOW")
        self.assertEqual(result["reason_codes"], [])

        none_data = {
            "from": None,
            "reply_to": None,
            "subject": None,
            "urls": None,
        }
        result2 = analyze_risk(none_data)
        self.assertEqual(result2["score"], 0)
        self.assertEqual(result2["band"], "LOW")
        self.assertEqual(result2["reason_codes"], [])

    def test_enrich_and_correlate_demo_intel_hit(self):
        parsed_email = {
            "reply_to": "payment-update@aicte-payments.example",
            "urls": ["http://aicte-payments.example/update"],
        }
        res = enrich_and_correlate(parsed_email, [])
        self.assertEqual(res["infrastructure"]["provider_status"], "demo_cache")
        self.assertEqual(len(res["infrastructure"]["geo"]), 1)
        self.assertEqual(res["infrastructure"]["geo"][0]["country"], "Demo Land")
        self.assertEqual(res["infrastructure"]["geo"][0]["city"], "Demo City")
        self.assertEqual(res["campaign"]["related_case_ids"], [])

    def test_enrich_and_correlate_unknown_domain(self):
        parsed_email = {
            "reply_to": "user@unknown-domain.example",
            "urls": ["http://unknown-domain.example/page"],
        }
        res = enrich_and_correlate(parsed_email, [])
        self.assertEqual(res["infrastructure"]["provider_status"], "demo_cache")
        self.assertEqual(res["infrastructure"]["geo"], [])
        self.assertEqual(len(res["infrastructure"]["indicators"]), 1)

    def test_campaign_correlation_with_prior_case(self):
        prior_cases = [
            {
                "case_id": "TS-DEMO-001",
                "message": {
                    "reply_to": "payment-update@aicte-payments.example",
                },
            }
        ]
        parsed_email = {
            "reply_to": "payment-update@aicte-payments.example",
            "urls": [],
        }
        res = enrich_and_correlate(parsed_email, prior_cases)
        self.assertIn("TS-DEMO-001", res["campaign"]["related_case_ids"])
        self.assertEqual(len(res["campaign"]["shared_indicators"]), 1)
        self.assertEqual(res["campaign"]["shared_indicators"][0]["value"], "aicte-payments.example")
        self.assertTrue(len(res["campaign"]["graph_nodes"]) >= 3)
        self.assertTrue(len(res["campaign"]["graph_edges"]) >= 2)

    def test_api_case_endpoint_integration_and_db_append(self):
        fixture_path = os.path.join(os.path.dirname(__file__), "..", "data", "fixtures", "test_phishing.eml")
        with open(fixture_path, "rb") as f:
            content = f.read()
        
        # First case creation
        upload_file_1 = UploadFile(file=io.BytesIO(content), filename="test_phishing.eml")
        data_1 = asyncio.run(create_case(upload_file_1))
        
        self.assertEqual(data_1["case_id"], "TS-DEMO-001")
        self.assertEqual(data_1["risk"]["score"], 43)
        self.assertEqual(data_1["risk"]["band"], "REVIEW")
        self.assertIn("infrastructure", data_1)
        self.assertEqual(data_1["infrastructure"]["provider_status"], "demo_cache")
        self.assertEqual(len(data_1["infrastructure"]["geo"]), 1)
        self.assertEqual(data_1["campaign"]["related_case_ids"], [])
        self.assertEqual(len(main.case_db), 1)

        # Second case creation with same indicator
        upload_file_2 = UploadFile(file=io.BytesIO(content), filename="test_phishing_2.eml")
        data_2 = asyncio.run(create_case(upload_file_2))
        
        self.assertEqual(data_2["case_id"], "TS-DEMO-002")
        self.assertIn("TS-DEMO-001", data_2["campaign"]["related_case_ids"])
        self.assertEqual(len(data_2["campaign"]["shared_indicators"]), 1)
        self.assertEqual(len(main.case_db), 2)

    def test_tier_2_llm_review_success(self):
        parsed_email = {
            "from": {"name": "Newsletter", "address": "news@beehiiv.com"},
            "reply_to": "author@custom.example",
            "subject": "Weekly Update",
            "urls": ["https://youtube.com/watch?v=xyz"],
        }
        rule_risk = {
            "score": 70,
            "band": "HIGH",
            "reason_codes": [{"code": "REPLY_TO_MISMATCH", "title": "Mismatch", "evidence_path": "message.reply_to"}],
        }

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "is_false_positive": True,
            "adjusted_score": 10,
            "adjusted_band": "LOW",
            "analyst_summary": "Legitimate newsletter sent via Beehiiv ESP.",
        })
        mock_response.choices = [mock_choice]

        with patch.object(main.groq_client.chat.completions, "create", return_value=mock_response):
            result = asyncio.run(tier_2_llm_review(parsed_email, rule_risk))
            self.assertTrue(result["is_false_positive"])
            self.assertEqual(result["adjusted_score"], 10)
            self.assertEqual(result["adjusted_band"], "LOW")
            self.assertEqual(result["analyst_summary"], "Legitimate newsletter sent via Beehiiv ESP.")

    def test_tier_2_llm_review_failure_graceful_fallback(self):
        parsed_email = {
            "from": {"name": "Hacker", "address": "spoof@bank.example"},
            "reply_to": "evil@attacker.example",
            "subject": "URGENT password reset",
            "urls": ["http://phish.example/login"],
        }
        rule_risk = {
            "score": 90,
            "band": "HIGH",
            "reason_codes": [],
        }

        with patch.object(main.groq_client.chat.completions, "create", side_effect=Exception("API connection timeout")):
            result = asyncio.run(tier_2_llm_review(parsed_email, rule_risk))
            self.assertEqual(result, {"error": "LLM review unavailable"})

    def test_create_case_low_risk_sets_ai_review_to_none(self):
        clean_email_content = b"From: clean@example.com\r\nSubject: Hello\r\n\r\nClean body"
        upload_file = UploadFile(file=io.BytesIO(clean_email_content), filename="clean.eml")
        data = asyncio.run(create_case(upload_file))
        
        self.assertLess(data["risk"]["score"], 70)
        self.assertIsNone(data["ai_review"])

    def test_create_case_high_risk_invokes_tier_2_llm_review(self):
        fixture_path = os.path.join(os.path.dirname(__file__), "..", "data", "fixtures", "01_payment_diversion.eml")
        with open(fixture_path, "rb") as f:
            content = f.read()

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "is_false_positive": False,
            "adjusted_score": 95,
            "adjusted_band": "HIGH",
            "analyst_summary": "Confirmed malicious phishing attempt.",
        })
        mock_response.choices = [mock_choice]

        with patch.object(main.groq_client.chat.completions, "create", return_value=mock_response):
            upload_file = UploadFile(file=io.BytesIO(content), filename="01_payment_diversion.eml")
            data = asyncio.run(create_case(upload_file))
            
            self.assertGreaterEqual(data["risk"]["score"], 70)
            self.assertIsNotNone(data["ai_review"])
            self.assertFalse(data["ai_review"]["is_false_positive"])
            self.assertEqual(data["ai_review"]["adjusted_score"], 95)
            self.assertEqual(data["ai_review"]["adjusted_band"], "HIGH")


if __name__ == "__main__":
    unittest.main()
