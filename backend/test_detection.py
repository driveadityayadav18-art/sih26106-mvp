"""
Tests for the real detection pipeline:
  - ThreatDetector (from backend.detection.detection) against ParsedEmail objects
  - main.py create_case(), enrich_and_correlate(), tier_2_llm_review(), and API endpoints

Replaces the former tests that targeted the now-deleted analyze_risk / parse_email
wrappers.  Mirrors the pattern used by backend/tests/test_detection_detector.py.
"""

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

# Isolate test database and test artifacts to protect development and demo data
TEST_DB_PATH = os.path.join(backend_dir, "data", "traceshield_test.db")
TEST_ARTIFACTS_DIR = os.path.join(backend_dir, "data", "test_artifacts")
os.environ["TRACESHIELD_DB_PATH"] = TEST_DB_PATH
os.environ["ARTIFACTS_DIR"] = TEST_ARTIFACTS_DIR

from fastapi import HTTPException, UploadFile

from backend.detection.detection import ThreatDetector
from backend.detection.context import DetectionContext, ReusedIndicator
from backend.parser.email_parser import EmailParser
from backend.parser.models import ParsedEmail, URLMetadata

import main
from main import (
    create_case,
    enrich_and_correlate,
    get_case_by_id,
    get_cases,
    tier_2_llm_review,
    case_db,
)

FIXTURES_DIR = os.path.join(parent_dir, "data", "fixtures")


def _load_fixture(name: str) -> bytes:
    with open(os.path.join(FIXTURES_DIR, name), "rb") as f:
        return f.read()


def _parse_fixture(name: str) -> ParsedEmail:
    return EmailParser().parse(_load_fixture(name))


def _scored_reasons(result):
    """Filter out zero-point notes like INSUFFICIENT_EVIDENCE."""
    return [rc for rc in result["reason_codes"] if rc["code"] != "INSUFFICIENT_EVIDENCE"]


# ─────────────────────────────────────────────────────────────────────
#  Part 1: ThreatDetector unit tests (replaces the old analyze_risk tests)
# ─────────────────────────────────────────────────────────────────────

class TestThreatDetectorWithFixtures(unittest.TestCase):
    """Tests ThreatDetector directly against .eml fixtures via EmailParser."""

    def setUp(self):
        self.detector = ThreatDetector()
        self.parser = EmailParser()

    # -- Phishing fixture -----------------------------------------------

    def test_phishing_fixture_triggers_expected_rules(self):
        parsed = _parse_fixture("test_phishing.eml")
        result = self.detector.analyze(parsed)

        self.assertEqual(result["score"], 43)
        self.assertEqual(result["band"], "REVIEW")
        codes = [rc["code"] for rc in _scored_reasons(result)]
        self.assertIn("REPLY_TO_MISMATCH", codes)
        self.assertIn("URGENT_PAYMENT_REQUEST", codes)

        for rc in _scored_reasons(result):
            self.assertTrue(
                rc["evidence_path"].startswith("message.")
                or rc["evidence_path"].startswith("authentication."),
                f"Unexpected evidence_path prefix: {rc['evidence_path']}",
            )

    # -- Legitimate internal email (low risk) ---------------------------

    def test_legitimate_internal_email_scores_low(self):
        parsed = _parse_fixture("03_legitimate_internal.eml")
        result = self.detector.analyze(parsed)

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["band"], "LOW")
        self.assertEqual(_scored_reasons(result), [])

    # -- Constructed clean email ----------------------------------------

    def test_clean_constructed_email_low_risk(self):
        email = ParsedEmail()
        email.message.from_.address = "alice@company.example"
        email.message.reply_to = "alice@company.example"
        email.message.return_path = "alice@company.example"
        email.message.subject = "Monthly status report"
        email.message.urls.append(
            URLMetadata(raw="https://company.example/reports/august", host="company.example")
        )
        email.authentication.spf.result = "pass"
        email.authentication.dkim.result = "pass"

        result = self.detector.analyze(email)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["band"], "LOW")
        self.assertEqual(_scored_reasons(result), [])

    # -- Reply-to mismatch only -----------------------------------------

    def test_reply_to_mismatch_only(self):
        email = ParsedEmail()
        email.message.from_.address = "support@service.example"
        email.message.reply_to = "attacker@evil.example"
        email.message.subject = "Meeting notes"
        email.authentication.spf.result = "pass"
        email.authentication.dkim.result = "pass"

        result = self.detector.analyze(email)
        codes = [rc["code"] for rc in _scored_reasons(result)]
        self.assertIn("REPLY_TO_MISMATCH", codes)

    # -- sample-1.eml: real-world phishing (HIGH) -----------------------

    def test_sample1_phishing_high_risk(self):
        parsed = _parse_fixture("sample-1.eml")
        result = self.detector.analyze(parsed)

        self.assertGreaterEqual(result["score"], 70)
        self.assertEqual(result["band"], "HIGH")
        codes = [rc["code"] for rc in _scored_reasons(result)]
        self.assertIn("EXTERNAL_URL_MISMATCH", codes)
        self.assertIn("RETURN_PATH_ANOMALY", codes)
        self.assertIn("AUTH_DKIM_FAIL_OR_NONE", codes)

    # -- 01_payment_diversion: HIGH risk --------------------------------

    def test_payment_diversion_high_risk(self):
        parsed = _parse_fixture("01_payment_diversion.eml")
        result = self.detector.analyze(parsed)

        self.assertGreaterEqual(result["score"], 70)
        self.assertEqual(result["band"], "HIGH")
        codes = [rc["code"] for rc in _scored_reasons(result)]
        self.assertIn("AUTH_SPF_FAIL", codes)
        self.assertIn("AUTH_DKIM_FAIL_OR_NONE", codes)
        self.assertIn("AUTH_DMARC_FAIL", codes)
        self.assertIn("REPLY_TO_MISMATCH", codes)
        self.assertIn("URGENT_PAYMENT_REQUEST", codes)

    # -- Empty / None fields don't crash --------------------------------

    def test_empty_email_safe(self):
        result = self.detector.analyze(ParsedEmail())
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["band"], "LOW")
        self.assertIsInstance(result["reason_codes"], list)
        self.assertIsInstance(result["limitations"], list)

    # -- DetectionContext reused indicator -------------------------------

    def test_detection_context_reused_indicator(self):
        email = ParsedEmail()
        email.message.from_.address = "attacker@phish.example"
        email.message.reply_to = "attacker@phish.example"

        ctx = DetectionContext(
            current_case_id="TS-DEMO-002",
            reused_indicators=[
                ReusedIndicator(
                    indicator_type="domain",
                    value="phish.example",
                    related_case_ids=["TS-DEMO-001"],
                    source="case_store:TS-DEMO-001.message.reply_to",
                ),
            ],
        )

        result = self.detector.analyze(email, context=ctx)
        codes = [rc["code"] for rc in _scored_reasons(result)]
        self.assertIn("REUSED_INDICATOR", codes)


# ─────────────────────────────────────────────────────────────────────
#  Part 2: main.py integration tests (create_case, enrich, LLM, API)
# ─────────────────────────────────────────────────────────────────────

class TestMainIntegration(unittest.TestCase):
    """Tests the create_case endpoint and supporting functions in main.py."""

    @classmethod
    def setUpClass(cls):
        os.makedirs(TEST_ARTIFACTS_DIR, exist_ok=True)
        main.ARTIFACTS_DIR = TEST_ARTIFACTS_DIR

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(TEST_ARTIFACTS_DIR):
            import shutil
            shutil.rmtree(TEST_ARTIFACTS_DIR, ignore_errors=True)
        if os.path.exists(TEST_DB_PATH):
            try:
                os.remove(TEST_DB_PATH)
            except Exception:
                pass

    def setUp(self):
        main.clear_cases(TEST_DB_PATH)
        main.case_db.clear()
        if os.path.isdir(TEST_ARTIFACTS_DIR):
            for f in os.listdir(TEST_ARTIFACTS_DIR):
                try:
                    os.remove(os.path.join(TEST_ARTIFACTS_DIR, f))
                except Exception:
                    pass

    # -- Enrichment & Correlation ----------------------------------------

    def test_enrich_and_correlate_demo_intel_hit(self):
        parsed_email = {
            "reply_to": "payment-update@aicte-payments.example",
            "urls": ["http://aicte-payments.example/update"],
        }
        res = enrich_and_correlate(parsed_email, [])
        self.assertEqual(res["infrastructure"]["provider_status"], "demo_cache")
        self.assertEqual(len(res["infrastructure"]["geo"]), 1)
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

    # -- create_case integration -----------------------------------------

    def test_create_case_phishing_fixture(self):
        content = _load_fixture("test_phishing.eml")
        upload_file = UploadFile(file=io.BytesIO(content), filename="test_phishing.eml")
        data = asyncio.run(create_case(upload_file))

        self.assertEqual(data["case_id"], "TS-DEMO-001")
        self.assertEqual(data["risk"]["score"], 43)
        self.assertEqual(data["risk"]["band"], "REVIEW")
        self.assertIn("infrastructure", data)
        self.assertEqual(data["infrastructure"]["provider_status"], "demo_cache")
        self.assertEqual(data["campaign"]["related_case_ids"], [])
        self.assertEqual(len(main.case_db), 1)

    def test_create_case_cross_case_correlation(self):
        content = _load_fixture("test_phishing.eml")

        # First case
        upload_1 = UploadFile(file=io.BytesIO(content), filename="test_phishing.eml")
        data_1 = asyncio.run(create_case(upload_1))
        self.assertEqual(data_1["case_id"], "TS-DEMO-001")

        # Second case with same indicators
        upload_2 = UploadFile(file=io.BytesIO(content), filename="test_phishing_2.eml")
        data_2 = asyncio.run(create_case(upload_2))
        self.assertEqual(data_2["case_id"], "TS-DEMO-002")
        self.assertIn("TS-DEMO-001", data_2["campaign"]["related_case_ids"])
        self.assertEqual(len(data_2["campaign"]["shared_indicators"]), 1)
        self.assertEqual(len(main.case_db), 2)

    def test_create_case_low_risk_no_ai_review(self):
        clean_email_content = b"From: clean@example.com\r\nSubject: Hello\r\n\r\nClean body"
        upload_file = UploadFile(file=io.BytesIO(clean_email_content), filename="clean.eml")
        data = asyncio.run(create_case(upload_file))

        self.assertLess(data["risk"]["score"], 70)
        self.assertIsNone(data["ai_review"])

    def test_create_case_high_risk_invokes_tier_2_llm_review(self):
        content = _load_fixture("01_payment_diversion.eml")

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

    def test_create_case_sample1_high_risk(self):
        content = _load_fixture("sample-1.eml")

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "is_false_positive": False,
            "adjusted_score": 90,
            "adjusted_band": "HIGH",
            "analyst_summary": "Confirmed malicious Brazilian banking phishing lure.",
        })
        mock_response.choices = [mock_choice]

        with patch.object(main.groq_client.chat.completions, "create", return_value=mock_response):
            upload_file = UploadFile(file=io.BytesIO(content), filename="sample-1.eml")
            data = asyncio.run(create_case(upload_file))

            self.assertGreaterEqual(data["risk"]["score"], 70)
            self.assertEqual(data["risk"]["band"], "HIGH")
            self.assertIsNotNone(data["ai_review"])
            self.assertFalse(data["ai_review"]["is_false_positive"])
            self.assertEqual(data["ai_review"]["adjusted_score"], 90)

    def test_create_case_saves_artifact_to_disk(self):
        sample_content = b"From: test@example.com\r\nSubject: Test Artifact\r\n\r\nHello World"
        upload_file = UploadFile(file=io.BytesIO(sample_content), filename="artifact_test.eml")
        data = asyncio.run(create_case(upload_file))

        case_id = data["case_id"]
        expected_path = os.path.join(main.ARTIFACTS_DIR, f"{case_id}.eml")
        self.assertTrue(os.path.exists(expected_path))
        with open(expected_path, "rb") as f:
            self.assertEqual(f.read(), sample_content)

    def test_create_case_write_failure_raises_500(self):
        sample_content = b"From: test@example.com\r\nSubject: Fail Artifact\r\n\r\nTest"
        upload_file = UploadFile(file=io.BytesIO(sample_content), filename="fail_artifact.eml")

        with patch("builtins.open", side_effect=IOError("Disk write failed")):
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(create_case(upload_file))
            self.assertEqual(ctx.exception.status_code, 500)
            self.assertIn("Failed to save email artifact", ctx.exception.detail)

    # -- Tier-2 LLM Review -----------------------------------------------

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

        with patch.object(main.groq_client.chat.completions, "create", return_value=mock_response) as mock_create:
            result = asyncio.run(tier_2_llm_review(parsed_email, rule_risk))
            self.assertTrue(result["is_false_positive"])
            self.assertEqual(result["adjusted_score"], 10)
            self.assertEqual(result["adjusted_band"], "LOW")
            self.assertEqual(result["analyst_summary"], "Legitimate newsletter sent via Beehiiv ESP.")
            # Verify temperature and seed
            _, kwargs = mock_create.call_args
            self.assertEqual(kwargs.get("temperature"), 0.0)
            self.assertEqual(kwargs.get("seed"), 42)

    def test_tier_2_llm_review_band_normalization(self):
        parsed_email = {"subject": "Test", "from": "test@example.com"}
        rule_risk = {"score": 40, "band": "REVIEW"}

        mock_response = MagicMock()
        mock_choice = MagicMock()
        # Mock LLM returning a score of 50 but mistakenly tagging HIGH
        mock_choice.message.content = json.dumps({
            "is_false_positive": False,
            "adjusted_score": 50,
            "adjusted_band": "HIGH",
            "analyst_summary": "Unsolicited email.",
        })
        mock_response.choices = [mock_choice]

        with patch.object(main.groq_client.chat.completions, "create", return_value=mock_response):
            result = asyncio.run(tier_2_llm_review(parsed_email, rule_risk))
            self.assertEqual(result["adjusted_score"], 50)
            # Python logic must enforce REVIEW for score 50 (30-69)
            self.assertEqual(result["adjusted_band"], "REVIEW")

    def test_tier_2_llm_review_failure_graceful_fallback(self):
        parsed_email = {
            "from": {"name": "Hacker", "address": "spoof@bank.example"},
            "reply_to": "evil@attacker.example",
            "subject": "URGENT password reset",
            "urls": ["http://phish.example/login"],
        }
        rule_risk = {"score": 90, "band": "HIGH", "reason_codes": []}

        with patch.object(main.groq_client.chat.completions, "create", side_effect=Exception("API connection timeout")):
            result = asyncio.run(tier_2_llm_review(parsed_email, rule_risk))
            self.assertEqual(result, {"error": "LLM review unavailable"})

    # -- API endpoints (DB reads) ----------------------------------------

    def test_get_case_reads_from_db(self):
        sample_case = {
            "case_id": "TS-TEST-DB-001",
            "risk": {"score": 75, "band": "HIGH"},
            "created_at": "2026-09-06T12:00:00Z",
        }
        main.save_case(sample_case)
        main.case_db.clear()

        result = asyncio.run(get_case_by_id("TS-TEST-DB-001"))
        self.assertIsNotNone(result)
        self.assertEqual(result["case_id"], "TS-TEST-DB-001")
        self.assertEqual(result["risk"]["score"], 75)

    def test_get_case_not_found_raises_404(self):
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(get_case_by_id("TS-NONEXISTENT-999"))
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail, "Case not found")

    def test_get_cases_list_from_db(self):
        sample_case = {
            "case_id": "TS-LIST-001",
            "risk": {"score": 50, "band": "REVIEW"},
            "created_at": "2026-09-06T12:00:00Z",
        }
        main.save_case(sample_case)
        cases = asyncio.run(get_cases())
        self.assertTrue(any(c["case_id"] == "TS-LIST-001" for c in cases))

    def test_sqlite_cross_case_correlation_persistence(self):
        prior_case = {
            "case_id": "TS-DEMO-001",
            "message": {
                "reply_to": "attacker@phish.example",
                "origin_ip": "198.51.100.25",
            },
            "risk": {"score": 70, "band": "HIGH"},
        }
        main.save_case(prior_case)
        main.case_db.clear()

        new_email = {
            "reply_to": "attacker@phish.example",
            "origin_ip": "198.51.100.25",
        }
        result = enrich_and_correlate(new_email)
        self.assertIn("TS-DEMO-001", result["campaign"]["related_case_ids"])


if __name__ == "__main__":
    unittest.main()
