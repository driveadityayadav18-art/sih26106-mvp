import unittest
import asyncio
import json
from unittest.mock import MagicMock, patch

from backend.utils.pii_masker import mask_pii
from backend.services.llm_analysis import sanitize_email_for_llm, run_tier_2_llm_review


class TestPIIMasker(unittest.TestCase):
    def test_mask_credit_card_variations(self):
        # Dash separated
        text1 = "Payment card: 4532-1234-5678-9010."
        res1, meta1 = mask_pii(text1)
        self.assertIn("[REDACTED_CREDIT_CARD]", res1)
        self.assertNotIn("4532-1234-5678-9010", res1)
        self.assertEqual(meta1["cards_redacted"], 1)
        self.assertTrue(meta1["pii_detected"])

        # Space separated
        text2 = "Card: 5412 7534 8901 2345"
        res2, meta2 = mask_pii(text2)
        self.assertIn("[REDACTED_CREDIT_CARD]", res2)
        self.assertEqual(meta2["cards_redacted"], 1)

        # Contiguous 16 digits
        text3 = "Card number 4111222233334444 on file"
        res3, meta3 = mask_pii(text3)
        self.assertIn("[REDACTED_CREDIT_CARD]", res3)
        self.assertEqual(meta3["cards_redacted"], 1)

    def test_mask_indian_phone_numbers(self):
        # +91 with space
        text1 = "Call me at +91 9876543210 immediately."
        res1, meta1 = mask_pii(text1)
        self.assertIn("[REDACTED_PHONE]", res1)
        self.assertNotIn("9876543210", res1)
        self.assertEqual(meta1["phones_redacted"], 1)
        self.assertTrue(meta1["pii_detected"])

        # +91 with dash
        text2 = "Support: +91-9123456789"
        res2, meta2 = mask_pii(text2)
        self.assertIn("[REDACTED_PHONE]", res2)
        self.assertEqual(meta2["phones_redacted"], 1)

        # 10-digit number starting with 6-9
        text3 = "Reach out at 8887776665 today."
        res3, meta3 = mask_pii(text3)
        self.assertIn("[REDACTED_PHONE]", res3)
        self.assertEqual(meta3["phones_redacted"], 1)

        # 0 prefixed 10 digits
        text4 = "Mobile: 09876543210"
        res4, meta4 = mask_pii(text4)
        self.assertIn("[REDACTED_PHONE]", res4)
        self.assertEqual(meta4["phones_redacted"], 1)

    def test_mask_aadhaar_numbers(self):
        # 12 digits grouped by 4 with spaces
        text1 = "Aadhaar UID: 2345 6789 0123"
        res1, meta1 = mask_pii(text1)
        self.assertIn("[REDACTED_AADHAAR]", res1)
        self.assertNotIn("2345 6789 0123", res1)
        self.assertEqual(meta1["aadhaar_redacted"], 1)

        # 12 digits grouped by 4 with hyphens
        text2 = "Gov ID: 9876-5432-1098"
        res2, meta2 = mask_pii(text2)
        self.assertIn("[REDACTED_AADHAAR]", res2)
        self.assertEqual(meta2["aadhaar_redacted"], 1)

    def test_mask_email_addresses(self):
        text = "Contact support@example.com or admin@bank-secure.co.in for help."
        res, meta = mask_pii(text)
        self.assertEqual(res, "Contact [REDACTED_EMAIL] or [REDACTED_EMAIL] for help.")
        self.assertEqual(meta["emails_redacted"], 2)
        self.assertTrue(meta["pii_detected"])

    def test_mask_combined_payload(self):
        text = (
            "Dear customer, your card 4532-1234-5678-9010 linked to Aadhaar 4567 8901 2345 "
            "and phone +91 9876543210 has been flagged. Email security@bank.com."
        )
        res, meta = mask_pii(text)
        self.assertIn("[REDACTED_CREDIT_CARD]", res)
        self.assertIn("[REDACTED_AADHAAR]", res)
        self.assertIn("[REDACTED_PHONE]", res)
        self.assertIn("[REDACTED_EMAIL]", res)
        self.assertEqual(meta["cards_redacted"], 1)
        self.assertEqual(meta["aadhaar_redacted"], 1)
        self.assertEqual(meta["phones_redacted"], 1)
        self.assertEqual(meta["emails_redacted"], 1)
        self.assertTrue(meta["pii_detected"])

    def test_no_pii_leaves_text_intact(self):
        text = "This is a benign corporate email discussing quarterly security posture."
        res, meta = mask_pii(text)
        self.assertEqual(res, text)
        self.assertEqual(meta["cards_redacted"], 0)
        self.assertEqual(meta["phones_redacted"], 0)
        self.assertEqual(meta["emails_redacted"], 0)
        self.assertEqual(meta["aadhaar_redacted"], 0)
        self.assertFalse(meta["pii_detected"])

    def test_sanitize_email_for_llm(self):
        parsed_email = {
            "subject": "Urgent update regarding 4532-1234-5678-9010",
            "from": {"name": "Support", "address": "attacker@fakebank.com"},
            "reply_to": "agent@fakebank.com",
            "body_text": "Please call +91 9876543210 and verify Aadhaar 3456 7890 1234.",
        }
        sanitized, audit = sanitize_email_for_llm(parsed_email)
        self.assertIn("[REDACTED_CREDIT_CARD]", sanitized["subject"])
        self.assertEqual(sanitized["from"]["address"], "[REDACTED_EMAIL]")
        self.assertEqual(sanitized["reply_to"], "[REDACTED_EMAIL]")
        self.assertIn("[REDACTED_PHONE]", sanitized["body_text"])
        self.assertIn("[REDACTED_AADHAAR]", sanitized["body_text"])

        self.assertTrue(audit["pii_sanitized"])
        self.assertTrue(audit["pii_detected"])
        self.assertEqual(audit["masked_entities_count"], 5)
        self.assertEqual(audit["cards_redacted"], 1)
        self.assertEqual(audit["phones_redacted"], 1)
        self.assertEqual(audit["aadhaar_redacted"], 1)
        self.assertEqual(audit["emails_redacted"], 2)

    def test_run_tier_2_llm_review_masks_prompt_payload(self):
        parsed_email = {
            "subject": "Wire to +91 9988776655",
            "body_text": "Transfer funds from card 4111-2222-3333-4444 to target.",
            "from": "scammer@fraud.com",
        }
        rule_risk = {"score": 80, "band": "HIGH"}

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "is_false_positive": False,
            "adjusted_score": 85,
            "adjusted_band": "HIGH",
            "analyst_summary": "Malicious financial request targeting masked card.",
        })
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        result = asyncio.run(run_tier_2_llm_review(parsed_email, rule_risk, client=mock_client))

        # Check LLM received sanitized prompt
        call_args = mock_client.chat.completions.create.call_args
        user_message = call_args[1]["messages"][1]["content"]
        self.assertNotIn("4111-2222-3333-4444", user_message)
        self.assertNotIn("9988776655", user_message)
        self.assertIn("[REDACTED_CREDIT_CARD]", user_message)
        self.assertIn("[REDACTED_PHONE]", user_message)

        # Check privacy audit in result
        self.assertIn("privacy_audit", result)
        self.assertTrue(result["privacy_audit"]["pii_sanitized"])
        self.assertTrue(result["privacy_audit"]["pii_detected"])
        self.assertGreater(result["privacy_audit"]["masked_entities_count"], 0)


if __name__ == "__main__":
    unittest.main()
