import pytest

from backend.detection.rules.content import (
    check_urgent_payment_request,
    check_credential_request,
    check_sensitive_data_request,
)
from backend.parser.models import ParsedEmail


RULE_CASES = [
    (check_urgent_payment_request, "Transfer the funds immediately.", "URGENT_PAYMENT_REQUEST", 25),
    (check_credential_request, "Please send your OTP.", "CREDENTIAL_REQUEST", 20),
    (check_sensitive_data_request, "Upload a copy of your passport.", "SENSITIVE_DATA_REQUEST", 15),
]


@pytest.mark.parametrize("rule, text, code, weight", RULE_CASES)
@pytest.mark.parametrize("field", ["subject", "body_text"])
def test_content_positive_and_evidence(rule, text, code, weight, field):
    email = ParsedEmail()
    setattr(email.message, field, text)
    result = rule(email)
    assert result is not None
    assert result["code"] == code
    assert result["weight"] == weight
    assert result["evidence_path"] == f"message.{field}"
    assert "not proof of fraud" in result["message"]
    assert rule(email) == result


@pytest.mark.parametrize("rule, text", [
    (check_urgent_payment_request, "URGENT: please pay the invoice."),
    (check_urgent_payment_request, "Wire the money within an hour."),
    (check_credential_request, "Enter your password at this link."),
    (check_credential_request, "Provide your one-time code."),
    (check_sensitive_data_request, "Share your bank account details."),
    (check_sensitive_data_request, "Please provide your Aadhaar number."),
    (check_sensitive_data_request, "Send your PAN number."),
])
def test_more_request_phrases(rule, text):
    email = ParsedEmail()
    email.message.body_text = text
    assert rule(email) is not None


@pytest.mark.parametrize("rule, text", [
    (check_urgent_payment_request, "Urgent: meeting moved."),
    (check_urgent_payment_request, "Your payment receipt is attached."),
    (check_urgent_payment_request, "Please pay the invoice when convenient."),
    (check_urgent_payment_request, "Urgent meeting today. Your payment receipt is attached."),
    (check_urgent_payment_request, "Do not transfer funds immediately."),
    (check_urgent_payment_request, "Pay the invoice, but not immediately."),
    (check_urgent_payment_request, "Please repay the invoice immediately."),
    (check_credential_request, "Your password was changed."),
    (check_credential_request, "Use a strong password."),
    (check_credential_request, "Never share your OTP."),
    (check_credential_request, "Please do not send your password."),
    (check_credential_request, "Don't provide your recovery code."),
    (check_credential_request, "Don’t share your OTP."),
    (check_credential_request, "Share no passwords."),
    (check_credential_request, "There is no need to send your password."),
    (check_credential_request, "Please send your password123."),
    (check_sensitive_data_request, "Your passport appointment is confirmed."),
    (check_sensitive_data_request, "Do not upload your passport."),
    (check_sensitive_data_request, "Never share your bank account details."),
    (check_sensitive_data_request, "Please send your OTP."),
    (check_credential_request, "Please send your passport."),
])
def test_notices_negations_and_near_misses(rule, text):
    email = ParsedEmail()
    email.message.body_text = text
    assert rule(email) is None


@pytest.mark.parametrize("rule, text, code, weight", RULE_CASES)
@pytest.mark.parametrize("value", [None, "", "   ", 123, [], {}])
def test_missing_or_wrong_type_text(rule, text, code, weight, value):
    email = ParsedEmail()
    email.message.subject = value
    email.message.body_text = value
    assert rule(email) is None
    email.message = None
    assert rule(email) is None
    assert rule(None) is None


@pytest.mark.parametrize("rule, text, code, weight", RULE_CASES)
def test_repeated_requests_return_one_reason(rule, text, code, weight):
    email = ParsedEmail()
    email.message.subject = text
    email.message.body_text = text * 3
    result = rule(email)
    assert isinstance(result, dict)
    assert result["weight"] == weight
    assert result["evidence_path"] == "message.subject"


def test_no_matching_across_fields_sentences_or_long_distances():
    email = ParsedEmail()
    email.message.subject = "Urgent"
    email.message.body_text = "Please transfer the funds."
    assert check_urgent_payment_request(email) is None
    email.message.subject = None
    email.message.body_text = "Please send the report. Your password was changed."
    assert check_credential_request(email) is None
    email.message.body_text = "Send " + "report " * 12 + "password"
    assert check_credential_request(email) is None


def test_negative_sentence_does_not_hide_separate_request():
    email = ParsedEmail()
    email.message.body_text = "Never share your OTP. Please send your password."
    assert check_credential_request(email) is not None


def test_reason_does_not_echo_secrets():
    email = ParsedEmail()
    email.message.body_text = "Send your password private-secret-123."
    result = check_credential_request(email)
    assert result is not None
    assert "private-secret-123" not in result["message"]


@pytest.mark.parametrize("text", [
    "Please update our beneficiary banking details immediately.",
    "Change vendor bank details right now.",
    "Replace bank account details urgently.",
])
def test_urgent_bank_change_patterns(text):
    email = ParsedEmail()
    email.message.body_text = text
    result = check_urgent_payment_request(email)
    assert result["code"] == "URGENT_PAYMENT_REQUEST"
    assert result["weight"] == 25
    assert result["evidence_path"] == "message.body_text"


@pytest.mark.parametrize("text", [
    "Please update our beneficiary banking details when convenient.",
    "Do not update beneficiary banking details immediately.",
    "Update the meeting details immediately.",
    "Your bank account details were updated immediately.",
    "Update the invoice immediately.",
])
def test_bank_change_near_misses(text):
    email = ParsedEmail()
    email.message.body_text = text
    assert check_urgent_payment_request(email) is None


LURE_TEXT = (
    "Keep your current password active by verifying identity below. "
    "If you fail to verify before the deadline, account access will be suspended."
)


@pytest.mark.parametrize("field", ["subject", "body_text"])
def test_password_retention_lure(field):
    email = ParsedEmail()
    setattr(email.message, field, LURE_TEXT)
    result = check_credential_request(email)
    assert result["code"] == "CREDENTIAL_REQUEST"
    assert result["weight"] == 20
    assert result["evidence_path"] == f"message.{field}"
    assert check_credential_request(email) == result


@pytest.mark.parametrize("text", [
    "Keep existing password.",
    "Keep your current password private and never share it.",
    "Keep existing password and verify your identity.",
    "Verify your identity or your account will be locked.",
    "Keep existing password. Your account will be locked.",
    "Do not keep existing password. Verify your identity. Your account will be locked.",
    "Keep existing password. Never verify your identity. Your account will be locked.",
    "Keep existing password. Verify your identity. Your account will not be suspended.",
])
def test_password_lure_requires_all_three_parts(text):
    email = ParsedEmail()
    email.message.body_text = text
    assert check_credential_request(email) is None


def test_password_lure_does_not_join_fields_or_distant_text():
    email = ParsedEmail()
    email.message.subject = "Keep existing password"
    email.message.body_text = "Verify your identity. Your account will be locked."
    assert check_credential_request(email) is None
    email.message.subject = None
    email.message.body_text = "Keep existing password. " + "report " * 90 + "Verify your identity. Your account will be locked."
    assert check_credential_request(email) is None


def test_lure_and_direct_request_still_return_one_reason():
    email = ParsedEmail()
    email.message.body_text = LURE_TEXT + " Please send your OTP."
    result = check_credential_request(email)
    assert isinstance(result, dict)
    assert result["weight"] == 20
