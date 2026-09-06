from unittest.mock import patch

import pytest

from backend.detection.detection import ThreatDetector
from backend.parser.models import ParsedEmail


def scored_reasons(result):
    """Existing rule/score checks exclude the separately tested zero-point note."""
    return [reason for reason in result["reason_codes"]
            if reason["code"] != "INSUFFICIENT_EVIDENCE"]


@pytest.mark.parametrize("status", ["pass", "unknown"])
def test_no_authentication_failures(status):
    email = ParsedEmail()
    email.authentication.spf.result = status
    email.authentication.dkim.result = status
    email.authentication.dmarc.result = status

    result = ThreatDetector().analyze(email)

    assert result["score"] == 0
    assert result["band"] == "LOW"
    assert scored_reasons(result) == []
    assert isinstance(result["limitations"], list)


@pytest.mark.parametrize(
    "field, status, code, weight",
    [
        ("spf", "fail", "AUTH_SPF_FAIL", 10),
        ("dkim", "fail", "AUTH_DKIM_FAIL_OR_NONE", 8),
        ("dkim", "none", "AUTH_DKIM_FAIL_OR_NONE", 8),
        ("dmarc", "fail", "AUTH_DMARC_FAIL", 12),
    ],
)
def test_one_authentication_reason(field, status, code, weight):
    email = ParsedEmail()
    getattr(email.authentication, field).result = status

    result = ThreatDetector().analyze(email)

    assert result["score"] == weight
    assert result["band"] == "LOW"
    assert len(scored_reasons(result)) == 1
    reason = scored_reasons(result)[0]
    assert reason["code"] == code
    assert reason["weight"] == weight
    assert reason["evidence_path"] == f"authentication.{field}.result"
    assert reason["message"]


def test_all_authentication_failures_add_up():
    email = ParsedEmail()
    email.authentication.spf.result = "fail"
    email.authentication.dkim.result = "fail"
    email.authentication.dmarc.result = "fail"
    detector = ThreatDetector()

    result = detector.analyze(email)

    assert result["score"] == 30
    assert result["band"] == "REVIEW"
    assert [reason["code"] for reason in scored_reasons(result)] == [
        "AUTH_SPF_FAIL",
        "AUTH_DKIM_FAIL_OR_NONE",
        "AUTH_DMARC_FAIL",
    ]
    assert sum(reason["weight"] for reason in scored_reasons(result)) == 30
    assert detector.analyze(email) == result

    # A later email must not keep points or reasons from the previous email.
    clean_result = detector.analyze(ParsedEmail())
    assert clean_result["score"] == 0
    assert scored_reasons(clean_result) == []


@pytest.mark.parametrize(
    "total, expected_score, expected_band",
    [
        (-5, 0, "LOW"),
        (29, 29, "LOW"),
        (30, 30, "REVIEW"),
        (69, 69, "REVIEW"),
        (70, 70, "HIGH"),
        (100, 100, "HIGH"),
        (120, 100, "HIGH"),
    ],
)
def test_score_limits_and_band_edges(total, expected_score, expected_band):
    # Use a temporary fake result to
    # test higher scores without changing the real rules or their weights.
    reason = {
        "code": "TEST_SIGNAL",
        "message": "Test-only score input",
        "evidence_path": "authentication.spf.result",
        "weight": total,
    }
    with patch(
        "backend.detection.detection.check_spf_fail", return_value=reason
    ):
        result = ThreatDetector().analyze(ParsedEmail())

    assert result["score"] == expected_score
    assert result["band"] == expected_band
    assert scored_reasons(result) == [reason]


@pytest.mark.parametrize("address, name, reply_to, code, weight, path", [
    ("sender@company.example", None, "reply@other.example",
     "REPLY_TO_MISMATCH", 18, "message.reply_to"),
    ("sender@company.example", "sender@other.example", None,
     "DISPLAY_NAME_DOMAIN_MISMATCH", 10, "message.from_"),
    ("sender@compamy.example", None, None,
     "LOOKALIKE_DOMAIN", 20, "message.from_.address"),
    ("sender@xn--bcher-kva.example", None, None,
     "PUNYCODE_DOMAIN", 10, "message.from_.address"),
])
def test_identity_rules_are_connected(address, name, reply_to, code, weight, path):
    email = ParsedEmail()
    email.message.from_.address = address
    email.message.from_.name = name
    email.message.reply_to = reply_to

    result = ThreatDetector().analyze(email)

    assert result["score"] == weight
    assert result["band"] == "LOW"
    assert len(scored_reasons(result)) == 1
    assert scored_reasons(result)[0]["code"] == code
    assert scored_reasons(result)[0]["evidence_path"] == path


def test_authentication_and_identity_combine_to_high():
    email = ParsedEmail()
    email.authentication.spf.result = "fail"
    email.authentication.dkim.result = "fail"
    email.authentication.dmarc.result = "fail"
    email.message.from_.address = "sender@compamy.example"
    email.message.from_.name = "accounts@company.example"
    email.message.reply_to = "reply@other.example"
    detector = ThreatDetector()

    result = detector.analyze(email)

    assert result["score"] == 78  # 10 + 8 + 12 + 18 + 10 + 20
    assert result["band"] == "HIGH"
    assert [reason["code"] for reason in scored_reasons(result)] == [
        "AUTH_SPF_FAIL", "AUTH_DKIM_FAIL_OR_NONE", "AUTH_DMARC_FAIL",
        "REPLY_TO_MISMATCH", "DISPLAY_NAME_DOMAIN_MISMATCH", "LOOKALIKE_DOMAIN",
    ]
    assert sum(reason["weight"] for reason in scored_reasons(result)) == 78
    assert detector.analyze(email) == result
    assert scored_reasons(detector.analyze(ParsedEmail())) == []


def test_aligned_identity_does_not_add_points():
    email = ParsedEmail()
    email.message.from_.address = "sender@company.example"
    email.message.from_.name = "Accounts Team"
    email.message.reply_to = "reply@company.example"
    result = ThreatDetector().analyze(email)
    assert result["score"] == 0
    assert result["band"] == "LOW"
    assert scored_reasons(result) == []


@pytest.mark.parametrize("missing", ["authentication", "spf", "message", "from_", "input"])
def test_missing_nested_data_returns_controlled_result(missing):
    email = ParsedEmail()
    if missing == "input":
        email = None
    elif missing == "spf":
        email.authentication.spf = None
    elif missing == "from_":
        email.message.from_ = None
    else:
        setattr(email, missing, None)

    detector = ThreatDetector()
    result = detector.analyze(email)
    assert result["score"] == 0
    assert result["band"] == "LOW"
    assert scored_reasons(result) == []
    assert result["limitations"]
    assert detector.analyze(email) == result


def test_empty_model_explains_missing_evidence():
    result = ThreatDetector().analyze(ParsedEmail())
    notes = " ".join(result["limitations"])
    for label in ("SPF", "DKIM", "DMARC", "Sender"):
        assert label in notes
    assert result["score"] == 0


def test_missing_authentication_keeps_observed_identity_reason():
    email = ParsedEmail()
    email.authentication = None
    email.message.from_.address = "sender@company.example"
    email.message.reply_to = "reply@other.example"
    result = ThreatDetector().analyze(email)
    assert result["score"] == 18
    assert scored_reasons(result)[0]["code"] == "REPLY_TO_MISMATCH"
    assert any("SPF" in note for note in result["limitations"])


def test_missing_message_keeps_observed_authentication_reason():
    email = ParsedEmail()
    email.message = None
    email.authentication.spf.result = "fail"
    result = ThreatDetector().analyze(email)
    assert result["score"] == 10
    assert scored_reasons(result)[0]["code"] == "AUTH_SPF_FAIL"
    assert any("Sender" in note for note in result["limitations"])


@pytest.mark.parametrize("value", [None, "", 123, [], {}, "unexpected"])
def test_unusable_authentication_result_is_not_failure(value):
    email = ParsedEmail()
    email.authentication.spf.result = value
    email.authentication.dkim.result = value
    email.authentication.dmarc.result = value
    result = ThreatDetector().analyze(email)
    assert result["score"] == 0
    assert scored_reasons(result) == []
    assert all(any(method in note for note in result["limitations"])
               for method in ("SPF", "DKIM", "DMARC"))


def test_complete_aligned_evidence_has_no_limitations():
    email = ParsedEmail()
    email.message.body_text = "Monthly status report."
    email.authentication.spf.result = "pass"
    email.authentication.dkim.result = "pass"
    email.authentication.dmarc.result = "pass"
    email.message.from_.address = "sender@company.example"
    email.message.from_.name = "Accounts Team"
    email.message.reply_to = "reply@company.example"
    result = ThreatDetector().analyze(email)
    assert result["score"] == 0
    assert result["limitations"] == []


def test_explicit_dkim_none_still_adds_points_without_missing_dkim_note():
    email = ParsedEmail()
    email.authentication.dkim.result = "none"
    result = ThreatDetector().analyze(email)
    assert result["score"] == 8
    assert not any("DKIM" in note for note in result["limitations"])


def test_broken_reply_to_is_skipped_and_not_exposed_in_notes():
    email = ParsedEmail()
    email.message.from_.address = "sender@company.example"
    email.message.reply_to = "private-person@company..example"
    result = ThreatDetector().analyze(email)
    assert result["score"] == 0
    assert any("Reply-To" in note for note in result["limitations"])
    assert "private-person" not in " ".join(result["limitations"])


def test_malformed_sender_skips_all_identity_rules():
    email = ParsedEmail()
    email.message.from_.address = "sender@compamy.example"
    email.message.from_.name = "sender@company.example"
    email.message.from_.malformed = True
    email.message.reply_to = "reply@other.example"
    result = ThreatDetector().analyze(email)
    assert result["score"] == 0
    assert scored_reasons(result) == []
    assert any("Sender" in note for note in result["limitations"])


@pytest.mark.parametrize("status", ["temperror", "permerror"])
def test_authentication_errors_are_not_failure_points(status):
    email = ParsedEmail()
    email.authentication.spf.result = status
    result = ThreatDetector().analyze(email)
    assert result["score"] == 0
    assert any("SPF reported an authentication error" in note
               for note in result["limitations"])


@pytest.mark.parametrize("text, code, weight", [
    ("Transfer the funds immediately.", "URGENT_PAYMENT_REQUEST", 25),
    ("Please send your OTP.", "CREDENTIAL_REQUEST", 20),
    ("Please upload your passport.", "SENSITIVE_DATA_REQUEST", 15),
])
def test_content_rules_are_connected(text, code, weight):
    email = ParsedEmail()
    email.message.body_text = text
    result = ThreatDetector().analyze(email)
    assert result["score"] == weight
    assert result["band"] == "LOW"
    assert len(scored_reasons(result)) == 1
    assert scored_reasons(result)[0]["code"] == code
    assert scored_reasons(result)[0]["evidence_path"] == "message.body_text"


def test_content_repeats_are_not_counted_twice():
    email = ParsedEmail()
    email.message.subject = "Please send your OTP."
    email.message.body_text = "Please send your OTP. " * 3
    result = ThreatDetector().analyze(email)
    assert result["score"] == 20
    assert len(scored_reasons(result)) == 1


def test_content_combined_with_authentication_and_identity():
    email = ParsedEmail()
    email.authentication.spf.result = "fail"
    email.message.from_.address = "sender@company.example"
    email.message.reply_to = "reply@other.example"
    email.message.body_text = (
        "Transfer the funds immediately. Please send your OTP. "
        "Please upload your passport."
    )
    detector = ThreatDetector()
    result = detector.analyze(email)
    assert result["score"] == 88  # 10 + 18 + 25 + 20 + 15
    assert result["band"] == "HIGH"
    assert [reason["code"] for reason in scored_reasons(result)] == [
        "AUTH_SPF_FAIL", "REPLY_TO_MISMATCH", "URGENT_PAYMENT_REQUEST",
        "CREDENTIAL_REQUEST", "SENSITIVE_DATA_REQUEST",
    ]
    assert sum(reason["weight"] for reason in scored_reasons(result)) == 88
    assert detector.analyze(email) == result
    assert detector.analyze(ParsedEmail())["score"] == 0
    email.authentication.dkim.result = "fail"
    email.authentication.dmarc.result = "fail"
    assert detector.analyze(email)["score"] == 100  # Actual reasons total 108.


def test_content_safety_advice_adds_no_points():
    email = ParsedEmail()
    email.message.body_text = (
        "Do not transfer funds immediately. Never share your OTP. "
        "Do not upload your passport."
    )
    result = ThreatDetector().analyze(email)
    assert result["score"] == 0
    assert scored_reasons(result) == []


@pytest.mark.parametrize("kind, expected_score, expected_codes", [
    ("shortener", 5, ["SHORTENED_URL"]),
    ("attachment", 12, ["SUSPICIOUS_ATTACHMENT"]),
    ("path", 30, ["CREDENTIAL_REQUEST", "SUSPICIOUS_URL_PATH"]),
])
def test_url_attachment_rules_connected(kind, expected_score, expected_codes):
    from backend.parser.models import URLMetadata, AttachmentMetadata
    email = ParsedEmail()
    if kind == "attachment":
        email.message.attachments = [AttachmentMetadata(filename="invoice.pdf.exe")]
    else:
        host = "bit.ly" if kind == "shortener" else "portal.example"
        email.message.urls = [URLMetadata(raw="unused", scheme="https", host=host, path="/login")]
        if kind == "path":
            email.message.body_text = "Enter your password."
    result = ThreatDetector().analyze(email)
    assert result["score"] == expected_score
    assert result["band"] == ("REVIEW" if expected_score >= 30 else "LOW")
    assert [r["code"] for r in scored_reasons(result)] == expected_codes


def test_urls_attachments_combine_with_existing_rules_and_deduplicate():
    from backend.parser.models import URLMetadata, AttachmentMetadata
    email = ParsedEmail()
    email.message.from_.address = "sender@company.example"
    email.message.reply_to = "reply@other.example"
    email.authentication.spf.result = "fail"
    email.message.body_text = "Enter your password."
    email.message.urls = [URLMetadata(raw="unused", scheme="https", host="bit.ly", path="/login")] * 3
    email.message.attachments = [AttachmentMetadata(filename="invoice.exe")] * 3
    detector = ThreatDetector()
    result = detector.analyze(email)
    assert result["score"] == 75  # 10 + 18 + 20 + 10 + 5 + 12
    assert result["band"] == "HIGH"
    assert [r["code"] for r in scored_reasons(result)] == [
        "AUTH_SPF_FAIL", "REPLY_TO_MISMATCH", "CREDENTIAL_REQUEST",
        "SUSPICIOUS_URL_PATH", "SHORTENED_URL", "SUSPICIOUS_ATTACHMENT",
    ]
    assert detector.analyze(email) == result
    assert detector.analyze(ParsedEmail())["score"] == 0


@pytest.mark.parametrize("code, score", [
    ("MALFORMED_ADDRESS", 10), ("MISSING_REPLY_TO", 0),
    ("MISSING_AUTHENTICATION_RESULTS", 0),
])
def test_header_rule_connected(code, score):
    from backend.parser.models import Warning
    email = ParsedEmail()
    email.warnings = [Warning(code, "")] * 3
    result = ThreatDetector().analyze(email)
    assert result["score"] == score
    assert result["band"] == "LOW"
    assert len(scored_reasons(result)) == (1 if score else 0)
    if score:
        assert scored_reasons(result)[0]["code"] == "HEADER_ANOMALY"
        assert scored_reasons(result)[0]["evidence_path"] == "warnings[0].code"


def test_optional_context_is_connected_without_changing_old_call():
    from backend.detection.context import DetectionContext, ReusedIndicator
    email = ParsedEmail()
    email.message.from_.address = "sender@company.example"
    detector = ThreatDetector()
    baseline = detector.analyze(email)
    assert detector.analyze(email, None) == baseline
    assert detector.analyze(email, DetectionContext()) == baseline
    assert baseline["score"] == 0
    context = DetectionContext([
        ReusedIndicator("domain", "company.example", ["CASE-OLD"], "local_case_store")
    ], "CASE-CURRENT")
    result = detector.analyze(email, context)
    assert result["score"] == 15
    assert result["band"] == "LOW"
    assert scored_reasons(result)[0]["code"] == "REUSED_INDICATOR"
    assert scored_reasons(result)[0]["evidence_path"] == "message.from_.address"
    assert detector.analyze(email) == baseline


def test_header_context_and_existing_rules_combine():
    from backend.detection.context import DetectionContext, ReusedIndicator
    from backend.parser.models import Warning
    email = ParsedEmail()
    email.authentication.spf.result = "fail"
    email.message.from_.address = "sender@company.example"
    email.message.reply_to = "reply@other.example"
    email.message.body_text = "Transfer funds immediately."
    email.warnings = [Warning("MALFORMED_DATE", "private header")]
    context = DetectionContext([
        ReusedIndicator("domain", "other.example", ["CASE-OLD"], "local_case_store")
    ])
    detector = ThreatDetector()
    result = detector.analyze(email, context)
    assert result["score"] == 78  # 10 + 18 + 25 + 10 + 15
    assert result["band"] == "HIGH"
    assert [r["code"] for r in scored_reasons(result)] == [
        "AUTH_SPF_FAIL", "REPLY_TO_MISMATCH", "URGENT_PAYMENT_REQUEST",
        "HEADER_ANOMALY", "REUSED_INDICATOR",
    ]
    assert sum(r["weight"] for r in scored_reasons(result)) == 78
    assert detector.analyze(email, context) == result
    assert detector.analyze(ParsedEmail())["score"] == 0


def test_bank_change_request_combines_with_authentication_and_reply_mismatch():
    email = ParsedEmail()
    email.message.from_.address = "accounts@company.example"
    email.message.reply_to = "reply@other.example"
    email.message.body_text = "Please update our beneficiary banking details immediately."
    for method in ("spf", "dkim", "dmarc"):
        getattr(email.authentication, method).result = "fail"
    result = ThreatDetector().analyze(email)
    assert result["score"] == 73
    assert result["band"] == "HIGH"
    assert "URGENT_PAYMENT_REQUEST" in [r["code"] for r in result["reason_codes"]]


def test_password_lure_supplies_login_url_context_without_inflating_weights():
    from backend.parser.models import URLMetadata
    email = ParsedEmail()
    email.message.from_.address = "sender@company.example"
    email.message.reply_to = "reply@other.example"
    email.authentication.spf.result = "neutral"
    email.authentication.dkim.result = "none"
    email.authentication.dmarc.result = "fail"
    email.message.body_text = (
        "Keep your current password active by verifying identity below. "
        "If you fail to verify before the deadline, account access will be suspended."
    )
    email.message.urls = [URLMetadata(raw="https://portal.example/login", scheme="https", host="portal.example", path="/login")]
    result = ThreatDetector().analyze(email)
    assert result["score"] == 68  # 8 + 12 + 18 + 20 + 10
    assert result["band"] == "REVIEW"
    assert [r["code"] for r in scored_reasons(result)] == [
        "AUTH_DKIM_FAIL_OR_NONE", "AUTH_DMARC_FAIL", "REPLY_TO_MISMATCH",
        "CREDENTIAL_REQUEST", "SUSPICIOUS_URL_PATH",
    ]
