import pytest

from backend.detection.detection import ThreatDetector
from backend.detection.rules.evidence import check_insufficient_evidence
from backend.parser.models import ParsedEmail, Warning, URLMetadata, AttachmentMetadata


def complete_email():
    email = ParsedEmail()
    email.authentication.spf.result = "pass"
    email.authentication.dkim.result = "pass"
    email.authentication.dmarc.result = "pass"
    email.message.from_.address = "sender@company.example"
    email.message.body_text = "Monthly status report."
    return email


def test_empty_input_has_one_zero_point_reason_and_detailed_notes():
    detector = ThreatDetector()
    result = detector.analyze(ParsedEmail())
    assert result["score"] == 0
    assert result["band"] == "LOW"
    assert len(result["reason_codes"]) == 1
    reason = result["reason_codes"][0]
    assert reason["code"] == "INSUFFICIENT_EVIDENCE"
    assert reason["weight"] == 0
    assert reason["evidence_path"] == "authentication.spf.result"
    assert "no risk points" in reason["message"]
    assert any("content" in note for note in result["limitations"])
    assert detector.analyze(ParsedEmail()) == result


def test_absent_optional_fields_are_not_insufficient_evidence():
    email = complete_email()
    # Missing Reply-To/name/context and empty URL/attachment lists are normal.
    assert email.message.reply_to is None
    assert check_insufficient_evidence(email) is None
    result = ThreatDetector().analyze(email)
    assert result["reason_codes"] == []
    assert result["score"] == 0


@pytest.mark.parametrize("method", ["spf", "dkim", "dmarc"])
@pytest.mark.parametrize("value", ["unknown", "temperror", "permerror", None, [], 123])
def test_authentication_gaps(method, value):
    email = complete_email()
    getattr(email.authentication, method).result = value
    result = check_insufficient_evidence(email)
    assert result["weight"] == 0
    assert result["evidence_path"] == f"authentication.{method}.result"


def test_explicit_none_is_observed_evidence_not_missing():
    email = complete_email()
    email.authentication.dkim.result = "none"
    assert check_insufficient_evidence(email) is None
    result = ThreatDetector().analyze(email)
    assert result["score"] == 8
    assert [r["code"] for r in result["reason_codes"]] == ["AUTH_DKIM_FAIL_OR_NONE"]


@pytest.mark.parametrize("value", [None, "", " ", 123, [], {}])
def test_no_usable_content(value):
    email = complete_email()
    email.message.subject = value
    email.message.body_text = value
    reason = check_insufficient_evidence(email)
    assert reason["evidence_path"] == "message.body_text"
    assert reason["weight"] == 0


def test_html_only_body_is_incomplete_even_with_subject():
    email = complete_email()
    email.message.subject = "Account update"
    email.message.body_text = None
    email.message.body_html_present = True
    reason = check_insufficient_evidence(email)
    assert reason["evidence_path"] == "message.body_text"
    assert any("HTML" in note for note in ThreatDetector().analyze(email)["limitations"])


@pytest.mark.parametrize("field", ["urls", "attachments"])
@pytest.mark.parametrize("value", [None, 123, {}, [None], ["raw text"]])
def test_missing_or_broken_metadata(field, value):
    email = complete_email()
    setattr(email.message, field, value)
    reason = check_insufficient_evidence(email)
    assert reason["evidence_path"].startswith(f"message.{field}")
    assert reason["weight"] == 0


def test_partial_attachment_keeps_observed_risk_and_adds_note():
    email = complete_email()
    email.message.attachments = [AttachmentMetadata(filename="file.exe", parse_status="partial")]
    result = ThreatDetector().analyze(email)
    assert result["score"] == 12
    assert [r["code"] for r in result["reason_codes"]] == [
        "SUSPICIOUS_ATTACHMENT", "INSUFFICIENT_EVIDENCE",
    ]
    assert result["reason_codes"][-1]["evidence_path"] == "message.attachments[0]"


@pytest.mark.parametrize("code", [
    "MIME_PARSE_WARNING", "HEADER_DECODE_WARNING", "BODY_DECODE_WARNING",
    "URL_PARSE_WARNING", "ATTACHMENT_METADATA_WARNING",
])
def test_parser_warning_evidence_path_and_private_text(code):
    email = complete_email()
    email.warnings = [Warning("MISSING_REPLY_TO", ""), Warning(code, "private-secret-text")]
    result = ThreatDetector().analyze(email)
    assert result["reason_codes"][-1]["evidence_path"] == "warnings[1].code"
    assert result["score"] == 0
    assert "private-secret-text" not in str(result)


def test_valid_metadata_does_not_trigger_missing_evidence():
    email = complete_email()
    email.message.urls = [URLMetadata(raw="https://portal.example/", scheme="https", host="portal.example", path="/")]
    email.message.attachments = [AttachmentMetadata(filename="invoice.pdf", content_type="application/pdf")]
    assert check_insufficient_evidence(email) is None


def test_new_reason_does_not_change_high_score_or_hide_valid_reasons():
    email = complete_email()
    email.message.body_text = "Transfer funds immediately. Send your OTP. Upload your passport."
    email.message.reply_to = "reply@other.example"
    detector = ThreatDetector()
    baseline = detector.analyze(email)
    assert baseline["score"] == 78
    assert baseline["band"] == "HIGH"
    email.authentication = None
    result = detector.analyze(email)
    assert result["score"] == baseline["score"]
    assert result["band"] == baseline["band"]
    assert result["reason_codes"][:-1] == baseline["reason_codes"]
    assert result["reason_codes"][-1]["code"] == "INSUFFICIENT_EVIDENCE"
    assert sum(r["weight"] for r in result["reason_codes"]) == 78


def test_null_input_is_controlled():
    result = ThreatDetector().analyze(None)
    assert result["score"] == 0
    assert [r["code"] for r in result["reason_codes"]] == ["INSUFFICIENT_EVIDENCE"]


def test_no_note_carries_over_to_next_email():
    detector = ThreatDetector()
    assert detector.analyze(None)["reason_codes"]
    assert detector.analyze(complete_email())["reason_codes"] == []
