from unittest.mock import patch

import pytest

from backend.detection.detection import ThreatDetector
from backend.parser.models import ParsedEmail


@pytest.mark.parametrize("status", ["pass", "unknown"])
def test_no_authentication_failures(status):
    email = ParsedEmail()
    email.authentication.spf.result = status
    email.authentication.dkim.result = status
    email.authentication.dmarc.result = status

    result = ThreatDetector().analyze(email)

    assert result["score"] == 0
    assert result["band"] == "LOW"
    assert result["reason_codes"] == []
    # Missing-information notes will be added later.
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
    assert len(result["reason_codes"]) == 1
    reason = result["reason_codes"][0]
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
    assert [reason["code"] for reason in result["reason_codes"]] == [
        "AUTH_SPF_FAIL",
        "AUTH_DKIM_FAIL_OR_NONE",
        "AUTH_DMARC_FAIL",
    ]
    assert sum(reason["weight"] for reason in result["reason_codes"]) == 30
    assert detector.analyze(email) == result

    # A later email must not keep points or reasons from the previous email.
    clean_result = detector.analyze(ParsedEmail())
    assert clean_result["score"] == 0
    assert clean_result["reason_codes"] == []


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
    # The current rules total at most 30. Use a temporary fake result to
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
    assert result["reason_codes"] == [reason]
