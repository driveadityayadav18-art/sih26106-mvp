import pytest

from backend.parser.models import ParsedEmail, Warning
from backend.detection.rules import headers


@pytest.mark.parametrize("code", ["MALFORMED_ADDRESS", "MALFORMED_DATE", "MALFORMED_RECEIVED_HEADER"])
def test_header_anomaly(code):
    email = ParsedEmail()
    email.warnings = [Warning("MISSING_REPLY_TO", ""), Warning(code, "private header text")]
    result = headers.check_header_anomaly(email)
    assert result["code"] == "HEADER_ANOMALY"
    assert result["weight"] == 10
    assert result["evidence_path"] == "warnings[1].code"
    assert code in result["message"]
    assert "private header text" not in result["message"]
    assert headers.check_header_anomaly(email) == result


@pytest.mark.parametrize("code", [
    "MISSING_REPLY_TO", "MISSING_AUTHENTICATION_RESULTS", "MISSING_FROM",
    "MISSING_RETURN_PATH", "MISSING_MESSAGE_ID", "PRIVATE_OR_RESERVED_IP_OBSERVED",
    "MIME_PARSE_WARNING", "BODY_DECODE_WARNING", "URL_PARSE_WARNING",
    "HEADER_DECODE_WARNING", "UNKNOWN_WARNING", "", None, [], 123,
])
def test_unselected_or_broken_warning_adds_no_points(code):
    email = ParsedEmail()
    email.warnings = [Warning(code, "")]
    assert headers.check_header_anomaly(email) is None


@pytest.mark.parametrize("warnings", [None, [], {}, 123, "MALFORMED_ADDRESS", [None, {}, "MALFORMED_ADDRESS"]])
def test_missing_or_unusable_warnings(warnings):
    email = ParsedEmail()
    email.warnings = warnings
    assert headers.check_header_anomaly(email) is None
    assert headers.check_header_anomaly(None) is None


def test_repeated_warnings_return_one_reason():
    email = ParsedEmail()
    email.warnings = [Warning("MALFORMED_ADDRESS", "")] * 3
    result = headers.check_header_anomaly(email)
    assert isinstance(result, dict)
    assert result["weight"] == 10
    assert result["evidence_path"] == "warnings[0].code"


def test_warning_selection_is_configurable(monkeypatch):
    monkeypatch.setattr(headers, "HEADER_ANOMALY_WARNING_CODES", ())
    email = ParsedEmail()
    email.warnings = [Warning("MALFORMED_ADDRESS", "")]
    assert headers.check_header_anomaly(email) is None
