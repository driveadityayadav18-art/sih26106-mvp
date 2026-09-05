import pytest

from backend.detection.config import (
    DISPLAY_NAME_DOMAIN_MISMATCH_SCORE,
    REPLY_TO_MISMATCH_SCORE,
)
from backend.detection.rules.identity import (
    check_display_name_domain_mismatch,
    check_reply_to_mismatch,
)
from backend.parser.models import ParsedEmail


def test_reply_to_mismatch():
    email = ParsedEmail()
    email.message.from_.address = "accounts@company.example"
    email.message.reply_to = "payments@other.example"

    result = check_reply_to_mismatch(email)

    assert result is not None
    assert result["code"] == "REPLY_TO_MISMATCH"
    assert result["weight"] == REPLY_TO_MISMATCH_SCORE == 18
    assert result["evidence_path"] == "message.reply_to"
    assert result["message"]
    # Running the same rule again should give the same result.
    assert check_reply_to_mismatch(email) == result


@pytest.mark.parametrize(
    "sender, reply_to",
    [
        ("accounts@company.example", "help@company.example"),
        ("accounts@COMPANY.EXAMPLE", "help@company.example"),
        ("accounts@company.example", None),
        ("accounts@company.example", ""),
        (None, "help@company.example"),
        ("", "help@company.example"),
        (None, None),
        ("accounts@company.example", "not-an-address"),
        ("not-an-address", "help@company.example"),
        ("accounts@company.example", "user@"),
        ("user@", "help@company.example"),
        ("accounts@company.example", 123),
    ],
    ids=[
        "same-domain", "same-domain-different-case", "missing-reply-to",
        "empty-reply-to", "missing-sender", "empty-sender", "both-missing",
        "reply-to-without-at", "sender-without-at", "reply-to-without-domain",
        "sender-without-domain", "reply-to-wrong-type",
    ],
)
def test_reply_to_does_not_flag_missing_or_matching_evidence(sender, reply_to):
    email = ParsedEmail()
    email.message.from_.address = sender
    email.message.reply_to = reply_to

    assert check_reply_to_mismatch(email) is None


def test_display_name_domain_mismatch():
    email = ParsedEmail()
    email.message.from_.address = "sender@other.example"
    email.message.from_.name = "accounts@company.example"

    result = check_display_name_domain_mismatch(email)

    assert result is not None
    assert result["code"] == "DISPLAY_NAME_DOMAIN_MISMATCH"
    assert result["weight"] == DISPLAY_NAME_DOMAIN_MISMATCH_SCORE == 10
    # This is the current ParsedEmail path; API naming needs a later handoff.
    assert result["evidence_path"] == "message.from_"
    assert result["message"]
    assert check_display_name_domain_mismatch(email) == result


@pytest.mark.parametrize(
    "sender, display_name",
    [
        ("sender@company.example", "accounts@company.example"),
        ("sender@company.example", "accounts@COMPANY.EXAMPLE"),
        ("sender@company.example", "Accounts Team"),
        ("sender@company.example", None),
        ("sender@company.example", ""),
        (None, "accounts@company.example"),
        ("", "accounts@company.example"),
        (None, None),
        ("not-an-address", "accounts@company.example"),
        ("sender@company.example", "user@"),
        ("user@", "accounts@company.example"),
        ("sender@company.example", 123),
        ("sender@company.example", "Support <agent@company.example>"),
    ],
    ids=[
        "same-domain", "same-domain-different-case", "ordinary-name",
        "missing-name", "empty-name", "missing-sender", "empty-sender",
        "both-missing", "sender-without-at", "name-without-domain",
        "sender-without-domain", "name-wrong-type", "same-domain-in-label",
    ],
)
def test_display_name_does_not_flag_missing_or_matching_evidence(sender, display_name):
    email = ParsedEmail()
    email.message.from_.address = sender
    email.message.from_.name = display_name

    assert check_display_name_domain_mismatch(email) is None
