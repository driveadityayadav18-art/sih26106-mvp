import pytest

from backend.detection.config import (
    DISPLAY_NAME_DOMAIN_MISMATCH_SCORE,
    REPLY_TO_MISMATCH_SCORE,
    LOOKALIKE_DOMAIN_SCORE,
    PUNYCODE_DOMAIN_SCORE,
)
from backend.detection.rules.identity import (
    check_display_name_domain_mismatch,
    check_reply_to_mismatch,
    check_lookalike_domain,
    check_punycode_domain,
)
from backend.parser.models import ParsedEmail
from backend.detection.rules import identity


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


@pytest.mark.parametrize("domain", [
    "compny.example",       # One missing character.
    "companyy.example",     # One added character.
    "compamy.example",      # One replaced character.
    "COMPAMY.EXAMPLE",      # Uppercase is handled too.
    "company.exampl",       # Compare the whole domain, including its ending.
])
def test_lookalike_domain(domain):
    email = ParsedEmail()
    email.message.from_.address = f"sender@{domain}"

    result = check_lookalike_domain(email)

    assert result is not None
    assert result["code"] == "LOOKALIKE_DOMAIN"
    assert result["weight"] == LOOKALIKE_DOMAIN_SCORE == 20
    assert result["evidence_path"] == "message.from_.address"
    assert domain.lower() in result["message"]
    assert "company.example" in result["message"]
    assert check_lookalike_domain(email) == result


@pytest.mark.parametrize("domain", [
    "company.example", "COMPANY.EXAMPLE", "mail.company.example",
    "aicte-demo.example", "store.example", "compamyx.example",
    "company.example.attacker.test", "cornpany.example",
])
def test_lookalike_near_misses(domain):
    email = ParsedEmail()
    email.message.from_.address = f"sender@{domain}"
    assert check_lookalike_domain(email) is None


def test_lookalike_uses_configured_domains_and_returns_one_reason(monkeypatch):
    monkeypatch.setattr(identity, "TRUSTED_DOMAINS", ["alpha.example", "alphi.example"])
    email = ParsedEmail()
    email.message.from_.address = "sender@alphx.example"
    result = check_lookalike_domain(email)
    assert isinstance(result, dict)
    assert result["weight"] == 20

    # Exact matches must win even if an earlier entry looks similar.
    email.message.from_.address = "sender@alphi.example"
    assert check_lookalike_domain(email) is None
    monkeypatch.setattr(identity, "TRUSTED_DOMAINS", [])
    email.message.from_.address = "sender@compamy.example"
    assert check_lookalike_domain(email) is None


@pytest.mark.parametrize("domain", [
    "xn--bcher-kva.example", "mail.xn--bcher-kva.example",
    "XN--BCHER-KVA.EXAMPLE",
])
def test_punycode_domain(domain):
    email = ParsedEmail()
    email.message.from_.address = f"sender@{domain}"
    result = check_punycode_domain(email)
    assert result is not None
    assert result["code"] == "PUNYCODE_DOMAIN"
    assert result["weight"] == PUNYCODE_DOMAIN_SCORE == 10
    assert result["evidence_path"] == "message.from_.address"
    assert domain.lower() in result["message"]
    assert "legitimate" in result["message"]
    assert check_punycode_domain(email) == result


@pytest.mark.parametrize("address", [
    "sender@company.example", "xn--bcher-kva@company.example",
    "sender@prefix-xn--bcher-kva.example", "sender@bücher.example",
])
def test_punycode_near_misses(address):
    email = ParsedEmail()
    email.message.from_.address = address
    assert check_punycode_domain(email) is None


@pytest.mark.parametrize("rule", [check_lookalike_domain, check_punycode_domain])
@pytest.mark.parametrize("address", [
    None, "", 123, "not-an-address", "sender@", "@compamy.example",
    "sender@compamy..example", "sender@-compamy.example",
    "sender@xn--.example", "sender@compamy.example/path",
    "sender@xn--bcher-kva..example",
])
def test_domain_rules_skip_broken_or_missing_addresses(rule, address):
    email = ParsedEmail()
    email.message.from_.address = address
    assert rule(email) is None


@pytest.mark.parametrize("rule, address", [
    (check_lookalike_domain, "sender@compamy.example"),
    (check_punycode_domain, "sender@xn--bcher-kva.example"),
])
def test_domain_rules_skip_missing_objects_and_parser_marked_bad_sender(rule, address):
    email = ParsedEmail()
    email.message.from_.address = address
    email.message.from_.malformed = True
    assert rule(email) is None
    email.message.from_ = None
    assert rule(email) is None
    email.message = None
    assert rule(email) is None
    assert rule(None) is None


@pytest.mark.parametrize("rule", [check_reply_to_mismatch, check_display_name_domain_mismatch])
@pytest.mark.parametrize("bad_domain", ["company..example", "-company.example", "company_.example", "company.example/path"])
def test_older_identity_rules_reject_broken_domains(rule, bad_domain):
    email = ParsedEmail()
    email.message.from_.address = "sender@company.example"
    email.message.reply_to = f"reply@{bad_domain}"
    email.message.from_.name = f"name@{bad_domain}"
    assert rule(email) is None


@pytest.mark.parametrize("rule", [check_reply_to_mismatch, check_display_name_domain_mismatch])
def test_older_identity_rules_handle_missing_objects_and_malformed_sender(rule):
    email = ParsedEmail()
    email.message.from_.address = "sender@other.example"
    email.message.from_.malformed = True
    email.message.from_.name = "sender@company.example"
    email.message.reply_to = "reply@company.example"
    assert rule(email) is None
    email.message.from_ = None
    assert rule(email) is None
    email.message = None
    assert rule(email) is None
    assert rule(None) is None
