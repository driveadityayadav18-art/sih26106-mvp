from backend.detection.rules.authentication import (
    check_spf_fail,
    check_spf_softfail,
    check_compauth_fail,
    check_dkim_fail_or_none,
    check_dmarc_fail,
)

from backend.parser.models import ParsedEmail

from backend.detection.config import (
    SPF_FAIL_SCORE,
    SPF_SOFTFAIL_SCORE,
    COMPAUTH_FAIL_SCORE,
    DKIM_FAIL_OR_NONE_SCORE,
    DMARC_FAIL_SCORE,
)


def test_spf_fail():
    # Make an object email
    email = ParsedEmail()

    # Set SPF to fail
    email.authentication.spf.result = "fail"

    result = check_spf_fail(email)

    assert result is not None
    assert result["code"] == "AUTH_SPF_FAIL"
    assert result["weight"] == SPF_FAIL_SCORE


def test_spf_pass():
    # Make an object email
    email = ParsedEmail()

    # Set SPF to pass
    email.authentication.spf.result = "pass"

    result = check_spf_fail(email)

    assert result is None


def test_spf_unknown():
    # Make an object email
    email = ParsedEmail()

    result = check_spf_fail(email)

    assert result is None


def test_dkim_fail():
    email = ParsedEmail()
    email.authentication.dkim.result = "fail"

    result = check_dkim_fail_or_none(email)

    assert result is not None
    assert result["code"] == "AUTH_DKIM_FAIL_OR_NONE"
    assert result["weight"] == DKIM_FAIL_OR_NONE_SCORE


def test_dkim_none():
    email = ParsedEmail()
    email.authentication.dkim.result = "none"

    result = check_dkim_fail_or_none(email)

    assert result is not None
    assert result["code"] == "AUTH_DKIM_FAIL_OR_NONE"
    assert result["weight"] == DKIM_FAIL_OR_NONE_SCORE


def test_dkim_pass():
    email = ParsedEmail()
    email.authentication.dkim.result = "pass"

    result = check_dkim_fail_or_none(email)

    assert result is None


def test_dkim_unknown():
    email = ParsedEmail()

    result = check_dkim_fail_or_none(email)

    assert result is None


def test_dmarc_fail():
    email = ParsedEmail()
    email.authentication.dmarc.result = "fail"

    result = check_dmarc_fail(email)

    assert result is not None
    assert result["code"] == "AUTH_DMARC_FAIL"
    assert result["weight"] == DMARC_FAIL_SCORE


def test_dmarc_pass():
    email = ParsedEmail()
    email.authentication.dmarc.result = "pass"

    result = check_dmarc_fail(email)

    assert result is None


def test_dmarc_unknown():
    email = ParsedEmail()

    result = check_dmarc_fail(email)

    assert result is None


def test_spf_softfail():
    email = ParsedEmail()
    email.authentication.spf.result = "softfail"
    result = check_spf_softfail(email)
    assert result is not None
    assert result["code"] == "AUTH_SPF_SOFTFAIL"
    assert result["weight"] == SPF_SOFTFAIL_SCORE


def test_compauth_fail():
    email = ParsedEmail()
    email.authentication.compauth = "fail"
    result = check_compauth_fail(email)
    assert result is not None
    assert result["code"] == "AUTH_COMPAUTH_FAIL"
    assert result["weight"] == COMPAUTH_FAIL_SCORE
