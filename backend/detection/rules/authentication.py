from ..config import (
    SPF_FAIL_SCORE,
    DKIM_FAIL_OR_NONE_SCORE,
    DMARC_FAIL_SCORE,
)


def _get_auth_result(parsed_email, method):
    """Read an observed result safely, without treating missing data as failure."""
    authentication = getattr(parsed_email, "authentication", None)
    observation = getattr(authentication, method, None)
    result = getattr(observation, "result", None)
    return result if isinstance(result, str) else None


def check_spf_fail(parsed_email):

    if _get_auth_result(parsed_email, "spf") == "fail":
        return {
            "code": "AUTH_SPF_FAIL",
            "message": "SPF Failed",
            "evidence_path": "authentication.spf.result",
            "weight": SPF_FAIL_SCORE
        }

    return None


def check_dkim_fail_or_none(parsed_email):

    if _get_auth_result(parsed_email, "dkim") in ("fail", "none"):
        return {
            "code": "AUTH_DKIM_FAIL_OR_NONE",
            "message": "DKIM authentication failed or is absent",
            "evidence_path": "authentication.dkim.result",
            "weight": DKIM_FAIL_OR_NONE_SCORE
        }

    return None


def check_dmarc_fail(parsed_email):

    if _get_auth_result(parsed_email, "dmarc") == "fail":
        return {
            "code": "AUTH_DMARC_FAIL",
            "message": "DMARC authentication failed",
            "evidence_path": "authentication.dmarc.result",
            "weight": DMARC_FAIL_SCORE
        }

    return None
