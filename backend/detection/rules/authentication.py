import re

from ..config import (
    SPF_FAIL_SCORE,
    SPF_SOFTFAIL_SCORE,
    COMPAUTH_FAIL_SCORE,
    DKIM_FAIL_OR_NONE_SCORE,
    DMARC_FAIL_SCORE,
    AUTH_ANOMALY_SCORE,
)
from .identity import _get_sender_domain


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


def check_spf_softfail(parsed_email):

    if _get_auth_result(parsed_email, "spf") == "softfail":
        return {
            "code": "AUTH_SPF_SOFTFAIL",
            "message": "SPF SoftFail observed (sender IP actively discouraged by domain SPF policy)",
            "evidence_path": "authentication.spf.result",
            "weight": SPF_SOFTFAIL_SCORE
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


def check_authentication_anomaly(parsed_email):
    """
    Flags when authentication lookup encounters error/temperror/permerror
    while claiming a sender domain without valid cryptographic DKIM verification.
    """
    sender_domain = _get_sender_domain(parsed_email)
    if not sender_domain:
        return None

    spf = _get_auth_result(parsed_email, "spf")
    dmarc = _get_auth_result(parsed_email, "dmarc")
    dkim = _get_auth_result(parsed_email, "dkim")

    # If SPF or DMARC has lookup or configuration errors, and DKIM is not passing
    if (spf in ("temperror", "permerror") or dmarc in ("temperror", "permerror")) and dkim in ("fail", "none", None):
        err_type = spf if spf in ("temperror", "permerror") else dmarc
        evidence_field = "spf" if spf in ("temperror", "permerror") else "dmarc"
        return {
            "code": "AUTH_ANOMALY",
            "message": (
                f"Authentication lookup error encountered ({evidence_field.upper()}: {err_type}) "
                "with absent cryptographic signature (DKIM: none/fail). Sender identity cannot be validated."
            ),
            "evidence_path": f"authentication.{evidence_field}.result",
            "weight": AUTH_ANOMALY_SCORE,
        }

    return None


def check_compauth_fail(parsed_email):
    """
    Flags when upstream composite authentication reports compauth=fail,
    indicating the sending server is unauthorized or forged.
    """
    auth = getattr(parsed_email, "authentication", None)
    compauth = getattr(auth, "compauth", None) if auth else None
    if not compauth and auth:
        for raw in getattr(auth, "raw_authentication_headers", []):
            if re.search(r"\bcompauth\s*=\s*fail\b", raw, re.IGNORECASE):
                compauth = "fail"
                break

    if compauth == "fail":
        return {
            "code": "AUTH_COMPAUTH_FAIL",
            "message": "Upstream composite authentication failed (compauth=fail). Relay is unauthorized.",
            "evidence_path": "authentication.compauth",
            "weight": COMPAUTH_FAIL_SCORE,
        }

    return None

