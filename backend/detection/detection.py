from backend.detection.rules.authentication import (
    check_spf_fail,
    check_dkim_fail_or_none,
    check_dmarc_fail,
    _get_auth_result,
)
from backend.detection.config import (
    LOW_MAX_SCORE,
    REVIEW_MAX_SCORE,
    MAX_SCORE
)
from backend.detection.rules.identity import (
    check_reply_to_mismatch,
    check_display_name_domain_mismatch,
    check_lookalike_domain,
    check_punycode_domain,
    _get_domain,
    _get_sender_domain,
)
from backend.detection.rules.content import (
    check_urgent_payment_request,
    check_credential_request,
    check_sensitive_data_request,
)
from backend.detection.rules.urls_attachments import (
    check_suspicious_url_path,
    check_shortened_url,
    check_suspicious_attachment,
)
from backend.detection.context import DetectionContext
from backend.detection.rules.headers import check_header_anomaly
from backend.detection.rules.context import check_reused_indicator


def _collect_limitations(parsed_email):
    """Explain skipped checks without adding points or exposing email content."""
    limitations = []
    known_results = {
        "spf": ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"),
        "dkim": ("pass", "fail", "none", "neutral", "temperror", "permerror"),
        "dmarc": ("pass", "fail", "none", "bestguesspass", "temperror", "permerror"),
    }
    for method, statuses in known_results.items():
        result = _get_auth_result(parsed_email, method)
        if result not in statuses:
            limitations.append(
                f"{method.upper()} result was missing or unusable; this check was skipped."
            )
        elif result in ("temperror", "permerror"):
            limitations.append(
                f"{method.upper()} reported an authentication error; this is not treated as a failure."
            )

    message = getattr(parsed_email, "message", None)
    if _get_sender_domain(parsed_email) is None:
        limitations.append(
            "Sender address was missing or unusable; identity checks were skipped."
        )
    else:
        reply_to = getattr(message, "reply_to", None)
        if _get_domain(reply_to) is None:
            limitations.append(
                "Reply-To was missing or unusable; the reply-domain comparison was skipped. "
                "A missing Reply-To is normal and adds no points."
            )
        sender = getattr(message, "from_", None)
        name = getattr(sender, "name", None)
        if name is not None and not isinstance(name, str):
            limitations.append("Display name was unusable; its domain comparison was skipped.")
        elif isinstance(name, str) and "@" in name and _get_domain(name) is None:
            limitations.append(
                "Display name was not a usable plain email address; its domain comparison was skipped."
            )
    return limitations


class ThreatDetector:
    def analyze(self, parsed_email, context: DetectionContext | None = None):
        score = 0
        reason_code = []
        band = ""

        # Authentication
        for rule in (
            check_spf_fail,
            check_dkim_fail_or_none,
            check_dmarc_fail,
        ):
            result = rule(parsed_email)
            if result:
                score += result["weight"]
                reason_code.append(result)

        # Identity
        for rule in (
            check_reply_to_mismatch,
            check_display_name_domain_mismatch,
            check_lookalike_domain,
            check_punycode_domain,
        ):
            result = rule(parsed_email)
            if result:
                score += result["weight"]
                reason_code.append(result)

        # Content
        for rule in (
            check_urgent_payment_request,
            check_credential_request,
            check_sensitive_data_request,
        ):
            result = rule(parsed_email)
            if result:
                score += result["weight"]
                reason_code.append(result)

        # URLs and attachments
        for rule in (
            check_suspicious_url_path,
            check_shortened_url,
            check_suspicious_attachment,
        ):
            result = rule(parsed_email)
            if result:
                score += result["weight"]
                reason_code.append(result)

        # Parser warnings and optional reuse evidence
        for result in (
            check_header_anomaly(parsed_email),
            check_reused_indicator(parsed_email, context),
        ):
            if result:
                score += result["weight"]
                reason_code.append(result)

        # Assess band
        score = max(0, min(MAX_SCORE, score))

        if score <= LOW_MAX_SCORE:
            band = "LOW"
        elif score <= REVIEW_MAX_SCORE:
            band = "REVIEW"
        else:
            band = "HIGH"

        return {
            "score": score,
            "band": band,
            "reason_codes": reason_code,
            "limitations": _collect_limitations(parsed_email),
        }
