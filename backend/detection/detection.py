from backend.detection.rules.authentication import (
    check_spf_fail,
    check_spf_softfail,
    check_compauth_fail,
    check_dkim_fail_or_none,
    check_dmarc_fail,
    check_authentication_anomaly,
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
    check_return_path_anomaly,
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
    check_external_url_mismatch,
    check_obfuscated_or_redirect_url,
    check_url_ml_risk,
)
from backend.detection.context import DetectionContext
from backend.detection.rules.headers import check_header_anomaly
from backend.detection.rules.context import check_reused_indicator
from backend.detection.rules.evidence import check_insufficient_evidence, evidence_gaps


def _collect_limitations(parsed_email):
    """Explain skipped checks without adding points or exposing email content."""
    limitations = [note for _, note in evidence_gaps(parsed_email)]
    message = getattr(parsed_email, "message", None)
    if _get_sender_domain(parsed_email) is not None:
        reply_to = getattr(message, "reply_to", None)
        if reply_to is None or reply_to == "":
            limitations.append(
                "Reply-To was missing; the reply-domain comparison was skipped. "
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
    return list(dict.fromkeys(limitations))


class ThreatDetector:
    def analyze(self, parsed_email, context: DetectionContext | None = None):
        score = 0
        reason_code = []
        band = ""

        # Authentication
        for rule in (
            check_spf_fail,
            check_spf_softfail,
            check_compauth_fail,
            check_dkim_fail_or_none,
            check_dmarc_fail,
            check_authentication_anomaly,
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
            check_return_path_anomaly,
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
            check_external_url_mismatch,
            check_obfuscated_or_redirect_url,
            check_url_ml_risk,
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

        # Missing evidence is visible but adds zero points.
        result = check_insufficient_evidence(parsed_email)
        if result:
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
