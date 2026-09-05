from backend.detection.rules.authentication import (
    check_spf_fail,
    check_dkim_fail_or_none,
    check_dmarc_fail
)
from backend.detection.config import (
    LOW_MAX_SCORE,
    REVIEW_MAX_SCORE,
    MAX_SCORE
)


class ThreatDetector:
    def analyze(self, parsed_email):
        score = 0
        reason_code = []
        band = ""

        # Authentication
        result = check_spf_fail(parsed_email)
        if result:
            score += result["weight"]
            reason_code.append(result)

        result = check_dkim_fail_or_none(parsed_email)
        if result:
            score += result["weight"]
            reason_code.append(result)

        result = check_dmarc_fail(parsed_email)
        if result:
            score += result["weight"]
            reason_code.append(result)

        # Assese band
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
            "limitations": [],
        }
