"""Consume parser warnings without reading or parsing raw headers."""

from ..config import HEADER_ANOMALY_SCORE, HEADER_ANOMALY_WARNING_CODES


def check_header_anomaly(parsed_email):
    warnings = getattr(parsed_email, "warnings", None)
    if not isinstance(warnings, (list, tuple)):
        return None

    for index, warning in enumerate(warnings):
        code = getattr(warning, "code", None)
        if isinstance(code, str) and code in HEADER_ANOMALY_WARNING_CODES:
            return {
                "code": "HEADER_ANOMALY",
                "message": (
                    f"The parser reported {code}. A header could not be interpreted reliably. "
                    "This may be a formatting problem, not proof of malicious intent."
                ),
                "evidence_path": f"warnings[{index}].code",
                "weight": HEADER_ANOMALY_SCORE,
            }
    return None
