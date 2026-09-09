import re
from typing import Dict, Any, Tuple


# Precompiled Regex Patterns for High Performance
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# 16-digit credit cards with optional spaces or hyphens (4-4-4-4 or 16 continuous)
CREDIT_CARD_REGEX = re.compile(
    r"\b(?:\d{4}[-\s]){3}\d{4}\b|\b\d{16}\b"
)

# 12-digit Indian Aadhaar numbers formatted in 3 groups of 4 or 12 continuous digits
AADHAAR_REGEX = re.compile(
    r"\b\d{4}[-\s]\d{4}[-\s]\d{4}\b|\b[2-9]\d{11}\b"
)

# Indian mobile/phone numbers (+91 / 0 / 10 digits starting with 6-9)
PHONE_REGEX = re.compile(
    r"(?:\+91[-\s]?|\(?91\)?[-.\s]?|0)?[6-9]\d{2}[-.\s]?\d{3}[-.\s]?\d{4}\b|"
    r"(?:\+91[-\s]?|\(?91\)?[-.\s]?|0)?[6-9]\d{4}[-.\s]?\d{5}\b|"
    r"(?:\+91[-\s]?|\(?91\)?[-.\s]?|0)?[6-9]\d{9}\b"
)


def mask_pii(text: str) -> Tuple[str, Dict[str, Any]]:
    """
    Automated PII masking before passing email content to external AI/LLMs
    to satisfy data privacy, GDPR, and DPDP compliance claims.

    Redaction Rules:
    - Credit Card numbers (16 digits with dashes/spaces/contiguous) -> [REDACTED_CREDIT_CARD]
    - Indian Phone numbers (+91 / 10 digits starting with 6-9)     -> [REDACTED_PHONE]
    - Aadhaar numbers (12 digits grouped by 4 or contiguous)       -> [REDACTED_AADHAAR]
    - Email addresses inside body text                             -> [REDACTED_EMAIL]

    Returns:
        tuple[str, dict]: (sanitized_text, summary_dict)
        where summary_dict = {
            "cards_redacted": int,
            "phones_redacted": int,
            "emails_redacted": int,
            "aadhaar_redacted": int,
            "pii_detected": bool
        }
    """
    if not text or not isinstance(text, str):
        return text if text is not None else "", {
            "cards_redacted": 0,
            "phones_redacted": 0,
            "emails_redacted": 0,
            "aadhaar_redacted": 0,
            "pii_detected": False,
        }

    sanitized = text

    # 1. Redact Email addresses
    emails_found = EMAIL_REGEX.findall(sanitized)
    emails_count = len(emails_found)
    if emails_count > 0:
        sanitized = EMAIL_REGEX.sub("[REDACTED_EMAIL]", sanitized)

    # 2. Redact Credit Card numbers (16 digits)
    cards_found = CREDIT_CARD_REGEX.findall(sanitized)
    cards_count = len(cards_found)
    if cards_count > 0:
        sanitized = CREDIT_CARD_REGEX.sub("[REDACTED_CREDIT_CARD]", sanitized)

    # 3. Redact Aadhaar numbers (12 digits)
    aadhaar_found = AADHAAR_REGEX.findall(sanitized)
    aadhaar_count = len(aadhaar_found)
    if aadhaar_count > 0:
        sanitized = AADHAAR_REGEX.sub("[REDACTED_AADHAAR]", sanitized)

    # 4. Redact Indian Phone numbers
    phones_found = PHONE_REGEX.findall(sanitized)
    phones_count = len(phones_found)
    if phones_count > 0:
        sanitized = PHONE_REGEX.sub("[REDACTED_PHONE]", sanitized)

    pii_detected = bool(cards_count > 0 or phones_count > 0 or emails_count > 0 or aadhaar_count > 0)

    summary = {
        "cards_redacted": cards_count,
        "phones_redacted": phones_count,
        "emails_redacted": emails_count,
        "aadhaar_redacted": aadhaar_count,
        "pii_detected": pii_detected,
    }

    return sanitized, summary
