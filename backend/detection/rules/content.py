"""Offline English request patterns over parser-provided subject and body text."""

import re

from ..config import (
    URGENT_PAYMENT_SCORE,
    CREDENTIAL_REQUEST_SCORE,
    SENSITIVE_DATA_REQUEST_SCORE,
    REQUEST_GAP,
    PRESSURE_GAP,
    NEGATION_WINDOW,
    PAYMENT_ACTIONS,
    PAYMENT_ITEMS,
    PRESSURE_PHRASES,
    CREDENTIAL_ACTIONS,
    CREDENTIAL_ITEMS,
    SENSITIVE_ACTIONS,
    SENSITIVE_ITEMS,
    NEGATIONS,
    BANK_CHANGE_ACTIONS, BANK_CHANGE_ITEMS,
    PASSWORD_RETENTION_PHRASES, IDENTITY_VERIFICATION_PHRASES,
    ACCOUNT_THREAT_PHRASES, CREDENTIAL_LURE_WINDOW,
)


def _sentences(parsed_email):
    """Yield tokens and their field path; never join subject and body."""
    message = getattr(parsed_email, "message", None)
    for field in ("subject", "body_text"):
        value = getattr(message, field, None)
        if not isinstance(value, str) or not value.strip():
            continue
        text = value.lower().replace("’", "'")
        for sentence in re.split(r"[.!?;\n]+|\bbut\b|\bhowever\b", text):
            tokens = re.findall(r"\w+(?:'\w+)?", sentence)
            if tokens:
                yield tokens, f"message.{field}"


def _phrase_spans(tokens, phrases):
    """Find whole phrases, returning token positions and the matched phrase."""
    for phrase in phrases:
        words = phrase.split()
        for start in range(len(tokens) - len(words) + 1):
            end = start + len(words)
            if tokens[start:end] == words:
                yield start, end, phrase


def _check_request(parsed_email, actions, items, code, weight, title, pressure=False):
    for tokens, path in _sentences(parsed_email):
        for action_start, action_end, action in _phrase_spans(tokens, actions):
            before = tokens[max(0, action_start - NEGATION_WINDOW):action_start]
            if any(word in NEGATIONS for word in before):
                continue
            for item_start, item_end, item in _phrase_spans(tokens, items):
                if not 0 <= item_start - action_end <= REQUEST_GAP:
                    continue
                # "Share no passwords" is also a negative instruction.
                if any(word in NEGATIONS or word == "no"
                       for word in tokens[action_end:item_start]):
                    continue
                if pressure:
                    nearby = tokens[max(0, action_start - PRESSURE_GAP):item_end + PRESSURE_GAP]
                    if not any(
                        not any(word in NEGATIONS for word in nearby[max(0, start - 2):start])
                        for start, _, _ in _phrase_spans(nearby, PRESSURE_PHRASES)
                    ):
                        continue
                return {
                    "code": code,
                    "message": (
                        f"{title}: request wording '{action}' near '{item}'"
                        + (" with urgency wording" if pressure else "")
                        + ". This is a review signal, not proof of fraud."
                    ),
                    "evidence_path": path,
                    "weight": weight,
                }
    return None


def check_urgent_payment_request(parsed_email):
    result = _check_request(
        parsed_email, PAYMENT_ACTIONS, PAYMENT_ITEMS,
        "URGENT_PAYMENT_REQUEST", URGENT_PAYMENT_SCORE,
        "Urgent payment request observed", pressure=True,
    )
    return result or _check_request(
        parsed_email, BANK_CHANGE_ACTIONS, BANK_CHANGE_ITEMS,
        "URGENT_PAYMENT_REQUEST", URGENT_PAYMENT_SCORE,
        "Urgent bank-details change request observed", pressure=True,
    )


def _check_password_retention_lure(parsed_email):
    """Require retention, verification and account-threat wording in one field."""
    message = getattr(parsed_email, "message", None)
    for field in ("subject", "body_text"):
        text = getattr(message, field, None)
        if not isinstance(text, str):
            continue
        tokens = re.findall(r"\w+(?:'\w+)?", text.lower().replace("’", "'"))

        def positive_spans(phrases):
            return [(start, end) for start, end, _ in _phrase_spans(tokens, phrases)
                    if not any(word in NEGATIONS
                               for word in tokens[max(0, start - NEGATION_WINDOW):start])]

        retention = positive_spans(PASSWORD_RETENTION_PHRASES)
        verification = positive_spans(IDENTITY_VERIFICATION_PHRASES)
        threats = positive_spans(ACCOUNT_THREAT_PHRASES)
        for start, end in retention:
            for verify_start, verify_end in verification:
                if max(end, verify_end) - min(start, verify_start) > CREDENTIAL_LURE_WINDOW:
                    continue
                for threat_start, threat_end in threats:
                    if max(end, verify_end, threat_end) - min(start, verify_start, threat_start) <= CREDENTIAL_LURE_WINDOW:
                        return {
                            "code": "CREDENTIAL_REQUEST",
                            "message": (
                                "Password-retention wording appears near identity verification and "
                                "an account-suspension or lock warning. This may be a credential lure, "
                                "but is not proof of fraud."
                            ),
                            "evidence_path": f"message.{field}",
                            "weight": CREDENTIAL_REQUEST_SCORE,
                        }
    return None


def check_credential_request(parsed_email):
    result = _check_request(
        parsed_email, CREDENTIAL_ACTIONS, CREDENTIAL_ITEMS,
        "CREDENTIAL_REQUEST", CREDENTIAL_REQUEST_SCORE,
        "Request to share or enter credentials observed",
    )
    return result or _check_password_retention_lure(parsed_email)


def check_sensitive_data_request(parsed_email):
    return _check_request(
        parsed_email, SENSITIVE_ACTIONS, SENSITIVE_ITEMS,
        "SENSITIVE_DATA_REQUEST", SENSITIVE_DATA_REQUEST_SCORE,
        "Request for sensitive information observed",
    )
