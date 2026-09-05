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
    return _check_request(
        parsed_email, PAYMENT_ACTIONS, PAYMENT_ITEMS,
        "URGENT_PAYMENT_REQUEST", URGENT_PAYMENT_SCORE,
        "Urgent payment request observed", pressure=True,
    )


def check_credential_request(parsed_email):
    return _check_request(
        parsed_email, CREDENTIAL_ACTIONS, CREDENTIAL_ITEMS,
        "CREDENTIAL_REQUEST", CREDENTIAL_REQUEST_SCORE,
        "Request to share or enter credentials observed",
    )


def check_sensitive_data_request(parsed_email):
    return _check_request(
        parsed_email, SENSITIVE_ACTIONS, SENSITIVE_ITEMS,
        "SENSITIVE_DATA_REQUEST", SENSITIVE_DATA_REQUEST_SCORE,
        "Request for sensitive information observed",
    )
