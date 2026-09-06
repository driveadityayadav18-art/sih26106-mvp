"""Report unavailable evidence without treating its absence as a threat."""

from ..config import (
    AUTH_RESULT_VALUES, INCOMPLETE_PARSER_WARNING_CODES, INSUFFICIENT_EVIDENCE_SCORE,
)
from .authentication import _get_auth_result
from .identity import _get_domain, _get_sender_domain
from .urls_attachments import _url_host


def evidence_gaps(parsed_email):
    """Return ordered (field path, safe explanation) pairs for incomplete checks."""
    gaps = []
    for method, statuses in AUTH_RESULT_VALUES.items():
        result = _get_auth_result(parsed_email, method)
        if result not in statuses:
            gaps.append((f"authentication.{method}.result",
                         f"{method.upper()} result was missing or unusable; this check was skipped."))
        elif result in ("temperror", "permerror"):
            gaps.append((f"authentication.{method}.result",
                         f"{method.upper()} reported an authentication error; this is not treated as a failure."))

    message = getattr(parsed_email, "message", None)
    if _get_sender_domain(parsed_email) is None:
        gaps.append(("message.from_.address",
                     "Sender address was missing or unusable; identity checks were skipped."))

    texts = [getattr(message, field, None) for field in ("subject", "body_text")]
    if not any(isinstance(value, str) and value.strip() for value in texts):
        gaps.append(("message.body_text",
                     "No usable subject or body text was available; content checks could not run."))
    else:
        for field, value in zip(("subject", "body_text"), texts):
            if value is not None and not isinstance(value, str):
                gaps.append((f"message.{field}", f"{field} was not text; that content field was skipped."))
    if getattr(message, "body_html_present", False) is True and not (
        isinstance(texts[1], str) and texts[1].strip()
    ):
        gaps.append(("message.body_text",
                     "HTML was present without usable plain body text; body requests may be missed."))

    reply_to = getattr(message, "reply_to", None)
    if reply_to is not None and reply_to != "" and _get_domain(reply_to) is None:
        gaps.append(("message.reply_to", "Reply-To was unusable; its domain comparison was skipped."))

    for field in ("urls", "attachments"):
        items = getattr(message, field, None)
        if not isinstance(items, (list, tuple)):
            gaps.append((f"message.{field}", f"The {field} list was unavailable or unusable; its checks may be incomplete."))
            continue
        for index, item in enumerate(items):
            if field == "urls":
                usable = _url_host(item) is not None
                path = getattr(item, "path", None)
                usable = usable and (path is None or isinstance(path, str))
            else:
                usable = getattr(item, "parse_status", None) == "parsed"
                filename = getattr(item, "filename", None)
                content_type = getattr(item, "content_type", None)
                usable = usable and any(isinstance(value, str) and value.strip()
                                        for value in (filename, content_type))
            if not usable:
                gaps.append((f"message.{field}[{index}]",
                             f"Some {field} metadata was unusable or partial; checks may be incomplete."))
                break

    warnings = getattr(parsed_email, "warnings", None)
    if isinstance(warnings, (list, tuple)):
        for index, warning in enumerate(warnings):
            code = getattr(warning, "code", None)
            if isinstance(code, str) and code in INCOMPLETE_PARSER_WARNING_CODES:
                gaps.append((f"warnings[{index}].code",
                             f"Parser warning {code} indicates incomplete evidence; some checks may be unavailable."))
    return gaps


def check_insufficient_evidence(parsed_email):
    gaps = evidence_gaps(parsed_email)
    if not gaps:
        return None
    return {
        "code": "INSUFFICIENT_EVIDENCE",
        "message": (
            "Some evidence was missing or unusable, so the assessment is incomplete. "
            "See limitations for skipped checks. Missing evidence adds no risk points."
        ),
        "evidence_path": gaps[0][0],
        "weight": INSUFFICIENT_EVIDENCE_SCORE,
    }
