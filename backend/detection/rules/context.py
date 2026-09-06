"""Check supplied reuse observations; never search cases or build a graph."""

import re

from ..config import REUSED_INDICATOR_SCORE, REUSED_INDICATOR_TYPES
from .identity import _get_domain, _get_sender_domain
from .urls_attachments import _metadata_items, _url_host


def _observed_indicators(parsed_email):
    """Yield supported current-email values and the fields that support them."""
    message = getattr(parsed_email, "message", None)
    sender = _get_sender_domain(parsed_email)
    if sender:
        yield "domain", sender, "message.from_.address"
    reply = _get_domain(getattr(message, "reply_to", None))
    if reply:
        yield "domain", reply, "message.reply_to"

    for index, url in _metadata_items(parsed_email, "urls"):
        host = _url_host(url)
        if host:
            yield "domain", host, f"message.urls[{index}].host"
            raw = getattr(url, "raw", None)
            if isinstance(raw, str) and raw.strip():
                yield "url", raw, f"message.urls[{index}].raw"

    for index, attachment in _metadata_items(parsed_email, "attachments"):
        if getattr(attachment, "parse_status", None) not in ("parsed", "partial"):
            continue
        digest = getattr(attachment, "sha256", None)
        if isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            yield "attachment_sha256", digest.lower(), f"message.attachments[{index}].sha256"


def check_reused_indicator(parsed_email, context=None):
    observations = getattr(context, "reused_indicators", None)
    if not isinstance(observations, (list, tuple)):
        return None
    current_case_id = getattr(context, "current_case_id", None)
    observed = list(_observed_indicators(parsed_email))

    for index, observation in enumerate(observations):
        kind = getattr(observation, "indicator_type", None)
        value = getattr(observation, "value", None)
        source = getattr(observation, "source", None)
        cases = getattr(observation, "related_case_ids", None)
        if (
            not isinstance(kind, str) or kind not in REUSED_INDICATOR_TYPES
            or not isinstance(value, str) or not value.strip()
            or not isinstance(source, str) or not source.strip()
            or not isinstance(cases, (list, tuple))
        ):
            continue
        previous_cases = {
            case.strip() for case in cases
            if isinstance(case, str) and case.strip()
            and case.strip() != (current_case_id.strip() if isinstance(current_case_id, str) else current_case_id)
        }
        if not previous_cases:
            continue
        # URL paths/queries remain case-sensitive; no redirect resolution.
        if kind == "domain":
            value = value.strip().lower().removesuffix(".")
        elif kind == "attachment_sha256":
            value = value.strip().lower()
        for observed_kind, observed_value, path in observed:
            if kind == observed_kind and value == observed_value:
                return {
                    "code": "REUSED_INDICATOR",
                    "message": (
                        f"A current {kind} matches supplied reuse evidence from "
                        f"{len(previous_cases)} other case(s), recorded at "
                        f"context.reused_indicators[{index}]. "
                        "The detector did not verify those cases; shared indicators can be legitimate."
                    ),
                    "evidence_path": path,
                    "weight": REUSED_INDICATOR_SCORE,
                }
    return None
