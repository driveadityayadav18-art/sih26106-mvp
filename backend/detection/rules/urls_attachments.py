"""Check parser-provided metadata only; never fetch URLs or open attachments."""

import re

from ..config import (
    URL_SHORTENER_HOSTS, URL_PATH_REQUEST_TYPES,
    RISKY_ATTACHMENT_EXTENSIONS, RISKY_ATTACHMENT_CONTENT_TYPES,
    SUSPICIOUS_URL_PATH_SCORE, SHORTENED_URL_SCORE, SUSPICIOUS_ATTACHMENT_SCORE,
    PAYMENT_ACTIONS, PAYMENT_ITEMS,
)
from .content import check_credential_request, check_sensitive_data_request, _check_request


def _metadata_items(parsed_email, field):
    message = getattr(parsed_email, "message", None)
    items = getattr(message, field, None)
    if isinstance(items, (list, tuple)):
        yield from enumerate(items)


def _url_host(url):
    """Require usable HTTP(S) metadata, without reparsing the raw URL."""
    scheme = getattr(url, "scheme", None)
    host = getattr(url, "host", None)
    if (
        getattr(url, "parse_status", None) != "parsed"
        or not isinstance(scheme, str)
        or scheme.lower() not in ("http", "https")
        or not isinstance(host, str)
    ):
        return None
    host = host.lower().removesuffix(".")
    if not host or len(host) > 253:
        return None
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in host.split(".")):
        return None
    return host


def check_shortened_url(parsed_email):
    for index, url in _metadata_items(parsed_email, "urls"):
        host = _url_host(url)
        if host in URL_SHORTENER_HOSTS:
            return {
                "code": "SHORTENED_URL",
                "message": (
                    f"URL host {host} matches the configured shortener list. "
                    "The final destination is hidden and was not checked; this is not proof of harm."
                ),
                "evidence_path": f"message.urls[{index}].host",
                "weight": SHORTENED_URL_SCORE,
            }
    return None


def check_suspicious_url_path(parsed_email):
    requests = {
        "credential": check_credential_request(parsed_email),
        "sensitive": check_sensitive_data_request(parsed_email),
        # A payment URL needs a payment request, but does not require urgency.
        "payment": _check_request(
            parsed_email, PAYMENT_ACTIONS, PAYMENT_ITEMS,
            "PAYMENT_CONTEXT", 0, "Payment request observed",
        ),
    }
    for index, url in _metadata_items(parsed_email, "urls"):
        if _url_host(url) is None:
            continue
        path = getattr(url, "path", None)
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        if any(char.isspace() for char in path) or "?" in path or "#" in path:
            continue
        for segment in path.lower().split("/"):
            for request_type in URL_PATH_REQUEST_TYPES.get(segment, ()):
                request = requests[request_type]
                if request:
                    return {
                        "code": "SUSPICIOUS_URL_PATH",
                        "message": (
                            f"URL path contains /{segment} and a {request_type} request "
                            f"was observed in {request['evidence_path']}. "
                            "Their connection is not verified; legitimate requests can match too."
                        ),
                        "evidence_path": f"message.urls[{index}].path",
                        "weight": SUSPICIOUS_URL_PATH_SCORE,
                    }
    return None


def check_suspicious_attachment(parsed_email):
    for index, attachment in _metadata_items(parsed_email, "attachments"):
        if getattr(attachment, "parse_status", None) not in ("parsed", "partial"):
            continue
        filename = getattr(attachment, "filename", None)
        content_type = getattr(attachment, "content_type", None)
        extension = ""
        if isinstance(filename, str) and "." in filename:
            extension = "." + filename.strip().rsplit(".", 1)[1].lower()
        if extension in RISKY_ATTACHMENT_EXTENSIONS:
            field, observed = "filename", f"final extension {extension}"
        elif isinstance(content_type, str) and content_type.strip().lower() in RISKY_ATTACHMENT_CONTENT_TYPES:
            field, observed = "content_type", f"content type {content_type.strip().lower()}"
        else:
            continue
        return {
            "code": "SUSPICIOUS_ATTACHMENT",
            "message": (
                f"Attachment {observed} matches the configured risky-type list. "
                "Only metadata was checked; this is not proof of malware."
            ),
            "evidence_path": f"message.attachments[{index}].{field}",
            "weight": SUSPICIOUS_ATTACHMENT_SCORE,
        }
    return None
