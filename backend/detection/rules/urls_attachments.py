"""Check parser-provided metadata only; never fetch URLs or open attachments."""

import re

from ..config import (
    URL_SHORTENER_HOSTS, URL_PATH_REQUEST_TYPES,
    RISKY_ATTACHMENT_EXTENSIONS, RISKY_ATTACHMENT_CONTENT_TYPES,
    SUSPICIOUS_URL_PATH_SCORE, SHORTENED_URL_SCORE, SUSPICIOUS_ATTACHMENT_SCORE,
    EXTERNAL_URL_MISMATCH_SCORE, TRUSTED_URL_DOMAINS,
    OBFUSCATED_URL_SCORE, TRAMPOLINE_REDIRECT_SCORE,
    PAYMENT_ACTIONS, PAYMENT_ITEMS,
)
from .content import check_credential_request, check_sensitive_data_request, _check_request
from .identity import _get_sender_domain, _get_domain


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


def check_external_url_mismatch(parsed_email):
    """
    Flags when an email contains links to an external domain that differs from
    both the visible sender domain and reply-to domain, excluding trusted services.
    """
    from_domain = _get_sender_domain(parsed_email)
    if not from_domain:
        return None

    message = getattr(parsed_email, "message", None)
    reply_to = getattr(message, "reply_to", None)
    reply_domain = _get_domain(reply_to) if isinstance(reply_to, str) else None

    for index, url in _metadata_items(parsed_email, "urls"):
        host = _url_host(url)
        if not host:
            continue

        # Skip known shorteners (handled by check_shortened_url)
        if host in URL_SHORTENER_HOSTS:
            continue

        # Skip RFC test domains (.example, .test) used across unit tests
        if host.endswith(".example") or host.endswith(".test"):
            continue

        # Check trusted global domains (Google, Microsoft, YouTube, etc.)
        is_trusted = False
        for trusted in TRUSTED_URL_DOMAINS:
            if host == trusted or host.endswith("." + trusted):
                is_trusted = True
                break

        # If the outer host is trusted (e.g. google.com) but wraps an unpacked trampoline destination,
        # evaluate the true destination host instead of blindly discarding.
        unpacked_host = getattr(url, "unpacked_host", None)
        if unpacked_host and (is_trusted or host in URL_SHORTENER_HOSTS):
            target_eval_host = unpacked_host.lower().removesuffix(".")
            if not target_eval_host.endswith(".example") and not target_eval_host.endswith(".test"):
                is_unpacked_trusted = any(
                    target_eval_host == t or target_eval_host.endswith("." + t)
                    for t in TRUSTED_URL_DOMAINS
                )
                if not is_unpacked_trusted:
                    if (
                        target_eval_host != from_domain
                        and not target_eval_host.endswith("." + from_domain)
                        and (not reply_domain or (target_eval_host != reply_domain and not target_eval_host.endswith("." + reply_domain)))
                    ):
                        return {
                            "code": "EXTERNAL_URL_MISMATCH",
                            "message": (
                                f"External link host '{target_eval_host}' (unpacked from trampoline redirect) differs from sender domain '{from_domain}'. "
                                "Directing recipients to third-party unaligned domains is a prominent credential phishing tactic."
                            ),
                            "evidence_path": f"message.urls[{index}].unpacked_host",
                            "weight": EXTERNAL_URL_MISMATCH_SCORE,
                        }

        if is_trusted:
            continue

        # Check alignment with sender domain
        if host == from_domain or host.endswith("." + from_domain):
            continue

        # Check alignment with reply_to domain
        if reply_domain and (host == reply_domain or host.endswith("." + reply_domain)):
            continue

        return {
            "code": "EXTERNAL_URL_MISMATCH",
            "message": (
                f"External link host '{host}' differs from sender domain '{from_domain}'. "
                "Directing recipients to third-party unaligned domains is a prominent credential phishing tactic."
            ),
            "evidence_path": f"message.urls[{index}].host",
            "weight": EXTERNAL_URL_MISMATCH_SCORE,
        }

    return None


def check_obfuscated_or_redirect_url(parsed_email):
    """
    Detects percent-encoded host/protocol evasion or trampoline open-redirect wrappers
    designed to conceal the true external destination.
    """
    for index, url in _metadata_items(parsed_email, "urls"):
        is_obfuscated = getattr(url, "is_obfuscated", False)
        is_trampoline = getattr(url, "is_trampoline", False)
        unpacked_host = getattr(url, "unpacked_host", None)

        if is_obfuscated:
            return {
                "code": "OBFUSCATED_URL",
                "message": (
                    f"Obfuscated URL detected (percent-encoding evasion or character masking). "
                    f"Target destination: '{unpacked_host or getattr(url, 'host', 'unknown')}'. "
                    "Adversaries employ encoding evasion to bypass perimeter gateway filters."
                ),
                "evidence_path": f"message.urls[{index}].raw",
                "weight": OBFUSCATED_URL_SCORE,
            }

        if is_trampoline:
            return {
                "code": "TRAMPOLINE_REDIRECT",
                "message": (
                    f"Open redirect trampoline wrapper detected targeting '{unpacked_host or 'external destination'}'. "
                    "Abusing legitimate domain redirectors to route recipients to external destinations."
                ),
                "evidence_path": f"message.urls[{index}].raw",
                "weight": TRAMPOLINE_REDIRECT_SCORE,
            }

    return None

