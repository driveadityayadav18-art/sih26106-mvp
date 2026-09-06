from ..config import (
    REPLY_TO_MISMATCH_SCORE,
    DISPLAY_NAME_DOMAIN_MISMATCH_SCORE,
    LOOKALIKE_DOMAIN_SCORE,
    PUNYCODE_DOMAIN_SCORE,
    RETURN_PATH_ANOMALY_SCORE,
    TRUSTED_DOMAINS,
)


def _get_domain(address):
    """Extract domain from an email address."""
    if not isinstance(address, str):
        return None

    address = address.strip()
    # Only use plain addresses; skip labels and broken values.
    if address.count("@") != 1 or any(
        char.isspace() or char in "<>" for char in address
    ):
        return None

    local_part, domain = address.rsplit("@", 1)
    if not local_part or not domain:
        return None

    domain = domain.lower()
    if len(domain) > 253:
        return None
    for label in domain.split("."):
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in label)
        ):
            return None
    return domain


def check_reply_to_mismatch(parsed_email):
    message = getattr(parsed_email, "message", None)
    reply_to = getattr(message, "reply_to", None)

    from_domain = _get_sender_domain(parsed_email)
    reply_domain = _get_domain(reply_to)

    # Missing evidence is not a mismatch.
    if from_domain is None or reply_domain is None:
        return None

    if from_domain != reply_domain:
        return {
            "code": "REPLY_TO_MISMATCH",
            "message": "Reply-To domain differs from sender domain",
            "evidence_path": "message.reply_to",
            "weight": REPLY_TO_MISMATCH_SCORE
        }

    return None


def _get_sender_domain(parsed_email):
    """Read a usable ASCII sender domain for all identity rules."""
    message = getattr(parsed_email, "message", None)
    sender = getattr(message, "from_", None)
    if getattr(sender, "malformed", False):
        return None

    return _get_domain(getattr(sender, "address", None))


def _is_one_edit_apart(first, second):
    """True for exactly one added, removed or replaced character."""
    if abs(len(first) - len(second)) > 1:
        return False
    if len(first) == len(second):
        return sum(a != b for a, b in zip(first, second)) == 1

    shorter, longer = sorted((first, second), key=len)
    for index, char in enumerate(shorter):
        if char != longer[index]:
            return shorter[index:] == longer[index + 1:]
    return True  # The extra character is at the end.


def check_lookalike_domain(parsed_email):
    domain = _get_sender_domain(parsed_email)
    if domain is None:
        return None

    # Check every trusted domain before considering a spelling similarity.
    if any(domain == trusted or domain.endswith("." + trusted) for trusted in TRUSTED_DOMAINS):
        return None

    for trusted in TRUSTED_DOMAINS:
        if _is_one_edit_apart(domain, trusted):
            return {
                "code": "LOOKALIKE_DOMAIN",
                "message": (
                    f"Sender domain {domain} resembles trusted demo domain {trusted} "
                    "by one added, removed or replaced character. "
                    "This may cause confusion, but is not proof of impersonation."
                ),
                "evidence_path": "message.from_.address",
                "weight": LOOKALIKE_DOMAIN_SCORE,
            }
    return None


def check_punycode_domain(parsed_email):
    domain = _get_sender_domain(parsed_email)
    if domain is None:
        return None

    if any(label.startswith("xn--") for label in domain.split(".")):
        return {
            "code": "PUNYCODE_DOMAIN",
            "message": (
                f"Sender domain {domain} contains an xn-- prefix used for Punycode. "
                "Review for visual confusion; legitimate international domains use it too."
            ),
            "evidence_path": "message.from_.address",
            "weight": PUNYCODE_DOMAIN_SCORE,
        }
    return None


def check_display_name_domain_mismatch(parsed_email):
    message = getattr(parsed_email, "message", None)
    sender = getattr(message, "from_", None)
    display_name = getattr(sender, "name", None)

    from_domain = _get_sender_domain(parsed_email)

    if not isinstance(display_name, str) or not display_name or from_domain is None:
        return None

    # Only compare when the display name itself contains an email address.
    if "@" not in display_name:
        return None

    display_domain = _get_domain(display_name)

    if display_domain is None:
        return None

    if display_domain != from_domain:
        return {
            "code": "DISPLAY_NAME_DOMAIN_MISMATCH",
            "message": "Display-name domain differs from sender domain",
            "evidence_path": "message.from_",
            "weight": DISPLAY_NAME_DOMAIN_MISMATCH_SCORE
        }

    return None


def check_return_path_anomaly(parsed_email):
    """
    Checks for anomalies in Return-Path (envelope sender):
    1. Unqualified/internal hostname without a public domain (e.g. localhost, droplet/VPS hostnames).
    2. Envelope domain mismatching visible From domain where SPF is not authenticated.
    """
    message = getattr(parsed_email, "message", None)
    return_path = getattr(message, "return_path", None)
    if not isinstance(return_path, str) or not return_path.strip():
        return None

    raw_addr = return_path.strip()
    if "<" in raw_addr and ">" in raw_addr:
        raw_addr = raw_addr.split("<", 1)[1].split(">", 1)[0].strip()

    if "@" not in raw_addr:
        return None

    local_part, host = raw_addr.rsplit("@", 1)
    host = host.lower().strip()
    if not host:
        return None

    # Check 1: Host has no dot (unqualified local machine name, e.g. droplet/VPS) or internal TLD
    is_unqualified = ("." not in host) or host.endswith(".internal") or host.endswith(".local") or host.endswith(".localdomain")
    if is_unqualified:
        return {
            "code": "RETURN_PATH_ANOMALY",
            "message": (
                f"Return-Path contains an unqualified or internal server hostname '{host}' lacking a public domain. "
                "Legitimate internet email requires a fully qualified domain."
            ),
            "evidence_path": "message.return_path",
            "weight": RETURN_PATH_ANOMALY_SCORE,
        }

    # Check 2: Domain mismatch with visible From domain when not a recognized test or trusted domain
    from_domain = _get_sender_domain(parsed_email)
    if from_domain and not host.endswith(".example") and not host.endswith(".test"):
        if host != from_domain and not host.endswith("." + from_domain):
            # Check if SPF authenticated this sender
            spf_auth = getattr(getattr(parsed_email, "authentication", None), "spf", None)
            spf_res = getattr(spf_auth, "result", "")
            if spf_res != "pass":
                return {
                    "code": "RETURN_PATH_ANOMALY",
                    "message": (
                        f"Return-Path domain '{host}' does not match visible sender domain '{from_domain}', "
                        "and envelope is not validated by SPF pass."
                    ),
                    "evidence_path": "message.return_path",
                    "weight": RETURN_PATH_ANOMALY_SCORE,
                }

    return None

