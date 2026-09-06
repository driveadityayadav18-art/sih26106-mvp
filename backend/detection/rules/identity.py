from ..config import (
    REPLY_TO_MISMATCH_SCORE,
    DISPLAY_NAME_DOMAIN_MISMATCH_SCORE,
    LOOKALIKE_DOMAIN_SCORE,
    PUNYCODE_DOMAIN_SCORE,
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
