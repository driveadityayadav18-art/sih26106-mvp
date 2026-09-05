from ..config import (
    REPLY_TO_MISMATCH_SCORE,
    DISPLAY_NAME_DOMAIN_MISMATCH_SCORE,
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

    return domain.lower()


def check_reply_to_mismatch(parsed_email):
    from_address = parsed_email.message.from_.address
    reply_to = parsed_email.message.reply_to

    from_domain = _get_domain(from_address)
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


def check_display_name_domain_mismatch(parsed_email):
    display_name = parsed_email.message.from_.name
    from_address = parsed_email.message.from_.address

    from_domain = _get_domain(from_address)

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
