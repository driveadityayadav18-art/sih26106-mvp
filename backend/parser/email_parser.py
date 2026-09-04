from email import policy
from email.parser import BytesParser

from .models import ParsedEmail
from ..evidence.hashing import calculate_sha256, get_byte_length


class EmailParser:
    """
    Parser for extracting observable and normalized evidence
    from raw .eml email bytes.
    """

    def parse(self, raw_bytes: bytes) -> ParsedEmail:
        """
        Parse raw email bytes and return a normalized ParsedEmail object.
        """

        message = BytesParser(
            policy=policy.default
        ).parsebytes(raw_bytes)

        parsed_email = ParsedEmail()

        # Artifact information comes directly from the original bytes.
        parsed_email.artifact.sha256 = calculate_sha256(raw_bytes)
        parsed_email.artifact.byte_length = get_byte_length(raw_bytes)

        return parsed_email