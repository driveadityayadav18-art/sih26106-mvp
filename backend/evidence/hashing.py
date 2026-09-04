import hashlib


def calculate_sha256(raw_bytes: bytes) -> str:
    """
    Calculate SHA-256 hash from the original raw email bytes.
    """
    return hashlib.sha256(raw_bytes).hexdigest()


def get_byte_length(raw_bytes: bytes) -> int:
    """
    Return the size of the original raw email in bytes.
    """
    return len(raw_bytes)