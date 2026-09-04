from backend.parser.email_parser import EmailParser


def test_parser_hashes_original_bytes():
    raw_email = (
        b"From: test@example.test\r\n"
        b"Subject: Test\r\n"
        b"\r\n"
        b"Hello"
    )

    parser = EmailParser()
    result = parser.parse(raw_email)

    assert result.artifact.byte_length == len(raw_email)
    assert result.artifact.sha256 != ""