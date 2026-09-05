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
    assert len(result.artifact.sha256) == 64


def test_basic_headers_are_extracted():
    raw_email = (
        b"From: John Doe <john@example.test>\r\n"
        b"To: Alice <alice@example.test>\r\n"
        b"Cc: Bob <bob@example.test>\r\n"
        b"Reply-To: reply@example.test\r\n"
        b"Return-Path: <return@example.test>\r\n"
        b"Subject: Important Test\r\n"
        b"Message-ID: <123@example.test>\r\n"
        b"Date: Tue, 01 Jan 2026 10:00:00 +0000\r\n"
        b"\r\n"
        b"Hello world"
    )

    result = EmailParser().parse(raw_email)

    assert result.message.from_.name == "John Doe"
    assert result.message.from_.address == "john@example.test"

    assert result.message.to[0].name == "Alice"
    assert result.message.to[0].address == "alice@example.test"

    assert result.message.cc[0].name == "Bob"
    assert result.message.cc[0].address == "bob@example.test"

    assert result.message.reply_to == "reply@example.test"
    assert result.message.return_path == "return@example.test"

    assert result.message.subject == "Important Test"
    assert result.message.message_id == "<123@example.test>"

    assert result.message.body_text == "Hello world"

def test_html_body_is_detected():
    raw_email = (
        b"From: test@example.test\r\n"
        b"Reply-To: reply@example.test\r\n"
        b"Return-Path: <return@example.test>\r\n"
        b"Subject: HTML Test\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html><body>Hello</body></html>"
    )

    result = EmailParser().parse(raw_email)

    assert result.message.body_html_present is True

def test_urls_are_extracted_without_fetching():
    raw_email = (
        b"From: test@example.test\r\n"
        b"Reply-To: reply@example.test\r\n"
        b"Return-Path: <return@example.test>\r\n"
        b"Subject: URL Test\r\n"
        b"\r\n"
        b"Visit https://example.test/update?id=123 today."
    )

    result = EmailParser().parse(raw_email)

    assert len(result.message.urls) == 1

    url = result.message.urls[0]

    assert url.raw == "https://example.test/update?id=123"
    assert url.scheme == "https"
    assert url.host == "example.test"
    assert url.path == "/update"
    assert url.query_present is True
    assert url.is_https is True
    assert url.parse_status == "parsed"

def test_authentication_results_are_extracted():
    raw_email = (
        b"From: sender@example.test\r\n"
        b"Reply-To: reply@example.test\r\n"
        b"Return-Path: <return@example.test>\r\n"
        b"Authentication-Results: example.test; "
        b"spf=pass smtp.mailfrom=sender@example.test; "
        b"dkim=pass header.d=example.test; "
        b"dmarc=pass header.from=example.test\r\n"
        b"\r\n"
        b"Hello"
    )

    result = EmailParser().parse(raw_email)

    assert result.authentication.spf.result == "pass"
    assert result.authentication.spf.source == "header"

    assert result.authentication.dkim.result == "pass"
    assert result.authentication.dkim.source == "header"

    assert result.authentication.dmarc.result == "pass"
    assert result.authentication.dmarc.source == "header"

    assert (
        result.authentication.dmarc.header_from_domain
        == "example.test"
    )

    assert result.authentication.dmarc.aligned is None

def test_authentication_fail_results_are_extracted():
    raw_email = (
        b"From: sender@example.test\r\n"
        b"Reply-To: reply@example.test\r\n"
        b"Return-Path: <return@example.test>\r\n"
        b"Authentication-Results: example.test; "
        b"spf=fail; "
        b"dkim=fail; "
        b"dmarc=fail header.from=example.test\r\n"
        b"\r\n"
        b"Hello"
    )

    result = EmailParser().parse(raw_email)

    assert result.authentication.spf.result == "fail"
    assert result.authentication.dkim.result == "fail"
    assert result.authentication.dmarc.result == "fail"

def test_missing_authentication_results_are_reported():
    raw_email = (
        b"From: sender@example.test\r\n"
        b"Reply-To: reply@example.test\r\n"
        b"Return-Path: <return@example.test>\r\n"
        b"Subject: No Auth\r\n"
        b"\r\n"
        b"Hello"
    )

    result = EmailParser().parse(raw_email)

    assert result.authentication.spf.result == "unknown"
    assert result.authentication.spf.source == "missing"

    assert result.authentication.dkim.result == "unknown"
    assert result.authentication.dkim.source == "missing"

    assert result.authentication.dmarc.result == "unknown"
    assert result.authentication.dmarc.source == "missing"

    warning_codes = [
        warning.code
        for warning in result.warnings
    ]

    assert "MISSING_AUTHENTICATION_RESULTS" in warning_codes

def test_received_spf_is_extracted():
    raw_email = (
        b"From: sender@example.test\r\n"
        b"Reply-To: reply@example.test\r\n"
        b"Return-Path: <return@example.test>\r\n"
        b"Received-SPF: fail "
        b"(example.test: domain of sender@example.test "
        b"does not designate permitted sender)\r\n"
        b"\r\n"
        b"Hello"
    )

    result = EmailParser().parse(raw_email)

    assert result.authentication.spf.result == "fail"
    assert result.authentication.spf.source == "header"

def test_received_headers_are_extracted():
    raw_email = (
        b"From: sender@example.test\r\n"
        b"Reply-To: reply@example.test\r\n"
        b"Return-Path: <return@example.test>\r\n"
        b"Received: from mail2.example.test "
        b"(mail2.example.test [203.0.113.20]) "
        b"by mx.example.test with ESMTPS; "
        b"Thu, 01 Jan 2026 10:02:00 +0000\r\n"
        b"Received: from mail1.example.test "
        b"(mail1.example.test [203.0.113.10]) "
        b"by mail2.example.test with SMTP; "
        b"Thu, 01 Jan 2026 10:01:00 +0000\r\n"
        b"\r\n"
        b"Hello"
    )

    result = EmailParser().parse(raw_email)

    assert len(result.trace.hops) == 2

    first_hop = result.trace.hops[0]

    assert first_hop.index == 1
    assert first_hop.from_host == "mail1.example.test"
    assert first_hop.from_ip == "203.0.113.10"
    assert first_hop.by_host == "mail2.example.test"
    assert first_hop.with_protocol == "SMTP"
    assert first_hop.timestamp is not None
    assert first_hop.parse_status == "parsed"

    assert result.trace.earliest_reliable_observable == (
        "Received hop 1"
    )

def test_private_ip_in_received_header_adds_warning():
    raw_email = (
        b"From: sender@example.test\r\n"
        b"Reply-To: reply@example.test\r\n"
        b"Return-Path: <return@example.test>\r\n"
        b"Received: from internal.example.test "
        b"(internal.example.test [192.168.1.10]) "
        b"by mx.example.test with SMTP; "
        b"Thu, 01 Jan 2026 10:00:00 +0000\r\n"
        b"\r\n"
        b"Hello"
    )

    result = EmailParser().parse(raw_email)

    warning_codes = [
        warning.code
        for warning in result.warnings
    ]

    assert (
        "PRIVATE_OR_RESERVED_IP_OBSERVED"
        in warning_codes
    )

def test_missing_received_headers_add_limitation():
    raw_email = (
        b"From: sender@example.test\r\n"
        b"Reply-To: reply@example.test\r\n"
        b"Return-Path: <return@example.test>\r\n"
        b"Subject: No Received\r\n"
        b"\r\n"
        b"Hello"
    )

    result = EmailParser().parse(raw_email)

    assert result.trace.hops == []

    assert (
        "No Received headers were observed."
        in result.trace.limitations
    )

def test_malformed_received_header_adds_warning():
    raw_email = (
        b"From: sender@example.test\r\n"
        b"Reply-To: reply@example.test\r\n"
        b"Return-Path: <return@example.test>\r\n"
        b"Received: ;;;;;\r\n"
        b"\r\n"
        b"Hello"
    )

    result = EmailParser().parse(raw_email)

    warning_codes = [
        warning.code
        for warning in result.warnings
    ]

    assert (
        "MALFORMED_RECEIVED_HEADER"
        in warning_codes
    )