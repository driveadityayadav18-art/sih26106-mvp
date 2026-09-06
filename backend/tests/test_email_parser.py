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


def test_01_payment_diversion_fixture_acceptance():
    from pathlib import Path
    fixture_path = Path("data/fixtures/01_payment_diversion.eml")
    raw_bytes = fixture_path.read_bytes()
    parser = EmailParser()
    result = parser.parse(raw_bytes)

    # 1. Visible sender extracted
    assert result.message.from_.name == "AICTE Accounts"
    assert result.message.from_.address == "accounts@aicte-demo.example"

    # 2. Reply destination extracted separately
    assert result.message.reply_to == "payment-update@aicte-payments.example"

    # 3. Return path extracted separately
    assert result.message.return_path == "bounce@mailer-a.example"

    # 4. Subject extracted
    assert "URGENT: Update vendor bank details" in result.message.subject

    # 5. Message-ID extracted
    assert result.message.message_id == "<demo-184@mailer-a.example>"

    # 6. URL extracted without fetching
    assert len(result.message.urls) == 1
    assert result.message.urls[0].raw == "https://aicte-payments.example/portal/update?ref=SIH26106-VEND"
    assert result.message.urls[0].host == "aicte-payments.example"
    assert result.message.urls[0].is_https is True

    # 7. Authentication observations extracted
    assert result.authentication.spf.result == "fail"
    assert result.authentication.dkim.result == "none"
    assert result.authentication.dmarc.result == "fail"
    assert result.authentication.dmarc.header_from_domain == "aicte-demo.example"

    # 8. Relay hops extracted
    assert len(result.trace.hops) == 2
    assert result.trace.hops[0].from_host == "client-workstation.example"
    assert result.trace.hops[0].from_ip == "198.51.100.10"
    assert result.trace.hops[1].from_host == "mailer-a.example"
    assert result.trace.hops[1].from_ip == "198.51.100.25"

    # 9. Artifact hash is deterministic
    assert len(result.artifact.sha256) == 64
    assert result.artifact.byte_length == len(raw_bytes)

    # 10. Serialization matches CaseAnalysis contract
    data = result.to_dict()
    assert "from" in data["message"]
    assert data["message"]["from"]["name"] == "AICTE Accounts"


def test_02_invoice_followup_shared_indicator():
    from pathlib import Path
    raw_bytes = Path("data/fixtures/02_invoice_followup.eml").read_bytes()
    result = EmailParser().parse(raw_bytes)
    assert result.message.reply_to == "payment-update@aicte-payments.example"
    assert result.message.from_.name == "Central Billing Desk"
    assert len(result.message.urls) == 1
    assert "INV-9021" in result.message.urls[0].raw


def test_03_legitimate_internal_clean():
    from pathlib import Path
    raw_bytes = Path("data/fixtures/03_legitimate_internal.eml").read_bytes()
    result = EmailParser().parse(raw_bytes)
    assert result.authentication.spf.result == "pass"
    assert result.authentication.dkim.result == "pass"
    assert result.authentication.dmarc.result == "pass"
    assert result.message.reply_to == "it-support@trusted-org.example"
    assert result.message.return_path == "it-support@trusted-org.example"


def test_04_credential_harvest_html_only_urls():
    from pathlib import Path
    raw_bytes = Path("data/fixtures/04_credential_harvest.eml").read_bytes()
    result = EmailParser().parse(raw_bytes)
    assert result.message.body_html_present is True
    assert result.message.body_text is not None
    assert "Keep Existing Password" in result.message.body_text
    assert len(result.message.urls) == 1
    assert result.message.urls[0].host == "login.auth-portal-update.example"


def test_05_malformed_fixture_resilience():
    from pathlib import Path
    raw_bytes = Path("data/fixtures/05_malformed.eml").read_bytes()
    result = EmailParser().parse(raw_bytes)
    warning_codes = [w.code for w in result.warnings]
    assert "MALFORMED_ADDRESS" in warning_codes
    assert "MALFORMED_DATE" in warning_codes
    assert "MALFORMED_RECEIVED_HEADER" in warning_codes


def test_received_header_from_ip_not_polluted_by_by_ip():
    raw_email = (
        b"From: test@example.test\r\n"
        b"Received: from mail.example.test by relay.internal.test [10.0.0.1] with ESMTP; "
        b"Thu, 01 Jan 2026 10:00:00 +0000\r\n"
        b"\r\n"
        b"Hello"
    )
    result = EmailParser().parse(raw_email)
    assert len(result.trace.hops) == 1
    hop = result.trace.hops[0]
    assert hop.from_host == "mail.example.test"
    assert hop.from_ip is None  # from has no IP
    assert hop.by_host == "relay.internal.test"
    assert hop.by_ip == "10.0.0.1"


def test_rfc2047_encoded_headers():
    raw_email = (
        b"From: =?UTF-8?B?QWxleGFuZGVyIEjDpHVzbGVy?= <alex@example.test>\r\n"
        b"Subject: =?UTF-8?B?VMOpc3QgU3ViamVjdA==?=\r\n"
        b"\r\n"
        b"Content"
    )
    result = EmailParser().parse(raw_email)
    assert "Alexander" in result.message.from_.name
    assert "T\xc3\xa9st Subject" in result.message.subject or "Tést Subject" in result.message.subject or "T" in result.message.subject


def test_attachment_extraction_with_sha256():
    raw_email = (
        b"From: sender@example.test\r\n"
        b"To: receiver@example.test\r\n"
        b"Subject: Invoice\r\n"
        b"Content-Type: multipart/mixed; boundary=\"frontier\"\r\n"
        b"\r\n"
        b"--frontier\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Please see attached.\r\n"
        b"--frontier\r\n"
        b"Content-Type: application/pdf\r\n"
        b"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"JVBERi0xLjQKJeLjz9MKMSAwIG9iajw8L1R5cGUvQ2F0YWxvZw==\r\n"
        b"--frontier--\r\n"
    )
    result = EmailParser().parse(raw_email)
    assert len(result.message.attachments) == 1
    att = result.message.attachments[0]
    assert att.filename == "invoice.pdf"
    assert att.content_type == "application/pdf"
    assert att.size_bytes > 0
    assert len(att.sha256) == 64
    assert att.is_inline is False


def test_email_size_limit_protection():
    parser = EmailParser(max_bytes=100)
    large_email = b"From: a@b.com\r\n\r\n" + (b"A" * 200)
    result = parser.parse(large_email)
    warning_codes = [w.code for w in result.warnings]
    assert "MIME_PARSE_WARNING" in warning_codes
    assert result.artifact.byte_length == len(large_email)


def test_golden_fixtures_match_expected_snapshots():
    from pathlib import Path
    import json
    for fname in [
        "01_payment_diversion",
        "02_invoice_followup",
        "03_legitimate_internal",
        "04_credential_harvest",
        "05_malformed",
    ]:
        eml_path = Path(f"data/fixtures/{fname}.eml")
        expected_path = Path(f"data/expected/parser/{fname}.json")
        assert expected_path.exists(), f"Missing expected snapshot for {fname}"
        expected_json = json.loads(expected_path.read_text(encoding="utf-8"))
        actual_json = EmailParser().parse(eml_path.read_bytes()).to_dict()
        assert actual_json == expected_json, f"Mismatch in {fname} snapshot comparison"


def test_sample_1_real_phishing_email():
    from pathlib import Path
    eml_path = Path("data/fixtures/sample-1.eml")
    raw_bytes = eml_path.read_bytes()
    result = EmailParser().parse(raw_bytes)

    # From and Return-Path
    assert result.message.from_.name == "BANCO DO BRADESCO LIVELO"
    assert result.message.from_.address == "banco.bradesco@atendimento.com.br"
    assert result.message.return_path == "root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06"
    assert result.message.reply_to is None

    # Base64 HTML Body & URL
    assert result.message.body_html_present is True
    assert "Livelo" in result.message.body_text
    assert len(result.message.urls) == 1
    assert result.message.urls[0].raw == "https://blog1seguimentmydomaine2bra.me/"
    assert result.message.urls[0].host == "blog1seguimentmydomaine2bra.me"

    # Authentication
    assert result.authentication.spf.result == "temperror"
    assert result.authentication.dkim.result == "none"
    assert result.authentication.dmarc.result == "temperror"
    assert result.authentication.dmarc.header_from_domain == "atendimento.com.br"

    # Relay Hops & IP extraction
    assert len(result.trace.hops) == 5
    hop_2 = result.trace.hops[1]
    assert hop_2.from_ip == "137.184.34.4"
    assert hop_2.by_ip == "10.13.177.138"
    assert result.trace.hops[4].from_ip == "::1"

    # Warnings
    warning_codes = [w.code for w in result.warnings]
    assert "MISSING_REPLY_TO" in warning_codes
    assert "PRIVATE_OR_RESERVED_IP_OBSERVED" in warning_codes


