import pytest

from backend.parser.models import ParsedEmail, URLMetadata, AttachmentMetadata
from backend.detection.rules import urls_attachments as rules


def make_url(host="portal.example", path="/login"):
    return URLMetadata(raw=f"https://{host}{path}", scheme="https", host=host, path=path)


@pytest.mark.parametrize("path, text", [
    ("/login", "Enter your password."),
    ("/account/LOGIN", "Please send your OTP."),
    ("/verify", "Upload your passport."),
    ("/update", "Provide your bank account details."),
    ("/payment", "Please pay the invoice when convenient."),
])
@pytest.mark.parametrize("field", ["subject", "body_text"])
def test_path_with_relevant_request(path, text, field):
    email = ParsedEmail()
    email.message.urls = [make_url(path=path)]
    setattr(email.message, field, text)
    result = rules.check_suspicious_url_path(email)
    assert result["code"] == "SUSPICIOUS_URL_PATH"
    assert result["weight"] == 10
    assert result["evidence_path"] == "message.urls[0].path"
    assert f"message.{field}" in result["message"]
    assert rules.check_suspicious_url_path(email) == result


@pytest.mark.parametrize("path, text", [
    ("/login", "Welcome to our website."),
    ("/login", "Never share your OTP."),
    ("/login", "Pay the invoice immediately."),
    ("/payment", "Enter your password."),
    ("/login-help", "Enter your password."),
    ("/logins", "Enter your password."),
    ("/news", "Enter your password."),
    ("/search?q=/login", "Enter your password."),
    (None, "Enter your password."),
    (123, "Enter your password."),
    ("login", "Enter your password."),
])
def test_path_near_misses(path, text):
    email = ParsedEmail()
    email.message.urls = [make_url(path=path)]
    email.message.body_text = text
    assert rules.check_suspicious_url_path(email) is None


@pytest.mark.parametrize("host", ["bit.ly", "BIT.LY", "bit.ly.", "tinyurl.com", "t.co"])
def test_shortener_exact_host(host):
    email = ParsedEmail()
    email.message.urls = [make_url(host=host)]
    result = rules.check_shortened_url(email)
    assert result["code"] == "SHORTENED_URL"
    assert result["weight"] == 5
    assert result["evidence_path"] == "message.urls[0].host"
    assert rules.check_shortened_url(email) == result


@pytest.mark.parametrize("host", ["bit.ly.attacker.example", "fakebit.ly", "sub.bit.ly", "portal.example", None, 123, "bit..ly", "bit.ly..", "bit.ly/path"])
def test_shortener_near_misses(host):
    email = ParsedEmail()
    email.message.urls = [make_url(host=host)]
    assert rules.check_shortened_url(email) is None


@pytest.mark.parametrize("field, value", [("scheme", None), ("scheme", "ftp"), ("scheme", []), ("parse_status", "unparsed"), ("host", None)])
def test_unusable_url_metadata_is_skipped(field, value):
    email = ParsedEmail()
    url = make_url(host="bit.ly")
    setattr(url, field, value)
    email.message.urls = [url]
    email.message.body_text = "Enter your password."
    assert rules.check_shortened_url(email) is None
    assert rules.check_suspicious_url_path(email) is None


@pytest.mark.parametrize("filename, content_type, evidence", [
    ("invoice.pdf.exe", "application/pdf", "filename"),
    ("INVOICE.EXE", None, "filename"),
    ("script.ps1", None, "filename"),
    (None, "application/x-msdownload", "content_type"),
    ("invoice.pdf", "APPLICATION/X-EXECUTABLE", "content_type"),
])
def test_risky_attachment(filename, content_type, evidence):
    email = ParsedEmail()
    email.message.attachments = [AttachmentMetadata(filename=filename, content_type=content_type)]
    result = rules.check_suspicious_attachment(email)
    assert result["code"] == "SUSPICIOUS_ATTACHMENT"
    assert result["weight"] == 12
    assert result["evidence_path"] == f"message.attachments[0].{evidence}"
    assert "not proof of malware" in result["message"]
    assert rules.check_suspicious_attachment(email) == result


@pytest.mark.parametrize("filename, content_type", [
    ("invoice.pdf", "application/pdf"), ("invoice.exe.pdf", "application/pdf"),
    ("photo.jpg", "image/jpeg"), (None, None), (123, []),
    ("archive.zip", "application/zip"), ("file", "application/octet-stream"),
])
def test_attachment_near_misses(filename, content_type):
    email = ParsedEmail()
    email.message.attachments = [AttachmentMetadata(filename=filename, content_type=content_type)]
    assert rules.check_suspicious_attachment(email) is None


@pytest.mark.parametrize("status, triggers", [("parsed", True), ("partial", True), ("unparsed", False)])
def test_attachment_parse_status(status, triggers):
    email = ParsedEmail()
    email.message.attachments = [AttachmentMetadata(filename="file.exe", parse_status=status)]
    assert (rules.check_suspicious_attachment(email) is not None) == triggers


@pytest.mark.parametrize("rule, field", [
    (rules.check_shortened_url, "urls"), (rules.check_suspicious_url_path, "urls"),
    (rules.check_suspicious_attachment, "attachments"),
])
@pytest.mark.parametrize("value", [None, [], 123, "raw text", {}, [None, {}, "raw text"]])
def test_missing_or_broken_collections(rule, field, value):
    email = ParsedEmail()
    setattr(email.message, field, value)
    assert rule(email) is None
    email.message = None
    assert rule(email) is None
    assert rule(None) is None


def test_first_matching_index_and_no_repeated_points():
    email = ParsedEmail()
    email.message.body_text = "Enter your password."
    email.message.urls = [make_url(path="/news"), make_url("bit.ly"), make_url("bit.ly")]
    email.message.attachments = [None, AttachmentMetadata(filename="file.exe"), AttachmentMetadata(filename="second.exe")]
    for rule, field, weight in [
        (rules.check_shortened_url, "urls[1].host", 5),
        (rules.check_suspicious_url_path, "urls[1].path", 10),
        (rules.check_suspicious_attachment, "attachments[1].filename", 12),
    ]:
        result = rule(email)
        assert isinstance(result, dict)
        assert result["weight"] == weight
        assert result["evidence_path"] == f"message.{field}"


def test_configurable_lists(monkeypatch):
    email = ParsedEmail()
    email.message.urls = [make_url("short.example", "/signin")]
    email.message.body_text = "Enter your password."
    email.message.attachments = [AttachmentMetadata(filename="sample.demo")]
    monkeypatch.setattr(rules, "URL_SHORTENER_HOSTS", ("short.example",))
    monkeypatch.setattr(rules, "URL_PATH_REQUEST_TYPES", {"signin": ("credential",)})
    monkeypatch.setattr(rules, "RISKY_ATTACHMENT_EXTENSIONS", (".demo",))
    assert rules.check_shortened_url(email)
    assert rules.check_suspicious_url_path(email)
    assert rules.check_suspicious_attachment(email)
