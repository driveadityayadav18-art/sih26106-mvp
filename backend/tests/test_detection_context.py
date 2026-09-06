import pytest

from backend.detection.context import DetectionContext, ReusedIndicator
from backend.detection.rules.context import check_reused_indicator
from backend.parser.models import ParsedEmail, URLMetadata, AttachmentMetadata


def reuse(kind="domain", value="company.example", cases=None, source="local_case_store"):
    return ReusedIndicator(kind, value, ["CASE-OLD"] if cases is None else cases, source)


def sample_email():
    email = ParsedEmail()
    email.message.from_.address = "sender@company.example"
    email.message.reply_to = "reply@other.example"
    email.message.urls = [URLMetadata(
        raw="https://portal.example/Login?token=private", scheme="https",
        host="portal.example", path="/Login",
    )]
    email.message.attachments = [AttachmentMetadata(filename="file.pdf", sha256="a" * 64)]
    return email


@pytest.mark.parametrize("kind, value, path", [
    ("domain", "COMPANY.EXAMPLE.", "message.from_.address"),
    ("domain", "other.example", "message.reply_to"),
    ("domain", "portal.example", "message.urls[0].host"),
    ("url", "https://portal.example/Login?token=private", "message.urls[0].raw"),
    ("attachment_sha256", "A" * 64, "message.attachments[0].sha256"),
])
def test_reuse_matches_current_evidence(kind, value, path):
    email = sample_email()
    context = DetectionContext([reuse(kind, value)], "CASE-CURRENT")
    result = check_reused_indicator(email, context)
    assert result["code"] == "REUSED_INDICATOR"
    assert result["weight"] == 15
    assert result["evidence_path"] == path
    assert "context.reused_indicators[0]" in result["message"]
    assert "private" not in result["message"]
    assert "legitimate" in result["message"]
    assert check_reused_indicator(email, context) == result


@pytest.mark.parametrize("kind, value", [
    ("domain", "unrelated.example"), ("domain", "mail.company.example"),
    ("domain", "company.example.attacker.test"),
    ("url", "https://portal.example/login?token=private"),
    ("url", "https://portal.example/Login?token=different"),
    ("attachment_sha256", "b" * 64), ("attachment_sha256", "a" * 63),
    ("ip", "192.0.2.1"), (None, "company.example"), ([], "company.example"),
    ("domain", None), ("domain", 123), ("domain", ""),
])
def test_reuse_near_misses(kind, value):
    assert check_reused_indicator(sample_email(), DetectionContext([reuse(kind, value)])) is None


@pytest.mark.parametrize("cases", [[], [""], [None, 123], "CASE-OLD", ["CASE-CURRENT"]])
def test_prior_case_is_required(cases):
    context = DetectionContext([reuse(cases=cases)], "CASE-CURRENT")
    assert check_reused_indicator(sample_email(), context) is None


@pytest.mark.parametrize("source", ["", " ", None, 123])
def test_source_is_required(source):
    assert check_reused_indicator(sample_email(), DetectionContext([reuse(source=source)])) is None


@pytest.mark.parametrize("context", [None, {}, 123, DetectionContext(), DetectionContext(None), DetectionContext([None, {}, "raw"])])
def test_no_usable_context_means_no_reason(context):
    assert check_reused_indicator(sample_email(), context) is None


def test_no_current_evidence_means_no_reason():
    context = DetectionContext([reuse()])
    assert check_reused_indicator(ParsedEmail(), context) is None
    assert check_reused_indicator(None, context) is None
    email = sample_email()
    email.message.from_.malformed = True
    assert check_reused_indicator(email, context) is None
    email.message = None
    assert check_reused_indicator(email, context) is None


def test_multiple_matches_add_only_one_weight_and_exclude_self():
    observation = reuse(cases=["CASE-CURRENT", "CASE-OLD", "CASE-OLD"])
    context = DetectionContext([observation, observation], "CASE-CURRENT")
    result = check_reused_indicator(sample_email(), context)
    assert result["weight"] == 15
    assert "1 other case(s)" in result["message"]


def test_skip_invalid_entry_and_preserve_context_index():
    context = DetectionContext([None, reuse()])
    result = check_reused_indicator(sample_email(), context)
    assert "context.reused_indicators[1]" in result["message"]


def test_dataclass_lists_are_not_shared():
    first, second = DetectionContext(), DetectionContext()
    first.reused_indicators.append(reuse())
    assert second.reused_indicators == []


def test_broken_url_and_attachment_metadata_do_not_supply_reuse_evidence():
    email = sample_email()
    email.message.urls[0].parse_status = "unparsed"
    email.message.attachments[0].sha256 = "not-a-hash"
    for observation in [reuse("domain", "portal.example"), reuse("attachment_sha256", "not-a-hash")]:
        assert check_reused_indicator(email, DetectionContext([observation])) is None
