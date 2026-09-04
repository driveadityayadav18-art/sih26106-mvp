from backend.parser.models import (
    Artifact,
    Authentication,
    Message,
    ParsedEmail,
    Trace,
)


def test_parsed_email_default_structure():
    parsed = ParsedEmail()

    assert isinstance(parsed.message, Message)
    assert isinstance(parsed.authentication, Authentication)
    assert isinstance(parsed.trace, Trace)

    assert parsed.warnings == []
    assert parsed.message.to == []
    assert parsed.message.cc == []
    assert parsed.message.urls == []
    assert parsed.message.attachments == []


def test_artifact_values():
    artifact = Artifact(
        sha256="abc123",
        byte_length=100,
    )

    assert artifact.sha256 == "abc123"
    assert artifact.byte_length == 100