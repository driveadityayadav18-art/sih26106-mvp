from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class EmailAddress:
    name: Optional[str] = None
    address: Optional[str] = None
    raw: Optional[str] = None
    malformed: bool = False


@dataclass
class URLMetadata:
    raw: str
    scheme: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None
    query_present: bool = False
    is_https: bool = False
    parse_status: str = "parsed"


@dataclass
class AttachmentMetadata:
    filename: Optional[str] = None
    content_type: Optional[str] = None
    size_bytes: int = 0
    sha256: Optional[str] = None
    is_inline: bool = False
    parse_status: str = "parsed"


@dataclass
class AuthenticationResult:
    result: str = "unknown"
    source: str = "unknown"
    timestamp: Optional[str] = None


@dataclass
class DMARCResult(AuthenticationResult):
    aligned: Optional[bool] = None
    header_from_domain: Optional[str] = None


@dataclass
class Authentication:
    spf: AuthenticationResult = field(default_factory=AuthenticationResult)
    dkim: AuthenticationResult = field(default_factory=AuthenticationResult)
    dmarc: DMARCResult = field(default_factory=DMARCResult)
    raw_authentication_headers: List[str] = field(default_factory=list)


@dataclass
class ReceivedHop:
    index: int
    raw: str
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    by_ip: Optional[str] = None
    with_protocol: Optional[str] = None
    timestamp: Optional[str] = None
    parse_status: str = "unparsed"
    trust: str = "unknown"


@dataclass
class Trace:
    hops: List[ReceivedHop] = field(default_factory=list)
    earliest_reliable_observable: Optional[str] = None
    limitations: List[str] = field(default_factory=list)


@dataclass
class Warning:
    code: str
    message: str


@dataclass
class Artifact:
    sha256: str
    byte_length: int


@dataclass
class Message:
    subject: Optional[str] = None

    # "from" is a reserved Python keyword,
    # so we use from_ internally.
    from_: EmailAddress = field(default_factory=EmailAddress)

    to: List[EmailAddress] = field(default_factory=list)
    cc: List[EmailAddress] = field(default_factory=list)

    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    message_id: Optional[str] = None
    date: Optional[str] = None

    body_text: Optional[str] = None
    body_html_present: bool = False

    urls: List[URLMetadata] = field(default_factory=list)
    attachments: List[AttachmentMetadata] = field(default_factory=list)


@dataclass
class ParsedEmail:
    message: Message = field(default_factory=Message)
    authentication: Authentication = field(
        default_factory=Authentication
    )
    trace: Trace = field(default_factory=Trace)
    warnings: List[Warning] = field(default_factory=list)
    artifact: Artifact = field(
        default_factory=lambda: Artifact(
            sha256="",
            byte_length=0
        )
    )