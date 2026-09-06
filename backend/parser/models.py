from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EmailAddress:
    name: Optional[str] = None
    address: Optional[str] = None
    raw: Optional[str] = None
    malformed: bool = False

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "name": self.name,
            "address": self.address,
        }


@dataclass
class URLMetadata:
    raw: str
    scheme: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None
    query_present: bool = False
    is_https: bool = False
    parse_status: str = "parsed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw": self.raw,
            "scheme": self.scheme,
            "host": self.host,
            "path": self.path,
            "query_present": self.query_present,
            "is_https": self.is_https,
            "parse_status": self.parse_status,
        }


@dataclass
class AttachmentMetadata:
    filename: Optional[str] = None
    content_type: Optional[str] = None
    size_bytes: int = 0
    sha256: Optional[str] = None
    is_inline: bool = False
    parse_status: str = "parsed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "is_inline": self.is_inline,
            "parse_status": self.parse_status,
        }


@dataclass
class AuthenticationResult:
    result: str = "unknown"
    source: str = "unknown"
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result": self.result,
            "source": self.source,
            "timestamp": self.timestamp,
        }


@dataclass
class DMARCResult(AuthenticationResult):
    aligned: Optional[bool] = None
    header_from_domain: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result": self.result,
            "aligned": self.aligned,
            "header_from_domain": self.header_from_domain,
            "source": self.source,
            "timestamp": self.timestamp,
        }


@dataclass
class Authentication:
    spf: AuthenticationResult = field(default_factory=AuthenticationResult)
    dkim: AuthenticationResult = field(default_factory=AuthenticationResult)
    dmarc: DMARCResult = field(default_factory=DMARCResult)
    raw_authentication_headers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spf": self.spf.to_dict(),
            "dkim": self.dkim.to_dict(),
            "dmarc": self.dmarc.to_dict(),
            "raw_authentication_headers": list(self.raw_authentication_headers),
        }


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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "raw": self.raw,
            "from_host": self.from_host,
            "from_ip": self.from_ip,
            "by_host": self.by_host,
            "by_ip": self.by_ip,
            "with_protocol": self.with_protocol,
            "timestamp": self.timestamp,
            "parse_status": self.parse_status,
            "trust": self.trust,
        }


@dataclass
class Trace:
    hops: List[ReceivedHop] = field(default_factory=list)
    earliest_reliable_observable: Optional[str] = None
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hops": [hop.to_dict() for hop in self.hops],
            "earliest_reliable_observable": self.earliest_reliable_observable,
            "limitations": list(self.limitations),
        }


@dataclass
class Warning:
    code: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "message": self.message,
        }


@dataclass
class Artifact:
    sha256: str
    byte_length: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sha256": self.sha256,
            "byte_length": self.byte_length,
        }


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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "from": self.from_.to_dict(),
            "to": [addr.to_dict() for addr in self.to],
            "cc": [addr.to_dict() for addr in self.cc],
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "message_id": self.message_id,
            "date": self.date,
            "body_text": self.body_text,
            "body_html_present": self.body_html_present,
            "urls": [url.to_dict() for url in self.urls],
            "attachments": [att.to_dict() for att in self.attachments],
        }


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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message": self.message.to_dict(),
            "authentication": self.authentication.to_dict(),
            "trace": self.trace.to_dict(),
            "warnings": [w.to_dict() for w in self.warnings],
            "artifact": self.artifact.to_dict(),
        }