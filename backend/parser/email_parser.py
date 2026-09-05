import re
import ipaddress
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .models import (
    AttachmentMetadata,
    AuthenticationResult,
    DMARCResult,
    EmailAddress,
    ParsedEmail,
    ReceivedHop,
    URLMetadata,
    Warning,
)
from ..evidence.hashing import calculate_sha256, get_byte_length


class _SafeHTMLTextExtractor(HTMLParser):
    """
    Safely extract readable text and href links from HTML markup.
    Never executes JavaScript, renders CSS, or fetches resources.
    """

    def __init__(self):
        super().__init__()
        self.text_chunks = []
        self.extracted_urls = []

    def handle_data(self, data):
        cleaned = data.strip()
        if cleaned:
            self.text_chunks.append(cleaned)

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for attr_name, attr_val in attrs:
                if attr_name.lower() == "href" and attr_val:
                    self.extracted_urls.append(attr_val.strip())

    def get_text(self) -> str:
        return " ".join(self.text_chunks)


class EmailParser:
    """
    Parser for extracting observable and normalized evidence
    from raw .eml email bytes.

    The parser never:
    - executes attachments
    - fetches URLs
    - makes network calls
    """

    def __init__(self, max_bytes: int = 10 * 1024 * 1024):
        self.max_bytes = max_bytes

    def parse(self, raw_bytes: bytes) -> ParsedEmail:
        """
        Parse raw email bytes and return normalized evidence.
        """

        result = ParsedEmail()

        # Hash and size are calculated from the original bytes.
        result.artifact.sha256 = calculate_sha256(raw_bytes)
        result.artifact.byte_length = get_byte_length(raw_bytes)

        # Protect against excessively large input.
        if len(raw_bytes) > self.max_bytes:
            result.warnings.append(
                Warning(
                    code="MIME_PARSE_WARNING",
                    message=(
                        f"Email exceeds the configured size limit "
                        f"of {self.max_bytes} bytes."
                    ),
                )
            )
            return result

        try:
            message = BytesParser(
                policy=policy.default
            ).parsebytes(raw_bytes)

        except Exception:
            result.warnings.append(
                Warning(
                    code="MIME_PARSE_WARNING",
                    message="Email MIME parsing failed.",
                )
            )
            return result

        self._parse_basic_headers(message, result)
        self._parse_authentication(message, result)
        self._parse_received_headers(message, result)
        self._parse_body_and_attachments(message, result)
        self._extract_urls(result)

        return result

    # =========================================================
    # HEADER PARSING
    # =========================================================

    def _parse_basic_headers(
        self,
        message,
        result: ParsedEmail,
    ):
        """
        Extract From, To, Cc, Reply-To, Return-Path,
        Subject, Message-ID and Date.
        """

        # -----------------------------------------------------
        # From
        # -----------------------------------------------------

        from_values = message.get_all("From", [])

        if not from_values:
            result.warnings.append(
                Warning(
                    code="MISSING_FROM",
                    message="From header is missing.",
                )
            )

        else:
            addresses = self._parse_addresses(
                from_values,
                result,
            )

            if addresses:
                result.message.from_ = addresses[0]

        # -----------------------------------------------------
        # To
        # -----------------------------------------------------

        to_values = message.get_all("To", [])

        result.message.to = self._parse_addresses(
            to_values,
            result,
        )

        # -----------------------------------------------------
        # Cc
        # -----------------------------------------------------

        cc_values = message.get_all("Cc", [])

        result.message.cc = self._parse_addresses(
            cc_values,
            result,
        )

        # -----------------------------------------------------
        # Reply-To
        # -----------------------------------------------------

        reply_to = message.get("Reply-To")

        if reply_to is None:
            result.warnings.append(
                Warning(
                    code="MISSING_REPLY_TO",
                    message="Reply-To header is missing.",
                )
            )

        else:
            reply_addresses = self._parse_addresses(
                [reply_to],
                result,
            )

            if reply_addresses:
                result.message.reply_to = (
                    reply_addresses[0].address
                )

        # -----------------------------------------------------
        # Return-Path
        # -----------------------------------------------------

        return_path = message.get("Return-Path")

        if return_path is None:
            result.warnings.append(
                Warning(
                    code="MISSING_RETURN_PATH",
                    message="Return-Path header is missing.",
                )
            )

        else:
            return_addresses = self._parse_addresses(
                [return_path],
                result,
            )

            if return_addresses:
                result.message.return_path = (
                    return_addresses[0].address
                )

        # -----------------------------------------------------
        # Subject
        # -----------------------------------------------------

        subject = message.get("Subject")

        if subject is not None:
            decoded_subject, warning = self._decode_header(
                subject
            )

            result.message.subject = decoded_subject

            if warning:
                result.warnings.append(warning)

        # -----------------------------------------------------
        # Message-ID
        # -----------------------------------------------------

        message_id = message.get("Message-ID")

        if message_id is None:
            result.warnings.append(
                Warning(
                    code="MISSING_MESSAGE_ID",
                    message="Message-ID header is missing.",
                )
            )

        else:
            result.message.message_id = message_id.strip()

        # -----------------------------------------------------
        # Date
        # -----------------------------------------------------

        date_value = message.get("Date")

        if date_value is not None:
            try:
                parsed_date = parsedate_to_datetime(
                    date_value
                )

                result.message.date = parsed_date.isoformat()

            except (TypeError, ValueError, IndexError):
                result.message.date = date_value.strip()

                result.warnings.append(
                    Warning(
                        code="MALFORMED_DATE",
                        message=(
                            "Date header could not be "
                            "parsed reliably."
                        ),
                    )
                )

    # =========================================================
    # AUTHENTICATION RESULT PARSING
    # =========================================================

    def _parse_authentication(
        self,
        message,
        result: ParsedEmail,
    ):
        """
        Extract observed SPF, DKIM and DMARC results from
        Authentication-Results and Received-SPF headers.

        This does not verify authentication independently.
        """

        auth_headers = message.get_all(
            "Authentication-Results",
            []
        )

        received_spf_headers = message.get_all(
            "Received-SPF",
            []
        )

        dkim_sig_headers = message.get_all(
            "DKIM-Signature",
            []
        )

        # Preserve raw authentication headers including DKIM signatures
        result.authentication.raw_authentication_headers = (
            auth_headers + received_spf_headers + [f"DKIM-Signature: {sig}" for sig in dkim_sig_headers]
        )

        if not auth_headers and not received_spf_headers:
            result.warnings.append(
                Warning(
                    code="MISSING_AUTHENTICATION_RESULTS",
                    message=(
                        "No Authentication-Results or "
                        "Received-SPF header was observed."
                    ),
                )
            )

            result.authentication.spf.source = "missing"
            result.authentication.dkim.source = "missing"
            result.authentication.dmarc.source = "missing"

            return

        # -----------------------------------------------------
        # Authentication-Results
        # -----------------------------------------------------

        for header in auth_headers:

            header_lower = header.lower()

            # SPF
            spf_match = re.search(
                r"\bspf\s*=\s*"
                r"(pass|fail|softfail|neutral|none|"
                r"temperror|permerror)\b",
                header_lower,
            )

            if spf_match:
                result.authentication.spf = (
                    AuthenticationResult(
                        result=spf_match.group(1),
                        source="header",
                    )
                )

            # DKIM
            dkim_match = re.search(
                r"\bdkim\s*=\s*"
                r"(pass|fail|none|neutral|temperror|permerror)\b",
                header_lower,
            )

            if dkim_match:
                result.authentication.dkim = (
                    AuthenticationResult(
                        result=dkim_match.group(1),
                        source="header",
                    )
                )

            # DMARC
            dmarc_match = re.search(
                r"\bdmarc\s*=\s*"
                r"(pass|fail|bestguesspass|none|"
                r"temperror|permerror)\b",
                header_lower,
            )

            if dmarc_match:

                header_from_match = re.search(
                    r"\bheader\.from\s*=\s*([^\s;]+)",
                    header_lower,
                )

                header_from_domain = None

                if header_from_match:
                    header_from_domain = (
                        header_from_match.group(1)
                    )

                # Check if alignment was explicitly observed
                aligned = None
                if re.search(r"\b(aligned=yes|alignment=pass|aspf=pass|adkim=pass)\b", header_lower):
                    aligned = True
                elif re.search(r"\b(aligned=no|alignment=fail|aspf=fail|adkim=fail)\b", header_lower):
                    aligned = False

                result.authentication.dmarc = (
                    DMARCResult(
                        result=dmarc_match.group(1),
                        source="header",
                        header_from_domain=(
                            header_from_domain
                        ),
                        aligned=aligned,
                    )
                )

        # -----------------------------------------------------
        # Received-SPF
        # -----------------------------------------------------

        for header in received_spf_headers:

            spf_match = re.search(
                r"^\s*(pass|fail|softfail|neutral|none|"
                r"temperror|permerror)\b",
                header,
                re.IGNORECASE,
            )

            if spf_match:
                # Authentication-Results SPF takes precedence
                # when both are present.
                if result.authentication.spf.source != "header":
                    result.authentication.spf = (
                        AuthenticationResult(
                            result=spf_match.group(1).lower(),
                            source="header",
                        )
                    )

    # =========================================================
    # RECEIVED HEADER / RELAY HOP PARSING
    # =========================================================

    def _parse_received_headers(
        self,
        message,
        result: ParsedEmail,
    ):
        """
        Extract observable relay hops from Received headers.

        Received headers are treated as observations from the
        raw message. They are not independently verified.
        """

        received_headers = message.get_all(
            "Received",
            []
        )

        if not received_headers:
            result.trace.limitations.append(
                "No Received headers were observed."
            )
            return

        # Received headers are normally stored newest first.
        # Reverse them so hop index 1 represents the earliest
        # header in the observable chain.
        received_headers = list(reversed(received_headers))

        for index, header in enumerate(
            received_headers,
            start=1,
        ):
            raw_header = str(header).strip()

            hop = self._parse_received_header(
                raw_header,
                index,
                result,
            )

            result.trace.hops.append(hop)

        # The earliest observable hop is the first successfully
        # parsed hop. This is only an observation from the header.
        for hop in result.trace.hops:
            if hop.parse_status == "parsed":
                result.trace.earliest_reliable_observable = (
                    f"Received hop {hop.index}"
                )
                break

        result.trace.limitations.append(
            "Received headers are observable message-header "
            "evidence and are not independently verified."
        )

    def _parse_received_header(
        self,
        raw_header: str,
        index: int,
        result: ParsedEmail,
    ) -> ReceivedHop:
        """
        Parse one Received header into observable fields.
        """

        hop = ReceivedHop(
            index=index,
            raw=raw_header,
            parse_status="unparsed",
            trust="unknown",
        )

        try:
            # Locate by_match and from_match
            by_match = re.search(
                r"\bby\s+([^\s(]+)",
                raw_header,
                re.IGNORECASE,
            )

            from_match = re.search(
                r"\bfrom\s+([^\s(]+)",
                raw_header,
                re.IGNORECASE,
            )

            # If by occurs before from, from is inside a comment/subclause (e.g. "by host (Postfix, from userid 0)")
            if by_match and from_match and by_match.start() < from_match.start():
                from_match = None

            if from_match:
                hop.from_host = from_match.group(1)

                # Bound from_ip search strictly to the section before "by" (if present)
                from_section_end = (
                    by_match.start()
                    if by_match and by_match.start() > from_match.start()
                    else len(raw_header)
                )
                from_section = raw_header[from_match.end():from_section_end]
                hop.from_ip = self._extract_ip_candidate(from_section)

            if by_match:
                hop.by_host = by_match.group(1)

                # Bound by_ip search to the section before "with" or ";"
                with_or_semi = re.search(
                    r"(\bwith\b|;)",
                    raw_header[by_match.end():],
                    re.IGNORECASE,
                )
                by_section_end = (
                    (by_match.end() + with_or_semi.start())
                    if with_or_semi
                    else len(raw_header)
                )
                by_section = raw_header[by_match.end():by_section_end]
                hop.by_ip = self._extract_ip_candidate(by_section)

            # -------------------------------------------------
            # Extract protocol
            # -------------------------------------------------

            with_match = re.search(
                r"\bwith\s+([^\s;]+)",
                raw_header,
                re.IGNORECASE,
            )

            if with_match:
                hop.with_protocol = with_match.group(1)

            # -------------------------------------------------
            # Extract timestamp
            # -------------------------------------------------

            timestamp_match = re.search(
                r";\s*(.+)$",
                raw_header,
            )

            if timestamp_match:
                timestamp_text = (
                    timestamp_match.group(1).strip()
                )

                try:
                    hop.timestamp = (
                        parsedate_to_datetime(
                            timestamp_text
                        ).isoformat()
                    )
                except (TypeError, ValueError, OverflowError):
                    result.warnings.append(
                        Warning(
                            code="MALFORMED_RECEIVED_HEADER",
                            message=(
                                f"Received hop {index} contains "
                                f"an unparseable timestamp."
                            ),
                        )
                    )

            # -------------------------------------------------
            # Check whether anything useful was extracted
            # -------------------------------------------------

            if (
                hop.from_host is None
                and hop.from_ip is None
                and hop.by_host is None
                and hop.by_ip is None
                and hop.with_protocol is None
                and hop.timestamp is None
            ):
                hop.parse_status = "unparsed"

                result.warnings.append(
                    Warning(
                        code="MALFORMED_RECEIVED_HEADER",
                        message=(
                            f"Received hop {index} could not "
                            f"be parsed."
                        ),
                    )
                )

                return hop

            hop.parse_status = "parsed"

            # -------------------------------------------------
            # Check observed IP addresses
            # -------------------------------------------------

            self._check_received_ip(
                hop.from_ip,
                index,
                result,
            )

            self._check_received_ip(
                hop.by_ip,
                index,
                result,
            )

            return hop

        except Exception:
            result.warnings.append(
                Warning(
                    code="MALFORMED_RECEIVED_HEADER",
                    message=(
                        f"Received hop {index} could not "
                        f"be parsed."
                    ),
                )
            )

            return hop

    def _extract_ip_candidate(self, section: str):
        """
        Extract IP candidate from bracketed [ ] or parenthesized ( ) clauses.
        Supports IPv4, IPv6, and IPv6: prefixes.
        """
        if not section:
            return None

        matches = re.findall(
            r"[\(\[]\s*(?:IPv6:)?([0-9A-Fa-f:.]+)\s*[\)\]]",
            section,
            re.IGNORECASE,
        )

        for cand in matches:
            cand_clean = cand.strip()
            try:
                ipaddress.ip_address(cand_clean)
                return cand_clean
            except ValueError:
                continue

        if matches:
            return matches[0].strip()

        return None

    def _check_received_ip(
        self,
        ip_value: str,
        index: int,
        result: ParsedEmail,
    ):
        """
        Report private/reserved IP observations.

        This does not classify the sender or relay as malicious.
        """

        if not ip_value:
            return

        try:
            ip = ipaddress.ip_address(ip_value)

            if ip.is_private or ip.is_reserved:
                result.warnings.append(
                    Warning(
                        code="PRIVATE_OR_RESERVED_IP_OBSERVED",
                        message=(
                            f"Received hop {index} contains "
                            f"private or reserved IP {ip_value}."
                        ),
                    )
                )

        except ValueError:
            result.warnings.append(
                Warning(
                    code="MALFORMED_RECEIVED_HEADER",
                    message=(
                        f"Received hop {index} contains "
                        f"an invalid IP address."
                    ),
                )
            )

    # =========================================================
    # ADDRESS PARSING
    # =========================================================

    def _parse_addresses(
        self,
        values,
        result: ParsedEmail,
    ):
        """
        Normalize email addresses while preserving the raw
        header value.
        """

        if not values:
            return []

        raw_header = ", ".join(values)

        parsed_addresses = getaddresses(
            [raw_header]
        )

        addresses = []

        for name, address in parsed_addresses:

            name = name.strip() or None
            address = address.strip() or None

            malformed = False

            if not address or "@" not in address:
                malformed = True

                result.warnings.append(
                    Warning(
                        code="MALFORMED_ADDRESS",
                        message=(
                            "An email address could not "
                            "be normalized."
                        ),
                    )
                )

            decoded_name = None

            if name:
                decoded_name, warning = (
                    self._decode_header(name)
                )

                if warning:
                    result.warnings.append(warning)

            addresses.append(
                EmailAddress(
                    name=decoded_name,
                    address=address,
                    raw=raw_header,
                    malformed=malformed,
                )
            )

        return addresses

    # =========================================================
    # HEADER DECODING
    # =========================================================

    def _decode_header(self, value):
        """
        Safely decode an encoded email header value.
        """

        try:
            parts = decode_header(value)

            decoded_parts = []

            for part, charset in parts:

                if isinstance(part, bytes):

                    try:
                        decoded_parts.append(
                            part.decode(
                                charset or "utf-8"
                            )
                        )

                    except (
                        UnicodeDecodeError,
                        LookupError,
                    ):
                        decoded_parts.append(
                            part.decode(
                                "utf-8",
                                errors="replace",
                            )
                        )

                        return (
                            "".join(decoded_parts),
                            Warning(
                                code="HEADER_DECODE_WARNING",
                                message=(
                                    "Header decoding was "
                                    "incomplete."
                                ),
                            ),
                        )

                else:
                    decoded_parts.append(part)

            return "".join(decoded_parts), None

        except Exception:
            return (
                str(value),
                Warning(
                    code="HEADER_DECODE_WARNING",
                    message="Header decoding failed.",
                ),
            )

    # =========================================================
    # BODY + MIME + ATTACHMENTS
    # =========================================================

    def _parse_body_and_attachments(
        self,
        message,
        result: ParsedEmail,
    ):
        """
        Extract plain-text body, detect HTML and collect
        attachment metadata.

        HTML is never rendered and attachments are never executed.
        """

        plain_text_parts = []
        html_parts = []
        html_present = False

        for part in message.walk():

            # Multipart containers do not contain the actual body.
            if part.is_multipart():
                continue

            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            filename = part.get_filename()

            # -------------------------------------------------
            # Attachment
            # -------------------------------------------------

            if filename is not None or disposition == "attachment":

                attachment = self._parse_attachment(
                    part,
                    result,
                )

                result.message.attachments.append(
                    attachment
                )

                continue

            # -------------------------------------------------
            # HTML body
            # -------------------------------------------------

            if content_type == "text/html":
                html_present = True
                try:
                    html_content = part.get_content()
                    if isinstance(html_content, str):
                        html_parts.append(html_content)
                    elif isinstance(html_content, bytes):
                        html_parts.append(html_content.decode("utf-8", errors="replace"))
                except Exception:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_parts.append(payload.decode("utf-8", errors="replace"))
                    except Exception:
                        pass

            # -------------------------------------------------
            # Plain text body
            # -------------------------------------------------

            if content_type == "text/plain":

                try:
                    content = part.get_content()

                    if isinstance(content, str):
                        plain_text_parts.append(content)
                    elif isinstance(content, bytes):
                        plain_text_parts.append(content.decode("utf-8", errors="replace"))

                except Exception:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            plain_text_parts.append(payload.decode("utf-8", errors="replace"))
                    except Exception:
                        result.warnings.append(
                            Warning(
                                code="BODY_DECODE_WARNING",
                                message=(
                                    "Plain-text body could not "
                                    "be decoded."
                                ),
                            )
                        )

        result.message.body_html_present = html_present

        html_urls = []
        if html_parts:
            combined_html = "\n".join(html_parts)
            try:
                html_extractor = _SafeHTMLTextExtractor()
                html_extractor.feed(combined_html)
                html_urls = html_extractor.extracted_urls
                if not plain_text_parts:
                    extracted_text = html_extractor.get_text()
                    if extracted_text:
                        result.message.body_text = extracted_text
            except Exception:
                pass

        if plain_text_parts:
            result.message.body_text = "\n".join(
                plain_text_parts
            )
        elif not result.message.body_text:
            result.message.body_text = None

        self._pending_html_urls = html_urls

    # =========================================================
    # ATTACHMENT METADATA
    # =========================================================

    def _parse_attachment(
        self,
        part,
        result: ParsedEmail,
    ) -> AttachmentMetadata:

        filename = part.get_filename()

        if filename:
            filename, warning = self._decode_header(
                filename
            )

            if warning:
                result.warnings.append(warning)

        content_type = part.get_content_type()

        try:
            payload = part.get_payload(
                decode=True
            )

            if payload is None:
                payload = b""

            attachment_hash = calculate_sha256(
                payload
            )

            size_bytes = len(payload)

            disposition = (
                part.get_content_disposition()
            )

            is_inline = disposition == "inline"

            return AttachmentMetadata(
                filename=filename,
                content_type=content_type,
                size_bytes=size_bytes,
                sha256=attachment_hash,
                is_inline=is_inline,
                parse_status="parsed",
            )

        except Exception:

            result.warnings.append(
                Warning(
                    code="ATTACHMENT_METADATA_WARNING",
                    message=(
                        "Attachment metadata could not "
                        "be fully extracted."
                    ),
                )
            )

            return AttachmentMetadata(
                filename=filename,
                content_type=content_type,
                parse_status="partial",
            )

    # =========================================================
    # URL EXTRACTION
    # =========================================================

    def _extract_urls(self, result: ParsedEmail):
        """
        Extract URL metadata from the plain-text body and HTML links.

        URLs are only parsed as metadata.
        They are never fetched or followed.
        """

        body = result.message.body_text or ""

        # Match HTTP and HTTPS URLs in the extracted body.
        pattern = r"https?://[^\s<>'\"]+"

        found_urls = re.findall(pattern, body)

        # Include URLs found from HTML href attributes
        pending_html = getattr(self, "_pending_html_urls", [])
        for u in pending_html:
            if u.startswith("http://") or u.startswith("https://"):
                found_urls.append(u)

        seen_raw = set()
        for raw_url in found_urls:
            # Remove punctuation that may be attached to a URL
            # in normal sentences.
            raw_url = raw_url.rstrip(".,);!?]}>")

            if raw_url in seen_raw:
                continue
            seen_raw.add(raw_url)

            try:
                parsed = urlsplit(raw_url)

                if not parsed.scheme or not parsed.netloc:
                    raise ValueError

                result.message.urls.append(
                    URLMetadata(
                        raw=raw_url,
                        scheme=parsed.scheme,
                        host=parsed.hostname,
                        path=parsed.path or None,
                        query_present=bool(parsed.query),
                        is_https=parsed.scheme.lower() == "https",
                        parse_status="parsed",
                    )
                )

            except Exception:
                result.warnings.append(
                    Warning(
                        code="URL_PARSE_WARNING",
                        message=(
                            f"URL metadata could not be parsed: {raw_url}"
                        ),
                    )
                )