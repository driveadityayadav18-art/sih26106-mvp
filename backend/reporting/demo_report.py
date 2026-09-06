#!/usr/bin/env python3
"""
demo_report.py – Standalone script that generates a TraceShield incident report.

Usage (from the project root):
    python -m backend.reporting.demo_report                          # Markdown → stdout, first SQLite case
    python -m backend.reporting.demo_report --html                   # HTML → data/reports/<case>.html, auto-open
    python -m backend.reporting.demo_report --eml data/fixtures/04_credential_harvest.eml
    python -m backend.reporting.demo_report --eml data/fixtures/04_credential_harvest.eml --html
    python -m backend.reporting.demo_report --case TS-DEMO-001 --html
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys

# ── path bootstrap ──────────────────────────────────────────────────────────
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_THIS_DIR)
_ROOT_DIR = os.path.dirname(_BACKEND_DIR)

for p in (_ROOT_DIR, _BACKEND_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

# ── imports after path fixup ────────────────────────────────────────────────
from backend.reporting.report_generator import generate_markdown_report, generate_html_report
from backend.parser.email_parser import EmailParser
from backend.parser.models import ParsedEmail
from backend.evidence.hashing import calculate_sha256, get_byte_length
from backend.detection.detection import ThreatDetector
from backend.detection.context import DetectionContext
from backend.db import init_db, get_case, get_all_cases


# ---------------------------------------------------------------------------
# Build a case dict from a raw .eml file (mirrors the create_case flow
# in main.py but without FastAPI / LLM / enrichment).
# ---------------------------------------------------------------------------

def build_case_from_eml(eml_path: str, case_id: str = "RPT-LOCAL-001") -> dict:
    """Parse an .eml file and run heuristic detection, returning a case dict."""
    with open(eml_path, "rb") as fh:
        raw_bytes = fh.read()

    sha256 = calculate_sha256(raw_bytes)
    byte_len = get_byte_length(raw_bytes)

    parser = EmailParser()
    try:
        parsed: ParsedEmail = parser.parse(raw_bytes)
    except Exception:
        parsed = ParsedEmail()

    # Extract originating IP (same logic as main.py)
    origin_ip = None
    if parsed.trace.hops:
        for hop in parsed.trace.hops:
            if hop.from_ip:
                try:
                    ip_obj = ipaddress.ip_address(hop.from_ip)
                    if not ip_obj.is_private and not ip_obj.is_loopback:
                        origin_ip = hop.from_ip
                        break
                except Exception:
                    pass
    if not origin_ip:
        for raw_hdr in parsed.authentication.raw_authentication_headers:
            m = re.search(r"sender\s+IP\s+is\s+([0-9a-fA-F:.]+)", raw_hdr, re.IGNORECASE)
            if m:
                origin_ip = m.group(1)
                break

    message_dict = {
        "from": {
            "name": parsed.message.from_.name,
            "address": parsed.message.from_.address,
        },
        "reply_to": parsed.message.reply_to,
        "return_path": parsed.message.return_path,
        "origin_ip": origin_ip,
        "subject": parsed.message.subject,
        "date": parsed.message.date,
        "body_text": parsed.message.body_text,
        "urls": [u.raw for u in parsed.message.urls],
        "attachments": [a.to_dict() for a in parsed.message.attachments],
        "spf": parsed.authentication.spf.result,
        "dkim": parsed.authentication.dkim.result,
        "dmarc": parsed.authentication.dmarc.result,
        "authentication": {
            "spf": parsed.authentication.spf.result,
            "dkim": parsed.authentication.dkim.result,
            "dmarc": parsed.authentication.dmarc.result,
            "compauth": parsed.authentication.compauth,
        },
        "trace": parsed.trace.to_dict(),
    }

    detector = ThreatDetector()
    threat_result = detector.analyze(parsed, DetectionContext())

    formatted_reasons = []
    for rc in threat_result.get("reason_codes", []):
        formatted_reasons.append({
            "code": rc.get("code", ""),
            "title": rc.get("message") or rc.get("title", ""),
            "message": rc.get("message") or rc.get("title", ""),
            "evidence_path": rc.get("evidence_path", ""),
            "weight": rc.get("weight", 0),
        })

    risk_assessment = {
        "score": threat_result.get("score", 0),
        "band": threat_result.get("band", "LOW"),
        "reason_codes": formatted_reasons,
        "limitations": threat_result.get("limitations", []),
    }

    return {
        "case_id": case_id,
        "artifact": {
            "sha256": sha256,
            "byte_length": byte_len,
            "is_demo_data": True,
        },
        "message": message_dict,
        "risk": risk_assessment,
        "ai_review": None,
        "trace": parsed.trace.to_dict(),
        "warnings": [w.to_dict() for w in parsed.warnings],
        "authentication": parsed.authentication.to_dict(),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate a TraceShield incident report (Markdown or HTML).",
    )
    ap.add_argument(
        "--eml",
        type=str,
        default=None,
        help="Path to an .eml file to parse and report on.",
    )
    ap.add_argument(
        "--case",
        type=str,
        default=None,
        help="Case ID to load from the SQLite database (e.g. TS-DEMO-001).",
    )
    ap.add_argument(
        "--html",
        action="store_true",
        default=False,
        help="Generate a standalone HTML report instead of Markdown, save to data/reports/ and open it.",
    )
    args = ap.parse_args()

    case_dict: dict | None = None

    # Priority: --case flag → --eml flag → first DB case → default fixture
    if args.case:
        init_db()
        case_dict = get_case(args.case)
        if case_dict is None:
            print(f"[ERROR] Case '{args.case}' not found in the database.", file=sys.stderr)
            sys.exit(1)
        print(f"[INFO] Loaded case '{args.case}' from SQLite.\n")

    elif args.eml:
        if not os.path.isfile(args.eml):
            print(f"[ERROR] File not found: {args.eml}", file=sys.stderr)
            sys.exit(1)
        print(f"[INFO] Parsing EML file: {args.eml}\n")
        case_dict = build_case_from_eml(args.eml)

    else:
        # Try loading the first case from the database
        init_db()
        all_cases = get_all_cases()
        if all_cases:
            case_dict = all_cases[0]
            print(f"[INFO] Loaded first case from SQLite: {case_dict.get('case_id', '?')}\n")
        else:
            # Fall back to a fixture .eml
            fixture_path = os.path.join(
                _ROOT_DIR, "data", "fixtures", "04_credential_harvest.eml",
            )
            if os.path.isfile(fixture_path):
                print(f"[INFO] No cases in DB — parsing fixture: {fixture_path}\n")
                case_dict = build_case_from_eml(fixture_path)
            else:
                print(
                    "[ERROR] No cases in database and no fixture .eml found.\n"
                    "        Pass --eml <path> or --case <id>.",
                    file=sys.stderr,
                )
                sys.exit(1)

    if args.html:
        _write_html_report(case_dict)
    else:
        report = generate_markdown_report(case_dict)
        # Windows consoles may use cp1252; force UTF-8 for the report output.
        try:
            sys.stdout.buffer.write(report.encode("utf-8"))
            sys.stdout.buffer.write(b"\n")
            sys.stdout.buffer.flush()
        except Exception:
            print(report)


def _write_html_report(case_dict: dict) -> None:
    """Generate the HTML report, write it to data/reports/, and open it in the browser."""
    import webbrowser

    case_id = case_dict.get("case_id") or "report"
    # Sanitise case_id for use as a filename
    safe_id = re.sub(r"[^\w\-]", "_", str(case_id))

    reports_dir = os.path.join(_ROOT_DIR, "data", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    out_path = os.path.join(reports_dir, f"{safe_id}.html")

    html = generate_html_report(case_dict)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    abs_path = os.path.abspath(out_path)
    print(f"[INFO] HTML report saved to: {abs_path}")
    print(f"[INFO] Opening in browser…")
    webbrowser.open(f"file:///{abs_path.replace(os.sep, '/')}")


if __name__ == "__main__":
    main()
