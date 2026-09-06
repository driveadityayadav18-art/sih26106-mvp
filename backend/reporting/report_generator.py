"""
TraceShield – Incident-Report Generator
========================================

Produces structured, analyst-ready reports from a persisted case
dictionary (the same shape stored in ``analysis_json`` in SQLite).

Public API
----------
    generate_markdown_report(case_dict) -> str
    generate_html_report(case_dict)     -> str   # standalone, printable HTML
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _defang_url(url: str) -> str:
    """Defang a URL for safe inclusion in reports.

    Replaces ``http`` → ``hxxp`` and ``.`` → ``[.]`` in the netloc portion,
    so that the URL cannot be accidentally clicked or auto-linked.
    """
    # Replace scheme
    defanged = re.sub(r"^https://", "hxxps://", url, count=1)
    defanged = re.sub(r"^http://", "hxxp://", defanged, count=1)

    # Defang dots only in the authority (host:port) section.
    # Split on the first '/' after the scheme separator to isolate the host.
    scheme_sep = "://"
    if scheme_sep in defanged:
        before, rest = defanged.split(scheme_sep, 1)
        if "/" in rest:
            authority, path = rest.split("/", 1)
            authority = authority.replace(".", "[.]")
            defanged = f"{before}{scheme_sep}{authority}/{path}"
        else:
            rest = rest.replace(".", "[.]")
            defanged = f"{before}{scheme_sep}{rest}"
    return defanged


def _safe(value: Any, default: str = "N/A") -> str:
    """Return *value* as a non-empty string, or *default*."""
    if value is None:
        return default
    s = str(value).strip()
    return s if s else default


def _auth_badge(result: str) -> str:
    """Return a small emoji badge for an auth result."""
    r = (result or "unknown").lower()
    if r == "pass":
        return "✅ pass"
    if r in ("fail", "hardfail"):
        return "❌ fail"
    if r in ("softfail",):
        return "⚠️ softfail"
    if r == "none":
        return "➖ none"
    return f"❓ {r}"


def _extract_from_display(msg: Dict[str, Any]) -> str:
    """Return a human-friendly 'Name <address>' string from the message dict."""
    from_val = msg.get("from")
    if isinstance(from_val, dict):
        name = from_val.get("name") or ""
        addr = from_val.get("address") or ""
        if name and addr:
            return f"{name} <{addr}>"
        return addr or name or "N/A"
    return _safe(from_val)


# ---------------------------------------------------------------------------
# Core generator
# ---------------------------------------------------------------------------

def generate_markdown_report(case_dict: Dict[str, Any]) -> str:
    """Format a case analysis dict into a structured Markdown incident report.

    Parameters
    ----------
    case_dict : dict
        The full case dictionary as persisted by ``save_case()`` (or returned
        by ``create_case``).  Expected top-level keys include *case_id*,
        *artifact*, *message*, *authentication*, *risk*, *trace*, and
        optionally *ai_review*.

    Returns
    -------
    str
        A complete Markdown document ready for console output, file export,
        or downstream rendering.
    """

    lines: List[str] = []

    # Convenience accessors
    case_id = _safe(case_dict.get("case_id"), "UNKNOWN")
    artifact = case_dict.get("artifact") or {}
    sha256 = _safe(artifact.get("sha256"), "not computed")
    msg: Dict[str, Any] = case_dict.get("message") or {}
    auth_section: Dict[str, Any] = case_dict.get("authentication") or {}
    risk: Dict[str, Any] = case_dict.get("risk") or {}
    trace_data: Dict[str, Any] = case_dict.get("trace") or {}
    ai_review: Optional[Dict[str, Any]] = case_dict.get("ai_review")
    analysis_ts = _safe(
        case_dict.get("created_at"),
        datetime.now(timezone.utc).isoformat(),
    )

    # ── 1. Header ──────────────────────────────────────────────────────────
    lines.append("═" * 72)
    lines.append("  TRACESHIELD — INCIDENT ANALYSIS REPORT")
    lines.append("═" * 72)
    lines.append("")
    lines.append(f"**Case ID:**        `{case_id}`")
    lines.append(f"**SHA-256 Hash:**   `{sha256}`")
    lines.append(f"**Analysis Date:**  {analysis_ts}")
    lines.append(f"**Subject:**        {_safe(msg.get('subject'))}")
    lines.append(f"**From:**           {_extract_from_display(msg)}")
    lines.append(f"**Reply-To:**       {_safe(msg.get('reply_to'))}")
    lines.append(f"**Return-Path:**    {_safe(msg.get('return_path'))}")
    lines.append("")

    # ── 2. Sender & Authentication Summary ─────────────────────────────────
    lines.append("---")
    lines.append("## Sender & Authentication Summary")
    lines.append("")

    # Try nested auth dict first, fall back to flat keys on the message
    auth_nested = auth_section or {}
    spf_dict = auth_nested.get("spf") or {}
    dkim_dict = auth_nested.get("dkim") or {}
    dmarc_dict = auth_nested.get("dmarc") or {}

    spf_result = spf_dict.get("result") if isinstance(spf_dict, dict) else msg.get("spf", "unknown")
    dkim_result = dkim_dict.get("result") if isinstance(dkim_dict, dict) else msg.get("dkim", "unknown")
    dmarc_result = dmarc_dict.get("result") if isinstance(dmarc_dict, dict) else msg.get("dmarc", "unknown")
    compauth = auth_nested.get("compauth")

    lines.append("| Check   | Result           |")
    lines.append("|---------|------------------|")
    lines.append(f"| **SPF**   | {_auth_badge(spf_result)} |")
    lines.append(f"| **DKIM**  | {_auth_badge(dkim_result)} |")
    lines.append(f"| **DMARC** | {_auth_badge(dmarc_result)} |")
    if compauth:
        lines.append(f"| **CompAuth** | `{compauth}` |")
    lines.append("")

    # ── 3. Risk Score & Reason Codes ───────────────────────────────────────
    lines.append("---")
    lines.append("## Risk Score & Reason Codes")
    lines.append("")

    score = risk.get("score", 0)
    band = risk.get("band", "UNKNOWN")
    band_emoji = {"LOW": "🟢", "REVIEW": "🟡", "HIGH": "🔴"}.get(band, "⚪")
    lines.append(f"**Score:** {score} / 100  {band_emoji} **{band}**")
    lines.append("")

    reason_codes: List[Dict[str, Any]] = risk.get("reason_codes") or []
    if reason_codes:
        lines.append("| Code | Weight | Evidence Path |")
        lines.append("|------|-------:|---------------|")
        for rc in reason_codes:
            code = _safe(rc.get("code"), "—")
            weight = rc.get("weight", 0)
            evidence = _safe(rc.get("evidence_path"), "—")
            lines.append(f"| `{code}` | {weight:+d} | `{evidence}` |")
        lines.append("")
    else:
        lines.append("_No reason codes were triggered._")
        lines.append("")

    # Limitations
    limitations: List[str] = risk.get("limitations") or []
    if limitations:
        lines.append("**Limitations / Skipped Checks:**")
        for lim in limitations:
            lines.append(f"- {lim}")
        lines.append("")

    # ── 4. Relay Path ──────────────────────────────────────────────────────
    lines.append("---")
    lines.append("## Relay Path (Received Hops)")
    lines.append("")

    hops: List[Dict[str, Any]] = trace_data.get("hops") or []
    if hops:
        for hop in hops:
            idx = hop.get("index", "?")
            from_host = _safe(hop.get("from_host"), "?")
            from_ip = _safe(hop.get("from_ip"), "?")
            by_host = _safe(hop.get("by_host"), "?")
            by_ip = _safe(hop.get("by_ip"), "")
            proto = _safe(hop.get("with_protocol"), "?")
            ts = _safe(hop.get("timestamp"), "")
            trust = _safe(hop.get("trust"), "unknown")

            by_display = f"{by_host}"
            if by_ip and by_ip != "?":
                by_display += f" [{by_ip}]"

            lines.append(
                f"**Hop {idx}** — `{from_host}` (`{from_ip}`) "
                f"→ `{by_display}` via {proto}  "
            )
            if ts:
                lines.append(f"  ⏱ {ts}  | trust: **{trust}**")
            else:
                lines.append(f"  trust: **{trust}**")
            lines.append("")
    else:
        lines.append("_No relay hops were extracted from the headers._")
        lines.append("")

    # ── 5. Observed URLs (defanged) ────────────────────────────────────────
    lines.append("---")
    lines.append("## Observed URLs (Defanged)")
    lines.append("")

    urls = msg.get("urls") or []
    if urls:
        for i, url_item in enumerate(urls, start=1):
            # urls may be raw strings or URLMetadata dicts
            raw = url_item if isinstance(url_item, str) else (
                url_item.get("raw", str(url_item)) if isinstance(url_item, dict) else str(url_item)
            )
            lines.append(f"{i}. `{_defang_url(raw)}`")
        lines.append("")
    else:
        lines.append("_No URLs were observed in the email body._")
        lines.append("")

    # ── 6. Analyst Notes / LLM Summary ─────────────────────────────────────
    lines.append("---")
    lines.append("## Analyst Notes / LLM Summary")
    lines.append("")

    if ai_review and isinstance(ai_review, dict) and "error" not in ai_review:
        adj_score = ai_review.get("adjusted_score")
        adj_band = ai_review.get("adjusted_band")
        is_fp = ai_review.get("is_false_positive")
        summary_text = ai_review.get("analyst_summary", "")

        if adj_score is not None or adj_band:
            fp_label = "Yes" if is_fp else "No"
            lines.append(f"**LLM Adjusted Score:** {adj_score} / 100  **Band:** {adj_band}")
            lines.append(f"**False-Positive Determination:** {fp_label}")
            lines.append("")

        if summary_text:
            lines.append(f"> {summary_text}")
            lines.append("")
    else:
        reason = ""
        if ai_review and isinstance(ai_review, dict):
            reason = ai_review.get("error", "")
        if reason:
            lines.append(f"_LLM review was not available: {reason}_")
        else:
            lines.append("_No LLM analyst summary is present for this case._")
        lines.append("")

    # ── 7. Chain of Custody Footer ─────────────────────────────────────────
    lines.append("---")
    lines.append("## Chain of Custody")
    lines.append("")
    lines.append(f"- **Artifact SHA-256:** `{sha256}`")
    byte_len = artifact.get("byte_length")
    if byte_len is not None:
        lines.append(f"- **Artifact Size:**   {byte_len:,} bytes")
    lines.append(f"- **Report Generated:** {analysis_ts}")
    lines.append(f"- **Case Reference:**  `{case_id}`")
    lines.append("")
    lines.append("═" * 72)
    lines.append("  END OF REPORT")
    lines.append("═" * 72)
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML report generator
# ---------------------------------------------------------------------------

# Inline stylesheet — dark theme on screen, clean white on print.
_HTML_CSS = """
/* ── Reset & base ────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  font-size: 14px;
  line-height: 1.65;
  background: #0d1117;
  color: #c9d1d9;
  padding: 2rem;
}

/* ── Page wrapper ────────────────────────────────────────────────── */
.report {
  max-width: 900px;
  margin: 0 auto;
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 10px;
  overflow: hidden;
}

/* ── Header banner ───────────────────────────────────────────────── */
.report-header {
  background: linear-gradient(135deg, #0f2744 0%, #0a1929 60%, #1a0a2e 100%);
  border-bottom: 2px solid #1f6feb;
  padding: 2rem 2.5rem 1.75rem;
}
.report-header .logo-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1.25rem;
}
.report-header .shield-icon {
  width: 36px; height: 36px;
  background: linear-gradient(135deg, #1f6feb, #388bfd);
  border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  font-size: 18px;
}
.report-header .brand {
  font-size: 1rem;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #388bfd;
}
.report-header h1 {
  font-size: 1.55rem;
  font-weight: 700;
  color: #e6edf3;
  letter-spacing: 0.02em;
  margin-bottom: 1.25rem;
}
.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 0.5rem 1.5rem;
}
.meta-row { display: flex; gap: 0.5rem; align-items: baseline; }
.meta-label {
  font-size: 0.72rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #8b949e;
  white-space: nowrap;
  flex-shrink: 0;
}
.meta-value { color: #c9d1d9; word-break: break-all; }
.meta-value code {
  font-family: 'Cascadia Code', 'Consolas', monospace;
  font-size: 0.8em;
  background: rgba(255,255,255,0.07);
  padding: 1px 5px;
  border-radius: 4px;
  color: #79c0ff;
}

/* ── Sections ────────────────────────────────────────────────────── */
.section {
  padding: 1.5rem 2.5rem;
  border-bottom: 1px solid #21262d;
}
.section:last-child { border-bottom: none; }
.section-title {
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #8b949e;
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.section-title::after {
  content: '';
  flex: 1;
  height: 1px;
  background: #21262d;
}

/* ── Auth table ──────────────────────────────────────────────────── */
.auth-grid {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
}
.auth-card {
  background: #0d1117;
  border: 1px solid #30363d;
  border-radius: 8px;
  padding: 0.75rem 1.25rem;
  min-width: 120px;
  text-align: center;
}
.auth-card .check-name {
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #8b949e;
  margin-bottom: 0.4rem;
}
.auth-card .check-result {
  font-size: 1rem;
  font-weight: 700;
}
.result-pass  { color: #3fb950; }
.result-fail  { color: #f85149; }
.result-soft  { color: #d29922; }
.result-none  { color: #8b949e; }
.result-other { color: #a5d6ff; }

/* ── Risk score ──────────────────────────────────────────────────── */
.score-row {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  margin-bottom: 1.25rem;
  flex-wrap: wrap;
}
.score-dial {
  width: 80px; height: 80px;
  border-radius: 50%;
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  border: 3px solid var(--band-color, #8b949e);
  flex-shrink: 0;
}
.score-dial .score-num {
  font-size: 1.6rem;
  font-weight: 800;
  color: var(--band-color, #c9d1d9);
  line-height: 1;
}
.score-dial .score-denom {
  font-size: 0.65rem;
  color: #8b949e;
}
.band-badge {
  font-size: 0.85rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  padding: 0.3rem 0.9rem;
  border-radius: 20px;
  background: var(--band-bg, #21262d);
  color: var(--band-color, #c9d1d9);
  border: 1px solid var(--band-color, #30363d);
}

/* ── Tables (reason codes, etc.) ─────────────────────────────────── */
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.83rem;
}
thead th {
  background: #0d1117;
  color: #8b949e;
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.55rem 0.75rem;
  text-align: left;
  border-bottom: 1px solid #30363d;
}
tbody tr { border-bottom: 1px solid #21262d; }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: rgba(255,255,255,0.03); }
td { padding: 0.55rem 0.75rem; vertical-align: top; }
td code, th code {
  font-family: 'Cascadia Code', 'Consolas', monospace;
  font-size: 0.8em;
  background: rgba(255,255,255,0.07);
  padding: 1px 5px;
  border-radius: 4px;
  color: #79c0ff;
}
.weight-pos { color: #f85149; font-weight: 700; }
.weight-zero { color: #8b949e; }
.evidence-path { color: #a5d6ff; font-family: 'Cascadia Code','Consolas',monospace; font-size:0.78em; }

/* ── Limitations list ────────────────────────────────────────────── */
.limitations {
  margin-top: 0.75rem;
  padding: 0.75rem 1rem;
  background: rgba(210,153,34,0.08);
  border-left: 3px solid #d29922;
  border-radius: 0 6px 6px 0;
}
.limitations .lim-title {
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #d29922;
  margin-bottom: 0.4rem;
}
.limitations ul { list-style: none; padding: 0; }
.limitations li { color: #c9d1d9; padding: 0.15rem 0; font-size: 0.82rem; }
.limitations li::before { content: '⚠ '; color: #d29922; }

/* ── Relay hops ──────────────────────────────────────────────────── */
.hop-list { display: flex; flex-direction: column; gap: 0.6rem; }
.hop {
  display: grid;
  grid-template-columns: 2.5rem 1fr auto;
  gap: 0.75rem;
  align-items: start;
  background: #0d1117;
  border: 1px solid #21262d;
  border-radius: 8px;
  padding: 0.75rem 1rem;
}
.hop-idx {
  width: 2rem; height: 2rem;
  background: #1f6feb22;
  border: 1px solid #1f6feb55;
  border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 0.75rem;
  font-weight: 700;
  color: #388bfd;
  flex-shrink: 0;
}
.hop-body { min-width: 0; }
.hop-route {
  font-family: 'Cascadia Code', 'Consolas', monospace;
  font-size: 0.78em;
  color: #c9d1d9;
  word-break: break-all;
}
.hop-route .arrow { color: #388bfd; margin: 0 0.3em; }
.hop-meta { font-size: 0.72rem; color: #8b949e; margin-top: 0.2rem; }
.hop-trust {
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  background: #21262d;
  color: #8b949e;
  align-self: center;
  white-space: nowrap;
}

/* ── URL list ────────────────────────────────────────────────────── */
.url-list { display: flex; flex-direction: column; gap: 0.5rem; }
.url-item {
  display: flex;
  gap: 0.75rem;
  align-items: baseline;
  background: #0d1117;
  border: 1px solid #21262d;
  border-radius: 6px;
  padding: 0.6rem 1rem;
}
.url-num {
  font-size: 0.72rem;
  font-weight: 700;
  color: #8b949e;
  flex-shrink: 0;
  min-width: 1.5rem;
}
.url-text {
  font-family: 'Cascadia Code', 'Consolas', monospace;
  font-size: 0.78em;
  color: #ffa657;
  word-break: break-all;
}

/* ── LLM analyst summary ─────────────────────────────────────────── */
.llm-meta {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  margin-bottom: 1rem;
}
.llm-chip {
  font-size: 0.78rem;
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  background: #21262d;
  border: 1px solid #30363d;
  color: #c9d1d9;
}
.llm-chip strong { color: #79c0ff; }
.llm-summary {
  background: rgba(31,111,235,0.08);
  border-left: 3px solid #1f6feb;
  border-radius: 0 6px 6px 0;
  padding: 1rem 1.25rem;
  color: #c9d1d9;
  font-size: 0.88rem;
  line-height: 1.7;
}
.empty-note {
  color: #8b949e;
  font-style: italic;
  font-size: 0.85rem;
}

/* ── Chain of Custody footer ─────────────────────────────────────── */
.custody {
  background: #0d1117;
}
.custody-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 0.6rem;
}
.custody-item { display: flex; flex-direction: column; gap: 0.2rem; }
.custody-label {
  font-size: 0.65rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #8b949e;
}
.custody-value {
  font-family: 'Cascadia Code', 'Consolas', monospace;
  font-size: 0.78em;
  color: #79c0ff;
  word-break: break-all;
}
.custody-value.plain { font-family: inherit; font-size: 0.83em; color: #c9d1d9; }

/* ── Print overrides ─────────────────────────────────────────────── */
@media print {
  body { background: #fff; color: #111; padding: 0; font-size: 11pt; }
  .report {
    background: #fff; color: #111;
    border: none; border-radius: 0;
    max-width: 100%;
  }
  .report-header {
    background: #f0f4f8;
    border-bottom: 2px solid #1f6feb;
  }
  .report-header h1,
  .report-header .brand { color: #0f2744; }
  .meta-label, .section-title,
  .custody-label, .lim-title { color: #555; }
  .meta-value, .meta-value code,
  .custody-value, .hop-route,
  .url-text { color: #111; background: none; }
  .auth-card, .hop, .url-item, .custody { background: #f8f9fa; border-color: #dee2e6; }
  .llm-summary { background: #f0f4ff; border-left-color: #1f6feb; color: #111; }
  .limitations { background: #fff8e1; border-left-color: #f59e0b; }
  .score-dial { border-color: #333; }
  .score-dial .score-num { color: #111; }
  .band-badge { background: #f0f0f0; color: #333; border-color: #999; }
  .result-pass  { color: #166534; }
  .result-fail  { color: #991b1b; }
  .result-soft  { color: #92400e; }
  a { color: #1f6feb; text-decoration: underline; }
  .section { page-break-inside: avoid; }
}
"""


def _h(text: str) -> str:
    """HTML-escape a plain string."""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _auth_html(result: str) -> tuple[str, str]:
    """Return (css_class, display_text) for an auth result."""
    r = (result or "unknown").lower()
    if r == "pass":
        return "result-pass", "✓ pass"
    if r in ("fail", "hardfail"):
        return "result-fail", "✗ fail"
    if r == "softfail":
        return "result-soft", "~ softfail"
    if r == "none":
        return "result-none", "— none"
    return "result-other", _h(r)


def _band_vars(band: str) -> str:
    """Return inline style variables for the risk band."""
    palettes = {
        "LOW":    ("--band-color:#3fb950; --band-bg:rgba(63,185,80,0.12);"),
        "REVIEW": ("--band-color:#d29922; --band-bg:rgba(210,153,34,0.12);"),
        "HIGH":   ("--band-color:#f85149; --band-bg:rgba(248,81,73,0.12);"),
    }
    return palettes.get(band.upper(), "--band-color:#8b949e; --band-bg:#21262d;")


def generate_html_report(case_dict: Dict[str, Any]) -> str:
    """Format a case analysis dict into a standalone, printable HTML report.

    The returned string is a complete ``<!DOCTYPE html>`` document with all
    styles inlined — no external stylesheets, fonts, or CDN dependencies.
    It renders well in a browser and produces a clean white page when printed
    (or saved as PDF via Ctrl+P).

    Parameters
    ----------
    case_dict : dict
        Same shape as accepted by :func:`generate_markdown_report`.

    Returns
    -------
    str
        A self-contained HTML document (UTF-8).
    """

    # ── Extract data (mirrors generate_markdown_report) ──────────────────
    case_id = _safe(case_dict.get("case_id"), "UNKNOWN")
    artifact = case_dict.get("artifact") or {}
    sha256 = _safe(artifact.get("sha256"), "not computed")
    byte_len = artifact.get("byte_length")
    msg: Dict[str, Any] = case_dict.get("message") or {}
    auth_section: Dict[str, Any] = case_dict.get("authentication") or {}
    risk: Dict[str, Any] = case_dict.get("risk") or {}
    trace_data: Dict[str, Any] = case_dict.get("trace") or {}
    ai_review: Optional[Dict[str, Any]] = case_dict.get("ai_review")
    analysis_ts = _safe(
        case_dict.get("created_at"),
        datetime.now(timezone.utc).isoformat(),
    )

    # Auth results
    auth_nested = auth_section or {}
    spf_dict  = auth_nested.get("spf")  or {}
    dkim_dict = auth_nested.get("dkim") or {}
    dmarc_dict = auth_nested.get("dmarc") or {}
    spf_result  = spf_dict.get("result")   if isinstance(spf_dict,  dict) else msg.get("spf",  "unknown")
    dkim_result = dkim_dict.get("result")  if isinstance(dkim_dict, dict) else msg.get("dkim", "unknown")
    dmarc_result = dmarc_dict.get("result") if isinstance(dmarc_dict, dict) else msg.get("dmarc", "unknown")
    compauth = auth_nested.get("compauth")

    # Risk
    score = risk.get("score", 0)
    band  = risk.get("band", "UNKNOWN")
    reason_codes: List[Dict[str, Any]] = risk.get("reason_codes") or []
    limitations: List[str] = risk.get("limitations") or []

    # Hops / URLs
    hops: List[Dict[str, Any]] = trace_data.get("hops") or []
    urls_raw = msg.get("urls") or []

    # ── Helper: render one HTML section ──────────────────────────────────
    def section(icon: str, title: str, body: str) -> str:
        return (
            f'<div class="section">'
            f'<div class="section-title">{icon}&nbsp;{_h(title)}</div>'
            f'{body}'
            f'</div>'
        )

    # ── 1. Header ────────────────────────────────────────────────────────
    subject_disp = _h(_safe(msg.get("subject")))
    from_disp    = _h(_extract_from_display(msg))
    reply_disp   = _h(_safe(msg.get("reply_to")))
    rpath_disp   = _h(_safe(msg.get("return_path")))

    header_html = f"""
<div class="report-header">
  <div class="logo-row">
    <div class="shield-icon">🛡</div>
    <span class="brand">TraceShield</span>
  </div>
  <h1>Incident Analysis Report</h1>
  <div class="meta-grid">
    <div class="meta-row"><span class="meta-label">Case ID</span>
      <span class="meta-value"><code>{_h(case_id)}</code></span></div>
    <div class="meta-row"><span class="meta-label">SHA-256</span>
      <span class="meta-value"><code>{_h(sha256)}</code></span></div>
    <div class="meta-row"><span class="meta-label">Analysis Date</span>
      <span class="meta-value">{_h(analysis_ts)}</span></div>
    <div class="meta-row"><span class="meta-label">Subject</span>
      <span class="meta-value">{subject_disp}</span></div>
    <div class="meta-row"><span class="meta-label">From</span>
      <span class="meta-value">{from_disp}</span></div>
    <div class="meta-row"><span class="meta-label">Reply-To</span>
      <span class="meta-value">{reply_disp}</span></div>
    <div class="meta-row"><span class="meta-label">Return-Path</span>
      <span class="meta-value">{rpath_disp}</span></div>
  </div>
</div>"""

    # ── 2. Auth Summary ───────────────────────────────────────────────────
    def auth_card(label: str, result: str) -> str:
        css, text = _auth_html(result)
        return (
            f'<div class="auth-card">'
            f'<div class="check-name">{_h(label)}</div>'
            f'<div class="check-result {css}">{text}</div>'
            f'</div>'
        )

    auth_cards = (
        auth_card("SPF",  spf_result)
        + auth_card("DKIM", dkim_result)
        + auth_card("DMARC", dmarc_result)
    )
    if compauth:
        auth_cards += auth_card("CompAuth", str(compauth))

    auth_body = f'<div class="auth-grid">{auth_cards}</div>'
    s2 = section("🔐", "Sender & Authentication Summary", auth_body)

    # ── 3. Risk Score & Reason Codes ─────────────────────────────────────
    bvars = _band_vars(band)
    dial = (
        f'<div class="score-dial" style="{bvars}">'
        f'<span class="score-num">{score}</span>'
        f'<span class="score-denom">/ 100</span>'
        f'</div>'
        f'<div class="band-badge" style="{bvars}">{_h(band)}</div>'
    )

    if reason_codes:
        rows = ""
        for rc in reason_codes:
            code     = _safe(rc.get("code"), "—")
            weight   = rc.get("weight", 0)
            evidence = _safe(rc.get("evidence_path"), "—")
            title_rc = _h(_safe(rc.get("title") or rc.get("message"), ""))
            w_class  = "weight-pos" if weight > 0 else "weight-zero"
            w_sign   = f"+{weight}" if weight > 0 else str(weight)
            rows += (
                f"<tr>"
                f"<td><code>{_h(code)}</code></td>"
                f"<td>{_h(title_rc)}</td>"
                f'<td class="{w_class}">{w_sign}</td>'
                f'<td class="evidence-path">{_h(evidence)}</td>'
                f"</tr>"
            )
        rc_table = (
            '<table><thead><tr>'
            '<th>Code</th><th>Description</th><th>Weight</th><th>Evidence Path</th>'
            '</tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )
    else:
        rc_table = '<p class="empty-note">No reason codes were triggered.</p>'

    lim_html = ""
    if limitations:
        items = "".join(f"<li>{_h(l)}</li>" for l in limitations)
        lim_html = (
            '<div class="limitations">'
            '<div class="lim-title">Limitations / Skipped Checks</div>'
            f'<ul>{items}</ul></div>'
        )

    risk_body = (
        f'<div class="score-row">{dial}</div>'
        f'{rc_table}'
        f'{lim_html}'
    )
    s3 = section("📊", "Risk Score & Reason Codes", risk_body)

    # ── 4. Relay Path ─────────────────────────────────────────────────────
    if hops:
        hop_items = ""
        for hop in hops:
            idx       = hop.get("index", "?")
            from_host = _safe(hop.get("from_host"), "?")
            from_ip   = _safe(hop.get("from_ip"),   "?")
            by_host   = _safe(hop.get("by_host"),   "?")
            by_ip     = _safe(hop.get("by_ip"),     "")
            proto     = _safe(hop.get("with_protocol"), "?")
            ts        = _safe(hop.get("timestamp"),  "")
            trust     = _safe(hop.get("trust"),      "unknown")
            by_display = f"{by_host} [{by_ip}]" if by_ip and by_ip != "?" else by_host
            meta_parts = []
            if ts:
                meta_parts.append(f"⏱ {ts}")
            meta_parts.append(f"proto: {proto}")
            meta_str = " &nbsp;·&nbsp; ".join(_h(p) for p in meta_parts)
            hop_items += (
                f'<div class="hop">'
                f'<div class="hop-idx">{idx}</div>'
                f'<div class="hop-body">'
                f'<div class="hop-route">'
                f'{_h(from_host)} <span class="arrow">({_h(from_ip)})</span>'
                f' <span class="arrow">→</span> '
                f'{_h(by_display)}'
                f'</div>'
                f'<div class="hop-meta">{meta_str}</div>'
                f'</div>'
                f'<div class="hop-trust">{_h(trust)}</div>'
                f'</div>'
            )
        relay_body = f'<div class="hop-list">{hop_items}</div>'
    else:
        relay_body = '<p class="empty-note">No relay hops were extracted from the headers.</p>'
    s4 = section("🔀", "Relay Path (Received Hops)", relay_body)

    # ── 5. Observed URLs ──────────────────────────────────────────────────
    if urls_raw:
        url_items = ""
        for i, url_item in enumerate(urls_raw, start=1):
            raw = (
                url_item if isinstance(url_item, str)
                else (url_item.get("raw", str(url_item)) if isinstance(url_item, dict) else str(url_item))
            )
            url_items += (
                f'<div class="url-item">'
                f'<span class="url-num">#{i}</span>'
                f'<span class="url-text">{_h(_defang_url(raw))}</span>'
                f'</div>'
            )
        url_body = f'<div class="url-list">{url_items}</div>'
    else:
        url_body = '<p class="empty-note">No URLs were observed in the email body.</p>'
    s5 = section("🔗", "Observed URLs (Defanged)", url_body)

    # ── 6. Analyst Notes / LLM Summary ───────────────────────────────────
    if ai_review and isinstance(ai_review, dict) and "error" not in ai_review:
        adj_score   = ai_review.get("adjusted_score")
        adj_band    = ai_review.get("adjusted_band", "")
        is_fp       = ai_review.get("is_false_positive")
        summary_txt = _h(_safe(ai_review.get("analyst_summary", ""), ""))
        fp_label    = "Yes" if is_fp else "No"
        chips = ""
        if adj_score is not None:
            chips += f'<div class="llm-chip">LLM Score: <strong>{adj_score}/100</strong></div>'
        if adj_band:
            chips += f'<div class="llm-chip">Band: <strong>{_h(adj_band)}</strong></div>'
        chips += f'<div class="llm-chip">False Positive: <strong>{fp_label}</strong></div>'
        llm_body = (
            f'<div class="llm-meta">{chips}</div>'
            f'<div class="llm-summary">{summary_txt}</div>'
        )
    else:
        err_msg = ""
        if ai_review and isinstance(ai_review, dict):
            err_msg = ai_review.get("error", "")
        note = (
            f"LLM review was not available: {_h(err_msg)}"
            if err_msg else
            "No LLM analyst summary is present for this case."
        )
        llm_body = f'<p class="empty-note">{note}</p>'
    s6 = section("🤖", "Analyst Notes / LLM Summary", llm_body)

    # ── 7. Chain of Custody Footer ────────────────────────────────────────
    size_str = f"{byte_len:,} bytes" if byte_len is not None else "N/A"
    custody_body = (
        '<div class="custody-grid">'
        f'<div class="custody-item"><span class="custody-label">Artifact SHA-256</span>'
        f'<span class="custody-value">{_h(sha256)}</span></div>'
        f'<div class="custody-item"><span class="custody-label">Artifact Size</span>'
        f'<span class="custody-value plain">{_h(size_str)}</span></div>'
        f'<div class="custody-item"><span class="custody-label">Report Generated</span>'
        f'<span class="custody-value plain">{_h(analysis_ts)}</span></div>'
        f'<div class="custody-item"><span class="custody-label">Case Reference</span>'
        f'<span class="custody-value">{_h(case_id)}</span></div>'
        '</div>'
    )
    s7 = section("⛓", "Chain of Custody", custody_body)

    # ── Assemble full document ─────────────────────────────────────────────
    page_title = f"TraceShield Report — {case_id}"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_h(page_title)}</title>
  <style>{_HTML_CSS}</style>
</head>
<body>
<div class="report">
{header_html}
{s2}
{s3}
{s4}
{s5}
{s6}
<div class="section custody">
  <div class="section-title">⛓&nbsp;Chain of Custody</div>
  {custody_body}
</div>
</div>
</body>
</html>
"""
