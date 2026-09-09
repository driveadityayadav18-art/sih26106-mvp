"""
TraceShield – Services Report Generator Re-export
=================================================

Re-exports reporting generator routines from ``backend.reporting.report_generator``
to ensure both ``backend.services.report_generator`` and ``backend.reporting.report_generator``
can be cleanly resolved across the service layer.
"""

from backend.reporting.report_generator import (
    generate_markdown_report,
    generate_html_report,
    generate_json_report,
    _get_url_ml_intelligence,
    _get_tor_proxy_intelligence,
    _get_privacy_audit_intelligence,
    _get_mitigation_intelligence,
)

__all__ = [
    "generate_markdown_report",
    "generate_html_report",
    "generate_json_report",
    "_get_url_ml_intelligence",
    "_get_tor_proxy_intelligence",
    "_get_privacy_audit_intelligence",
    "_get_mitigation_intelligence",
]
