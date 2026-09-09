"""
TraceShield Threat Scoring Engine
Provides deterministic threat score calculation, multi-vector risk aggregation,
band classification, and granular reason codes for incoming email vectors and parsed messages.
"""

import os
import sys
from typing import Any, Dict, List, Optional, Union

# Ensure backend and root paths are in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from backend.detection.config import (
    COMPAUTH_FAIL_SCORE,
    AUTH_ANOMALY_SCORE,
    REPLY_TO_MISMATCH_SCORE,
    DISPLAY_NAME_DOMAIN_MISMATCH_SCORE,
    LOOKALIKE_DOMAIN_SCORE,
    PUNYCODE_DOMAIN_SCORE,
    RETURN_PATH_ANOMALY_SCORE,
    SUSPICIOUS_URL_PATH_SCORE,
    SHORTENED_URL_SCORE,
    SUSPICIOUS_ATTACHMENT_SCORE,
    EXTERNAL_URL_MISMATCH_SCORE,
    OBFUSCATED_URL_SCORE,
    TRAMPOLINE_REDIRECT_SCORE,
    LOW_MAX_SCORE,
    REVIEW_MAX_SCORE,
    MAX_SCORE,
)
from backend.services.geo_ip import is_tor_exit_node, is_datacenter_proxy
from backend.parser.models import ParsedEmail

# Calibrated weights for multi-vector threat evaluation
SPF_FAIL_SCORE = 15
SPF_SOFTFAIL_SCORE = 8
DKIM_FAIL_OR_NONE_SCORE = 10
DMARC_FAIL_SCORE = 15
TOR_EXIT_NODE_SCORE = 30
DATACENTER_PROXY_SCORE = 15
URL_ML_PHISHING_SCORE = 30
URGENT_PAYMENT_SCORE = 25
SPOOFED_DISPLAY_SCORE = 20
HEADER_ANOMALY_SCORE = 5
REUSED_INDICATOR_SCORE = 15

__all__ = [
    "ThreatScoringEngine",
    "score_threat_vector",
    "evaluate_threat_vector",
    "get_scoring_engine",
    "SPF_FAIL_SCORE",
    "SPF_SOFTFAIL_SCORE",
    "DKIM_FAIL_OR_NONE_SCORE",
    "DMARC_FAIL_SCORE",
    "TOR_EXIT_NODE_SCORE",
    "DATACENTER_PROXY_SCORE",
    "URL_ML_PHISHING_SCORE",
    "URGENT_PAYMENT_SCORE",
    "SPOOFED_DISPLAY_SCORE",
    "LOW_MAX_SCORE",
    "REVIEW_MAX_SCORE",
    "MAX_SCORE",
]


class ThreatScoringEngine:
    """
    Core scoring engine for evaluating security vectors against the TraceShield
    threat intelligence and heuristic framework.
    """

    def __init__(self):
        pass

    def evaluate_vector(self, vector: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a synthetic or extracted vector dictionary.
        Returns total score, band, granular reason codes, and threat classifications.
        """
        raw_score = 0
        reasons: List[Dict[str, Any]] = []

        # 1. Authentication Layer (SPF, DKIM, DMARC, CompAuth)
        spf_val = str(vector.get("spf", "")).lower().strip()
        if spf_val in ("fail", "hardfail", "-all"):
            raw_score += SPF_FAIL_SCORE
            reasons.append({
                "code": "AUTH_SPF_FAIL",
                "message": "SPF check failed (sender IP unauthorized for claimed domain).",
                "weight": SPF_FAIL_SCORE,
                "evidence_path": "authentication.spf.result",
            })
        elif spf_val in ("softfail", "~all"):
            raw_score += SPF_SOFTFAIL_SCORE
            reasons.append({
                "code": "AUTH_SPF_SOFTFAIL",
                "message": "SPF softfail detected (sender IP not explicitly authorized).",
                "weight": SPF_SOFTFAIL_SCORE,
                "evidence_path": "authentication.spf.result",
            })
        elif spf_val in ("neutral", "?all"):
            raw_score += 3
            reasons.append({
                "code": "AUTH_SPF_NEUTRAL",
                "message": "SPF neutral status (domain owner makes no assertion).",
                "weight": 3,
                "evidence_path": "authentication.spf.result",
            })

        dkim_val = str(vector.get("dkim", "")).lower().strip()
        if dkim_val in ("invalid", "fail", "none", "temperror", "permerror"):
            raw_score += DKIM_FAIL_OR_NONE_SCORE
            reasons.append({
                "code": "AUTH_DKIM_FAIL_OR_NONE",
                "message": "DKIM signature failed cryptographic verification or was absent.",
                "weight": DKIM_FAIL_OR_NONE_SCORE,
                "evidence_path": "authentication.dkim.result",
            })

        dmarc_val = str(vector.get("dmarc", "")).lower().strip()
        if dmarc_val in ("reject", "fail"):
            raw_score += DMARC_FAIL_SCORE
            reasons.append({
                "code": "AUTH_DMARC_FAIL",
                "message": "DMARC policy failed alignment checks (action: reject).",
                "weight": DMARC_FAIL_SCORE,
                "evidence_path": "authentication.dmarc.result",
            })
        elif dmarc_val == "quarantine":
            raw_score += 10
            reasons.append({
                "code": "AUTH_DMARC_QUARANTINE",
                "message": "DMARC policy requested quarantine treatment for message.",
                "weight": 10,
                "evidence_path": "authentication.dmarc.result",
            })

        # 2. IP Forensics & Anonymizer Routing (Tor Exit Nodes, Datacenter Proxies)
        ip_type = str(vector.get("ip_type", "")).lower().strip()
        origin_ip = str(vector.get("origin_ip", "")).strip()

        is_tor = (
            ip_type == "tor"
            or vector.get("is_tor", False)
            or (origin_ip and is_tor_exit_node(origin_ip))
        )
        is_proxy = (
            ip_type in ("proxy", "datacenter", "vpn")
            or vector.get("is_proxy", False)
            or (origin_ip and is_datacenter_proxy(origin_ip))
        )

        if is_tor:
            raw_score += TOR_EXIT_NODE_SCORE
            reasons.append({
                "code": "NET_TOR_EXIT_NODE_ORIGIN",
                "message": f"Originating IP ({origin_ip or 'Anonymized'}) is a confirmed Tor exit relay.",
                "weight": TOR_EXIT_NODE_SCORE,
                "evidence_path": "trace.hops[0].from_ip",
            })
        elif is_proxy:
            raw_score += DATACENTER_PROXY_SCORE
            reasons.append({
                "code": "NET_DATACENTER_PROXY_ORIGIN",
                "message": f"Originating IP ({origin_ip or 'Proxy'}) routes via a cloud datacenter/VPN CIDR.",
                "weight": DATACENTER_PROXY_SCORE,
                "evidence_path": "trace.hops[0].from_ip",
            })

        # 3. URL Risk & Machine Learning Classification
        url_risk = str(vector.get("url_risk", "")).lower().strip()
        is_url_phishing = (
            url_risk in ("high", "malicious", "phishing")
            or vector.get("is_malicious_url", False)
        )

        if is_url_phishing:
            raw_score += URL_ML_PHISHING_SCORE
            reasons.append({
                "code": "ML_PHISHING_URL_DETECTED",
                "message": "Random Forest URL Classifier flagged high phishing probability for link target.",
                "weight": URL_ML_PHISHING_SCORE,
                "evidence_path": "message.urls[0].raw",
            })
        elif url_risk == "medium":
            raw_score += 15
            reasons.append({
                "code": "URL_ELEVATED_RISK",
                "message": "URL contains suspicious lexical or structural patterns.",
                "weight": 15,
                "evidence_path": "message.urls[0].raw",
            })

        if vector.get("is_trampoline", False) or "trampoline" in vector.get("evasion_type", ""):
            raw_score += TRAMPOLINE_REDIRECT_SCORE
            reasons.append({
                "code": "TRAMPOLINE_REDIRECT",
                "message": "Open redirect trampoline wrapper detected targeting external destination.",
                "weight": TRAMPOLINE_REDIRECT_SCORE,
                "evidence_path": "message.urls[0].raw",
            })

        if vector.get("is_obfuscated", False) or "obfuscated" in vector.get("evasion_type", ""):
            raw_score += OBFUSCATED_URL_SCORE
            reasons.append({
                "code": "OBFUSCATED_URL",
                "message": "Percent-encoded or masked URL structure detected.",
                "weight": OBFUSCATED_URL_SCORE,
                "evidence_path": "message.urls[0].raw",
            })

        # 4. Content & Intent Analysis (Urgency, Credential Harvest, Financial Coercion)
        keywords_type = str(vector.get("keywords", "")).lower().strip()
        body_text = str(vector.get("body_text", "")).lower()
        has_urgent_content = (
            keywords_type in ("urgent", "financial", "wire", "credential", "threat")
            or any(kw in body_text for kw in ["urgent", "immediately", "wire transfer", "password", "suspend"])
            or vector.get("has_urgent_keywords", False)
        )

        if has_urgent_content:
            raw_score += URGENT_PAYMENT_SCORE
            reasons.append({
                "code": "CONTENT_URGENT_PAYMENT_OR_CREDENTIAL",
                "message": "High-pressure urgency, financial transfer, or credential harvest language detected.",
                "weight": URGENT_PAYMENT_SCORE,
                "evidence_path": "message.body_text",
            })

        # 5. Identity Spoofing & Header Inconsistencies
        is_spoofed = (
            vector.get("spoofed_display", False)
            or vector.get("display_name_spoofed", False)
            or str(vector.get("display_name", "")).lower().strip() in ("spoofed", "mismatch")
        )
        if is_spoofed:
            raw_score += SPOOFED_DISPLAY_SCORE
            reasons.append({
                "code": "IDENTITY_DISPLAY_NAME_SPOOF",
                "message": "Display name impersonates trusted entity or executive identity.",
                "weight": SPOOFED_DISPLAY_SCORE,
                "evidence_path": "message.from.name",
            })

        if vector.get("reply_to_mismatch", False):
            raw_score += REPLY_TO_MISMATCH_SCORE
            reasons.append({
                "code": "IDENTITY_REPLY_TO_MISMATCH",
                "message": "Reply-To header routes responses to an external mismatched domain.",
                "weight": REPLY_TO_MISMATCH_SCORE,
                "evidence_path": "message.reply_to",
            })

        if vector.get("lookalike_domain", False):
            raw_score += LOOKALIKE_DOMAIN_SCORE
            reasons.append({
                "code": "IDENTITY_LOOKALIKE_DOMAIN",
                "message": "Sender domain is a lookalike/typosquatted variation of a trusted domain.",
                "weight": LOOKALIKE_DOMAIN_SCORE,
                "evidence_path": "message.from.address",
            })

        if vector.get("punycode_domain", False):
            raw_score += PUNYCODE_DOMAIN_SCORE
            reasons.append({
                "code": "IDENTITY_PUNYCODE_DOMAIN",
                "message": "Domain uses IDN Punycode character masking ('xn--').",
                "weight": PUNYCODE_DOMAIN_SCORE,
                "evidence_path": "message.from.address",
            })

        # 6. Attachment Threat Vectors
        attachment = vector.get("attachment")
        if attachment:
            fname = str(attachment.get("filename", "")).lower() if isinstance(attachment, dict) else str(attachment).lower()
            ctype = str(attachment.get("content_type", "")).lower() if isinstance(attachment, dict) else ""
            if (
                any(fname.endswith(ext) for ext in [".exe", ".iso", ".vbs", ".hta", ".scr", ".ps1", ".xlsm", ".lnk", ".bat", ".cmd", ".js", ".msi", ".zip", ".rar", ".7z"])
                or any(ct in ctype for ct in ["application/x-msdownload", "application/x-dosexec", "application/x-executable", "application/x-iso9660-image", "text/vbscript", "application/hta", "application/zip"])
            ):
                raw_score += SUSPICIOUS_ATTACHMENT_SCORE
                reasons.append({
                    "code": "ATTACHMENT_SUSPICIOUS_EXTENSION",
                    "message": f"Dangerous executable/script attachment extension detected ({fname}).",
                    "weight": SUSPICIOUS_ATTACHMENT_SCORE,
                    "evidence_path": "message.attachments[0].filename",
                })

        # 7. Additional Context Anomalies
        if vector.get("header_anomaly", False):
            raw_score += HEADER_ANOMALY_SCORE
            reasons.append({
                "code": "HEADER_ANOMALY",
                "message": "RFC header syntax anomaly or corrupted routing tokens.",
                "weight": HEADER_ANOMALY_SCORE,
                "evidence_path": "warnings[0].code",
            })

        if vector.get("reused_indicator", False):
            raw_score += REUSED_INDICATOR_SCORE
            reasons.append({
                "code": "CONTEXT_REUSED_INDICATOR",
                "message": "Observed infrastructure links to previously flagged phishing campaigns.",
                "weight": REUSED_INDICATOR_SCORE,
                "evidence_path": "trace.reused_indicator",
            })

        # Strict clamping between 0 and 100
        final_score = max(0, min(MAX_SCORE, raw_score))

        # Band determination
        if final_score <= LOW_MAX_SCORE:
            band = "LOW"
        elif final_score <= REVIEW_MAX_SCORE:
            band = "REVIEW"
        else:
            band = "HIGH"

        return {
            "score": final_score,
            "raw_score": raw_score,
            "band": band,
            "is_high_risk": final_score >= 70,
            "is_benign": final_score < 30,
            "is_review": 30 <= final_score < 70,
            "reasons": reasons,
            "reason_codes": [r["code"] for r in reasons],
        }

    def evaluate_email(self, parsed_email: ParsedEmail) -> Dict[str, Any]:
        """Evaluates a ParsedEmail instance using the ThreatDetector framework."""
        from backend.detection.detection import ThreatDetector
        detector = ThreatDetector()
        res = detector.analyze(parsed_email)
        score = res.get("score", 0)
        return {
            "score": score,
            "band": res.get("band", "LOW"),
            "is_high_risk": score >= 70,
            "is_benign": score < 30,
            "is_review": 30 <= score < 70,
            "reason_codes": [r.get("code") for r in res.get("reason_codes", [])],
            "limitations": res.get("limitations", []),
        }

    def evaluate(self, target: Union[Dict[str, Any], ParsedEmail]) -> Dict[str, Any]:
        """Universal evaluation dispatcher for dict vectors or ParsedEmail objects."""
        if isinstance(target, ParsedEmail):
            return self.evaluate_email(target)
        elif isinstance(target, dict):
            return self.evaluate_vector(target)
        else:
            raise TypeError(f"Unsupported evaluation target type: {type(target)}")


# Singleton instance
_global_scoring_engine: Optional[ThreatScoringEngine] = None


def get_scoring_engine() -> ThreatScoringEngine:
    """Returns or initializes the ThreatScoringEngine singleton."""
    global _global_scoring_engine
    if _global_scoring_engine is None:
        _global_scoring_engine = ThreatScoringEngine()
    return _global_scoring_engine


def score_threat_vector(vector: Union[Dict[str, Any], ParsedEmail]) -> Dict[str, Any]:
    """Public helper function to score an attack vector or email object."""
    engine = get_scoring_engine()
    return engine.evaluate(vector)


def evaluate_threat_vector(vector: Union[Dict[str, Any], ParsedEmail]) -> Dict[str, Any]:
    """Alias for score_threat_vector."""
    return score_threat_vector(vector)
