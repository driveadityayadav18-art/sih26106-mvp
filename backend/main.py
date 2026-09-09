import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

# Ensure local backend and root paths are resolvable
backend_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(backend_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(backend_dir, ".env"))
    load_dotenv(os.path.join(backend_dir, ".env.local"), override=True)
    load_dotenv()
except Exception:
    pass

from fastapi import FastAPI, File, HTTPException, UploadFile, status, Response
from fastapi.middleware.cors import CORSMiddleware
from groq import Groq

# Person 2 & 3 integrations: Forensic Parser and Threat Detection
from backend.parser.email_parser import EmailParser
from backend.parser.models import (
    ParsedEmail,
    URLMetadata,
    AttachmentMetadata,
)
from backend.evidence.hashing import calculate_sha256, get_byte_length
from backend.detection.detection import ThreatDetector
from backend.detection.context import DetectionContext, ReusedIndicator
from backend.detectors.url_ml import predict_url_risk
try:
    from backend.utils.pii_masker import mask_pii
    from backend.services.llm_analysis import run_tier_2_llm_review, sanitize_email_for_llm
except ImportError:
    from utils.pii_masker import mask_pii
    from services.llm_analysis import run_tier_2_llm_review, sanitize_email_for_llm
try:
    from backend.services.geo_ip import detect_anonymizer
except ImportError:
    from services.geo_ip import detect_anonymizer
try:
    from db import init_db, save_case, get_case, list_cases, get_all_cases, count_cases, clear_cases, get_max_case_number, quarantine_case
except ImportError:
    from backend.db import init_db, save_case, get_case, list_cases, get_all_cases, count_cases, clear_cases, get_max_case_number, quarantine_case

try:
    from reporting.report_generator import generate_markdown_report, generate_html_report, generate_json_report
except ImportError:
    from backend.reporting.report_generator import generate_markdown_report, generate_html_report, generate_json_report

# Initialize Groq client
try:
    groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
except Exception:
    groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY") or "")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="TraceShield MVP Backend",
    version="0.1.0",
    lifespan=lifespan,
)

# Enable CORS so frontend on localhost:3000 can talk to it
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Deprecated in-memory store; SQLite via db.py is the primary source of truth.
# Retained as an in-memory shadow for backward-compatible module references.
case_db: List[Dict[str, Any]] = []

URL_REGEX = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
DEMO_INTEL_PATH = os.path.join(os.path.dirname(__file__), "data", "demo_intel.json")
ARTIFACTS_DIR = os.environ.get(
    "ARTIFACTS_DIR",
    os.path.join(parent_dir, "data", "artifacts"),
)


def _load_demo_intel() -> Dict[str, Any]:
    """Loads demo intelligence cache from data/demo_intel.json without external network calls."""
    if os.path.exists(DEMO_INTEL_PATH):
        try:
            with open(DEMO_INTEL_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}



def _build_detection_context(current_case_id: str, prior_cases: Optional[List[Dict[str, Any]]] = None) -> DetectionContext:
    """Builds DetectionContext from existing SQLite cases (or passed prior_cases) to detect reused indicators."""
    if prior_cases is None:
        prior_cases = get_all_cases()
    reused: List[ReusedIndicator] = []
    for c in prior_cases:
        c_id = c.get("case_id")
        if not c_id or c_id == current_case_id:
            continue
        c_msg = c.get("message") or {}

        c_from = _extract_email_domain(c_msg.get("from"))
        if c_from:
            reused.append(ReusedIndicator(
                indicator_type="domain",
                value=c_from,
                related_case_ids=[c_id],
                source=f"case_store:{c_id}.message.from",
            ))

        c_reply = _extract_email_domain(c_msg.get("reply_to"))
        if c_reply:
            reused.append(ReusedIndicator(
                indicator_type="domain",
                value=c_reply,
                related_case_ids=[c_id],
                source=f"case_store:{c_id}.message.reply_to",
            ))

        for u in c_msg.get("urls") or []:
            u_str = u if isinstance(u, str) else (u.get("raw", "") if isinstance(u, dict) else "")
            if u_str:
                reused.append(ReusedIndicator(
                    indicator_type="url",
                    value=u_str,
                    related_case_ids=[c_id],
                    source=f"case_store:{c_id}.message.urls",
                ))
                u_host = _extract_url_domain(u_str)
                if u_host:
                    reused.append(ReusedIndicator(
                        indicator_type="domain",
                        value=u_host,
                        related_case_ids=[c_id],
                        source=f"case_store:{c_id}.message.urls.host",
                    ))

        for att in c_msg.get("attachments") or []:
            if isinstance(att, dict) and att.get("sha256"):
                reused.append(ReusedIndicator(
                    indicator_type="attachment_sha256",
                    value=att["sha256"],
                    related_case_ids=[c_id],
                    source=f"case_store:{c_id}.message.attachments.sha256",
                ))

    return DetectionContext(reused_indicators=reused, current_case_id=current_case_id)



def _extract_email_domain(email_val: Any) -> Optional[str]:
    """Extract lowercase domain from email address string or dict."""
    if not email_val:
        return None
    if isinstance(email_val, dict):
        email_val = email_val.get("address") or ""
    if not isinstance(email_val, str):
        return None
    email_val = email_val.strip()
    if "@" in email_val:
        domain = email_val.split("@")[-1].strip().lower()
        return domain if domain else None
    return None


def _extract_url_domain(url_val: str) -> Optional[str]:
    """Extract lowercase host/domain from a URL string without network calls."""
    if not url_val or not isinstance(url_val, str):
        return None
    try:
        parsed = urlparse(url_val.strip())
        netloc = parsed.netloc or parsed.path
        if "@" in netloc:
            netloc = netloc.split("@")[-1]
        if ":" in netloc:
            netloc = netloc.split(":")[0]
        netloc = netloc.strip().lower()
        return netloc if netloc else None
    except Exception:
        return None



def enrich_and_correlate(parsed_email: Dict[str, Any], prior_cases: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Enriches observable email indicators using local cached demo intelligence and correlates
    the current case with prior cases in SQLite via exact shared indicators.
    
    Returns:
    - infrastructure: indicators, approximate geo context, provider status
    - campaign: related case IDs, shared indicators, graph nodes and edges
    """
    if prior_cases is None:
        prior_cases = get_all_cases()
    demo_intel = _load_demo_intel()
    
    # 1. Intelligence: extract domains and originating IP
    indicators: List[Dict[str, Any]] = []
    geo: List[Dict[str, Any]] = []
    observed_domains: List[str] = []

    origin_ip = parsed_email.get("origin_ip")
    if not origin_ip:
        trace_data = parsed_email.get("trace") or {}
        for hop in trace_data.get("hops") or []:
            f_ip = hop.get("from_ip") if isinstance(hop, dict) else getattr(hop, "from_ip", None)
            if f_ip:
                try:
                    ip_cand = ipaddress.ip_address(f_ip)
                    if not ip_cand.is_private and not ip_cand.is_loopback:
                        origin_ip = f_ip
                        break
                except Exception:
                    pass

    if origin_ip:
        indicators.append({
            "type": "ip",
            "value": origin_ip,
            "source": "originating_relay_hop",
        })
        if origin_ip in demo_intel:
            intel_entry = demo_intel[origin_ip]
            geo.append({
                "indicator": origin_ip,
                "country": intel_entry.get("country"),
                "city": intel_entry.get("city"),
                "provider": intel_entry.get("provider", "demo_cache"),
                "accuracy_caveat": "Originating sender IP resolved from earliest relay hop header.",
            })
        else:
            anon = detect_anonymizer(origin_ip)
            if anon.get("is_tor"):
                geo.append({
                    "indicator": origin_ip,
                    "country": "Tor Anonymization Network",
                    "city": "Tor Exit Relay",
                    "provider": "TorProject / Onion Router",
                    "accuracy_caveat": "High-risk Tor Exit Node. True sender IP obfuscated by onion routing.",
                })
            elif anon.get("is_proxy"):
                geo.append({
                    "indicator": origin_ip,
                    "country": "Cloud / Datacenter Infrastructure",
                    "city": "Datacenter Proxy Node",
                    "provider": "Datacenter Proxy / Hosting",
                    "accuracy_caveat": "Originates from known cloud hosting / VPN proxy CIDR infrastructure.",
                })
            else:
                geo.append({
                    "indicator": origin_ip,
                    "country": "External Public Network",
                    "city": "Unknown",
                    "provider": "Autonomous System Relay",
                    "accuracy_caveat": "Observable infrastructure context; external relay hop.",
                })

    reply_to_domain = _extract_email_domain(parsed_email.get("reply_to"))
    if reply_to_domain and reply_to_domain not in observed_domains:
        observed_domains.append(reply_to_domain)

    for url in parsed_email.get("urls") or []:
        u_domain = _extract_url_domain(url)
        if u_domain and u_domain not in observed_domains:
            observed_domains.append(u_domain)

    for domain in observed_domains:
        indicators.append({
            "type": "domain",
            "value": domain,
            "source": "normalized_email_evidence",
        })
        if domain in demo_intel:
            intel_entry = demo_intel[domain]
            geo.append({
                "indicator": domain,
                "country": intel_entry.get("country"),
                "city": intel_entry.get("city"),
                "provider": intel_entry.get("provider", "demo_cache"),
                "accuracy_caveat": "Approximate infrastructure context; not human attribution.",
            })

    infrastructure = {
        "indicators": indicators,
        "geo": geo,
        "provider_status": "demo_cache",
    }

    # 2. Campaign Correlation: compare reply_to domain and origin_ip with prior cases
    related_case_ids: List[str] = []
    shared_indicators: List[Dict[str, Any]] = []
    graph_nodes: List[Dict[str, Any]] = []
    graph_edges: List[Dict[str, Any]] = []
    seen_node_ids: Set[str] = set()

    current_case_id = parsed_email.get("case_id") or f"TS-DEMO-{len(prior_cases) + 1:03d}"

    if reply_to_domain:
        for prior_case in prior_cases:
            prior_message = prior_case.get("message") or {}
            prior_reply_domain = _extract_email_domain(prior_message.get("reply_to"))

            if prior_reply_domain and prior_reply_domain == reply_to_domain:
                prior_id = prior_case.get("case_id", "UNKNOWN_CASE")
                if prior_id not in related_case_ids:
                    related_case_ids.append(prior_id)

                # Register current case node
                current_node_id = f"case:{current_case_id}"
                if current_node_id not in seen_node_ids:
                    graph_nodes.append({
                        "id": current_node_id,
                        "type": "case",
                        "label": current_case_id,
                    })
                    seen_node_ids.add(current_node_id)

                # Register shared indicator node
                domain_node_id = f"domain:{reply_to_domain}"
                if domain_node_id not in seen_node_ids:
                    graph_nodes.append({
                        "id": domain_node_id,
                        "type": "domain",
                        "label": reply_to_domain,
                        "source": "normalized_email_evidence",
                    })
                    seen_node_ids.add(domain_node_id)

                # Register prior case node
                prior_node_id = f"case:{prior_id}"
                if prior_node_id not in seen_node_ids:
                    graph_nodes.append({
                        "id": prior_node_id,
                        "type": "case",
                        "label": prior_id,
                    })
                    seen_node_ids.add(prior_node_id)

                # Add graph edges connecting cases to the shared indicator
                graph_edges.append({
                    "source": current_node_id,
                    "target": domain_node_id,
                    "type": "SHARED_REPLY_DOMAIN",
                    "evidence": ["message.reply_to"],
                })
                graph_edges.append({
                    "source": prior_node_id,
                    "target": domain_node_id,
                    "type": "SHARED_REPLY_DOMAIN",
                    "evidence": ["message.reply_to"],
                })

        if related_case_ids:
            shared_indicators.append({
                "type": "domain",
                "value": reply_to_domain,
                "relationship": "SHARED_REPLY_DOMAIN",
            })

    if origin_ip:
        for prior_case in prior_cases:
            prior_message = prior_case.get("message") or {}
            prior_origin = prior_message.get("origin_ip")
            if prior_origin and prior_origin == origin_ip:
                prior_id = prior_case.get("case_id", "UNKNOWN_CASE")
                if prior_id not in related_case_ids:
                    related_case_ids.append(prior_id)

                current_node_id = f"case:{current_case_id}"
                if current_node_id not in seen_node_ids:
                    graph_nodes.append({
                        "id": current_node_id,
                        "type": "case",
                        "label": current_case_id,
                    })
                    seen_node_ids.add(current_node_id)

                ip_node_id = f"ip:{origin_ip}"
                if ip_node_id not in seen_node_ids:
                    graph_nodes.append({
                        "id": ip_node_id,
                        "type": "ip",
                        "label": origin_ip,
                        "source": "originating_relay_hop",
                    })
                    seen_node_ids.add(ip_node_id)

                prior_node_id = f"case:{prior_id}"
                if prior_node_id not in seen_node_ids:
                    graph_nodes.append({
                        "id": prior_node_id,
                        "type": "case",
                        "label": prior_id,
                    })
                    seen_node_ids.add(prior_node_id)

                graph_edges.append({
                    "source": current_node_id,
                    "target": ip_node_id,
                    "type": "SHARED_ORIGIN_IP",
                    "evidence": ["trace.hops[0].from_ip"],
                })
                graph_edges.append({
                    "source": prior_node_id,
                    "target": ip_node_id,
                    "type": "SHARED_ORIGIN_IP",
                    "evidence": ["trace.hops[0].from_ip"],
                })

        if any((c.get("message") or {}).get("origin_ip") == origin_ip for c in prior_cases):
            shared_indicators.append({
                "type": "ip",
                "value": origin_ip,
                "relationship": "SHARED_ORIGIN_IP",
            })

    campaign = {
        "related_case_ids": related_case_ids,
        "shared_indicators": shared_indicators,
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
    }

    return {
        "infrastructure": infrastructure,
        "campaign": campaign,
    }


async def tier_2_llm_review(parsed_email: dict, rule_risk: dict) -> dict:
    """
    Tier 2 LLM Review using Groq SDK with automated PII masking.
    Evaluates potential false positives (e.g. ESP Reply-To mismatches or trusted domains).
    """
    return await run_tier_2_llm_review(parsed_email, rule_risk, client=groq_client)


@app.get("/api/v1/health")
async def health_check():
    return {"status": "ok"}


def get_next_case_id(artifacts_dir: Optional[str] = None) -> str:
    """
    Computes the next case ID using the high-watermark of existing IDs in both
    the SQLite database and the artifacts directory.
    If no cases exist, it returns 'TS-DEMO-001'.
    """
    max_num = get_max_case_number()

    target_dir = artifacts_dir or ARTIFACTS_DIR
    if os.path.isdir(target_dir):
        try:
            for fname in os.listdir(target_dir):
                m = re.match(r"TS-DEMO-(\d+)\.eml", fname, re.IGNORECASE)
                if m:
                    num = int(m.group(1))
                    if num > max_num:
                        max_num = num
        except Exception:
            pass

    next_num = max_num + 1
    candidate = f"TS-DEMO-{next_num:03d}"
    while get_case(candidate) is not None:
        next_num += 1
        candidate = f"TS-DEMO-{next_num:03d}"
    return candidate


@app.post("/api/v1/cases")
async def create_case(file: UploadFile = File(...)):
    raw_bytes = await file.read()
    calculated_hash = calculate_sha256(raw_bytes)
    byte_len = get_byte_length(raw_bytes)

    # High-watermark case ID generation across SQLite and disk storage
    case_id = get_next_case_id()

    try:
        os.makedirs(ARTIFACTS_DIR, exist_ok=True)
        artifact_path = os.path.join(ARTIFACTS_DIR, f"{case_id}.eml")
        with open(artifact_path, "wb") as f:
            f.write(raw_bytes)

        rel_artifacts_dir = os.path.abspath(os.path.join("data", "artifacts"))
        if rel_artifacts_dir != os.path.abspath(ARTIFACTS_DIR):
            os.makedirs(rel_artifacts_dir, exist_ok=True)
            with open(os.path.join(rel_artifacts_dir, f"{case_id}.eml"), "wb") as f:
                f.write(raw_bytes)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save email artifact: {str(e)}",
        )

    content = raw_bytes

    # 1. Run Person 2 Forensic Parser
    parser = EmailParser()
    try:
        parsed_email_obj = parser.parse(content)
    except Exception:
        parsed_email_obj = ParsedEmail()

    # 2. Extract originating IP and message dictionary for frontend and enrichment
    origin_ip = None
    if parsed_email_obj.trace.hops:
        for hop in parsed_email_obj.trace.hops:
            if hop.from_ip:
                try:
                    ip_cand = ipaddress.ip_address(hop.from_ip)
                    if not ip_cand.is_private and not ip_cand.is_loopback:
                        origin_ip = hop.from_ip
                        break
                except Exception:
                    pass
    if not origin_ip:
        for raw_hdr in parsed_email_obj.authentication.raw_authentication_headers:
            ip_m = re.search(r"sender\s+IP\s+is\s+([0-9a-fA-F:.]+)", raw_hdr, re.IGNORECASE)
            if ip_m:
                origin_ip = ip_m.group(1)
                break

    parsed_message = {
        "from": {
            "name": parsed_email_obj.message.from_.name,
            "address": parsed_email_obj.message.from_.address,
        },
        "reply_to": parsed_email_obj.message.reply_to,
        "return_path": parsed_email_obj.message.return_path,
        "message_id": parsed_email_obj.message.message_id,
        "origin_ip": origin_ip,
        "subject": parsed_email_obj.message.subject,
        "date": parsed_email_obj.message.date,
        "body_text": parsed_email_obj.message.body_text,
        "urls": [u.raw for u in parsed_email_obj.message.urls],
        "attachments": [a.to_dict() for a in parsed_email_obj.message.attachments],
        "spf": parsed_email_obj.authentication.spf.result,
        "dkim": parsed_email_obj.authentication.dkim.result,
        "dmarc": parsed_email_obj.authentication.dmarc.result,
        "authentication": {
            "spf": parsed_email_obj.authentication.spf.result,
            "dkim": parsed_email_obj.authentication.dkim.result,
            "dmarc": parsed_email_obj.authentication.dmarc.result,
            "compauth": parsed_email_obj.authentication.compauth,
        },
        "trace": parsed_email_obj.trace.to_dict(),
    }

    # 3. Build DetectionContext for cross-case indicator reuse from SQLite
    prior_cases = get_all_cases()
    detection_context = _build_detection_context(case_id, prior_cases)

    # 4. Run Person 3 Threat Detector Heuristics Engine
    detector = ThreatDetector()
    threat_result = detector.analyze(parsed_email_obj, detection_context)

    # Format reason codes for frontend UI (ensuring both 'title' and 'message')
    formatted_reasons = []
    for rc in threat_result.get("reason_codes", []):
        formatted_reasons.append({
            "code": rc.get("code", ""),
            "title": rc.get("message") or rc.get("title", ""),
            "message": rc.get("message") or rc.get("title", ""),
            "evidence_path": rc.get("evidence_path", ""),
            "weight": rc.get("weight", 0),
        })

    # Run ML inference on all extracted URLs
    url_ml_analysis = []
    for u in parsed_email_obj.message.urls:
        if u.raw:
            try:
                ml_res = predict_url_risk(u.raw)
                url_ml_analysis.append({
                    "url": u.raw,
                    "host": u.host,
                    "phishing_probability": ml_res.get("phishing_probability", 0.0),
                    "is_malicious": ml_res.get("is_malicious", False),
                    "top_risk_factors": ml_res.get("top_risk_factors", []),
                    "features": ml_res.get("features_extracted", {}),
                })
            except Exception:
                pass

    risk_assessment = {
        "score": threat_result.get("score", 0),
        "band": threat_result.get("band", "LOW"),
        "reason_codes": formatted_reasons,
        "limitations": threat_result.get("limitations", []),
        "url_ml_analysis": url_ml_analysis,
    }

    # 5. Run Intelligence Enrichment & Campaign Correlation from SQLite
    enrichment = enrich_and_correlate(parsed_message, prior_cases)

    # 6. Tier 2 Dynamic LLM Review & PII Sanitization Audit
    _, privacy_audit = sanitize_email_for_llm(parsed_message)
    should_trigger_llm = (
        risk_assessment.get("score", 0) >= 30
        or (
            parsed_email_obj.authentication.dmarc.result == "fail"
            and len(parsed_email_obj.message.urls) > 0
        )
        or any(
            rc.get("code") in ("OBFUSCATED_URL", "TRAMPOLINE_REDIRECT", "AUTH_COMPAUTH_FAIL", "EXTERNAL_URL_MISMATCH")
            for rc in risk_assessment.get("reason_codes", [])
        )
    )
    ai_review = None
    if should_trigger_llm:
        ai_review = await tier_2_llm_review(parsed_message, risk_assessment)
        if ai_review and "privacy_audit" in ai_review:
            privacy_audit = ai_review["privacy_audit"]

    # 7. Assemble final CaseAnalysis record matching schema
    case_record = {
        "case_id": case_id,
        "status": "ACTIVE",
        "artifact": {
            "sha256": calculated_hash,
            "byte_length": byte_len,
            "is_demo_data": True,
        },
        "message": parsed_message,
        "risk": risk_assessment,
        "ai_review": ai_review,
        "privacy_audit": privacy_audit,
        "infrastructure": enrichment["infrastructure"],
        "campaign": enrichment["campaign"],
        "trace": parsed_email_obj.trace.to_dict(),
        "warnings": [w.to_dict() for w in parsed_email_obj.warnings],
        "authentication": parsed_email_obj.authentication.to_dict(),
    }

    # 8. Persist to SQLite database as primary source of truth
    save_case(case_record)
    case_db.append(case_record)

    return case_record


@app.get("/api/v1/cases")
async def get_cases():
    cases = list_cases()
    return cases if cases is not None else []


@app.get("/api/v1/cases/{case_id}")
async def get_case_by_id(case_id: str):
    case = get_case(case_id)
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found",
        )
    return case


@app.post("/api/v1/cases/{case_id}/quarantine")
async def quarantine_case_endpoint(case_id: str):
    case = get_case(case_id)
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    # 1. Resolve Target Message-ID from parsed headers or fallback
    message = case.get("message") or {}
    target_message_id = (
        message.get("message_id")
        or (case.get("raw_headers", {}).get("message-id") if isinstance(case.get("raw_headers"), dict) else None)
        or f"<{case_id}@traceshield.internal>"
    )

    # 2. Resolve Originating IP address
    origin_ip = message.get("origin_ip")
    if not origin_ip:
        # Check infrastructure indicators
        infra = case.get("infrastructure") or {}
        for indicator in infra.get("indicators", []):
            if isinstance(indicator, dict) and indicator.get("type") == "ip" and indicator.get("value"):
                origin_ip = indicator.get("value")
                break
    if not origin_ip:
        # Check trace hops
        trace = case.get("trace") or message.get("trace") or {}
        for hop in trace.get("hops", []):
            if isinstance(hop, dict) and hop.get("from_ip"):
                origin_ip = hop.get("from_ip")
                break
    if not origin_ip:
        origin_ip = "198.51.100.24"

    # 3. Simulate and record IMAP mitigation action log
    timestamp = datetime.now(timezone.utc).isoformat()
    mitigation_log = {
        "action": "IMAP_STORE_FLAGS_DELETED",
        "target_message_id": target_message_id,
        "originating_ip_firewall_rule": f"iptables -A INPUT -s {origin_ip} -j DROP",
        "timestamp": timestamp,
        "status": "APPLIED_SUCCESSFULLY",
    }

    # 4. Update case in SQLite and in-memory shadow
    updated_case = quarantine_case(case_id, mitigation_log)
    if not updated_case:
        case["status"] = "QUARANTINED"
        case["mitigation"] = mitigation_log
        case["mitigation_log"] = mitigation_log
        save_case(case)
        updated_case = case

    # Update in-memory shadow case_db if present
    for idx, c in enumerate(case_db):
        if c.get("case_id") == case_id:
            case_db[idx] = updated_case
            break

    return updated_case


@app.get("/api/v1/cases/{case_id}/report")
async def get_case_report(case_id: str, format: str = "markdown", download: bool = False):
    case = get_case(case_id)
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found",
        )

    fmt = format.lower().strip()
    if fmt in ("markdown", "md"):
        content = generate_markdown_report(case)
        media_type = "text/markdown; charset=utf-8"
        filename = f"TraceShield_Report_{case_id}.md"
    elif fmt == "html":
        content = generate_html_report(case)
        media_type = "text/html; charset=utf-8"
        filename = f"TraceShield_Report_{case_id}.html"
    elif fmt == "json":
        report_data = generate_json_report(case)
        content = json.dumps(report_data, indent=2, ensure_ascii=False)
        media_type = "application/json; charset=utf-8"
        filename = f"TraceShield_Report_{case_id}.json"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format '{format}'. Supported formats: markdown, html, json",
        )

    disposition = "attachment" if download else ("inline" if fmt == "html" else "attachment")
    headers = {
        "Content-Disposition": f'{disposition}; filename="{filename}"'
    }
    return Response(content=content, media_type=media_type, headers=headers)


