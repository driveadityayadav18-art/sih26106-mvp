import hashlib
import json
import os
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    load_dotenv(os.path.join(backend_dir, ".env"))
    load_dotenv(os.path.join(backend_dir, ".env.local"), override=True)
    load_dotenv()
except Exception:
    pass

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from groq import Groq

# Initialize Groq client
try:
    groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
except Exception:
    groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY") or "")

app = FastAPI(
    title="TraceShield MVP Backend",
    version="0.1.0",
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

# In-memory case storage for prototype correlation
case_db: List[Dict[str, Any]] = []

URL_REGEX = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
DEMO_INTEL_PATH = os.path.join(os.path.dirname(__file__), "data", "demo_intel.json")


def _load_demo_intel() -> Dict[str, Any]:
    """Loads demo intelligence cache from data/demo_intel.json without external network calls."""
    if os.path.exists(DEMO_INTEL_PATH):
        try:
            with open(DEMO_INTEL_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def parse_email(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Parses raw .eml email bytes using Python's standard email library.
    Extracts headers (from, reply_to, return_path, subject) and plain text body URLs.
    Does not execute, fetch URLs, or modify the raw bytes.
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception:
        # Fallback if bytes parser encounters malformed input
        msg = BytesParser().parsebytes(raw_bytes)

    # 1. From (sender's email address and display name if present)
    from_header = str(msg.get("From", "") or "")
    display_name, email_address = parseaddr(from_header)
    from_data = {
        "name": display_name if display_name else None,
        "address": email_address if email_address else (from_header if from_header else None),
    }

    # 2. Reply-To
    reply_to_header = str(msg.get("Reply-To", "") or "")
    _, reply_to_addr = parseaddr(reply_to_header)
    reply_to = reply_to_addr if reply_to_addr else (reply_to_header if reply_to_header else None)

    # 3. Return-Path
    return_path_header = str(msg.get("Return-Path", "") or "")
    _, return_path_addr = parseaddr(return_path_header)
    return_path = return_path_addr if return_path_addr else (return_path_header if return_path_header else None)

    # 4. Subject
    subject_raw = msg.get("Subject")
    subject = str(subject_raw) if subject_raw is not None else None

    # 5. Extract Plain Text Body & URLs
    body_text_parts: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", "") or "")
            if content_type == "text/plain" and "attachment" not in content_disposition.lower():
                try:
                    payload = part.get_content()
                    if isinstance(payload, str):
                        body_text_parts.append(payload)
                    elif isinstance(payload, bytes):
                        body_text_parts.append(payload.decode(errors="replace"))
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text_parts.append(payload.decode(errors="replace"))
    else:
        try:
            payload = msg.get_content()
            if isinstance(payload, str):
                body_text_parts.append(payload)
            elif isinstance(payload, bytes):
                body_text_parts.append(payload.decode(errors="replace"))
        except Exception:
            payload = msg.get_payload(decode=True)
            if payload:
                body_text_parts.append(payload.decode(errors="replace"))

    body_text = "\n".join(body_text_parts)

    # Find unique URLs in plain text body (without fetching)
    found_urls = URL_REGEX.findall(body_text)
    urls = list(dict.fromkeys(found_urls))

    # 6. Extract SPF and DKIM indicators if present in headers
    auth_results_header = str(msg.get("Authentication-Results", "") or "").lower()
    received_spf_header = str(msg.get("Received-SPF", "") or "").lower()

    spf_val = "none"
    if "spf=pass" in auth_results_header or received_spf_header.startswith("pass"):
        spf_val = "pass"
    elif "spf=fail" in auth_results_header or received_spf_header.startswith("fail") or received_spf_header.startswith("softfail"):
        spf_val = "fail"

    dkim_val = "none"
    if "dkim=pass" in auth_results_header:
        dkim_val = "pass"
    elif "dkim=fail" in auth_results_header:
        dkim_val = "fail"

    return {
        "from": from_data,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "urls": urls,
        "spf": spf_val,
        "dkim": dkim_val,
        "authentication": {
            "spf": spf_val,
            "dkim": dkim_val,
        },
    }


TRUSTED_DOMAINS: Set[str] = {
    "youtube.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "techcrunch.com",
    "google.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "facebook.com",
    "instagram.com",
    "beehiiv.com",
    "mailchimp.com",
    "substack.com",
}


def _is_trusted_domain(domain: Optional[str]) -> bool:
    """Checks if a domain is a known trusted domain or subdomain thereof."""
    if not domain:
        return False
    domain = domain.lower().strip()
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False


def _extract_auth_status(auth_val: Any) -> str:
    """Extract lowercase status string from a string or dict auth descriptor."""
    if not auth_val:
        return ""
    if isinstance(auth_val, str):
        return auth_val.strip().lower()
    if isinstance(auth_val, dict):
        return str(auth_val.get("result", "") or "").strip().lower()
    return ""


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


def analyze_risk(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes normalized parsed email signals and calculates an explainable risk assessment.
    
    Deterministic Rules:
    1. REPLY_TO_MISMATCH / REPLY_TO_ESP_MISMATCH:
       - If Reply-To domain differs from From domain:
         - If SPF or DKIM is 'pass' (authenticated sender / ESP relay):
           adds +5 points (lower weight), emits REPLY_TO_ESP_MISMATCH with authenticated ESP relay evidence.
         - If SPF and DKIM are 'fail' or 'none':
           adds +50 points, emits REPLY_TO_MISMATCH.
    2. URGENT_SUBJECT (+20): Subject contains the word 'URGENT' (case-insensitive).
    3. SUSPICIOUS_URL (+20 for untrusted external domains):
       - If URL belongs to a known trusted domain (e.g., youtube.com, twitter.com, linkedin.com, techcrunch.com),
         no penalty is added.
       - If URL domain differs from From domain and is unknown/phishing-like, adds +20 points, emits SUSPICIOUS_URL.
    
    Risk Bands:
    - HIGH: score >= 70
    - REVIEW: 30 <= score < 70
    - LOW: score < 30
    """
    score = 0
    reason_codes: List[Dict[str, str]] = []

    from_domain = _extract_email_domain(parsed_email.get("from"))
    reply_to_domain = _extract_email_domain(parsed_email.get("reply_to"))
    subject = parsed_email.get("subject")
    urls = parsed_email.get("urls") or []

    # Authentication resolution (SPF / DKIM)
    spf_status = _extract_auth_status(parsed_email.get("spf"))
    dkim_status = _extract_auth_status(parsed_email.get("dkim"))
    if not spf_status and not dkim_status and isinstance(parsed_email.get("authentication"), dict):
        auth_dict = parsed_email.get("authentication") or {}
        spf_status = _extract_auth_status(auth_dict.get("spf"))
        dkim_status = _extract_auth_status(auth_dict.get("dkim"))

    is_authenticated = (spf_status == "pass" or dkim_status == "pass")

    # Rule 1: REPLY_TO_MISMATCH vs REPLY_TO_ESP_MISMATCH
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        if is_authenticated:
            score += 5
            reason_codes.append({
                "code": "REPLY_TO_ESP_MISMATCH",
                "title": "Reply destination differs from sender domain (Authenticated ESP relay)",
                "evidence_path": "message.reply_to (authenticated ESP relay)",
            })
        else:
            score += 50
            reason_codes.append({
                "code": "REPLY_TO_MISMATCH",
                "title": "Reply destination differs from visible sender domain",
                "evidence_path": "message.reply_to",
            })

    # Rule 2: URGENT_SUBJECT (+20)
    if isinstance(subject, str) and re.search(r"\burgent\b", subject, re.IGNORECASE):
        score += 20
        reason_codes.append({
            "code": "URGENT_SUBJECT",
            "title": "Urgent language detected in subject line",
            "evidence_path": "message.subject",
        })

    # Rule 3: SUSPICIOUS_URL (+20 for untrusted external domains)
    if from_domain and isinstance(urls, list):
        has_suspicious_url = False
        for u in urls:
            u_domain = _extract_url_domain(u)
            if u_domain and u_domain != from_domain:
                # Do not penalize known trusted domains
                if not _is_trusted_domain(u_domain):
                    has_suspicious_url = True
                    break
        if has_suspicious_url:
            score += 20
            reason_codes.append({
                "code": "SUSPICIOUS_URL",
                "title": "External URL domain differs from sender domain",
                "evidence_path": "message.urls",
            })

    # Clamping score to 0-100
    clamped_score = max(0, min(100, score))

    # Determine risk band
    if clamped_score >= 70:
        band = "HIGH"
    elif clamped_score >= 30:
        band = "REVIEW"
    else:
        band = "LOW"

    return {
        "score": clamped_score,
        "band": band,
        "reason_codes": reason_codes,
    }


def enrich_and_correlate(parsed_email: Dict[str, Any], case_db: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Enriches observable email indicators using local cached demo intelligence and correlates
    the current case with prior cases in case_db via exact shared indicators.
    
    Returns:
    - infrastructure: indicators, approximate geo context, provider status
    - campaign: related case IDs, shared indicators, graph nodes and edges
    """
    demo_intel = _load_demo_intel()
    
    # 1. Intelligence: extract domains from reply_to and urls
    indicators: List[Dict[str, Any]] = []
    geo: List[Dict[str, Any]] = []
    observed_domains: List[str] = []
    
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

    # 2. Campaign Correlation: compare reply_to domain with prior cases in case_db
    related_case_ids: List[str] = []
    shared_indicators: List[Dict[str, Any]] = []
    graph_nodes: List[Dict[str, Any]] = []
    graph_edges: List[Dict[str, Any]] = []
    seen_node_ids: Set[str] = set()

    current_case_id = f"TS-DEMO-{len(case_db) + 1:03d}"

    if reply_to_domain:
        for prior_case in case_db:
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
    Tier 2 LLM Review using Groq SDK.
    Evaluates potential false positives (e.g. ESP Reply-To mismatches or trusted domains).
    """
    try:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            return {"error": "LLM review unavailable"}

        client = groq_client
        if not getattr(client, "api_key", None) or client.api_key == "":
            client = Groq(api_key=api_key)

        system_prompt = (
            "You are a Senior Email Security Analyst. A Tier 1 rules engine has flagged this email with a risk score. "
            "Your job is to review the context and determine if this is a false positive. Specifically, check if the email "
            "is from a known Email Service Provider (ESP) like Beehiiv, Substack, or Mailchimp where a Reply-To mismatch is normal. "
            "Check if URLs are trusted domains like YouTube or LinkedIn. Return your final verdict as a strict JSON object with "
            'these keys: "is_false_positive" (boolean), "adjusted_score" (int 0-100), "adjusted_band" ("LOW"|"REVIEW"|"HIGH"), '
            'and "analyst_summary" (string explaining your reasoning).'
        )

        user_content = json.dumps(
            {
                "parsed_email": {
                    "Subject": parsed_email.get("subject"),
                    "From": parsed_email.get("from"),
                    "Reply-To": parsed_email.get("reply_to"),
                    "URLs": parsed_email.get("urls") or [],
                },
                "rule_risk": rule_risk,
            },
            indent=2,
        )

        # Support configurable model with intelligent fallbacks
        models_to_try = [
            os.environ.get("GROQ_MODEL"),
            "openai/gpt-oss-120b",
            "qwen/qwen3.8-27b",
            "llama-3.3-70b-versatile",
            "llama3-70b-8192",
        ]
        models_to_try = [m for m in dict.fromkeys(models_to_try) if m]

        chat_completion = None
        last_err = None
        for model_name in models_to_try:
            try:
                chat_completion = client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_content},
                    ],
                    model=model_name,
                    response_format={"type": "json_object"},
                )
                if chat_completion and chat_completion.choices:
                    break
            except Exception as err:
                last_err = err
                continue

        if not chat_completion or not chat_completion.choices:
            if last_err:
                print(f"[Tier 2 LLM Review Error]: {last_err}")
            return {"error": "LLM review unavailable"}

        content = chat_completion.choices[0].message.content
        if not content:
            return {"error": "LLM review unavailable"}

        return json.loads(content)
    except Exception as e:
        print(f"[Tier 2 LLM Review Error]: {e}")
        return {"error": "LLM review unavailable"}


@app.get("/api/v1/health")
async def health_check():
    return {"status": "ok"}


@app.post("/api/v1/cases")
async def create_case(file: UploadFile = File(...)):
    content = await file.read()
    calculated_hash = hashlib.sha256(content).hexdigest()
    
    # 1. Run parser
    parsed_message = parse_email(content)
    
    # 2. Run risk analyzer
    risk_assessment = analyze_risk(parsed_message)
    
    # 3. Run enrich_and_correlate
    enrichment = enrich_and_correlate(parsed_message, case_db)

    # 4. Tier 2 LLM Review (if risk score >= 70)
    ai_review = None
    if risk_assessment.get("score", 0) >= 70:
        ai_review = await tier_2_llm_review(parsed_message, risk_assessment)
    
    # 5. Assemble final CaseAnalysis JSON
    case_id = f"TS-DEMO-{len(case_db) + 1:03d}"
    case_record = {
        "case_id": case_id,
        "artifact": {
            "sha256": calculated_hash,
            "is_demo_data": True,
        },
        "message": parsed_message,
        "risk": risk_assessment,
        "ai_review": ai_review,
        "infrastructure": enrichment["infrastructure"],
        "campaign": enrichment["campaign"],
    }
    
    # 6. Append to in-memory case_db for subsequent correlation
    case_db.append(case_record)
    
    return case_record
