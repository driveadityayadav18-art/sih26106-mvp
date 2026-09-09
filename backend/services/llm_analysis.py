import json
import os
from typing import Any, Dict, Optional, Tuple
from groq import Groq
from backend.utils.pii_masker import mask_pii


def sanitize_email_for_llm(parsed_email: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Sanitizes all text fields in parsed_email (subject, body_text, headers, etc.)
    using mask_pii to ensure zero sensitive PII is passed to third-party LLMs.
    """
    total_cards = 0
    total_phones = 0
    total_emails = 0
    total_aadhaar = 0

    def _mask_field(val: Any) -> Any:
        nonlocal total_cards, total_phones, total_emails, total_aadhaar
        if isinstance(val, str):
            masked_str, summary = mask_pii(val)
            total_cards += summary["cards_redacted"]
            total_phones += summary["phones_redacted"]
            total_emails += summary["emails_redacted"]
            total_aadhaar += summary["aadhaar_redacted"]
            return masked_str
        elif isinstance(val, dict):
            return {k: _mask_field(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [_mask_field(item) for item in val]
        return val

    sanitized = {}
    for k, v in (parsed_email or {}).items():
        sanitized[k] = _mask_field(v)

    total_masked = total_cards + total_phones + total_emails + total_aadhaar
    privacy_audit = {
        "pii_sanitized": True,
        "masked_entities_count": total_masked,
        "cards_redacted": total_cards,
        "phones_redacted": total_phones,
        "emails_redacted": total_emails,
        "aadhaar_redacted": total_aadhaar,
        "pii_detected": total_masked > 0,
    }
    return sanitized, privacy_audit


async def run_tier_2_llm_review(
    parsed_email: Dict[str, Any],
    rule_risk: Dict[str, Any],
    client: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Tier 2 LLM Review with automated PII sanitization.
    Evaluates potential false positives (e.g. ESP Reply-To mismatches or trusted domains).
    """
    sanitized_email, privacy_audit = sanitize_email_for_llm(parsed_email)

    try:
        api_key = os.environ.get("GROQ_API_KEY")
        llm_client = client
        if not llm_client:
            if not api_key:
                return {"error": "LLM review unavailable"}
            llm_client = Groq(api_key=api_key or "")

        system_prompt = (
            "You are a Senior Email Security and Threat Intelligence Analyst. A Tier 1 heuristic engine has analyzed this email.\n"
            "Your role is to provide a deterministic, calibrated forensic risk review.\n\n"
            "Forensic Calibration & Scoring Rubric:\n"
            "1. Benign False Positive (e.g. verified newsletters/ESP like Substack/Beehiiv/Mailchimp, standard service notifications with trusted domains and passing SPF/DKIM):\n"
            "   - is_false_positive: true\n"
            "   - adjusted_score: 5 to 25\n"
            "   - adjusted_band: 'LOW'\n"
            "2. Genuine Malicious Threat (e.g. credential harvesting, malicious links, open redirect trampolines, obfuscated scripts, urgent financial wire demands with mismatched sender/reply-to):\n"
            "   - is_false_positive: false\n"
            "   - adjusted_score: 75 to 100\n"
            "   - adjusted_band: 'HIGH'\n"
            "3. Ambiguous / Unsolicited Outreach / Grey-Area (e.g. unsolicited student or internship pitches, recruitment marketing from personal webmail like Gmail with passing SPF/DKIM but without credential theft, phishing links, or malicious payloads):\n"
            "   - is_false_positive: false\n"
            "   - adjusted_score: 40 to 50\n"
            "   - adjusted_band: 'REVIEW'\n\n"
            "Deterministic Band Scale:\n"
            "- 0 to 29: 'LOW'\n"
            "- 30 to 69: 'REVIEW'\n"
            "- 70 to 100: 'HIGH'\n\n"
            "Return a strict JSON object with exact keys:\n"
            '{\n'
            '  "is_false_positive": boolean,\n'
            '  "adjusted_score": integer (0-100),\n'
            '  "adjusted_band": "LOW" | "REVIEW" | "HIGH",\n'
            '  "analyst_summary": string explaining forensic evidence, intent analysis, and security posture\n'
            '}'
        )

        # Compact URLs and risk payload to prevent token limits on large emails
        raw_urls = sanitized_email.get("urls") or []
        sample_urls = []
        for u in raw_urls[:6]:
            if isinstance(u, dict):
                sample_urls.append(u.get("raw", str(u))[:150])
            else:
                sample_urls.append(str(u)[:150])

        reason_codes = [
            {
                "code": rc.get("code"),
                "title": rc.get("title") or rc.get("message"),
                "weight": rc.get("weight"),
            }
            for rc in (rule_risk.get("reason_codes") or [])[:10]
        ]
        compact_risk = {
            "score": rule_risk.get("score"),
            "band": rule_risk.get("band"),
            "reason_codes": reason_codes,
        }

        user_content = json.dumps(
            {
                "parsed_email": {
                    "Subject": sanitized_email.get("subject"),
                    "From": sanitized_email.get("from"),
                    "Reply-To": sanitized_email.get("reply_to"),
                    "Origin_IP": sanitized_email.get("origin_ip"),
                    "Sample_URLs": sample_urls,
                    "Total_URLs_Count": len(raw_urls),
                    "Authentication": sanitized_email.get("authentication"),
                    "Body_Preview": (sanitized_email.get("body_text") or "")[:500],
                },
                "rule_risk": compact_risk,
            },
            indent=2,
        )

        models_to_try = [
            os.environ.get("GROQ_MODEL"),
            "qwen/qwen3.8-27b",
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b",
            "qwen/qwen3.6-27b",
        ]
        models_to_try = [m for m in dict.fromkeys(models_to_try) if m]

        chat_completion = None
        last_err = None
        for model_name in models_to_try:
            try:
                chat_completion = llm_client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_content},
                    ],
                    model=model_name,
                    temperature=0.0,
                    seed=42,
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

        parsed_res = json.loads(content)
        # Enforce deterministic band threshold alignment
        try:
            raw_score = int(parsed_res.get("adjusted_score", rule_risk.get("score", 0)))
            score = max(0, min(100, raw_score))
            parsed_res["adjusted_score"] = score
            if score <= 29:
                parsed_res["adjusted_band"] = "LOW"
            elif score <= 69:
                parsed_res["adjusted_band"] = "REVIEW"
            else:
                parsed_res["adjusted_band"] = "HIGH"
        except (ValueError, TypeError):
            pass

        parsed_res["privacy_audit"] = privacy_audit
        return parsed_res
    except Exception as e:
        print(f"[Tier 2 LLM Review Error]: {e}")
        return {"error": "LLM review unavailable"}
