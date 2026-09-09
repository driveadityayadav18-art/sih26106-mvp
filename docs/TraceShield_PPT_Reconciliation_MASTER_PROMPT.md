# MASTER PROMPT — Paste this entire block into your coding AI

Copy everything between the line below and the end of the file, and paste it as
one single message into your coding AI (Claude Code, Cursor, etc.), run from the
repo root of `traceshield-mvp`.

---

## PROMPT STARTS HERE

I need a brutally honest **claim-by-claim reconciliation** between our already-submitted
SIH pitch deck and the actual state of this codebase. I am not the person who wrote the
deck, so I genuinely don't know which of its claims are real, partially real, or
completely aspirational. Treat this as a forensic audit, not a status update — I need
to know exactly what a judge could catch us out on.

Below is the verbatim (transcribed) content of every claim-bearing slide in the deck
(`traceshieldA_.pptx`). Most of this deck's content is baked into images, not
extractable text, so use this transcription as the source of truth for what the deck
says — do not re-parse the pptx and assume you've seen everything if it comes back
mostly blank.

### SLIDE 2 — "Trace Shield AI" (capability comparison table)

Bulleted capability claims:
- Reconstruct complete SMTP relay paths
- Analyze originating IPs & geolocation
- Validate SPF, DKIM, and DMARC alignment
- Generate explainable, confidence-based fraud risk assessments

Comparison table ("Legacy Secure Email Gateways" vs "Proposed API-Native AI"):
- **Threat Detection** → "Multi-Modal AI (NLP Intent Parsing + Scikit-Learn Random
  Forest on 20 URL features)"
- **Forensic Tracing** → "Deep OSINT enrichment, Geographic IP hopping, and SMTP
  Timeline mapping (The Glass Box)"
- **Deployment & Privacy** → "Sovereign, Zero-Cloud Leakage (Local SQLite WAL storage
  with open-weight models)"

### SLIDE 3 — "Technical Approach" (architecture diagram, three columns)

**Input & Orchestration:**
- Email Ingestion (IMAP Collector / Manual Upload)
- API Backend (FastAPI RESTful routing + APScheduler trigger)

**Processing & Detection:**
- Email Parser (Decodes RFC 822, extracts headers, body, URLs)
- Multi-Modal Threat Detection ("Node D") — three parallel sub-modules:
  - Scikit-learn Random Forest URL ML
  - Email Heuristics
  - Image OCR/Steganography
- Forensic Investigator (WHOIS, SSL, DNS, SMTP Paths)
- Fusion Engine (Phishing Confidence Score)

**Storage & Action:**
- Local Storage (Zero-admin SQLite Database)
- Evidence Builder (JSON/HTML Report Generation)
- User Interface (Streamlit Dashboard & 1-Click IMAP Firewall)

### SLIDE 4 — "Feasibility and Viability"

- Technical Feasibility: "Built on standardized RFC 5322/7489 protocols; containerized
  microservices run lightweight on-premises or cloud."
- Operational Viability: "Non-disruptive integration via API webhooks; ingests logs
  from existing gateways without altering mail MX routing."
- Institutional Scalability: "Zero-learning-curve reporting button for staff/students;
  structured case view for Tier-1/2 SOC teams."
- Risk mitigation — AI Hallucination/Drift: "Mitigated via deterministic rule engine
  baseline + inspectable reason codes + analyst confirmation override."
- Risk mitigation — IP Geolocation Obfuscation: "VPN/TOR/Proxy context tagging with
  confidence intervals; explicitly prevents reckless human accusations."
- Risk mitigation — Data Privacy & Compliance: "Local cryptographic hashing, strict
  RBAC, automated PII masking, and configurable data retention policies."

### SLIDE 5 — "Impact and Benefits"

- Pre-Attack Visibility (Dark Web Scope): "Continuously monitors underground markets
  and stealer logs. Neutralizes compromised credentials before they are weaponized
  into Account Takeovers (ATO)."
- Real-Time Defense (Behavioral AI): "Applies Natural Language Processing (NLP) to
  detect Behavioural Baseline Deviation. Blocks sophisticated Business Email
  Compromise (BEC) and VIP impersonation synchronously, without relying on known
  signatures."
- Post-Attack Forensics (Automated Response): "Extracts geolocation, domain
  intelligence, and forensic Indicators of Compromise (IOCs). Automates
  post-delivery inbox sweeping across the network in minutes, rather than hours."
- Strategic Ecosystem (National Impact): "Prevents massive financial fraud, ensures
  secure multi-channel collaboration, and feeds correlated intelligence directly
  into existing SIEM/SOAR infrastructures."
- Banner claim: "TODAY'S IMPACT: Proactive Intelligence. API-native integration.
  Behavioral context. Explainable AI (XAI) for rapid SOC decision-making."

### SLIDE 6 — "Research and References"

- States: "Golden Dataset Validation — 444 automated tests against curated
  real-world attack vectors."
- Lists repo: `github.com/driveadityayadav18-art/sih26106-mvp`

---

## YOUR TASK

For **every single claim above**, individually check it against the real codebase and
classify it as one of:

- ✅ **DONE** — fully implemented, cite the exact file(s)/line(s) as proof
- 🟡 **PARTIAL** — something related exists but doesn't match the claim as stated;
  explain precisely what's real vs what's exaggerated
- ❌ **MISSING** — nothing in the codebase implements this at all
- 🔴 **FALSE / CONTRADICTED** — the codebase actively contradicts the claim (e.g. the
  deck claims a technology that a *different* technology was used instead)

Do not be diplomatic or round up partial work to "done." Do not accept a similarly-named
function or a comment as evidence — trace actual execution paths. If a claim mentions a
specific technology (scikit-learn, Streamlit, IMAP, WHOIS, etc.), grep the entire repo
for it by name and report the literal result, not your impression.

Specifically verify:
1. Is there any scikit-learn / Random Forest / trained ML model anywhere in this repo,
   or is threat detection purely rule-based? Grep for `sklearn`, `RandomForest`,
   `.pkl`, `.joblib`, `model.fit`.
2. Is the frontend Streamlit or Next.js/React? Check `frontend/` and `requirements.txt`
   for `streamlit`.
3. Is there any local/open-weight LLM running on-device, or does Tier-2 review call
   an external cloud API? Check for Groq/OpenAI/Anthropic API usage.
4. Is there any image OCR or steganography detection code at all?
5. Is there an IMAP collector or APScheduler-based polling job, or only manual
   file upload?
6. Is there WHOIS, SSL certificate inspection, or DNS resolution anywhere, or only
   header-based SMTP relay parsing?
7. Is there any VPN/TOR/proxy detection logic (e.g. exit-node list, CIDR match)?
8. Is there any PII masking/redaction applied before data is displayed or sent to
   the LLM?
9. Is there any dark web monitoring, stealer log ingestion, or credential-leak
   checking?
10. Is there any SIEM/SOAR export format or webhook integration?
11. Run the actual test suite right now and report the real current pass count —
    compare it honestly against the claimed "444 automated tests."
12. Is there a "1-click IMAP firewall" action anywhere, or any RBAC/role-based
    access control?

## OUTPUT

Produce exactly **one** file: `docs/PPT_VS_CODEBASE_RECONCILIATION.md`

Structure it as:

1. **Executive Summary** — one paragraph, blunt, no hedging. State plainly whether
   the deck's technical claims are broadly accurate or broadly aspirational, and
   name the single biggest risk if a judge who read the deck starts asking
   technical questions.
2. **🔴 Critical Mismatches** — a table of every claim you marked FALSE/CONTRADICTED
   or MISSING that names a *specific* technology/feature (these are the ones a
   technical judge can catch in one question). Columns: Slide, Claim, Reality,
   Evidence (file:line or "grep returned nothing"), Suggested talking-point if
   asked live.
3. **Full Claim-by-Claim Table** — every single claim from all five content slides,
   one row each, columns: Slide, Claim (short), Status, Evidence, Notes.
4. **What's Genuinely Strong** — the claims that are fully true, so there's an
   honest positive list to actually lean on in Q&A.
5. **Recommended Fixes Before Judging**, split into two tiers:
   - **Tier A — Fix the deck, not the code** (claims that are wildly out of scope
     for remaining time — e.g. dark web monitoring, SIEM/SOAR — where the honest
     move is editing future presentation language to match reality, not building
     the feature)
   - **Tier B — Fix the code** (claims that are close enough to be genuinely
     achievable before judging — flag anything already covered by an existing
     P0/P1 plan in this repo if you find one, so we don't duplicate work)
6. **Questions judges are likely to ask based on this specific deck**, with an
   honest suggested answer for each, in the same spirit as: don't rationalize,
   don't oversell, state the real current status.

Show me your grep commands and their raw output inline as you go, not just your
conclusions — I want to see the evidence, not just trust a summary.

## PROMPT ENDS HERE
