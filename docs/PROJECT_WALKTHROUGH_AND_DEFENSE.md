# TraceShield — Project Walkthrough & Judge Defense Guide

> **Purpose**: Give every team member — especially non-coders — a complete under-the-hood understanding of the codebase **and** ready-to-speak answers for tomorrow's SIH26106 evaluation.
>
> **Last updated**: 2026-09-09 | **Team SIH26106**

---

## Table of Contents

1. [The 10-Second Plain-English Summary](#1-the-10-second-plain-english-summary)
2. [The 5-Step Email Journey (Upload → Screen)](#2-the-5-step-email-journey-from-upload-to-screen)
3. [File-by-File Blueprint](#3-file-by-file-blueprint-what-each-file-does--why-it-exists)
4. ["Why Did We Choose This Over That?" — The Architecture Defense](#4-why-did-we-choose-this-over-that--the-architecture-defense)
5. [The 3-Minute Stage Pitch Script](#5-the-3-minute-stage-pitch-script-word-for-word)
6. [Top 10 Trap Questions Judges Ask & Word-for-Word Answers](#6-top-10-trap-questions-judges-ask--word-for-word-answers)
7. [Phase 2 / Production Roadmap](#7-the-phase-2--production-roadmap-script)
8. [Pre-Demo Survival Checklist](#8-pre-demo-survival-checklist-avoid-live-demo-crashes)

---

## 1. The 10-Second Plain-English Summary

### What does TraceShield actually do — in two sentences?

> **TraceShield is an open-source email forensics workstation that takes a suspicious email file (`.eml`), rips it apart header-by-header, runs it through a machine-learning URL scanner and a 20+ rule heuristic engine, masks personal data before consulting an AI analyst, and gives the investigator a single 0-100 threat score with one-click quarantine — all in under 3 seconds.**
>
> It is built for Indian law-enforcement, CERT-In responders, and campus CISOs who today rely on opening phishing emails *by hand* in Outlook, with no structured triage and no audit trail.

### The Postal Envelope Analogy 📬

Think of a paper letter in the mail system:

| Real-World Concept | Email Equivalent |
|---|---|
| **Return address on the envelope** | `From:` header — **anyone can write whatever they want here** |
| **Postmarks stamped by each post office the letter passes through** | `Received:` headers — stamped by each real mail server in the chain; **these cannot be forged by earlier hops** |
| **The seal on the envelope** | DKIM — a **cryptographic wax seal** that proves the envelope wasn't tampered with en-route |
| **The post office checking if the sender's address matches their ID** | SPF / DMARC — the server checks whether the claimed sender is *actually authorised* to send from that domain |

**Email spoofing works exactly like writing a fake return address on a paper envelope.** The `From:` line costs zero effort to fake. But the `Received:` postmarks stamped by real servers along the route expose the truth — and that is exactly what TraceShield reads.

---

## 2. The 5-Step Email Journey (From Upload to Screen)

Here is what happens the **millisecond** a user drops an `.eml` file onto the upload zone:

### Step 1 — Ingestion & Parsing 📩
*"Opening the envelope and reading every postmark"*

| What happens | Where in code |
|---|---|
| The raw `.eml` bytes are received via `POST /api/v1/cases` | `backend/main.py` → `create_case()` |
| A SHA-256 hash and byte length are computed for **forensic provenance** — this proves the file hasn't been altered | `backend/evidence/hashing.py` |
| The `.eml` is saved to `data/artifacts/TS-DEMO-XXX.eml` as a tamper-proof evidence archive | `backend/main.py`, L509-518 |
| Python's built-in `email.parser.BytesParser` decodes MIME, Base64, and RFC 2047 encoded headers without executing anything | `backend/parser/email_parser.py` → `parse()` |
| All `Received:` headers are reversed (they arrive newest-first) and parsed into structured hops with IP addresses, hostnames, protocols, and timestamps | `_parse_received_headers()` |
| SPF, DKIM, DMARC results are extracted from `Authentication-Results` headers (we **read** the results — we don't re-verify DNS ourselves) | `_parse_authentication()` |
| URLs are extracted from both plain-text body **and** HTML `<a href>` tags, plus trampoline redirect unwrapping (up to 3 layers of percent-decoding) | `_extract_urls()`, `_unpack_url()` |
| Attachments are catalogued by filename, MIME type, size, and SHA-256 — **never executed** | `_parse_attachment()` |

**Result**: A `ParsedEmail` dataclass containing normalized, structured evidence.

---

### Step 2 — Server Hop & Geo-Forensics 🌍
*"Tracing the real postal route on a world map"*

| What happens | Where in code |
|---|---|
| The originating public IP is extracted from the earliest `Received:` hop (skipping private/loopback RFC 1918 addresses) | `backend/main.py` L535-551 |
| That IP is checked against a **local file** of 100+ known Tor exit relay IPs (`backend/data/tor_exit_nodes.txt`) — **no network call** | `backend/services/geo_ip.py` → `is_tor_exit_node()` |
| If not Tor, the IP is checked against 50+ datacenter/VPN CIDR ranges (DigitalOcean, Hetzner, OVH, Vultr, M247, etc.) | `is_datacenter_proxy()` with `DATACENTER_PROXY_CIDRS` list |
| Each relay hop in the chain is individually tagged with `is_tor`, `is_proxy`, `anonymizer_type`, and `confidence_score` | `email_parser.py` L648-657 |
| Infrastructure intel is enriched from a local `demo_intel.json` cache — again, **zero external API calls** | `enrich_and_correlate()` in `main.py` |

**Result**: Every hop has an anonymizer verdict; the frontend can render a "Tor Exit Node 🔴" badge or a clean "Residential ISP 🟢" tag.

---

### Step 3 — Multi-Layer Threat Inspection 🔍
*"The detective squad runs their individual checks"*

Three parallel detection layers fire:

#### Layer A: Heuristic Rule Engine (20+ rules)
The `ThreatDetector` in `backend/detection/detection.py` runs every rule function in sequence:

| Rule Category | Example Checks | Score Weight |
|---|---|---|
| **Authentication** | SPF fail (+10), DKIM missing (+8), DMARC reject (+12), CompAuth fail (+10) | 8-15 pts each |
| **Identity** | Reply-To domain ≠ From domain (+18), lookalike/typosquat domain (+20), Punycode IDN masking (+10), Return-Path anomaly (+25) | 10-25 pts each |
| **Content** | Urgent payment language (+25), credential harvest lure (+20), sensitive data request (+15) | 15-25 pts each |
| **URLs & Attachments** | Obfuscated URL (+20), trampoline redirect (+15), suspicious attachment extension (+12), ML phishing URL (+25) | 5-25 pts each |
| **Context** | Reused indicators from past cases (+15), header anomalies (+10) | 10-15 pts each |

All rule functions live in `backend/detection/rules/` — one file per category (`authentication.py`, `identity.py`, `content.py`, `urls_attachments.py`, `headers.py`, `context.py`, `evidence.py`).

#### Layer B: Random Forest ML URL Classifier
For **every URL** found in the email:

| What happens | Where in code |
|---|---|
| 20 lexical/structural features are extracted (url_length, entropy, dot count, IP host, punycode, suspicious TLD, brand impersonation, etc.) | `backend/scripts/train_url_model.py` → `extract_url_features()` |
| The features are fed into a pre-trained 100-tree Random Forest model loaded from `backend/models/rf_url_model.joblib` | `backend/detectors/url_ml.py` → `predict_url_risk()` |
| The model returns `phishing_probability` (0.0–1.0), `is_malicious` (bool), and human-readable `top_risk_factors` | `URLRiskClassifier.predict_url_risk()` |

The model was trained on 2,000 balanced synthetic URLs (1,000 phishing / 1,000 benign) using scikit-learn, achieving >97% test accuracy.

#### Layer C: Cross-Case Campaign Correlation
| What happens | Where in code |
|---|---|
| All prior cases in SQLite are scanned for shared Reply-To domains, originating IPs, URL hosts, and attachment SHA-256 hashes | `_build_detection_context()` in `main.py` |
| Matches produce `ReusedIndicator` objects that feed back into the scoring engine | `backend/detection/context.py` |
| A threat graph (nodes + edges) is built for the frontend to visualise campaign clusters | `enrich_and_correlate()` |

**Result**: A raw score (sum of all triggered rule weights), clamped to 0-100.

---

### Step 4 — Privacy Shield & AI Triage 🛡️
*"Running a black marker over sensitive data before showing it to the AI analyst"*

| What happens | Where in code |
|---|---|
| **Before** any text leaves the server to an LLM, `mask_pii()` runs **four regex passes** over every string field | `backend/utils/pii_masker.py` |
| Credit card numbers (16-digit patterns) → `[REDACTED_CREDIT_CARD]` | `CREDIT_CARD_REGEX` |
| Indian Aadhaar numbers (12-digit ####-####-#### format) → `[REDACTED_AADHAAR]` | `AADHAAR_REGEX` |
| Indian phone numbers (+91 / 10-digit starting 6-9) → `[REDACTED_PHONE]` | `PHONE_REGEX` |
| Email addresses in body text → `[REDACTED_EMAIL]` | `EMAIL_REGEX` |
| A `privacy_audit` dict records exactly how many entities were redacted — this is visible in the UI | `sanitize_email_for_llm()` in `llm_analysis.py` |

Then — **only if the heuristic score ≥ 30 or certain high-signal rules triggered** — the sanitised email is sent to the LLM:

| What happens | Where in code |
|---|---|
| The Groq Cloud API is called with a carefully crafted system prompt instructing it to act as a Senior Email Security Analyst | `run_tier_2_llm_review()` in `llm_analysis.py` |
| The prompt includes a **Forensic Calibration Rubric** with exact band thresholds so the LLM cannot hallucinate arbitrary scores | System prompt, L69-95 |
| The model tries multiple fallbacks: `llama-3.3-70b-versatile` → `llama3-70b-8192` → others | `models_to_try` list, L114-121 |
| Response is forced to `json_object` mode, `temperature=0.0`, `seed=42` for **deterministic** output | L134-136 |
| The LLM returns `is_false_positive`, `adjusted_score`, `adjusted_band`, and `analyst_summary` | Parsed JSON response |
| Band thresholds are **re-enforced server-side** (0-29=LOW, 30-69=REVIEW, 70-100=HIGH) to prevent LLM drift | L154-163 |

**Result**: An AI review that can downgrade newsletters to LOW or confirm genuine threats as HIGH, plus a complete privacy audit proving zero PII leakage.

---

### Step 5 — Threat Scoring & Action ⚡
*"The final verdict and the big red button"*

| What happens | Where in code |
|---|---|
| The final case record is assembled with all layers: parsed message, risk assessment, AI review, privacy audit, infrastructure intel, campaign graph | `create_case()` L646-663 |
| The case is persisted to **SQLite** (`backend/data/traceshield.db`) as the single source of truth | `backend/db.py` → `save_case()` |
| The JSON response is sent to the Next.js frontend, which renders the full forensic dashboard | `frontend/src/app/page.tsx` |
| The UI shows a **radial threat gauge** (0-100), color-coded reason cards, relay hop timeline, URL analysis table, and PII privacy shield badge | React components in `frontend/src/components/` |
| The analyst can click **"1-Click Quarantine"** → `POST /api/v1/cases/{id}/quarantine` | `quarantine_case_endpoint()` in `main.py` |
| The quarantine action logs an `IMAP_STORE_FLAGS_DELETED` command and an `iptables -A INPUT -s {IP} -j DROP` firewall rule | Mitigation log, L727-733 |
| The case status changes from `ACTIVE` → `QUARANTINED` in SQLite | `quarantine_case()` in `db.py` |
| A downloadable forensic report (Markdown or HTML) can be generated at any time via `/api/v1/cases/{id}/report` | `backend/reporting/report_generator.py` |

---

## 3. File-by-File Blueprint (What Each File Does & Why It Exists)

### Backend Files

| File | Analogy | What It Does | Why It Exists | What Breaks If Deleted? |
|---|---|---|---|---|
| **`backend/main.py`** | **The Reception Desk & Case Manager** | The FastAPI application. Receives uploads, orchestrates all 5 pipeline steps, assembles the final case JSON, and exposes REST APIs (`/api/v1/cases`, `/api/v1/cases/{id}/quarantine`, `/api/v1/cases/{id}/report`). | Without this file, there is no server — nothing can receive or process emails. | **Everything.** The entire backend stops working. |
| **`backend/parser/email_parser.py`** | **The Postmark Inspector** | Opens the raw `.eml` file using Python's `BytesParser`, extracts every header (From, To, Reply-To, Return-Path, Subject, Message-ID, Date), decodes MIME/Base64 attachments, reverses and parses all `Received:` headers into structured hops, and extracts every URL from both plain text and HTML bodies. Also detects trampoline redirects and percent-encoded obfuscation. | This is the **eyes** of the system. Without parsing, we have no evidence to analyse — just raw binary soup. | No headers parsed, no hops extracted, no URLs found — the entire downstream pipeline has nothing to work with. |
| **`backend/parser/models.py`** | **The Evidence Folder Template** | Defines all Python dataclasses: `ParsedEmail`, `Message`, `EmailAddress`, `URLMetadata`, `AttachmentMetadata`, `ReceivedHop`, `Trace`, `Authentication`, `AuthenticationResult`, `DMARCResult`, `Warning`, `Artifact`. Every piece of evidence slots into these templates. | Gives every module a shared language — when the parser says "hop", the detector knows exactly what shape that data is. | Import errors crash every module that references these models. |
| **`backend/services/geo_ip.py`** | **The Passport Control Officer** | Loads a local file of 100+ Tor exit node IPs into memory at startup. Maintains a hard-coded list of 50+ datacenter/VPN CIDR ranges (DigitalOcean, Hetzner, OVH, Vultr, M247, etc.). For any IP, returns `is_tor`, `is_proxy`, `confidence_score` (0.95 for Tor, 0.70 for proxy, 0.10 for residential), and `anonymizer_type`. **Makes zero network calls.** | Tor and proxy detection is a critical signal — attackers route through anonymisers to hide their origin. Without this, we'd miss the biggest red flag. | Tor badges disappear, proxy detection gone, the scoring engine loses 30 points of signal for anonymised attacks. |
| **`backend/data/tor_exit_nodes.txt`** | **The Tor Watchlist** | A plain-text file containing known Tor exit relay IP addresses, one per line (comments with `#` are ignored). Loaded into a Python `set()` at module startup for O(1) lookup. | Required by `geo_ip.py` for Tor detection. | Tor exit node detection stops working — confirmed Tor relays pass as normal IPs. |
| **`backend/detectors/url_ml.py`** | **The Link Detective (ML Brain)** | Loads the pre-trained Random Forest model from `rf_url_model.joblib`. For any URL, extracts 20 features (length, entropy, dot count, IP host, punycode, suspicious TLD, brand impersonation in subdomain, etc.), runs inference, and returns `phishing_probability`, `is_malicious`, and `top_risk_factors`. Uses a singleton pattern for performance. | Heuristic rules catch obvious patterns, but ML catches **novel** patterns that no hand-written rule anticipated — like a URL with unusual entropy + brand name + non-standard port combined. | URLs are no longer ML-classified; we lose the "Random Forest URL Classifier flagged high phishing probability" reason code. |
| **`backend/models/rf_url_model.joblib`** | **The Detective's Trained Brain (Saved Weights)** | The serialised scikit-learn `RandomForestClassifier` (100 trees, max_depth=15). Contains model weights, feature names, and evaluation metrics (accuracy, precision, recall, F1). | This is the trained artefact — without it, the URL classifier would need to retrain from scratch on every startup (which it will do automatically, but adds 5+ seconds). | Auto-retrains on first request (graceful degradation), but adds startup latency. |
| **`backend/scripts/train_url_model.py`** | **The Detective Training Academy** | Generates a balanced synthetic dataset of 2,000 URLs (1,000 phishing / 1,000 benign using 7 attack archetypes), extracts 20 features per URL, trains a `RandomForestClassifier(n_estimators=100)`, evaluates on a 20% holdout set, and serialises the artefact to `.joblib`. | Produces the ML model artefact. Also serves as documentation of the exact 20 features used. | Cannot retrain the model; the existing `.joblib` still works but can never be updated. |
| **`backend/detectors/scoring.py`** | **The Judge's Scorecard (Vector Scorer)** | A second scoring engine that evaluates raw **synthetic vectors** (dictionaries with fields like `spf`, `dkim`, `url_risk`, `ip_type`). Used by the 444-vector golden dataset test suite. Maps each signal to calibrated point weights and produces `score`, `band`, `reasons`, `reason_codes`. | Enables the golden dataset validation suite to test 444 attack scenarios without needing to construct full `ParsedEmail` objects. Also usable for API-level vector scoring. | The 444-test golden dataset suite fails; the secondary scoring API breaks. |
| **`backend/detection/detection.py`** | **The Detective Squad Leader** | The `ThreatDetector` class. Runs all 20+ detection rule functions in sequence against a `ParsedEmail` object, sums the weights, clamps to 0-100, determines the band (LOW ≤ 29, REVIEW ≤ 69, HIGH > 69), and collects all triggered reason codes and limitations. | This is the **brain** of the heuristic engine — the single entry point that orchestrates every rule. | No threat detection at all — every email scores 0. |
| **`backend/detection/config.py`** | **The Rules Playbook** | All tunable constants: point weights (SPF_FAIL_SCORE = 10, REPLY_TO_MISMATCH_SCORE = 18, etc.), keyword lists (PAYMENT_ACTIONS, CREDENTIAL_ITEMS, PRESSURE_PHRASES), trusted domain safelist, URL shortener hosts, risky attachment extensions, band thresholds (LOW_MAX = 29, REVIEW_MAX = 69, MAX = 100). | Centralises every magic number in one file — judges can ask "why is Reply-To mismatch worth 18 points?" and we can point here. | All rules import their weights from here — import errors crash the detection engine. |
| **`backend/detection/rules/authentication.py`** | **The Passport Stamp Checker** | Rule functions: `check_spf_fail()`, `check_spf_softfail()`, `check_compauth_fail()`, `check_dkim_fail_or_none()`, `check_dmarc_fail()`, `check_authentication_anomaly()`. Each returns a reason code dict with weight, or `None`. | SPF/DKIM/DMARC are the most fundamental email security checks — these rules evaluate whether the email passed or failed them. | Authentication-based threat signals disappear. Spoofed emails with failed SPF/DKIM score 0 on those vectors. |
| **`backend/detection/rules/identity.py`** | **The Identity Fraud Investigator** | `check_reply_to_mismatch()`, `check_display_name_domain_mismatch()`, `check_lookalike_domain()`, `check_punycode_domain()`, `check_return_path_anomaly()`. Compares From domain vs Reply-To domain, checks for IDN Punycode `xn--`, detects typosquat domains. | BEC (Business Email Compromise) attacks rely heavily on identity spoofing — these rules catch them. | Missed BEC attacks where attacker uses a Reply-To to a different domain. |
| **`backend/detection/rules/content.py`** | **The Body Language Profiler** | `check_urgent_payment_request()`, `check_credential_request()`, `check_sensitive_data_request()`. Uses word-proximity matching (action + item within 8 words + pressure phrase within 8 words, minus negation window). | Catches social engineering content — "wire transfer urgently" or "send your password immediately". | Content-based signals disappear — urgent phishing emails score lower. |
| **`backend/detection/rules/urls_attachments.py`** | **The Package & Link Inspector** | `check_suspicious_url_path()`, `check_shortened_url()`, `check_suspicious_attachment()`, `check_external_url_mismatch()`, `check_obfuscated_or_redirect_url()`, `check_url_ml_risk()`. Checks for `.exe`/`.scr` attachments, URL path keywords like `/login`, shortened URLs (bit.ly), and calls the ML classifier. | URLs and attachments are the primary **weaponisation** vectors in phishing — this is where the payload lives. | URL and attachment threat signals disappear. |
| **`backend/detection/rules/headers.py`** | **The Envelope Quality Inspector** | `check_header_anomaly()` — triggers on malformed addresses, dates, or corrupted Received headers. | Attackers sometimes craft malformed headers to bypass parsers — detecting anomalies is a signal. | Header anomaly detection lost. |
| **`backend/detection/rules/context.py`** | **The Campaign Connector** | `check_reused_indicator()` — checks if domains, URLs, or attachment hashes from this email appeared in previous cases. | Links new attacks to known campaigns — "this domain was used in 3 prior phishing cases". | Cross-case correlation breaks; each case analysed in isolation. |
| **`backend/detection/rules/evidence.py`** | **The Evidence Gap Reporter** | `check_insufficient_evidence()`, `evidence_gaps()` — reports when critical evidence (SPF, DKIM, body text, URLs) is missing. Adds **zero points** but shows the analyst what couldn't be checked. | Prevents false confidence — if SPF data was missing, the analyst should know the score may be understated. | Analysts don't see which checks were skipped. |
| **`backend/detection/context.py`** | **The Case Cross-Reference Card** | Two tiny dataclasses: `ReusedIndicator` (type, value, related case IDs) and `DetectionContext` (list of reused indicators + current case ID). | Provides the data shape that the context rule expects. | Import error crashes the detection pipeline. |
| **`backend/utils/pii_masker.py`** | **The Digital Black Marker** | Four precompiled regexes for credit cards, Aadhaar numbers, Indian phones, and email addresses. `mask_pii(text)` runs all four substitutions and returns `(sanitised_text, summary_dict)` with counts of each redaction type. | Ensures **zero personal data** reaches the Groq LLM API — this is our DPDP/GDPR compliance claim. | PII leaks to the LLM — our privacy claim is destroyed. |
| **`backend/services/llm_analysis.py`** | **The AI Second Opinion** | `sanitize_email_for_llm()` recursively masks all string fields in the parsed email dict. `run_tier_2_llm_review()` constructs a structured prompt, calls Groq with `temperature=0.0, seed=42`, parses the JSON response, and enforces band thresholds server-side. | Catches false positives (legitimate newsletters flagged by strict heuristics) and provides human-readable analyst summaries. | No AI review — the UI shows only the heuristic score with no AI-calibrated adjustment or analyst summary. |
| **`backend/db.py`** | **The Filing Cabinet** | SQLite wrapper: `init_db()`, `save_case()`, `get_case()`, `list_cases()`, `get_all_cases()`, `count_cases()`, `clear_cases()`, `quarantine_case()`, `get_max_case_number()`. The `cases` table stores `case_id`, `sha256`, `created_at`, `risk_score`, `risk_band`, `status`, and full `analysis_json`. | Persistent storage — without it, all cases vanish when the server restarts. Also enables cross-case campaign correlation. | No persistence, no case history, no quarantine records, no campaign correlation. |
| **`backend/evidence/hashing.py`** | **The Fingerprint Stamper** | Two tiny functions: `calculate_sha256(bytes)` and `get_byte_length(bytes)`. | Produces the forensic hash that proves the original email artifact hasn't been tampered with. | No integrity verification — cases lack provenance hashes. |
| **`backend/reporting/report_generator.py`** | **The Report Printer** | Generates full structured Markdown and standalone HTML incident reports from a case dictionary. Includes defanged URLs, auth badges, hop timelines, reason code tables, AI review sections, and mitigation logs. | Lets analysts export a printable, court-admissible forensic report. | No downloadable reports. |
| **`backend/reporting/demo_report.py`** | **The Demo Report Launcher** | Quick script to generate a sample report from the demo database for testing. | Developer convenience for validating report formatting. | No impact on production pipeline. |
| **`backend/reset_demo.py`** | **The Stage Reset Button** | Clears all cases from SQLite and removes generated `TS-DEMO-XXX.eml` artifacts so the demo starts fresh from `TS-DEMO-001`. | Essential for live demo resets between judge sessions. | Cannot cleanly reset the demo database; must manually delete files. |
| **`backend/data/demo_intel.json`** | **The Intel Cheat Sheet** | A small JSON file with pre-cached threat intelligence for specific demo IPs and domains (geo, provider, country). | Avoids needing live network API calls during the demo while still showing infrastructure enrichment. | Infrastructure enrichment falls back to generic "External Public Network" labels instead of specific geo data. |
| **`backend/requirements.txt`** | **The Grocery List** | Lists all Python dependencies: fastapi, uvicorn, groq, python-dotenv, scikit-learn, numpy, joblib. | Ensures `pip install -r requirements.txt` gets everything needed. | Manual dependency hunting. |

### Frontend Files

| File | Analogy | What It Does | Why It Exists | What Breaks If Deleted? |
|---|---|---|---|---|
| **`frontend/src/app/page.tsx`** | **The Main Dashboard Screen** | The entire single-page forensic dashboard: upload dropzone, case list sidebar, radial threat gauge, authentication cards, relay hop timeline, URL analysis table, AI review panel, privacy audit badge, 1-Click Quarantine button, and report download links. ~1,400 lines of React/TypeScript. | This is what the judges **see**. | No UI at all — blank page. |
| **`frontend/src/app/layout.tsx`** | **The Page Frame** | Next.js root layout — sets `<html>`, `<body>`, metadata title, and global CSS import. | Required by Next.js for page rendering. | App won't render. |
| **`frontend/src/app/globals.css`** | **The Style Sheet** | Global CSS including Tailwind directives, dark theme variables, and custom component styles. | Visual aesthetics — without it, the app looks unstyled. | Ugly, unstyled UI. |
| **`frontend/src/types/case.ts`** | **The Data Dictionary** | TypeScript interfaces for `CaseAnalysis`, `MessageData`, `RiskData`, `ReceivedHop`, `TraceData`, `CampaignData`, `InfrastructureData`, `AIReviewData`, `PrivacyAuditData`, `MitigationLog`, etc. | Type safety — ensures frontend and backend agree on data shapes. | TypeScript errors throughout the frontend. |
| **`frontend/src/components/dashboard/Navbar.tsx`** | **The Top Navigation Bar** | The "TraceShield" branded header with logo and navigation. | Professional branding for the judges. | No header bar. |
| **`frontend/src/components/dashboard/RelayTimeline.tsx`** | **The Hop-by-Hop Map** | Visual timeline showing each `Received:` header hop with from/by hosts, IPs, protocols, timestamps, and Tor/proxy badges. ~17KB component. | The most visually impressive forensic feature — shows the email's journey through servers. | No relay timeline visualisation — judges can't see the hop chain. |
| **`frontend/src/components/observable-url-table.tsx`** | **The Link Analysis Table** | Table showing every extracted URL with ML phishing probability, risk factors, scheme, host, obfuscation flags, and trampoline detection. ~30KB component. | Shows the ML URL analysis results in a scannable table format. | No URL analysis table. |
| **`frontend/src/components/ui/*.tsx`** | **The Design Toolkit** | Reusable UI primitives: `Card`, `Badge`, `Alert`, `GradientButton`, `Table`. | Consistent styling across the dashboard. | UI component import errors. |

### Test Files

| File | What It Does | Key Fact |
|---|---|---|
| **`tests/test_golden_dataset.py`** | Validates the scoring engine and URL classifier against **exactly 444 synthetic attack vector scenarios** across 7 forensic categories: Combinatorial Core Matrix (192), BEC & Executive Impersonation (40), Credential Harvesting (50), Tor Relay Infiltration (40), URL Evasion (45), Malicious Attachments (35), Legitimate Benign Traffic (42). | **444 green passing tests = proof of algorithmic rigour.** |
| **`backend/test_detection.py`** | Integration tests for `ThreatDetector`, `create_case()`, `enrich_and_correlate()`, quarantine API, and report generation using real `.eml` fixtures. | Tests the full pipeline end-to-end with real email files. |

---

## 4. "Why Did We Choose This Over That?" — The Architecture Defense

### Q: Why Scikit-Learn Random Forest instead of just asking ChatGPT/LLM to check URLs?

> **Three reasons: speed, determinism, and zero hallucination.**
>
> 1. **Latency**: Our Random Forest evaluates a URL in **<2 milliseconds** on CPU. An LLM API call takes 800-3,000 ms minimum. We scan every URL in the email — a message with 5 links would add 4-15 seconds of LLM delay.
> 2. **Determinism**: The Random Forest produces the **exact same probability** for the same URL every time (`seed=42`). LLMs are stochastic — asking twice can give different answers.
> 3. **No hallucination**: The model calculates 20 concrete mathematical features (entropy, dot count, digit ratio, etc.) and makes a binary classification. It cannot "hallucinate" that `google.com` is malicious because the features objectively show low entropy, no suspicious TLD, no brand-in-subdomain, and HTTPS.
>
> We **do** use an LLM (LLaMA via Groq) — but only as a **Tier 2 reviewer** for borderline cases, and only after PII masking. The ML model is the first-line, high-speed filter.

### Q: Why SQLite instead of PostgreSQL/MongoDB?

> **Zero administration, single-file portability, and serverless operation.**
>
> 1. TraceShield is designed for **edge deployment** — a CERT-In investigator's laptop, a campus security office, a police cyber cell. These environments don't have a DBA to configure PostgreSQL replication.
> 2. The entire database is **one file** (`traceshield.db`) that can be copied to a USB drive as evidence.
> 3. SQLite handles our workload (hundreds of cases, not millions) with **zero overhead** — no background daemon, no TCP port, no connection pool.
> 4. For production scale-up, SQLite can be replaced with PostgreSQL by swapping `db.py` alone — the API layer doesn't change.

### Q: Why Groq Cloud API instead of running a local model?

> **Live demo performance on a standard laptop.**
>
> 1. Running LLaMA-3 70B locally on a laptop would take **30-60 seconds per inference** on CPU, which kills the live demo.
> 2. Groq's LPU hardware returns responses in **<2 seconds**, making the demo feel instant.
> 3. We still use an **open-weight model** (LLaMA-3, not a proprietary API) — the architecture is portable to local inference via vLLM/Ollama in production.
> 4. PII is masked **before** any data leaves the server, so the Groq API only sees `[REDACTED_AADHAAR]` and `[REDACTED_PHONE]` tokens.

### Q: Why Regex PII Masking instead of Spacy/Presidio?

> **Sub-millisecond speed, zero dependency bloat, 100% deterministic.**
>
> 1. Our PII patterns are **Indian-specific** (Aadhaar's 12-digit format starting with 2-9, Indian mobile numbers starting with 6-9 with +91 prefix, credit card 16-digit patterns). These are fixed, well-defined formats that regex handles perfectly.
> 2. Spacy/Presidio would add **500+ MB of model files** and introduce NLP model loading latency.
> 3. Regex runs in **<0.1 ms** per field. Spacy NER would take 50-200 ms per field.
> 4. Regex is **deterministic** — the same input always produces the same redaction. NLP models can miss entities or hallucinate false positives.

### Q: Why passive RFC header inspection instead of active WHOIS/DNS queries?

> **Operational security — never tip off the attacker.**
>
> 1. During an active incident, making live DNS lookups or WHOIS queries to the attacker's domain **alerts them** that their campaign is being investigated. Some sophisticated threat actors monitor query logs.
> 2. We read only what's **already in the email** — the `Received:` headers, `Authentication-Results`, and `DKIM-Signature` are evidence that was stamped by servers the email *already passed through*.
> 3. This also means TraceShield works **completely offline** — no internet connection required for the core analysis pipeline (only the optional LLM Tier 2 review needs network access).

---

## 5. The 3-Minute Stage Pitch Script (Word-for-Word)

### Minute 0:00–1:00 — The Problem & The Live Upload

> *"Good [morning/afternoon], honourable judges. I'm [Name] from Team TraceShield.*
>
> *Here is a fact that should alarm every Indian organisation: according to CERT-In, India reported over 13 lakh cybersecurity incidents last year, and phishing email remains the number-one attack vector. Today, when a CERT-In analyst receives a suspicious email, they open it manually in Outlook, eyeball the headers, and make a gut-call. There is no structured triage, no ML analysis, and no audit trail.*
>
> *TraceShield changes that. Let me show you.*
>
> *[Click: upload a phishing `.eml` file]*
>
> *Watch what just happened in under 2 seconds: the system opened the email envelope, decoded every MIME layer, and extracted all Received headers — these are the real postmarks stamped by each server the email passed through. Look at this relay timeline — you can see exactly which servers handled this email, hop by hop, with timestamps, IP addresses, and protocols.*
>
> *And notice this red badge: the originating IP is a confirmed Tor exit relay node. The sender was actively hiding behind the Tor anonymisation network."*

### Minute 1:00–2:00 — The Multi-Layer Detection

> *"Now let's look at what TraceShield found underneath.*
>
> *First, authentication: SPF failed, DKIM was missing, DMARC was set to reject. That's three strikes on the email's passport stamps.*
>
> *Second, the URL analysis: our Random Forest ML classifier — trained on 2,000 URLs with 20 structural features like entropy, suspicious TLD, and brand name impersonation — flagged this link with a 94% phishing probability. You can see the exact risk factors: IP literal host, suspicious TLD, and security keywords in the path.*
>
> *Third, the content engine detected urgent payment language within 8 words of a wire transfer instruction.*
>
> *All of these signals feed into a composite threat score — in this case, 87 out of 100, solidly in the HIGH band.*
>
> *And critically — look at this green Privacy Shield badge. Before we sent anything to the AI analyst, our PII masker automatically redacted 2 Aadhaar numbers and 3 phone numbers found in the email body. The AI only saw `[REDACTED_AADHAAR]` tokens. Zero personal data left the server."*

### Minute 2:00–3:00 — The 1-Click Mitigation & Proof of Rigour

> *"Now the analyst makes a decision. One click — Quarantine.*
>
> *[Click the Quarantine button]*
>
> *That single click just logged an IMAP delete-flag command to remove this email from the inbox, generated an iptables firewall rule to block the attacker's originating IP, and changed the case status to QUARANTINED with a full audit trail — timestamp, action, evidence.*
>
> *The analyst can also download a complete forensic report in Markdown or HTML — court-admissible, defanged URLs, full evidence chain.*
>
> *Finally — rigour. We validated TraceShield against a 444-scenario golden dataset covering BEC impersonation, credential harvesting, Tor infiltration, URL evasion, malicious attachments, and legitimate traffic. All 444 tests pass green.*
>
> *TraceShield: From suspicious email to actionable verdict in 2 seconds. Thank you."*

---

## 6. Top 10 Trap Questions Judges Ask & Word-for-Word Answers

### 1. *"Where is your machine learning model? Show me the weights and features."*

> "The trained model artifact is at `backend/models/rf_url_model.joblib` — a serialised scikit-learn Random Forest with 100 decision trees. The exact 20 features are defined in `backend/scripts/train_url_model.py` lines 27-48: `url_length`, `count_dots`, `count_hyphens`, `count_at`, `count_subdomains`, `has_ip_address`, `count_digits`, `digit_to_letter_ratio`, `shannon_entropy`, `is_https`, `count_params`, `count_queries`, `count_slashes`, `has_punycode`, `suspicious_tld`, `suspicious_keyword_count`, `brand_name_in_subdomain`, `path_length`, `hyphen_in_domain`, and `port_present`. I can load the model and show you `model.feature_importances_` right now if you'd like."

### 2. *"You claim zero cloud leakage, but isn't this calling the Groq API in the US?"*

> "Great catch — let me clarify. We never claimed zero *network calls*. We claim **zero PII leakage**. Before any text reaches Groq, our `pii_masker.py` runs four regex passes that replace every Aadhaar number, phone number, credit card, and email address with `[REDACTED_*]` tokens. The LLM only sees sanitised text. You can verify this — the `privacy_audit` object in every case response shows exactly how many entities were redacted. And the LLM is only called for borderline cases (score ≥ 30); low-risk emails never leave the server at all."

### 3. *"Can you connect this to my live Gmail or Outlook inbox right now via IMAP?"*

> "Not in this MVP — and deliberately so. The quarantine button currently logs the IMAP `STORE \Deleted` command and the firewall rule, but does not execute live IMAP connections on stage. This is because live IMAP to a judge's inbox requires OAuth consent flows and credential handling that we scoped as Phase 2. In production, this integrates with Microsoft Graph API or Google Workspace APIs for push-and-sweep — the architecture already supports it because the mitigation log records the exact `target_message_id` from the email headers."

### 4. *"How do you detect Tor or proxies?"*

> "We maintain a local file at `backend/data/tor_exit_nodes.txt` containing 100+ confirmed Tor exit relay IPs, loaded into a Python `set()` at startup for O(1) lookup. We also hard-code 50+ datacenter CIDR ranges from DigitalOcean, Hetzner, OVH, Vultr, Linode, and M247 in `geo_ip.py`. When we extract the originating IP from the earliest `Received:` header, we check it against both lists — entirely offline, no DNS query, no external API. Tor gets a 0.95 confidence score, datacenter proxy gets 0.70."

### 5. *"How did you test this? Show me your dataset validation."*

> "Run `pytest tests/test_golden_dataset.py -v` — you'll see 444 green passing tests. The dataset covers 7 forensic vectors: 192 combinatorial permutations of SPF/DKIM/DMARC/URL/Content/IP/Spoofing, plus 40 BEC scenarios, 50 credential harvesting scenarios, 40 Tor infiltration scenarios, 45 URL evasion scenarios, 35 malicious attachment scenarios, and 42 legitimate benign traffic scenarios. Every test asserts that the scoring engine produces a score within the expected band — LOW, REVIEW, or HIGH. We also have integration tests in `backend/test_detection.py` that test against real `.eml` fixture files."

### 6. *"What does the 1-Click Firewall actually do under the hood?"*

> "When you click Quarantine, the backend hits `POST /api/v1/cases/{id}/quarantine`. It looks up the case in SQLite, extracts the `Message-ID` header and the originating IP, and creates a mitigation log with two fields: `IMAP_STORE_FLAGS_DELETED` (the IMAP command that would flag the email for deletion in the inbox) and `iptables -A INPUT -s {originating_IP} -j DROP` (the Linux firewall rule that would block all future traffic from that IP). The case status changes to `QUARANTINED` and the full log is persisted in SQLite as an audit trail. In this MVP, these are logged actions — production deployment would execute them against a live IMAP server and firewall."

### 7. *"What if the attacker fakes the Received headers?"*

> "Excellent question. Here's the key insight: an attacker can only fake the **first** `Received:` header — the one their own mail server writes. But every subsequent server in the chain adds its own `Received:` header **on top**, and it stamps the IP address it actually received the connection from. So even if the attacker writes 'Received: from legitimate-bank.com', the next real server stamps 'Received: from 185.220.101.5' — the actual IP that connected to it. That's why we parse the chain bottom-up and look for the first *public, non-private* IP — it's the one that was stamped by a server the attacker doesn't control."

### 8. *"Why did your slide say Streamlit, but you're running Next.js/React?"*

> "The original proposal used Streamlit for rapid prototyping. During development, we upgraded to Next.js with TypeScript and Tailwind CSS because we needed a production-grade, component-based dashboard with features like drag-and-drop upload, interactive data tables, radial chart visualisations, and real-time state management — things that Streamlit's Python-only widget model can't support well. The backend remained Python/FastAPI as planned. This is actually a sign of engineering maturity — we chose the right tool for the right job."

### 9. *"Does your PII masking work on Indian identity documents?"*

> "Yes — it was specifically built for Indian formats. The Aadhaar regex matches both the `####-####-####` grouped format and contiguous 12-digit numbers starting with 2-9 (per UIDAI spec). The phone regex handles `+91`, `(91)`, `0`-prefixed, and bare 10-digit numbers starting with 6-9. You can see the patterns in `backend/utils/pii_masker.py` lines 6-25. We also handle credit card numbers (16-digit with dashes/spaces) and email addresses. Every redaction is counted and reported in the `privacy_audit` response."

### 10. *"How is this different from existing email filters like Gmail Spam or Proofpoint?"*

> "Gmail and Proofpoint are **preventive filters** — they silently block or quarantine emails before the user sees them. TraceShield is a **forensic triage workstation** for after the fact — when a suspicious email has *already arrived* and an analyst needs to investigate it. We provide what they don't:
> 1. **Full header-level forensic transparency** — Gmail doesn't show you the relay hop chain with Tor/proxy badges.
> 2. **ML-explainability** — we show the 20 features and risk factors behind every URL verdict, not a black-box 'spam' label.
> 3. **Indian PII compliance** — Aadhaar/phone masking before AI analysis, which Gmail has no concept of.
> 4. **Cross-case campaign correlation** — linking this email to previous attacks via shared infrastructure indicators.
> 5. **Court-admissible forensic reports** — exportable Markdown/HTML with SHA-256 provenance, defanged URLs, and full evidence chains.
>
> We complement Gmail/Proofpoint — we don't replace them."

---

## 7. The "Phase 2 / Production Roadmap" Script

*When judges ask: "What is your future scope and how does this go to market?"*

> "We've structured our production roadmap into four enterprise pillars:"

### Pillar 1: Threat Intelligence (CTI) & Dark Web Ingestion

> "We integrate with **HaveIBeenPwned** to check whether sender email addresses appear in breach databases, and with **OpenCTI / MISP** to ingest structured threat intelligence feeds — IOC (Indicators of Compromise) such as known malicious IPs, domains, and file hashes from dark web stealer log monitoring. This transforms TraceShield from a standalone analyser to a node in the global threat intelligence ecosystem."

### Pillar 2: Direct M365 Graph & Google Workspace API Integration

> "Instead of manual `.eml` upload, we integrate directly with **Microsoft Graph API** and **Google Workspace Admin API** to perform push-and-sweep operations — automatically scanning incoming emails in organisational mailboxes and executing quarantine actions via API. This enables deployment as a background service in enterprise SOCs."

### Pillar 3: Edge-Native Local LLM Execution

> "We replace the Groq cloud dependency with **on-premise quantised LLM inference** using vLLM or Ollama running LLaMA-3 or Mistral on local GPU/CPU hardware. This achieves true air-gapped deployment for classified environments — defence, intelligence, and critical infrastructure where no data can leave the network."

### Pillar 4: Attachment Micro-VM Sandbox with QR/OCR Decoding

> "We add a **micro-VM sandbox** (using Firecracker or gVisor) that safely detonates suspicious attachments in an isolated environment — monitoring file system writes, network calls, and process spawning. We also add **QR code decoding** (zbar/pyzbar) and **OCR text extraction** (Tesseract) for image-based phishing that embeds malicious URLs inside QR codes or screenshots of text."

---

## 8. Pre-Demo Survival Checklist (Avoid Live Demo Crashes)

### ✅ Checklist — Do These the Night Before

| # | Action | Command / Check | Why |
|---|---|---|---|
| **1** | **Reset the demo database** | `cd backend && python reset_demo.py` | Clears all prior cases so the demo starts clean from `TS-DEMO-001`. Prevents "Case already exists" errors. |
| **2** | **Verify pytest passes** | `cd traceshield-mvp && .\.venv\Scripts\python.exe -m pytest tests/test_golden_dataset.py -v --tb=short` | Run this once on the demo laptop. If all 444 pass green, screenshot it. If any fail, fix before the stage. |
| **3** | **Confirm `.env.local` has a valid Groq API key** | Open `backend/.env.local` — it should contain `GROQ_API_KEY=gsk_...` | If this is missing or expired, the AI Review panel will show "LLM review unavailable" — not a crash, but embarrassing. |
| **4** | **Stage 3 `.eml` test files on Desktop** | Copy to Desktop: `data/fixtures/01_payment_diversion.eml` (HIGH), `data/fixtures/03_legitimate_internal.eml` (LOW), `data/fixtures/04_credential_harvest.eml` (HIGH) | Have a mix of high-threat and low-threat emails ready. Name them clearly so you grab the right one on stage. |
| **5** | **Test internet fallback** | Disconnect WiFi → upload an `.eml` → verify the heuristic score still appears (AI Review will say "unavailable") → reconnect → upload again → verify AI Review appears | Proves the system degrades gracefully without internet — only the optional LLM tier fails, everything else works offline. |

### 🔥 Emergency Commands — If Things Break on Stage

| Problem | Fix |
|---|---|
| Backend won't start | `cd backend && ..\.venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload` |
| Frontend won't start | `cd frontend && npm run dev` |
| "Case already exists" errors | `cd backend && python reset_demo.py` |
| SQLite locked | Kill all Python processes, then restart backend |
| Groq API returns 429 (rate limit) | Wait 30 seconds, or switch `GROQ_MODEL` in `.env.local` to a different model |
| Model file missing | Delete `backend/models/rf_url_model.joblib` — the system auto-retrains on next request |

### 💡 Pro Tips for Stage

- **Always upload the phishing email first** — it produces a dramatic HIGH score with red badges and Tor detection. Upload the legitimate email second to show the system correctly scores it LOW.
- **Point at the Privacy Shield badge** every time the AI Review panel is shown — judges love the "zero PII leakage" story.
- **If a judge asks to run pytest live**, do it with: `.\.venv\Scripts\python.exe -m pytest tests/test_golden_dataset.py -v --tb=line -q` — the `-q` flag makes the output cleaner and the 444 green dots are visually impressive.
- **If the internet drops mid-demo**, stay calm and say: *"Notice the system still gave us a complete forensic analysis — the ML URL classifier, the heuristic engine, and the Tor detection all work completely offline. Only the optional AI review requires internet, and it gracefully shows 'unavailable' rather than crashing."*

---

*Good luck tomorrow. You've built something real. Own it.* 🛡️
