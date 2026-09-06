# 🛡️ TraceShield AI (SIH26106 MVP)
### AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

> **Smart India Hackathon 2026** | **Problem Statement ID:** SIH26106  
> **Organization:** All India Council for Technical Education (AICTE)  
> **Theme:** Blockchain & Cybersecurity | **Category:** Software  

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-16%20(App%20Router)-black?style=flat&logo=next.js&logoColor=white)](https://nextjs.org)
[![SQLite](https://img.shields.io/badge/SQLite-Persistence-003B57?style=flat&logo=sqlite&logoColor=white)](https://sqlite.org)
[![Groq](https://img.shields.io/badge/Groq-Llama%203.3%2070B-F55036?style=flat)](https://groq.com)
[![Tests](https://img.shields.io/badge/Tests-444%20Passing-emerald?style=flat&logo=pytest&logoColor=white)](#-testing-qa--golden-fixtures)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat)](LICENSE)

---

## 📌 Table of Contents
1. [Overview & Problem Statement Alignment](#-overview--problem-statement-alignment)
2. [End-to-End System Architecture](#-end-to-end-system-architecture)
3. [⚡ Quick Start Guide (Run in 3 Minutes)](#-quick-start-guide-run-in-3-minutes)
4. [🗄️ SQLite Persistence & Data Architecture](#-sqlite-persistence--data-architecture)
5. [📄 Forensic Incident Reporting Engine](#-forensic-incident-reporting-engine)
6. [🔌 Complete REST API Reference](#-complete-rest-api-reference)
7. [🖥️ SOC Analyst Console & UI Visualizers](#-soc-analyst-console--ui-visualizers)
8. [🧪 Testing, QA & Golden Fixtures (444+ Tests)](#-testing-qa--golden-fixtures-444-tests)
9. [🎬 Live Hackathon Demo & Judging Runbook](#-live-hackathon-demo--judging-runbook)
10. [👥 6-Member Team Roles & Edit Boundaries](#-6-member-team-roles--edit-boundaries)
11. [📂 Repository Directory Structure](#-repository-directory-structure)

---

## 🚀 Overview & Problem Statement Alignment

Email continues to be the primary attack vector for phishing, Business Email Compromise (BEC), CEO fraud, payment diversion, and credential harvesting. Traditional email security gateways (SEGs) primarily rely on static blacklists and binary spam filters that offer **zero explainability** and fail to reconstruct transmission paths or correlate repeated fraud campaigns.

**TraceShield AI** bridges this gap as an explainable, forensic-grade email threat investigation platform designed for Security Operations Centers (SOC), incident responders, and law enforcement agencies. It satisfies the core requirements of **SIH26106**:

| SIH26106 Mandate | TraceShield AI Implementation |
| :--- | :--- |
| **Fraudulent Email Detection Engine** | NLP analysis of urgency cues, payment diversion, executive impersonation, lookalike domains, and heuristic rule scoring (0–100) with deterministic reason codes. |
| **Email Header & Protocol Analysis** | Deep RFC 5322 MIME parser validating SPF, DKIM, DMARC, and CompAuth alignment, detecting relay manipulation and mismatched Return-Path / Reply-To. |
| **Origin Traceability & Location** | Full chronological Received-header reconstruction, earliest reliable public hop extraction, and offline/cached IP/domain geolocation enrichment (ISP, ASN, Country, City). |
| **Identity Correlation & Attribution** | Cross-case graph correlation in SQLite detecting reused infrastructure (shared Reply-To domains, originating IPs, attachment SHA-256 hashes) and campaign clustering. |
| **Alerting, Dashboard & Reporting** | Next.js 16 SOC analyst dashboard with interactive Relay Hop Timeline, URL defanging table, campaign graph, and exportable standalone HTML/Markdown forensic reports. |
| **Privacy, Legal & Evidentiary Chain of Custody** | Raw artifact preservation with cryptographic SHA-256 hashing, defanged observables (`hxxp[s]://`, `[.]`), audit logging, and reproducible analysis. |

### 🔄 The Core Analysis Flow
```text
Upload .eml File 
  │
  ├── 1. Cryptographic Hashing & Artifact Preservation (SHA-256 + Byte Length)
  ├── 2. Deep MIME & Header Forensics (RFC 5322, SPF, DKIM, DMARC, CompAuth, Received Hops)
  ├── 3. Deterministic Threat Engine (Risk Score 0–100, Reason Codes, Weights, Evidence Paths)
  ├── 4. Historical Context & SQLite Cross-Case Correlation (Reused IPs, Domains, Attachments)
  ├── 5. OSINT & Geolocation Enrichment (Origin IP, ASN, ISP, Domain Geo Context)
  ├── 6. Tier 2 Explainable LLM Review (Groq Llama 3.3 70B for ambiguous / high-risk cases)
  ├── 7. SQLite Storage Engine (Full Case Persistence, High-Watermark Sequencing TS-DEMO-XXX)
  └── 8. Forensic Report Generation (Standalone Printable HTML + Markdown Export)
```

---

## 🏗️ End-to-End System Architecture

```mermaid
graph TD
    User([Analyst / Investigator]) -->|Uploads .eml file| FE[Next.js 16 Analyst Dashboard\n:3000]
    FE -->|POST /api/v1/cases| BE[FastAPI Orchestrator\n:8000]
    
    subgraph Backend Core Pipeline
        BE --> Hash[SHA-256 Artifact Hasher\nevidence/hashing.py]
        BE --> Parser[Deep RFC MIME & Header Parser\nparser/email_parser.py]
        Parser --> AuthCheck[Authentication & Protocol Analyzer\nSPF · DKIM · DMARC · CompAuth]
        Parser --> HopReconstruct[Relay Chain Reconstructor\nEarliest Observable Node]
        
        AuthCheck & HopReconstruct --> Engine[Deterministic Threat Engine\ndetection/detection.py]
        Engine --> Rules[Rule Modules: Identity, Content,\nURLs, Attachments, RFC Headers]
        
        Engine --> SQLiteDB[(SQLite Case Store\nbackend/data/traceshield.db)]
        SQLiteDB --> Context[Cross-Case Reused\nIndicator Context]
        Context --> Engine
        
        Engine --> OSINT[Cached Geolocation & Intel\ndata/demo_intel.json]
        
        Engine -->|Score >= 30 or DMARC Fail| LLM[Tier-2 Explainable LLM Review\nGroq Llama 3.3 70B Versatile]
        
        Engine & OSINT & LLM --> Correlator[Campaign Graph Correlator\nNodes · Edges · Clusters]
        Correlator --> SQLiteDB
        
        SQLiteDB --> ReportGen[Forensic Report Generator\nreporting/report_generator.py]
    end
    
    ReportGen -->|GET /cases/{id}/report| Export[Exportable Standalone HTML / Markdown]
    SQLiteDB -->|CaseAnalysis JSON| FE
    
    subgraph Frontend Analyst Console
        FE --> Meter[Threat Score Radial Meter 0-100]
        FE --> Relay[Relay Hop Transmission Visualizer]
        FE --> IOCs[Defanged URL & IOC Table]
        FE --> Graph[Campaign Threat Graph]
        FE --> RepBtn[One-Click Forensic Report Exporter]
    end
```

---

## ⚡ Quick Start Guide (Run in 3 Minutes)

### 📋 Prerequisites
- **Python 3.10+** (Tested on Python 3.10, 3.11, and 3.14)
- **Node.js 18+** & **npm**
- **Git**
- **Groq API Key** (Free tier from [console.groq.com](https://console.groq.com) for Tier 2 LLM analysis)

---

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/driveadityayadav18-art/sih26106-mvp.git
cd sih26106-mvp
```

---

### 2️⃣ Backend Setup
```bash
# 1. Navigate to backend
cd backend

# 2. Create and activate a virtual environment
python -m venv .venv

# Windows (PowerShell / Command Prompt):
.venv\Scripts\activate
# Linux / macOS:
# source .venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Configure environment variables
# Copy template to .env.local
cp .env.example .env.local

# Edit .env.local to include your Groq API key:
# GROQ_API_KEY=gsk_your_actual_groq_api_key_here
# Optional: TRACESHIELD_DB_PATH=data/traceshield.db

# 5. Start the FastAPI backend server
uvicorn main:app --reload --port 8000
```
> 🌐 **Backend API:** `http://localhost:8000`  
> 📖 **Interactive Swagger UI:** `http://localhost:8000/docs`  
> 🩺 **Health Check:** `http://localhost:8000/api/v1/health`

---

### 3️⃣ Frontend Setup
Open a **new terminal tab/window**:
```bash
# 1. Navigate to frontend
cd frontend

# 2. Install Node dependencies
npm install

# 3. Start Next.js development server
npm run dev
```
> 💻 **Analyst UI Console:** `http://localhost:3000`

---

### 4️⃣ Verify Health & Services
```bash
# Check Backend Health
curl http://localhost:8000/api/v1/health
# Response: {"status":"ok"}

# Run Demo Reset (resets SQLite DB and demo artifacts to clean state TS-DEMO-001)
python backend/reset_demo.py
```

---

## 🗄️ SQLite Persistence & Data Architecture

TraceShield AI uses a robust SQLite database engine ([backend/db.py](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/backend/db.py)) as the primary source of truth, replacing volatile in-memory storage while keeping deployment zero-configuration and self-contained.

### Database Location & Configuration
- **Default Database Path:** `backend/data/traceshield.db`
- **Dynamic Path Override:** Configure via the `TRACESHIELD_DB_PATH` environment variable (crucial for isolated unit and integration test runs).

### Database Schema
```sql
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    sha256 TEXT,
    created_at TEXT,
    risk_score INTEGER,
    risk_band TEXT,
    analysis_json TEXT
);
```

### Key Capabilities
1. **High-Watermark Case ID Generation (`TS-DEMO-XXX`)**:  
   The `get_next_case_id()` orchestrator examines both SQLite database entries and disk storage (`data/artifacts/` and `backend/data/artifacts/`) to determine the highest existing integer suffix. Uploads cleanly increment (e.g. `TS-DEMO-001`, `TS-DEMO-002`) without collision or ID reuse.
2. **Cross-Case Reused Indicator Context**:  
   Every new email analysis queries SQLite via `get_all_cases()` to construct a `DetectionContext`. If an incoming email shares an originating IP, Reply-To domain, body URL, or attachment hash with a previous case, the threat engine flags `REUSED_INDICATOR` and links them in the campaign graph.
3. **Demo Reset Automation (`backend/reset_demo.py`)**:  
   Allows demo operators and hackathon judges to reset all stored records and generated artifact files back to zero with one command:
   ```bash
   python backend/reset_demo.py
   ```

---

## 📄 Forensic Incident Reporting Engine

TraceShield AI includes a specialized reporting engine ([backend/reporting/](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/backend/reporting/)) designed to generate verifiable, analyst-ready incident documentation for cyber teams, legal counsel, and law enforcement agencies.

### 1. Standalone Printable HTML Report (`generate_html_report`)
- **Visual Design:** Sleek dark-mode aesthetic on screen with an automatic clean, print-optimized white stylesheet for hard copies or PDF printing.
- **Safety First (Defanged Observables):** Automatically defangs all body links and indicators (`hxxps://`, `[.]`) to prevent accidental clicks or link resolution during investigation.
- **Structured Sections:**
  - Case metadata & cryptographic SHA-256 artifact hash.
  - Sender & Protocol Authentication table (SPF, DKIM, DMARC, CompAuth badges).
  - Risk score meter with risk band indicator (`LOW`, `REVIEW`, `HIGH`).
  - Explainable Reason Codes table with weights and exact JSON evidence paths.
  - Chronological Relay Path Hop table (from host/IP to receiving MX host).
  - Defanged observed body URLs table.
  - Senior Security Analyst reasoning summary (from Tier-2 LLM).
  - Evidentiary Chain-of-Custody audit footer.

### 2. Markdown Incident Report (`generate_markdown_report`)
Outputs clean GitHub-flavored Markdown suitable for ticket integration (Jira/ServiceNow), terminal review, or console reporting.

### 3. Standalone CLI Report Generator (`demo_report.py`)
Investigators can generate reports directly from the terminal without launching the web server:
```bash
# Generate Markdown report for the latest case to stdout
python -m backend.reporting.demo_report

# Generate standalone HTML report and automatically open it in your browser
python -m backend.reporting.demo_report --html

# Generate report directly from a raw .eml file without running the server
python -m backend.reporting.demo_report --eml data/fixtures/04_credential_harvest.eml --html

# Generate report for a specific persisted case ID
python -m backend.reporting.demo_report --case TS-DEMO-001 --html
```

---

## 🔌 Complete REST API Reference

All backend endpoints are prefixed under `/api/v1` and feature full CORS support for the frontend console.

### 1. Health & Readiness Probe
- **`GET /api/v1/health`**
- **Description:** Verifies server responsiveness and DB readiness.
- **Response:**
  ```json
  { "status": "ok" }
  ```

---

### 2. Ingest & Analyze Email Artifact
- **`POST /api/v1/cases`**
- **Payload:** `multipart/form-data` with `file: UploadFile` (`.eml` format)
- **Pipeline Executed:** Cryptographic hashing ➔ RFC parsing ➔ Threat rule evaluation ➔ Cross-case context check ➔ Geolocation enrichment ➔ Tier-2 LLM review (if score ≥ 30 or DMARC fail) ➔ SQLite persistence.
- **Response Schema (`CaseAnalysis`):**
  ```json
  {
    "case_id": "TS-DEMO-001",
    "artifact": {
      "sha256": "3a8c...7b1e",
      "byte_length": 1566,
      "is_demo_data": true
    },
    "message": {
      "subject": "URGENT: Verify Your Corporate Payroll Account",
      "from": { "name": "IT Support", "address": "support@bank-portal.example" },
      "reply_to": "attacker@evil-harvest.ru",
      "return_path": "bounce@mailer.evil-harvest.ru",
      "origin_ip": "41.85.176.17",
      "urls": ["https://evil-login-phish.ru/verify"],
      "authentication": {
        "spf": "softfail",
        "dkim": "fail",
        "dmarc": "fail",
        "compauth": "fail"
      },
      "trace": { "hops": [...] }
    },
    "risk": {
      "score": 90,
      "band": "HIGH",
      "reason_codes": [
        {
          "code": "REPLY_TO_MISMATCH",
          "title": "Reply-To header does not match From sender domain.",
          "message": "Reply-To header does not match From sender domain.",
          "weight": 25,
          "evidence_path": "message.reply_to"
        },
        {
          "code": "URGENT_SUBJECT",
          "title": "Subject line exhibits high urgency / social engineering cues.",
          "message": "Subject line exhibits high urgency / social engineering cues.",
          "weight": 20,
          "evidence_path": "message.subject"
        }
      ],
      "limitations": []
    },
    "ai_review": {
      "is_false_positive": false,
      "adjusted_score": 92,
      "adjusted_band": "HIGH",
      "analyst_summary": "High-confidence credential harvesting attempt with deceptive Reply-To mismatch and spoofed branding."
    },
    "infrastructure": {
      "indicators": [
        { "type": "ip", "value": "41.85.176.17", "source": "originating_relay_hop" }
      ],
      "geo": [
        {
          "indicator": "41.85.176.17",
          "country": "Kenya",
          "city": "Nairobi",
          "provider": "Africa Online / Autonomous System AS36914",
          "accuracy_caveat": "Originating sender IP resolved from earliest relay hop header."
        }
      ],
      "provider_status": "demo_cache"
    },
    "campaign": {
      "related_case_ids": ["TS-DEMO-001", "TS-DEMO-002"],
      "shared_indicators": [
        { "type": "domain", "value": "evil-harvest.ru", "relationship": "SHARED_REPLY_DOMAIN" }
      ],
      "graph_nodes": [...],
      "graph_edges": [...]
    }
  }
  ```

---

### 3. List All Stored Cases
- **`GET /api/v1/cases`**
- **Description:** Returns all analyzed cases stored in SQLite with summary metadata (ordered newest first).
- **Response:**
  ```json
  [
    {
      "id": "TS-DEMO-002",
      "case_id": "TS-DEMO-002",
      "created_at": "2026-09-06T14:20:11.123456+00:00",
      "risk_score": 85,
      "risk_band": "HIGH"
    },
    {
      "id": "TS-DEMO-001",
      "case_id": "TS-DEMO-001",
      "created_at": "2026-09-06T14:18:02.987654+00:00",
      "risk_score": 90,
      "risk_band": "HIGH"
    }
  ]
  ```

---

### 4. Retrieve Case Analysis by ID
- **`GET /api/v1/cases/{case_id}`**
- **Description:** Retrieves the complete JSON analysis object for a specific case ID from SQLite.
- **Errors:** Returns `404 Not Found` if the case does not exist.

---

### 5. Download Forensic Incident Report
- **`GET /api/v1/cases/{case_id}/report?format=html`** (or `?format=markdown`)
- **Description:** Returns a formatted, analyst-ready incident report file with download headers (`Content-Disposition: attachment; filename="TraceShield_Report_{case_id}.html"`).
- **Supported Formats:**
  - `html` (Default for browser viewing and printing)
  - `markdown` (or `md`)

---

## 🖥️ SOC Analyst Console & UI Visualizers

The frontend is built with **Next.js 16 (App Router)**, **TypeScript**, **TailwindCSS**, **Recharts**, and **Lucide Icons** to deliver a high-density, mission-critical SOC analyst experience.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 🛡️ TraceShield AI   [● Backend: localhost:8000]   [📥 Download Forensic Report]  [+ Scan] │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ Case: TS-DEMO-001 | SHA-256: 3a8c7b... [Copy] | Status: HIGH RISK [90/100]             │
├───────────────────────────────┬────────────────────────────────────────────────────────┤
│ 1. Threat Score Radial Meter  │ 2. Sender Authentication Badges                        │
│    Score: 90 / 100            │    SPF: ❌ Fail  |  DKIM: ❌ Fail  |  DMARC: ❌ Fail     │
│    Band: HIGH THREAT          │    From: Security Team <support@service.example>       │
├───────────────────────────────┴────────────────────────────────────────────────────────┤
│ 3. Observed Relay Timeline (RelayTimeline.tsx)                                         │
│    Hop 1: mx.google.com (185.220.101.5) via ESMTPS [⏱ 14:15:02 UTC] (trust: low)       │
│    Hop 2: internal-gateway.org (10.0.0.1) via SMTP    [⏱ 14:15:05 UTC] (trust: internal)  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 4. Observable Body URLs Table (ObservableUrlTable.tsx)                                 │
│    Defanged URL: hxxps://evil-harvest[.]ru/login | Domain: evil-harvest.ru | Risk: +25 │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 5. Campaign Correlation & Threat Graph (ThreatGraph.tsx)                               │
│    [Case: TS-DEMO-001] ─── (SHARED_REPLY_DOMAIN) ───> [domain: evil-harvest.ru]       │
│    [Case: TS-DEMO-002] ─── (SHARED_REPLY_DOMAIN) ───/                                  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 6. Senior Analyst Reasoning (Tier 2 LLM Review - Groq Llama 3.3 70B)                   │
│    Verdict: HIGH THREAT CONFIRMED | False Positive: No                                 │
│    "Deceptive Reply-To mismatch targeting corporate credentials with fake urgency..."  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Highlights of Key Frontend Components
1. **Top Navigation Bar (`Navbar.tsx`)**:
   - **Real-Time Backend Status Pill:** Actively pings `/api/v1/health` to confirm server availability.
   - **Active Case Action Button:** Appears automatically when a case is loaded, enabling instant report download.
2. **Observed Relay Timeline (`RelayTimeline.tsx`)**:
   - Visualizes the chronological Received transmission chain from earliest external sender to recipient mail server.
   - Interactive copy buttons for IP addresses and hostnames.
   - Displays protocol used (ESMTPS, SMTP), timestamp delay, and trust level categorization.
3. **High-Density Observable URL Table (`observable-url-table.tsx`)**:
   - Defangs links for safe inspection.
   - Identifies high-risk indicators like IP-literal URLs, obfuscated schemes, and external redirect trampolines.
4. **Campaign Threat Graph (`ThreatGraph`)**:
   - Visualizes multi-case pivot nodes, shared Reply-To domains, and shared originating sender IPs.
5. **False-Positive & Review Badges**:
   - `FALSE POSITIVE DETECTED` (Green badge): Identifies legitimate marketing or corporate ESP variations.
   - `MANUAL REVIEW RECOMMENDED` (Amber badge): Highlights ambiguous outreach or grey-area solicitations.
   - `HIGH THREAT CONFIRMED` (Red badge): Confirms malicious intent and credential harvesting.

---

## 🧪 Testing, QA & Golden Fixtures (444+ Tests)

TraceShield AI maintains rigorous test coverage with **444 passing modular tests** in `backend/tests/` and **25 end-to-end integration tests** in `backend/test_detection.py`.

### 1. Run the Full Modular Pytest Suite (444 Tests)
To run all 444 unit and rule tests with `backend` module resolution:
```bash
# Windows (PowerShell / CMD):
cmd /c "set PYTHONPATH=. && .venv\Scripts\pytest backend/tests"

# Linux / macOS:
# PYTHONPATH=. pytest backend/tests
```

#### Test Suite Breakdown:
| Test Module | Coverage Area | Tests |
| :--- | :--- | :--- |
| `test_detection_authentication.py` | SPF/DKIM/DMARC/CompAuth failure and softfail logic | 12 tests |
| `test_detection_content.py` | BEC keywords, urgent subject lines, financial wire cues | 78 tests |
| `test_detection_context.py` | Cross-case indicator reuse (IPs, domains, attachments) | 38 tests |
| `test_detection_detector.py` | Score thresholds, band assignment, rule weighting | 57 tests |
| `test_detection_evidence.py` | Insufficient evidence handling, evidence path mapping | 48 tests |
| `test_detection_headers.py` | RFC 5322 header anomalies, missing fields, relay delay | 26 tests |
| `test_detection_identity.py` | Display name spoofing, free webmail abuse, domain typos | 82 tests |
| `test_detection_urls_attachments.py`| Obfuscated URLs, IP URLs, malicious extensions (.exe, .scr) | 78 tests |
| `test_email_parser.py` | MIME decoding, Received hop extraction, charset handling | 23 tests |
| `test_models.py` | Serialization, schema conformity, type validation | 2 tests |
| **Total Passing Tests** | **Full Unit & Rule Verification** | **444 Passed** |

---

### 2. Run End-to-End Integration Tests
```bash
python backend/test_detection.py
```
> Validates file hashing, MIME parsing, rule engine scoring, SQLite persistence, report generation, and API payloads across golden fixtures.

---

### 3. Curated Golden `.eml` Fixtures (`data/fixtures/`)
The repository includes real-world and synthetic `.eml` fixtures to test specific attack vectors:

| Fixture Name | Attack Vector / Test Scenario | Expected Outcome |
| :--- | :--- | :--- |
| `01_payment_diversion.eml` | BEC wire fraud requesting urgent account update | High Risk (Score 80+), BEC reason code |
| `02_invoice_followup.eml` | Invoice scam with urgency cues and mismatched Reply-To | High Risk (Score 75+), Reply-To Mismatch |
| `03_legitimate_internal.eml`| Clean internal communication with passing SPF/DKIM | Low Risk (Score 0, Green), False-Positive Safe |
| `04_credential_harvest.eml` | Security alert spoof with external harvesting link | High Risk (Score 90+), Tier 2 LLM triggered |
| `05_malformed.eml` | Corrupted RFC headers, missing Message-ID and Date | RFC Warning flags, Insufficient Evidence handling |
| `Gaming Army Live...eml` | Multi-hop marketing relay with 3+ intermediate hops | Detailed Relay Hop Timeline, trust evaluation |
| `test_phishing.eml` | Primary phishing attack sample | High Risk (Score 90), Campaign pivot node |
| `test_phishing_2.eml` | Correlated secondary phishing sample sharing domain | Triggers Campaign Correlation Graph match |

---

## 🎬 Live Hackathon Demo & Judging Runbook

Follow these steps during live presentations and judging evaluations:

### Step 1: Clean State Reset (10 Seconds)
Open a terminal in the project root:
```bash
python backend/reset_demo.py
```
*Console output confirms SQLite database reset and artifact cleanup. The next case will start cleanly at `TS-DEMO-001`.*

### Step 2: Ingest Clean Baseline Email (30 Seconds)
1. In the browser (`http://localhost:3000`), drag and drop `data/fixtures/03_legitimate_internal.eml`.
2. **Observe:**
   - Risk score: `0 / 100` (`LOW RISK` green badge).
   - Sender authentication: SPF, DKIM, and DMARC all show green `pass`.
   - No high-risk reason triggers.

### Step 3: Ingest Malicious Phishing Attack (45 Seconds)
1. Click **"+ New Investigation"** in the top navbar.
2. Drag and drop `data/fixtures/04_credential_harvest.eml`.
3. **Observe:**
   - Risk score jumps to `90+ / 100` (`HIGH RISK` red gauge).
   - Reply-To mismatch flagged with exact evidence path `message.reply_to`.
   - Relay timeline displays originating external IP and geographic context.
   - Tier 2 LLM Review displays Senior Security Analyst reasoning explaining the deceptive cues.

### Step 4: Test Campaign Correlation (45 Seconds)
1. Click **"+ New Investigation"**.
2. Drag and drop `data/fixtures/test_phishing_2.eml`.
3. **Observe:**
   - The **Campaign Correlation & Threat Graph** immediately lights up with shared pivot nodes.
   - It links `TS-DEMO-002` to `TS-DEMO-001` via the shared `evil-harvest.ru` Reply-To domain.

### Step 5: Export Forensic Incident Report (20 Seconds)
1. Click the **"Download Forensic Report"** button in the case header or top navbar.
2. A new tab opens showing the standalone printable HTML incident report.
3. Review the SHA-256 chain of custody block, defanged URLs (`hxxps://`), and authentication summary.

---

## 👥 6-Member Team Roles & Edit Boundaries

To maintain software engineering rigor and prevent merge conflicts, each teammate has a designated role and strictly bounded edit scope:

```
┌────────────────────────┬───────────────────────────────────────┬──────────────────────────────────────────┐
│ Teammate               │ Primary Responsibilities              │ STRICT Allowed Edit Scope                │
├────────────────────────┼───────────────────────────────────────┼──────────────────────────────────────────┤
│ Person 1               │ • Platform Lead & FastAPI Architect   │ • backend/main.py                        │
│                        │ • SQLite persistence integration      │ • backend/core/ & backend/models/        │
│                        │ • Lifespan, CORS, routing contracts   │ • Root configs (.gitignore, README.md)   │
│                        │ • PR reviews & integration health     │ • Docker & deployment infrastructure     │
├────────────────────────┼───────────────────────────────────────┼──────────────────────────────────────────┤
│ Person 2               │ • Deep .eml MIME parsing              │ • backend/parser/                        │
│                        │ • Received-header hop reconstruction  │ • backend/evidence/hashing.py            │
│                        │ • SPF / DKIM / DMARC authentication   │ • MIME attachment extractors             │
│                        │ • Parser fixtures & models            │ ❌ DO NOT edit UI or detection rules     │
├────────────────────────┼───────────────────────────────────────┼──────────────────────────────────────────┤
│ Person 3               │ • Threat detection engine             │ • backend/detection/                     │
│                        │ • Risk score computation (0-100)      │ • backend/detection/rules/               │
│                        │ • Deterministic reason codes & weights│ • Tier-2 Groq prompt engineering         │
│                        │ • Insufficient evidence handling      │ ❌ DO NOT edit frontend or parser core   │
├────────────────────────┼───────────────────────────────────────┼──────────────────────────────────────────┤
│ Person 4               │ • Next.js 16 Analyst Dashboard        │ • frontend/src/app/                      │
│                        │ • Relay hop transmission timeline     │ • frontend/src/components/               │
│                        │ • Observable URL & IOC tables         │ • frontend/src/types/                    │
│                        │ • Cybersecurity aesthetics & charts   │ ❌ DO NOT modify backend logic           │
├────────────────────────┼───────────────────────────────────────┼──────────────────────────────────────────┤
│ Person 5               │ • Origin IP Geolocation extraction    │ • backend/data/demo_intel.json           │
│                        │ • ASN / ISP / Proxy / VPN tagger      │ • backend/intel/                         │
│                        │ • Accuracy caveats & infrastructure   │ • Campaign graph node/edge linking       │
│                        │ • Cross-case threat correlation       │ ❌ DO NOT edit frontend or core parser   │
├────────────────────────┼───────────────────────────────────────┼──────────────────────────────────────────┤
│ Person 6               │ • Chain-of-custody audit logs         │ • backend/reporting/ (report generator)  │
│                        │ • Verifiable HTML/MD report exporter  │ • backend/reset_demo.py                  │
│                        │ • Curating golden test fixtures       │ • backend/test_detection.py & tests/     │
│                        │ • Live demo rehearsal & QA operations │ ❌ DO NOT rewrite core API schemas       │
└────────────────────────┴───────────────────────────────────────┴──────────────────────────────────────────┘
```

---

## 📂 Repository Directory Structure

```text
traceshield-mvp/
├── .gitignore                          # Global ignore rules (.env*, __pycache__, node_modules)
├── README.md                           # Master Project Onboarding & Documentation
├── backend/
│   ├── .env.example                    # Environment variable template
│   ├── .env.local                      # Local secrets (GROQ_API_KEY, DB config - NEVER committed)
│   ├── main.py                         # FastAPI Application, Lifespan, Endpoints & Orchestration
│   ├── db.py                           # SQLite Database Engine & Persistence Layer
│   ├── reset_demo.py                   # Demo Reset Script (clears SQLite DB and demo artifacts)
│   ├── requirements.txt                # Python dependencies (FastAPI, Uvicorn, Pydantic, Groq)
│   ├── test_detection.py               # End-to-End Integration Test Suite (25 Tests)
│   ├── data/
│   │   ├── demo_intel.json             # Offline threat intel, ASN, and GeoIP cache
│   │   ├── traceshield.db              # SQLite Database file (generated on startup)
│   │   └── artifacts/                  # Preserved raw .eml artifacts (TS-DEMO-XXX.eml)
│   ├── detection/                      # Person 3: Threat Detection Engine
│   │   ├── config.py                   # Rule weights, threshold scales, and risk bands
│   │   ├── context.py                  # DetectionContext and ReusedIndicator models
│   │   ├── detection.py                # Main ThreatDetector engine
│   │   └── rules/                      # Modular rule evaluation modules
│   │       ├── authentication.py       # SPF, DKIM, DMARC, CompAuth failure rules
│   │       ├── content.py              # Urgency, BEC, wire transfer, credential cues
│   │       ├── context.py              # Cross-case indicator reuse detection
│   │       ├── evidence.py             # Insufficient evidence and score calculation
│   │       ├── headers.py              # RFC 5322 header anomalies and delay checks
│   │       ├── identity.py             # Display name spoofing and free webmail abuse
│   │       └── urls_attachments.py     # Obfuscated URLs, IP hosts, dangerous files
│   ├── evidence/                       # Person 2: Cryptographic Evidence Preservation
│   │   └── hashing.py                  # SHA-256 calculation and byte length verification
│   ├── parser/                         # Person 2: Deep RFC MIME & Header Forensics
│   │   ├── email_parser.py             # RFC MIME decoding, hop parser, URL extractor
│   │   └── models.py                   # Pydantic models for ParsedEmail, Trace, Hops
│   ├── reporting/                      # Person 6: Forensic Incident Reporting Engine
│   │   ├── demo_report.py              # Standalone CLI report generator tool
│   │   └── report_generator.py         # Printable HTML & Markdown report formatters
│   └── tests/                          # 444+ Passing Modular Pytest Test Suite
│       ├── test_detection_authentication.py
│       ├── test_detection_content.py
│       ├── test_detection_context.py
│       ├── test_detection_detector.py
│       ├── test_detection_evidence.py
│       ├── test_detection_headers.py
│       ├── test_detection_identity.py
│       ├── test_detection_urls_attachments.py
│       ├── test_email_parser.py
│       ├── test_models.py
│       └── overall.py
├── data/
│   ├── artifacts/                      # High-watermark preserved .eml files
│   ├── expected/                       # Golden expected parser JSON outputs
│   ├── fixtures/                       # Curated test emails (.eml files)
│   │   ├── 01_payment_diversion.eml
│   │   ├── 02_invoice_followup.eml
│   │   ├── 03_legitimate_internal.eml
│   │   ├── 04_credential_harvest.eml
│   │   ├── 05_malformed.eml
│   │   ├── Gaming Army Live...eml
│   │   ├── test_phishing.eml
│   │   └── test_phishing_2.eml
│   └── reports/                        # Output folder for CLI-generated HTML reports
├── docs/                               # SIH Problem Statement & Master AI Context Prompts
│   ├── psrefrence.md                   # AICTE SIH26106 official reference
│   ├── parser.md                       # Parser specification document
│   ├── Person-1-Master-Prompt.md       # Platform Architect & Integration Lead
│   ├── Person 2 — Master AI Context Prompt.md  # Parser & Header Forensics Specialist
│   ├── Person 3 — Master AI Context Prompt.md  # Threat Detection & Scoring Specialist
│   ├── Person 4 — Master AI Context Prompt.md  # Frontend Lead & UI/UX Developer
│   ├── Person 5 — Master AI Context Prompt.md  # Intelligence & Campaign Correlation
│   └── Person 6 — Master AI Context Prompt.md  # Reporting, QA & Demo Operations
└── frontend/
    ├── package.json                    # Next.js 16, TailwindCSS, Recharts, Lucide
    ├── tsconfig.json                   # TypeScript configuration
    ├── src/
    │   ├── app/
    │   │   ├── layout.tsx              # Root HTML wrapper
    │   │   ├── page.tsx                # Main SOC Analyst Investigation Console
    │   │   └── globals.css             # Cybersecurity dark-mode styles
    │   ├── components/
    │   │   ├── dashboard/
    │   │   │   ├── Navbar.tsx          # Real-time backend status pill & report action
    │   │   │   └── RelayTimeline.tsx   # Interactive Received relay hop visualizer
    │   │   ├── observable-url-table.tsx# High-density defanged URL & IOC table
    │   │   └── ui/                     # Badges, Cards, Gradient Buttons, Tables
    │   ├── lib/                        # Utility functions (cn class combiner)
    │   └── types/
    │       └── case.ts                 # TypeScript data contracts matching API
    └── public/                         # Static assets and icons
```

---

### 🛡️ Built with Pride for Smart India Hackathon 2026 | TraceShield AI Team
*Questions or integration issues? Coordinate with **Person 1 (Team Leader)**.*
