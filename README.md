# 🛡️ Fake Offer Letter & Phishing Inspector

> **AI-Powered Forensic Cybersecurity Inspection Dashboard**  
> Detect fraudulent job offer letters, advance-fee rental traps, counterfeit corporate letterheads, and recruitment wire scams in real time.

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React_19-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Bundler-Vite_8-646CFF.svg?logo=vite&logoColor=white)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Styles-Tailwind_v4-38B2AC.svg?logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Google Gemini](https://img.shields.io/badge/AI_Engine-Gemini_3.6_Flash-4285F4.svg?logo=google&logoColor=white)](https://ai.google.dev/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)

---

## 📌 Problem Statement

Recruitment wire fraud and advance-fee contract scams represent one of the fastest-growing cyber threats targeting job seekers and renters. Attackers leverage spoofed corporate identities, disposable domains, and fake checks to coerce victims into:
- Purchasing "work equipment" from sham vendors via irreversible payment channels (Zelle, CashApp, wire transfer, crypto).
- Paying upfront "security deposits" or "application fees" for properties they never saw.
- Bypassing standard recruitment and interview vetting protocols.

**Fake Offer Letter & Phishing Inspector** provides a comprehensive, forensic multi-tier analysis pipeline that evaluates document text, email domains, WHOIS registry age, and deep semantic signals to calculate a dynamic **Scam Threat Index (0–100%)**.

---

## 🚀 Key Features

- **📄 Multi-Format Ingestion:**
  - Drag-and-drop file ingestion supporting **PDF** (`pypdf`), **Microsoft Word** (`python-docx`), and plain text/emails (`.txt`, `.eml`).
  - Raw text ingestion with automatic character counting and validation (10 MB guard).
- **🌐 Domain Telemetry & WHOIS Verification:**
  - Extracts root domains from URLs or recruiter email addresses.
  - Queries domain creation dates via `python-whois` with an automated fallback to **RDAP** over `httpx`.
  - Imposes tiered risk penalties based on domain age (`< 30 days`: +30 pts, `30–90 days`: +15 pts, generic TLDs like `.xyz`/`.top` or hidden privacy: +10 pts).
- **🧠 Forensic AI Analysis (Google Gemini 3.6 Flash):**
  - Analyzes linguistic patterns, counterfeit corporate letterheads, and coercive timers.
  - Structured extraction utilizing strict Pydantic schemas.
  - **Graceful Fallback:** If live AI services are unreachable, the system automatically falls back to deterministic rule matching and highlights an `AI Audit Unavailable — Heuristics Applied` badge.
- **⚡ Dynamic Scam Threat Index (0–100%):**
  - Weighted algorithmic scoring engine:
    $$\text{Threat Index} = \min\Big(100,\; (\text{AI Score} \times 0.40) + \text{Payment Penalty} + \text{Domain Penalty} + \text{Bypass Penalty}\Big)$$
  - Color-coded security bands:
    - `0% – 34%`: 🟢 **Verified Safe / Low Risk**
    - `35% – 69%`: 🟡 **Elevated Risk / Suspicious**
    - `70% – 100%`: 🔴 **Critical Scam Detected**
- **🎯 1-Click Quick Demo Presets:**
  - 🚨 **Equipment Scam:** Remote data entry check-cashing and wire transfer scam.
  - 🏠 **Rental Trap:** Upfront deposit wire fraud for an unseen property.
  - ✅ **Legitimate Offer:** Real corporate Stripe/Google software engineering contract.
- **🛡️ Actionable Countermeasures:** Direct links to report scams to authorities (**FTC**, **FBI IC3**, and **Action Fraud UK**).

---

## 🏗️ System Architecture

```
                               ┌────────────────────────────────┐
                               │   Offer Document / Text / URL  │
                               └───────────────┬────────────────┘
                                               │
                                               ▼
                              ┌───────────────────────────────────┐
                              │     FastAPI Ingestion Endpoint    │
                              │         (POST /api/scan)          │
                              └────────┬─────────────────┬────────┘
                                       │                 │
                ┌──────────────────────▼───────┐  ┌──────▼─────────────────────┐
                │     File / Text Extractor    │  │   Domain WHOIS & RDAP     │
                │    (pypdf, docx, utf-8)      │  │  (Age penalty calculation) │
                └──────────────┬───────────────┘  └──────┬─────────────────────┘
                               │                         │
                               ▼                         ▼
                      ┌─────────────────────────────────────────┐
                      │    Deterministic Regex Heuristics       │
                      │  (Payment, Wire, Channel Red Flags)     │
                      └────────────────┬────────────────────────┘
                                       │
                                       ▼
                      ┌─────────────────────────────────────────┐
                      │   Google Gemini 3.6 Flash Analyzer      │
                      │  (Structured Pydantic JSON Extraction)  │
                      └────────────────┬────────────────────────┘
                                       │
                                       ▼
                      ┌─────────────────────────────────────────┐
                      │    Threat Index Aggregation Engine      │
                      │   (Dynamic Formula Capped at 100%)      │
                      └────────────────┬────────────────────────┘
                                       │
                                       ▼
                      ┌─────────────────────────────────────────┐
                      │   SecOps Cybersecurity Dashboard (UI)   │
                      │    (Gauge, Flags, Telemetry, Recs)      │
                      └─────────────────────────────────────────┘
```

---

## 📂 Project Structure

```text
.
├── backend/
│   ├── services/
│   │   ├── aggregator.py          # Threat Index formula & recommendation builder
│   │   ├── domain_checker.py      # Domain extraction, WHOIS & RDAP query engine
│   │   ├── file_extractor.py      # PDF, DOCX, TXT, EML parser (10MB guard)
│   │   ├── gemini_analyzer.py     # Gemini 3.6 Flash structured AI auditor
│   │   └── heuristics.py          # Regex rule-matching for wire & payment traps
│   ├── tests/
│   │   └── test_pipeline.py       # Automated integration tests
│   ├── .env.example               # Environment configuration template
│   ├── main.py                    # FastAPI application & endpoint definitions
│   ├── requirements.txt           # Python dependency specifications
│   └── schemas.py                 # Pydantic request/response data models
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── DomainDetails.tsx  # Domain WHOIS telemetry badge
│   │   │   ├── FileDropZone.tsx   # Drag-and-drop document upload target
│   │   │   ├── FlagCard.tsx       # Severity-styled evidence card
│   │   │   ├── ScanningOverlay.tsx# Radar animation & multi-step progress
│   │   │   └── ThreatGauge.tsx    # Semi-circular SVG gauge & score breakdown
│   │   ├── api.ts                 # Multipart FormData API client
│   │   ├── App.tsx                # 12-column responsive SecOps dashboard
│   │   ├── index.css              # Tailwind v4 theme tokens & animations
│   │   ├── main.tsx               # React application root
│   │   └── utils.ts               # Threat score classification helpers
│   ├── package.json               # Node.js dependencies & build scripts
│   ├── tsconfig.json              # TypeScript compilation settings
│   └── vite.config.ts             # Vite dev server configuration & API proxy
├── index.html                     # Standalone single-page console (zero-build CDN)
├── .gitignore                     # Git exclusion rules
└── README.md                      # Comprehensive documentation
```

---

## ⚡ Quick Start Guide

### Prerequisites
- **Python 3.10+**
- **Node.js 18+** & **npm**
- **Google Gemini API Key** (optional but recommended; [get one free here](https://aistudio.google.com/))

---

### 1. Clone the Repository
```bash
git clone https://github.com/nagarajchittapur18-dev/Fake-Offer-Letter-Phishing-Inspector.git
cd Fake-Offer-Letter-Phishing-Inspector
```

---

### 2. Backend Setup
```bash
cd backend

# Create and activate a virtual environment (optional)
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
```

Open `backend/.env` and insert your Gemini API Key:
```ini
GEMINI_API_KEY=your_gemini_api_key_here
```

Start the FastAPI backend:
```bash
python -m uvicorn main:app --reload --port 8000
```
> The API will be live at `http://127.0.0.1:8000` with Swagger docs available at `http://127.0.0.1:8000/docs`.

---

### 3. Frontend Setup
In a new terminal window:
```bash
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```

Open your browser to:
👉 **[http://localhost:5173](http://localhost:5173)**

---

### 4. Standalone Version (Zero-Build Option)
If you prefer running without Node/Vite, simply open [`index.html`](index.html) in your browser (or use VS Code Live Server) while the backend is running on port `8000`.

---

## 📡 API Reference

### Health Check
```http
GET /api/health
```
**Response:**
```json
{
  "status": "healthy",
  "message": "Fake Offer Letter & Phishing Inspector API v2 is running."
}
```

---

### Forensic Scan Endpoint
```http
POST /api/scan/flat
Content-Type: multipart/form-data
```

**Parameters:**
| Field | Type | Required | Description |
|---|---|---|---|
| `file` | `File` | Optional | Document file (`.pdf`, `.docx`, `.txt`, `.eml`) |
| `text` | `string` | Optional | Raw offer letter or contract text |
| `url`  | `string` | Optional | Target corporate website or recruiter email |

*Note: At least one of `file` or `text` must be provided.*

---

## 🧪 Running Tests

Verify the backend heuristic and WHOIS pipeline:
```bash
cd backend
python -m pytest tests/test_pipeline.py -v
```

---

## ⚖️ Security & Ethical Disclaimer

This application is engineered for **educational, security research, and consumer protection purposes**. While it employs advanced heuristic and forensic AI techniques, no automated tool can guarantee 100% detection of zero-day social engineering campaigns. Users should always independently verify employment offers directly through official, verified corporate career portals.

---

## 📄 License

Distributed under the **MIT License**.
