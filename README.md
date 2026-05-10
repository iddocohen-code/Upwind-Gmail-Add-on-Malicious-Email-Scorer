# Upwind-Gmail-Add-on-Malicious-Email-Scorer

A modular security analysis engine designed to detect maliciousness in real-time. The system integrates directly as a Gmail Add-on and uses a multi-staged pipeline combining technical heuristics, threat intelligence, and semantic AI analysis.

## System Architecture

The project is split into two main components:

1.  **Frontend (Gmail Add-on):** A Google Apps Script-based client that extracts email metadata, calculates attachment hashes natively (SHA-256), and relays the payload to the backend.
2.  **Backend (Python API):** A Flask-based orchestration engine that executes parallel analysis modules to determine a final reliability score.

### The Analysis Pipeline

The engine follows a 4-stage "Hybrid Pipeline" to balance accuracy with performance:

* **Stage 1: Veto (Instant Mitigation):** Immediate blocking of known high-risk impersonation patterns and trusted service spoofing.
* **Stage 2: Technical Parallel Execution:** Simultaneous execution of three core modules:
    * **Auth Module:** Validates SPF, DKIM (Relaxed Alignment), and DMARC policies with smart fallbacks for email forwarding.
    * **Reputation Module:** Cross-references sender IPs against global blacklists and analyzes domain age/registration metadata.
    * **Payload Analysis:** Structural inspection of URLs and attachment metadata/hashes.
* **Stage 3: AI Gatekeeper:** Semantic analysis using Gemini (LLM) is triggered only if the technical scores pass a safety threshold, optimizing API costs and latency.
* **Stage 4: Weighted Aggregation:** Final score calculation based on configurable weights (Reputation, Auth, and Content).

## Tech Stack

* **Backend:** Python 3.9+, Flask, ThreadPoolExecutor.
* **Frontend:** Google Apps Script (JavaScript).
* **AI/ML:** Google GenAI (Gemini 1.5/2.5 Flash).
* **External Integrations:** VirusTotal API (Hash reputation), DNS/Whois lookups.

## Setup & Installation

### Backend Requirements
1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt