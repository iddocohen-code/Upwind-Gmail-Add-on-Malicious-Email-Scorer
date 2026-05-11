# Upwind Gmail Add-on: Malicious Email Scorer

A modular security analysis engine designed to detect maliciousness in real-time. The system integrates directly as a Gmail Add-on and uses a multi-staged pipeline combining technical heuristics, threat intelligence, and semantic AI analysis.

## System Architecture

The project is split into two main components:

1. Frontend (Gmail Add-on): A Google Apps Script-based client that extracts email metadata, calculates attachment hashes natively (SHA-256), and relays the payload to the backend.
2. Backend (Python API): A Flask-based orchestration engine that executes parallel analysis modules to determine a final reliability score.

### The Analysis Pipeline

The engine follows a 4-stage "Hybrid Pipeline" to balance accuracy with performance:

* Stage 1: Veto (Instant Mitigation): Immediate blocking of known high-risk impersonation patterns and trusted service spoofing.
* Stage 2: Technical Parallel Execution: Simultaneous execution of Auth (SPF/DKIM/DMARC), Reputation (IP/Domain), and Payload Analysis (URLs/Hashes).
* Stage 3: AI Gatekeeper: Semantic analysis using Gemini (LLM) is triggered only if the technical scores pass a safety threshold.
* Stage 4: Weighted Aggregation: Final score calculation based on configurable weights.

## Design Rationale

The architecture was engineered to ensure high performance, modularity, and precise root-cause analysis.

### 1. Multi-Vector Analysis Logic
Instead of a monolithic check, the system deconstructs email security into three distinct technical vectors: Identity (Auth), Infrastructure (Reputation), and Content (Payloads). This allows the engine to isolate failures independently.

### 2. Orchestration & Sub-Engine Modularity
The system follows a Manager-Sub-Engine pattern orchestrated by engine.py. A single central engine executes multiple specialized sub-engines, allowing new detection modules to be plugged in without refactoring core logic.

### 3. High-Concurrency Parallelism
To minimize end-to-end latency, the technical modules are executed simultaneously using a ThreadPoolExecutor. This ensures that the total processing time is dictated by the slowest single module rather than the sum of all checks.

### 4. Conditional AI Gatekeeper
The engine uses "Gatekeeper" logic to evaluate structural results first. If technical payloads provide a conclusive "High Risk" verdict, the AI analysis is bypassed to save runtime and API resources.

## Security & System Hardening: Chronological Analysis Pipeline

### Phase 1: Edge Mitigation (Frontend)
* Client-Side Hashing: Attachment hashes (SHA-256) are computed natively within Google's infrastructure. 
* Zero-Byte Transfer: The backend never handles actual file content, eliminating risks of memory exhaustion or malicious binaries.

### Phase 2: Ingress & Sanitization (API Entry)
* Input Sanitization: Every incoming string is stripped of dangerous characters to block injection attempts.
* Environment Isolation: The backend operates within an isolated container, ensuring no access to the host system.

### Phase 3: Orchestration & Logic Bypassing
* The "Veto" Fast-Fail: High-confidence threats are blocked in the first millisecond, terminating the analysis instantly.
* Conditional Execution: AI analysis is bypassed entirely if technical modules detect a definitive threat.

### Phase 4: Semantic Analysis Hardening (AI Stage)
* XML-Based Delimitation: Content is wrapped in <email_body> tags to block Prompt Injection.
* Logic Enforcement: The system prompt instructs the model to treat these tags as raw data, ignoring internal instructions.

### Phase 5: Post-Analysis Cleanup
* Stateless Operation: All temporary data is purged from memory after analysis. No sensitive content is ever written to permanent storage.

## Getting Started: Installation & Execution

Follow these steps to deploy the hybrid engine, either for local development or production.

### 1. Prerequisites
* Python 3.10+
* Google Account with permissions to deploy Gmail Add-ons.
* API Keys: VT_API_KEY (VirusTotal) and GOOGLE_API_KEY (Gemini).
* Tunneling Tool: ngrok or localhost.run to expose your local port via HTTPS.

### 2. Environment Configuration
Create a .env file in the root directory:
VT_API_KEY=your_virustotal_key
GOOGLE_API_KEY=your_gemini_key
PORT=5001
Note: Port 5001 avoids conflicts with macOS AirPlay on port 5000.

### 3. Backend Setup (Local)
# 1. Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the server
python src/main.py

### 4. Exposing the Backend (The Tunnel)
Google Apps Script requires an HTTPS public URL. For local demos:
ssh -R 80:localhost:5001 nokey@localhost.run
Copy the provided HTTPS URL.

### 5. Gmail Add-on Deployment (Frontend)
1. Open Google Apps Script and create a new project.
2. Paste the content of frontend/code.gs.
3. In appsscript.json, ensure the scopes match the provided file in this repo.
4. Update the API_URL variable in code.gs with your HTTPS tunnel/production URL.
5. Click Deploy > Test Deployments and install the Add-on to your Gmail account.

### 6. Verification & Health Check
Verify the backend independently:
curl -s http://127.0.0.1:5001/analyze -X POST \
  -H "Content-Type: application/json" \
  -d '{"sender":"test@example.com","subject":"Hello","body":"Test content","ip":"0.0.0.0"}'

### 7. Optional: Automated Tests
python tests/test_suite.py

## Production Deployment
The repository includes a Procfile for Railway/Heroku:
web: gunicorn --chdir src main:app