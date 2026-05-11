# Upwind Gmail Add-on: Malicious Email Scorer

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

## Design Rationale

The architecture was engineered to ensure high performance, modularity, and precise root-cause analysis.

### 1. Multi-Vector Analysis Logic
Instead of a monolithic check, the system deconstructs email security into three distinct technical vectors: **Identity** (Auth), **Infrastructure** (Reputation), and **Content** (Payloads). This allows the engine to isolate failures; for example, a legitimate sender with a misconfigured DNS won't be treated the same as an active phishing server.

### 2. Orchestration & Sub-Engine Modularity
The system follows a **Manager-Sub-Engine pattern** orchestrated by `engine.py`. A single central engine executes multiple specialized sub-engines:
* **Modularity:** New detection modules (e.g., OCR or Sandbox) can be plugged into the pipeline without refactoring the core logic.
* **Granular Feedback:** Each sub-engine provides its own "verdict" and findings, allowing the system to pinpoint the exact root of a security risk (e.g., a "New Domain" vs. a "Malicious Hash").
* **Centralized Utils:** To avoid code duplication, all shared networking and text-processing logic is abstracted into a `utils/` library, serving as a single source of truth.

### 3. High-Concurrency Parallelism
To minimize end-to-end latency, the technical modules (Auth, Reputation, and Payload Analysis) are executed simultaneously using a `ThreadPoolExecutor`. This parallel execution ensures that the total processing time is dictated by the slowest single module rather than the sum of all checks, providing near-instant results for the end user.

### 4. Conditional AI Gatekeeper
Semantic analysis via Gemini (AI) is integrated within the Content Manager but is not triggered for every request.
* **Performance Optimization:** The engine uses "Gatekeeper" logic to evaluate structural results first.
* **Bypass Logic:** If technical payloads (e.g., a known malicious attachment hash) already provide a conclusive "High Risk" verdict, the AI analysis is bypassed to save runtime and API resources.

## Security & System Hardening: Chronological Analysis Pipeline

The engine is built with a focus on system resilience, ensuring that malicious inputs are mitigated at each stage of the data flow.

### Phase 1: Edge Mitigation (Frontend)
Security starts at the source to protect backend resources:
* **Client-Side Hashing:** To prevent Denial of Service (DoS) attacks via massive file transfers, attachment hashes (SHA-256) are computed natively within Google's infrastructure. 
* **Zero-Byte Transfer:** The backend never handles actual file content. By processing only metadata and hashes, we eliminate risks associated with memory exhaustion or accidental execution of malicious binaries.

### Phase 2: Ingress & Sanitization (API Entry)
As soon as data reaches the Flask environment:
* **Input Sanitization:** Every incoming string (Subject, Sender, Body) is stripped of dangerous characters or escape sequences to block basic injection attempts.
* **Environment Isolation:** The backend operates within an isolated container. This isolation ensures that even if a logic vulnerability is found, the process has no access to the host system or internal network.

### Phase 3: Orchestration & Logic Bypassing
The `engine.py` orchestrator optimizes security vs. performance:
* **The "Veto" Fast-Fail:** High-confidence threats (like direct impersonation) are blocked in the first millisecond, instantly terminating the analysis to save CPU and API resources.
* **Conditional Execution:** Semantic AI analysis is treated as a secondary tier. If technical sub-engines (Auth or Reputation) detect a definitive threat, the AI module is bypassed entirely to minimize the system's attack surface.

### Phase 4: Semantic Analysis Hardening (AI Stage)
When deep inspection is required:
* **XML-Based Delimitation:** To block "Prompt Injection" (attackers hiding commands in the email text), the content is wrapped in `<email_body>` tags.
* **Logic Enforcement:** The system prompt explicitly defines these tags as raw data, instructing the model to ignore any instructions found within the email body.

### Phase 5: Post-Analysis Cleanup
* **Stateless Operation:** The system is entirely stateless. Once the analysis is dispatched back to the Gmail UI, all temporary data is purged from memory. No sensitive email content is ever written to permanent storage.