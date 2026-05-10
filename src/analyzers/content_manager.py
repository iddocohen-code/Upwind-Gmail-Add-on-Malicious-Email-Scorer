# analyzers/content_manager.py
from .content_modules import url_analyzer, nlp_ai_analyzer, attachment_analyzer
from utils.text_helpers import get_clean_domain
from concurrent.futures import ThreadPoolExecutor

def evaluate_payloads(body_text, sender_email, attachments=None):
    """
    Evaluates structural payloads (Attachments and URLs) in parallel.
    Uses an internal ThreadPoolExecutor to minimize latency during network lookups.
    """
    if attachments is None:
        attachments = []
        
    findings = []
    print("\n[BACKEND LOG] CONTENT: --- Starting Parallel Payload Execution ---")
    
    try:
        sender_domain = get_clean_domain(sender_email)
        
        # Using max_workers=2 to run Attachment and URL analysis simultaneously
        with ThreadPoolExecutor(max_workers=2) as executor:
            # Dispatch threads
            future_att = executor.submit(attachment_analyzer.analyze, attachments)
            future_url = executor.submit(url_analyzer.analyze, body_text, sender_domain)

            # --- SECURE EXTRACTION: Attachment Result ---
            try:
                att_score, att_findings = future_att.result()
                findings.extend(att_findings)
                print(f"[BACKEND LOG] CONTENT: Attachment thread finished. Score: {att_score}")
            except Exception as e:
                print(f"[BACKEND LOG] !!! CONTENT THREAD ERROR (Attachments): {e}")
                att_score = 50 # Fallback score for technical failure
                findings.append("System: Attachment structural scan failed due to a technical error.")

            # --- SECURE EXTRACTION: URL Result ---
            try:
                url_score = future_url.result()
                if url_score < 100:
                    findings.append("Content: Found links to external domains that could not be verified.")
                print(f"[BACKEND LOG] CONTENT: URL thread finished. Score: {url_score}")
            except Exception as e:
                print(f"[BACKEND LOG] !!! CONTENT THREAD ERROR (URLs): {e}")
                url_score = 50 # Fallback score for technical failure
                findings.append("System: URL reputation scan failed due to a technical error.")

        # Aggregate Payload Score
        payload_score = min(att_score, url_score)
        print(f"[BACKEND LOG] CONTENT: Parallel Payload Phase complete. Aggregate Score: {payload_score}")
        
        return payload_score, findings

    except Exception as e:
        print(f"[BACKEND LOG] !!! CONTENT CRITICAL FAILURE (Payload Stage): {e}")
        return 50, ["Payload analysis encountered a system-level interruption."]

def evaluate_ai_and_finalize(body_text, payload_score, current_findings, technical_auth_score):
    """
    Executes AI semantic analysis and finalizes the module score.
    Only called if payloads pass the Gatekeeper threshold (>= 50).
    """
    print("\n[BACKEND LOG] CONTENT: --- Starting AI & Finalization Phase ---")
    findings = list(current_findings)
    
    try:
        # AI SEMANTIC ANALYSIS
        ai_score, ai_reason = nlp_ai_analyzer.analyze(body_text)
        
        if ai_score == -429:
            print("[BACKEND LOG] CONTENT: AI Quota limit reached. Scaling without semantic insights.")
            findings.append("System: AI semantic scan skipped (quota). Reliability based on technical payloads.")
            final_score = payload_score
        
        elif ai_score == -1:
            print("[BACKEND LOG] CONTENT: AI technical failure detected.")
            findings.append("System: AI scan failed due to technical limits.")
            final_score = min(payload_score, 85)
            
        else:
            print(f"[BACKEND LOG] CONTENT: AI module finished. Score: {ai_score} | Reason: {ai_reason}")
            if ai_score < 100:
                findings.append(f"AI Insight: {ai_reason}")
            
            # Mitigation Logic
            if technical_auth_score >= 95 and 40 <= ai_score < 80:
                print(f"[BACKEND LOG] CONTENT: Mitigation Triggered. High Auth trust boosted AI score to 80.")
                findings.append("Identity Trust: High sender reliability mitigated content suspicion.")
                ai_score = 80
            
            final_score = min(payload_score, ai_score)
            
        print(f"[BACKEND LOG] CONTENT: AI Score: {final_score}")
        return final_score, findings

    except Exception as e:
        print(f"[BACKEND LOG] !!! CONTENT CRITICAL FAILURE (AI Stage): {e}")
        findings.append("Content semantic analysis failed due to a system error.")
        return min(payload_score, 50), findings