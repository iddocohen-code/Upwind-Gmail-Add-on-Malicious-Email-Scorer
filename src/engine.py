# engine.py
import analyzers.veto as veto
import analyzers.auth as auth
import analyzers.reputation as reputation
import analyzers.content_manager as content
from config import WEIGHTS
from concurrent.futures import ThreadPoolExecutor

def run_analysis(email_data):
    """
    Main orchestration engine implementing the Hybrid Pipeline.
    Executes technical modules in parallel and uses a Gatekeeper for AI analysis.
    Includes robust error handling for thread execution.
    """
    sender = email_data.get('sender')
    ip = email_data.get('ip')
    auth_results = email_data.get('auth_results', "")
    attachments = email_data.get('attachments', [])
    body_text = email_data.get('body', '')
    
    all_findings = []
    
    # STAGE 1: VETO (Instant check for known impersonation)
    is_veto, veto_reason = veto.check_all(sender) 
    if is_veto:
        print(f"[BACKEND LOG] ENGINE: VETO TRIGGERED - {veto_reason}")
        return {
            "reliability_score": 0, 
            "verdict": "High Risk", 
            "findings": ["Direct impersonation of a trusted service detected."],
            "reasoning": veto_reason
        }

    # STAGE 2: PARALLEL EXECUTION (Auth, Reputation, and Payload Analysis)
    print("\n[BACKEND LOG] ENGINE: Launching parallel execution for technical modules...")
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        # Submit tasks to the thread pool
        future_rep = executor.submit(reputation.get_score, sender, ip)
        future_auth = executor.submit(auth.get_score, sender, ip, auth_results)
        future_pay = executor.submit(content.evaluate_payloads, body_text, sender, attachments)
        
        # --- SECURE EXTRACTION OF RESULTS ---
        
        # Extraction: Reputation
        try:
            rep_score, rep_findings = future_rep.result()
        except Exception as e:
            print(f"[BACKEND LOG] !!! THREAD FAILED (Reputation): {e}")
            # Fallback to zero trust to ensure safety, documenting the crash
            rep_score, rep_findings = 0, ["System: Reputation thread failed due to technical error."]

        # Extraction: Authentication
        try:
            auth_score, auth_findings = future_auth.result()
        except Exception as e:
            print(f"[BACKEND LOG] !!! THREAD FAILED (Auth): {e}")
            auth_score, auth_findings = 0, ["System: Auth thread failed due to technical error."]

        # Extraction: Structural Payloads (Links/Files)
        try:
            payload_score, payload_findings = future_pay.result()
        except Exception as e:
            print(f"[BACKEND LOG] !!! THREAD FAILED (Payloads): {e}")
            payload_score, payload_findings = 0, ["System: Content payload thread failed."]

    all_findings.extend(rep_findings)
    all_findings.extend(auth_findings)
    
    # STAGE 3: THE GATEKEEPER (Conditional AI Analysis)
    if payload_score < 50:
        # Early Exit: Payloads are already highly suspicious, skip AI to save resources.
        print(f"\n[BACKEND LOG] ENGINE: Payload score ({payload_score}) is below threshold. Bypassing AI.")
        content_score = payload_score
        all_findings.extend(payload_findings)
        all_findings.append("System: Critical payload detected. AI analysis skipped for safety.")
    else:
        # Proceed with semantic AI analysis
        print(f"\n[BACKEND LOG] ENGINE: Payloads passed Gatekeeper. Initiating AI...")
        ai_score, ai_findings = content.evaluate_ai_and_finalize(
            body_text, payload_score, payload_findings, auth_score
        )
        all_findings.extend(ai_findings)
        content_score = ai_score*0.3+payload_score*0.7 # Weighted combination to balance structural and semantic insights

    # STAGE 4: Final Weighted Calculation
    print("\n[BACKEND LOG] ENGINE: Final Aggregation (Weights)")
    w_rep = rep_score * WEIGHTS["reputation"]
    w_auth = auth_score * WEIGHTS["auth"]
    w_cont = content_score * WEIGHTS["content"]
    
    final_score = round(w_rep + w_auth + w_cont, 1)
    print(f"[BACKEND LOG] Final Score Components -> Rep: {rep_score} | Auth: {auth_score} | Content: {content_score}")

    return {
        "reliability_score": final_score, 
        "verdict": "Safe" if final_score > 80 else "Suspicious" if final_score >= 50 else "High Risk", 
        "findings": all_findings
    }