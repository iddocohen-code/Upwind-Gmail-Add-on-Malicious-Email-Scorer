# analyzers/reputation.py
from config import TRUSTED_DOMAINS
from utils.network_helpers import get_domain_creation_date, check_ip_against_blacklist, is_known_infrastructure
from datetime import datetime
from utils.text_helpers import get_clean_domain

def get_score(sender, ip):
    """
    Evaluates sender reputation using domain age and IP status.
    Now uses Zero Trust Infrastructure validation and 40% (Domain) / 60% (IP) weighting.
    """
    domain = get_clean_domain(sender)
    domain_score = 100
    findings = []
    
    print(f"\n[BACKEND LOG] REPUTATION: Starting analysis for {domain}")

    # Stage 1: Whitelist Check
    if domain and domain in TRUSTED_DOMAINS:
        print(f"[BACKEND LOG] REPUTATION: Domain '{domain}' is whitelisted. Scoring 100.")
        return 100.0, []

    # Stage 2: Domain Age Analysis (Weight: 40%)
    if domain:
        creation_date = get_domain_creation_date(domain)
        if creation_date:
            if creation_date.tzinfo: 
                creation_date = creation_date.replace(tzinfo=None)
            
            age_in_days = (datetime.now() - creation_date).days
            print(f"[BACKEND LOG] REPUTATION: Domain age verified: {age_in_days} days.")
            
            if age_in_days < 30:
                domain_score = 0
                findings.append("The sender's domain is extremely new, posing a high security risk.")
            elif age_in_days < 365:
                domain_score = 60
                findings.append(f"The sender's domain is relatively new (registered {age_in_days} days ago).")
        else:
            print("[BACKEND LOG] REPUTATION: No registration history found.")
            domain_score -= 15

    # Stage 3: IP Blacklist & Ownership Check (Weight: 60%)
    ip_score = 100
    is_blacklisted, black_list_checked = check_ip_against_blacklist(ip)
    print(f"[BACKEND LOG] REPUTATION: IP {ip} blacklist check: {'FAILED' if is_blacklisted else 'PASSED'}")
    
    if is_blacklisted:
        findings.append(f"The sender's IP address ({ip}) is listed on global blacklists.")
        ip_score = 0
    else:
        if not is_blacklisted and not black_list_checked:
            ip_score -= 5
            findings.append("Unable to verify IP reputation due to an error in the blacklist check.")
        # ZERO TRUST: If it's clean, is it an official mail server?
        if not is_known_infrastructure(ip):
            ip_score -= 5
            findings.append("Sender IP originates from an unverified or anonymous infrastructure.")

    # Stage 4: Final Aggregation (40% Domain, 60% IP)
    final_score = (domain_score * 0.4) + (ip_score * 0.6)
    print(f"[BACKEND LOG] REPUTATION: Final module score: {final_score}")
    return final_score, findings