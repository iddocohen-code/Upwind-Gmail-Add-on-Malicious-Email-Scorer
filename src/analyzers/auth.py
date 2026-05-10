# analyzers/auth.py
from utils.network_helpers import get_dns_txt_records, check_ip_in_spf, check_dkim_alignment, get_registered_domain
from utils.text_helpers import get_clean_domain

def get_score(sender, ip, auth_results):
    """
    Validates technical identity (SPF, DKIM, DMARC) with Relaxed Alignment and inheritance.
    """
    domain = get_clean_domain(sender)
    if not domain: 
        print("[BACKEND LOG] AUTH: Invalid sender format.")
        return 0, ["Invalid sender format detected."]

    print(f"\n[BACKEND LOG] AUTH: Starting technical scan for {domain}")
    spf_score, dkim_score, dmarc_score = 100, 100, 100
    findings = []

    # 1. SPF (Sender Policy Framework) Check  
    # Allows a domain owner to specify which mail servers are authorized to send emails on their behalf
    txt_records = get_dns_txt_records(domain)
    print(f"[BACKEND LOG] AUTH: Found DNS TXT records: {txt_records}")
    spf_record = next((rec for rec in txt_records if "v=spf1" in rec), None)
    
    if not spf_record:
        findings.append(findings.append("SPF: No authorized server record found for this domain."))
        spf_score -= 50
    else:
        print(f"[BACKEND LOG] AUTH: SPF Record found: {spf_record}")
        if not check_ip_in_spf(spf_record, ip):
            findings.append("SPF: The sender server is not authorized by the domain's DNS.")
            spf_score -= 100

        

    # 2. DKIM Alignment - checking for alignment between  the Digital signature and the sender's domain family
    dkim_pass = check_dkim_alignment(auth_results, domain)
    print(f"[BACKEND LOG] AUTH: DKIM Alignment: {'SUCCESS' if dkim_pass else 'FAILED'}")
    if not dkim_pass:
        dkim_score -= 100
        findings.append("DKIM: Digital signature is missing or misaligned with the sender's domain family.")

    # 3. DMARC Discovery 
    # Technical policy that tells email servers how to handle messages that fail SPF or DKIM check
    root_domain = get_registered_domain(domain)
    dmarc_targets = [domain, root_domain]
    dmarc_found = False
    
    # Use a unique list to check subdomain then root
    for target in list(dict.fromkeys(dmarc_targets)):
        dmarc_records = get_dns_txt_records(f"_dmarc.{target}")
        if dmarc_records:
            dmarc_found = True
            print(f"[BACKEND LOG] AUTH: DMARC record discovered for {target}")
            if not any("p=reject" in r or "p=quarantine" in r for r in dmarc_records):
                dmarc_score -= 10
                findings.append("DMARC: The domain uses a weak security policy (p=none) allowing spoofing.")
            break
    
    if not dmarc_found:
        dmarc_score -= 30
        print("[BACKEND LOG] AUTH: No DMARC policy found.")
        findings.append("DMARC: No global security policy was found for this domain.")

    final_auth_score = (spf_score * 0.35) + (dkim_score * 0.35) + (dmarc_score * 0.3)
    print(f"[BACKEND LOG] AUTH: Final module score: {final_auth_score}")
    return final_auth_score, findings