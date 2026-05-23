# utils/network_helpers.py
import whois
import requests
from datetime import datetime
import dns.resolver
import socket
import re
import tldextract
from config import VT_API_KEY
from config import trusted_providers

def get_registered_domain(domain):
    """
    Extracts the eTLD+1 (Registered Domain) using tldextract.
    Essential for identifying the root owner of subdomains.
    Example: 'mail.tau.ac.il' -> 'tau.ac.il'
    """
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"

def get_domain_creation_date(domain):
    """
    Retrieves domain creation date using WHOIS with a VirusTotal fallback.
    Includes Root Domain Fallback (Option 1) to handle subdomains.
    """
    def query_whois(target):
        try:
            w = whois.whois(target)
            if w.creation_date:
                created = w.creation_date
                # WHOIS can return a list or a single datetime object
                return created[0] if isinstance(created, list) else created
        except Exception:
            return None

    # Attempt 1: Standard WHOIS query on the specific domain
    creation_date = query_whois(domain)

    # Attempt 2: Root Domain Fallback (Option 1 Implementation)
    root_domain = get_registered_domain(domain)
    if not creation_date and root_domain != domain:
        print(f"  [~] WHOIS failed for {domain}. Trying registered domain: {root_domain}")
        creation_date = query_whois(root_domain)
        
    return creation_date

def get_dns_txt_records(domain):
    """Fetches DNS TXT records for Auth module checks."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        answers = resolver.resolve(domain, 'TXT')
        return [str(rdata) for rdata in answers]
    except Exception:
        return []

def check_ip_in_spf(spf_record, ip):
    """
    Structural check to see if an IP is authorized within a given SPF string.
    """
    return ip in spf_record or "all" in spf_record

def check_dkim_alignment(auth_results, sender_domain):
    """
    Validates if the DKIM signing domain has a relaxed alignment with the sender domain.
    Updated to compare Registered Domains (Option 1).
    """
    auth_lower = auth_results.lower()
    if "dkim=pass" not in auth_lower:
        return False

    # Extract signing domain (e.g., d=spmail.uber.com)
    match = re.search(r"header\.[di]=@?([a-zA-Z0-9.-]+)", auth_lower)
    if not match:
        return True # Trust platform verification if alignment data is unavailable

    signing_domain = match.group(1)
    
    # Relaxed Alignment: Compare Registered Domains
    sender_root = get_registered_domain(sender_domain)
    signing_root = get_registered_domain(signing_domain)
    
    print(f"[BACKEND LOG] AUTH: Comparing roots -> Sender: {sender_root} | Signer: {signing_root}")
    return sender_root == signing_root

def check_ip_against_blacklist(ip):
    """
    Queries VirusTotal to check if an IP is blacklisted.
    """
    in_blacklist = False
    black_list_checked = False
    try:
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            in_blacklist = (stats.get('malicious', 0) + stats.get('phishing', 0)) > 0
            black_list_checked = True
    except Exception:
        black_list_checked = False
    return in_blacklist, black_list_checked

def is_known_infrastructure(ip):
    """
    ZERO TRUST: Checks if the IP belongs to a known/trusted mail provider or has valid PTR.
    Uses reverse DNS (PTR) to verify if the server identifies itself legitimately.
    """
    try:
        host = socket.gethostbyaddr(ip)[0].lower()
        print(f"[BACKEND LOG] PTR Lookup for {ip}: {host}")
        return any(provider in host for provider in trusted_providers)
    except Exception:
        return False
