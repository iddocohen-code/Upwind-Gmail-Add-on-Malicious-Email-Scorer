# analyzers/content_modules/url_analyzer.py
import re
import requests
from config import VT_API_KEY, LOWER_URL_SCORE
from utils.network_helpers import get_registered_domain
from utils.text_helpers import sanitize_url

def sandbox_unfurl_url(url):
    """
    DEEP INSPECTION: Active Sandbox logic.
    Follows all redirects to find the FINAL destination hidden behind shorteners.
    Includes a 'Referer Spoofing' fallback to bypass strict WAFs cleanly.
    Returns a tuple: (final_url, is_accessible)
    """
    try:
        # Attempt 1: Our official scanner
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityScanner/1.0'
        }
        
        response = requests.get(url, headers=headers, allow_redirects=True, timeout=5, stream=True)
        
        if response.status_code == 200:
            print(f"[BACKEND LOG] URL Sandbox: Initial access successful. Final URL: {response.url}")
            return response.url, True
            
        # First attempt failed (not 200) - moving to fallback
        print(f"[BACKEND LOG] URL Sandbox: Received status {response.status_code} for {url[:50]}... Attempting Referer Bypass.")
        
        # Attempt 2: Referer Spoofing
        # We use a clean User-Agent and add a declaration that we arrived from Google
        fallback_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': 'https://www.google.com/'
        }
        
        fallback_response = requests.get(url, headers=fallback_headers, allow_redirects=True, timeout=5, stream=True)
        
        if fallback_response.status_code == 200:
            print(f"[BACKEND LOG] URL Sandbox: Referer Bypass successful! Bypassed block cleanly.")
            return fallback_response.url, True
        else:
            print(f"[BACKEND LOG] URL Sandbox: Referer Bypass also failed (Status: {fallback_response.status_code}). Marking as inaccessible.")
            print(fallback_response.url)
            return fallback_response.url, False

    except Exception as e:
        # ZERO-TRUST: True network errors (Timeout, DNS)
        print(f"[!] Sandbox Access Failure for {url}: {e}")
        return url, False

def get_link_reputation(url_from_mail):
    """
    ZERO-TRUST: Verifying the final destination against global threat intel (VirusTotal).
    """
    try:
        headers = {"x-apikey": VT_API_KEY}
        params = {'query': url_from_mail}
        response = requests.get(
            url="https://www.virustotal.com/api/v3/search", 
            headers=headers, 
            params=params, 
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and len(data['data']) > 0:
                stats = data['data'][0].get('attributes', {}).get('last_analysis_stats', {})
                return stats.get('malicious', 0) + stats.get('phishing', 0)
        return 0
    except Exception:
        return 0

def analyze(body_text, sender_domain):
    """
    Professional URL Analyzer: Sanitization -> Sandbox Unfuring -> Reputation Check.
    """
    url_pattern = r'https?://[^\s<>"]+'
    raw_links = list(set(re.findall(url_pattern, body_text)))
    
    if not raw_links:
        return 100

    sender_root = get_registered_domain(sender_domain)
    url_score = 100

    # Inspect top links in the content
    for raw_link in raw_links[:3]:
        # Step 1: SANITIZATION - Clean the URL before processing
        link = sanitize_url(raw_link)
        print(f"[BACKEND LOG] URL: Deep Inspecting sanitized link: {link}")
        
        # Step 2: SANDBOX - Follow redirects to the final destination
        final_destination, is_accessible = sandbox_unfurl_url(url=link)
        
        # Step 3: INTELLIGENT FAIL-SAFE
        # If the link is unreachable after sanitization, we apply a moderate penalty (85)
        # to flag it without killing the score of a legitimate authenticated email.
        if not is_accessible:
            print(f"[BACKEND LOG] URL: Sandbox could not verify integrity. Applying caution.")
            url_score = LOWER_URL_SCORE

        if final_destination != link:
            print(f"[BACKEND LOG] URL: Redirect chain discovered -> {final_destination}")
        
        final_root = get_registered_domain(final_destination)

        # 4. Structural Trust: Check if the FINAL destination aligns with the sender
        if final_root == sender_root:
            print(f"[BACKEND LOG] URL: Final destination domain matches sender's registered domain. No penalty.")
            continue

        # 5. Global Intelligence: Verify the landing page against blacklists
        malicious_flags = get_link_reputation(url_from_mail=final_destination)
        if malicious_flags > 0:
            print(f"[BACKEND LOG] URL: MALICIOUS FINAL DESTINATION: {final_destination}")
            return 0 # Immediate failure for confirmed malicious landing page

    return url_score