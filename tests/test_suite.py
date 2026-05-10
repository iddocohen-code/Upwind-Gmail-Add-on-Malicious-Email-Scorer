# test_suite.py
import requests
import time
import json

# Port 5001 is used to avoid conflict with macOS AirPlay on port 5000
BASE_URL = "http://127.0.0.1:5001/analyze"

def run_suite():
    """
    Focused Test Suite: 5 critical cases to stay within Gemini API free tier limits.
    Includes a 12-second delay between requests to prevent 429 errors.
    """
    
    test_cases = [
        # {
        #     "name": "1. CLEAN: Official Google Notification",
        #     "payload": {
        #         "sender": "noreply@google.com",
        #         "subject": "Security Alert",
        #         "body": "A new device signed into your account. If this was you, no action is needed.",
        #         "ip": "209.85.220.41",
        #         "auth_results": "dkim=pass header.d=google.com; spf=pass;"
        #     },
        #     "expected": "Looks Safe"
        # },
        # {
        #     "name": "2. VETO: Visual Impersonation (Lookalike)",
        #     "payload": {
        #         "sender": "support@g0ogle.com", # Uses '0' instead of 'o'
        #         "subject": "Account Locked",
        #         "body": "Please login to verify your identity.",
        #         "ip": "1.2.3.4",
        #         "auth_results": "dkim=fail; spf=fail;"
        #     },
        #     "expected": "High Risk" # This test does NOT use Gemini API quota
        # },
        # {
        #     "name": "3. AUTH FAIL: Impersonating PayPal",
        #     "payload": {
        #         "sender": "service@paypal.com",
        #         "subject": "Unexpected Payment",
        #         "body": "You sent $800 to an unknown user. If you didn't do this, cancel now.",
        #         "ip": "192.168.1.1", # Fake IP
        #         "auth_results": "dkim=fail; spf=fail;"
        #     },
        #     "expected": "High Risk"
        # },
        # {
        #     "name": "4. SOCIAL ENG: High Pressure/Urgency",
        #     "payload": {
        #         "sender": "ceo-internal@company.com",
        #         "subject": "URGENT REQUEST",
        #         "body": "I need you to buy 50 gift cards for a client immediately. I am in a meeting, do not call.",
        #         "ip": "45.33.22.11",
        #         "auth_results": "dkim=pass; spf=pass;" # Technically valid, tests AI detection
        #     },
        #     "expected": "Caution Advised"
        # },
        # {
        #     "name": "5. MALICIOUS: Phishing Link Detection",
        #     "payload": {
        #         "sender": "verify@secure-check.net",
        #         "subject": "Account Verification",
        #         "body": "Please verify your account here: https://www.haaretz.co.il/",
        #         # "body": "Please verify your account here: http://bit.ly/secure-login-phish",
        #         "ip": "88.77.66.55",
        #         "auth_results": "dkim=pass; spf=pass;"
        #     },
        #     "expected": "High Risk"
        # }
        {
            "name": "4. SUSPICIOUS: Missing WHOIS / No Creation Date",
            "payload": {
                "sender": "billing@unregistered-fake-domain-998877.xyz",
                "subject": "Invoice Overdue",
                "body": "Please find your attached invoice for this month. http://61.0.82.176:43179/i",
                "ip": "185.130.5.200",
                "auth_results": "dkim=pass; spf=pass;" 
            },
            "expected": "Suspicious" 
        }
    ]

    print("="*60)
    print("STARTING OPTIMIZED SECURITY TEST SUITE (5 CASES)")
    print("="*60)

    for i, case in enumerate(test_cases):
        print(f"\n[{i+1}/5] RUNNING: {case['name']}")
        
        try:
            response = requests.post(BASE_URL, json=case['payload'])
            if response.status_code == 200:
                res = response.json()
                print(f"  > Score: {res.get('reliability_score')}")
                print(f"  > Verdict: {res.get('verdict')}")
                print(f"  > Findings: {res.get('findings')}")
                
                status = "PASS" if res.get('verdict') == case['expected'] else "FAIL (Review Weights)"
                print(f"  > STATUS: {status}")
            else:
                print(f"  [!] Server Error: {response.status_code}")
        
        except Exception as e:
            print(f"  [!] Connection Error: {e}")

        # Delay to respect the 5 requests per minute limit
        if i < len(test_cases) - 1:
            print(f"  [~] Waiting 12 seconds for API quota...")
            time.sleep(12)

    print("\n" + "="*60)
    print("TEST SUITE COMPLETED")
    print("="*60)

if __name__ == "__main__":
    run_suite()