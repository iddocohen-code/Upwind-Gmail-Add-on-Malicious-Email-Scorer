# config.py
import os
# Analysis weights for the final score calculation
WEIGHTS = {
    "auth": 0.25,
    "reputation": 0.30,
    "content": 0.45
}

# VirusTotal API configuration for global threat intelligence and domain data
# Loaded from environment variables for security
VT_API_KEY = os.environ.get("VT_API_KEY")

# Initialize the GenAI Client using an environment variable
# This prevents the API key from being exposed in source control
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")


# --- GLOBAL WHITELIST ---
# Highly trusted domains used for Alignment checks and Veto bypass.
# Includes Tech Giants, Financial Services, Infrastructure, and SaaS.
TRUSTED_DOMAINS = [
    # Tech & Infrastructure
    "google.com", "microsoft.com", "apple.com", "amazon.com", "aws.amazon.com",
    "cloudflare.com", "github.com", "gitlab.com", "bitbucket.org", "docker.com",
    "heroku.com", "digitalocean.com", "vercel.com", "netlify.com", "okta.com",
    
    # Financial & Payments (International)
    "paypal.com", "stripe.com", "square.com", "visa.com", "mastercard.com",
    "americanexpress.com", "chase.com", "bankofamerica.com", "hsbc.com",

    # Israeli Trusted Services (Added to prevent WHOIS/Reputation false positives)
    "max.co.il", "cal-online.co.il", "bankhapoalim.co.il", 
    "leumi.co.il", "discountbank.co.il", "fibi.co.il", "mizrahi-tefahot.co.il",
    
    # Communication & Collaboration
    "slack.com", "zoom.us", "atlassian.com", "trello.com",
    "asana.com", "monday.com", "zoom.com", "discord.com", "whatsapp.com",
    "telegram.org", "signal.org", "skype.com",
    
    # Productivity & SaaS
    "salesforce.com", "hubspot.com", "zendesk.com", "dropbox.com", "box.com",
    "adobe.com", "docusign.com", "mailchimp.com", "intercom.com", "notion.so",
    "canva.com", "figma.com", "shopify.com", "wix.com",
    
    # Social Media & Content
    "linkedin.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "reddit.com", "youtube.com", "netflix.com", "pinterest.com",
    
    # Government & Academic
    "gov.il", "ac.il", "edu", "gov", "org", "wikipedia.org"
]

# --- OBFUSCATION TOOLS ---
LINK_SHORTENERS = [
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "buff.ly", "rebrand.ly", 
    "shorturl.at", "tiny.cc", "bit.do", "cutt.ly", "ow.ly", "bl.ink", 
    "linktree", "t.me", "shorte.st", "adf.ly", "bitly.com", "goo.gl", 
    "mcaf.ee", "su.pr", "post.ly", "tiny.pl", "u.to", "v.gd", "yao.li"
]

# --- GLOBAL BLACKLIST ---
MALICIOUS_DOMAINS = [
    "secure-login-verify.net", "update-your-account.biz", "claim-reward.ru",
    "verify-identity-now.com", "login-microsoft-support.online", "gift-card-win.top",
    "account-security-alert.site", "billing-issue-resolved.info"
]

# --- URL SANDBOX CONFIG ---
LOWER_URL_SCORE = 85
