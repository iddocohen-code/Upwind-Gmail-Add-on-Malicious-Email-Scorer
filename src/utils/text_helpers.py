# utils/text_helpers.py
import html
import re

def sanitize_text(text):
    """
    Basic sanitization to prevent injection and clean control characters.
    """
    if not text:
        return ""
    clean_text = html.escape(text)
    return "".join(ch for ch in clean_text if ord(ch) >= 32 or ch in "\n\r\t")

def normalize_visual_chars(text):
    """
    Standardizes visual character substitutions to prevent lookalike attacks.
    Example: 'g0ogle' becomes 'googie' (based on the mapping).
    Matches the 'Engineering Hygiene' principle by centralizing logic.
    """
    substitutions = {
        '0': 'o',
        '1': 'i',
        'l': 'i',
        'vv': 'w'
    }
    for char, replacement in substitutions.items():
        text = text.replace(char, replacement)
    return text

def get_clean_domain(sender):
    """
    Extracts and cleans the domain from a sender string.
    Handles HTML entities (&gt;), brackets (>), and trailing punctuation (;).
    """
    if not sender or "@" not in sender:
        return None
    
    # Extract the part after @
    raw_domain = sender.split("@")[-1]
    
    # Split by common delimiters found in email headers/HTML encoding
    clean_domain = re.split(r'[> ;&]', raw_domain)[0]
    
    return clean_domain.lower().strip()

def extract_domain_from_url(url):
    """
    Utility to isolate the domain part from a full URL.
    Example: https://gett.com/login -> gett.com
    """
    if not url:
        return None
    # Remove protocol and path
    domain_part = url.split("//")[-1].split("/")[0].split("?")[0]
    # Reuse our existing cleaning logic for consistency
    return get_clean_domain(f"dummy@{domain_part}")

def sanitize_url(raw_url):
    """
    ROOT CAUSE FIX: Standardizes and cleans URLs from email/HTML artifacts.
    1. Unescapes HTML entities (e.g., &gt; -> >).
    2. Strips trailing characters that aren't part of a valid URL structure.
    Matches 'Engineering Hygiene' by ensuring the sandbox receives a valid target.
    """
    if not raw_url:
        return ""
    
    # Decode HTML entities (&gt; becomes >, &amp; becomes &)
    clean = html.unescape(raw_url)
    
    # Split by characters that mark the end of a URL in an email/HTML context.
    clean = re.split(r'[>\]\)\s]', clean)[0]
    
    # Strip trailing punctuation that belongs to the sentence context, not the URL
    clean = clean.rstrip('.,;!')
    
    return clean.strip()