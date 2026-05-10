# analyzers/veto.py
from config import TRUSTED_DOMAINS
from utils.text_helpers import normalize_visual_chars, get_clean_domain

def check_all(sender):
    """
    Runs high-confidence security triggers using ONLY the sender address.
    Part of the 'Early Exit' strategy to stop malicious input early.
    """
    # No need for .get() because sender is now a string
    if not sender:
        return False, ""
    
    # Check: Impersonation via Lookalike Domain
    if is_lookalike(sender):
        return True, "Potential executive impersonation (Lookalike domain detected)."
    
    return False, ""

def is_lookalike(sender):
    """
    Standard domain analysis logic.
    """
    if "@" not in sender:
        return False
    
    domain = get_clean_domain(sender)
    if domain in TRUSTED_DOMAINS:
        return False

    normalized_input = normalize_visual_chars(domain)
    for trusted in TRUSTED_DOMAINS:
        if normalized_input == normalize_visual_chars(trusted):
            return True 
            
    return False