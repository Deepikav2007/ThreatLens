"""
MailTrace AI - Identity & Sender Signal Detection
Feature 1: AI Threat Detection
"""

import re
from email.utils import parseaddr
from typing import Dict, Optional, Tuple


FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", 
    "aol.com", "icloud.com", "protonmail.com", "mail.com", "zoho.com"
}

KNOWN_ORGANIZATIONS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "bank of america", "chase", "wells fargo", "citi", "internal revenue service",
    "irs", "facebook", "meta", "instagram", "linkedin", "dropbox", "docuSign"
]

EXECUTIVE_TITLES = re.compile(
    r"\b(ceo|cfo|coo|cto|president|managing\s+director|chief\s+executive|board\s+of\s+directors|"
    r"executive\s+director|vp|vice\s+president|human\s+resources|hr\s+director|it\s+support|"
    r"it\s+admin|system\s+administrator|payroll|finance\s+department)\b",
    re.IGNORECASE,
)

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "secure-", "-login", "verify-", "account-", "update-", "service-",
    "support-", "portal-", "-auth", "security-", "webscr", "paypa1", "amaz0n"
]

HIGH_RISK_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work", 
    ".click", ".rest", ".fit", ".bar", ".loan"
}


def _extract_domain(email_addr: str) -> str:
    """Extract domain from an email address."""
    if not email_addr:
        return ""
    if "@" in email_addr:
        return email_addr.split("@")[-1].strip().lower()
    return ""


def _parse_sender(sender_str: str) -> Tuple[str, str, str]:
    """
    Parse a sender string into (display_name, email_address, domain).
    Handles formats like 'PayPal Support <support@paypal.com>' or 'user@domain.com'.
    """
    if not sender_str:
        return "", "", ""
    name, addr = parseaddr(sender_str)
    domain = _extract_domain(addr)
    return name.strip(), addr.strip().lower(), domain


def extract_identity_signals(
    sender: str = "",
    reply_to: str = "",
    return_path: str = "",
    subject: str = "",
    body: str = "",
) -> Dict[str, bool]:
    """
    Analyzes sender identity, headers, and impersonation indicators.
    Returns a dictionary mapping signal names to boolean triggers.
    """
    disp_name, sender_addr, sender_domain = _parse_sender(sender)
    _, reply_addr, reply_domain = _parse_sender(reply_to)
    _, return_addr, return_domain = _parse_sender(return_path)
    
    full_text = f"{subject} {body}"
    
    # 1. Reply-To mismatch
    reply_to_mismatch = False
    if reply_domain and sender_domain and reply_domain != sender_domain:
        reply_to_mismatch = True
    elif reply_addr and sender_addr and reply_addr != sender_addr:
        reply_to_mismatch = True

    # 2. Return-Path mismatch
    return_path_mismatch = False
    if return_domain and sender_domain and return_domain != sender_domain:
        return_path_mismatch = True
    elif return_addr and sender_addr and return_addr != sender_addr:
        return_path_mismatch = True

    # 3. Display name mismatch / brand impersonation
    display_name_mismatch = False
    lower_disp_name = disp_name.lower()
    
    # Check if display name claims to be a known organization while domain doesn't match
    for org in KNOWN_ORGANIZATIONS:
        if org in lower_disp_name and org.replace(" ", "") not in sender_domain:
            display_name_mismatch = True
            break
            
    # Check if executive title is in display name while using public/free webmail
    has_exec_title = bool(EXECUTIVE_TITLES.search(disp_name))
    if has_exec_title and sender_domain in FREE_WEBMAIL_DOMAINS:
        display_name_mismatch = True

    # 4. Suspicious sender domain
    suspicious_sender_domain = False
    if sender_domain:
        for keyword in SUSPICIOUS_DOMAIN_KEYWORDS:
            if keyword in sender_domain:
                suspicious_sender_domain = True
                break
        for tld in HIGH_RISK_TLDS:
            if sender_domain.endswith(tld):
                suspicious_sender_domain = True
                break

    # 5. Executive / Official Impersonation indicator
    impersonation_indicator = False
    if display_name_mismatch or (has_exec_title and (reply_to_mismatch or suspicious_sender_domain)):
        impersonation_indicator = True
    # Executive impersonation language in body (e.g., 'Are you at your desk?', 'I need you to process this confidential wire')
    exec_body_pattern = re.compile(
        r"\b(are\s+you\s+(?:at\s+your\s+desk|available)|strictly\s+confidential|"
        r"do\s+not\s+discuss\s+with\s+anyone|wire\s+instructions\s+from\s+ceo)\b",
        re.IGNORECASE
    )
    if exec_body_pattern.search(full_text) and (has_exec_title or reply_to_mismatch or sender_domain in FREE_WEBMAIL_DOMAINS):
        impersonation_indicator = True

    # 6. BEC (Business Email Compromise) indicator
    bec_indicator = False
    bec_keywords = re.compile(
        r"\b(wire\s+transfer|urgent\s+payment|invoice\s+payment|bank\s+details\s+update|"
        r"remit\s+funds|process\s+payment|new\s+beneficiary)\b",
        re.IGNORECASE
    )
    if (impersonation_indicator or has_exec_title or reply_to_mismatch) and bec_keywords.search(full_text):
        bec_indicator = True

    return {
        "display_name_mismatch": display_name_mismatch,
        "suspicious_sender_domain": suspicious_sender_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "impersonation_indicator": impersonation_indicator,
        "bec_indicator": bec_indicator,
    }
