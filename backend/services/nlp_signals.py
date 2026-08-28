"""
MailTrace AI - NLP & Content Signal Detection
Feature 1: AI Threat Detection
"""

import re
from typing import Dict


# Compile regex patterns for fast local detection
PATTERNS = {
    "urgent_language": re.compile(
        r"\b(urgent(ly)?|immediate(ly)?|asap|act\s+now|action\s+required|right\s+away|"
        r"without\s+delay|prompt\s+response|time[-\s]sensitive|within\s+(?:24|12|48)\s*hours|"
        r"do\s+not\s+delay|requires?\s+immediate\s+attention)\b",
        re.IGNORECASE,
    ),
    "threat_language": re.compile(
        r"\b(suspend(ed|ion)?|terminat(ed|ion)?|restrict(ed|ion)?|locked?|legal\s+action|"
        r"lawsuit|penalt(y|ies)|unauthorized\s+access|breach(ed)?|deactivat(ed|ion)?|"
        r"consequences|law\s+enforcement|permanent(ly)?\s+closed?)\b",
        re.IGNORECASE,
    ),
    "account_suspension": re.compile(
        r"\b(account\s+(?:(?:will|has|is|was)\s+(?:been\s+)?)?(?:suspended|locked|deactivated|closed|restricted)|"
        r"suspension\s+notice|access\s+has\s+been\s+restricted|prevent\s+(?:account\s+)?suspension|"
        r"account\s+termination\s+warning)\b",
        re.IGNORECASE,
    ),
    "credential_request": re.compile(
        r"\b(password|credentials?|login\s+details|sign[-\s]in\s+to\s+verify|update\s+your\s+password|"
        r"reset\s+password|security\s+questions?|re-enter\s+your\s+credentials|"
        r"confirm\s+your\s+password|enter\s+your\s+(?:username|passcode))\b",
        re.IGNORECASE,
    ),
    "otp_request": re.compile(
        r"\b(one[-\s]time\s+pass(?:word)?|otp|2fa\s+code|mfa\s+code|verification\s+code|"
        r"authentication\s+code|security\s+pin|token\s+code|confirm\s+code)\b",
        re.IGNORECASE,
    ),
    "payment_financial_request": re.compile(
        r"\b(wire\s+transfer|remit(?:tance)?|payment\s+required|send\s+funds|transfer\s+funds|"
        r"cryptocurrency|bitcoin|btc|gift\s+cards?|direct\s+deposit|routing\s+number|"
        r"bank\s+transfer|settle\s+the\s+invoice|remit\s+payment|process\s+payment)\b",
        re.IGNORECASE,
    ),
    "invoice_language": re.compile(
        r"\b(invoice\s+(?:attached|due|overdue|pending|#\d+|details)|billing\s+statement|"
        r"past\s+due\s+invoice|outstanding\s+balance|remittance\s+advice|purchase\s+order|po#\d+)\b",
        re.IGNORECASE,
    ),
    "verify_account": re.compile(
        r"\b(verify\s+your\s+account|confirm\s+your\s+identity|validate\s+(?:your\s+)?account|"
        r"identity\s+verification|confirm\s+(?:your\s+)?details|security\s+review\s+required|"
        r"re-activate\s+your\s+account|validate\s+credentials)\b",
        re.IGNORECASE,
    ),
    "suspicious_cta": re.compile(
        r"\b(click\s+here\s+immediately|click\s+the\s+link\s+below|follow\s+this\s+link|"
        r"download\s+(?:the\s+)?attachment\s+now|open\s+the\s+attachment\s+to\s+view|"
        r"verify\s+now\s+by\s+clicking|login\s+to\s+prevent\s+loss)\b",
        re.IGNORECASE,
    ),
    "unusual_financial": re.compile(
        r"\b(swift\s+code|iban|new\s+bank\s+(?:account\s+)?details|changed\s+banking\s+details|"
        r"wire\s+instructions|apple\s+gift\s+card|steam\s+card|vanilla\s+visa|escrow\s+account)\b",
        re.IGNORECASE,
    ),
}


def extract_nlp_signals(subject: str = "", body: str = "") -> Dict[str, bool]:
    """
    Scans the combined email subject and body for linguistic threat signals.
    Returns a dictionary mapping signal names to boolean triggers.
    """
    full_text = f"{subject or ''} {body or ''}"
    
    detected: Dict[str, bool] = {}
    for signal_name, pattern in PATTERNS.items():
        detected[signal_name] = bool(pattern.search(full_text))
        
    return detected
