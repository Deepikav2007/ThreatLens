"""
MailTrace AI - Protocol & Security Signal Detection
Feature 1: AI Threat Detection
"""

import re
from typing import Dict, List, Any
from urllib.parse import urlparse


DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".hta", ".iso", ".bat", ".cmd", 
    ".ps1", ".js", ".wsf", ".jar", ".msi", ".pif", ".reg", ".dll", ".vbe"
}

SUSPICIOUS_URL_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", 
    ".work", ".click", ".rest", ".fit", ".bar", ".loan", ".link"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", 
    "cutt.ly", "shorturl.at", "tiny.cc", "goo.gl"
}

PHISHING_PATH_KEYWORDS = [
    "login", "signin", "verify", "account", "webscr", "auth", 
    "update", "security", "banking", "credential", "portal"
]

IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _is_suspicious_url(url_str: str) -> bool:
    """Checks if a URL has suspicious indicators (IP host, high risk TLD, shortener, phishing path)."""
    if not url_str:
        return False
    try:
        if not url_str.startswith(("http://", "https://")):
            parsed = urlparse(f"http://{url_str}")
        else:
            parsed = urlparse(url_str)
            
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        
        # 1. Hostname is a raw IP address
        if IP_PATTERN.match(hostname):
            return True
            
        # 2. Hostname is a URL shortener
        if hostname in URL_SHORTENERS:
            return True
            
        # 3. Hostname has high-risk TLD
        for tld in SUSPICIOUS_URL_TLDS:
            if hostname.endswith(tld):
                return True
                
        # 4. Phishing keywords in path combined with generic/unusual hostname
        for kw in PHISHING_PATH_KEYWORDS:
            if kw in path:
                return True
                
        # 5. Lookalike / brand in subdomain (e.g. paypal.com.attacker.com)
        parts = hostname.split(".")
        if len(parts) >= 3:
            for brand in ["paypal", "microsoft", "google", "apple", "amazon", "chase", "netflix"]:
                if brand in parts[:-2]:  # brand is in subdomain rather than apex domain
                    return True
                    
    except Exception:
        return True  # Malformed URLs are suspicious
        
    return False


def _is_suspicious_domain(domain_str: str) -> bool:
    """Checks if a domain has suspicious indicators."""
    if not domain_str:
        return False
    domain_lower = domain_str.lower().strip()
    
    for tld in SUSPICIOUS_URL_TLDS:
        if domain_lower.endswith(tld):
            return True
            
    for kw in ["secure-", "-login", "verify-", "account-", "update-", "service-", "webscr", "paypa1"]:
        if kw in domain_lower:
            return True
            
    return False


def _is_suspicious_attachment(att: Any) -> bool:
    """Check attachment for dangerous or double file extensions."""
    if isinstance(att, str):
        filename = att.lower()
    elif isinstance(att, dict):
        filename = (att.get("filename") or att.get("name") or "").lower()
    else:
        return False
        
    # Check double extension like invoice.pdf.exe
    parts = filename.split(".")
    if len(parts) > 2:
        ext = f".{parts[-1]}"
        prev_ext = f".{parts[-2]}"
        if ext in DANGEROUS_EXTENSIONS or (prev_ext in [".pdf", ".doc", ".docx", ".xls", ".xlsx"] and ext in [".exe", ".scr", ".js", ".vbs"]):
            return True
            
    # Check direct dangerous extension
    for ext in DANGEROUS_EXTENSIONS:
        if filename.endswith(ext):
            return True
            
    return False


def extract_security_signals(
    urls: List[str] = None,
    domains: List[str] = None,
    ips: List[str] = None,
    attachments: List[Any] = None,
    spf: str = "unknown",
    dkim: str = "unknown",
    dmarc: str = "unknown",
) -> Dict[str, bool]:
    """
    Extracts security and authentication signals from the email metadata.
    Returns a dictionary mapping signal names to boolean triggers.
    """
    urls = urls or []
    domains = domains or []
    ips = ips or []
    attachments = attachments or []
    
    # 1. Email authentication failures
    spf_clean = (spf or "unknown").lower().strip()
    dkim_clean = (dkim or "unknown").lower().strip()
    dmarc_clean = (dmarc or "unknown").lower().strip()
    
    spf_failure = spf_clean in {"fail", "softfail", "permerror"}
    dkim_failure = dkim_clean in {"fail", "permerror"}
    dmarc_failure = dmarc_clean in {"fail", "permerror"}
    
    # 2. Suspicious URL presence
    suspicious_url = any(_is_suspicious_url(u) for u in urls)
    
    # 3. Suspicious domain presence
    suspicious_domain = any(_is_suspicious_domain(d) for d in domains)
    
    # 4. Suspicious attachment
    suspicious_attachment = any(_is_suspicious_attachment(a) for a in attachments)
    
    # 5. Suspicious external IP
    suspicious_external_ip = False
    if ips:
        for ip in ips:
            ip_str = str(ip).strip()
            # Flag if valid IP pattern present and non-empty
            if IP_PATTERN.match(ip_str):
                # If email contains explicit IP indicator or failure
                suspicious_external_ip = True
                break

    return {
        "spf_failure": spf_failure,
        "dkim_failure": dkim_failure,
        "dmarc_failure": dmarc_failure,
        "suspicious_url": suspicious_url,
        "suspicious_domain": suspicious_domain,
        "suspicious_attachment": suspicious_attachment,
        "suspicious_external_ip": suspicious_external_ip,
    }
