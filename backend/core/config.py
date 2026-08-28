"""
MailTrace AI - Configuration & Settings
Features 1–5: Threat Detection, Explainable AI, Forensics, IOC Extraction & Threat Intelligence
"""

import os
from typing import Dict

# Scoring weights for threat signals (Feature 1)
DEFAULT_SIGNAL_WEIGHTS: Dict[str, int] = {
    # Security Signals
    "suspicious_url": 20,
    "suspicious_domain": 15,
    "suspicious_attachment": 20,
    "suspicious_external_ip": 10,
    "spf_failure": 10,
    "dkim_failure": 10,
    "dmarc_failure": 15,
    
    # Content & NLP Signals
    "credential_request": 15,
    "urgent_language": 10,
    "threat_language": 10,
    "account_suspension": 15,
    "otp_request": 15,
    "payment_financial_request": 20,
    "invoice_language": 10,
    "verify_account": 15,
    "suspicious_cta": 10,
    
    # Identity & Sender Signals
    "reply_to_mismatch": 15,
    "return_path_mismatch": 10,
    "display_name_mismatch": 15,
    "suspicious_sender_domain": 15,
    "impersonation_indicator": 20,
    "bec_indicator": 20,
}

# Risk level boundaries
RISK_THRESHOLDS = {
    "LOW": (0, 19),
    "MEDIUM": (20, 39),
    "HIGH": (40, 69),
    "CRITICAL": (70, 100),
}

# Threat Intelligence Configuration (Feature 5)
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

# Mode: "auto" (uses real if API key exists, else mock), "real" (requires keys), "mock" (always mock)
THREAT_INTEL_MODE: str = os.getenv("THREAT_INTEL_MODE", "auto")

# Safety & Rate-limiting controls
MAX_INTEL_LOOKUPS_PER_TYPE: int = int(os.getenv("MAX_INTEL_LOOKUPS_PER_TYPE", "5"))
INTEL_REQUEST_TIMEOUT_SECONDS: float = float(os.getenv("INTEL_REQUEST_TIMEOUT_SECONDS", "8.0"))
INTEL_CACHE_TTL_SECONDS: int = int(os.getenv("INTEL_CACHE_TTL_SECONDS", "3600"))

# App metadata
APP_NAME = "MailTrace AI"
APP_VERSION = "1.4.0 - Features 1–5 (Detection, XAI, Forensics, IOCs & Threat Intel)"
API_PREFIX = "/api/v1"
