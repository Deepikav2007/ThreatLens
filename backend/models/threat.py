"""
MailTrace AI - Data Models
Feature 1: AI Threat Detection
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class EmailAnalysisInput(BaseModel):
    """
    Structured email payload consumed by the AI Threat Detection Engine.
    All fields are optional or have defaults to gracefully handle varied inputs.
    """
    sender: Optional[str] = Field(default="", description="From email address or display name + address")
    recipient: Optional[str] = Field(default="", description="To email address")
    reply_to: Optional[str] = Field(default="", description="Reply-To header address")
    return_path: Optional[str] = Field(default="", description="Return-Path header address")
    subject: Optional[str] = Field(default="", description="Email subject line")
    body: Optional[str] = Field(default="", description="Plain text or parsed email body content")
    urls: Optional[List[str]] = Field(default_factory=list, description="Extracted URLs found in the email")
    domains: Optional[List[str]] = Field(default_factory=list, description="Extracted domains found in the email")
    ips: Optional[List[str]] = Field(default_factory=list, description="Extracted IP addresses")
    attachments: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list, 
        description="Attachment metadata (e.g. filename, file_type, size)"
    )
    spf: Optional[str] = Field(default="unknown", description="SPF validation status: pass, fail, softfail, unknown")
    dkim: Optional[str] = Field(default="unknown", description="DKIM validation status: pass, fail, unknown")
    dmarc: Optional[str] = Field(default="unknown", description="DMARC validation status: pass, fail, unknown")


class ThreatTypeItem(BaseModel):
    """Single threat classification entry with its normalized confidence."""
    type: str = Field(description="Threat category (e.g. PHISHING, BEC, SPOOFING / IMPERSONATION, etc.)")
    confidence: float = Field(description="Confidence score from 0.0 to 1.0", ge=0.0, le=1.0)


class ThreatDetectionResult(BaseModel):
    """
    Standard output contract for Feature 1 (AI Threat Detection).
    Exposes raw signals and signal_scores for downstream consumption by Feature 2 (Explainable AI).
    """
    threat_score: int = Field(description="Overall normalized threat score between 0 and 100", ge=0, le=100)
    risk_level: str = Field(description="Overall risk level: LOW, MEDIUM, HIGH, CRITICAL")
    primary_threat: str = Field(description="Primary detected threat type or BENIGN")
    threat_types: List[ThreatTypeItem] = Field(
        default_factory=list, 
        description="Ranked list of detected threat types with confidence scores"
    )
    signals: Dict[str, bool] = Field(
        default_factory=dict, 
        description="Boolean map of triggered detection signals"
    )
    signal_scores: Dict[str, int] = Field(
        default_factory=dict, 
        description="Weighted score contributions per triggered signal"
    )
