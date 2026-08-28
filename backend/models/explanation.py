"""
MailTrace AI - Explainable AI Data Models
Feature 2: Explainable AI
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from backend.models.threat import ThreatDetectionResult, ThreatTypeItem


class RiskFactorItem(BaseModel):
    """
    Detailed explanation for an individual triggered threat signal.
    Maps detection signal to plain-English analyst reasoning and verifiable evidence.
    """
    signal: str = Field(description="Internal signal identifier (e.g. dmarc_failure)")
    label: str = Field(description="Human-readable title (e.g. DMARC Authentication Failure)")
    category: str = Field(description="Category: SENDER / IDENTITY, AUTHENTICATION, CONTENT, URL / DOMAIN, ATTACHMENT")
    contribution: int = Field(description="Weighted score contribution from Feature 1")
    severity: str = Field(description="Severity rating: CRITICAL, HIGH, MEDIUM, LOW")
    explanation: str = Field(description="Clear analyst-friendly rationale for why this signal contributes to risk")
    evidence: Optional[str] = Field(default=None, description="Actual excerpt, URL, or header comparison from the email")


class ThreatTypeExplanationItem(BaseModel):
    """
    Rationale explaining why a specific threat category was identified.
    Clearly distinguishes classifier confidence from overall threat score.
    """
    type: str = Field(description="Threat category (e.g. PHISHING, BEC, etc.)")
    confidence: float = Field(description="Model confidence score between 0.0 and 1.0", ge=0.0, le=1.0)
    explanation: str = Field(description="Analyst explanation for why this threat type was identified")


class ExplainableThreatResult(BaseModel):
    """
    Comprehensive output contract combining Feature 1 Threat Detection
    and Feature 2 Explainable AI.
    """
    # Feature 1 Core Fields
    threat_score: int = Field(description="Overall normalized threat score 0-100", ge=0, le=100)
    risk_level: str = Field(description="Overall risk level: LOW, MEDIUM, HIGH, CRITICAL")
    primary_threat: str = Field(description="Primary detected threat type")
    threat_types: List[ThreatTypeItem] = Field(default_factory=list)
    signals: Dict[str, bool] = Field(default_factory=dict)
    signal_scores: Dict[str, int] = Field(default_factory=dict)

    # Feature 2 Explainable AI Fields
    summary: str = Field(description="Natural-language analyst assessment summarizing key risk drivers")
    risk_factors: List[RiskFactorItem] = Field(
        default_factory=list, 
        description="Ranked list of contributing signals with evidence and explanations"
    )
    top_reasons: List[str] = Field(
        default_factory=list, 
        description="Top contributing human-readable reasons sorted descending by weight"
    )
    threat_explanations: List[ThreatTypeExplanationItem] = Field(
        default_factory=list, 
        description="Detailed justifications for identified threat categories"
    )
    confidence_note: str = Field(
        default="Assessment is based on observed deterministic and linguistic indicators.",
        description="Guidance on assessment certainty and evidence scope"
    )
    is_benign: bool = Field(default=False, description="True if email is assessed as benign/low risk")
    benign_assurances: List[str] = Field(
        default_factory=list, 
        description="Reassuring clean indicators observed for low-risk emails"
    )
