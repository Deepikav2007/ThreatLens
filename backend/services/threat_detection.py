"""
MailTrace AI - AI Threat Detection Engine Service
Feature 1: AI Threat Detection
"""

from typing import Dict, List, Tuple
from backend.models.threat import EmailAnalysisInput, ThreatDetectionResult, ThreatTypeItem
from backend.services.nlp_signals import extract_nlp_signals
from backend.services.identity_signals import extract_identity_signals
from backend.services.security_signals import extract_security_signals
from backend.services.scoring_engine import calculate_threat_score
from backend.services.threat_classifier import RuleBasedHybridClassifier, BaseThreatClassifier


class ThreatDetectionService:
    """
    Main Threat Detection Engine Orchestrator.
    Consumes structured email data, extracts signals, calculates threat score,
    and classifies primary/secondary threats with confidence scores.
    """
    def __init__(self, classifier: BaseThreatClassifier = None):
        self.classifier = classifier or RuleBasedHybridClassifier()

    def detect_phishing(self, signals: Dict[str, bool], text: str = "") -> bool:
        """Determines if the signals indicate a phishing attempt."""
        return bool(
            signals.get("suspicious_url")
            or (signals.get("verify_account") and signals.get("credential_request"))
            or (signals.get("account_suspension") and signals.get("suspicious_cta"))
        )

    def detect_bec(self, signals: Dict[str, bool], text: str = "") -> bool:
        """Determines if the signals indicate Business Email Compromise."""
        return bool(
            signals.get("bec_indicator")
            or (signals.get("impersonation_indicator") and signals.get("payment_financial_request"))
        )

    def classify_threat(
        self, 
        signals: Dict[str, bool], 
        threat_score: int, 
        text: str = ""
    ) -> Tuple[str, List[ThreatTypeItem]]:
        """Invokes the modular classifier to assign primary and secondary threats with confidence."""
        return self.classifier.classify(signals, threat_score)

    def detect_threat(self, email_data: EmailAnalysisInput) -> ThreatDetectionResult:
        """
        End-to-end evaluation of an email input.
        Returns a ThreatDetectionResult matching the system contract.
        """
        # 1. Extract content & linguistic NLP signals
        nlp_signals = extract_nlp_signals(
            subject=email_data.subject or "",
            body=email_data.body or ""
        )

        # 2. Extract identity & sender signals
        identity_signals = extract_identity_signals(
            sender=email_data.sender or "",
            reply_to=email_data.reply_to or "",
            return_path=email_data.return_path or "",
            subject=email_data.subject or "",
            body=email_data.body or ""
        )

        # 3. Extract protocol & security signals
        security_signals = extract_security_signals(
            urls=email_data.urls or [],
            domains=email_data.domains or [],
            ips=email_data.ips or [],
            attachments=email_data.attachments or [],
            spf=email_data.spf or "unknown",
            dkim=email_data.dkim or "unknown",
            dmarc=email_data.dmarc or "unknown"
        )

        # 4. Consolidate all signals
        all_signals: Dict[str, bool] = {
            **nlp_signals,
            **identity_signals,
            **security_signals,
        }

        # 5. Calculate normalized threat score, risk level, and signal contributions
        threat_score, risk_level, signal_scores = calculate_threat_score(all_signals)

        # 6. Classify primary and secondary threat types with confidence scores
        combined_text = f"{email_data.subject or ''} {email_data.body or ''}"
        primary_threat, threat_types = self.classify_threat(
            all_signals, 
            threat_score, 
            text=combined_text
        )

        return ThreatDetectionResult(
            threat_score=threat_score,
            risk_level=risk_level,
            primary_threat=primary_threat,
            threat_types=threat_types,
            signals=all_signals,
            signal_scores=signal_scores,
        )


# Global default service instance
default_threat_service = ThreatDetectionService()


def detect_threat(email_data: EmailAnalysisInput) -> ThreatDetectionResult:
    """Convenience function calling the default threat detection service."""
    return default_threat_service.detect_threat(email_data)
