"""
MailTrace AI - Modular Threat Classification & Confidence Engine
Feature 1: AI Threat Detection
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Tuple
from backend.models.threat import ThreatTypeItem


class BaseThreatClassifier(ABC):
    """
    Modular classifier interface.
    Allows easy extension or swapping with an ML/NLP model (e.g. Scikit-learn TF-IDF) in the future.
    """
    @abstractmethod
    def classify(
        self, 
        signals: Dict[str, bool], 
        threat_score: int
    ) -> Tuple[str, List[ThreatTypeItem]]:
        pass


class RuleBasedHybridClassifier(BaseThreatClassifier):
    """
    High-performance, explainable rule-based threat categorizer.
    Calculates normalized confidence for each threat category from observed security & NLP signals.
    """
    
    def classify(
        self, 
        signals: Dict[str, bool], 
        threat_score: int
    ) -> Tuple[str, List[ThreatTypeItem]]:
        
        # If threat score is low and no high-risk signals fired, classify as BENIGN
        if threat_score < 20:
            benign_confidence = round(max(0.80, 1.0 - (threat_score / 100.0)), 2)
            return "BENIGN", [ThreatTypeItem(type="BENIGN", confidence=benign_confidence)]
            
        category_scores: Dict[str, float] = {}

        # 1. PHISHING
        phishing_points = 0.0
        if signals.get("suspicious_url"): phishing_points += 0.40
        if signals.get("account_suspension"): phishing_points += 0.25
        if signals.get("verify_account"): phishing_points += 0.25
        if signals.get("credential_request"): phishing_points += 0.15
        if signals.get("threat_language"): phishing_points += 0.10
        if signals.get("suspicious_cta"): phishing_points += 0.15
        if signals.get("suspicious_domain") or signals.get("suspicious_sender_domain"): phishing_points += 0.15
        if phishing_points >= 0.20:
            category_scores["PHISHING"] = min(0.96, round(phishing_points, 2))

        # 2. BEC (Business Email Compromise)
        bec_points = 0.0
        if signals.get("bec_indicator"): bec_points += 0.45
        if signals.get("payment_financial_request"): bec_points += 0.25
        if signals.get("impersonation_indicator"): bec_points += 0.25
        if signals.get("reply_to_mismatch"): bec_points += 0.15
        if signals.get("urgent_language"): bec_points += 0.10
        if bec_points >= 0.25:
            category_scores["BEC"] = min(0.97, round(bec_points, 2))

        # 3. SPOOFING / IMPERSONATION
        spoof_points = 0.0
        if signals.get("display_name_mismatch"): spoof_points += 0.35
        if signals.get("impersonation_indicator"): spoof_points += 0.30
        if signals.get("reply_to_mismatch"): spoof_points += 0.20
        if signals.get("return_path_mismatch"): spoof_points += 0.15
        if signals.get("dmarc_failure"): spoof_points += 0.20
        if signals.get("spf_failure"): spoof_points += 0.15
        if signals.get("dkim_failure"): spoof_points += 0.15
        if spoof_points >= 0.25:
            category_scores["SPOOFING / IMPERSONATION"] = min(0.95, round(spoof_points, 2))

        # 4. CREDENTIAL THEFT
        cred_points = 0.0
        if signals.get("credential_request"): cred_points += 0.35
        if signals.get("otp_request"): cred_points += 0.30
        if signals.get("verify_account"): cred_points += 0.20
        if signals.get("suspicious_url"): cred_points += 0.15
        if cred_points >= 0.25:
            category_scores["CREDENTIAL THEFT"] = min(0.88, round(cred_points, 2))

        # 5. FINANCIAL FRAUD
        fin_points = 0.0
        if signals.get("payment_financial_request"): fin_points += 0.40
        if signals.get("unusual_financial"): fin_points += 0.35
        if signals.get("invoice_language"): fin_points += 0.25
        if fin_points >= 0.25:
            category_scores["FINANCIAL FRAUD"] = min(0.94, round(fin_points, 2))

        # 6. MALICIOUS / SUSPICIOUS EMAIL
        if signals.get("suspicious_attachment"):
            category_scores["MALICIOUS / SUSPICIOUS EMAIL"] = 0.90
        elif threat_score >= 40 and not category_scores:
            category_scores["MALICIOUS / SUSPICIOUS EMAIL"] = round(threat_score / 100.0, 2)

        # Fallback if no specific categories triggered but threat_score is medium/high
        if not category_scores:
            category_scores["MALICIOUS / SUSPICIOUS EMAIL"] = round(threat_score / 100.0, 2)

        # Sort threats by confidence descending
        sorted_threats = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)
        threat_items = [ThreatTypeItem(type=t, confidence=c) for t, c in sorted_threats]
        
        primary = threat_items[0].type if threat_items else "BENIGN"
        return primary, threat_items
