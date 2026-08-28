"""
MailTrace AI - Explainable AI Engine Service
Feature 2: Explainable AI
"""

import re
from typing import Dict, List, Optional, Tuple, Any
from backend.models.threat import EmailAnalysisInput, ThreatDetectionResult, ThreatTypeItem
from backend.models.explanation import (
    RiskFactorItem, 
    ThreatTypeExplanationItem, 
    ExplainableThreatResult
)
from backend.services.nlp_signals import PATTERNS as NLP_PATTERNS
from backend.services.identity_signals import _parse_sender


# Detailed metadata and templates for each detection signal
SIGNAL_METADATA: Dict[str, Dict[str, str]] = {
    "suspicious_url": {
        "label": "Suspicious Destination URL",
        "category": "URL / DOMAIN",
        "severity": "CRITICAL",
        "explanation": "The email contains a URL with suspicious indicators (such as high-risk TLD, raw IP address, URL shortener, or credential-harvesting path).",
    },
    "suspicious_domain": {
        "label": "Suspicious Domain Indicator",
        "category": "URL / DOMAIN",
        "severity": "HIGH",
        "explanation": "One or more referenced domains contain known phishing keywords, typosquatting patterns, or high-risk TLD extensions.",
    },
    "suspicious_attachment": {
        "label": "Dangerous File Attachment",
        "category": "ATTACHMENT",
        "severity": "CRITICAL",
        "explanation": "The message includes an attachment with a dangerous executable extension or deceptive double extension designed to deliver malware.",
    },
    "suspicious_external_ip": {
        "label": "Suspicious External IP Address",
        "category": "NETWORK / INFRASTRUCTURE",
        "severity": "MEDIUM",
        "explanation": "The email originates from or references an unverified external or raw IP address rather than an established mail gateway.",
    },
    "spf_failure": {
        "label": "SPF Authentication Failure",
        "category": "AUTHENTICATION",
        "severity": "MEDIUM",
        "explanation": "The sending server IP is not authorized to send mail on behalf of the declared sender domain under the domain's SPF policy.",
    },
    "dkim_failure": {
        "label": "DKIM Signature Failure",
        "category": "AUTHENTICATION",
        "severity": "MEDIUM",
        "explanation": "DKIM cryptographic signature verification failed, indicating possible message tampering or unauthorized relay.",
    },
    "dmarc_failure": {
        "label": "DMARC Alignment Failure",
        "category": "AUTHENTICATION",
        "severity": "HIGH",
        "explanation": "DMARC validation failed, demonstrating that the sender domain could not be authenticated or aligned with SPF/DKIM policies.",
    },
    "credential_request": {
        "label": "Credential Harvesting Language",
        "category": "CONTENT",
        "severity": "HIGH",
        "explanation": "The message explicitly requests passwords, login credentials, or account verification from the recipient.",
    },
    "urgent_language": {
        "label": "Artificial Urgency & Pressure",
        "category": "CONTENT",
        "severity": "MEDIUM",
        "explanation": "The message employs high-pressure urgency cues designed to compel immediate action before the recipient can verify authenticity.",
    },
    "threat_language": {
        "label": "Intimidation & Consequence Threats",
        "category": "CONTENT",
        "severity": "MEDIUM",
        "explanation": "The message threatens adverse consequences such as legal action, termination, or penalties if instructions are not followed.",
    },
    "account_suspension": {
        "label": "Account Suspension Pretext",
        "category": "CONTENT",
        "severity": "HIGH",
        "explanation": "The message claims the recipient's account has been suspended or is pending deactivation to trigger panic.",
    },
    "otp_request": {
        "label": "MFA / OTP Code Solicitation",
        "category": "CONTENT",
        "severity": "HIGH",
        "explanation": "The sender solicits one-time passwords, 2FA tokens, or security verification codes to bypass account security.",
    },
    "payment_financial_request": {
        "label": "Direct Payment / Wire Transfer Request",
        "category": "CONTENT",
        "severity": "CRITICAL",
        "explanation": "The email requests immediate wire transfers, cryptocurrency remittance, or urgent financial settlement.",
    },
    "invoice_language": {
        "label": "Invoice Pretext / Billing Lure",
        "category": "CONTENT",
        "severity": "MEDIUM",
        "explanation": "The message references overdue invoices, billing statements, or purchase orders to fabricate business legitimacy.",
    },
    "verify_account": {
        "label": "Account Verification Call-to-Action",
        "category": "CONTENT",
        "severity": "HIGH",
        "explanation": "The email prompts the recipient to validate their identity or re-authenticate their corporate account.",
    },
    "suspicious_cta": {
        "label": "Deceptive Call-to-Action",
        "category": "CONTENT",
        "severity": "MEDIUM",
        "explanation": "Urgent instructions direct the user to click links or download attachments immediately to avert loss.",
    },
    "unusual_financial": {
        "label": "Unusual Banking / Remittance Details",
        "category": "CONTENT",
        "severity": "HIGH",
        "explanation": "The email introduces updated bank account details, SWIFT codes, or non-standard remittance methods such as gift cards.",
    },
    "reply_to_mismatch": {
        "label": "Reply-To Address Redirection",
        "category": "SENDER / IDENTITY",
        "severity": "HIGH",
        "explanation": "The Reply-To destination differs from the apparent sender address, redirecting replies away from the legitimate sender.",
    },
    "return_path_mismatch": {
        "label": "Return-Path Inconsistency",
        "category": "SENDER / IDENTITY",
        "severity": "MEDIUM",
        "explanation": "The envelope bounce address (Return-Path) does not align with the declared header sender.",
    },
    "display_name_mismatch": {
        "label": "Display Name / Identity Spoofing",
        "category": "SENDER / IDENTITY",
        "severity": "HIGH",
        "explanation": "The friendly display name claims to represent a recognized organization or executive, but the actual sending domain is unrelated.",
    },
    "suspicious_sender_domain": {
        "label": "Suspicious Sender Domain",
        "category": "SENDER / IDENTITY",
        "severity": "HIGH",
        "explanation": "The sender's domain exhibits lookalike characteristics, typosquatting, or is hosted on a high-risk top-level domain.",
    },
    "impersonation_indicator": {
        "label": "Executive / Official Impersonation",
        "category": "SENDER / IDENTITY",
        "severity": "CRITICAL",
        "explanation": "Linguistic and identity cues indicate an attempt to impersonate an executive (e.g. CEO, CFO) or IT administrator.",
    },
    "bec_indicator": {
        "label": "Business Email Compromise (BEC) Pattern",
        "category": "SENDER / IDENTITY",
        "severity": "CRITICAL",
        "explanation": "A composite signature of executive authority, confidentiality pleas, and urgent financial redirection strongly matches BEC tactics.",
    },
}


class ExplainableAIService:
    """
    Explainable AI (XAI) Engine Service.
    Transforms raw detection signals from Feature 1 into human-readable evidence,
    concrete text snippets, contribution rankings, and natural-language summaries.
    """

    def extract_evidence(self, signal_name: str, email_data: EmailAnalysisInput) -> Optional[str]:
        """
        Extracts verifiable text evidence, URL, or header comparison from the email payload.
        Ensures strict zero-hallucination compliance by retrieving only actual content.
        """
        sender_disp, sender_addr, sender_domain = _parse_sender(email_data.sender or "")
        _, reply_addr, _ = _parse_sender(email_data.reply_to or "")
        _, return_addr, _ = _parse_sender(email_data.return_path or "")
        full_text = f"{email_data.subject or ''}\n{email_data.body or ''}"

        # 1. URL and Domain Evidence
        if signal_name == "suspicious_url" and email_data.urls:
            return f"Found URL: \"{email_data.urls[0]}\""
        if signal_name == "suspicious_domain" and email_data.domains:
            return f"Flagged Domain: \"{email_data.domains[0]}\""

        # 2. Header and Identity Evidence
        if signal_name == "reply_to_mismatch" and email_data.reply_to:
            return f"Reply-To <{reply_addr}> differs from From <{sender_addr}>"
        if signal_name == "return_path_mismatch" and email_data.return_path:
            return f"Return-Path <{return_addr}> differs from From <{sender_addr}>"
        if signal_name == "display_name_mismatch" and sender_disp:
            return f"Display Name \"{sender_disp}\" used with domain @{sender_domain or 'unknown'}"
        if signal_name == "suspicious_sender_domain" and sender_domain:
            return f"Sending domain: \"{sender_domain}\""

        # 3. Protocol Authentication Evidence
        if signal_name == "spf_failure":
            return f"SPF record result: {email_data.spf.upper() if email_data.spf else 'FAIL'}"
        if signal_name == "dkim_failure":
            return f"DKIM signature verification: {email_data.dkim.upper() if email_data.dkim else 'FAIL'}"
        if signal_name == "dmarc_failure":
            return f"DMARC policy alignment: {email_data.dmarc.upper() if email_data.dmarc else 'FAIL'}"

        # 4. Attachment Evidence
        if signal_name == "suspicious_attachment" and email_data.attachments:
            first_att = email_data.attachments[0]
            att_name = first_att.get("filename") or first_att.get("name") if isinstance(first_att, dict) else str(first_att)
            return f"Attachment: \"{att_name}\""

        # 5. IP Evidence
        if signal_name == "suspicious_external_ip" and email_data.ips:
            return f"IP Address: \"{email_data.ips[0]}\""

        # 6. Linguistic / NLP Snippet Extraction
        if signal_name in NLP_PATTERNS:
            pattern = NLP_PATTERNS[signal_name]
            match = pattern.search(full_text)
            if match:
                start = max(0, match.start() - 25)
                end = min(len(full_text), match.end() + 35)
                snippet = full_text[start:end].replace("\n", " ").strip()
                return f"Excerpt: \"...{snippet}...\""

        # 7. BEC & Impersonation Body Patterns
        if signal_name == "impersonation_indicator":
            if sender_disp:
                return f"Sender claims role: \"{sender_disp}\""
        if signal_name == "bec_indicator":
            if email_data.reply_to and reply_addr != sender_addr:
                return f"Executive identity combined with external Reply-To <{reply_addr}>"

        return None

    def build_risk_factors(
        self, 
        signals: Dict[str, bool], 
        signal_scores: Dict[str, int], 
        email_data: EmailAnalysisInput
    ) -> List[RiskFactorItem]:
        """
        Builds and sorts the list of contributing risk factors with explanations and evidence.
        """
        risk_factors: List[RiskFactorItem] = []

        for signal_name, is_active in signals.items():
            if is_active:
                score = signal_scores.get(signal_name, 0)
                meta = SIGNAL_METADATA.get(signal_name, {
                    "label": signal_name.replace("_", " ").title(),
                    "category": "GENERAL",
                    "severity": "MEDIUM",
                    "explanation": f"Signal '{signal_name}' was triggered during threat evaluation."
                })
                
                evidence = self.extract_evidence(signal_name, email_data)
                
                risk_factors.append(RiskFactorItem(
                    signal=signal_name,
                    label=meta["label"],
                    category=meta["category"],
                    contribution=score,
                    severity=meta["severity"],
                    explanation=meta["explanation"],
                    evidence=evidence
                ))

        # Sort descending by contribution weight
        risk_factors.sort(key=lambda x: x.contribution, reverse=True)
        return risk_factors

    def synthesize_summary(
        self, 
        threat_result: ThreatDetectionResult, 
        risk_factors: List[RiskFactorItem],
        email_data: EmailAnalysisInput
    ) -> str:
        """
        Synthesizes a clear, evidence-grounded natural-language summary for cybersecurity analysts.
        Guarantees no hallucination of unobserved threats.
        """
        score = threat_result.threat_score
        level = threat_result.risk_level
        primary = threat_result.primary_threat

        # Benign / Low-risk handling
        if score < 20 or level == "LOW":
            return (
                f"This email is currently assessed as LOW risk ({score}/100). "
                "No strong phishing, impersonation, credential-theft, or financial-fraud indicators "
                "were detected in the analyzed message content or authentication headers."
            )

        # Highlight top 3 contributing factors
        top_labels = [rf.label for rf in risk_factors[:3]]
        drivers_str = ", ".join(top_labels) if top_labels else "observed security signals"

        summary = (
            f"This email is classified as {level} risk with a Threat Score of {score}/100, "
            f"primarily driven by {drivers_str}. "
        )

        if primary == "PHISHING":
            summary += "The presence of deceptive URLs, account suspension pretexts, or credential requests indicates a high probability of credential phishing."
        elif primary == "BEC":
            summary += "The combination of executive impersonation cues, urgent wire transfer language, and identity mismatches strongly reflects Business Email Compromise tactics."
        elif primary == "SPOOFING / IMPERSONATION":
            summary += "Inconsistencies between the declared sender identity, Reply-To routing, and email authentication failures suggest intentional sender spoofing."
        elif primary == "CREDENTIAL THEFT":
            summary += "The message explicitly attempts to harvest user authentication details, passwords, or verification codes."
        elif primary == "FINANCIAL FRAUD":
            summary += "The message solicits unauthorized invoice settlements, wire transfers, or updated banking coordinates."
        else:
            summary += "These indicators collectively represent elevated security risk warranting further investigation."

        return summary

    def build_threat_type_explanations(
        self, 
        threat_types: List[ThreatTypeItem], 
        signals: Dict[str, bool]
    ) -> List[ThreatTypeExplanationItem]:
        """
        Provides specific rationale for each detected threat category.
        Clearly separates model confidence from threat score.
        """
        explanations: List[ThreatTypeExplanationItem] = []

        for item in threat_types:
            t_type = item.type
            conf = item.confidence

            if t_type == "PHISHING":
                exp = "The message contains suspicious links, deceptive account verification calls-to-action, or panic-inducing suspension pretexts."
            elif t_type == "BEC":
                exp = "The communication exhibits executive impersonation, urgent wire payment requests, or Reply-To address diversion."
            elif t_type == "SPOOFING / IMPERSONATION":
                exp = "The sender's declared identity conflicts with the actual sending domain, Reply-To header, or email authentication results (SPF/DKIM/DMARC)."
            elif t_type == "CREDENTIAL THEFT":
                exp = "The email solicits recipient login credentials, passwords, or multi-factor authentication tokens."
            elif t_type == "FINANCIAL FRAUD":
                exp = "The content requests financial transfers, invoice settlements, or unauthorized bank account changes."
            elif t_type == "MALICIOUS / SUSPICIOUS EMAIL":
                exp = "Dangerous attachment signatures or cumulative security indicators warrant isolation."
            elif t_type == "BENIGN":
                exp = "The message aligns with normal business correspondence with no malicious indicators detected."
            else:
                exp = "Indicators correlate with this threat profile."

            explanations.append(ThreatTypeExplanationItem(
                type=t_type,
                confidence=conf,
                explanation=exp
            ))

        return explanations

    def generate_explanation(
        self, 
        threat_result: ThreatDetectionResult, 
        email_data: EmailAnalysisInput
    ) -> ExplainableThreatResult:
        """
        Main entry point for Feature 2.
        Enriches Feature 1 results with evidence-backed explanations and rankings.
        """
        risk_factors = self.build_risk_factors(
            threat_result.signals, 
            threat_result.signal_scores, 
            email_data
        )

        top_reasons = [rf.label for rf in risk_factors[:5]]
        summary = self.synthesize_summary(threat_result, risk_factors, email_data)
        threat_explanations = self.build_threat_type_explanations(
            threat_result.threat_types, 
            threat_result.signals
        )

        is_benign = threat_result.threat_score < 20 or threat_result.risk_level == "LOW"

        # Generate reassuring negative observations for benign emails
        benign_assurances: List[str] = []
        if is_benign:
            if not threat_result.signals.get("suspicious_url"):
                benign_assurances.append("No suspicious destination URLs or IP hosts detected")
            if not threat_result.signals.get("credential_request"):
                benign_assurances.append("No credential harvesting or password requests identified")
            if not threat_result.signals.get("bec_indicator") and not threat_result.signals.get("payment_financial_request"):
                benign_assurances.append("No urgent wire transfer or financial fraud indicators found")
            if not threat_result.signals.get("reply_to_mismatch"):
                benign_assurances.append("Sender and Reply-To identities align consistently")
            if (email_data.spf or "").lower() == "pass" or (email_data.dmarc or "").lower() == "pass":
                benign_assurances.append("Email authentication headers verified without failure")

        confidence_note = (
            "Assessment is based on observed deterministic and linguistic indicators. "
            "A high threat score indicates elevated risk, but does not by itself prove malicious intent without verification."
        )

        # Note limitation if authentication data was missing
        if email_data.spf == "unknown" and email_data.dkim == "unknown" and email_data.dmarc == "unknown":
            confidence_note += " (Note: Email authentication headers were not provided; analysis relied solely on content and sender heuristics)."

        return ExplainableThreatResult(
            threat_score=threat_result.threat_score,
            risk_level=threat_result.risk_level,
            primary_threat=threat_result.primary_threat,
            threat_types=threat_result.threat_types,
            signals=threat_result.signals,
            signal_scores=threat_result.signal_scores,
            summary=summary,
            risk_factors=risk_factors,
            top_reasons=top_reasons,
            threat_explanations=threat_explanations,
            confidence_note=confidence_note,
            is_benign=is_benign,
            benign_assurances=benign_assurances,
        )


# Global default Explainable AI service instance
default_explainable_service = ExplainableAIService()


def generate_explanation(
    threat_result: ThreatDetectionResult, 
    email_data: EmailAnalysisInput
) -> ExplainableThreatResult:
    """Convenience helper calling the default Explainable AI service."""
    return default_explainable_service.generate_explanation(threat_result, email_data)
