"""
MailTrace AI - API Endpoints
Features 1–5: Threat Detection, Explainable AI, Forensics, IOC Extraction & Threat Intelligence
"""

from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, UploadFile, File
from backend.models.threat import EmailAnalysisInput, ThreatDetectionResult
from backend.models.explanation import ExplainableThreatResult
from backend.models.forensics import ForensicEvidenceResult, RawEmlInput
from backend.models.ioc import IocExtractionResult, IocExtractionInput
from backend.models.intel import ThreatIntelligenceResult, ThreatIntelligenceInput
from backend.services.threat_detection import detect_threat
from backend.services.explainable_ai import generate_explanation
from backend.services.email_forensics import default_forensics_service, analyze_email_forensics
from backend.services.ioc_extractor import default_ioc_service, extract_iocs
from backend.services.threat_intelligence import default_intel_service, enrich_iocs_with_threat_intel
from backend.data.demo_emails import DEMO_EMAILS
from backend.data.eml_samples import EML_SAMPLES

router = APIRouter()


# ==========================================================
# FEATURE 1: AI THREAT DETECTION
# ==========================================================

@router.post(
    "/analyze/threat",
    response_model=ThreatDetectionResult,
    summary="Analyze email payload for cyber threats (Feature 1)",
    description="Processes structured email metadata and content to compute threat score, risk level, and primary/secondary threat categories."
)
async def analyze_threat_endpoint(email_data: EmailAnalysisInput) -> ThreatDetectionResult:
    """Dedicated endpoint for Feature 1 Threat Detection."""
    try:
        return detect_threat(email_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat detection failed: {str(e)}")


# ==========================================================
# FEATURE 2: EXPLAINABLE AI
# ==========================================================

@router.post(
    "/analyze/explain",
    response_model=ExplainableThreatResult,
    summary="Explain threat analysis with evidence and risk factor ranking (Feature 2)",
    description="Evaluates email threat score and produces human-readable explanations, evidence mappings, contribution ranking, and natural language assessment."
)
async def explain_threat_endpoint(email_data: EmailAnalysisInput) -> ExplainableThreatResult:
    """Dedicated endpoint for Feature 2 Explainable AI."""
    try:
        threat_result = detect_threat(email_data)
        explanation = generate_explanation(threat_result, email_data)
        return explanation
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Explanation generation failed: {str(e)}")


@router.post(
    "/analyze",
    response_model=ExplainableThreatResult,
    summary="Unified email threat analysis & explanation endpoint",
    description="Standard analysis entry point executing both Threat Detection and Explainable AI."
)
async def unified_analyze_endpoint(email_data: EmailAnalysisInput) -> ExplainableThreatResult:
    """Unified email analysis endpoint returning threat assessment with evidence explanations."""
    return await explain_threat_endpoint(email_data)


# ==========================================================
# FEATURE 3: EMAIL FORENSICS
# ==========================================================

@router.post(
    "/analyze/forensics",
    response_model=ForensicEvidenceResult,
    summary="Deep forensic analysis of raw RFC 822 .eml string (Feature 3)",
    description="Extracts headers, reconstructs SMTP Received relay path, verifies SPF/DKIM/DMARC evidence, computes attachment SHA-256 hashes, and records anomalies."
)
async def analyze_forensics_endpoint(payload: RawEmlInput) -> ForensicEvidenceResult:
    """Accepts raw .eml string and returns comprehensive forensic analysis."""
    try:
        return analyze_email_forensics(payload.raw_eml)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Forensic analysis failed: {str(e)}")


@router.post(
    "/analyze/forensics/upload",
    response_model=ForensicEvidenceResult,
    summary="Upload raw .eml file for forensic investigation (Feature 3)",
    description="Accepts a raw .eml file upload and performs in-memory RFC 822 forensic parsing."
)
async def upload_forensics_endpoint(file: UploadFile = File(...)) -> ForensicEvidenceResult:
    """Handles raw .eml file upload and returns forensic analysis."""
    try:
        content_bytes = await file.read()
        return analyze_email_forensics(content_bytes)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload forensic analysis failed: {str(e)}")


# ==========================================================
# FEATURE 4: IOC EXTRACTION
# ==========================================================

@router.post(
    "/analyze/iocs",
    response_model=IocExtractionResult,
    summary="Extract and normalize Indicators of Compromise (Feature 4)",
    description="Extracts URLs, domains, IPv4/IPv6 addresses, emails, cryptographic hashes, and hostnames with source provenance and scope classification."
)
async def analyze_iocs_endpoint(payload: IocExtractionInput) -> IocExtractionResult:
    """Dedicated endpoint for Feature 4 IOC Extraction."""
    try:
        forensics = analyze_email_forensics(payload.raw_eml)
        return default_ioc_service.extract_from_forensics(forensics, payload.raw_eml)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IOC extraction failed: {str(e)}")


# ==========================================================
# FEATURE 5: THREAT INTELLIGENCE
# ==========================================================

@router.post(
    "/analyze/intelligence",
    response_model=ThreatIntelligenceResult,
    summary="Enrich IOCs with VirusTotal and AbuseIPDB threat intelligence (Feature 5)",
    description="Asynchronously queries external threat intelligence providers, applies caching and private IP protections, and normalizes reputation findings."
)
async def analyze_intelligence_endpoint(payload: ThreatIntelligenceInput) -> ThreatIntelligenceResult:
    """Dedicated endpoint for Feature 5 Threat Intelligence."""
    try:
        if payload.raw_eml:
            forensics = analyze_email_forensics(payload.raw_eml)
            iocs = default_ioc_service.extract_from_forensics(forensics, payload.raw_eml)
        elif payload.indicators:
            # Construct minimal IOC container from list
            from backend.models.ioc import IpIoc, DomainIoc, UrlIoc, HashIoc
            iocs = IocExtractionResult()
            for ind in payload.indicators:
                if ind.startswith("http://") or ind.startswith("https://"):
                    iocs.urls.append(UrlIoc(value=ind, normalized=ind))
                elif "@" in ind:
                    iocs.emails.append(ind)
                elif any(c in ind for c in [":", "."]) and ind.replace(".", "").isdigit():
                    iocs.ips.append(IpIoc(value=ind, scope="public"))
                elif len(ind) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in ind):
                    iocs.hashes.append(HashIoc(value=ind, algorithm="SHA256" if len(ind)==64 else ("SHA1" if len(ind)==40 else "MD5")))
                else:
                    iocs.domains.append(DomainIoc(value=ind))
        else:
            raise HTTPException(status_code=400, detail="Must provide either 'raw_eml' or 'indicators'")

        return await default_intel_service.enrich_iocs(iocs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat intelligence query failed: {str(e)}")


# ==========================================================
# COMPLETE MULTI-FEATURE PIPELINE (Features 1–5)
# ==========================================================

@router.post(
    "/analyze/eml",
    summary="End-to-end processing of raw .eml (Forensics + IOCs + Threat Intel + Detection + XAI)",
    description="Runs Feature 3 Forensics, Feature 4 IOCs, Feature 5 Threat Intelligence, Feature 1 Detection, and Feature 2 Explainable AI."
)
async def analyze_complete_eml_endpoint(payload: RawEmlInput) -> Dict[str, Any]:
    """Complete end-to-end pipeline starting from raw .eml RFC 822 input."""
    try:
        # 1. Feature 3: Forensics
        forensics = analyze_email_forensics(payload.raw_eml)
        
        # 2. Feature 4: IOC Extraction
        iocs = default_ioc_service.extract_from_forensics(forensics, payload.raw_eml)

        # 3. Feature 5: Threat Intelligence
        intel = await default_intel_service.enrich_iocs(iocs)

        # 4. Bridge into Feature 1 & 2
        body_content = forensics.mime_analysis.plain_text_preview or ""
        email_data = default_forensics_service.convert_forensics_to_analysis_input(forensics, body_content)
        
        threat_result = detect_threat(email_data)
        explanation = generate_explanation(threat_result, email_data)
        
        return {
            "forensics": forensics,
            "iocs": iocs,
            "threat_intelligence": intel,
            "threat_analysis": threat_result,
            "explanation": explanation
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Complete EML analysis failed: {str(e)}")


# ==========================================================
# DEMO FIXTURES & HEALTH
# ==========================================================

@router.get(
    "/demo-emails",
    summary="Retrieve pre-configured demo email test cases",
    description="Returns preloaded Phishing, BEC, Impersonation, and Benign demo emails for instant verification."
)
async def get_demo_emails():
    """Returns catalog of demo emails."""
    return DEMO_EMAILS


@router.get(
    "/demo-emls",
    summary="Retrieve raw RFC 822 .eml test fixtures",
    description="Returns catalog of authentic .eml strings covering phishing, BEC, impersonation, benign, malware attachments, and malformed emails."
)
async def get_demo_emls():
    """Returns catalog of raw .eml samples."""
    return EML_SAMPLES


@router.get(
    "/health",
    summary="System health check",
    description="Returns system and engine status."
)
async def health_check():
    """Returns service health status."""
    return {
        "status": "healthy",
        "service": "MailTrace AI - Features 1–5 (Threat Detection, XAI, Forensics, IOCs & Threat Intel)",
        "version": "1.5.0"
    }
