"""
MailTrace AI - Email Forensics Data Models
Feature 3: Email Forensics
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class RelayHop(BaseModel):
    """
    Single SMTP transmission relay hop extracted from 'Received:' headers.
    Hops are ordered chronologically from origin to final destination.
    """
    hop_number: int = Field(description="Hop index (1 = earliest externally observed relay)")
    from_host: Optional[str] = Field(default=None, description="Reported sending hostname in Received header")
    from_ip: Optional[str] = Field(default=None, description="Extracted sending IP address")
    by_host: Optional[str] = Field(default=None, description="Receiving MTA hostname")
    protocol: Optional[str] = Field(default=None, description="Transfer protocol (e.g. ESMTPS, SMTP, HTTP)")
    tls_cipher: Optional[str] = Field(default=None, description="TLS encryption cipher/version if recorded")
    timestamp_raw: Optional[str] = Field(default=None, description="Original unparsed date string in Received header")
    timestamp_iso: Optional[str] = Field(default=None, description="Normalized ISO 8601 timestamp")
    delay_seconds: Optional[float] = Field(default=None, description="Transit delay in seconds from previous hop")


class RoutingAnalysis(BaseModel):
    """
    Forensic analysis of the complete SMTP Received relay path.
    """
    hop_count: int = Field(default=0, description="Total number of observed relay hops")
    observed_ips: List[str] = Field(default_factory=list, description="Unique IP addresses observed across relay hops")
    observed_hostnames: List[str] = Field(default_factory=list, description="Unique hostnames observed in transmission")
    originating_infrastructure_candidate: Optional[str] = Field(
        default=None, 
        description="Earliest externally observed relay candidate (avoids definitive physical attacker attribution)"
    )
    relay_path_visual: str = Field(default="", description="ASCII / text visualization of relay journey")
    total_transit_time_seconds: Optional[float] = Field(default=None, description="Cumulative relay delay")


class SpfEvidence(BaseModel):
    """SPF validation evidence parsed from authentication headers."""
    result: str = Field(default="unknown", description="SPF result: pass, fail, softfail, neutral, none, permerror, unknown")
    domain: Optional[str] = Field(default=None, description="Domain checked in SPF record")
    sender_ip: Optional[str] = Field(default=None, description="Sender IP evaluated by SPF")
    source_header: Optional[str] = Field(default=None, description="Header from which SPF result was parsed")


class DkimEvidence(BaseModel):
    """DKIM signature evidence parsed from headers."""
    result: str = Field(default="unknown", description="DKIM result: pass, fail, neutral, permerror, unknown")
    domain: Optional[str] = Field(default=None, description="Signing domain (d= tag)")
    selector: Optional[str] = Field(default=None, description="Selector (s= tag)")
    algorithm: Optional[str] = Field(default=None, description="Signature algorithm (a= tag)")
    signature_present: bool = Field(default=False, description="Whether a DKIM-Signature header exists")


class DmarcEvidence(BaseModel):
    """DMARC policy and alignment evidence."""
    result: str = Field(default="unknown", description="DMARC result: pass, fail, none, permerror, unknown")
    policy: Optional[str] = Field(default=None, description="Applied policy: none, quarantine, reject")
    domain: Optional[str] = Field(default=None, description="Domain evaluated by DMARC")
    spf_aligned: Optional[bool] = Field(default=None, description="Whether SPF aligns with From header domain")
    dkim_aligned: Optional[bool] = Field(default=None, description="Whether DKIM aligns with From header domain")


class AuthenticationForensics(BaseModel):
    """Consolidated email authentication forensics."""
    spf: SpfEvidence = Field(default_factory=SpfEvidence)
    dkim: DkimEvidence = Field(default_factory=DkimEvidence)
    dmarc: DmarcEvidence = Field(default_factory=DmarcEvidence)
    overall_status: str = Field(
        default="UNKNOWN", 
        description="Overall authentication state: VERIFIED, PARTIALLY_VERIFIED, SUSPICIOUS, FAILED, UNKNOWN"
    )
    raw_auth_headers: List[str] = Field(default_factory=list, description="Original authentication header lines")


class SenderIdentityForensics(BaseModel):
    """
    Forensic examination of declared and envelope sender identities.
    """
    from_address: str = Field(default="", description="Clean email address from 'From' header")
    display_name: str = Field(default="", description="Extracted friendly display name")
    from_domain: str = Field(default="", description="Domain of From address")
    reply_to_address: Optional[str] = Field(default=None, description="Address from 'Reply-To' header")
    reply_to_domain: Optional[str] = Field(default=None, description="Domain of Reply-To address")
    return_path_address: Optional[str] = Field(default=None, description="Address from 'Return-Path' header")
    return_path_domain: Optional[str] = Field(default=None, description="Domain of Return-Path address")
    sender_address: Optional[str] = Field(default=None, description="Address from 'Sender' header if present")
    
    reply_to_mismatch: bool = Field(default=False, description="True if Reply-To domain differs from From domain")
    return_path_mismatch: bool = Field(default=False, description="True if Return-Path domain differs from From domain")
    display_name_mismatch: bool = Field(default=False, description="True if display name claims a brand but domain differs")
    inconsistencies: List[str] = Field(default_factory=list, description="List of detected identity discrepancies")


class AttachmentForensics(BaseModel):
    """Forensic metadata and local cryptographic hash for an attachment."""
    filename: str = Field(description="Sanitized attachment filename")
    mime_type: str = Field(default="application/octet-stream", description="Declared Content-Type")
    size_bytes: int = Field(default=0, description="Attachment size in bytes")
    sha256_hash: str = Field(description="Cryptographic SHA-256 hash of attachment payload")
    extension: str = Field(default="", description="File extension (including double extensions)")
    disposition: str = Field(default="attachment", description="attachment or inline")
    indicators: List[str] = Field(default_factory=list, description="Suspicious markers: DOUBLE_EXTENSION, EXECUTABLE, etc.")


class MimeAnalysis(BaseModel):
    """Structural breakdown of MIME multipart container."""
    content_type: str = Field(default="text/plain", description="Primary message Content-Type")
    parts_count: int = Field(default=1, description="Total number of MIME body parts")
    has_plain_text: bool = Field(default=False, description="Whether plain text body is present")
    has_html: bool = Field(default=False, description="Whether HTML body is present")
    plain_text_preview: Optional[str] = Field(default=None, description="Preview snippet of plain text content")
    charsets: List[str] = Field(default_factory=list, description="Observed character encodings")


class ForensicAnomaly(BaseModel):
    """Single forensic anomaly or structural irregularity detected in the email."""
    type: str = Field(description="Anomaly code: REPLY_TO_MISMATCH, MALFORMED_MESSAGE_ID, etc.")
    severity: str = Field(description="Severity: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    description: str = Field(description="Clear explanation of the observed irregularity")


class ForensicEvidenceResult(BaseModel):
    """
    Master forensic evidence object produced by Feature 3.
    Preserves raw evidence integrity for downstream hashing by Feature 9.
    """
    raw_evidence_hash: str = Field(description="Cryptographic SHA-256 hash of original unparsed .eml bytes")
    normalized_date: Optional[str] = Field(default=None, description="ISO 8601 normalized Date header")
    original_date: Optional[str] = Field(default=None, description="Raw Date header string")
    message_id: Optional[str] = Field(default=None, description="Normalized Message-ID header")
    subject: str = Field(default="", description="Decoded subject line")
    
    headers: Dict[str, Any] = Field(default_factory=dict, description="Normalized key-value map of major email headers")
    raw_headers_text: str = Field(default="", description="Original unparsed header block for forensic audit")
    
    sender_identity: SenderIdentityForensics = Field(default_factory=SenderIdentityForensics)
    authentication: AuthenticationForensics = Field(default_factory=AuthenticationForensics)
    relay_path: List[RelayHop] = Field(default_factory=list, description="Chronological SMTP relay hops")
    routing_analysis: RoutingAnalysis = Field(default_factory=RoutingAnalysis)
    mime_analysis: MimeAnalysis = Field(default_factory=MimeAnalysis)
    attachments: List[AttachmentForensics] = Field(default_factory=list)
    anomalies: List[ForensicAnomaly] = Field(default_factory=list)


class RawEmlInput(BaseModel):
    """Payload for submitting raw .eml text directly via JSON."""
    raw_eml: str = Field(description="Raw RFC 822 MIME email string content")
