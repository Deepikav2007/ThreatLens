"""
MailTrace AI - Threat Intelligence Data Models
Feature 5: Threat Intelligence
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class VirusTotalDomainResult(BaseModel):
    """Normalized VirusTotal API v3 domain intelligence report."""
    status: str = Field(description="Lookup status: FOUND, NOT_FOUND, NOT_CONFIGURED, RATE_LIMITED, TIMEOUT, ERROR, MOCK")
    reputation: Optional[int] = Field(default=None, description="VirusTotal community reputation score")
    malicious_votes: int = Field(default=0, description="Number of security vendors flagging domain as malicious")
    suspicious_votes: int = Field(default=0, description="Number of vendors flagging domain as suspicious")
    harmless_votes: int = Field(default=0, description="Number of vendors flagging domain as harmless")
    categories: List[str] = Field(default_factory=list, description="Categorization labels (e.g. phishing, dynamic DNS)")
    creation_date: Optional[str] = Field(default=None, description="Domain registration date if available")
    registrar: Optional[str] = Field(default=None, description="Domain registrar name if available")
    tags: List[str] = Field(default_factory=list, description="Descriptive tags")
    last_analysis_date: Optional[str] = Field(default=None, description="Timestamp of latest analysis scan")


class VirusTotalIpResult(BaseModel):
    """Normalized VirusTotal API v3 IP address intelligence report."""
    status: str = Field(description="Lookup status: FOUND, NOT_FOUND, NOT_CONFIGURED, RATE_LIMITED, TIMEOUT, ERROR, MOCK")
    reputation: Optional[int] = Field(default=None, description="VirusTotal community reputation score")
    malicious_votes: int = Field(default=0, description="Number of security vendors flagging IP as malicious")
    suspicious_votes: int = Field(default=0, description="Number of vendors flagging IP as suspicious")
    harmless_votes: int = Field(default=0, description="Number of vendors flagging IP as harmless")
    country: Optional[str] = Field(default=None, description="Two-letter ISO country code of infrastructure")
    asn: Optional[int] = Field(default=None, description="Autonomous System Number")
    as_owner: Optional[str] = Field(default=None, description="Autonomous System / ISP owner name")
    tags: List[str] = Field(default_factory=list, description="Tags associated with IP")


class VirusTotalUrlResult(BaseModel):
    """Normalized VirusTotal API v3 URL intelligence report."""
    status: str = Field(description="Lookup status: FOUND, NOT_FOUND, NOT_CONFIGURED, RATE_LIMITED, TIMEOUT, ERROR, MOCK")
    reputation: Optional[int] = Field(default=None, description="VirusTotal community reputation score")
    malicious_votes: int = Field(default=0, description="Number of security vendors flagging URL as malicious")
    suspicious_votes: int = Field(default=0, description="Number of vendors flagging URL as suspicious")
    harmless_votes: int = Field(default=0, description="Number of vendors flagging URL as harmless")
    categories: List[str] = Field(default_factory=list, description="Categorization labels")
    final_url: Optional[str] = Field(default=None, description="Final landing URL if recorded")


class VirusTotalHashResult(BaseModel):
    """Normalized VirusTotal API v3 File Hash intelligence report."""
    status: str = Field(description="Lookup status: FOUND, NOT_FOUND, NOT_CONFIGURED, RATE_LIMITED, TIMEOUT, ERROR, MOCK")
    reputation: Optional[int] = Field(default=None, description="VirusTotal community reputation score")
    malicious_votes: int = Field(default=0, description="Number of security engines detecting file as malicious")
    suspicious_votes: int = Field(default=0, description="Number of security engines detecting file as suspicious")
    harmless_votes: int = Field(default=0, description="Number of security engines detecting file as harmless")
    file_type: Optional[str] = Field(default=None, description="Identified file format / type")
    file_size: Optional[int] = Field(default=None, description="Observed file size in bytes")
    names: List[str] = Field(default_factory=list, description="Known filenames associated with hash")
    tags: List[str] = Field(default_factory=list, description="Malware classification tags")


class AbuseIpDbResult(BaseModel):
    """Normalized AbuseIPDB API v2 IP check report."""
    status: str = Field(description="Lookup status: FOUND, NOT_FOUND, NOT_CONFIGURED, RATE_LIMITED, TIMEOUT, ERROR, SKIPPED, MOCK")
    abuse_confidence: int = Field(default=0, description="Abuse confidence score (0-100%)")
    total_reports: int = Field(default=0, description="Total malicious activity reports filed against IP")
    country: Optional[str] = Field(default=None, description="Country code where IP is located")
    isp: Optional[str] = Field(default=None, description="Internet Service Provider name")
    domain: Optional[str] = Field(default=None, description="Domain associated with IP host")
    usage_type: Optional[str] = Field(default=None, description="Usage category: Data Center, Commercial, Residential, etc.")
    is_whitelisted: bool = Field(default=False, description="Whether IP is on trusted whitelist")
    last_reported_at: Optional[str] = Field(default=None, description="Timestamp of most recent abuse report")


class ProviderIntelligence(BaseModel):
    """Consolidated provider lookup container for an indicator."""
    virustotal: Optional[Any] = Field(default=None, description="VirusTotal result (domain, IP, URL, or hash)")
    abuseipdb: Optional[AbuseIpDbResult] = Field(default=None, description="AbuseIPDB result for IP addresses")


class IocIntelligenceItem(BaseModel):
    """
    Enriched Intelligence Report for a single IOC.
    """
    indicator: str = Field(description="Indicator value (IP, domain, URL, or hash)")
    ioc_type: str = Field(description="Indicator type: ip, domain, url, hash")
    normalized_status: str = Field(
        description="Unified status: MALICIOUS, SUSPICIOUS, CLEAN_REPORTED, UNKNOWN, NOT_FOUND, NOT_CONFIGURED"
    )
    status_reason: str = Field(description="Evidence-grounded rationale explaining the assigned status")
    providers: ProviderIntelligence = Field(default_factory=ProviderIntelligence)
    is_mock: bool = Field(default=False, description="True if indicator was populated using demo/mock fixtures")
    checked_at: str = Field(description="ISO 8601 timestamp of threat intelligence lookup")


class ThreatIntelligenceSummary(BaseModel):
    """High-level statistical summary of threat intelligence findings."""
    total_analyzed: int = Field(default=0, description="Total number of unique indicators queried")
    malicious_count: int = Field(default=0, description="Indicators with high-confidence malicious detections")
    suspicious_count: int = Field(default=0, description="Indicators with elevated suspicious detections")
    clean_reported_count: int = Field(default=0, description="Indicators where queried providers returned 0 detections")
    unknown_count: int = Field(default=0, description="Indicators where no intelligence was returned or skipped")
    is_demo_mode: bool = Field(default=False, description="True if demo/mock intelligence was utilized")


class ThreatIntelligenceResult(BaseModel):
    """
    Master Threat Intelligence result object produced by Feature 5.
    """
    summary: ThreatIntelligenceSummary = Field(default_factory=ThreatIntelligenceSummary)
    results: List[IocIntelligenceItem] = Field(default_factory=list)
    cached_lookups_count: int = Field(default=0, description="Number of indicator lookups served from local cache")


class ThreatIntelligenceInput(BaseModel):
    """Payload for standalone threat intelligence evaluation."""
    raw_eml: Optional[str] = Field(default=None, description="Raw RFC 822 EML string content")
    indicators: Optional[List[str]] = Field(default=None, description="Explicit list of indicators to query")
