"""
MailTrace AI - IOC Extraction Data Models
Feature 4: IOC Extraction
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class UrlIoc(BaseModel):
    """Normalized URL indicator with extraction source tracking."""
    type: str = Field(default="url", description="IOC type identifier")
    value: str = Field(description="Original URL exactly as observed in email")
    normalized: str = Field(description="Canonical normalized URL for correlation and deduplication")
    scheme: Optional[str] = Field(default=None, description="URL protocol scheme (http, https, ftp)")
    hostname: Optional[str] = Field(default=None, description="Extracted hostname")
    path: Optional[str] = Field(default=None, description="URL path component")
    query: Optional[str] = Field(default=None, description="Query string parameters")
    sources: List[str] = Field(default_factory=list, description="Provenance sources where URL was observed")
    context: Optional[str] = Field(default=None, description="Surrounding contextual text snippet or anchor text")
    confidence: float = Field(default=1.0, description="Extraction confidence score (not maliciousness)")


class DomainIoc(BaseModel):
    """Normalized Domain indicator."""
    type: str = Field(default="domain", description="IOC type identifier")
    value: str = Field(description="Observed domain name")
    registered_domain: Optional[str] = Field(default=None, description="Registrable root domain (e.g. example.com)")
    is_punycode: bool = Field(default=False, description="True if domain contains IDN Punycode (xn--)")
    unicode_domain: Optional[str] = Field(default=None, description="Decoded Unicode representation if applicable")
    sources: List[str] = Field(default_factory=list, description="Provenance sources where domain was observed")
    context: Optional[str] = Field(default=None, description="Contextual origin (e.g. sender_header, url_hostname)")
    confidence: float = Field(default=1.0, description="Extraction confidence score")


class IpIoc(BaseModel):
    """Normalized IPv4 or IPv6 indicator with scope classification."""
    type: str = Field(default="ip", description="IOC type identifier")
    value: str = Field(description="Validated IP address string")
    version: int = Field(default=4, description="IP version (4 or 6)")
    scope: str = Field(
        default="public", 
        description="IP scope: public, private, loopback, link-local, reserved, multicast"
    )
    sources: List[str] = Field(default_factory=list, description="Provenance sources (e.g. received_header, email_body)")
    context: Optional[str] = Field(default=None, description="Contextual transmission hop or body context")
    confidence: float = Field(default=1.0, description="Extraction confidence score")


class EmailIoc(BaseModel):
    """Normalized Email Address indicator."""
    type: str = Field(default="email", description="IOC type identifier")
    value: str = Field(description="Complete normalized email address")
    local_part: str = Field(description="Username or mailbox component before @")
    domain: str = Field(description="Domain component after @")
    sources: List[str] = Field(default_factory=list, description="Provenance sources (e.g. from_header, reply_to, body)")
    context: Optional[str] = Field(default=None, description="Header field or textual context")
    confidence: float = Field(default=1.0, description="Extraction confidence score")


class HashIoc(BaseModel):
    """Cryptographic file or message hash indicator."""
    type: str = Field(default="hash", description="IOC type identifier")
    value: str = Field(description="Hexadecimal hash string in lowercase")
    algorithm: str = Field(description="Hash algorithm: MD5, SHA1, SHA256")
    sources: List[str] = Field(default_factory=list, description="Provenance sources (e.g. email_body, attachment, subject)")
    context: Optional[str] = Field(default=None, description="Context (e.g. calculated_from_attachment, body_text)")
    confidence: float = Field(default=1.0, description="Extraction confidence score")


class HostnameIoc(BaseModel):
    """Extracted hostname indicator."""
    type: str = Field(default="hostname", description="IOC type identifier")
    value: str = Field(description="Normalized hostname in lowercase")
    sources: List[str] = Field(default_factory=list, description="Provenance sources (e.g. received_hop, url)")
    context: Optional[str] = Field(default=None, description="Origin context")
    confidence: float = Field(default=1.0, description="Extraction confidence score")


class AttachmentIoc(BaseModel):
    """Attachment forensic indicator."""
    type: str = Field(default="attachment", description="IOC type identifier")
    filename: str = Field(description="Sanitized attachment filename")
    mime_type: str = Field(default="application/octet-stream", description="Declared Content-Type")
    size_bytes: int = Field(default=0, description="File size in bytes")
    sha256: str = Field(description="SHA-256 hash of attachment payload")
    sha1: Optional[str] = Field(default=None, description="SHA-1 hash of attachment payload")
    md5: Optional[str] = Field(default=None, description="MD5 hash of attachment payload")
    indicators: List[str] = Field(default_factory=list, description="Structural indicators (e.g. DOUBLE_EXTENSION)")
    sources: List[str] = Field(default_factory=lambda: ["attachment"], description="Provenance sources")


class IocSummary(BaseModel):
    """Statistical summary count of extracted IOCs."""
    urls: int = Field(default=0, description="Count of distinct normalized URLs")
    domains: int = Field(default=0, description="Count of distinct domains")
    ips: int = Field(default=0, description="Count of distinct IP addresses")
    emails: int = Field(default=0, description="Count of distinct email addresses")
    hashes: int = Field(default=0, description="Count of distinct cryptographic hashes")
    hostnames: int = Field(default=0, description="Count of distinct hostnames")
    attachments: int = Field(default=0, description="Count of attachments analyzed")


class IocExtractionResult(BaseModel):
    """
    Master IOC extraction result container produced by Feature 4.
    Feeds downstream Threat Intelligence (Feature 5) and Attack Graph (Feature 6).
    """
    summary: IocSummary = Field(default_factory=IocSummary)
    urls: List[UrlIoc] = Field(default_factory=list)
    domains: List[DomainIoc] = Field(default_factory=list)
    ips: List[IpIoc] = Field(default_factory=list)
    emails: List[EmailIoc] = Field(default_factory=list)
    hashes: List[HashIoc] = Field(default_factory=list)
    hostnames: List[HostnameIoc] = Field(default_factory=list)
    attachments: List[AttachmentIoc] = Field(default_factory=list)


class IocExtractionInput(BaseModel):
    """Payload for submitting an email for standalone IOC extraction."""
    raw_eml: str = Field(description="Raw RFC 822 MIME email string content")
