"""
MailTrace AI - VirusTotal API v3 Provider Adapter
Feature 5: Threat Intelligence
"""

import base64
import httpx
from typing import Optional, Dict, Any

from backend.core.config import (
    VIRUSTOTAL_API_KEY,
    THREAT_INTEL_MODE,
    INTEL_REQUEST_TIMEOUT_SECONDS,
    INTEL_CACHE_TTL_SECONDS
)
from backend.models.intel import (
    VirusTotalDomainResult,
    VirusTotalIpResult,
    VirusTotalUrlResult,
    VirusTotalHashResult
)
from backend.services.threat_intelligence.cache import default_intel_cache


# Deterministic mock intelligence fixtures for offline testing and hackathon demonstration
VT_MOCK_DATABASE = {
    # Domains
    "alert-center.xyz": {
        "reputation": -25,
        "malicious_votes": 9,
        "suspicious_votes": 3,
        "harmless_votes": 0,
        "categories": ["phishing", "suspicious", "credential theft"],
        "creation_date": "2026-08-01T10:00:00Z",
        "registrar": "NameCheap, Inc.",
        "tags": ["phishing", "lookalike", "fast-flux"]
    },
    "support-portal.top": {
        "reputation": -30,
        "malicious_votes": 12,
        "suspicious_votes": 2,
        "harmless_votes": 0,
        "categories": ["spoofing", "brand impersonation"],
        "creation_date": "2026-07-15T08:30:00Z",
        "registrar": "Hostinger Operations, UAB",
        "tags": ["impersonation", "office365-spoof"]
    },
    "corporation.com": {
        "reputation": 45,
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "harmless_votes": 68,
        "categories": ["business", "corporate portal"],
        "creation_date": "2010-03-12T00:00:00Z",
        "registrar": "MarkMonitor Inc.",
        "tags": ["clean", "verified-enterprise"]
    },
    "paypa1-security.com": {
        "reputation": -40,
        "malicious_votes": 16,
        "suspicious_votes": 4,
        "harmless_votes": 0,
        "categories": ["phishing", "typosquatting"],
        "creation_date": "2026-08-20T14:15:00Z",
        "registrar": "PDR Ltd.",
        "tags": ["typosquat", "paypal-impersonation"]
    },

    # IP Addresses
    "185.190.140.22": {
        "reputation": -18,
        "malicious_votes": 8,
        "suspicious_votes": 2,
        "harmless_votes": 1,
        "country": "DE",
        "asn": 49981,
        "as_owner": "WorldStream B.V.",
        "tags": ["bulletproof-hosting", "botnet-relay", "phishing-origin"]
    },
    "194.26.29.112": {
        "reputation": -15,
        "malicious_votes": 6,
        "suspicious_votes": 1,
        "harmless_votes": 2,
        "country": "RU",
        "asn": 57523,
        "as_owner": "Chang Way Technologies Co. Ltd.",
        "tags": ["malicious-relay", "spam-source"]
    },
    "198.51.100.25": {
        "reputation": 0,
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "harmless_votes": 10,
        "country": "US",
        "asn": 64496,
        "as_owner": "Example Transit Corp",
        "tags": ["documentation-network"]
    },

    # URLs
    "http://secure-login.alert-center.xyz/auth/verify": {
        "reputation": -35,
        "malicious_votes": 14,
        "suspicious_votes": 3,
        "harmless_votes": 0,
        "categories": ["phishing", "credential harvesting"],
        "final_url": "http://secure-login.alert-center.xyz/auth/verify"
    },
    "http://185.190.140.22/login": {
        "reputation": -28,
        "malicious_votes": 11,
        "suspicious_votes": 2,
        "harmless_votes": 0,
        "categories": ["phishing", "raw-ip-phish"],
        "final_url": "http://185.190.140.22/login"
    },
    "http://secure-login.alert-center.xyz/auth": {
        "reputation": -35,
        "malicious_votes": 14,
        "suspicious_votes": 3,
        "harmless_votes": 0,
        "categories": ["phishing"],
        "final_url": "http://secure-login.alert-center.xyz/auth"
    },

    # Hashes (overdue_receipt.pdf.exe sample and test hashes)
    "b778c51f4bf491f4": {  # Partial prefix match for test convenience
        "reputation": -50,
        "malicious_votes": 48,
        "suspicious_votes": 2,
        "harmless_votes": 0,
        "file_type": "Win32 EXE (Dropper)",
        "file_size": 75200,
        "names": ["overdue_receipt.pdf.exe", "invoice_scan.exe"],
        "tags": ["trojan", "stealer", "double-extension"]
    },
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "reputation": 0,
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "harmless_votes": 75,
        "file_type": "Empty File",
        "file_size": 0,
        "names": ["empty.dat"],
        "tags": ["zero-byte"]
    }
}


class VirusTotalProvider:
    """
    Asynchronous client for VirusTotal API v3.
    """
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = VIRUSTOTAL_API_KEY, mode: str = THREAT_INTEL_MODE):
        self.api_key = api_key
        self.mode = mode

    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def _should_use_mock(self) -> bool:
        if self.mode == "mock":
            return True
        if self.mode == "auto" and not self.is_configured():
            return True
        return False

    async def lookup_domain(self, domain: str) -> VirusTotalDomainResult:
        """Queries VirusTotal for domain intelligence."""
        clean_domain = domain.lower().strip()
        cached = default_intel_cache.get("virustotal", "domain", clean_domain)
        if cached:
            return cached

        if self._should_use_mock():
            # Check mock DB
            if clean_domain in VT_MOCK_DATABASE:
                d = VT_MOCK_DATABASE[clean_domain]
                res = VirusTotalDomainResult(
                    status="MOCK",
                    reputation=d.get("reputation"),
                    malicious_votes=d.get("malicious_votes", 0),
                    suspicious_votes=d.get("suspicious_votes", 0),
                    harmless_votes=d.get("harmless_votes", 0),
                    categories=d.get("categories", []),
                    creation_date=d.get("creation_date"),
                    registrar=d.get("registrar"),
                    tags=d.get("tags", [])
                )
            else:
                res = VirusTotalDomainResult(
                    status="MOCK",
                    reputation=0,
                    malicious_votes=0,
                    suspicious_votes=0,
                    harmless_votes=10,
                    categories=["unclassified"],
                    tags=[]
                )
            default_intel_cache.set("virustotal", "domain", clean_domain, res, INTEL_CACHE_TTL_SECONDS)
            return res

        if not self.is_configured():
            return VirusTotalDomainResult(status="NOT_CONFIGURED")

        url = f"{self.BASE_URL}/domains/{clean_domain}"
        headers = {"x-apikey": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=INTEL_REQUEST_TIMEOUT_SECONDS) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    res = VirusTotalDomainResult(
                        status="FOUND",
                        reputation=data.get("reputation"),
                        malicious_votes=stats.get("malicious", 0),
                        suspicious_votes=stats.get("suspicious", 0),
                        harmless_votes=stats.get("harmless", 0),
                        categories=list(data.get("categories", {}).values()) if isinstance(data.get("categories"), dict) else [],
                        creation_date=str(data.get("creation_date")) if data.get("creation_date") else None,
                        registrar=data.get("registrar"),
                        tags=data.get("tags", [])
                    )
                elif resp.status_code == 404:
                    res = VirusTotalDomainResult(status="NOT_FOUND")
                elif resp.status_code == 429:
                    res = VirusTotalDomainResult(status="RATE_LIMITED")
                else:
                    res = VirusTotalDomainResult(status="ERROR")
        except httpx.TimeoutException:
            res = VirusTotalDomainResult(status="TIMEOUT")
        except Exception:
            res = VirusTotalDomainResult(status="ERROR")

        default_intel_cache.set("virustotal", "domain", clean_domain, res, INTEL_CACHE_TTL_SECONDS)
        return res

    async def lookup_ip(self, ip_address: str) -> VirusTotalIpResult:
        """Queries VirusTotal for IP intelligence."""
        clean_ip = ip_address.strip()
        cached = default_intel_cache.get("virustotal", "ip", clean_ip)
        if cached:
            return cached

        if self._should_use_mock():
            if clean_ip in VT_MOCK_DATABASE:
                d = VT_MOCK_DATABASE[clean_ip]
                res = VirusTotalIpResult(
                    status="MOCK",
                    reputation=d.get("reputation"),
                    malicious_votes=d.get("malicious_votes", 0),
                    suspicious_votes=d.get("suspicious_votes", 0),
                    harmless_votes=d.get("harmless_votes", 0),
                    country=d.get("country"),
                    asn=d.get("asn"),
                    as_owner=d.get("as_owner"),
                    tags=d.get("tags", [])
                )
            else:
                res = VirusTotalIpResult(
                    status="MOCK",
                    reputation=0,
                    malicious_votes=0,
                    suspicious_votes=0,
                    harmless_votes=5,
                    tags=[]
                )
            default_intel_cache.set("virustotal", "ip", clean_ip, res, INTEL_CACHE_TTL_SECONDS)
            return res

        if not self.is_configured():
            return VirusTotalIpResult(status="NOT_CONFIGURED")

        url = f"{self.BASE_URL}/ip_addresses/{clean_ip}"
        headers = {"x-apikey": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=INTEL_REQUEST_TIMEOUT_SECONDS) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    res = VirusTotalIpResult(
                        status="FOUND",
                        reputation=data.get("reputation"),
                        malicious_votes=stats.get("malicious", 0),
                        suspicious_votes=stats.get("suspicious", 0),
                        harmless_votes=stats.get("harmless", 0),
                        country=data.get("country"),
                        asn=data.get("asn"),
                        as_owner=data.get("as_owner"),
                        tags=data.get("tags", [])
                    )
                elif resp.status_code == 404:
                    res = VirusTotalIpResult(status="NOT_FOUND")
                elif resp.status_code == 429:
                    res = VirusTotalIpResult(status="RATE_LIMITED")
                else:
                    res = VirusTotalIpResult(status="ERROR")
        except httpx.TimeoutException:
            res = VirusTotalIpResult(status="TIMEOUT")
        except Exception:
            res = VirusTotalIpResult(status="ERROR")

        default_intel_cache.set("virustotal", "ip", clean_ip, res, INTEL_CACHE_TTL_SECONDS)
        return res

    async def lookup_url(self, raw_url: str) -> VirusTotalUrlResult:
        """Queries VirusTotal for URL intelligence using url-safe base64 ID."""
        clean_url = raw_url.strip()
        cached = default_intel_cache.get("virustotal", "url", clean_url)
        if cached:
            return cached

        if self._should_use_mock():
            if clean_url in VT_MOCK_DATABASE:
                d = VT_MOCK_DATABASE[clean_url]
                res = VirusTotalUrlResult(
                    status="MOCK",
                    reputation=d.get("reputation"),
                    malicious_votes=d.get("malicious_votes", 0),
                    suspicious_votes=d.get("suspicious_votes", 0),
                    harmless_votes=d.get("harmless_votes", 0),
                    categories=d.get("categories", []),
                    final_url=d.get("final_url", clean_url)
                )
            else:
                res = VirusTotalUrlResult(
                    status="MOCK",
                    reputation=0,
                    malicious_votes=0,
                    suspicious_votes=0,
                    harmless_votes=15,
                    categories=["clean"],
                    final_url=clean_url
                )
            default_intel_cache.set("virustotal", "url", clean_url, res, INTEL_CACHE_TTL_SECONDS)
            return res

        if not self.is_configured():
            return VirusTotalUrlResult(status="NOT_CONFIGURED")

        # VirusTotal v3 URL ID format: urlsafe base64 without '=' padding
        url_id = base64.urlsafe_b64encode(clean_url.encode("utf-8")).decode("ascii").strip("=")
        endpoint = f"{self.BASE_URL}/urls/{url_id}"
        headers = {"x-apikey": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=INTEL_REQUEST_TIMEOUT_SECONDS) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    res = VirusTotalUrlResult(
                        status="FOUND",
                        reputation=data.get("reputation"),
                        malicious_votes=stats.get("malicious", 0),
                        suspicious_votes=stats.get("suspicious", 0),
                        harmless_votes=stats.get("harmless", 0),
                        categories=list(data.get("categories", {}).values()) if isinstance(data.get("categories"), dict) else [],
                        final_url=data.get("last_final_url") or clean_url
                    )
                elif resp.status_code == 404:
                    res = VirusTotalUrlResult(status="NOT_FOUND")
                elif resp.status_code == 429:
                    res = VirusTotalUrlResult(status="RATE_LIMITED")
                else:
                    res = VirusTotalUrlResult(status="ERROR")
        except httpx.TimeoutException:
            res = VirusTotalUrlResult(status="TIMEOUT")
        except Exception:
            res = VirusTotalUrlResult(status="ERROR")

        default_intel_cache.set("virustotal", "url", clean_url, res, INTEL_CACHE_TTL_SECONDS)
        return res

    async def lookup_hash(self, hash_value: str) -> VirusTotalHashResult:
        """Queries VirusTotal for file hash intelligence."""
        clean_hash = hash_value.lower().strip()
        cached = default_intel_cache.get("virustotal", "hash", clean_hash)
        if cached:
            return cached

        if self._should_use_mock():
            # Check prefix or full match
            matched = None
            for key, val in VT_MOCK_DATABASE.items():
                if clean_hash.startswith(key) or key.startswith(clean_hash[:16]):
                    matched = val
                    break

            if matched:
                res = VirusTotalHashResult(
                    status="MOCK",
                    reputation=matched.get("reputation"),
                    malicious_votes=matched.get("malicious_votes", 0),
                    suspicious_votes=matched.get("suspicious_votes", 0),
                    harmless_votes=matched.get("harmless_votes", 0),
                    file_type=matched.get("file_type", "Binary File"),
                    file_size=matched.get("file_size"),
                    names=matched.get("names", []),
                    tags=matched.get("tags", [])
                )
            else:
                res = VirusTotalHashResult(
                    status="MOCK",
                    reputation=0,
                    malicious_votes=0,
                    suspicious_votes=0,
                    harmless_votes=20,
                    file_type="Document / Data",
                    names=[],
                    tags=[]
                )
            default_intel_cache.set("virustotal", "hash", clean_hash, res, INTEL_CACHE_TTL_SECONDS)
            return res

        if not self.is_configured():
            return VirusTotalHashResult(status="NOT_CONFIGURED")

        url = f"{self.BASE_URL}/files/{clean_hash}"
        headers = {"x-apikey": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=INTEL_REQUEST_TIMEOUT_SECONDS) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    res = VirusTotalHashResult(
                        status="FOUND",
                        reputation=data.get("reputation"),
                        malicious_votes=stats.get("malicious", 0),
                        suspicious_votes=stats.get("suspicious", 0),
                        harmless_votes=stats.get("harmless", 0),
                        file_type=data.get("type_description"),
                        file_size=data.get("size"),
                        names=data.get("names", [])[:3],
                        tags=data.get("tags", [])
                    )
                elif resp.status_code == 404:
                    res = VirusTotalHashResult(status="NOT_FOUND")
                elif resp.status_code == 429:
                    res = VirusTotalHashResult(status="RATE_LIMITED")
                else:
                    res = VirusTotalHashResult(status="ERROR")
        except httpx.TimeoutException:
            res = VirusTotalHashResult(status="TIMEOUT")
        except Exception:
            res = VirusTotalHashResult(status="ERROR")

        default_intel_cache.set("virustotal", "hash", clean_hash, res, INTEL_CACHE_TTL_SECONDS)
        return res
