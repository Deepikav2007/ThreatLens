"""
MailTrace AI - AbuseIPDB API v2 Provider Adapter
Feature 5: Threat Intelligence
"""

import httpx
from typing import Optional, Dict, Any

from backend.core.config import (
    ABUSEIPDB_API_KEY,
    THREAT_INTEL_MODE,
    INTEL_REQUEST_TIMEOUT_SECONDS,
    INTEL_CACHE_TTL_SECONDS
)
from backend.models.intel import AbuseIpDbResult
from backend.services.threat_intelligence.cache import default_intel_cache


# Deterministic mock intelligence fixtures for AbuseIPDB
ABUSEIPDB_MOCK_DATABASE = {
    "185.190.140.22": {
        "abuse_confidence": 87,
        "total_reports": 143,
        "country": "DE",
        "isp": "WorldStream B.V.",
        "domain": "worldstream.nl",
        "usage_type": "Data Center/Web Hosting",
        "is_whitelisted": False,
        "last_reported_at": "2026-08-28T09:12:00Z"
    },
    "194.26.29.112": {
        "abuse_confidence": 92,
        "total_reports": 218,
        "country": "RU",
        "isp": "Chang Way Technologies Co. Ltd.",
        "domain": "changway.hk",
        "usage_type": "Data Center/Web Hosting",
        "is_whitelisted": False,
        "last_reported_at": "2026-08-27T18:45:00Z"
    },
    "198.51.100.25": {
        "abuse_confidence": 0,
        "total_reports": 0,
        "country": "US",
        "isp": "IANA Special Use",
        "domain": "example.net",
        "usage_type": "Reserved / Documentation",
        "is_whitelisted": True,
        "last_reported_at": None
    }
}


class AbuseIPDBProvider:
    """
    Asynchronous client for AbuseIPDB API v2 check endpoint.
    Guarantees private IP protection and offline demo reliability.
    """
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str = ABUSEIPDB_API_KEY, mode: str = THREAT_INTEL_MODE):
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

    async def lookup_ip(self, ip_address: str, scope: str = "public") -> AbuseIpDbResult:
        """
        Queries AbuseIPDB for IP reputation and abuse history.
        Automatically skips private/local/loopback IPs.
        """
        clean_ip = ip_address.strip()

        # Strict safety check: Never transmit non-public IPs
        if scope.lower() in ["private", "loopback", "reserved", "link-local", "multicast"]:
            return AbuseIpDbResult(
                status="SKIPPED",
                abuse_confidence=0,
                total_reports=0,
                usage_type=f"Non-routable {scope.title()} Address"
            )

        cached = default_intel_cache.get("abuseipdb", "ip", clean_ip)
        if cached:
            return cached

        if self._should_use_mock():
            if clean_ip in ABUSEIPDB_MOCK_DATABASE:
                d = ABUSEIPDB_MOCK_DATABASE[clean_ip]
                res = AbuseIpDbResult(
                    status="MOCK",
                    abuse_confidence=d.get("abuse_confidence", 0),
                    total_reports=d.get("total_reports", 0),
                    country=d.get("country"),
                    isp=d.get("isp"),
                    domain=d.get("domain"),
                    usage_type=d.get("usage_type"),
                    is_whitelisted=d.get("is_whitelisted", False),
                    last_reported_at=d.get("last_reported_at")
                )
            else:
                res = AbuseIpDbResult(
                    status="MOCK",
                    abuse_confidence=0,
                    total_reports=0,
                    usage_type="Commercial / Web",
                    is_whitelisted=False
                )
            default_intel_cache.set("abuseipdb", "ip", clean_ip, res, INTEL_CACHE_TTL_SECONDS)
            return res

        if not self.is_configured():
            return AbuseIpDbResult(status="NOT_CONFIGURED")

        params = {
            "ipAddress": clean_ip,
            "maxAgeInDays": 90,
            "verbose": True
        }
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

        try:
            async with httpx.AsyncClient(timeout=INTEL_REQUEST_TIMEOUT_SECONDS) as client:
                resp = await client.get(self.BASE_URL, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    res = AbuseIpDbResult(
                        status="FOUND",
                        abuse_confidence=data.get("abuseConfidenceScore", 0),
                        total_reports=data.get("totalReports", 0),
                        country=data.get("countryCode"),
                        isp=data.get("isp"),
                        domain=data.get("domain"),
                        usage_type=data.get("usageType"),
                        is_whitelisted=data.get("isWhitelisted", False),
                        last_reported_at=data.get("lastReportedAt")
                    )
                elif resp.status_code == 404:
                    res = AbuseIpDbResult(status="NOT_FOUND")
                elif resp.status_code == 429:
                    res = AbuseIpDbResult(status="RATE_LIMITED")
                else:
                    res = AbuseIpDbResult(status="ERROR")
        except httpx.TimeoutException:
            res = AbuseIpDbResult(status="TIMEOUT")
        except Exception:
            res = AbuseIpDbResult(status="ERROR")

        default_intel_cache.set("abuseipdb", "ip", clean_ip, res, INTEL_CACHE_TTL_SECONDS)
        return res
