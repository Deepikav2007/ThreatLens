"""
MailTrace AI - Threat Intelligence Aggregator Service
Feature 5: Threat Intelligence
"""

import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any, Tuple

from backend.core.config import (
    MAX_INTEL_LOOKUPS_PER_TYPE,
    THREAT_INTEL_MODE
)
from backend.models.ioc import IocExtractionResult
from backend.models.intel import (
    ProviderIntelligence,
    IocIntelligenceItem,
    ThreatIntelligenceSummary,
    ThreatIntelligenceResult
)
from backend.services.threat_intelligence.virustotal import VirusTotalProvider
from backend.services.threat_intelligence.abuseipdb import AbuseIPDBProvider
from backend.services.threat_intelligence.cache import default_intel_cache
from backend.services.ioc_extractor import extract_iocs


class ThreatIntelligenceService:
    """
    Orchestration and correlation engine for Threat Intelligence enrichment.
    Queries VirusTotal and AbuseIPDB asynchronously, applies caching, and normalizes findings.
    """
    def __init__(
        self,
        vt_provider: Optional[VirusTotalProvider] = None,
        abuse_provider: Optional[AbuseIPDBProvider] = None
    ):
        self.vt = vt_provider or VirusTotalProvider()
        self.abuse = abuse_provider or AbuseIPDBProvider()

    def _determine_ip_status(self, vt_res: Any, abuse_res: Any) -> Tuple[str, str]:
        """Calculates normalized status and explanation for an IP address."""
        if getattr(abuse_res, "status", "") == "SKIPPED":
            return "UNKNOWN", "Private / local network address — external intelligence lookup skipped"

        vt_malicious = getattr(vt_res, "malicious_votes", 0) or 0
        abuse_conf = getattr(abuse_res, "abuse_confidence", 0) or 0
        abuse_reports = getattr(abuse_res, "total_reports", 0) or 0

        # Multi-source or strong malicious evidence
        if vt_malicious >= 5 or abuse_conf >= 50:
            return "MALICIOUS", f"Confirmed malicious infrastructure: AbuseIPDB confidence {abuse_conf}% ({abuse_reports} reports), VirusTotal {vt_malicious} vendor detections"
        
        # Suspicious evidence
        if vt_malicious >= 1 or abuse_conf >= 15 or abuse_reports >= 5:
            return "SUSPICIOUS", f"Elevated threat indicators: AbuseIPDB confidence {abuse_conf}% ({abuse_reports} reports), VirusTotal {vt_malicious} detections"

        # Explicitly clean reported
        if (vt_res and vt_res.status in ["FOUND", "MOCK"] and vt_malicious == 0) or \
           (abuse_res and abuse_res.status in ["FOUND", "MOCK"] and abuse_conf == 0):
            return "CLEAN_REPORTED", "No malicious detections or abuse reports returned by queried providers"

        return "UNKNOWN", "No reputation data found or intelligence unconfigured"

    def _determine_domain_status(self, vt_res: Any) -> Tuple[str, str]:
        """Calculates normalized status for a domain."""
        if not vt_res:
            return "UNKNOWN", "No intelligence available"

        malicious = vt_res.malicious_votes or 0
        suspicious = vt_res.suspicious_votes or 0

        if malicious >= 3:
            cats = ", ".join(vt_res.categories) if vt_res.categories else "malicious domain"
            return "MALICIOUS", f"VirusTotal: {malicious} security vendors flagged domain ({cats})"
        if malicious >= 1 or suspicious >= 2:
            return "SUSPICIOUS", f"VirusTotal: {malicious} malicious, {suspicious} suspicious vendor detections"
        if vt_res.status in ["FOUND", "MOCK"] and malicious == 0 and suspicious == 0:
            return "CLEAN_REPORTED", "No malicious vendor detections reported in VirusTotal"

        return "UNKNOWN", "Domain reputation not found or provider unconfigured"

    def _determine_url_status(self, vt_res: Any) -> Tuple[str, str]:
        """Calculates normalized status for a URL."""
        if not vt_res:
            return "UNKNOWN", "No intelligence available"

        malicious = vt_res.malicious_votes or 0
        suspicious = vt_res.suspicious_votes or 0

        if malicious >= 3:
            return "MALICIOUS", f"VirusTotal: {malicious} security vendors flagged URL as malicious"
        if malicious >= 1 or suspicious >= 2:
            return "SUSPICIOUS", f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections"
        if vt_res.status in ["FOUND", "MOCK"] and malicious == 0 and suspicious == 0:
            return "CLEAN_REPORTED", "No security detections returned for URL"

        return "UNKNOWN", "URL record not found in threat database"

    def _determine_hash_status(self, vt_res: Any) -> Tuple[str, str]:
        """Calculates normalized status for a cryptographic hash."""
        if not vt_res:
            return "UNKNOWN", "No intelligence available"

        malicious = vt_res.malicious_votes or 0
        suspicious = vt_res.suspicious_votes or 0

        if malicious >= 3:
            ftype = vt_res.file_type or "binary"
            return "MALICIOUS", f"VirusTotal: {malicious} anti-malware engines identified malicious {ftype}"
        if malicious >= 1 or suspicious >= 2:
            return "SUSPICIOUS", f"VirusTotal: {malicious} engines flagged payload as suspicious"
        if vt_res.status in ["FOUND", "MOCK"] and malicious == 0 and suspicious == 0:
            return "CLEAN_REPORTED", "Known file hash with 0 malware detections"

        return "UNKNOWN", "File hash signature not found in malware database"

    async def _enrich_ip(self, ip_obj: Any) -> IocIntelligenceItem:
        val = ip_obj.value
        scope = getattr(ip_obj, "scope", "public")

        # Concurrently query VT and AbuseIPDB for IP
        vt_task = asyncio.create_task(self.vt.lookup_ip(val))
        abuse_task = asyncio.create_task(self.abuse.lookup_ip(val, scope))
        vt_res, abuse_res = await asyncio.gather(vt_task, abuse_task)

        status, reason = self._determine_ip_status(vt_res, abuse_res)
        is_mock = getattr(vt_res, "status", "") == "MOCK" or getattr(abuse_res, "status", "") == "MOCK"

        return IocIntelligenceItem(
            indicator=val,
            ioc_type="ip",
            normalized_status=status,
            status_reason=reason,
            providers=ProviderIntelligence(virustotal=vt_res, abuseipdb=abuse_res),
            is_mock=is_mock,
            checked_at=datetime.now(timezone.utc).isoformat()
        )

    async def _enrich_domain(self, dom_obj: Any) -> IocIntelligenceItem:
        val = dom_obj.value
        vt_res = await self.vt.lookup_domain(val)
        status, reason = self._determine_domain_status(vt_res)
        is_mock = getattr(vt_res, "status", "") == "MOCK"

        return IocIntelligenceItem(
            indicator=val,
            ioc_type="domain",
            normalized_status=status,
            status_reason=reason,
            providers=ProviderIntelligence(virustotal=vt_res),
            is_mock=is_mock,
            checked_at=datetime.now(timezone.utc).isoformat()
        )

    async def _enrich_url(self, url_obj: Any) -> IocIntelligenceItem:
        val = getattr(url_obj, "normalized", getattr(url_obj, "value", str(url_obj)))
        vt_res = await self.vt.lookup_url(val)
        status, reason = self._determine_url_status(vt_res)
        is_mock = getattr(vt_res, "status", "") == "MOCK"

        return IocIntelligenceItem(
            indicator=val,
            ioc_type="url",
            normalized_status=status,
            status_reason=reason,
            providers=ProviderIntelligence(virustotal=vt_res),
            is_mock=is_mock,
            checked_at=datetime.now(timezone.utc).isoformat()
        )

    async def _enrich_hash(self, hash_obj: Any) -> IocIntelligenceItem:
        val = getattr(hash_obj, "value", str(hash_obj))
        vt_res = await self.vt.lookup_hash(val)
        status, reason = self._determine_hash_status(vt_res)
        is_mock = getattr(vt_res, "status", "") == "MOCK"

        return IocIntelligenceItem(
            indicator=val,
            ioc_type="hash",
            normalized_status=status,
            status_reason=reason,
            providers=ProviderIntelligence(virustotal=vt_res),
            is_mock=is_mock,
            checked_at=datetime.now(timezone.utc).isoformat()
        )

    async def enrich_iocs(self, iocs: IocExtractionResult) -> ThreatIntelligenceResult:
        """
        Main orchestration entry point: enriches all distinct IOCs concurrently.
        """
        initial_cache_hits = default_intel_cache.hits
        tasks = []

        # 1. Limit and dispatch IPs
        ips_to_query = [ip for ip in iocs.ips if getattr(ip, "scope", "public") == "public"][:MAX_INTEL_LOOKUPS_PER_TYPE]
        # Also include non-public for explicit skip labeling
        private_ips = [ip for ip in iocs.ips if getattr(ip, "scope", "public") != "public"][:MAX_INTEL_LOOKUPS_PER_TYPE]
        for ip in ips_to_query + private_ips:
            tasks.append(self._enrich_ip(ip))

        # 2. Domains
        for dom in iocs.domains[:MAX_INTEL_LOOKUPS_PER_TYPE]:
            tasks.append(self._enrich_domain(dom))

        # 3. URLs
        for u in iocs.urls[:MAX_INTEL_LOOKUPS_PER_TYPE]:
            tasks.append(self._enrich_url(u))

        # 4. Hashes
        for h in iocs.hashes[:MAX_INTEL_LOOKUPS_PER_TYPE]:
            tasks.append(self._enrich_hash(h))

        # Parallel resolution
        items: List[IocIntelligenceItem] = []
        if tasks:
            items = await asyncio.gather(*tasks)

        # Calculate summary metrics
        malicious_cnt = sum(1 for it in items if it.normalized_status == "MALICIOUS")
        suspicious_cnt = sum(1 for it in items if it.normalized_status == "SUSPICIOUS")
        clean_cnt = sum(1 for it in items if it.normalized_status == "CLEAN_REPORTED")
        unknown_cnt = sum(1 for it in items if it.normalized_status in ["UNKNOWN", "NOT_FOUND", "NOT_CONFIGURED"])
        is_demo = any(it.is_mock for it in items)

        summary = ThreatIntelligenceSummary(
            total_analyzed=len(items),
            malicious_count=malicious_cnt,
            suspicious_count=suspicious_cnt,
            clean_reported_count=clean_cnt,
            unknown_count=unknown_cnt,
            is_demo_mode=is_demo
        )

        cached_lookups = default_intel_cache.hits - initial_cache_hits

        return ThreatIntelligenceResult(
            summary=summary,
            results=items,
            cached_lookups_count=cached_lookups
        )


# Global default service instance
default_intel_service = ThreatIntelligenceService()


async def enrich_iocs_with_threat_intel(iocs: IocExtractionResult) -> ThreatIntelligenceResult:
    """Convenience helper for enriching Feature 4 IOCs with threat intelligence."""
    return await default_intel_service.enrich_iocs(iocs)
