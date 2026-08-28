"""
MailTrace AI - Threat Intelligence Package
Feature 5: Threat Intelligence
"""

from backend.services.threat_intelligence.aggregator import (
    ThreatIntelligenceService,
    default_intel_service,
    enrich_iocs_with_threat_intel
)

__all__ = [
    "ThreatIntelligenceService",
    "default_intel_service",
    "enrich_iocs_with_threat_intel"
]
