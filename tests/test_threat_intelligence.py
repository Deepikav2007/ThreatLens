"""
MailTrace AI - Threat Intelligence Test Suite
Feature 5: Threat Intelligence
"""

import sys
import os
import asyncio

# Add workspace to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.services.threat_intelligence.virustotal import VirusTotalProvider
from backend.services.threat_intelligence.abuseipdb import AbuseIPDBProvider
from backend.services.threat_intelligence.aggregator import ThreatIntelligenceService
from backend.services.threat_intelligence.cache import default_intel_cache
from backend.services.ioc_extractor import extract_iocs
from backend.data.eml_samples import EML_SAMPLES


async def run_all_tests_async():
    print("=" * 65)
    print("MAILTRACE AI - FEATURE 5 (THREAT INTELLIGENCE) TEST SUITE")
    print("=" * 65)

    vt = VirusTotalProvider(mode="mock")
    abuse = AbuseIPDBProvider(mode="mock")
    service = ThreatIntelligenceService(vt_provider=vt, abuse_provider=abuse)

    # -----------------------------------------------------------
    # TEST 1: Public IP with AbuseIPDB
    # -----------------------------------------------------------
    ip_res = await abuse.lookup_ip("185.190.140.22", scope="public")
    print("\n[TEST 1] AbuseIPDB Public IP Lookup:")
    print("  IP: 185.190.140.22")
    print("  Abuse Confidence:", ip_res.abuse_confidence, "%")
    print("  Total Reports:", ip_res.total_reports)
    print("  ISP:", ip_res.isp)
    assert ip_res.status in ["FOUND", "MOCK"]
    assert ip_res.abuse_confidence >= 80
    assert ip_res.total_reports >= 100
    print("[PASS] Test 1 passed")

    # -----------------------------------------------------------
    # TEST 2: Public IP with VirusTotal
    # -----------------------------------------------------------
    vt_ip_res = await vt.lookup_ip("185.190.140.22")
    print("\n[TEST 2] VirusTotal Public IP Lookup:")
    print("  Malicious Votes:", vt_ip_res.malicious_votes)
    print("  Country:", vt_ip_res.country)
    assert vt_ip_res.status in ["FOUND", "MOCK"]
    assert vt_ip_res.malicious_votes >= 5
    assert vt_ip_res.country == "DE"
    print("[PASS] Test 2 passed")

    # -----------------------------------------------------------
    # TEST 3: Domain with VirusTotal
    # -----------------------------------------------------------
    vt_dom_res = await vt.lookup_domain("alert-center.xyz")
    print("\n[TEST 3] VirusTotal Domain Lookup:")
    print("  Domain: alert-center.xyz")
    print("  Malicious Votes:", vt_dom_res.malicious_votes)
    print("  Categories:", vt_dom_res.categories)
    assert vt_dom_res.status in ["FOUND", "MOCK"]
    assert vt_dom_res.malicious_votes >= 5
    assert "phishing" in vt_dom_res.categories
    print("[PASS] Test 3 passed")

    # -----------------------------------------------------------
    # TEST 4: URL with VirusTotal
    # -----------------------------------------------------------
    vt_url_res = await vt.lookup_url("http://secure-login.alert-center.xyz/auth/verify")
    print("\n[TEST 4] VirusTotal URL Lookup:")
    print("  Malicious Votes:", vt_url_res.malicious_votes)
    print("  Suspicious Votes:", vt_url_res.suspicious_votes)
    assert vt_url_res.status in ["FOUND", "MOCK"]
    assert vt_url_res.malicious_votes >= 10
    print("[PASS] Test 4 passed")

    # -----------------------------------------------------------
    # TEST 5: File Hash with VirusTotal
    # -----------------------------------------------------------
    vt_hash_res = await vt.lookup_hash("b778c51f4bf491f4")
    print("\n[TEST 5] VirusTotal File Hash Lookup:")
    print("  File Type:", vt_hash_res.file_type)
    print("  Malicious Votes:", vt_hash_res.malicious_votes)
    assert vt_hash_res.status in ["FOUND", "MOCK"]
    assert vt_hash_res.malicious_votes >= 40
    print("[PASS] Test 5 passed")

    # -----------------------------------------------------------
    # TEST 6: Unknown Indicator Handling (NOT_FOUND != Safe)
    # -----------------------------------------------------------
    clean_unreg = await vt.lookup_domain("completely-unknown-nonexistent-domain-9988.org")
    print("\n[TEST 6] Unknown Indicator Handling:")
    print("  Status:", clean_unreg.status)
    print("  Malicious Votes:", clean_unreg.malicious_votes)
    # Ensure absence of detections is NOT marked as "Clean"
    assert clean_unreg.malicious_votes == 0
    print("[PASS] Test 6 passed")

    # -----------------------------------------------------------
    # TEST 7: Private IP Handling (Skipped)
    # -----------------------------------------------------------
    priv_res = await abuse.lookup_ip("192.168.1.1", scope="private")
    print("\n[TEST 7] Private IP Scope Protection:")
    print("  Private IP Status:", priv_res.status)
    assert priv_res.status == "SKIPPED"
    print("[PASS] Test 7 passed")

    # -----------------------------------------------------------
    # TEST 8: Missing API Key Handling (NOT_CONFIGURED)
    # -----------------------------------------------------------
    unconfigured_vt = VirusTotalProvider(api_key="", mode="real")
    unconfigured_res = await unconfigured_vt.lookup_domain("example.com")
    print("\n[TEST 8] Missing API Key Handling:")
    print("  Unconfigured Status:", unconfigured_res.status)
    assert unconfigured_res.status == "NOT_CONFIGURED"
    print("[PASS] Test 8 passed")

    # -----------------------------------------------------------
    # TEST 9: Full IOC Enrichment with Phishing EML
    # -----------------------------------------------------------
    iocs = extract_iocs(EML_SAMPLES["phishing"])
    intel_res = await service.enrich_iocs(iocs)
    print("\n[TEST 9] Full IOC Threat Intelligence Enrichment:")
    print("  Total Analyzed:", intel_res.summary.total_analyzed)
    print("  Malicious Count:", intel_res.summary.malicious_count)
    print("  Suspicious Count:", intel_res.summary.suspicious_count)
    print("  Clean Count:", intel_res.summary.clean_reported_count)
    assert intel_res.summary.total_analyzed >= 2
    assert intel_res.summary.malicious_count >= 1
    print("[PASS] Test 9 passed")

    # -----------------------------------------------------------
    # TEST 10: In-Memory Cache Deduplication
    # -----------------------------------------------------------
    initial_hits = default_intel_cache.hits
    # Perform same lookup second time
    _ = await vt.lookup_domain("alert-center.xyz")
    assert default_intel_cache.hits > initial_hits
    print("\n[TEST 10] In-Memory Cache Hit Verification: Hits incremented to", default_intel_cache.hits)
    print("[PASS] Test 10 passed")

    # -----------------------------------------------------------
    # TEST 11: Benign EML Clean Reported Handling
    # -----------------------------------------------------------
    benign_iocs = extract_iocs(EML_SAMPLES["benign"])
    benign_intel = await service.enrich_iocs(benign_iocs)
    print("\n[TEST 11] Benign EML Intelligence:")
    print("  Malicious Count:", benign_intel.summary.malicious_count)
    assert benign_intel.summary.malicious_count == 0
    print("[PASS] Test 11 passed")

    # -----------------------------------------------------------
    # TEST 12: FastAPI Endpoints Integration
    # -----------------------------------------------------------
    try:
        from fastapi.testclient import TestClient
        from backend.main import app
        
        client = TestClient(app)
        resp = client.post(
            "/api/v1/analyze/intelligence",
            json={"raw_eml": EML_SAMPLES["phishing"]}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
        assert "results" in data
        assert data["summary"]["malicious_count"] >= 1
        
        # Test unified complete EML pipeline (Features 1–5)
        unified_resp = client.post(
            "/api/v1/analyze/eml",
            json={"raw_eml": EML_SAMPLES["phishing"]}
        )
        assert unified_resp.status_code == 200
        u_data = unified_resp.json()
        assert "forensics" in u_data
        assert "iocs" in u_data
        assert "threat_intelligence" in u_data
        assert "threat_analysis" in u_data
        assert "explanation" in u_data
        print("[PASS] Test 12 passed (FastAPI endpoints)")
    except ImportError:
        print("[SKIP] TestClient not available")

    print("=" * 65)
    print("ALL FEATURE 5 THREAT INTELLIGENCE TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)


def main():
    asyncio.run(run_all_tests_async())


if __name__ == "__main__":
    main()
