"""
MailTrace AI - IOC Extractor Test Suite
Feature 4: IOC Extraction
"""

import sys
import os

# Add workspace to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.services.ioc_extractor import extract_iocs, default_ioc_service
from backend.services.email_forensics import analyze_email_forensics
from backend.data.eml_samples import EML_SAMPLES


def test_1_standard_email_extraction():
    """TEST 1: Email with URLs, domains, IPs, and email addresses."""
    eml = (
        "From: Alice <alice@security-corp.com>\r\n"
        "To: Bob <bob@victim-domain.org>\r\n"
        "Subject: Critical IOCs\r\n"
        "Received: from origin.net (198.51.100.25) by mx.victim-domain.org with ESMTP; Fri, 28 Aug 2026 12:00:00 +0000\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Please review these destination links:\r\n"
        "https://portal.security-corp.com/auth\r\n"
        "http://tracker.victim-domain.org/click?id=99\r\n"
        "https://cdn.security-corp.com/static\r\n"
        "Connected via relay host 203.0.113.88.\r\n"
    )
    res = extract_iocs(eml)
    print("\n[TEST 1] Standard Email IOC Extraction:")
    print("  URLs:", res.summary.urls)
    print("  Domains:", res.summary.domains)
    print("  IPs:", res.summary.ips)
    print("  Emails:", res.summary.emails)

    assert res.summary.urls >= 3
    url_strings = [u.normalized for u in res.urls]
    assert "https://portal.security-corp.com/auth" in url_strings
    assert "http://tracker.victim-domain.org/click?id=99" in url_strings

    # Email addresses
    email_vals = [e.value for e in res.emails]
    assert "alice@security-corp.com" in email_vals
    assert "bob@victim-domain.org" in email_vals

    # IP addresses
    ip_vals = [i.value for i in res.ips]
    assert "198.51.100.25" in ip_vals
    assert "203.0.113.88" in ip_vals

    print("[PASS] Test 1 passed")


def test_2_html_links_and_deduplication():
    """TEST 2: Email with HTML links and duplicate URLs merged with multiple sources."""
    eml = (
        "From: service@alert-center.xyz\r\n"
        "To: user@company.com\r\n"
        "Subject: Duplicate link test\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body>"
        "<p>Please visit: http://secure-login.alert-center.xyz/auth</p>"
        "<a href=\"http://secure-login.alert-center.xyz/auth\">Click to Login</a>"
        "</body></html>"
    )
    res = extract_iocs(eml)
    print("[TEST 2] Duplicate URL Deduplication:")
    
    # Must have merged into 1 URL with multiple sources
    assert res.summary.urls == 1
    url_ioc = res.urls[0]
    print("  URL:", url_ioc.normalized)
    print("  Sources:", url_ioc.sources)
    assert url_ioc.normalized == "http://secure-login.alert-center.xyz/auth"
    assert "email_body" in url_ioc.sources
    assert "html_body" in url_ioc.sources

    print("[PASS] Test 2 passed")


def test_3_hash_classification():
    """TEST 3: Strict classification of MD5, SHA-1, and SHA-256 hashes."""
    md5_sample = "5d41402abc4b2a76b9719d911017c592"
    sha1_sample = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
    sha256_sample = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    eml = (
        "From: admin@soc.com\r\n"
        "To: analyst@soc.com\r\n"
        "Subject: Malware hashes\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        f"MD5: {md5_sample}\r\n"
        f"SHA1: {sha1_sample}\r\n"
        f"SHA256: {sha256_sample}\r\n"
    )
    res = extract_iocs(eml)
    print("[TEST 3] Cryptographic Hash Extraction:")
    
    hash_dict = {h.algorithm: h.value for h in res.hashes}
    print("  Extracted Algorithms:", list(hash_dict.keys()))
    
    assert "MD5" in hash_dict
    assert hash_dict["MD5"] == md5_sample
    assert "SHA1" in hash_dict
    assert hash_dict["SHA1"] == sha1_sample
    assert "SHA256" in hash_dict
    assert hash_dict["SHA256"] == sha256_sample

    print("[PASS] Test 3 passed")


def test_4_attachment_metadata_and_hashing():
    """TEST 4: Email with attachment metadata, size, MIME type, and local SHA-256."""
    raw_eml = EML_SAMPLES["double_extension"]
    res = extract_iocs(raw_eml)
    print("[TEST 4] Attachment Forensic Indicators:")
    
    assert res.summary.attachments >= 1
    att = res.attachments[0]
    print("  Filename:", att.filename)
    print("  MIME type:", att.mime_type)
    print("  SHA-256:", att.sha256[:16] + "...")
    print("  Indicators:", att.indicators)

    assert att.filename == "overdue_receipt.pdf.exe"
    assert len(att.sha256) == 64
    assert "DOUBLE_EXTENSION" in att.indicators

    # Attachment hash must also appear in hashes list
    hash_vals = [h.value for h in res.hashes]
    assert att.sha256 in hash_vals

    print("[PASS] Test 4 passed")


def test_5_ip_scope_classification():
    """TEST 5: Classification of private, loopback, and public IP scopes."""
    eml = (
        "From: internal@company.com\r\n"
        "To: admin@company.com\r\n"
        "Subject: Network scopes\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Servers observed: 192.168.1.50, 10.0.0.1, 127.0.0.1, and external gateway 185.190.140.22\r\n"
    )
    res = extract_iocs(eml)
    print("[TEST 5] IP Scope Classification:")
    
    scope_map = {ip.value: ip.scope for ip in res.ips}
    for ip, sc in scope_map.items():
        print(f"  {ip} -> {sc}")

    assert scope_map.get("192.168.1.50") == "private"
    assert scope_map.get("10.0.0.1") == "private"
    assert scope_map.get("127.0.0.1") == "loopback"
    assert scope_map.get("185.190.140.22") == "public"

    print("[PASS] Test 5 passed")


def test_6_lookalike_domain_preservation():
    """TEST 6: Lookalike domains preserved verbatim without automatic correction."""
    eml = (
        "From: Support <security@paypa1-security.com>\r\n"
        "To: user@target.com\r\n"
        "Subject: Urgent account check\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Log in at: http://login.paypa1-security.com/portal\r\n"
    )
    res = extract_iocs(eml)
    print("[TEST 6] Lookalike Domain Preservation:")
    
    domain_vals = [d.value for d in res.domains]
    print("  Observed Domains:", domain_vals)
    
    # Must preserve 'paypa1-security.com' exactly, never sanitize to paypal.com!
    assert "paypa1-security.com" in domain_vals
    assert "paypal.com" not in domain_vals

    print("[PASS] Test 6 passed")


def test_7_empty_email_handling():
    """TEST 7: Email with no URLs/IPs/hashes handled gracefully without crashes."""
    eml = (
        "From: test@clean.com\r\n"
        "To: test@clean.com\r\n"
        "Subject: Clean email\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Hello friend, this is an ordinary message without links or hashes.\r\n"
    )
    res = extract_iocs(eml)
    print("[TEST 7] Clean Email Handling:")
    print("  URLs:", res.summary.urls)
    print("  Hashes:", res.summary.hashes)
    print("  Attachments:", res.summary.attachments)

    assert res.summary.urls == 0
    assert res.summary.hashes == 0
    assert res.summary.attachments == 0
    assert res.summary.emails == 1

    print("[PASS] Test 7 passed")


def test_8_malformed_email_fault_tolerance():
    """TEST 8: Malformed email handled gracefully."""
    raw_eml = EML_SAMPLES["malformed_sparse"]
    res = extract_iocs(raw_eml)
    print("[TEST 8] Malformed Email Fault Tolerance:")
    print("  Summary:", res.summary.dict())

    assert res is not None
    assert res.summary.emails >= 1

    print("[PASS] Test 8 passed")


def test_9_fastapi_iocs_endpoint():
    """TEST 9: FastAPI /api/v1/analyze/iocs and unified /api/v1/analyze/eml."""
    try:
        from fastapi.testclient import TestClient
        from backend.main import app
        
        client = TestClient(app)
        
        resp = client.post(
            "/api/v1/analyze/iocs",
            json={"raw_eml": EML_SAMPLES["phishing"]}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
        assert "urls" in data
        assert "domains" in data
        assert data["summary"]["urls"] >= 1
        
        # Test unified endpoint
        unified_resp = client.post(
            "/api/v1/analyze/eml",
            json={"raw_eml": EML_SAMPLES["phishing"]}
        )
        assert unified_resp.status_code == 200
        u_data = unified_resp.json()
        assert "forensics" in u_data
        assert "iocs" in u_data
        assert "threat_analysis" in u_data
        assert "explanation" in u_data
        assert u_data["iocs"]["summary"]["urls"] >= 1
        
        print("[PASS] Test 9 passed")
    except ImportError:
        print("[SKIP] TestClient not available")


def run_all_tests():
    print("=" * 65)
    print("MAILTRACE AI - FEATURE 4 (IOC EXTRACTION) TEST SUITE")
    print("=" * 65)
    test_1_standard_email_extraction()
    test_2_html_links_and_deduplication()
    test_3_hash_classification()
    test_4_attachment_metadata_and_hashing()
    test_5_ip_scope_classification()
    test_6_lookalike_domain_preservation()
    test_7_empty_email_handling()
    test_8_malformed_email_fault_tolerance()
    test_9_fastapi_iocs_endpoint()
    print("=" * 65)
    print("ALL FEATURE 4 IOC EXTRACTION TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    run_all_tests()
