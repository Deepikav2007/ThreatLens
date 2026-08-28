"""
MailTrace AI - Email Forensics Test Suite
Feature 3: Email Forensics
"""

import sys
import os
import hashlib

# Add workspace to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.services.email_forensics import analyze_email_forensics, default_forensics_service
from backend.data.eml_samples import EML_SAMPLES


def test_benign_eml_forensics():
    """Test 1: Normal benign email forensic parsing."""
    raw_eml = EML_SAMPLES["benign"]
    res = analyze_email_forensics(raw_eml)
    
    print("\n[TEST 1] Benign EML Forensics:")
    print("  Subject:", res.subject)
    print("  Raw Hash:", res.raw_evidence_hash[:16] + "...")
    print("  Overall Auth:", res.authentication.overall_status)
    
    # Assert integrity hash matches
    expected_hash = hashlib.sha256(raw_eml.encode("utf-8")).hexdigest()
    assert res.raw_evidence_hash == expected_hash
    
    # Assert authentic headers
    assert res.sender_identity.from_address == "alice@corporation.com"
    assert res.sender_identity.reply_to_address == "alice@corporation.com"
    assert not res.sender_identity.reply_to_mismatch
    assert not res.sender_identity.return_path_mismatch
    
    # Assert authentication passed
    assert res.authentication.spf.result == "pass"
    assert res.authentication.dkim.result == "pass"
    assert res.authentication.dmarc.result == "pass"
    assert res.authentication.overall_status == "VERIFIED"
    
    # Assert attachment is extracted and hashed
    assert len(res.attachments) == 1
    att = res.attachments[0]
    assert att.filename == "quarterly_sync_agenda.pdf"
    assert att.extension == ".pdf"
    assert len(att.sha256_hash) == 64
    assert len(att.indicators) == 0
    
    print("[PASS] Test 1: Benign EML forensics passed")


def test_phishing_eml_forensics():
    """Test 2: Phishing email with authentication failures and suspicious links."""
    raw_eml = EML_SAMPLES["phishing"]
    res = analyze_email_forensics(raw_eml)
    
    print("[TEST 2] Phishing EML Forensics:")
    print("  From Domain:", res.sender_identity.from_domain)
    print("  DMARC Result:", res.authentication.dmarc.result)
    print("  Overall Auth:", res.authentication.overall_status)
    
    # DMARC and DKIM failures should be captured
    assert res.authentication.dmarc.result == "fail"
    assert res.authentication.dkim.result == "fail"
    assert res.authentication.spf.result == "pass"
    assert res.authentication.overall_status in ["FAILED", "SUSPICIOUS"]
    
    # Verify anomaly recorded
    anomaly_types = [a.type for a in res.anomalies]
    assert "DMARC_ALIGNMENT_FAILURE" in anomaly_types or "DKIM_SIGNATURE_FAILURE" in anomaly_types
    
    print("[PASS] Test 2: Phishing EML forensics passed")


def test_bec_reply_to_mismatch():
    """Test 3: BEC email with Reply-To mismatch and executive display name."""
    raw_eml = EML_SAMPLES["bec"]
    res = analyze_email_forensics(raw_eml)
    
    print("[TEST 3] BEC Reply-To Mismatch Forensics:")
    print("  From:", res.sender_identity.from_address)
    print("  Reply-To:", res.sender_identity.reply_to_address)
    print("  Mismatch Detected:", res.sender_identity.reply_to_mismatch)
    
    assert res.sender_identity.reply_to_mismatch is True
    assert res.sender_identity.from_domain == "corporation.com"
    assert res.sender_identity.reply_to_domain == "gmail.com"
    
    # Verify anomaly recorded
    anomaly_types = [a.type for a in res.anomalies]
    assert "REPLY_TO_MISMATCH" in anomaly_types
    
    print("[PASS] Test 3: BEC Reply-To mismatch test passed")


def test_smtp_relay_reconstruction():
    """Test 4: SMTP Received relay path chronological reconstruction."""
    raw_eml = EML_SAMPLES["phishing"]
    res = analyze_email_forensics(raw_eml)
    
    print("[TEST 4] SMTP Relay Reconstruction:")
    print("  Hops count:", res.routing_analysis.hop_count)
    print("  Visual Path:", res.routing_analysis.relay_path_visual)
    print("  Originating Candidate:", res.routing_analysis.originating_infrastructure_candidate)
    
    # Chronological ordering test:
    # In phishing.eml:
    # Bottom Received is from origin-mta.net (185.190.140.22) by mx2.alert-center.xyz (12:44:55)
    # Hop 1 MUST be the earliest external relay!
    assert res.routing_analysis.hop_count == 3
    assert len(res.relay_path) == 3
    
    hop1 = res.relay_path[0]
    assert hop1.hop_number == 1
    assert hop1.from_ip == "185.190.140.22"
    assert hop1.from_host == "origin-mta.net"
    assert "185.190.140.22" in (res.routing_analysis.originating_infrastructure_candidate or "")
    
    # Hop 3 must be the final internal receiving MTA
    hop3 = res.relay_path[2]
    assert hop3.hop_number == 3
    assert hop3.by_host == "internal-mta.corporation.com"
    
    # Assert IPs observed
    assert "185.190.140.22" in res.routing_analysis.observed_ips
    assert "194.26.29.112" in res.routing_analysis.observed_ips
    
    print("[PASS] Test 4: SMTP relay path reconstruction test passed")


def test_attachment_forensics_double_extension():
    """Test 5: Attachment forensics with local SHA-256 and double extension detection."""
    raw_eml = EML_SAMPLES["double_extension"]
    res = analyze_email_forensics(raw_eml)
    
    print("[TEST 5] Attachment Forensics:")
    assert len(res.attachments) == 1
    att = res.attachments[0]
    print("  Filename:", att.filename)
    print("  SHA-256:", att.sha256_hash[:16] + "...")
    print("  Indicators:", att.indicators)
    
    assert att.filename == "overdue_receipt.pdf.exe"
    assert "DOUBLE_EXTENSION" in att.indicators
    assert "EXECUTABLE_EXTENSION" in att.indicators
    assert len(att.sha256_hash) == 64
    
    # Check that anomaly was generated
    anomaly_types = [a.type for a in res.anomalies]
    assert "SUSPICIOUS_DOUBLE_EXTENSION" in anomaly_types or "EXECUTABLE_ATTACHMENT" in anomaly_types
    
    print("[PASS] Test 5: Attachment double extension forensics passed")


def test_malformed_sparse_email():
    """Test 6: Malformed / sparse email handling (fault-tolerant, no crashes)."""
    raw_eml = EML_SAMPLES["malformed_sparse"]
    res = analyze_email_forensics(raw_eml)
    
    print("[TEST 6] Malformed / Sparse Email:")
    print("  Message-ID:", res.message_id)
    print("  Anomalies count:", len(res.anomalies))
    
    # Must not crash
    assert res is not None
    assert res.routing_analysis.hop_count == 0
    assert res.authentication.overall_status == "UNKNOWN"
    
    # Missing Message-ID must be recorded as an anomaly
    anomaly_types = [a.type for a in res.anomalies]
    assert "MISSING_MESSAGE_ID" in anomaly_types
    
    print("[PASS] Test 6: Malformed email fault tolerance passed")


def test_api_forensic_endpoints():
    """Test 7: FastAPI endpoints integration."""
    try:
        from fastapi.testclient import TestClient
        from backend.main import app
        
        client = TestClient(app)
        
        # Test /api/v1/demo-emls
        eml_resp = client.get("/api/v1/demo-emls")
        assert eml_resp.status_code == 200
        assert "phishing" in eml_resp.json()
        
        # Test /api/v1/analyze/forensics
        forensics_resp = client.post(
            "/api/v1/analyze/forensics", 
            json={"raw_eml": EML_SAMPLES["phishing"]}
        )
        assert forensics_resp.status_code == 200
        data = forensics_resp.json()
        assert "raw_evidence_hash" in data
        assert "sender_identity" in data
        assert "relay_path" in data
        assert "authentication" in data
        assert len(data["relay_path"]) == 3
        
        # Test /api/v1/analyze/eml (Complete pipeline)
        complete_resp = client.post(
            "/api/v1/analyze/eml",
            json={"raw_eml": EML_SAMPLES["bec"]}
        )
        assert complete_resp.status_code == 200
        complete_data = complete_resp.json()
        assert "forensics" in complete_data
        assert "threat_analysis" in complete_data
        assert "explanation" in complete_data
        assert complete_data["threat_analysis"]["primary_threat"] == "BEC"
        
        print("[PASS] Test 7: FastAPI forensic endpoints test passed")
    except ImportError:
        print("[SKIP] TestClient/httpx not available")


def run_all_tests():
    print("=" * 65)
    print("MAILTRACE AI - FEATURE 3 (EMAIL FORENSICS) TEST SUITE")
    print("=" * 65)
    test_benign_eml_forensics()
    test_phishing_eml_forensics()
    test_bec_reply_to_mismatch()
    test_smtp_relay_reconstruction()
    test_attachment_forensics_double_extension()
    test_malformed_sparse_email()
    test_api_forensic_endpoints()
    print("=" * 65)
    print("ALL FEATURE 3 EMAIL FORENSICS TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    run_all_tests()
