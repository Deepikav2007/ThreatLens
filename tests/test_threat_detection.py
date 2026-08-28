"""
MailTrace AI - Threat Detection Engine Test Suite
Feature 1: AI Threat Detection
"""

import sys
import os

# Add workspace to sys.path for direct script execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.models.threat import EmailAnalysisInput
from backend.services.threat_detection import detect_threat
from backend.data.demo_emails import DEMO_EMAILS


def test_phishing_email_detection():
    """Test phishing email with account suspension and malicious auth link."""
    payload = EmailAnalysisInput(**DEMO_EMAILS["phishing"])
    result = detect_threat(payload)
    
    print(f"\n[TEST] Phishing Result: Score={result.threat_score}, Level={result.risk_level}, Primary={result.primary_threat}")
    assert result.risk_level in ["HIGH", "CRITICAL"], f"Expected HIGH/CRITICAL, got {result.risk_level}"
    assert result.threat_score >= 70, f"Expected score >= 70, got {result.threat_score}"
    assert result.primary_threat in ["PHISHING", "CREDENTIAL THEFT"], f"Expected PHISHING, got {result.primary_threat}"
    assert result.signals.get("suspicious_url") is True
    assert result.signals.get("dmarc_failure") is True
    assert "suspicious_url" in result.signal_scores
    print("[PASS] Phishing email test passed")


def test_bec_email_detection():
    """Test BEC email with urgent wire transfer and CEO reply-to mismatch."""
    payload = EmailAnalysisInput(**DEMO_EMAILS["bec"])
    result = detect_threat(payload)
    
    print(f"[TEST] BEC Result: Score={result.threat_score}, Level={result.risk_level}, Primary={result.primary_threat}")
    assert result.risk_level in ["HIGH", "CRITICAL"], f"Expected HIGH/CRITICAL, got {result.risk_level}"
    assert result.threat_score >= 70, f"Expected score >= 70, got {result.threat_score}"
    assert result.primary_threat in ["BEC", "FINANCIAL FRAUD"], f"Expected BEC, got {result.primary_threat}"
    assert result.signals.get("bec_indicator") is True
    assert result.signals.get("reply_to_mismatch") is True
    assert result.signals.get("payment_financial_request") is True
    print("[PASS] BEC email test passed")


def test_impersonation_email_detection():
    """Test Impersonation email with IT Helpdesk spoofing and SPF/DKIM/DMARC failure."""
    payload = EmailAnalysisInput(**DEMO_EMAILS["impersonation"])
    result = detect_threat(payload)
    
    print(f"[TEST] Impersonation Result: Score={result.threat_score}, Level={result.risk_level}, Primary={result.primary_threat}")
    assert result.risk_level in ["HIGH", "CRITICAL"], f"Expected HIGH/CRITICAL, got {result.risk_level}"
    assert result.threat_score >= 60, f"Expected score >= 60, got {result.threat_score}"
    assert result.primary_threat in ["SPOOFING / IMPERSONATION", "CREDENTIAL THEFT", "PHISHING"]
    assert result.signals.get("spf_failure") is True
    assert result.signals.get("dkim_failure") is True
    assert result.signals.get("dmarc_failure") is True
    print("[PASS] Impersonation email test passed")


def test_benign_email_detection():
    """Test Benign email with normal meeting agenda and authentic headers."""
    payload = EmailAnalysisInput(**DEMO_EMAILS["benign"])
    result = detect_threat(payload)
    
    print(f"[TEST] Benign Result: Score={result.threat_score}, Level={result.risk_level}, Primary={result.primary_threat}")
    assert result.risk_level == "LOW", f"Expected LOW risk, got {result.risk_level}"
    assert result.threat_score < 20, f"Expected score < 20, got {result.threat_score}"
    assert result.primary_threat == "BENIGN", f"Expected BENIGN, got {result.primary_threat}"
    # Verify no major attack signals are triggered
    assert not result.signals.get("suspicious_url")
    assert not result.signals.get("credential_request")
    assert not result.signals.get("bec_indicator")
    print("[PASS] Benign email test passed")


def test_api_endpoints():
    """Test FastAPI endpoint integration via TestClient."""
    try:
        from fastapi.testclient import TestClient
        from backend.main import app
        
        client = TestClient(app)
        
        # Test health check
        health_resp = client.get("/api/v1/health")
        assert health_resp.status_code == 200
        assert health_resp.json()["status"] == "healthy"
        
        # Test demo-emails
        demos_resp = client.get("/api/v1/demo-emails")
        assert demos_resp.status_code == 200
        assert "phishing" in demos_resp.json()
        
        # Test /api/v1/analyze/threat
        phishing_payload = DEMO_EMAILS["phishing"]
        threat_resp = client.post("/api/v1/analyze/threat", json=phishing_payload)
        assert threat_resp.status_code == 200
        data = threat_resp.json()
        assert data["threat_score"] >= 70
        assert data["risk_level"] in ["HIGH", "CRITICAL"]
        assert data["primary_threat"] in ["PHISHING", "CREDENTIAL THEFT"]
        assert "signals" in data
        assert "signal_scores" in data
        
        print("[PASS] FastAPI API endpoints test passed")
    except ImportError:
        print("[SKIP] httpx not installed for TestClient, skipping direct client test")


def run_all_tests():
    print("=" * 60)
    print("MAILTRACE AI - FEATURE 1 AUTOMATED VERIFICATION SUITE")
    print("=" * 60)
    test_phishing_email_detection()
    test_bec_email_detection()
    test_impersonation_email_detection()
    test_benign_email_detection()
    test_api_endpoints()
    print("=" * 60)
    print("ALL 4 DEMO TEST CASES + API PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
