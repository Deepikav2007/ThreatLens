"""
MailTrace AI - Explainable AI Test Suite
Feature 2: Explainable AI
"""

import sys
import os

# Add workspace to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.models.threat import EmailAnalysisInput
from backend.services.threat_detection import detect_threat
from backend.services.explainable_ai import generate_explanation
from backend.data.demo_emails import DEMO_EMAILS


def test_phishing_explanation():
    """Test Explainable AI output on phishing email."""
    email_data = EmailAnalysisInput(**DEMO_EMAILS["phishing"])
    threat_result = detect_threat(email_data)
    explanation = generate_explanation(threat_result, email_data)
    
    print("\n[TEST] Phishing Explanation Summary:", explanation.summary[:80], "...")
    assert explanation.threat_score >= 70
    assert explanation.risk_level in ["HIGH", "CRITICAL"]
    assert explanation.primary_threat == "PHISHING"
    assert not explanation.is_benign
    
    # Verify risk factors contain explanations and evidence
    signal_names = [rf.signal for rf in explanation.risk_factors]
    assert "suspicious_url" in signal_names
    assert "dmarc_failure" in signal_names
    
    # Check evidence extraction for suspicious URL
    url_factor = next(rf for rf in explanation.risk_factors if rf.signal == "suspicious_url")
    assert url_factor.evidence is not None
    assert "alert-center.xyz" in url_factor.evidence
    
    # Verify top reasons exist and are sorted
    assert len(explanation.top_reasons) > 0
    
    # Verify threat type explanations
    phishing_exp = next((te for te in explanation.threat_explanations if te.type == "PHISHING"), None)
    assert phishing_exp is not None
    assert phishing_exp.confidence >= 0.70
    
    print("[PASS] Phishing explanation test passed")


def test_bec_explanation():
    """Test Explainable AI output on BEC email."""
    email_data = EmailAnalysisInput(**DEMO_EMAILS["bec"])
    threat_result = detect_threat(email_data)
    explanation = generate_explanation(threat_result, email_data)
    
    print("[TEST] BEC Explanation Summary:", explanation.summary[:80], "...")
    assert explanation.risk_level in ["HIGH", "CRITICAL"]
    assert explanation.primary_threat == "BEC"
    
    # Verify Reply-To mismatch evidence
    reply_factor = next((rf for rf in explanation.risk_factors if rf.signal == "reply_to_mismatch"), None)
    assert reply_factor is not None
    assert "gmail.com" in (reply_factor.evidence or "")
    
    # Verify BEC threat justification
    bec_exp = next((te for te in explanation.threat_explanations if te.type == "BEC"), None)
    assert bec_exp is not None
    assert bec_exp.confidence >= 0.70
    
    print("[PASS] BEC explanation test passed")


def test_impersonation_explanation():
    """Test Explainable AI output on Impersonation / Spoofing email."""
    email_data = EmailAnalysisInput(**DEMO_EMAILS["impersonation"])
    threat_result = detect_threat(email_data)
    explanation = generate_explanation(threat_result, email_data)
    
    print("[TEST] Impersonation Explanation Summary:", explanation.summary[:80], "...")
    assert explanation.primary_threat in ["SPOOFING / IMPERSONATION", "CREDENTIAL THEFT", "PHISHING"]
    
    # Verify authentication failure evidence
    dmarc_factor = next((rf for rf in explanation.risk_factors if rf.signal == "dmarc_failure"), None)
    assert dmarc_factor is not None
    assert "FAIL" in (dmarc_factor.evidence or "")
    
    print("[PASS] Impersonation explanation test passed")


def test_benign_explanation():
    """Test Explainable AI output on clean Benign email."""
    email_data = EmailAnalysisInput(**DEMO_EMAILS["benign"])
    threat_result = detect_threat(email_data)
    explanation = generate_explanation(threat_result, email_data)
    
    print("[TEST] Benign Explanation Summary:", explanation.summary)
    assert explanation.is_benign is True
    assert explanation.threat_score < 20
    assert explanation.risk_level == "LOW"
    assert explanation.primary_threat == "BENIGN"
    
    # Should have zero high-risk factors
    assert len(explanation.risk_factors) == 0
    assert len(explanation.top_reasons) == 0
    
    # Should have reassuring benign assurances
    assert len(explanation.benign_assurances) >= 3
    print("[PASS] Benign explanation test passed")


def test_incomplete_data_handling():
    """Test that sparse or incomplete email payloads do not crash and handle gracefully."""
    sparse_email = EmailAnalysisInput(
        sender="unknown@example.com",
        subject="Hello",
        body="Short message with no extra headers."
    )
    threat_result = detect_threat(sparse_email)
    explanation = generate_explanation(threat_result, sparse_email)
    
    assert explanation is not None
    assert explanation.threat_score <= 20
    assert "authentication headers were not provided" in explanation.confidence_note.lower()
    print("[PASS] Incomplete data handling test passed")


def test_api_explain_endpoint():
    """Test FastAPI /api/v1/analyze/explain endpoint."""
    try:
        from fastapi.testclient import TestClient
        from backend.main import app
        
        client = TestClient(app)
        res = client.post("/api/v1/analyze/explain", json=DEMO_EMAILS["phishing"])
        assert res.status_code == 200
        data = res.json()
        
        assert "summary" in data
        assert "risk_factors" in data
        assert "top_reasons" in data
        assert "threat_explanations" in data
        assert "confidence_note" in data
        assert len(data["risk_factors"]) > 0
        
        # Test unified /analyze endpoint
        unified_res = client.post("/api/v1/analyze", json=DEMO_EMAILS["bec"])
        assert unified_res.status_code == 200
        unified_data = unified_res.json()
        assert "summary" in unified_data
        assert unified_data["primary_threat"] == "BEC"
        
        print("[PASS] API /api/v1/analyze/explain endpoint test passed")
    except ImportError:
        print("[SKIP] httpx/TestClient not available")


def run_all_tests():
    print("=" * 60)
    print("MAILTRACE AI - FEATURE 2 (EXPLAINABLE AI) TEST SUITE")
    print("=" * 60)
    test_phishing_explanation()
    test_bec_explanation()
    test_impersonation_explanation()
    test_benign_explanation()
    test_incomplete_data_handling()
    test_api_explain_endpoint()
    print("=" * 60)
    print("ALL FEATURE 2 EXPLAINABLE AI TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
