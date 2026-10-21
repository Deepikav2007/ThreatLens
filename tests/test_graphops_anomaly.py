"""
ThreatLens GraphOps - Phase 9 Anomaly Detection Test Suite
Verifies baseline initialization, cold-start handling, transparent rule-based scoring,
4-tier classification fidelity, held-out test suite metrics, and FastAPI endpoints.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.schema import RelationshipType
from backend.models.graphops import (
    AnomalyClassification,
    DeviationType,
    HistoryCompleteness,
    BaselineConfidence,
    AccessSequenceStep,
    AccessSequenceRequest,
    AccessSequenceAnomalyResult,
)
from backend.graphops.anomaly_detection import AccessAnomalyDetector


@pytest.fixture
def detector():
    return AccessAnomalyDetector()


@pytest.fixture
def test_client():
    return TestClient(app)


class TestBaselineAndColdStart:
    """Tests baseline profile initialization and cold-start handling."""

    def test_baseline_summary_structure(self, detector):
        summary = detector.get_baseline_summary()
        assert summary.total_baseline_entities > 0
        assert summary.total_baseline_relationships > 0
        assert len(summary.network_tiering_rules) >= 4
        assert "Finance" in summary.department_profiles
        assert "TIER 1" in summary.network_tiering_rules[0]
        assert "user:svc_backup@corporation.com" in summary.authorized_service_accounts

    def test_cold_start_handling_new_user(self, detector):
        # usr-104 is not in original fixture
        history_comp, conf, dept = detector._assess_cold_start("user:usr-104")
        assert history_comp == HistoryCompleteness.INCOMPLETE
        assert conf == BaselineConfidence.LOW
        assert dept == "Finance"

    def test_longitudinal_entity_high_confidence(self, detector):
        # usr-101 has multiple relationships in fixture
        history_comp, conf, dept = detector._assess_cold_start("user:usr-101")
        assert history_comp == HistoryCompleteness.COMPLETE
        assert conf == BaselineConfidence.HIGH
        assert dept == "Finance"


class TestFourTierClassificationMatrix:
    """Verifies that the detector accurately distinguishes all 4 behavioral categories."""

    def test_benign_expected_access(self, detector):
        # Alice Vance -> dev-ws-101 -> srv-app-01
        steps = [
            AccessSequenceStep(
                step_index=0,
                source_id="user:usr-101",
                relationship_type=RelationshipType.USES,
                target_id="device:dev-ws-101",
            ),
            AccessSequenceStep(
                step_index=1,
                source_id="device:dev-ws-101",
                relationship_type=RelationshipType.OBSERVED_CONNECTION,
                target_id="server:srv-app-01",
                properties={"port": 443},
            ),
        ]
        req = AccessSequenceRequest(
            evaluated_entity_id="user:usr-101",
            steps=steps,
        )
        res = detector.evaluate_sequence(req)
        assert res.classification == AnomalyClassification.BENIGN_EXPECTED
        assert res.anomaly_score < 20
        assert not res.is_anomalous
        assert len(res.unexpected_relationships) == 0

    def test_unobserved_new_legitimate_not_flagged_malicious(self, detector):
        # Newly provisioned analyst Evan Wright accessing ERP web portal
        steps = [
            AccessSequenceStep(
                step_index=0,
                source_id="user:usr-104",
                relationship_type=RelationshipType.USES,
                target_id="device:dev-ws-104",
            ),
            AccessSequenceStep(
                step_index=1,
                source_id="device:dev-ws-104",
                relationship_type=RelationshipType.OBSERVED_CONNECTION,
                target_id="server:srv-app-01",
                properties={"port": 443},
            ),
        ]
        req = AccessSequenceRequest(
            evaluated_entity_id="user:usr-104",
            steps=steps,
        )
        res = detector.evaluate_sequence(req)
        assert res.classification == AnomalyClassification.UNOBSERVED_NEW_LEGITIMATE
        assert 20 <= res.anomaly_score <= 39
        assert not res.is_anomalous  # Strictly NOT flagged as anomalous/malicious
        assert res.history_completeness == HistoryCompleteness.INCOMPLETE

    def test_policy_violation_tier_bypass(self, detector):
        # Workstation directly opening raw SQL connection to Database tier
        steps = [
            AccessSequenceStep(
                step_index=0,
                source_id="device:dev-ws-101",
                relationship_type=RelationshipType.OBSERVED_CONNECTION,
                target_id="server:srv-db-01",
                properties={"port": 5432},
            ),
        ]
        req = AccessSequenceRequest(
            evaluated_entity_id="device:dev-ws-101",
            steps=steps,
        )
        res = detector.evaluate_sequence(req)
        assert res.classification == AnomalyClassification.POLICY_VIOLATION_UNAUTHORIZED
        assert 40 <= res.anomaly_score <= 79
        assert res.is_anomalous
        assert len(res.unexpected_relationships) == 1
        assert res.unexpected_relationships[0].deviation_type == DeviationType.TIER_BYPASS

    def test_suspicious_anomalous_exploit_precondition(self, detector):
        # Traversing unpatched CVE exploit precondition
        steps = [
            AccessSequenceStep(
                step_index=0,
                source_id="device:dev-ws-101",
                relationship_type=RelationshipType.POTENTIAL_EXPLOIT,
                target_id="server:srv-app-01",
                properties={"via_cve": "CVE-2024-21413"},
            ),
            AccessSequenceStep(
                step_index=1,
                source_id="server:srv-app-01",
                relationship_type=RelationshipType.OBSERVED_CONNECTION,
                target_id="server:srv-db-01",
            ),
            AccessSequenceStep(
                step_index=2,
                source_id="server:srv-db-01",
                relationship_type=RelationshipType.CONTAINS_CRITICAL_DATA,
                target_id="critical:crit-pii-customer",
            ),
        ]
        req = AccessSequenceRequest(
            evaluated_entity_id="device:dev-ws-101",
            steps=steps,
        )
        res = detector.evaluate_sequence(req)
        assert res.classification == AnomalyClassification.SUSPICIOUS_ANOMALOUS
        assert res.anomaly_score >= 80
        assert res.is_anomalous
        assert any(
            u.deviation_type == DeviationType.EXPLOIT_PRECONDITION
            for u in res.unexpected_relationships
        )


class TestBenchmarkEvaluationSuite:
    """Verifies that the held-out test suite achieves reproducible precision and recall."""

    def test_run_test_suite_metrics(self, detector):
        suite_res = detector.run_test_suite()
        assert suite_res.total_evaluated == 12
        assert suite_res.total_correct == 12
        assert suite_res.precision == 1.0
        assert suite_res.recall == 1.0
        assert suite_res.f1_score == 1.0
        assert suite_res.false_positive_rate == 0.0
        assert suite_res.confusion_matrix["TP"] == 6
        assert suite_res.confusion_matrix["TN"] == 6
        assert suite_res.confusion_matrix["FP"] == 0
        assert suite_res.confusion_matrix["FN"] == 0


class TestFastAPIAnomalyEndpoints:
    """Verifies FastAPI HTTP contract for anomaly endpoints."""

    def test_api_get_baseline(self, test_client):
        response = test_client.get("/api/v1/graphops/anomaly/baseline")
        assert response.status_code == 200
        data = response.json()
        assert "network_tiering_rules" in data
        assert "scoring_formula" in data

    def test_api_evaluate_sequence(self, test_client):
        payload = {
            "evaluated_entity_id": "user:usr-101",
            "steps": [
                {
                    "step_index": 0,
                    "source_id": "user:usr-101",
                    "relationship_type": "USES",
                    "target_id": "device:dev-ws-101",
                }
            ],
            "include_explanations": True,
        }
        response = test_client.post("/api/v1/graphops/anomaly/evaluate-sequence", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["classification"] == "BENIGN_EXPECTED"
        assert "safety_disclaimer" in data

    def test_api_run_test_suite(self, test_client):
        response = test_client.get("/api/v1/graphops/anomaly/test-suite")
        assert response.status_code == 200
        data = response.json()
        assert data["total_evaluated"] == 12
        assert data["precision"] == 1.0
        assert data["recall"] == 1.0

    def test_api_evaluate_case(self, test_client):
        response = test_client.get("/api/v1/graphops/anomaly/evaluate-case/MT-101")
        assert response.status_code == 200
        data = response.json()
        assert "classification" in data
        assert "anomaly_score" in data
