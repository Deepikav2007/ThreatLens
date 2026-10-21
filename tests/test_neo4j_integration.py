"""
ThreatLens GraphOps - Neo4j Integration Test Suite
Phase 3: Database Client, Connection Lifecycle, Health Checks, Error Handling, and FastAPI Integration.
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.client import (
    Neo4jClient,
    GraphOpsConnectionError,
    GraphOpsQueryError,
    GraphOpsConfigurationError,
    get_graphops_client,
    close_graphops_client,
)
from backend.graphops.schema import CYPHER_SCHEMA_STATEMENTS


# =====================================================================
# 1. CLIENT INITIALIZATION & CONFIGURATION TESTS
# =====================================================================

def test_neo4j_client_initialization_defaults():
    client = Neo4jClient()
    assert client.uri.startswith("bolt://") or client.uri.startswith("neo4j://")
    assert client.user == "neo4j"
    assert client.database == "neo4j"
    assert client._driver is None


def test_neo4j_client_missing_uri():
    client = Neo4jClient(uri="")
    with pytest.raises(GraphOpsConfigurationError, match="not configured"):
        client.get_driver()


# =====================================================================
# 2. UNAVAILABLE DATABASE & FAILURE HANDLING TESTS
# =====================================================================

def test_neo4j_client_unavailable_connection_handling():
    """
    Verifies that when Neo4j is offline:
    1. verify_connectivity() raises GraphOpsConnectionError.
    2. execute_query() raises GraphOpsConnectionError and DOES NOT silently return empty list.
    """
    client = Neo4jClient(uri="bolt://127.0.0.1:59999", connection_timeout=0.5)

    with pytest.raises(GraphOpsConnectionError):
        client.verify_connectivity()

    with pytest.raises(GraphOpsConnectionError):
        client.execute_query("MATCH (n) RETURN n LIMIT 1")

    client.close()


def test_neo4j_client_health_check_unavailable_sanitized():
    """
    Verifies that health_check() returns safe status=unhealthy without disclosing credentials.
    """
    client = Neo4jClient(
        uri="bolt://127.0.0.1:59999",
        password="super_secret_password_12345",
        connection_timeout=0.5
    )
    health = client.health_check()
    assert health["status"] == "unhealthy"
    assert health["connected"] is False
    assert health["database"] == "neo4j"
    assert "error" in health

    # CRITICAL SECURITY CHECK: passwords must NEVER leak in health reports
    assert "super_secret_password_12345" not in str(health)
    client.close()


# =====================================================================
# 3. MOCKED SUCCESSFUL CONNECTION & EXECUTION TESTS
# =====================================================================

@patch("neo4j.GraphDatabase.driver")
def test_neo4j_client_mocked_successful_connection(mock_driver_factory):
    mock_driver = MagicMock()
    mock_server_info = MagicMock()
    mock_server_info.agent = "Neo4j/5.26.0"
    mock_server_info.protocol_version = "Bolt/5.4"
    mock_server_info.address = "localhost:7687"
    mock_driver.verify_connectivity.return_value = mock_server_info
    mock_driver_factory.return_value = mock_driver

    client = Neo4jClient()
    info = client.verify_connectivity()
    assert info["connected"] is True
    assert "Neo4j/5.26.0" in info["agent"]

    health = client.health_check()
    assert health["status"] == "healthy"
    assert health["connected"] is True
    assert health["server_agent"] == "Neo4j/5.26.0"
    client.close()


@patch("neo4j.GraphDatabase.driver")
def test_neo4j_client_mocked_parameterized_query(mock_driver_factory):
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    mock_record1 = MagicMock()
    mock_record1.data.return_value = {"n.id": "user:alice@corp.com", "n.name": "Alice"}
    mock_session.run.return_value = [mock_record1]
    mock_driver_factory.return_value = mock_driver

    client = Neo4jClient()
    results = client.execute_query(
        "MATCH (n:User {id: $uid}) RETURN n.id, n.name",
        parameters={"uid": "user:alice@corp.com"}
    )
    assert len(results) == 1
    assert results[0]["n.id"] == "user:alice@corp.com"

    # Verify parameterized invocation
    mock_session.run.assert_called_once_with(
        "MATCH (n:User {id: $uid}) RETURN n.id, n.name",
        {"uid": "user:alice@corp.com"}
    )
    client.close()


@patch("neo4j.GraphDatabase.driver")
def test_neo4j_client_mocked_write_transaction(mock_driver_factory):
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    def fake_execute_write(work_fn):
        fake_tx = MagicMock()
        fake_res = MagicMock()
        fake_consume = MagicMock()
        fake_counters = MagicMock()
        fake_counters.nodes_created = 3
        fake_counters.nodes_deleted = 0
        fake_counters.relationships_created = 2
        fake_counters.relationships_deleted = 0
        fake_counters.properties_set = 10
        fake_counters.labels_added = 3
        fake_counters.indexes_added = 0
        fake_counters.constraints_added = 1
        fake_consume.counters = fake_counters
        fake_res.consume.return_value = fake_consume
        fake_tx.run.return_value = fake_res
        return work_fn(fake_tx)

    mock_session.execute_write.side_effect = fake_execute_write
    mock_driver_factory.return_value = mock_driver

    client = Neo4jClient()
    counters = client.execute_write("MERGE (n:User {id: $id})", {"id": "user:test"})
    assert counters["nodes_created"] == 3
    assert counters["relationships_created"] == 2
    assert counters["constraints_added"] == 1
    client.close()


@patch("neo4j.GraphDatabase.driver")
def test_neo4j_client_schema_constraints_init(mock_driver_factory):
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session
    mock_session.execute_write.return_value = {"constraints_added": 1}
    mock_driver_factory.return_value = mock_driver

    client = Neo4jClient()
    summary = client.init_schema_constraints()
    assert summary["total_statements"] == len(CYPHER_SCHEMA_STATEMENTS)
    assert summary["applied_count"] == len(CYPHER_SCHEMA_STATEMENTS)
    assert len(summary["errors"]) == 0
    client.close()


def test_neo4j_client_cleanup_and_close():
    client = Neo4jClient()
    fake_driver = MagicMock()
    client._driver = fake_driver

    client.close()
    fake_driver.close.assert_called_once()
    assert client._driver is None


# =====================================================================
# 4. FASTAPI HEALTH ENDPOINT INTEGRATION TESTS
# =====================================================================

def test_fastapi_graphops_health_endpoint_healthy():
    client = TestClient(app)
    mock_client = MagicMock()
    mock_client.health_check.return_value = {
        "status": "healthy",
        "database": "neo4j",
        "connected": True,
        "server_agent": "Neo4j/5.26.0",
        "protocol": "Bolt/5.4"
    }

    app.dependency_overrides[get_graphops_client] = lambda: mock_client
    try:
        resp = client.get("/api/v1/graphops/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["connected"] is True
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


def test_fastapi_graphops_health_endpoint_unhealthy():
    client = TestClient(app)
    mock_client = MagicMock()
    mock_client.health_check.return_value = {
        "status": "unhealthy",
        "database": "neo4j",
        "connected": False,
        "error": "Failed to connect to localhost:7687"
    }

    app.dependency_overrides[get_graphops_client] = lambda: mock_client
    try:
        resp = client.get("/api/v1/graphops/health")
        assert resp.status_code == 503
        data = resp.json()
        assert "detail" in data
        assert data["detail"]["status"] == "unhealthy"
        assert data["detail"]["connected"] is False
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


def test_fastapi_graphops_schema_endpoints():
    client = TestClient(app)
    resp = client.get("/api/v1/graphops/schema/constraints")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_constraints_and_indexes"] == len(CYPHER_SCHEMA_STATEMENTS)
    assert len(data["statements"]) > 0


# =====================================================================
# 5. REGRESSION CHECK: EXISTING APIS CONTINUE OPERATING
# =====================================================================

def test_existing_apis_continue_operating():
    """
    Verifies that all existing ThreatLens endpoints continue operating cleanly
    even when Neo4j is not connected.
    """
    client = TestClient(app)

    # 1. Root route
    root_resp = client.get("/")
    assert root_resp.status_code == 200
    assert "ThreatLens" in root_resp.json()["message"]

    # 2. Existing core health check
    health_resp = client.get("/api/v1/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"

    # 3. Existing case repository list
    cases_resp = client.get("/api/v1/cases")
    assert cases_resp.status_code == 200
    assert len(cases_resp.json()) >= 4

    # 4. Existing campaign list
    camp_resp = client.get("/api/v1/campaigns")
    assert camp_resp.status_code == 200
    assert len(camp_resp.json()) >= 1
