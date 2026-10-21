"""
ThreatLens GraphOps - Phase 7 Integration and UI Contract Tests
Tests the GraphOps Interface, Case Evidence Bridge, and What-If Containment Simulator.
Verifies strictly in-memory simulation, before/after path delta calculations,
evidence mapping from email cases to corporate graph entities, and API responses.
"""

import pytest
import os
from typing import Dict, List, Any, Optional, Set
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
    InterventionAction,
)
from backend.models.graphops import (
    ContainmentSimulationRequest,
    ContainmentSimulationResult,
    ProposedIntervention,
    CaseBridgeResponse,
)
from backend.graphops.attack_paths import AttackPathService
from backend.graphops.client import get_graphops_client
from backend.data.graphops_fixtures import load_sample_enterprise_fixture


# =====================================================================
# IN-MEMORY GRAPH MOCK FOR PHASE 7 SIMULATION & CASE BRIDGE
# =====================================================================

class InMemoryPhase7GraphClient:
    """Mock client simulating Neo4j with path search, Crown Jewels, and USES queries."""

    def __init__(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        self.nodes = {n["id"].lower(): n for n in nodes}
        self.aliases: Dict[str, str] = {}
        for n in nodes:
            nid = n["id"].lower()
            props = n.get("properties", {})
            for key in ["email", "hostname", "user_id", "device_id", "server_id", "asset_id"]:
                val = props.get(key)
                if val:
                    self.aliases[str(val).lower()] = nid
                    if ":" in str(val):
                        self.aliases[str(val).split(":", 1)[1].lower()] = nid
            if ":" in nid:
                self.aliases[nid.split(":", 1)[1].lower()] = nid
        self.edges = edges

    def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        params = params or {}
        q = query.strip()

        # 1. Node Resolution Query
        if "WHERE n.id = $id" in q or "toLower(n.id) = toLower($id)" in q:
            target_id = str(params.get("id", "")).lower()
            id_without_prefix = str(params.get("id_without_prefix", "")).lower()

            resolved = (
                self.nodes.get(target_id)
                or self.nodes.get(id_without_prefix)
                or self.aliases.get(target_id)
                or self.aliases.get(id_without_prefix)
            )
            if resolved:
                node = resolved if isinstance(resolved, dict) else self.nodes[resolved]
                return [{
                    "id": node["id"],
                    "labels": node.get("labels", []),
                    "properties": node.get("properties", {}),
                }]
            return []

        # 2. Query All Crown Jewels
        if "MATCH (c:CriticalAsset)" in q:
            results = []
            for n in self.nodes.values():
                if "CriticalAsset" in n.get("labels", []) or n.get("properties", {}).get("criticality") == "CRITICAL":
                    results.append({"id": n["id"]})
            return results

        # 3. User to Assigned Device Query: MATCH (u {id: $uid})-[:USES]->(d)
        if "-[:USES]->(d)" in q:
            uid = str(params.get("uid", "")).lower()
            results = []
            for e in self.edges:
                if e["source_id"].lower() == uid and e["relationship_type"] == "USES":
                    target_node = self.nodes.get(e["target_id"].lower())
                    if target_node:
                        results.append({
                            "id": target_node["id"],
                            "labels": target_node.get("labels", []),
                            "properties": target_node.get("properties", {}),
                        })
            return results

        # 4. Path Search Query: MATCH p = (start)-[r*1..N]->(target)
        if "MATCH p = (start)-[r*" in q:
            entry_id = str(params.get("entry_id", "")).lower()
            target_ids = {str(t).lower() for t in params.get("target_ids", [])}
            allowed_types = set(params.get("allowed_types", []))
            include_hypothetical = params.get("include_hypothetical", False)
            limit = params.get("limit", 50)

            found_paths = []

            def dfs(current_id: str, path_nodes: List[Dict[str, Any]], path_edges: List[Dict[str, Any]], visited_ids: Set[str]):
                if len(found_paths) >= limit or len(path_edges) >= 6:
                    return

                for e in self.edges:
                    src = e["source_id"].lower()
                    if src != current_id:
                        continue

                    rel_type = e["relationship_type"]
                    ev_class = e.get("evidence_class", "OBSERVED")

                    if allowed_types and rel_type not in allowed_types:
                        continue
                    if not include_hypothetical:
                        if rel_type == "POTENTIAL_EXPLOIT" or ev_class == "HYPOTHETICAL":
                            continue

                    tgt = e["target_id"].lower()
                    if tgt in visited_ids:
                        continue

                    tgt_node = self.nodes.get(tgt)
                    if not tgt_node:
                        continue

                    new_nodes = path_nodes + [tgt_node]
                    edge_dict = {
                        "type": rel_type,
                        "source_id": e["source_id"],
                        "target_id": e["target_id"],
                        "evidence_class": ev_class,
                        "properties": e.get("properties", {}),
                    }
                    new_edges = path_edges + [edge_dict]

                    if tgt in target_ids:
                        found_paths.append({
                            "path_nodes": new_nodes,
                            "path_relationships": new_edges,
                        })

                    dfs(tgt, new_nodes, new_edges, visited_ids | {tgt})

            start_node = self.nodes.get(entry_id)
            if start_node:
                dfs(entry_id, [start_node], [], {entry_id})

            return found_paths

        return []

    def health_check(self) -> Dict[str, Any]:
        return {
            "status": "healthy",
            "connected": True,
            "database": "neo4j",
            "active_nodes": len(self.nodes),
            "active_relationships": len(self.edges),
            "error": None,
        }


def build_phase7_fixture_mock() -> InMemoryPhase7GraphClient:
    """Builds an InMemoryPhase7GraphClient preloaded with the synthetic enterprise fixture."""
    fixture = load_sample_enterprise_fixture()
    nodes = []
    edges = []

    label_map = {
        "users": [NodeLabel.USER.value],
        "devices": [NodeLabel.DEVICE.value],
        "servers": [NodeLabel.SERVER.value],
        "applications": [NodeLabel.APPLICATION.value],
        "ips": [NodeLabel.IP_ADDRESS.value],
        "vulnerabilities": [NodeLabel.VULNERABILITY.value],
        "critical_assets": [NodeLabel.CRITICAL_ASSET.value],
        "security_events": [NodeLabel.SECURITY_EVENT.value],
    }

    prefix_map = {
        "users": "user",
        "devices": "device",
        "servers": "server",
        "applications": "app",
        "ips": "ip",
        "vulnerabilities": "vuln",
        "critical_assets": "critical",
        "security_events": "event",
    }

    for category, entity_list in fixture["entities"].items():
        labels = label_map.get(category, ["Entity"])
        prefix = prefix_map.get(category, "entity")
        for ent in entity_list:
            raw_id = ent.get("id") or ent.get("ip") or ent.get("cve_id")
            clean_id = str(raw_id).lower()
            canonical_id = clean_id if clean_id.startswith(f"{prefix}:") else f"{prefix}:{clean_id}"
            props = dict(ent)
            props["id"] = canonical_id
            nodes.append({
                "id": canonical_id,
                "labels": labels,
                "properties": props,
            })

    alias_map = {}
    for n in nodes:
        props = n["properties"]
        if "email" in props:
            alias_map[f"user:{props['email'].lower()}"] = n["id"]
            alias_map[props['email'].lower()] = n["id"]

    for r in fixture["relationships"]["relationships"]:
        src = r["source_id"].lower()
        tgt = r["target_id"].lower()
        src = alias_map.get(src, src)
        tgt = alias_map.get(tgt, tgt)
        if src.startswith("vuln:cve-"):
            src = "vuln:" + src[5:].upper()
        if tgt.startswith("vuln:cve-"):
            tgt = "vuln:" + tgt[5:].upper()

        edge_props = dict(r.get("properties", {}))
        edge_props["evidence_class"] = r.get("evidence_class", "OBSERVED")
        edge_props["provenance"] = r.get("provenance", "Test")
        edge_props["confidence"] = r.get("confidence", 1.0)
        edge_props["timestamp"] = r.get("timestamp")

        edges.append({
            "source_id": src,
            "target_id": tgt,
            "relationship_type": r["relationship_type"],
            "evidence_class": r.get("evidence_class", "OBSERVED"),
            "properties": edge_props,
        })

    return InMemoryPhase7GraphClient(nodes, edges)


@pytest.fixture
def mock_phase7_client():
    return build_phase7_fixture_mock()


@pytest.fixture
def test_client(mock_phase7_client):
    app.dependency_overrides[get_graphops_client] = lambda: mock_phase7_client
    client = TestClient(app)
    yield client
    app.dependency_overrides.pop(get_graphops_client, None)


# =====================================================================
# 1. WHAT-IF CONTAINMENT SIMULATION UNIT TESTS
# =====================================================================

class TestWhatIfContainmentSimulation:

    def test_simulation_does_not_modify_live_graph(self, mock_phase7_client):
        """Simulation must guarantee that live persistent graph is unmodified."""
        service = AttackPathService(mock_phase7_client)
        req = ContainmentSimulationRequest(
            entry_node_id="device:dev-ws-101",
            proposed_interventions=[
                ProposedIntervention(
                    action=InterventionAction.ISOLATE_NODE,
                    node_id="server:srv-app-01",
                    description="Isolate application server gateway",
                )
            ],
        )
        res = service.simulate_containment(req)

        assert res.live_graph_modified is False
        assert "SIMULATION ONLY" in res.safety_disclaimer
        assert res.simulation_id.startswith("SIM-")

    def test_simulation_full_containment_of_gateway(self, mock_phase7_client):
        """Isolating srv-app-01 should eliminate all attack paths traversing through it."""
        service = AttackPathService(mock_phase7_client)
        req = ContainmentSimulationRequest(
            entry_node_id="device:dev-ws-101",
            proposed_interventions=[
                ProposedIntervention(
                    action=InterventionAction.ISOLATE_NODE,
                    node_id="server:srv-app-01",
                )
            ],
        )
        res = service.simulate_containment(req)

        assert res.baseline_paths_count > 0
        assert res.remaining_paths_count == 0
        assert res.paths_eliminated_count == res.baseline_paths_count
        assert res.containment_efficiency_pct == 100.0
        assert len(res.residual_exposed_assets) == 0
        assert "Full containment achieved" in res.analyst_verdict

        for ps in res.path_statuses:
            assert ps.status == "ELIMINATED"
            assert ps.severed_at_step is not None

    def test_simulation_partial_containment_relationship(self, mock_phase7_client):
        """Severing the connection to srv-db-01 should eliminate database paths while leaving DC paths active."""
        service = AttackPathService(mock_phase7_client)
        req = ContainmentSimulationRequest(
            entry_node_id="device:dev-ws-101",
            proposed_interventions=[
                ProposedIntervention(
                    action=InterventionAction.BLOCK_CONNECTION,
                    source_id="server:srv-app-01",
                    target_id="server:srv-db-01",
                    relationship_type=RelationshipType.OBSERVED_CONNECTION,
                )
            ],
        )
        res = service.simulate_containment(req)

        assert res.baseline_paths_count > 0
        assert res.live_graph_modified is False
        assert res.paths_eliminated_count >= 1
        assert res.remaining_paths_count >= 1
        assert "Partial containment" in res.analyst_verdict


# =====================================================================
# 2. CASE-TO-GRAPH EVIDENCE BRIDGE TESTS
# =====================================================================

class TestCaseBridgeResolution:

    def test_bridge_correlates_email_case_to_user_and_device(self, mock_phase7_client):
        """Recipient victim1@corporation.com must map to usr-101 and DEV-WS-101."""
        service = AttackPathService(mock_phase7_client)
        res = service.bridge_case_to_graph("MT-101")

        assert res.case_id == "MT-101"
        assert res.primary_compromised_node is not None
        assert res.primary_compromised_node.id == "user:usr-101"

        mapped_types = [m.evidence_type for m in res.mapped_entities]
        assert "RECIPIENT_EMAIL" in mapped_types
        assert "ASSIGNED_DEVICE" in mapped_types

        mapped_nodes = [m.mapped_node_id for m in res.mapped_entities]
        assert "user:usr-101" in mapped_nodes
        assert "device:dev-ws-101" in mapped_nodes

        # Verify external attacker IOCs are quarantined outside internal graph
        assert "185.190.140.22" in res.unmapped_external_iocs
        assert "alert-center.xyz" in res.unmapped_external_iocs
        assert "user:usr-101" in res.recommended_blast_radius_url


# =====================================================================
# 3. FASTAPI API INTEGRATION ENDPOINT TESTS
# =====================================================================

class TestGraphOpsPhase7APIEndpoints:

    def test_api_simulate_containment_endpoint(self, test_client):
        """POST /api/v1/graphops/simulate-containment returns valid result schema."""
        payload = {
            "entry_node_id": "device:dev-ws-101",
            "proposed_interventions": [
                {
                    "action": "ISOLATE_NODE",
                    "node_id": "server:srv-app-01",
                    "description": "Quarantine compromised jump host"
                }
            ]
        }
        resp = test_client.post("/api/v1/graphops/simulate-containment", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["live_graph_modified"] is False
        assert data["baseline_paths_count"] > 0
        assert data["remaining_paths_count"] == 0
        assert data["paths_eliminated_count"] == data["baseline_paths_count"]
        assert data["containment_efficiency_pct"] == 100.0
        assert "SIMULATION ONLY" in data["safety_disclaimer"]

    def test_api_simulate_containment_404_entry_node(self, test_client):
        """Simulation with non-existent entry node returns 404."""
        payload = {
            "entry_node_id": "device:non-existent-device-xyz",
            "proposed_interventions": [{"action": "ISOLATE_NODE", "node_id": "server:srv-app-01"}]
        }
        resp = test_client.post("/api/v1/graphops/simulate-containment", json=payload)
        assert resp.status_code == 404
        assert "does not exist" in resp.json()["detail"].lower() or "not found" in resp.json()["detail"].lower()

    def test_api_case_bridge_endpoint(self, test_client):
        """GET /api/v1/graphops/bridge/case/MT-101 maps recipient and isolates external IOCs."""
        resp = test_client.get("/api/v1/graphops/bridge/case/MT-101")
        assert resp.status_code == 200
        data = resp.json()

        assert data["case_id"] == "MT-101"
        assert data["primary_compromised_node"]["id"] == "user:usr-101"
        assert len(data["mapped_entities"]) >= 2
        assert "185.190.140.22" in data["unmapped_external_iocs"]
        assert "/api/v1/graphops/blast-radius" in data["recommended_blast_radius_url"]


# =====================================================================
# 4. FRONTEND UI ARTIFACT CONTRACT TESTS
# =====================================================================

class TestFrontendUIContract:

    def test_html_contains_graphops_workspace_and_components(self):
        """Verifies index.html has all required GraphOps DOM IDs and controls."""
        html_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
        assert os.path.isfile(html_path)

        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Navigation and view pane
        assert 'id="nav-item-graphops"' in html
        assert 'id="view-graphops"' in html
        assert 'id="btn-correlate-case-graphops"' in html

        # Status and bridge banner
        assert 'id="graphops-db-indicator"' in html
        assert 'id="btn-graphops-sync-fixture"' in html
        assert 'id="graphops-case-bridge-banner"' in html

        # Mode buttons
        assert 'id="tab-graphops-blast"' in html
        assert 'id="tab-graphops-paths"' in html
        assert 'id="tab-graphops-simulator"' in html

        # Controls
        assert 'id="graphops-node-preset-select"' in html
        assert 'id="graphops-node-input"' in html
        assert 'id="graphops-hops-select"' in html
        assert 'id="graphops-direction-select"' in html
        assert 'id="graphops-target-select"' in html
        assert 'id="graphops-sim-action-select"' in html
        assert 'id="graphops-sim-entity-input"' in html
        assert 'id="btn-graphops-execute"' in html
        assert 'id="btn-graphops-reset-sim"' in html

        # Canvas & Inspector
        assert 'id="cy-graphops-canvas"' in html
        assert 'id="btn-cy-zoom-in"' in html
        assert 'id="btn-cy-fit"' in html
        assert 'id="graphops-inspector-card"' in html
        assert 'id="panel-choke-points"' in html
        assert 'id="panel-simulation-results"' in html

    def test_js_app_contains_graphops_functions(self):
        """Verifies app.js contains all required controller methods and Cytoscape integration."""
        js_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "js", "app.js")
        assert os.path.isfile(js_path)

        with open(js_path, "r", encoding="utf-8") as f:
            js = f.read()

        assert "initGraphOpsWorkspace" in js
        assert "renderGraphOpsView" in js
        assert "bridgeCaseToGraph" in js
        assert "runBlastRadius" in js
        assert "runAttackPaths" in js
        assert "runContainmentSimulation" in js
        assert "renderGraphOpsCanvas" in js
        assert "renderChokePointsTable" in js
        assert "cyGraphOps" in js
        assert "node[?is_root]" in js
        assert "node[?is_critical]" in js
        assert "node[?is_severed]" in js
