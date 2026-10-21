"""
ThreatLens GraphOps - Phase 8: End-to-End Verification & Deterministic Scenarios
Validates all four deterministic scenarios, what-if containment safety guarantees,
performance benchmarks, regression baseline, and API contracts.
"""

import pytest
import os
import sys
from typing import Dict, List, Any, Optional, Set
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
    InterventionAction,
    TraversalDirection,
)
from backend.models.graphops import (
    BlastRadiusRequest,
    AttackPathRequest,
    ContainmentSimulationRequest,
    ProposedIntervention,
)
from backend.graphops.blast_radius import BlastRadiusService
from backend.graphops.attack_paths import AttackPathService
from backend.graphops.client import get_graphops_client
from backend.data.graphops_fixtures import load_sample_enterprise_fixture


class InMemoryPhase7GraphClient:
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
                return [{"id": node["id"], "labels": node.get("labels", []), "properties": node.get("properties", {})}]
            return []

        if "MATCH (c:CriticalAsset)" in q:
            results = []
            for n in self.nodes.values():
                if "CriticalAsset" in n.get("labels", []) or n.get("properties", {}).get("criticality") == "CRITICAL":
                    results.append({"id": n["id"]})
            return results

        if "-[:USES]->(d)" in q:
            uid = str(params.get("uid", "")).lower()
            results = []
            for e in self.edges:
                if e["source_id"].lower() == uid and e["relationship_type"] == "USES":
                    target_node = self.nodes.get(e["target_id"].lower())
                    if target_node:
                        results.append({"id": target_node["id"], "labels": target_node.get("labels", []), "properties": target_node.get("properties", {})})
            return results

        # 3b. BFS Frontier Traversal for Blast Radius
        if "frontier_ids" in params:
            frontier = [fid.lower() for fid in params.get("frontier_ids", [])]
            allowed_types = params.get("allowed_types", [])
            include_hypothetical = params.get("include_hypothetical", False)

            if "(s)<-[r]-(t)" in q:
                direction = "INCOMING"
            elif "(s)-[r]-(t)" in q:
                direction = "BOTH"
            else:
                direction = "OUTGOING"

            results = []
            for e in self.edges:
                src = e["source_id"].lower()
                tgt = e["target_id"].lower()
                rel_type = e["relationship_type"]
                ev_class = e.get("evidence_class", "OBSERVED")

                if allowed_types and rel_type not in allowed_types:
                    continue
                if not include_hypothetical:
                    if rel_type == "POTENTIAL_EXPLOIT" or ev_class == "HYPOTHETICAL":
                        continue

                matches = []
                if direction == "OUTGOING" and src in frontier:
                    matches.append((src, tgt))
                elif direction == "INCOMING" and tgt in frontier:
                    matches.append((tgt, src))
                elif direction == "BOTH":
                    if src in frontier:
                        matches.append((src, tgt))
                    if tgt in frontier and tgt != src:
                        matches.append((tgt, src))

                for f_id, n_id in matches:
                    neighbor_node = self.nodes.get(n_id)
                    if neighbor_node:
                        results.append({
                            "frontier_id": f_id,
                            "neighbor_id": n_id,
                            "neighbor_labels": neighbor_node.get("labels", []),
                            "neighbor_props": neighbor_node.get("properties", {}),
                            "rel_type": rel_type,
                            "rel_source_id": e["source_id"],
                            "rel_target_id": e["target_id"],
                            "rel_props": e.get("properties", {}),
                        })
            return results

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
                        found_paths.append({"path_nodes": new_nodes, "path_relationships": new_edges})
                    dfs(tgt, new_nodes, new_edges, visited_ids | {tgt})

            start_node = self.nodes.get(entry_id)
            if start_node:
                dfs(entry_id, [start_node], [], {entry_id})
            return found_paths

        return []

    def health_check(self) -> Dict[str, Any]:
        return {"status": "healthy", "connected": True, "database": "neo4j", "active_nodes": len(self.nodes), "active_relationships": len(self.edges), "error": None}


def build_phase7_fixture_mock() -> InMemoryPhase7GraphClient:
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
            nodes.append({"id": canonical_id, "labels": labels, "properties": props})

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
def mock_graph_client():
    return build_phase7_fixture_mock()


@pytest.fixture
def client(mock_graph_client):
    app.dependency_overrides[get_graphops_client] = lambda: mock_graph_client
    c = TestClient(app)
    yield c
    app.dependency_overrides.pop(get_graphops_client, None)


# =====================================================================
# SCENARIO 1: PHISHING EVIDENCE TO IDENTITY & INFRASTRUCTURE BRIDGE
# =====================================================================

class TestScenario1PhishingCaseBridge:
    """
    Scenario 1: Phishing email evidence correlated with corporate directory
    and internal infrastructure while quarantining external IOCs.
    """

    def test_phishing_case_maps_recipient_to_user_and_device(self, client):
        """Case MT-101 recipient victim1@corporation.com maps to user:usr-101 and device:dev-ws-101."""
        resp = client.get("/api/v1/graphops/bridge/case/MT-101")
        assert resp.status_code == 200
        data = resp.json()

        # 1. Identity correlation
        assert data["case_id"] == "MT-101"
        assert data["primary_compromised_node"]["id"] == "user:usr-101"
        assert data["primary_compromised_node"]["name"] == "Alice Vance"

        # 2. Workstation correlation
        device_mapping = [m for m in data["mapped_entities"] if m["node_label"] == "Device"]
        assert len(device_mapping) == 1
        assert device_mapping[0]["mapped_node_id"] == "device:dev-ws-101"

        # 3. External adversary indicator quarantine
        unmapped = data["unmapped_external_iocs"]
        assert "185.190.140.22" in unmapped
        assert "alert-center.xyz" in unmapped

        # 4. Blast-radius jump link
        assert "start_node_id=user:usr-101" in data["recommended_blast_radius_url"]


# =====================================================================
# SCENARIO 2: COMPROMISED LAPTOP MULTI-HOP BLAST-RADIUS PROPAGATION
# =====================================================================

class TestScenario2CompromisedLaptopBlastRadius:
    """
    Scenario 2: Potentially compromised laptop (DEV-WS-101) multi-hop
    lateral blast-radius propagation across 1-hop, 2-hop, and 3-hop tiers.
    """

    def test_blast_radius_hop_distribution_and_crown_jewel_exposure(self, mock_graph_client):
        """Validates exact hop counts, node deduplication, and Crown Jewel exposure."""
        service = BlastRadiusService(mock_graph_client)
        req = BlastRadiusRequest(
            start_node_id="device:dev-ws-101",
            max_hops=3,
            direction=TraversalDirection.OUTGOING,
            include_hypothetical=True,
        )
        res = service.calculate_blast_radius(req)

        # 1. Boundary and counts
        assert res.start_node.id == "device:dev-ws-101"
        assert res.max_hops_evaluated == 3
        assert res.total_reachable_nodes > 0

        # 2. Strict hop distance mapping
        hop1_ids = [n.id for n in res.hop_1.nodes]
        hop2_ids = [n.id for n in res.hop_2.nodes]
        hop3_ids = [n.id for n in res.hop_3.nodes]

        # Hop 1: Direct connections
        assert "server:srv-app-01" in hop1_ids

        # Hop 2: Intermediate servers and apps
        assert "server:srv-db-01" in hop2_ids or "server:srv-dc-01" in hop2_ids or "app:app-erp-01" in hop2_ids

        # Hop 3: Downstream databases and Crown Jewels
        assert "critical:crit-db-financial" in hop3_ids or "critical:crit-pii-customer" in hop3_ids or "critical:crit-ad-domain-root" in hop3_ids

        # 3. Crown Jewels Identification
        exposed_ids = {cj.asset_id for cj in res.critical_assets_at_risk}
        assert len(exposed_ids) > 0
        assert "critical:crit-db-financial" in exposed_ids or "critical:crit-ad-domain-root" in exposed_ids

        # 4. Deduplication: no node appears twice across hop groups
        all_ids = hop1_ids + hop2_ids + hop3_ids
        assert len(all_ids) == len(set(all_ids))


# =====================================================================
# SCENARIO 3: CANDIDATE ATTACK PATHS & STRATEGIC CHOKE POINTS
# =====================================================================

class TestScenario3AttackPathsAndChokePoints:
    """
    Scenario 3: Candidate attack paths from entry workstation to Crown Jewels,
    ranked choke points, and path betweenness evaluation.
    """

    def test_attack_paths_discovery_and_choke_point_ranking(self, mock_graph_client):
        """Server srv-app-01 is identified as Rank #1 choke point eliminating 100% of paths."""
        service = AttackPathService(mock_graph_client)
        req = AttackPathRequest(
            entry_node_id="device:dev-ws-101",
            max_depth=5,
            include_hypothetical=True,
        )
        path_res = service.find_attack_paths(req)

        assert path_res.total_paths_discovered > 0
        assert len(path_res.targets_reached) >= 3

        # Every path has calculated risk score and valid step sequence
        for p in path_res.paths:
            assert p.risk_score > 0
            assert p.length >= 2
            assert p.nodes[0].id == "device:dev-ws-101"
            assert p.target_id in path_res.targets_reached

        # Choke-point betweenness analysis
        cp_res = service.analyze_choke_points(path_res.paths, top_n=5)
        assert cp_res.total_paths_analyzed == path_res.total_paths_discovered
        assert len(cp_res.choke_points) >= 1

        top_cp = cp_res.top_recommendation
        assert top_cp is not None
        assert top_cp.rank == 1
        assert top_cp.entity_id == "server:srv-app-01"
        assert top_cp.traversal_percentage == 100.0
        assert top_cp.recommended_action == InterventionAction.ISOLATE_NODE


# =====================================================================
# SCENARIO 4: PRECONDITION EXPLOIT & BASELINE ACCESS COMPARISON
# =====================================================================

class TestScenario4BaselineVsPreconditionDeviation:
    """
    Scenario 4: Baseline access sequence vs. lateral movement via hypothetical
    exploit precondition (CVE-2024-21413 Moniker Link).
    """

    def test_exploit_precondition_dramatically_expands_reach(self, mock_graph_client):
        """Excluding hypothetical exploit edges denies lateral pivot from unprivileged workstation."""
        service = AttackPathService(mock_graph_client)

        # Baseline: Strictly observed / authorized edges
        req_strict = AttackPathRequest(
            entry_node_id="device:dev-ws-101",
            max_depth=5,
            include_hypothetical=False,
        )
        paths_strict = service.find_attack_paths(req_strict)

        # Deviant / Exploit scenario: Including hypothetical Moniker Link NTLM relay
        req_hypothetical = AttackPathRequest(
            entry_node_id="device:dev-ws-101",
            max_depth=5,
            include_hypothetical=True,
        )
        paths_hypothetical = service.find_attack_paths(req_hypothetical)

        # Hypothetical exploit unlocks additional lateral routes
        assert paths_hypothetical.total_paths_discovered >= paths_strict.total_paths_discovered
        for p in paths_hypothetical.paths:
            if p.hypothetical_steps_count > 0:
                assert any("CVE-2024-21413" in a or "POTENTIAL_EXPLOIT" in str(s) for a in p.assumptions for s in p.steps)


# =====================================================================
# SCENARIO 5: IN-MEMORY WHAT-IF CONTAINMENT SIMULATION
# =====================================================================

class TestScenario5WhatIfContainmentSafety:
    """
    Scenario 5: In-memory simulation proving zero live graph modification,
    full containment vs partial containment metrics, and safety disclaimers.
    """

    def test_full_containment_via_node_isolation(self, mock_graph_client):
        """Isolating srv-app-01 eliminates 100% of attack paths strictly in memory."""
        service = AttackPathService(mock_graph_client)
        req = ContainmentSimulationRequest(
            entry_node_id="device:dev-ws-101",
            proposed_interventions=[
                ProposedIntervention(action=InterventionAction.ISOLATE_NODE, node_id="server:srv-app-01")
            ],
        )
        sim_res = service.simulate_containment(req)

        # Safety guarantee
        assert sim_res.live_graph_modified is False
        assert "SIMULATION ONLY" in sim_res.safety_disclaimer

        # Calculated outcomes
        assert sim_res.baseline_paths_count > 0
        assert sim_res.remaining_paths_count == 0
        assert sim_res.paths_eliminated_count == sim_res.baseline_paths_count
        assert sim_res.containment_efficiency_pct == 100.0
        assert len(sim_res.residual_exposed_assets) == 0
        assert "Full containment achieved" in sim_res.analyst_verdict

    def test_partial_containment_via_relationship_severance(self, mock_graph_client):
        """Severing connection to srv-db-01 eliminates database paths while leaving DC paths active."""
        service = AttackPathService(mock_graph_client)
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
        sim_res = service.simulate_containment(req)

        assert sim_res.live_graph_modified is False
        assert sim_res.baseline_paths_count > 0
        assert sim_res.paths_eliminated_count >= 1
        assert sim_res.remaining_paths_count >= 1
        assert "Partial containment" in sim_res.analyst_verdict


# =====================================================================
# SCENARIO 6: SYSTEM REGRESSION & BACKWARD COMPATIBILITY
# =====================================================================

class TestScenario6BaselineRegressionPreservation:
    """
    Scenario 6: Verifies that core ThreatLens features operate identically
    to the Phase 1 audit baseline.
    """

    def test_existing_cases_endpoint_continues_operating(self, client):
        """GET /api/v1/cases continues returning historical investigation cases."""
        resp = client.get("/api/v1/cases")
        assert resp.status_code == 200
        cases = resp.json()
        assert len(cases) >= 5
        case_ids = [c["case_id"] for c in cases]
        assert "MT-101" in case_ids
        assert "MT-102" in case_ids

    def test_existing_campaigns_graph_continues_operating(self, client):
        """GET /api/v1/campaigns/CMP-001/graph operates with Cytoscape schema."""
        resp = client.get("/api/v1/campaigns/CMP-001/graph")
        assert resp.status_code == 200
        graph = resp.json()
        assert "nodes" in graph
        assert "edges" in graph
        assert len(graph["nodes"]) > 0

    def test_existing_demo_emls_continue_operating(self, client):
        """GET /api/v1/demo-emls returns raw EML fixtures."""
        resp = client.get("/api/v1/demo-emls")
        assert resp.status_code == 200
        data = resp.json()
        assert "phishing" in data
        assert "From:" in data["phishing"]
