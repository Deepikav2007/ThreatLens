import time
import os
import sys
import platform
import psutil
from typing import Dict, Any, List, Set, Optional

# Ensure repository root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.graphops.schema import NodeLabel, TraversalDirection, InterventionAction
from backend.models.graphops import (
    BlastRadiusRequest,
    AttackPathRequest,
    ContainmentSimulationRequest,
    ProposedIntervention,
)
from backend.graphops.blast_radius import BlastRadiusService
from backend.graphops.attack_paths import AttackPathService
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


def run_benchmarks() -> Dict[str, Any]:
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / (1024 * 1024)

    client = build_phase7_fixture_mock()
    blast_service = BlastRadiusService(client)
    path_service = AttackPathService(client)

    raw_fixture = load_sample_enterprise_fixture()
    total_nodes = len(client.nodes)
    total_edges = len(client.edges)

    results = {
        "environment": {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(logical=True),
            "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        },
        "dataset": {
            "total_nodes": total_nodes,
            "total_relationships": total_edges,
        },
        "latencies_ms": {},
    }

    # 1. Ingestion / Construction Benchmark
    t0 = time.perf_counter()
    iterations = 50
    for _ in range(iterations):
        _ = build_phase7_fixture_mock()
    t1 = time.perf_counter()
    avg_ingest_time_ms = ((t1 - t0) / iterations) * 1000
    results["latencies_ms"]["mock_graph_construction_avg"] = round(avg_ingest_time_ms, 3)

    # 2. Blast Radius 1-Hop
    req1 = BlastRadiusRequest(start_node_id="device:dev-ws-101", max_hops=1, direction=TraversalDirection.OUTGOING)
    t0 = time.perf_counter()
    for _ in range(100):
        _ = blast_service.calculate_blast_radius(req1)
    t1 = time.perf_counter()
    results["latencies_ms"]["blast_radius_1_hop_avg"] = round(((t1 - t0) / 100) * 1000, 3)

    # 3. Blast Radius 2-Hop
    req2 = BlastRadiusRequest(start_node_id="device:dev-ws-101", max_hops=2, direction=TraversalDirection.OUTGOING)
    t0 = time.perf_counter()
    for _ in range(100):
        _ = blast_service.calculate_blast_radius(req2)
    t1 = time.perf_counter()
    results["latencies_ms"]["blast_radius_2_hop_avg"] = round(((t1 - t0) / 100) * 1000, 3)

    # 4. Blast Radius 3-Hop
    req3 = BlastRadiusRequest(start_node_id="device:dev-ws-101", max_hops=3, direction=TraversalDirection.OUTGOING)
    t0 = time.perf_counter()
    for _ in range(100):
        _ = blast_service.calculate_blast_radius(req3)
    t1 = time.perf_counter()
    results["latencies_ms"]["blast_radius_3_hop_avg"] = round(((t1 - t0) / 100) * 1000, 3)

    # 5. Attack Path Discovery (Max Depth 5)
    path_req = AttackPathRequest(entry_node_id="device:dev-ws-101", max_depth=5, include_hypothetical=True)
    t0 = time.perf_counter()
    for _ in range(100):
        paths_res = path_service.find_attack_paths(path_req)
    t1 = time.perf_counter()
    results["latencies_ms"]["attack_path_discovery_avg"] = round(((t1 - t0) / 100) * 1000, 3)

    # 6. Choke-Point Analysis
    t0 = time.perf_counter()
    for _ in range(100):
        _ = path_service.analyze_choke_points(paths_res.paths, top_n=5)
    t1 = time.perf_counter()
    results["latencies_ms"]["choke_point_analysis_avg"] = round(((t1 - t0) / 100) * 1000, 3)

    # 7. What-If Containment Simulation
    sim_req = ContainmentSimulationRequest(
        entry_node_id="device:dev-ws-101",
        proposed_interventions=[
            ProposedIntervention(action=InterventionAction.ISOLATE_NODE, node_id="server:srv-app-01")
        ],
    )
    t0 = time.perf_counter()
    for _ in range(100):
        _ = path_service.simulate_containment(sim_req)
    t1 = time.perf_counter()
    results["latencies_ms"]["containment_simulation_avg"] = round(((t1 - t0) / 100) * 1000, 3)

    # 8. Case Bridge Resolution
    t0 = time.perf_counter()
    for _ in range(100):
        _ = path_service.bridge_case_to_graph("MT-101")
    t1 = time.perf_counter()
    results["latencies_ms"]["case_bridge_resolution_avg"] = round(((t1 - t0) / 100) * 1000, 3)

    mem_after = process.memory_info().rss / (1024 * 1024)
    results["memory"] = {
        "process_rss_before_mb": round(mem_before, 2),
        "process_rss_after_mb": round(mem_after, 2),
        "delta_mb": round(mem_after - mem_before, 2),
    }

    return results


if __name__ == "__main__":
    benchmark_data = run_benchmarks()
    import json
    print(json.dumps(benchmark_data, indent=2))
