# ThreatLens GraphOps — Phase 5: Multi-Hop Blast-Radius Analysis

## 1. Executive Summary

Phase 5 introduces a dedicated **Multi-Hop Blast-Radius Analytics Engine** (`backend/graphops/blast_radius.py`) for the ThreatLens GraphOps platform. Given any potentially compromised starting entity (User, Device, Server, IP, or Application), the engine traverses the organizational security graph to calculate its exact 1-hop, 2-hop, and 3-hop neighborhoods.

### Key Architectural Commitments Enforced
- **Strict Minimum-Hop Distance**: Traversal uses Breadth-First Search (BFS) to guarantee that each entity is assigned its true minimum hop distance from the start node. Multiple paths to the same node never produce misleading hop counts or duplicate entries.
- **Cycle & Loop Immunity**: Visited node tracking prevents infinite traversal on directed cycles (e.g., $A \rightarrow B \rightarrow C \rightarrow A$).
- **Bounded Traversal Depth**: Depth is strictly bounded to $1 \le \text{max\_hops} \le 3$.
- **Directional Flexibility**: Supports `OUTGOING` (downstream lateral movement propagation), `INCOMING` (upstream attack origin discovery), and `BOTH` (bidirectional blast boundary).
- **Evidence Tier Separation**: Distinguishes direct telemetry (`OBSERVED`), directory entitlements (`AUTHORIZED_ACCESS`), heuristic links (`INFERRED`), and simulated exploit paths (`HYPOTHETICAL`). Network connections are never conflated with authorized access grants.
- **Crown Jewel Exposure Highlighting**: Detects exposed high-value assets (`CriticalAsset` or `impact_score >= 85`), records their exact shortest path sequences, and labels them as `EXPOSED` rather than presumptively compromised.
- **Zero Graph Mutation**: Purely read-only Cypher operations. Never mutates database nodes or edges.

---

## 2. Blast-Radius Traversal Architecture

```
+-------------------------------------------------------------+
|    Compromised / Evaluated Node (e.g., user:usr-101)        |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|               BlastRadiusService                            |
|               (backend/graphops/blast_radius.py)            |
+-------------------------------------------------------------+
| 1. Node & Alias Resolution: Match canonical ID or email     |
| 2. Parameter Validation: max_hops (1..3), direction, types  |
| 3. BFS Traversal Engine:                                    |
|    - Hop 1: Direct 1-hop neighbors (Frontier 1)             |
|    - Hop 2: Intermediate pivot nodes (Frontier 2)           |
|    - Hop 3: Downstream assets & Crown Jewels (Frontier 3)   |
| 4. Shortest Path Tracking: Minimum-hop path reconstruction  |
| 5. Evidence Auditing: Counts by OBSERVED, AUTH, HYPO        |
| 6. Crown Jewel Extraction: Identification of exposed jewels |
| 7. Cytoscape Subgraph Assembly: Nodes & Edges for UI        |
+-------------------------------------------------------------+
         |                                           |
         v                                           v
+-----------------------------+          +--------------------+
|  Neo4j Read-Only Execution  |          |  FastAPI Endpoints |
|  (Parameterized MATCH)      |          |  GET & POST Routes |
+-----------------------------+          +--------------------+
```

---

## 3. Mathematical Traversal Rules & Constraints

### 3.1 Minimum-Hop Guarantee (BFS)
Let $G = (V, E)$ be the organizational security graph, and $s \in V$ be the root compromised node. The hop distance $d(s, v)$ is defined as the length of the shortest path from $s$ to $v$:
$$d(s, v) = \min \{ \text{length}(p) \mid p \text{ is a path from } s \text{ to } v \}$$

Each reachable entity $v$ is placed **exclusively** into the hop group corresponding to $d(s, v)$:
- **`hop_1`**: $\{ v \in V \mid d(s, v) = 1 \}$
- **`hop_2`**: $\{ v \in V \mid d(s, v) = 2 \}$
- **`hop_3`**: $\{ v \in V \mid d(s, v) = 3 \}$

If there exist multiple paths to $v$ (e.g., direct edge $s \rightarrow v$ and multi-hop edge $s \rightarrow u \rightarrow v$), $v$ is recorded **strictly in `hop_1`** and excluded from `hop_2`.

### 3.2 Cycle Immunity
For any cycle $A \rightarrow B \rightarrow C \rightarrow A$:
1. At hop 1: $B$ is discovered ($d(s, B) = 1$). `visited = {A, B}`.
2. At hop 2: $C$ is discovered ($d(s, C) = 2$). `visited = {A, B, C}`.
3. At hop 3: Edge $C \rightarrow A$ points to $A$, which is already in `visited` at depth 0. $A$ is discarded.
**Result**: Traversal terminates cleanly with zero infinite recursion and zero duplicate entities.

### 3.3 Evidence Separation
Relationships are strictly categorized:
- **`OBSERVED`**: Real telemetry (firewall flows, syslog, EDR events, email relay hops).
- **`AUTHORIZED_ACCESS`**: Static access controls (Active Directory groups, database permissions, IAM roles).
- **`INFERRED`**: Heuristic correlations or subnet proximity.
- **`HYPOTHETICAL`**: Modeled exploit preconditions (e.g. unpatched CVE pivot vectors via `POTENTIAL_EXPLOIT`).

When `include_hypothetical=False` (default), hypothetical edges are pruned from graph expansion. When `include_hypothetical=True`, hypothetical pivots are evaluated and explicitly flagged in the summary assessment.

---

## 4. REST API Contract & Endpoints

### 4.1 `GET /api/v1/graphops/blast-radius`
Calculates multi-hop blast radius using standard HTTP query parameters.

#### Query Parameters
| Parameter | Type | Required | Default | Description |
| :--- | :---: | :---: | :---: | :--- |
| `start_node_id` | `string` | **Yes** | — | Canonical ID (e.g., `user:usr-101`) or alias (e.g., `victim1@corporation.com`) |
| `max_hops` | `integer` | No | `3` | Maximum search depth ($1 \le \text{depth} \le 3$) |
| `direction` | `enum` | No | `OUTGOING` | Traversal orientation: `OUTGOING`, `INCOMING`, or `BOTH` |
| `include_hypothetical` | `boolean` | No | `false` | Whether to include modeled exploit edges (`POTENTIAL_EXPLOIT`) |
| `relationship_types` | `string` | No | `null` | Comma-separated whitelist of allowed relationship types |

#### Sample Request
```http
GET /api/v1/graphops/blast-radius?start_node_id=device:dev-ws-101&max_hops=3&direction=OUTGOING&include_hypothetical=true HTTP/1.1
Host: localhost:8000
```

#### Sample Response (200 OK)
```json
{
  "start_node": {
    "id": "device:dev-ws-101",
    "label": "Device",
    "name": "ws-fin-101.corp",
    "criticality": "LOW",
    "properties": {
      "hostname": "ws-fin-101.corp",
      "ip_address": "10.0.1.101",
      "os": "Windows 11 Enterprise"
    }
  },
  "max_hops_evaluated": 3,
  "direction": "OUTGOING",
  "hop_1": {
    "hop_number": 1,
    "node_count": 1,
    "nodes": [
      {
        "id": "server:srv-app-01",
        "label": "Server",
        "name": "Corporate Application Jump Server",
        "criticality": "HIGH"
      }
    ],
    "critical_asset_count": 0
  },
  "hop_2": {
    "hop_number": 2,
    "node_count": 4,
    "nodes": [
      { "id": "server:srv-db-01", "label": "Server", "name": "Customer Core Database Host", "criticality": "CRITICAL" },
      { "id": "server:srv-dc-01", "label": "Server", "name": "Enterprise Domain Controller 01", "criticality": "CRITICAL" },
      { "id": "app:app-erp-01", "label": "Application", "name": "Financial ERP Portal", "criticality": null },
      { "id": "vuln:CVE-2024-21413", "label": "Vulnerability", "name": "CVE-2024-21413", "criticality": null }
    ],
    "critical_asset_count": 0
  },
  "hop_3": {
    "hop_number": 3,
    "node_count": 3,
    "nodes": [
      { "id": "critical:crit-db-financial", "label": "CriticalAsset", "name": "Customer Financial Ledger & Payment Vault", "criticality": "CRITICAL" },
      { "id": "critical:crit-pii-customer", "label": "CriticalAsset", "name": "Customer PII & Identity Master Database", "criticality": "CRITICAL" },
      { "id": "critical:crit-ad-domain-root", "label": "CriticalAsset", "name": "Active Directory Domain Controller Enterprise Root", "criticality": "CRITICAL" }
    ],
    "critical_asset_count": 3
  },
  "total_reachable_nodes": 8,
  "critical_assets_at_risk": [
    {
      "asset_id": "critical:crit-db-financial",
      "name": "Customer Financial Ledger & Payment Vault",
      "category": "FINANCIAL_RECORDS",
      "impact_score": 95,
      "hop_depth": 3,
      "shortest_path_nodes": [
        "device:dev-ws-101",
        "server:srv-app-01",
        "server:srv-db-01",
        "critical:crit-db-financial"
      ],
      "reachability_status": "EXPOSED"
    },
    {
      "asset_id": "critical:crit-pii-customer",
      "name": "Customer PII & Identity Master Database",
      "category": "CUSTOMER_PII",
      "impact_score": 90,
      "hop_depth": 3,
      "shortest_path_nodes": [
        "device:dev-ws-101",
        "server:srv-app-01",
        "server:srv-db-01",
        "critical:crit-pii-customer"
      ],
      "reachability_status": "EXPOSED"
    },
    {
      "asset_id": "critical:crit-ad-domain-root",
      "name": "Active Directory Domain Controller Enterprise Root",
      "category": "DOMAIN_CONTROLLER",
      "impact_score": 100,
      "hop_depth": 3,
      "shortest_path_nodes": [
        "device:dev-ws-101",
        "server:srv-app-01",
        "server:srv-dc-01",
        "critical:crit-ad-domain-root"
      ],
      "reachability_status": "EXPOSED"
    }
  ],
  "subgraph_nodes": [ ... ],
  "subgraph_edges": [ ... ],
  "summary_assessment": "Compromise of ws-fin-101.corp (device:dev-ws-101) exposes 8 reachable entities within 3 outgoing hops (Hop 1: 1, Hop 2: 4, Hop 3: 3). Evidence basis: 7 observed connections, 1 hypothetical exploit vectors. CRITICAL ASSETS AT RISK (3): Customer Financial Ledger & Payment Vault (hop 3, impact 95); Customer PII & Identity Master Database (hop 3, impact 90); Active Directory Domain Controller Enterprise Root (hop 3, impact 100). Immediate containment or credential rotation recommended."
}
```

### 4.2 `POST /api/v1/graphops/blast-radius`
Calculates blast radius via JSON payload matching `BlastRadiusRequest`.

### 4.3 Diagnostic Error Handling
- **404 Not Found**: Start node does not exist in graph (`NodeNotFoundError`).
- **422 Unprocessable Content**: Validation errors (`max_hops < 1` or `max_hops > 3`, invalid relationship filter).
- **503 Service Unavailable**: Graph database offline (`GraphOpsConnectionError`).

---

## 5. Verification and Test Results

### Dedicated Test Suite: `tests/test_blast_radius.py`
| Test Case | Description | Result |
| :--- | :--- | :---: |
| `test_blast_radius_one_hop_outgoing` | Verifies `max_hops=1` returns direct neighbors only, leaving hops 2 & 3 empty | **PASSED** |
| `test_blast_radius_two_hops_outgoing` | Verifies `max_hops=2` reaches intermediate pivot servers | **PASSED** |
| `test_blast_radius_three_hops_outgoing_critical_assets` | Verifies `max_hops=3` reaches Crown Jewels and extracts shortest paths | **PASSED** |
| `test_blast_radius_direction_incoming` | Verifies `INCOMING` traversal discovers upstream source workstations | **PASSED** |
| `test_blast_radius_direction_both` | Verifies `BOTH` expands bidirectional neighborhood | **PASSED** |
| `test_blast_radius_cycles_and_no_infinite_loop` | Tests cycle ($A \rightarrow B \rightarrow C \rightarrow A$) termination without duplicate visits | **PASSED** |
| `test_blast_radius_multiple_paths_minimum_distance` | Direct vs indirect path verifies minimum distance preservation in `hop_1` | **PASSED** |
| `test_blast_radius_disconnected_node` | Disconnected node returns 0 reachable nodes and empty hop groups safely | **PASSED** |
| `test_blast_radius_nonexistent_node_raises_error` | Missing start node raises `NodeNotFoundError` with actionable message | **PASSED** |
| `test_blast_radius_relationship_type_filtering` | Restricts traversal strictly to specified `allowed_relationship_types` | **PASSED** |
| `test_blast_radius_hypothetical_edge_handling` | Confirms `POTENTIAL_EXPLOIT` edges are pruned when `include_hypothetical=False` | **PASSED** |
| `test_fastapi_blast_radius_get_endpoint` | End-to-end `GET /api/v1/graphops/blast-radius` with query params | **PASSED** |
| `test_fastapi_blast_radius_post_endpoint` | End-to-end `POST /api/v1/graphops/blast-radius` with JSON body | **PASSED** |
| `test_fastapi_blast_radius_not_found_returns_404` | FastAPI 404 response verification for unknown entities | **PASSED** |
| `test_fastapi_blast_radius_invalid_filter_returns_422`| FastAPI 422 validation for invalid relationship filter strings | **PASSED** |

### Complete Regression Baseline Verification
- **Total Pytest Suite**: 82 passed, 0 failed in 2.94s.
- **Standalone Integration Suites**:
  - `tests/test_attack_graph.py`: 12/12 passed (Attack graph, relay hopping, campaigns, clustering).
  - `tests/test_threat_intelligence.py`: 12/12 passed (AbuseIPDB, VirusTotal, private IP scopes, caching).
- **Regression Status**: Zero regressions across all prior modules.
