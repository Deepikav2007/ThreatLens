# ThreatLens GraphOps — Phase 6: Attack-Path Discovery and Choke-Point Analysis

## 1. Executive Summary

Phase 6 implements the **Attack-Path Discovery & Choke-Point Analytics Engine** (`backend/graphops/attack_paths.py`) for the ThreatLens GraphOps platform. It allows SOC analysts and proactive threat hunters to:
1. Discover plausible lateral movement routes from designated entry points (compromised user credentials or workstations) to high-value Crown Jewels.
2. Evaluate and rank attack paths using a transparent, explainable **Risk-Cost Model**.
3. Identify strategic **Graph Choke Points** whose remediation eliminates the maximum percentage of candidate attack vectors.
4. Simulate proposed containment interventions strictly in memory without modifying persistent graph data.

### Key Architectural Commitments Enforced
- **Path-Eligible Relationships Only**: Graph traversal only proceeds across documented lateral movement relationships (`USES`, `LOGGED_IN_TO`, `OBSERVED_CONNECTION`, `HAS_PERMISSION`, `HOSTS`, `CONTAINS_CRITICAL_DATA`, `POTENTIAL_EXPLOIT`, `RUNS_ON`). Non-routable leaf edges (such as `HAS_VULNERABILITY` and `ASSOCIATED_WITH_CASE`) are strictly excluded.
- **Path Explosion Prevention**: Traversal length is bounded ($1 \le \text{depth} \le 8$, default 5) and path result counts are capped at `MAX_PATHS_LIMIT = 50`.
- **Acyclic Simple Paths**: Candidate paths cannot revisit previously traversed nodes, preventing infinite loops on graph cycles.
- **Evidence-Grounded Risk Scoring**: Risk scoring combines target asset impact (55%), step feasibility based on evidence certainty (45%), and hop-length friction penalties. Missing risk factors are explicitly marked as unknown rather than assigned arbitrary weights.
- **Preservation of Alternative Routes**: Choke-point analysis accounts for the exact paths that depend on a candidate, explicitly noting when alternative pathways to critical assets remain active.
- **Zero Graph Mutation**: Read-only Cypher and in-memory simulation. Live permissions and configurations are never modified.

---

## 2. Attack-Path Traversal Architecture

```
+-------------------------------------------------------------+
|    Entry Point (e.g., device:dev-ws-101 or user:usr-101)    |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|               AttackPathService                             |
|               (backend/graphops/attack_paths.py)            |
+-------------------------------------------------------------+
| 1. Entry & Crown Jewel Target Resolution                    |
| 2. Bounded Acyclic Graph Search (Depth <= 5, Limit <= 50)   |
| 3. Step Feasibility & Technical Assumption Generation       |
| 4. Risk-Cost Scoring: Target Impact + Feasibility - Hop Pen |
| 5. Choke-Point Analyzer: Path Betweenness Centrality        |
| 6. Simulation Interface: In-memory disabled node/edge filter |
+-------------------------------------------------------------+
         |                                           |
         v                                           v
+-----------------------------+          +--------------------+
|  Neo4j Read-Only Execution  |          |  FastAPI Endpoints |
|  (Parameterized Cypher)     |          |  POST attack-paths |
|                             |          |  GET/POST choke    |
+-----------------------------+          +--------------------+
```

---

## 3. Path-Eligible Relationship Rules

| Relationship Type | Direction | Path Eligibility | Rationale |
| :--- | :---: | :---: | :--- |
| `USES` | User $\rightarrow$ Device | **ELIGIBLE** | Compromised user credentials allow initial session access on assigned device. |
| `LOGGED_IN_TO` | User/Device $\rightarrow$ Server | **ELIGIBLE** | Active logon session allows credential dumping or token impersonation. |
| `OBSERVED_CONNECTION` | Device/Server $\rightarrow$ Server | **ELIGIBLE** | Active network flow confirms route is routable and permitted by firewall. |
| `HAS_PERMISSION` | User $\rightarrow$ Server/Asset | **ELIGIBLE** | Granted directory role or database user privilege allows authorized access. |
| `HOSTS` | Server $\rightarrow$ App/Asset | **ELIGIBLE** | Access to host operating system implies direct access to hosted application. |
| `CONTAINS_CRITICAL_DATA`| Server $\rightarrow$ CriticalAsset | **ELIGIBLE** | Direct storage of Crown Jewel repository on server infrastructure. |
| `POTENTIAL_EXPLOIT` | Device/Server $\rightarrow$ Server | **ELIGIBLE** *(Hypothetical)* | Modeled exploit vector leveraging a verified CVE (e.g. Outlook Moniker Link RCE). |
| `RUNS_ON` | App $\rightarrow$ Server | **ELIGIBLE** | Reverse hosting dependency. |
| `HAS_VULNERABILITY` | Any $\rightarrow$ Vulnerability | **EXCLUDED** | Leaf node. Vulnerabilities exist *on* assets; attackers do not pivot *through* CVE nodes. |
| `ASSOCIATED_WITH_CASE` | Any $\rightarrow$ SecurityEvent | **EXCLUDED** | Leaf node. Audit references cannot be routed through as network hops. |

---

## 4. Explainable Risk-Cost Model

The composite risk score $R(P) \in [5, 100]$ for path $P = (n_0, e_1, n_1, \dots, e_k, n_k)$ is defined as:

$$R(P) = \max\left(5, \min\left(100, \left\lfloor I(n_k) \times 0.55 + \bar{F}(P) \times 0.45 - (k - 1) \times 3 \right\rfloor\right)\right)$$

### Components
1. **Target Business Impact $I(n_k)$**:
   - Extracted directly from `impact_score` of the destination Crown Jewel (e.g., Financial DB = 95, AD Root = 100, PII DB = 90).
   - If missing, marked as unknown and defaulted to 75.
2. **Mean Step Feasibility $\bar{F}(P)$**:
   - `OBSERVED`: **90** (live observed NetFlow or interactive logon confirms zero pivot friction).
   - `AUTHORIZED_ACCESS`: **80** (valid entitlement exists in directory; requires credential possession).
   - `INFERRED`: **60** (heuristic proximity).
   - `HYPOTHETICAL`: If via known CVE, $\min(100, \text{cvss} \times 10) + (5 \text{ if exploit available})$; if unknown, **50** (marked as unconfirmed).
3. **Hop Length Friction Penalty**:
   - $(k - 1) \times 3$ points subtracted per additional hop beyond 1, reflecting increased detection risk and lateral movement friction.
4. **Explicit Technical Assumptions**:
   - Every transition generates an actionable SOC assumption explaining what condition the adversary must satisfy to traverse that step.

---

## 5. Strategic Choke-Point Analysis

Given the set of candidate attack paths $\mathcal{P} = \{P_1, \dots, P_m\}$, intermediate entities (servers or edges) are evaluated for betweenness path intersection:

1. **Paths Traversed Count**: $k(e) = |\{ P \in \mathcal{P} \mid e \in P \}|$
2. **Traversal Percentage**: $\text{pct}(e) = \frac{k(e)}{|\mathcal{P}|} \times 100\%$
3. **Protected Crown Jewels**: $\text{assets}(e) = \{ P.\text{target\_name} \mid e \in P \}$
4. **Recommended Action**:
   - Server node: `ISOLATE_NODE`
   - Network flow edge: `BLOCK_CONNECTION`
   - Permission edge: `REVOKE_PERMISSION`
   - Exploit edge: `PATCH_VULNERABILITY`

### Primary Choke Point in Sample Fixture
In the synthetic enterprise graph, `server:srv-app-01` serves as the exclusive jump server between corporate workstations (`DEV-WS-101`, `DEV-WS-102`) and core databases:
- **Paths Traversed**: 100% of workstation lateral movement vectors.
- **Affected Assets**: Financial Ledger, Customer PII, Active Directory Root.
- **Recommended Action**: `ISOLATE_NODE` on `server:srv-app-01`.

---

## 6. Simulation-Friendly Interface

The service exposes `simulate_containment_impact(...)`:
```python
sim_impact = service.simulate_containment_impact(
    entry_node_id="device:dev-ws-101",
    target_asset_ids=None,
    disabled_node_ids={"server:srv-app-01"},
    disabled_edge_keys=set(),
)
```
- **In-Memory Traversal Filtering**: Evaluates path reduction by excluding disabled nodes or edges on the fly.
- **Zero Persistent Modification**: Does not alter Neo4j records, constraints, or configurations.
- **Alternative Path Integrity**: If alternative routes exist (e.g. backup operators reaching domain controllers through separate channels), the simulation reports `PARTIAL_CONTAINMENT` and identifies the remaining pathways.

---

## 7. REST API Endpoints

### 7.1 `POST /api/v1/graphops/attack-paths`
Discovers bounded attack paths from an entry point to critical assets.

#### Request Body (`AttackPathRequest`)
```json
{
  "entry_node_id": "device:dev-ws-101",
  "target_node_ids": ["critical:crit-db-financial"],
  "max_depth": 5,
  "include_hypothetical": true
}
```

#### Response (`AttackPathResult`)
```json
{
  "entry_node": { "id": "device:dev-ws-101", "label": "Device", "name": "ws-fin-101.corp" },
  "total_paths_discovered": 2,
  "paths": [
    {
      "path_id": "PATH-001",
      "target_id": "critical:crit-db-financial",
      "target_name": "Customer Financial Ledger & Payment Vault",
      "length": 3,
      "risk_score": 86,
      "nodes": [ ... ],
      "steps": [
        {
          "step_number": 1,
          "source_id": "device:dev-ws-101",
          "target_id": "server:srv-app-01",
          "relationship_type": "OBSERVED_CONNECTION",
          "evidence_class": "OBSERVED",
          "description": "Observed network traffic from device:dev-ws-101 to server:srv-app-01 (Port 443/TCP)."
        },
        {
          "step_number": 2,
          "source_id": "server:srv-app-01",
          "target_id": "server:srv-db-01",
          "relationship_type": "OBSERVED_CONNECTION",
          "evidence_class": "OBSERVED",
          "description": "Observed network traffic from server:srv-app-01 to server:srv-db-01 (Port 5432/TCP)."
        },
        {
          "step_number": 3,
          "source_id": "server:srv-db-01",
          "target_id": "critical:crit-db-financial",
          "relationship_type": "CONTAINS_CRITICAL_DATA",
          "evidence_class": "OBSERVED",
          "description": "Database/host stores designated Crown Jewel repository critical:crit-db-financial."
        }
      ],
      "observed_steps_count": 3,
      "hypothetical_steps_count": 0,
      "assumptions": [
        "Step 1: Assumes on port 443 on server:srv-app-01 is accessible from device:dev-ws-101.",
        "Step 2: Assumes on port 5432 on server:srv-db-01 is accessible from server:srv-app-01."
      ]
    }
  ],
  "targets_reached": ["critical:crit-db-financial"]
}
```

### 7.2 `GET /api/v1/graphops/choke-points`
Query-based endpoint returning top ranked choke points across candidate attack paths.

### 7.3 `POST /api/v1/graphops/choke-points`
Body-based endpoint accepting `ChokePointRequest`.

---

## 8. Verification and Regression Testing

### Test Suite: `tests/test_attack_paths.py`
| Test Case | Description | Result |
| :--- | :--- | :---: |
| `test_attack_paths_discovery_known_path` | Discovers 3-hop path from WS-101 to Financial DB via jump server | **PASSED** |
| `test_attack_paths_unreachable_target` | Returns 0 paths cleanly when target is isolated or unreachable | **PASSED** |
| `test_attack_paths_cycles_prevention` | Tests cycle ($A \rightarrow B \rightarrow C \rightarrow A \rightarrow T$) terminates without repeating nodes | **PASSED** |
| `test_attack_paths_multiple_routes` | Discovers and ranks multiple independent routes to the same Crown Jewel | **PASSED** |
| `test_attack_paths_hypothetical_exclusion`| Confirms `POTENTIAL_EXPLOIT` paths are pruned when `include_hypothetical=False` | **PASSED** |
| `test_attack_paths_risk_ranking_reproducibility` | Verifies deterministic risk ranking prioritizing observed high-impact routes | **PASSED** |
| `test_choke_point_identification_and_ranking` | Verifies `server:srv-app-01` ranks #1 intercepting 100% of workstation paths | **PASSED** |
| `test_simulation_interface_containment_impact` | Proves in-memory isolation eliminates 100% of dependent paths | **PASSED** |
| `test_simulation_interface_alternative_paths_preserved` | Confirms alternative paths remain active and reports partial containment | **PASSED** |
| `test_fastapi_attack_paths_endpoint` | End-to-end `POST /api/v1/graphops/attack-paths` validation | **PASSED** |
| `test_fastapi_choke_points_get_endpoint` | End-to-end `GET /api/v1/graphops/choke-points` validation | **PASSED** |
| `test_fastapi_choke_points_post_endpoint` | End-to-end `POST /api/v1/graphops/choke-points` validation | **PASSED** |
| `test_fastapi_attack_paths_not_found_returns_404` | Nonexistent entry point returns HTTP 404 | **PASSED** |

### Complete Regression Baseline Verification
- **Pytest Suite**: 95 passed, 0 failed in 3.05s.
- **Standalone Integration Suites**:
  - `tests/test_attack_graph.py`: 12/12 passed (Attack graph, relay hopping, campaigns).
  - `tests/test_threat_intelligence.py`: 12/12 passed (AbuseIPDB, VirusTotal, private scopes, caching).
- **Regression Status**: 100% clean baseline preserved across all modules.
