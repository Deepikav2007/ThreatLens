# ThreatLens GraphOps — Phase 7: GraphOps Interface & What-If Containment

## 1. Executive Summary

Phase 7 of the ThreatLens GraphOps architecture integrates enterprise graph analytics and proactive containment simulation into the existing ThreatLens cybersecurity platform.

This phase provides security analysts with an intuitive, unified investigation workspace for:
1. **Multi-Hop Blast-Radius Visualization:** Distinct visual tiers for 1-hop, 2-hop, and 3-hop lateral spread from any compromised entity.
2. **Deep Evidence & Provenance Inspection:** Real-time inspection of node identities, permissions, network flows, and CVE exploit preconditions.
3. **Attack-Path & Choke-Point Discovery:** Identification of lateral access routes to critical enterprise Crown Jewels and ranking of strategic choke points.
4. **Safe What-If Containment Simulation:** In-memory recalculation of attack pathways under proposed containment interventions with zero production graph mutation.
5. **Case-to-Organization Evidence Bridging:** Direct correlation between email incident dossiers (e.g., Case `MT-101`) and corporate directory entities (`user:usr-101`, `device:dev-ws-101`) while quarantining external adversary IOCs outside internal boundaries.

---

## 2. Interface Architecture & Technology Adherence

The implementation strictly respects all project constraints and preserves existing features:
- **Zero Framework Rewrites:** Built entirely with vanilla JavaScript (ES6+), semantic HTML5, and pure CSS.
- **Cytoscape.js Integration:** Leverages the existing Cytoscape.js engine (`cose` spring embedder layout, dynamic zooming, canvas fitting, and re-layout).
- **No Embedded Credentials:** Frontend communicates strictly with sanitized FastAPI endpoints (`/api/v1/graphops/*`); no Neo4j credentials or direct Bolt ports are exposed.
- **Backward Compatibility:** All existing ThreatLens pages (Dashboard, Email Analysis, Investigation Cases Repository, Case Detail Workspace, Threat Intelligence Hub, Attack Graph, Reports, Evidence Ledger) operate unchanged with 100% test pass rates.

---

## 3. Cytoscape.js Visual Encoding Schema

The GraphOps workspace utilizes an accessible visual color palette to clearly communicate entity criticality and traversal distance:

| Entity / Element Type | Cytoscape Visual Representation | Color Code | Shape / Dimensions | Rationale |
|:---|:---|:---|:---|:---|
| **Root Compromised Node** | Glowing cyan halo, thick border | `#38bdf8` / `#7dd3fc` | Circle, 52px | Immediately draws analyst focus to point of origin |
| **Hop 1 Neighborhood** | Emerald green fill | `#10b981` / `#34d399` | Circle, 42px | Direct, immediate lateral spread |
| **Hop 2 Neighborhood** | Amber fill | `#f59e0b` / `#fbbf24` | Circle, 38px | Intermediate pivot scope |
| **Hop 3 Neighborhood** | Indigo fill | `#6366f1` / `#818cf8` | Circle, 34px | Boundary tier reachable within enterprise perimeter |
| **Crown Jewels / Critical Assets** | Crimson with gold double border | `#ef4444` / `#fbbf24` | Diamond, 52px | Highest priority assets requiring proactive defense |
| **Observed Relationship** | Solid sky-blue directed edge | `#38bdf8` | Bezier, width 2.5px | Verified firewall NetFlow or Active Directory record |
| **Authorized Access / Privilege** | Solid blue directed edge | `#3b82f6` | Bezier, width 2.0px | Verified LDAP group, IAM role, or CMDB grant |
| **Hypothetical Exploit Edge** | Dashed amber directed edge | `#f59e0b` | Dashed [6, 4], width 2.0px | CVE precondition (e.g. CVE-2024-21413 Moniker Link) |
| **Highlighted Attack Path** | Glowing crimson edge | `#ef4444` | Bezier, width 4.0px | Active route traversing towards a target Crown Jewel |
| **Severed Simulation Element** | Faded dashed crimson with 0.35 opacity | `#ef4444` | Dashed [4, 4], opacity 0.35 | Visually represents proposed intervention in What-If mode |

---

## 4. Workspaces & Interactive Features

### 4.1 Mode 1: Blast Radius Propagation
- **Entity Selection:** Choose from known directory presets (Alice Vance, Workstations DEV-WS-101/102, Server SRV-APP-01, Bob Martinez) or input any canonical ID.
- **Configurable Parameters:** Hop depth (1, 2, or 3 hops), traversal direction (`OUTGOING` lateral spread, `INCOMING` origin trace, `BOTH` full boundary), and optional inclusion of hypothetical CVE exploits.
- **Computed Analytics:**
  - Real-time counters for Hop 1, Hop 2, and Hop 3 reachable nodes.
  - Critical Assets at Risk panel highlighting reachable Crown Jewels and distinguishing direct privilege from lateral pivoting.
  - Dynamic choke points table ranking intermediate intersection nodes.

### 4.2 Mode 2: Attack Paths & Choke Points
- **Target Filtering:** Evaluate pathways leading to all Crown Jewels or focus on a specific critical asset (`critical:crit-db-financial`, `critical:crit-pii-customer`, `critical:crit-ad-domain-root`).
- **Path Highlighting:** Renders candidate acyclic attack paths on the graph canvas and displays path risk score and step assumptions.
- **Strategic Choke Points Table:**
  - Ranked by betweenness centrality (percentage of candidate attack paths eliminated).
  - One-click **"Simulate &rarr;"** action button that transfers the candidate choke point directly into the What-If simulator.

### 4.3 Mode 3: What-If Containment Simulator
- **Safe In-Memory Projection:** Evaluates interventions strictly against transient path calculations without mutating the production Neo4j graph (`live_graph_modified: false`).
- **Supported Interventions:**
  - `ISOLATE_NODE`: Severs all inbound and outbound edges from a compromised host (e.g. `server:srv-app-01`).
  - `BLOCK_CONNECTION`: Severs a specific network connection between source and target hosts (e.g. `server:srv-app-01 -> server:srv-db-01`).
  - `REVOKE_PERMISSION`: Simulates revoking an administrative or user IAM privilege.
- **Before-and-After Comparison Panel:**
  - Baseline paths count vs. remaining active paths.
  - Exact count of eliminated pathways and containment efficiency percentage.
  - Analyst containment verdict: `FULL_CONTAINMENT` (all paths eliminated) or `PARTIAL_CONTAINMENT` (reduction percentage and remaining exposure).
  - Canvas update showing severed entities as dimmed and dashed red.
  - Dedicated **"Reset Simulation"** button restoring the baseline topology.

### 4.4 Forensic Case Bridge
- Correlates recipient evidence from email forensic cases (e.g., Case `MT-101` with recipient `victim1@corporation.com`) to Active Directory entities:
  - Mapped Primary Entity: `user:usr-101` (Alice Vance)
  - Mapped Device: `device:dev-ws-101` (Assigned Workstation)
- **External IOC Quarantine:** External threat infrastructure (`185.190.140.22`, `alert-center.xyz`) is explicitly isolated from internal directory entities and flagged as external adversary infrastructure.
- One-click navigation link from Case Detail header (`GraphOps Workspace &rarr;`) immediately opens the GraphOps workspace prefilled with the victim's identity.

---

## 5. Backend Endpoints Summary (Phase 7)

| HTTP Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/api/v1/graphops/simulate-containment` | Executes safe in-memory What-If containment simulation against proposed interventions. |
| `GET` | `/api/v1/graphops/bridge/case/{case_id}` | Bridges email forensic evidence to corporate graph entities with external IOC quarantine. |
| `GET` | `/api/v1/graphops/blast-radius` | Calculates multi-hop blast radius neighborhoods with hop distribution. |
| `POST` | `/api/v1/graphops/attack-paths` | Discovers bounded acyclic lateral movement paths to Crown Jewels. |
| `GET` / `POST` | `/api/v1/graphops/choke-points` | Identifies and ranks strategic choke points by path elimination efficacy. |
| `POST` | `/api/v1/graphops/ingest/sample` | Synchronizes synthetic SOC enterprise fixture into Neo4j idempotently. |
| `GET` | `/api/v1/graphops/health` | Sanitized database connectivity status (never leaks credentials). |

---

## 6. Test Verification & Results

A comprehensive test suite of 9 new Phase 7 integration and UI contract tests was executed alongside the existing baseline:

```
tests/test_graphops_phase7.py::TestWhatIfContainmentSimulation::test_simulation_does_not_modify_live_graph PASSED
tests/test_graphops_phase7.py::TestWhatIfContainmentSimulation::test_simulation_full_containment_of_gateway PASSED
tests/test_graphops_phase7.py::TestWhatIfContainmentSimulation::test_simulation_partial_containment_relationship PASSED
tests/test_graphops_phase7.py::TestCaseBridgeResolution::test_bridge_correlates_email_case_to_user_and_device PASSED
tests/test_graphops_phase7.py::TestGraphOpsPhase7APIEndpoints::test_api_simulate_containment_endpoint PASSED
tests/test_graphops_phase7.py::TestGraphOpsPhase7APIEndpoints::test_api_simulate_containment_404_entry_node PASSED
tests/test_graphops_phase7.py::TestGraphOpsPhase7APIEndpoints::test_api_case_bridge_endpoint PASSED
tests/test_graphops_phase7.py::TestFrontendUIContract::test_html_contains_graphops_workspace_and_components PASSED
tests/test_graphops_phase7.py::TestFrontendUIContract::test_js_app_contains_graphops_functions PASSED

============================== 104 passed in 2.81s ==============================
```

All 104 automated tests pass cleanly with zero regressions on existing ThreatLens features.
