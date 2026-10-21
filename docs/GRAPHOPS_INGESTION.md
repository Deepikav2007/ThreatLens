# ThreatLens GraphOps — Phase 4: Graph Data Ingestion and Construction

## 1. Executive Summary

Phase 4 implements a reproducible, validated, and fully idempotent ingestion engine that imports realistic, explicitly labeled synthetic SOC enterprise security data into Neo4j. It establishes the organizational security graph necessary for proactive threat hunting, attack path analysis (Phase 5), choke-point identification (Phase 6), and blast-radius containment simulation (Phase 7).

### Key Architectural Commitments Enforced
- **Strict Simulation Labeling**: All synthetic records carry explicit simulation markers (`SIMULATED_SOC_ENTERPRISE_FIXTURE`, `SIMULATED_ACTIVE_DIRECTORY`, `SIMULATED_EDR_INVENTORY`, etc.) and are never represented as live customer data.
- **No Manufactured Relationships**: Missing nodes or dangling references are strictly rejected with actionable diagnostic errors; phantom nodes are never fabricated to make the graph look connected.
- **Strict Evidence Categorization**: Relationships are categorized into distinct evidence tiers (`OBSERVED`, `AUTHORIZED_ACCESS`, `INFERRED`, `HYPOTHETICAL`). Network connections are not conflated with authorized permissions.
- **Parameterized & Batched Cypher**: All write transactions use bounded batching (`BATCH_SIZE = 50`) and parameterized `UNWIND $batch` constructs. No raw Cypher query interpolation is permitted.
- **Complete Idempotency**: Repeated imports update properties via `MERGE ... ON CREATE / ON MATCH` without duplicating entities or edges.
- **Zero Regression**: Preserves all existing ThreatLens capabilities, persistence stores, and test baselines.

---

## 2. Ingestion Pipeline Architecture

```
+-------------------------------------------------------------+
|    Synthetic Fixture: sample_enterprise_graph.json          |
|    (Users, Devices, Servers, Apps, IPs, Vulns, Jewels)     |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|               GraphOpsIngestionEngine                       |
|               (backend/graphops/ingest.py)                  |
+-------------------------------------------------------------+
| 1. Schema Init: Ensure unique constraints on n.id           |
| 2. Pre-fetch existing Node IDs & Email Aliases              |
| 3. Entity Validation: Pydantic v2 strict models             |
| 4. Node Ingestion: Parameterized MERGE (Batch = 50)         |
| 5. Reference Resolution: Check src & tgt against known IDs  |
| 6. Edge Ingestion: Parameterized MERGE (Batch = 50)         |
| 7. Summary & Error Diagnostics: Actionable failure logs     |
+-------------------------------------------------------------+
         |                                           |
         v                                           v
+-----------------------------+          +--------------------+
|  Neo4j Database Engine      |          |  CLI / REST API    |
|  (Organizational Graph)     |          |  (Summary Metrics) |
+-----------------------------+          +--------------------+
```

---

## 3. Synthetic Enterprise Dataset Specifications

Location: `backend/data/fixtures/sample_enterprise_graph.json`  
Loader: `backend/data/graphops_fixtures.py::load_sample_enterprise_fixture()`

### Entity Inventory (30 Nodes)
| Node Label | Count | Sample Identifiers | Critical Roles / Attributes |
| :--- | :---: | :--- | :--- |
| `User` | 6 | `user:usr-101`, `user:usr-102`, `user:usr-103`, `user:usr-201`, `user:svc-backup`, `user:usr-999` | Finance Analyst, IT Helpdesk Tier 2, DevOps Engineer, Controller, Backup Service Principal, CEO |
| `Device` | 4 | `device:dev-ws-101`, `device:dev-ws-102`, `device:dev-ws-103`, `device:dev-ws-201` | Workstations in subnet `10.0.1.0/24` with MAC and OS metadata |
| `Server` | 4 | `server:srv-app-01`, `server:srv-db-01`, `server:srv-dc-01`, `server:srv-backup-01` | Application Jump Server, Customer DB Cluster, Active Directory DC, Backup Server |
| `Application` | 3 | `app:app-erp-01`, `app:app-ad-01`, `app:app-pg-01` | Financial ERP (Port 443), Active Directory (Port 389), PostgreSQL (Port 5432) |
| `IpAddress` | 6 | `ip:10.0.1.101`, `ip:10.0.1.102`, `ip:10.0.1.103`, `ip:10.0.2.10`, `ip:10.0.3.50`, `ip:10.0.0.5` | Internal monitored IPv4 addresses across core corporate subnets |
| `Vulnerability`| 3 | `vuln:CVE-2024-21413`, `vuln:CVE-2023-38606`, `vuln:CVE-2023-44487` | CVSS 9.8 Outlook Moniker Link RCE, Linux Kernel LPE, HTTP/2 Rapid Reset |
| `CriticalAsset`| 3 | `critical:crit-db-financial`, `critical:crit-ad-domain-root`, `critical:crit-pii-customer` | Crown Jewels: Ledger & Payment Vault (Score 95), AD Root (Score 100), PII DB (Score 90) |
| `SecurityEvent`| 1 | `event:evt-mt101-phish` | Linked to RFC 822 forensic investigation Case `MT-101` |

### Strategic Graph Topology & Choke Points
- **Entry Points**: Phishing victim Alice Vance (`user:usr-101`) uses workstation `dev-ws-101`.
- **Choke Point (`server:srv-app-01`)**: The Application Gateway is the single pivot server connecting corporate workstations to both the Database Host (`server:srv-db-01`) and Domain Controller (`server:srv-dc-01`).
- **High-Value Targets (Crown Jewels)**:
  - `server:srv-db-01` contains `critical:crit-db-financial` and `critical:crit-pii-customer`.
  - `server:srv-dc-01` contains `critical:crit-ad-domain-root`.
- **Hypothetical Attack Path**: Workstation `dev-ws-101` has a `POTENTIAL_EXPLOIT` relationship to `server:srv-app-01` exploiting `vuln:CVE-2024-21413`.

### Relationship Inventory (20 Edges)
| Relationship Type | Direction | Evidence Class | Count | Description |
| :--- | :--- | :--- | :---: | :--- |
| `USES` | User -> Device | `OBSERVED` | 4 | Physical / virtual device assignment |
| `OBSERVED_CONNECTION` | Device/Server -> Server | `OBSERVED` | 4 | Actual NetFlow / firewall communication records |
| `HAS_PERMISSION` | User -> Server | `AUTHORIZED_ACCESS` | 3 | AD group / DB role authorization grants |
| `LOGGED_IN_TO` | User -> Server | `OBSERVED` | 1 | Windows Event ID 4624 remote interactive logon |
| `HOSTS` | Server -> Application | `OBSERVED` | 3 | Server hosting service process |
| `CONTAINS_CRITICAL_DATA`| Server -> CriticalAsset | `OBSERVED` | 3 | Server hosting designated crown jewel assets |
| `HAS_VULNERABILITY` | Server -> Vulnerability | `OBSERVED` | 1 | Vulnerability scanner finding |
| `POTENTIAL_EXPLOIT` | Device -> Server | `HYPOTHETICAL` | 1 | Modeled attack path vector via CVE-2024-21413 |
| `ASSOCIATED_WITH_CASE` | User -> SecurityEvent | `OBSERVED` | 1 | Forensic case correlation |

---

## 4. Ingestion Engine Implementation

### Module: `backend/graphops/ingest.py`

#### 1. Entity Validation (`validate_entity`)
Validates input JSON objects against typed Pydantic models ([`backend/models/graphops.py`](file:///d:/Desktop/Hackathon/ThreatLens/backend/models/graphops.py)).
- Applies canonical ID prefixes (e.g., `user:usr-101`, `server:srv-app-01`).
- Maps type-specific attributes (`is_admin`, `criticality`, `cvss_score`, `impact_score`).
- Produces actionable error descriptions upon validation failures rather than silent drops.

#### 2. Alias Resolution & Reference Validation (`validate_relationship`)
- Enterprise relationships frequently reference users by email address (`user:victim1@corporation.com`) or raw IDs (`user:usr-101`).
- The engine automatically indexes aliases during node ingestion and resolves them transparently before relationship validation.
- Normalizes vulnerability references (e.g. `vuln:cve-2024-21413` -> `vuln:CVE-2024-21413`).
- **Missing Reference Rejection**: If source or target ID cannot be resolved to a known node, the relationship is rejected with an actionable diagnostic message:
  ```
  Unresolved relationship reference: target_id 'server:nonexistent-host' does not exist.
  ```

#### 3. Bounded Batch Transactions & Parameterized Queries
Operations are batched in groups of `BATCH_SIZE = 50` using Cypher's `UNWIND $batch AS item`:
```cypher
UNWIND $batch AS item
MERGE (n:Server {id: item.id})
ON CREATE SET n += item.properties, n.created_at = $timestamp
ON MATCH SET n += item.properties, n.updated_at = $timestamp
```
For relationships:
```cypher
UNWIND $batch AS rel
MATCH (s {id: rel.source_id})
MATCH (t {id: rel.target_id})
MERGE (s)-[r:OBSERVED_CONNECTION]->(t)
ON CREATE SET r += rel.properties, r.created_at = $timestamp
ON MATCH SET r += rel.properties, r.updated_at = $timestamp
```

---

## 5. Execution Interfaces

### 1. Development CLI Runner
Execute sample ingestion from the command line:
```bash
python -m backend.graphops.ingest
```
Output:
```json
{
  "status": "SUCCESS",
  "dataset_name": "simulated_soc_enterprise_fixture_v1",
  "nodes_imported": 30,
  "nodes_updated": 0,
  "nodes_rejected": 0,
  "relationships_imported": 20,
  "relationships_updated": 0,
  "relationships_rejected": 0,
  "errors": [],
  "timestamp": "2026-10-20T07:25:00.000000+00:00"
}
```

### 2. REST API Endpoints

#### Ingest Sample Fixture
- **Route**: `POST /api/v1/graphops/ingest/sample`
- **Description**: Loads the curated synthetic enterprise fixture into Neo4j.
- **Response**: `IngestSummaryResponse` with imported/updated counts.

#### Ingest Custom Bulk Payload
- **Route**: `POST /api/v1/graphops/ingest/bulk`
- **Request Body**: `BulkIngestPayload`
- **Response**: `IngestSummaryResponse`

#### Query Graph Topology Summary
- **Route**: `GET /api/v1/graphops/summary`
- **Response**:
```json
{
  "total_nodes": 30,
  "total_relationships": 20,
  "node_counts_by_label": {
    "User": 6,
    "IpAddress": 6,
    "Device": 4,
    "Server": 4,
    "Application": 3,
    "Vulnerability": 3,
    "CriticalAsset": 3,
    "SecurityEvent": 1
  },
  "relationship_counts_by_type": {
    "USES": 4,
    "OBSERVED_CONNECTION": 4,
    "HAS_PERMISSION": 3,
    "HOSTS": 3,
    "CONTAINS_CRITICAL_DATA": 3,
    "LOGGED_IN_TO": 1,
    "HAS_VULNERABILITY": 1,
    "POTENTIAL_EXPLOIT": 1,
    "ASSOCIATED_WITH_CASE": 1
  },
  "critical_assets": [
    { "id": "critical:crit-db-financial", "name": "Customer Financial Ledger & Payment Vault", "impact": 95, "category": "FINANCIAL_RECORDS" },
    { "id": "critical:crit-ad-domain-root", "name": "Active Directory Domain Controller Enterprise Root", "impact": 100, "category": "DOMAIN_CONTROLLER" },
    { "id": "critical:crit-pii-customer", "name": "Customer PII & Identity Master Database", "impact": 90, "category": "CUSTOMER_PII" }
  ],
  "status": "POPULATED"
}
```

---

## 6. Test Suite and Regression Validation

### Ingestion Test Coverage: `tests/test_graphops_ingest.py`
| Test Case | Description | Result |
| :--- | :--- | :---: |
| `test_load_sample_enterprise_fixture_structure` | Verifies JSON fixture loads with all required node types, relationship types, and disclaimer | **PASSED** |
| `test_entity_validation_success` | Validates valid node models (User, Server, Vulnerability, CriticalAsset) | **PASSED** |
| `test_entity_validation_actionable_errors` | Confirms invalid fields (e.g. invalid CVSS score, missing ID) yield actionable error messages | **PASSED** |
| `test_relationship_validation_missing_endpoints` | Confirms missing endpoints are rejected and NOT silently manufactured | **PASSED** |
| `test_ingest_payload_idempotency` | Validates initial import creates nodes, second import updates nodes via `MERGE` | **PASSED** |
| `test_ingest_sample_fixture_workflow` | Validates full synthetic fixture ingestion flow against mock client | **PASSED** |
| `test_get_graph_summary` | Verifies aggregate node/edge count queries and Crown Jewels extraction | **PASSED** |
| `test_fastapi_ingest_sample_and_summary_endpoints` | Tests FastAPI routes `/ingest/sample`, `/ingest/bulk`, and `/summary` | **PASSED** |

### Complete Regression Verification
- **Pytest Suite**: 67 passed, 0 failed (2.96s).
- **Standalone Integration Tests**:
  - `tests/test_attack_graph.py`: 12/12 passed (Attack graph, relay hopping, campaigns, clustering).
  - `tests/test_threat_intelligence.py`: 12/12 passed (AbuseIPDB, VirusTotal, caching, scopes).
- **Regression Status**: 100% clean baseline preserved.
