# ThreatLens Phase 1: Repository Audit & Regression Baseline

**Date:** 2026-10-19  
**Platform:** Windows (Python 3.13.15, FastAPI 0.115.11, Pydantic 2.12.5)  
**Corpus / Workspace:** `ThreatLens`  
**Phase:** Phase 1 — Repository Audit & Regression Baseline  

---

## 1. Verified Architecture & Directory Layout

The repository has been thoroughly inspected. The active directory layout is:

```text
ThreatLens/
├── backend/
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py                 # 16 FastAPI endpoint handlers
│   ├── core/
│   │   ├── __init__.py
│   │   └── config.py                 # Scoring weights, thresholds, static paths, API config
│   ├── data/
│   │   ├── __init__.py
│   │   ├── demo_emails.py            # Structured JSON demo fixtures
│   │   └── eml_samples.py            # Raw RFC 822 .eml demo email strings
│   ├── models/
│   │   ├── __init__.py
│   │   ├── explanation.py            # Explainable AI Pydantic models
│   │   ├── forensics.py              # RFC 822 forensic evidence models
│   │   ├── graph.py                  # Case attack graph & campaign models
│   │   ├── intel.py                  # Threat intelligence data contracts
│   │   ├── ioc.py                    # Extracted IOC structures & summaries
│   │   └── threat.py                 # AI threat detection models
│   ├── services/
│   │   ├── __init__.py
│   │   ├── attack_graph.py           # In-memory case graph & campaign builder
│   │   ├── campaign_correlation.py   # Multi-case infrastructure clustering engine
│   │   ├── case_store.py             # Thread-safe in-memory case repository
│   │   ├── email_forensics.py        # RFC 822 MIME parser & relay reconstructor
│   │   ├── explainable_ai.py         # Evidence ranking & narrative generator
│   │   ├── identity_signals.py       # Sender spoofing, BEC, display name checks
│   │   ├── ioc_extractor.py          # Multi-type IOC extractor & scope classifier
│   │   ├── nlp_signals.py            # Urgency, credential request, payment NLP checks
│   │   ├── scoring_engine.py         # Composite score aggregator
│   │   ├── security_signals.py       # Attachment, URL, IP security signals
│   │   ├── threat_classifier.py      # Primary threat category classifier
│   │   ├── threat_detection.py       # Top-level threat detection coordinator
│   │   └── threat_intelligence/      # VirusTotal & AbuseIPDB connectors with cache
│   │       ├── __init__.py
│   │       ├── abuseipdb.py
│   │       ├── aggregator.py
│   │       ├── cache.py
│   │       └── virustotal.py
│   └── main.py                       # FastAPI application entry point
├── frontend/
│   ├── css/
│   │   └── styles.css                # Dark-mode SOC styling tokens & responsive layout
│   ├── js/
│   │   └── app.js                    # SPA hash router, Cytoscape controller, API client
│   └── index.html                    # Single-page application shell (8 view panes)
├── tests/
│   ├── test_attack_graph.py          # Feature 6 test suite (12 async integration tests)
│   ├── test_email_forensics.py       # Feature 3 test suite (7 pytest unit tests)
│   ├── test_explainable_ai.py        # Feature 2 test suite (6 pytest unit tests)
│   ├── test_ioc_extractor.py         # Feature 4 test suite (9 pytest unit tests)
│   ├── test_threat_detection.py      # Feature 1 test suite (5 pytest unit tests)
│   └── test_threat_intelligence.py   # Feature 5 test suite (12 async integration tests)
├── requirements.txt                  # Minimal root dependencies
└── run.py                            # Development server launcher (Uvicorn on port 8000)
```

---

## 2. Verified Active API Endpoints & Request/Response Contracts

All existing endpoints are registered in `backend/api/routes.py` and mounted under prefix `/api/v1`:

| HTTP Method | Route | Request Model | Response Model / Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/analyze/threat` | `EmailAnalysisInput` | `ThreatDetectionResult` | Analyzes structured email input for threat scores & signals |
| `POST` | `/api/v1/analyze/explain` | `EmailAnalysisInput` | `ExplainableThreatResult` | Computes threat detection + XAI factor contributions |
| `POST` | `/api/v1/analyze` | `EmailAnalysisInput` | `ExplainableThreatResult` | Unified alias endpoint executing threat detection + explanation |
| `POST` | `/api/v1/analyze/forensics` | `RawEmlInput` | `ForensicEvidenceResult` | Deep forensic parsing of raw RFC 822 `.eml` string |
| `POST` | `/api/v1/analyze/forensics/upload`| `UploadFile` (multipart) | `ForensicEvidenceResult` | Raw `.eml` file upload forensic investigation |
| `POST` | `/api/v1/analyze/iocs` | `IocExtractionInput` | `IocExtractionResult` | Extracts IPs, domains, URLs, hashes with scope & source context |
| `POST` | `/api/v1/analyze/intelligence` | `ThreatIntelligenceInput`| `ThreatIntelligenceResult`| Enriches IOCs via VirusTotal and AbuseIPDB (or mock fallback) |
| `GET` | `/api/v1/cases` | None | `List[CaseRecord]` | Retrieves all historical investigation cases indexed in memory |
| `GET` | `/api/v1/cases/{case_id}/graph`| Path param `case_id` | `AttackGraph` | Returns node/edge graph for a single email investigation |
| `GET` | `/api/v1/campaigns` | None | `List[CampaignCluster]` | Clusters cases sharing infrastructure into threat campaigns |
| `GET` | `/api/v1/campaigns/{id}/graph`| Path param `id` | `AttackGraph` | Returns multi-node topology for a campaign cluster |
| `GET` | `/api/v1/search/ioc` | Query param `q` | `Dict[str, Any]` | Cross-investigation search across cases and campaigns |
| `POST` | `/api/v1/analyze/eml` | `RawEmlInput` | `Dict[str, Any]` | End-to-end pipeline: Forensics + IOCs + Intel + XAI + Graph + Campaign |
| `GET` | `/api/v1/demo-emails` | None | `Dict[str, Any]` | Returns pre-packaged demo email structured fixtures |
| `GET` | `/api/v1/demo-emls` | None | `Dict[str, Any]` | Returns raw RFC 822 `.eml` sample fixtures |
| `GET` | `/api/v1/health` | None | `Dict[str, str]` | API health check status |

---

## 3. Frontend Architecture & Cytoscape.js Integration

* **Entry Point:** `frontend/index.html` served at `http://127.0.0.1:8000/static/index.html`.
* **Client Router:** Hash-based SPA router in `frontend/js/app.js` (`handleRouting`) switching active `.view-pane` containers:
  - `view-dashboard`: High-level metrics, active campaign counter, recent case table.
  - `view-email-analysis`: Dropzone for `.eml` upload, manual header overrides, demo loaders.
  - `view-investigations`: Searchable directory of indexed investigation cases.
  - `view-case-detail`: Tabbed deep dive into individual cases (`overview`, `forensics`, `iocs`, `intel`, `graph`, `evidence`, `reports`).
  - `view-threat-intelligence`: Interactive reputation lookup.
  - `view-attack-graph`: Multi-case campaign topology explorer.
  - `view-reports`: Incident executive summaries.
  - `view-evidence`: Cryptographic SHA-256 evidence audit log.
* **Cytoscape.js Usage:**
  - Library version: Cytoscape.js 3.28.1 (loaded via CDN).
  - Single-case instance: `state.cyCase` mounted in container `#cy-attack-graph`. Uses `cose` layout, coloring nodes by type (`domain`, `ip`, `url`, `attachment`) and flagging `status='MALICIOUS'`.
  - Multi-case instance: `state.cyDedicated` mounted in container `#cy-dedicated-graph`. Renders campaign clusters and shared infrastructure nodes.

---

## 4. Test Execution & Verified Baseline Results

The existing test suites were executed using the active Python 3.13 environment (`C:\Python313\python.exe`):

### 4.1 Pytest Execution Results
```text
Command: C:\Python313\python.exe -m pytest -v
Status: 0 (Success)
Collected: 27 items

tests/test_email_forensics.py:
  test_benign_eml_forensics ............................ PASSED
  test_phishing_eml_forensics .......................... PASSED
  test_bec_reply_to_mismatch ........................... PASSED
  test_smtp_relay_reconstruction ....................... PASSED
  test_attachment_forensics_double_extension ........... PASSED
  test_malformed_sparse_email .......................... PASSED
  test_api_forensic_endpoints .......................... PASSED

tests/test_explainable_ai.py:
  test_phishing_explanation ............................ PASSED
  test_bec_explanation ................................. PASSED
  test_impersonation_explanation ........................ PASSED
  test_benign_explanation .............................. PASSED
  test_incomplete_data_handling ......................... PASSED
  test_api_explain_endpoint ............................. PASSED

tests/test_ioc_extractor.py:
  test_1_standard_email_extraction ...................... PASSED
  test_2_html_links_and_deduplication ................... PASSED
  test_3_hash_classification ............................ PASSED
  test_4_attachment_metadata_and_hashing ................ PASSED
  test_5_ip_scope_classification ........................ PASSED
  test_6_lookalike_domain_preservation .................. PASSED
  test_7_empty_email_handling ........................... PASSED
  test_8_malformed_email_fault_tolerance ................ PASSED
  test_9_fastapi_iocs_endpoint .......................... PASSED

tests/test_threat_detection.py:
  test_phishing_email_detection ......................... PASSED
  test_bec_email_detection .............................. PASSED
  test_impersonation_email_detection .................... PASSED
  test_benign_email_detection ........................... PASSED
  test_api_endpoints .................................... PASSED

Summary: 27 passed, 1 deprecation warning (Pydantic v2 .dict() vs .model_dump() in test_8) in 0.65s
```

### 4.2 Attack Graph & Campaign Correlation Test Suite
```text
Command: C:\Python313\python.exe tests/test_attack_graph.py
Status: 0 (Success)

[TEST 1] Attack Graph Construction .................... PASSED
[TEST 2] Node Deduplication ........................... PASSED
[TEST 3] SMTP Transmission Relay Chain ................ PASSED
[TEST 4] Threat Intelligence Status Enrichment ........ PASSED
[TEST 5] Campaign Correlation for Shared Infra ........ PASSED
[TEST 6] Attachment Hash Correlation .................. PASSED
[TEST 7] Negative Test (Unrelated Emails) ............. PASSED
[TEST 8] Campaign Clustering .......................... PASSED
[TEST 9] Cross-Investigation IOC Search ............... PASSED
[TEST 10] Fault Tolerance Without Intel/Forensics ..... PASSED
[TEST 11] Multi-Case Campaign Graph ................... PASSED
[TEST 12] FastAPI Endpoints (/cases, /campaigns, ...) . PASSED

Summary: 12 of 12 tests passed successfully.
```

### 4.3 Threat Intelligence Test Suite
```text
Command: C:\Python313\python.exe tests/test_threat_intelligence.py
Status: 0 (Success)

[TEST 1] AbuseIPDB Public IP Lookup .................. PASSED
[TEST 2] VirusTotal Public IP Lookup ................. PASSED
[TEST 3] VirusTotal Domain Lookup .................... PASSED
[TEST 4] VirusTotal URL Lookup ....................... PASSED
[TEST 5] VirusTotal File Hash Lookup ................. PASSED
[TEST 6] Unknown Indicator Handling .................. PASSED
[TEST 7] Private IP Scope Protection ................. PASSED
[TEST 8] Missing API Key Handling .................... PASSED
[TEST 9] Full IOC Threat Intelligence Enrichment ..... PASSED
[TEST 10] In-Memory Cache Hit Verification ........... PASSED
[TEST 11] Benign EML Intelligence .................... PASSED
[TEST 12] FastAPI Endpoints (/analyze/intelligence) .. PASSED

Summary: 12 of 12 tests passed successfully.
```

### 4.4 Aggregate Baseline Summary
* Total Executed Tests: **51**
* Passed: **51 (100%)**
* Failed: **0 (0%)**
* Skipped: **0 (0%)**
* Error: **0 (0%)**

---

## 5. Identified Existing Issues and Constraints

1. **Test Collection Style:**
   - `test_attack_graph.py` and `test_threat_intelligence.py` use `async def run_all_tests_async()` wrapped in a `__main__` entry point instead of pytest test functions (`def test_*`). As a result, default `pytest` test collection does not collect these two files unless run directly via Python. They pass 100% when executed. Per instructions, existing test files will not be altered to preserve baseline integrity.
2. **Docker Tooling in Environment:**
   - Docker and Docker Compose are not present in PATH on the host Windows environment.
   - *Implication for Phase 3:* The GraphOps Neo4j connector must support an in-memory / simulated repository fallback so that automated tests and local runs continue to pass deterministically even when a live Neo4j service is not running locally.
3. **Pydantic Deprecation Warning:**
   - In `tests/test_ioc_extractor.py:218`, a call to `res.summary.dict()` triggers a Pydantic v2 warning (`The dict method is deprecated; use model_dump instead`). This warning does not cause test failures.

---

## 6. Recommended Safe Extension Points for GraphOps

GraphOps will be integrated cleanly without touching existing pipeline contracts:

1. **Subsystem Package:** New directory `backend/graphops/` isolating:
   - `client.py`: Neo4j driver connection manager with pooling, health checks, and fallback repository.
   - `schema.py`: Graph constraints, entity types, and relationship definitions.
   - `ingest.py`: Validated, idempotent ingestion of assets, identities, permissions, vulnerabilities.
   - `blast_radius.py`: Multi-hop neighborhood algorithms (1-hop, 2-hop, 3-hop).
   - `attack_path.py`: Bounded path discovery from entry points to critical assets.
   - `choke_point.py`: Centrality and bridge analysis ranking interventions.
   - `containment.py`: Read-only What-If simulator (zero live graph mutation).
   - `bridge.py`: Verified linkage between investigated email cases/IOCs and enterprise graph nodes.
2. **Dedicated API Route Module:** `backend/api/graphops_routes.py` registered in `backend/main.py` under prefix `/api/v1/graphops`. This prevents any disruption to existing `/api/v1/analyze/*`, `/cases`, or `/campaigns` routes.
3. **Data Contracts:** New models in `backend/models/graphops.py` subclassing `pydantic.BaseModel` without altering existing case or forensic models.
4. **Frontend Extension:**
   - Add a navigation item (`GraphOps Hunting`) in `frontend/index.html` sidebar.
   - Add `view-graphops` pane with Cytoscape.js canvas and interactive What-If simulation controls.
   - Add a "Pivot to GraphOps" action in `view-case-detail` to map investigated email identities/IPs into the organizational graph.
