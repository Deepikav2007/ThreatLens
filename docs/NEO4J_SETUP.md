# ThreatLens GraphOps: Neo4j Database Setup & Integration Guide

**Document Version:** 1.0.0  
**Phase:** Phase 3 — Neo4j Database Integration  
**Status:** Complete  

---

## 1. Version Compatibility Matrix

All components have been tested and verified for compatibility:

| Component | Pinned / Minimum Version | Verified Active Version | Notes |
| :--- | :--- | :--- | :--- |
| **Python Runtime** | `3.13.x` | `3.13.15` (64-bit Windows) | Official Python 3.13 release |
| **Neo4j Python Driver** | `neo4j>=5.28.0,<6.0.0` | `neo4j==5.28.1` | Pure-Python wheel; no C-compiler build required |
| **Neo4j Database Engine** | `neo4j:5.26.0-community` | `5.26.0 Community` | Stable LTS Community Release |
| **Cypher Query Language**| Cypher 5 | Cypher 5 (`IF NOT EXISTS` constraints) | Full parameterized query support |
| **FastAPI Framework** | `fastapi>=0.100.0` | `0.115.11` | Integrated with async lifespan shutdown hooks |

---

## 2. Environment Configuration

The application reads configuration through environment variables in [`backend/core/config.py`](file:///d:/Desktop/Hackathon/ThreatLens/backend/core/config.py). A template is provided in [`.env.example`](file:///d:/Desktop/Hackathon/ThreatLens/.env.example).

### Required Environment Variables

| Variable | Default Value | Description | Security Considerations |
| :--- | :--- | :--- | :--- |
| `NEO4J_URI` | `bolt://localhost:7687` | Bolt protocol connection URI | Default binds to localhost. |
| `NEO4J_USER` | `neo4j` | Database username | Standard administrative account. |
| `NEO4J_PASSWORD` | `threatlens_password` | Database password | **Never commit to version control.** Excluded via `.gitignore`. |
| `NEO4J_DATABASE` | `neo4j` | Default database name | Community edition supports single active database. |
| `NEO4J_CONNECTION_TIMEOUT_SECONDS` | `5.0` | Connection timeout in seconds | Prevents API worker blocking when DB is offline. |
| `NEO4J_MAX_CONNECTION_LIFETIME_SECONDS` | `3600.0` | Connection pool max age | Automatic recycling of stale TCP sessions. |
| `NEO4J_MAX_CONNECTION_POOL_SIZE` | `50` | Maximum connections in pool | Prevents connection exhaustion on server. |

To configure locally:
```powershell
Copy-Item .env.example .env
# Edit .env with your specific Neo4j password if different from default
```

---

## 3. Starting Neo4j Locally

### Option A: Using Docker Compose (Recommended)
A ready-to-use Docker Compose configuration is provided in [`docker-compose.yml`](file:///d:/Desktop/Hackathon/ThreatLens/docker-compose.yml):

```powershell
# Start Neo4j in the background
docker compose up -d

# Check service logs and startup health
docker compose logs -f threatlens-neo4j

# Stop Neo4j when finished
docker compose down
```

* **Neo4j Browser UI:** `http://127.0.0.1:7474`
* **Bolt Protocol Port:** `bolt://127.0.0.1:7687`
* **Username:** `neo4j`
* **Password:** `threatlens_password` (as configured in `docker-compose.yml`)

> [!NOTE]
> **Security Protection:** Ports `7474` and `7687` are explicitly bound to `127.0.0.1` in `docker-compose.yml` to prevent accidental public exposure across external network interfaces.

### Option B: Using Neo4j Desktop or Standalone Service
If Docker is not installed on the system:
1. Download and install Neo4j Desktop or Neo4j Community Server (version 5.26+).
2. Set the initial password to `threatlens_password` (or update `.env` to match your custom password).
3. Ensure Bolt protocol is active on port `7687`.

---

## 4. Application Verification & Health Checks

### 4.1 Safe Health Endpoint
The FastAPI application exposes a sanitized health verification route:
```http
GET /api/v1/graphops/health
```

* **When Connected (HTTP 200 OK):**
  ```json
  {
    "status": "healthy",
    "database": "neo4j",
    "connected": true,
    "server_agent": "Neo4j/5.26.0",
    "protocol": "Bolt/5.4"
  }
  ```
* **When Database is Offline / Unavailable (HTTP 503 Service Unavailable):**
  ```json
  {
    "detail": {
      "message": "GraphOps database connection is unavailable.",
      "database": "neo4j",
      "status": "unhealthy",
      "connected": false,
      "error": "Neo4j service unavailable at bolt://localhost:7687: ..."
    }
  }
  ```

> [!IMPORTANT]
> **Credential Sanitization:** Health checks and error responses **never disclose passwords or authentication tokens**, protecting security operations from credential leakage in logs or API responses.

### 4.2 Initializing Schema Constraints
Once Neo4j is running, initialize unique constraints and property indexes:
```http
POST /api/v1/graphops/schema/init
```
* **Response (HTTP 200 OK):**
  ```json
  {
    "total_statements": 13,
    "applied_count": 13,
    "applied": [
      "CREATE CONSTRAINT user_id_unique IF NOT EXISTS FOR (n:User) REQUIRE n.id IS UNIQUE",
      "CREATE CONSTRAINT device_id_unique IF NOT EXISTS FOR (n:Device) REQUIRE n.id IS UNIQUE",
      "CREATE CONSTRAINT server_id_unique IF NOT EXISTS FOR (n:Server) REQUIRE n.id IS UNIQUE",
      "CREATE CONSTRAINT app_id_unique IF NOT EXISTS FOR (n:Application) REQUIRE n.id IS UNIQUE",
      "CREATE CONSTRAINT ip_id_unique IF NOT EXISTS FOR (n:IPAddress) REQUIRE n.id IS UNIQUE",
      "CREATE CONSTRAINT vuln_id_unique IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.id IS UNIQUE",
      "CREATE CONSTRAINT crit_id_unique IF NOT EXISTS FOR (n:CriticalAsset) REQUIRE n.id IS UNIQUE",
      "CREATE CONSTRAINT event_id_unique IF NOT EXISTS FOR (n:SecurityEvent) REQUIRE n.id IS UNIQUE",
      "CREATE INDEX user_email_idx IF NOT EXISTS FOR (n:User) ON (n.email)",
      "CREATE INDEX device_ip_idx IF NOT EXISTS FOR (n:Device) ON (n.ip_address)",
      "CREATE INDEX server_ip_idx IF NOT EXISTS FOR (n:Server) ON (n.ip_address)",
      "CREATE INDEX vuln_cve_idx IF NOT EXISTS FOR (n:Vulnerability) ON (n.cve_id)",
      "CREATE INDEX crit_impact_idx IF NOT EXISTS FOR (n:CriticalAsset) ON (n.impact_score)"
    ],
    "errors": []
  }
  ```

---

## 5. Architectural Non-Disruption Guarantees

1. **Isolation of Existing APIs:**
   - Existing endpoints (`/api/v1/analyze/*`, `/api/v1/cases`, `/api/v1/campaigns`, `/api/v1/health`) do not depend on Neo4j. If Neo4j is offline or unconfigured, all existing ThreatLens workflows continue functioning without interruption.
2. **Explicit Error Handling:**
   - Database connection failures are raised as explicit domain exceptions ([`GraphOpsConnectionError`](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/client.py#L35) or [`GraphOpsQueryError`](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/client.py#L40)). A failed query is **never falsely treated as an empty successful result**.
3. **Controlled Driver Lifecycle:**
   - The FastAPI `lifespan` handler automatically invokes [`close_graphops_client()`](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/client.py#L268) upon server shutdown, releasing connection pools and preventing socket leaks.
