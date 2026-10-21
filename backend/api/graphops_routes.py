"""
ThreatLens GraphOps - API Router
Exposes health verification, connection diagnostics, and schema constraint initialization
without exposing sensitive credentials or disrupting existing ThreatLens endpoints.
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, status, Depends, Query
from backend.graphops.client import (
    get_graphops_client,
    Neo4jClient,
    GraphOpsConnectionError,
    GraphOpsQueryError,
)
from backend.graphops.schema import TraversalDirection, RelationshipType
from backend.models.graphops import (
    BlastRadiusRequest,
    BlastRadiusResult,
    AttackPathRequest,
    AttackPathResult,
    ChokePointRequest,
    ChokePointResult,
    ContainmentSimulationRequest,
    ContainmentSimulationResult,
    CaseBridgeResponse,
    AccessSequenceRequest,
    AccessSequenceAnomalyResult,
    BaselineProfileSummary,
    AnomalyTestSuiteResult,
)

router = APIRouter()


@router.get(
    "/health",
    summary="GraphOps Neo4j Health Check",
    description="Verifies graph database connectivity and driver status. Sanitized; never returns credentials.",
)
async def graphops_health_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
) -> Dict[str, Any]:
    """
    Safe health check for the GraphOps Neo4j backend.
    Returns HTTP 200 if connected, HTTP 503 if unavailable.
    """
    health = client.health_check()
    if not health.get("connected"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "message": "GraphOps database connection is unavailable.",
                "database": health.get("database"),
                "status": "unhealthy",
                "connected": False,
                "error": health.get("error"),
            },
        )
    return health


@router.get(
    "/schema/constraints",
    summary="View GraphOps Schema Constraints",
    description="Returns list of configured unique constraints and indexes for organizational graph entities.",
)
async def list_schema_constraints_endpoint() -> Dict[str, Any]:
    from backend.graphops.schema import CYPHER_SCHEMA_STATEMENTS
    return {
        "total_constraints_and_indexes": len(CYPHER_SCHEMA_STATEMENTS),
        "statements": CYPHER_SCHEMA_STATEMENTS,
    }


@router.post(
    "/schema/init",
    summary="Initialize Neo4j Schema Constraints",
    description="Idempotently creates unique constraints on node IDs and indexes on critical properties.",
)
async def init_schema_constraints_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
) -> Dict[str, Any]:
    """Applies unique constraints and indexes to the connected Neo4j instance."""
    try:
        return client.init_schema_constraints()
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Cannot initialize schema: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Schema initialization error: {str(e)}",
        )


# ==========================================================
# INGESTION & GRAPH TOPOLOGY SUMMARY
# ==========================================================

@router.post(
    "/ingest/sample",
    response_model=dict,
    summary="Ingest Sample Enterprise Security Graph Fixture",
    description="Loads the curated, synthetic SOC enterprise graph fixture into Neo4j idempotently.",
)
async def ingest_sample_fixture_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
) -> Dict[str, Any]:
    """Loads default synthetic enterprise security graph fixture into Neo4j."""
    from backend.graphops.ingest import GraphOpsIngestionEngine
    try:
        engine = GraphOpsIngestionEngine(client)
        summary = engine.ingest_sample_fixture()
        return summary.model_dump()
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Cannot ingest sample data: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sample ingestion failed: {str(e)}",
        )


@router.post(
    "/ingest/bulk",
    response_model=dict,
    summary="Bulk Ingest Custom Entities and Relationships",
    description="Validates and idempotently imports custom BulkIngestPayload into Neo4j with batching.",
)
async def ingest_bulk_payload_endpoint(
    payload: dict,
    client: Neo4jClient = Depends(get_graphops_client),
) -> Dict[str, Any]:
    """Imports custom bulk JSON dataset of enterprise nodes and edges."""
    from backend.models.graphops import BulkIngestPayload
    from backend.graphops.ingest import GraphOpsIngestionEngine
    try:
        validated_payload = BulkIngestPayload(**payload)
        engine = GraphOpsIngestionEngine(client)
        summary = engine.ingest_payload(validated_payload)
        return summary.model_dump()
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unreachable during bulk ingestion: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Bulk payload validation or ingestion error: {str(e)}",
        )


@router.get(
    "/summary",
    summary="Get GraphOps Topology Summary",
    description="Returns aggregate entity counts by label, relationship counts by type, and Crown Jewels status.",
)
async def get_graphops_summary_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
) -> Dict[str, Any]:
    """Returns high-level graph metrics and inventory summary."""
    from backend.graphops.ingest import GraphOpsIngestionEngine
    try:
        engine = GraphOpsIngestionEngine(client)
        return engine.get_graph_summary()
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Cannot fetch graph summary: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve graph summary: {str(e)}",
        )


# ==========================================================
# BLAST-RADIUS ANALYTICS
# ==========================================================

@router.get(
    "/blast-radius",
    response_model=BlastRadiusResult,
    summary="Calculate Neighborhood Blast Radius",
    description="Calculates bounded 1-hop, 2-hop, and 3-hop blast radius neighborhoods from a compromised entity.",
)
async def get_blast_radius_endpoint(
    start_node_id: str = Query(..., description="Canonical ID or alias of starting node"),
    max_hops: int = Query(3, ge=1, le=3, description="Neighborhood depth (1, 2, or 3 hops)"),
    direction: TraversalDirection = Query(TraversalDirection.OUTGOING, description="Traversal direction: OUTGOING, INCOMING, or BOTH"),
    include_hypothetical: bool = Query(False, description="Whether to include hypothetical exploit edges"),
    relationship_types: Optional[str] = Query(None, description="Comma-separated list of allowed relationship types"),
    client: Neo4jClient = Depends(get_graphops_client),
) -> BlastRadiusResult:
    """Calculates multi-hop blast radius using GET query parameters."""
    from backend.graphops.blast_radius import BlastRadiusService, NodeNotFoundError

    allowed_types = None
    if relationship_types:
        raw_types = [t.strip() for t in relationship_types.split(",") if t.strip()]
        allowed_types = []
        for rt in raw_types:
            try:
                allowed_types.append(RelationshipType(rt))
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid relationship type in filter: '{rt}'",
                )

    request = BlastRadiusRequest(
        start_node_id=start_node_id,
        max_hops=max_hops,
        direction=direction,
        include_hypothetical=include_hypothetical,
        allowed_relationship_types=allowed_types,
    )

    try:
        service = BlastRadiusService(client)
        return service.calculate_blast_radius(request)
    except NodeNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unreachable during blast radius calculation: {str(e)}",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Blast radius calculation error: {str(e)}",
        )


@router.post(
    "/blast-radius",
    response_model=BlastRadiusResult,
    summary="Calculate Neighborhood Blast Radius (JSON Body)",
    description="Calculates bounded 1-hop, 2-hop, and 3-hop blast radius neighborhoods from a compromised entity via POST request body.",
)
async def post_blast_radius_endpoint(
    payload: BlastRadiusRequest,
    client: Neo4jClient = Depends(get_graphops_client),
) -> BlastRadiusResult:
    """Calculates multi-hop blast radius using POST request body."""
    from backend.graphops.blast_radius import BlastRadiusService, NodeNotFoundError

    try:
        service = BlastRadiusService(client)
        return service.calculate_blast_radius(payload)
    except NodeNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unreachable during blast radius calculation: {str(e)}",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Blast radius calculation error: {str(e)}",
        )


# ==========================================================
# ATTACK-PATH DISCOVERY
# ==========================================================

@router.post(
    "/attack-paths",
    response_model=AttackPathResult,
    summary="Discover Candidate Attack Paths to Crown Jewels",
    description="Discovers bounded, acyclic access paths from specified entry point to critical assets with risk scoring.",
)
async def post_attack_paths_endpoint(
    payload: AttackPathRequest,
    client: Neo4jClient = Depends(get_graphops_client),
) -> AttackPathResult:
    """Discovers plausible attack paths to Crown Jewels using AttackPathRequest payload."""
    from backend.graphops.attack_paths import AttackPathService
    from backend.graphops.blast_radius import NodeNotFoundError

    try:
        service = AttackPathService(client)
        return service.find_attack_paths(payload)
    except NodeNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unreachable during attack path analysis: {str(e)}",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Attack path discovery error: {str(e)}",
        )


# ==========================================================
# CHOKE-POINT ANALYSIS
# ==========================================================

@router.get(
    "/choke-points",
    response_model=ChokePointResult,
    summary="Analyze Candidate Attack Paths for Strategic Choke Points",
    description="Identifies and ranks intermediate entities that eliminate the highest percentage of attack paths.",
)
async def get_choke_points_endpoint(
    entry_node_id: Optional[str] = Query(None, description="Optional entry point to analyze; if omitted, evaluates across default entry points"),
    top_n: int = Query(5, ge=1, le=20, description="Number of top choke points to return"),
    client: Neo4jClient = Depends(get_graphops_client),
) -> ChokePointResult:
    """Calculates choke points using GET query parameters."""
    from backend.graphops.attack_paths import AttackPathService
    from backend.models.graphops import AttackPathRequest

    try:
        service = AttackPathService(client)
        if entry_node_id:
            req = AttackPathRequest(entry_node_id=entry_node_id, max_depth=5, include_hypothetical=True)
            path_res = service.find_attack_paths(req)
            paths = path_res.paths
        else:
            paths = []
            for default_entry in ["device:dev-ws-101", "device:dev-ws-102"]:
                try:
                    req = AttackPathRequest(entry_node_id=default_entry, max_depth=5, include_hypothetical=True)
                    path_res = service.find_attack_paths(req)
                    paths.extend(path_res.paths)
                except Exception:
                    continue

        return service.analyze_choke_points(paths=paths, top_n=top_n)
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unreachable during choke-point analysis: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Choke-point analysis error: {str(e)}",
        )


@router.post(
    "/choke-points",
    response_model=ChokePointResult,
    summary="Analyze Candidate Attack Paths for Strategic Choke Points (JSON Body)",
    description="Identifies and ranks intermediate entities that eliminate the highest percentage of attack paths via POST body.",
)
async def post_choke_points_endpoint(
    payload: ChokePointRequest,
    client: Neo4jClient = Depends(get_graphops_client),
) -> ChokePointResult:
    """Calculates choke points using POST request body."""
    from backend.graphops.attack_paths import AttackPathService
    from backend.models.graphops import AttackPathRequest

    try:
        service = AttackPathService(client)
        paths = []
        for default_entry in ["device:dev-ws-101", "device:dev-ws-102"]:
            try:
                req = AttackPathRequest(entry_node_id=default_entry, max_depth=5, include_hypothetical=True)
                path_res = service.find_attack_paths(req)
                paths.extend(path_res.paths)
            except Exception:
                continue

        if payload.analyzed_path_ids:
            target_pids = set(payload.analyzed_path_ids)
            paths = [p for p in paths if p.path_id in target_pids]

        return service.analyze_choke_points(paths=paths, top_n=payload.top_n)
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unreachable during choke-point analysis: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Choke-point analysis error: {str(e)}",
        )


# ==========================================================
# WHAT-IF CONTAINMENT SIMULATION
# ==========================================================

@router.post(
    "/simulate-containment",
    response_model=ContainmentSimulationResult,
    summary="Simulate Containment Interventions In-Memory",
    description="Evaluates proposed containment actions (isolation, connection severing) strictly in memory without altering persistent data.",
)
async def post_simulate_containment_endpoint(
    payload: ContainmentSimulationRequest,
    client: Neo4jClient = Depends(get_graphops_client),
) -> ContainmentSimulationResult:
    """Executes safe in-memory What-If containment simulation."""
    from backend.graphops.attack_paths import AttackPathService
    from backend.graphops.blast_radius import NodeNotFoundError

    try:
        service = AttackPathService(client)
        return service.simulate_containment(payload)
    except NodeNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unreachable during containment simulation: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Simulation error: {str(e)}",
        )


# ==========================================================
# CASE-TO-ORGANIZATION FORENSIC BRIDGE
# ==========================================================

@router.get(
    "/bridge/case/{case_id}",
    response_model=CaseBridgeResponse,
    summary="Bridge Email Case Evidence to Organizational Graph",
    description="Maps email forensic evidence to internal user accounts and devices, while isolating external IOCs.",
)
async def get_case_bridge_endpoint(
    case_id: str,
    client: Neo4jClient = Depends(get_graphops_client),
) -> CaseBridgeResponse:
    """Bridges email case evidence to organizational security graph."""
    from backend.graphops.attack_paths import AttackPathService

    try:
        service = AttackPathService(client)
        return service.bridge_case_to_graph(case_id)
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unreachable during case bridge resolution: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Case bridge resolution error: {str(e)}",
        )


# ==========================================================
# GRAPH-BASED ACCESS ANOMALY DETECTION (PHASE 9)
# ==========================================================

@router.post(
    "/anomaly/evaluate-sequence",
    response_model=AccessSequenceAnomalyResult,
    summary="Evaluate Access Sequence for Graph-Based Anomalies",
    description="Evaluates an ordered sequence of relationships against baseline tiering, IAM policies, and role profiles.",
)
async def post_evaluate_sequence_endpoint(
    payload: AccessSequenceRequest,
    client: Neo4jClient = Depends(get_graphops_client),
) -> AccessSequenceAnomalyResult:
    """Evaluates access sequence against documented security graph baseline."""
    from backend.graphops.anomaly_detection import AccessAnomalyDetector
    try:
        detector = AccessAnomalyDetector(client)
        return detector.evaluate_sequence(payload)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Access sequence anomaly evaluation error: {str(e)}",
        )


@router.get(
    "/anomaly/baseline",
    response_model=BaselineProfileSummary,
    summary="Get Documented Anomaly Baseline Rules and Profiles",
    description="Returns active network tiering rules, department profiles, and scoring formula used for anomaly detection.",
)
async def get_anomaly_baseline_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
) -> BaselineProfileSummary:
    """Returns baseline rules and active security profile summary."""
    from backend.graphops.anomaly_detection import AccessAnomalyDetector
    detector = AccessAnomalyDetector(client)
    return detector.get_baseline_summary()


@router.get(
    "/anomaly/test-suite",
    response_model=AnomalyTestSuiteResult,
    summary="Run Benchmark Test Suite Across Labeled Sequences",
    description="Evaluates the held-out labeled test sequences fixture and returns precision, recall, F1, and FPR.",
)
async def get_anomaly_test_suite_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
) -> AnomalyTestSuiteResult:
    """Runs evaluation benchmark against the 12 curated labeled test sequences."""
    from backend.graphops.anomaly_detection import AccessAnomalyDetector
    detector = AccessAnomalyDetector(client)
    return detector.run_test_suite()


@router.get(
    "/anomaly/evaluate-case/{case_id}",
    response_model=AccessSequenceAnomalyResult,
    summary="Evaluate Case-Linked Access Sequence for Anomalies",
    description="Bridges email case evidence to internal identity/workstation and evaluates the observed access sequence.",
)
async def get_evaluate_case_anomalies_endpoint(
    case_id: str,
    client: Neo4jClient = Depends(get_graphops_client),
) -> AccessSequenceAnomalyResult:
    """Bridges case evidence and evaluates access sequence against graph baseline."""
    from backend.graphops.anomaly_detection import AccessAnomalyDetector
    try:
        detector = AccessAnomalyDetector(client)
        return detector.evaluate_case(case_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Case anomaly evaluation error: {str(e)}",
        )




