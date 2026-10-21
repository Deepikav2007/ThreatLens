"""
ThreatLens GraphOps - Model & Schema Validation Tests
Phase 2: Graph Schema, Canonical IDs, Relationship Typing, and API Contracts
"""

import pytest
from pydantic import ValidationError

from backend.graphops.schema import (
    NodeLabel,
    EvidenceClass,
    RelationshipType,
    CriticalityTier,
    DataClassification,
    TraversalDirection,
    InterventionAction,
    canonicalize_node_id,
    VALID_RELATIONSHIP_ENDPOINTS,
)
from backend.models.graphops import (
    UserNode,
    DeviceNode,
    ServerNode,
    ApplicationNode,
    IpAddressNode,
    VulnerabilityNode,
    CriticalAssetNode,
    SecurityEventNode,
    EnterpriseNode,
    EnterpriseRelationship,
    EntityIngestRequest,
    RelationshipIngestRequest,
    BulkIngestPayload,
    IngestSummaryResponse,
    BlastRadiusRequest,
    BlastRadiusHopGroup,
    CriticalAssetExposure,
    BlastRadiusResult,
    AttackPathRequest,
    AttackPathStep,
    AttackPathItem,
    AttackPathResult,
    ChokePointRequest,
    ChokePointItem,
    ChokePointResult,
    ProposedIntervention,
    ContainmentSimulationRequest,
    SimulatedPathStatus,
    ContainmentSimulationResult,
    CaseBridgeRequest,
    BridgeMappingItem,
    CaseBridgeResponse,
)


# =====================================================================
# 1. CANONICAL IDENTIFIER TESTS
# =====================================================================

def test_canonicalize_node_id_prefixes():
    """Verifies that every node type generates a deterministic canonical prefix."""
    assert canonicalize_node_id(NodeLabel.USER, "alice@corporation.com") == "user:alice@corporation.com"
    assert canonicalize_node_id(NodeLabel.DEVICE, "DEV-WS-109") == "device:dev-ws-109"
    assert canonicalize_node_id(NodeLabel.SERVER, "SRV-APP-01") == "server:srv-app-01"
    assert canonicalize_node_id(NodeLabel.APPLICATION, "payment-gateway") == "app:payment-gateway"
    assert canonicalize_node_id(NodeLabel.IP_ADDRESS, "10.0.1.15") == "ip:10.0.1.15"
    assert canonicalize_node_id(NodeLabel.VULNERABILITY, "cve-2024-21413") == "vuln:CVE-2024-21413"
    assert canonicalize_node_id(NodeLabel.CRITICAL_ASSET, "CRIT-DB-01") == "critical:crit-db-01"
    assert canonicalize_node_id(NodeLabel.SECURITY_EVENT, "EVT-8821") == "event:evt-8821"


def test_canonicalize_idempotent():
    """Verifies that already-prefixed IDs are idempotently normalized without double prefixing."""
    res1 = canonicalize_node_id(NodeLabel.USER, "alice@corp.com")
    res2 = canonicalize_node_id(NodeLabel.USER, res1)
    assert res1 == "user:alice@corp.com"
    assert res2 == "user:alice@corp.com"

    res_vuln1 = canonicalize_node_id(NodeLabel.VULNERABILITY, "vuln:cve-2024-21413")
    assert res_vuln1 == "vuln:CVE-2024-21413"


# =====================================================================
# 2. TYPED NODE MODEL VALIDATION TESTS
# =====================================================================

def test_user_node_valid():
    user = UserNode(
        id="USR-101",
        user_id="USR-101",
        email="ALICE@corporation.COM",
        name="Alice Johnson",
        department="Finance",
        role="Financial Analyst",
        is_admin=False
    )
    assert user.id == "user:usr-101"
    assert user.name == "Alice Johnson"
    assert user.status == "ACTIVE"


def test_device_node_valid():
    device = DeviceNode(
        id="DEV-WS-109",
        device_id="DEV-WS-109",
        hostname="WS-FIN-109",
        ip_address="10.0.1.109",
        os="Windows 11 Enterprise",
        criticality=CriticalityTier.MEDIUM
    )
    assert device.id == "device:dev-ws-109"
    assert device.criticality == CriticalityTier.MEDIUM
    assert device.is_isolated is False


def test_server_node_valid():
    server = ServerNode(
        id="SRV-APP-01",
        server_id="SRV-APP-01",
        name="Production Application Server 01",
        hostname="app01.internal.corp",
        ip_address="10.0.2.10",
        tier="Application",
        criticality=CriticalityTier.HIGH
    )
    assert server.id == "server:srv-app-01"
    assert server.environment == "Production"


def test_ip_address_node_valid_and_invalid():
    # Valid IPv4
    ip_node = IpAddressNode(id="10.0.1.15", ip="10.0.1.15", scope="internal")
    assert ip_node.id == "ip:10.0.1.15"

    # Valid IPv6
    ip6_node = IpAddressNode(id="2001:db8::1", ip="2001:db8::1", version=6)
    assert ip6_node.id == "ip:2001:db8::1"

    # Invalid IP string
    with pytest.raises(ValidationError):
        IpAddressNode(id="bad", ip="999.999.999.999")

    with pytest.raises(ValidationError):
        IpAddressNode(id="bad", ip="not-an-ip")


def test_vulnerability_node_valid_and_invalid():
    # Valid CVE
    vuln = VulnerabilityNode(
        id="CVE-2024-21413",
        cve_id="cve-2024-21413",
        cvss_score=9.8,
        severity=CriticalityTier.CRITICAL,
        description="Microsoft Outlook Remote Code Execution",
        exploit_available=True
    )
    assert vuln.id == "vuln:CVE-2024-21413"
    assert vuln.cve_id == "CVE-2024-21413"
    assert vuln.cvss_score == 9.8

    # Invalid CVE format
    with pytest.raises(ValidationError):
        VulnerabilityNode(
            id="bad",
            cve_id="INVALID-CVE",
            cvss_score=5.0,
            severity=CriticalityTier.MEDIUM
        )

    # Invalid CVSS score (> 10.0 or < 0.0)
    with pytest.raises(ValidationError):
        VulnerabilityNode(
            id="cve-2024-1111",
            cve_id="CVE-2024-1111",
            cvss_score=10.5,
            severity=CriticalityTier.CRITICAL
        )


def test_critical_asset_node_valid_and_invalid():
    crit = CriticalAssetNode(
        id="CRIT-DB-01",
        asset_id="CRIT-DB-01",
        name="Customer Financial Data Store",
        category="FINANCIAL_RECORDS",
        impact_score=95,
        data_classification=DataClassification.RESTRICTED
    )
    assert crit.id == "critical:crit-db-01"
    assert crit.impact_score == 95

    # Out of range impact score (< 1 or > 100)
    with pytest.raises(ValidationError):
        CriticalAssetNode(
            id="CRIT-01",
            asset_id="CRIT-01",
            name="Test",
            category="OTHER",
            impact_score=150
        )


# =====================================================================
# 3. TYPED RELATIONSHIP & EVIDENCE SEPARATION TESTS
# =====================================================================

def test_enterprise_relationship_edge_id_generation():
    """Verifies deterministic edge ID generation and evidence class tagging."""
    rel = EnterpriseRelationship(
        source_id="user:usr-101",
        target_id="device:dev-ws-109",
        relationship_type=RelationshipType.USES,
        evidence_class=EvidenceClass.OBSERVED,
        provenance="ActiveDirectory",
        timestamp="2026-10-19T10:00:00Z"
    )
    assert rel.id == "user:usr-101->device:dev-ws-109:USES"
    assert rel.evidence_class == EvidenceClass.OBSERVED
    assert rel.confidence == 1.0


def test_enterprise_relationship_evidence_classes():
    """Verifies that relationships distinguish observed from authorized and hypothetical."""
    # Authorized access (IAM / Directory permission)
    perm_rel = EnterpriseRelationship(
        source_id="user:usr-101",
        target_id="server:srv-app-01",
        relationship_type=RelationshipType.HAS_PERMISSION,
        evidence_class=EvidenceClass.AUTHORIZED_ACCESS,
        properties={"privilege_level": "ADMINISTRATOR"}
    )
    assert perm_rel.evidence_class == EvidenceClass.AUTHORIZED_ACCESS

    # Hypothetical exploit path (modeled without proof of execution)
    exploit_rel = EnterpriseRelationship(
        source_id="device:dev-ws-109",
        target_id="server:srv-app-01",
        relationship_type=RelationshipType.POTENTIAL_EXPLOIT,
        evidence_class=EvidenceClass.HYPOTHETICAL,
        confidence=0.7,
        properties={"via_cve": "CVE-2024-21413"}
    )
    assert exploit_rel.evidence_class == EvidenceClass.HYPOTHETICAL
    assert exploit_rel.confidence == 0.7


def test_valid_relationship_endpoint_registry():
    """Verifies schema endpoint constraints for each relationship type."""
    assert RelationshipType.USES in VALID_RELATIONSHIP_ENDPOINTS
    sources, targets = VALID_RELATIONSHIP_ENDPOINTS[RelationshipType.USES]
    assert NodeLabel.USER in sources
    assert NodeLabel.DEVICE in targets

    sources, targets = VALID_RELATIONSHIP_ENDPOINTS[RelationshipType.HAS_VULNERABILITY]
    assert NodeLabel.DEVICE in sources
    assert NodeLabel.VULNERABILITY in targets


# =====================================================================
# 4. INGESTION DATA CONTRACT TESTS
# =====================================================================

def test_bulk_ingest_payload_structure():
    users = [UserNode(id="USR-1", user_id="USR-1", email="user1@corp.com", name="User One")]
    devices = [DeviceNode(id="DEV-1", device_id="DEV-1", hostname="WS-01", ip_address="10.0.1.1")]
    rels = [
        EnterpriseRelationship(
            source_id="user:usr-1",
            target_id="device:dev-1",
            relationship_type=RelationshipType.USES
        )
    ]
    payload = BulkIngestPayload(
        dataset_name="test_fixture_v1",
        entities=EntityIngestRequest(users=users, devices=devices),
        relationships=RelationshipIngestRequest(relationships=rels)
    )
    assert payload.dataset_name == "test_fixture_v1"
    assert len(payload.entities.users) == 1
    assert len(payload.relationships.relationships) == 1


def test_ingest_summary_response():
    resp = IngestSummaryResponse(
        status="SUCCESS",
        dataset_name="enterprise_assets",
        nodes_imported=120,
        nodes_updated=5,
        relationships_imported=340
    )
    assert resp.status == "SUCCESS"
    assert resp.nodes_imported == 120
    assert resp.relationships_rejected == 0


# =====================================================================
# 5. BLAST-RADIUS CONTRACT TESTS
# =====================================================================

def test_blast_radius_request_defaults_and_validation():
    req = BlastRadiusRequest(start_node_id="user:usr-101")
    assert req.max_hops == 3
    assert req.direction == TraversalDirection.OUTGOING
    assert req.include_hypothetical is False

    # Max hops cannot exceed 3
    with pytest.raises(ValidationError):
        BlastRadiusRequest(start_node_id="user:usr-101", max_hops=4)

    # Max hops cannot be less than 1
    with pytest.raises(ValidationError):
        BlastRadiusRequest(start_node_id="user:usr-101", max_hops=0)


def test_blast_radius_result_structure():
    start = EnterpriseNode(
        id="user:usr-101",
        label=NodeLabel.USER,
        name="Alice Johnson",
        criticality=CriticalityTier.LOW
    )
    hop_1 = BlastRadiusHopGroup(hop_number=1, node_count=1, nodes=[
        EnterpriseNode(id="device:dev-ws-109", label=NodeLabel.DEVICE, name="WS-FIN-109")
    ])
    hop_2 = BlastRadiusHopGroup(hop_number=2, node_count=1, nodes=[
        EnterpriseNode(id="server:srv-app-01", label=NodeLabel.SERVER, name="App Server 01")
    ])
    hop_3 = BlastRadiusHopGroup(hop_number=3, node_count=1, critical_asset_count=1, nodes=[
        EnterpriseNode(id="critical:crit-db-01", label=NodeLabel.CRITICAL_ASSET, name="Customer PII DB", criticality=CriticalityTier.CRITICAL)
    ])
    exposure = CriticalAssetExposure(
        asset_id="critical:crit-db-01",
        name="Customer PII DB",
        category="CUSTOMER_PII",
        impact_score=95,
        hop_depth=3,
        shortest_path_nodes=["user:usr-101", "device:dev-ws-109", "server:srv-app-01", "critical:crit-db-01"]
    )
    result = BlastRadiusResult(
        start_node=start,
        max_hops_evaluated=3,
        direction=TraversalDirection.OUTGOING,
        hop_1=hop_1,
        hop_2=hop_2,
        hop_3=hop_3,
        total_reachable_nodes=3,
        critical_assets_at_risk=[exposure],
        summary_assessment="Compromise exposes 1 Crown Jewel at depth 3."
    )
    assert result.total_reachable_nodes == 3
    assert len(result.critical_assets_at_risk) == 1
    assert result.critical_assets_at_risk[0].hop_depth == 3


# =====================================================================
# 6. ATTACK-PATH & CHOKE-POINT CONTRACT TESTS
# =====================================================================

def test_attack_path_result_models():
    step = AttackPathStep(
        step_number=1,
        source_id="device:dev-ws-109",
        target_id="server:srv-app-01",
        relationship_type=RelationshipType.LOGGED_IN_TO,
        evidence_class=EvidenceClass.OBSERVED,
        provenance="Windows Event Log 4624",
        description="Active logon session observed from workstation"
    )
    path = AttackPathItem(
        path_id="PATH-01",
        target_id="critical:crit-db-01",
        target_name="Financial Records DB",
        length=2,
        risk_score=85,
        nodes=[
            EnterpriseNode(id="device:dev-ws-109", label=NodeLabel.DEVICE, name="WS-FIN-109"),
            EnterpriseNode(id="server:srv-app-01", label=NodeLabel.SERVER, name="App Server 01"),
            EnterpriseNode(id="critical:crit-db-01", label=NodeLabel.CRITICAL_ASSET, name="DB Server")
        ],
        steps=[step],
        observed_steps_count=1,
        hypothetical_steps_count=0,
        assumptions=["Attacker utilizes established session credentials."]
    )
    res = AttackPathResult(
        entry_node=EnterpriseNode(id="device:dev-ws-109", label=NodeLabel.DEVICE, name="WS-FIN-109"),
        total_paths_discovered=1,
        paths=[path],
        targets_reached=["critical:crit-db-01"]
    )
    assert res.total_paths_discovered == 1
    assert res.paths[0].risk_score == 85
    assert "Candidate paths" in res.methodology_note


def test_choke_point_result_models():
    item = ChokePointItem(
        rank=1,
        entity_id="server:srv-app-01",
        entity_label="Application Server 01",
        entity_type="Server",
        paths_traversed_count=4,
        traversal_percentage=80.0,
        affected_critical_assets=["critical:crit-db-01", "critical:crit-pii-02"],
        recommended_action=InterventionAction.ISOLATE_NODE,
        intervention_details="Isolate SRV-APP-01 to sever 80% of inbound attack paths."
    )
    res = ChokePointResult(
        total_paths_analyzed=5,
        choke_points=[item],
        top_recommendation=item,
        explanation="Calculated path intersection across candidate attack vectors."
    )
    assert res.total_paths_analyzed == 5
    assert res.top_recommendation.traversal_percentage == 80.0


# =====================================================================
# 7. WHAT-IF CONTAINMENT SIMULATION CONTRACT TESTS
# =====================================================================

def test_containment_simulation_contract_guarantees():
    """Verifies that simulation contracts preserve the strict live_graph_modified=False guarantee."""
    intervention = ProposedIntervention(
        action=InterventionAction.ISOLATE_NODE,
        node_id="server:srv-app-01",
        rationale="Sever primary lateral jump point"
    )
    req = ContainmentSimulationRequest(
        entry_node_id="device:dev-ws-109",
        target_asset_ids=["critical:crit-db-01"],
        proposed_interventions=[intervention]
    )
    assert len(req.proposed_interventions) == 1

    sim_res = ContainmentSimulationResult(
        simulation_id="SIM-2026-001",
        live_graph_modified=False,
        proposed_interventions=[intervention],
        baseline_paths_count=4,
        remaining_paths_count=0,
        paths_eliminated_count=4,
        containment_efficiency_pct=100.0,
        path_statuses=[
            SimulatedPathStatus(path_id="PATH-01", target_id="critical:crit-db-01", status="ELIMINATED", severed_at_step="server:srv-app-01 isolated")
        ],
        residual_exposed_assets=[],
        analyst_verdict="100% containment achieved; Crown Jewel CRIT-DB-01 is fully protected."
    )
    # Critical architectural invariant: simulation must NEVER mutate live graph
    assert sim_res.live_graph_modified is False
    assert sim_res.containment_efficiency_pct == 100.0
    assert "SIMULATION ONLY" in sim_res.safety_disclaimer


# =====================================================================
# 8. CASE-TO-ORGANIZATION BRIDGE CONTRACT TESTS
# =====================================================================

def test_case_bridge_contract():
    mapping = BridgeMappingItem(
        evidence_type="RECIPIENT_EMAIL",
        raw_value="alice@corporation.com",
        mapped_node_id="user:alice@corporation.com",
        node_label=NodeLabel.USER,
        match_confidence=1.0,
        match_rationale="Exact verified match against corporate user directory"
    )
    resp = CaseBridgeResponse(
        case_id="MT-101",
        primary_compromised_node=EnterpriseNode(
            id="user:alice@corporation.com",
            label=NodeLabel.USER,
            name="Alice Johnson"
        ),
        mapped_entities=[mapping],
        unmapped_external_iocs=["185.190.140.22", "alert-center.xyz"],
        recommended_blast_radius_url="/api/v1/graphops/blast-radius?start_node_id=user:alice@corporation.com"
    )
    assert resp.case_id == "MT-101"
    assert resp.primary_compromised_node.id == "user:alice@corporation.com"
    assert "185.190.140.22" in resp.unmapped_external_iocs
