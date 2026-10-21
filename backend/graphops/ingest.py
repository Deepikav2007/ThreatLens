"""
ThreatLens GraphOps - Data Ingestion and Construction Engine
Validates, normalizes, and idempotently imports enterprise entities and relationships into Neo4j.
Enforces canonical ID rules, validates endpoint references, tracks unresolved links,
and uses parameterized Cypher transactions with bounded batch sizes.
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
import logging
from pydantic import ValidationError

from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
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
    EnterpriseRelationship,
    BulkIngestPayload,
    IngestSummaryResponse,
)
from backend.graphops.client import Neo4jClient, get_graphops_client
from backend.data.graphops_fixtures import load_sample_enterprise_fixture

logger = logging.getLogger("threatlens.graphops.ingest")

BATCH_SIZE = 50


class GraphOpsIngestionEngine:
    """
    Ingests and normalizes enterprise graph datasets into Neo4j with full validation and idempotency.
    """

    def __init__(self, client: Optional[Neo4jClient] = None):
        self.client = client or get_graphops_client()

    def validate_entity(self, label: NodeLabel, raw_data: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Validates raw dictionary data against the corresponding Pydantic entity model.
        Returns (normalized_node_dict, None) or (None, error_message).
        """
        try:
            if label == NodeLabel.USER:
                node = UserNode(**raw_data)
                props = {
                    "id": node.id,
                    "user_id": node.user_id,
                    "email": node.email,
                    "name": node.name,
                    "department": node.department,
                    "role": node.role,
                    "is_service_account": node.is_service_account,
                    "is_admin": node.is_admin,
                    "status": node.status,
                }
            elif label == NodeLabel.DEVICE:
                node = DeviceNode(**raw_data)
                props = {
                    "id": node.id,
                    "device_id": node.device_id,
                    "hostname": node.hostname,
                    "ip_address": node.ip_address,
                    "mac_address": node.mac_address or "",
                    "os": node.os,
                    "subnet": node.subnet or "",
                    "is_isolated": node.is_isolated,
                    "criticality": node.criticality.value,
                }
            elif label == NodeLabel.SERVER:
                node = ServerNode(**raw_data)
                props = {
                    "id": node.id,
                    "server_id": node.server_id,
                    "name": node.name,
                    "hostname": node.hostname,
                    "ip_address": node.ip_address,
                    "tier": node.tier,
                    "environment": node.environment,
                    "criticality": node.criticality.value,
                    "is_isolated": node.is_isolated,
                }
            elif label == NodeLabel.APPLICATION:
                node = ApplicationNode(**raw_data)
                props = {
                    "id": node.id,
                    "app_id": node.app_id,
                    "name": node.name,
                    "version": node.version or "",
                    "port": node.port if node.port is not None else 0,
                    "service_type": node.service_type,
                    "environment": node.environment,
                }
            elif label == NodeLabel.IP_ADDRESS:
                node = IpAddressNode(**raw_data)
                props = {
                    "id": node.id,
                    "ip": node.ip,
                    "version": node.version,
                    "scope": node.scope,
                    "subnet": node.subnet or "",
                    "is_monitored": node.is_monitored,
                }
            elif label == NodeLabel.VULNERABILITY:
                node = VulnerabilityNode(**raw_data)
                props = {
                    "id": node.id,
                    "cve_id": node.cve_id,
                    "cvss_score": node.cvss_score,
                    "severity": node.severity.value,
                    "description": node.description,
                    "exploit_available": node.exploit_available,
                    "patch_available": node.patch_available,
                }
            elif label == NodeLabel.CRITICAL_ASSET:
                node = CriticalAssetNode(**raw_data)
                props = {
                    "id": node.id,
                    "asset_id": node.asset_id,
                    "name": node.name,
                    "category": node.category,
                    "impact_score": node.impact_score,
                    "data_classification": node.data_classification.value,
                    "owner_department": node.owner_department,
                }
            elif label == NodeLabel.SECURITY_EVENT:
                node = SecurityEventNode(**raw_data)
                props = {
                    "id": node.id,
                    "event_id": node.event_id,
                    "event_type": node.event_type,
                    "severity": node.severity.value,
                    "timestamp": node.timestamp,
                    "case_id": node.case_id or "",
                    "provenance": node.provenance,
                }
            else:
                return None, f"Unsupported entity label: {label}"

            # Merge extra metadata fields if present
            extra_data = raw_data.get("data")
            if isinstance(extra_data, dict):
                for k, v in extra_data.items():
                    if k not in props and isinstance(v, (str, int, float, bool)):
                        props[k] = v

            return {"label": label.value, "id": props["id"], "properties": props}, None
        except ValidationError as e:
            err_msg = "; ".join(f"{err['loc'][0]}: {err['msg']}" for err in e.errors() if 'loc' in err)
            return None, f"Validation failure for {label.value} ({raw_data.get('id', 'unknown')}): {err_msg}"
        except Exception as e:
            return None, f"Failed to parse {label.value} ({raw_data.get('id', 'unknown')}): {str(e)}"

    def validate_relationship(
        self,
        raw_rel: Dict[str, Any],
        known_node_ids: Set[str],
        id_aliases: Optional[Dict[str, str]] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Validates relationship structure and ensures source and target exist.
        Resolves entity aliases (e.g. user:email -> user:id) and normalizes vulnerability case.
        Prevents manufactured or broken links.
        """
        rel_data = dict(raw_rel)
        src = str(rel_data.get("source_id", "")).strip()
        tgt = str(rel_data.get("target_id", "")).strip()

        # Resolve aliases if present
        if id_aliases:
            src = id_aliases.get(src, src)
            tgt = id_aliases.get(tgt, tgt)

        # Normalize CVE case
        if src.lower().startswith("vuln:cve-"):
            src = "vuln:" + src[5:].upper()
        if tgt.lower().startswith("vuln:cve-"):
            tgt = "vuln:" + tgt[5:].upper()

        rel_data["source_id"] = src
        rel_data["target_id"] = tgt

        try:
            rel = EnterpriseRelationship(**rel_data)
        except ValidationError as e:
            err_msg = "; ".join(f"{err['loc'][0]}: {err['msg']}" for err in e.errors())
            return None, f"Relationship validation failed: {err_msg}"

        # Reference verification: Ensure source and target endpoints exist
        if rel.source_id not in known_node_ids:
            return None, f"Unresolved relationship reference: source_id '{rel.source_id}' does not exist."
        if rel.target_id not in known_node_ids:
            return None, f"Unresolved relationship reference: target_id '{rel.target_id}' does not exist."

        props = {
            "id": rel.id,
            "source_id": rel.source_id,
            "target_id": rel.target_id,
            "relationship_type": rel.relationship_type.value,
            "evidence_class": rel.evidence_class.value,
            "source_record_id": rel.source_record_id or "",
            "provenance": rel.provenance,
            "timestamp": rel.timestamp or "",
            "confidence": rel.confidence,
        }
        if rel.properties:
            for k, v in rel.properties.items():
                if isinstance(v, (str, int, float, bool)):
                    props[k] = v

        return {
            "type": rel.relationship_type.value,
            "source_id": rel.source_id,
            "target_id": rel.target_id,
            "properties": props
        }, None

    def ingest_payload(self, payload: BulkIngestPayload) -> IngestSummaryResponse:
        """
        Idempotently ingests validated entities and relationships into Neo4j.
        Splits operations into bounded transactional batches.
        """
        # Ensure schema constraints and indexes exist before loading data
        self.client.init_schema_constraints()

        nodes_imported = 0
        nodes_updated = 0
        nodes_rejected = 0
        relationships_imported = 0
        relationships_updated = 0
        relationships_rejected = 0
        errors: List[str] = []

        validated_nodes_by_label: Dict[str, List[Dict[str, Any]]] = {}
        known_node_ids: Set[str] = set()
        id_aliases: Dict[str, str] = {}

        # Pre-query existing node IDs from the database to allow relationships to link to existing assets
        try:
            existing_records = self.client.execute_query("MATCH (n) RETURN n.id AS id, n.email AS email")
            for r in existing_records:
                if r.get("id"):
                    known_node_ids.add(r["id"])
                if r.get("email"):
                    id_aliases[f"user:{r['email'].lower()}"] = r["id"]
        except Exception as e:
            logger.warning(f"Could not pre-fetch existing node IDs (database may be empty or starting up): {e}")

        # 1. Process & Validate Nodes
        entity_sources = [
            (NodeLabel.USER, payload.entities.users),
            (NodeLabel.DEVICE, payload.entities.devices),
            (NodeLabel.SERVER, payload.entities.servers),
            (NodeLabel.APPLICATION, payload.entities.applications),
            (NodeLabel.IP_ADDRESS, payload.entities.ips),
            (NodeLabel.VULNERABILITY, payload.entities.vulnerabilities),
            (NodeLabel.CRITICAL_ASSET, payload.entities.critical_assets),
            (NodeLabel.SECURITY_EVENT, payload.entities.security_events),
        ]

        for label, entity_list in entity_sources:
            validated_nodes_by_label[label.value] = []
            for item in entity_list:
                item_dict = item.model_dump() if hasattr(item, "model_dump") else dict(item)
                valid_node, err = self.validate_entity(label, item_dict)
                if err:
                    nodes_rejected += 1
                    errors.append(err)
                else:
                    validated_nodes_by_label[label.value].append(valid_node)
                    canonical_id = valid_node["id"]
                    known_node_ids.add(canonical_id)
                    # Register user email and ID aliases for clean reference resolution
                    if label == NodeLabel.USER:
                        email = item_dict.get("email")
                        uid = item_dict.get("user_id")
                        if email:
                            id_aliases[f"user:{email.lower()}"] = canonical_id
                            id_aliases[email.lower()] = canonical_id
                        if uid:
                            id_aliases[f"user:{uid.lower()}"] = canonical_id
                            id_aliases[uid.lower()] = canonical_id

        # Ingest nodes into Neo4j using bounded batches
        now_ts = datetime.now(timezone.utc).isoformat()
        for label_name, nodes in validated_nodes_by_label.items():
            if not nodes:
                continue

            for i in range(0, len(nodes), BATCH_SIZE):
                batch = nodes[i : i + BATCH_SIZE]
                cypher = f"""
                UNWIND $batch AS item
                MERGE (n:{label_name} {{id: item.id}})
                ON CREATE SET n += item.properties, n.created_at = $timestamp
                ON MATCH SET n += item.properties, n.updated_at = $timestamp
                """
                params = {"batch": batch, "timestamp": now_ts}
                counters = self.client.execute_write(cypher, params)
                nodes_imported += counters.get("nodes_created", 0)
                # If node already existed, properties were set on match
                if counters.get("nodes_created", 0) < len(batch):
                    nodes_updated += (len(batch) - counters.get("nodes_created", 0))

        # 2. Process & Validate Relationships
        all_resolvable_ids = known_node_ids.union(id_aliases.keys())
        validated_rels_by_type: Dict[str, List[Dict[str, Any]]] = {}
        for rel in payload.relationships.relationships:
            rel_dict = rel.model_dump() if hasattr(rel, "model_dump") else dict(rel)
            valid_rel, err = self.validate_relationship(rel_dict, all_resolvable_ids, id_aliases)
            if err:
                relationships_rejected += 1
                errors.append(err)
            else:
                rel_type = valid_rel["type"]
                if rel_type not in validated_rels_by_type:
                    validated_rels_by_type[rel_type] = []
                validated_rels_by_type[rel_type].append(valid_rel)

        # Ingest relationships into Neo4j using bounded batches
        for rel_type, rel_list in validated_rels_by_type.items():
            for i in range(0, len(rel_list), BATCH_SIZE):
                batch = rel_list[i : i + BATCH_SIZE]
                cypher = f"""
                UNWIND $batch AS rel
                MATCH (s {{id: rel.source_id}})
                MATCH (t {{id: rel.target_id}})
                MERGE (s)-[r:{rel_type}]->(t)
                ON CREATE SET r += rel.properties, r.created_at = $timestamp
                ON MATCH SET r += rel.properties, r.updated_at = $timestamp
                """
                params = {"batch": batch, "timestamp": now_ts}
                counters = self.client.execute_write(cypher, params)
                relationships_imported += counters.get("relationships_created", 0)
                if counters.get("relationships_created", 0) < len(batch):
                    relationships_updated += (len(batch) - counters.get("relationships_created", 0))

        status = "SUCCESS"
        if errors and (nodes_imported > 0 or relationships_imported > 0):
            status = "PARTIAL"
        elif errors and nodes_imported == 0 and relationships_imported == 0:
            status = "FAILED"

        return IngestSummaryResponse(
            status=status,
            dataset_name=payload.dataset_name,
            nodes_imported=nodes_imported,
            nodes_updated=nodes_updated,
            nodes_rejected=nodes_rejected,
            relationships_imported=relationships_imported,
            relationships_updated=relationships_updated,
            relationships_rejected=relationships_rejected,
            errors=errors,
            timestamp=now_ts,
        )

    def ingest_sample_fixture(self) -> IngestSummaryResponse:
        """
        Loads and ingests the default synthetic SOC enterprise security graph fixture.
        """
        raw_json = load_sample_enterprise_fixture()
        payload = BulkIngestPayload(**raw_json)
        return self.ingest_payload(payload)

    def get_graph_summary(self) -> Dict[str, Any]:
        """
        Queries and returns comprehensive topological metrics of the organizational security graph.
        """
        node_count_records = self.client.execute_query(
            "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC"
        )
        node_counts = {r["label"]: r["count"] for r in node_count_records if r.get("label")}

        rel_count_records = self.client.execute_query(
            "MATCH ()-[r]->() RETURN type(r) AS rel_type, count(r) AS count ORDER BY count DESC"
        )
        rel_counts = {r["rel_type"]: r["count"] for r in rel_count_records if r.get("rel_type")}

        critical_records = self.client.execute_query(
            "MATCH (c:CriticalAsset) RETURN c.id AS id, c.name AS name, c.impact_score AS impact, c.category AS category"
        )

        return {
            "total_nodes": sum(node_counts.values()),
            "total_relationships": sum(rel_counts.values()),
            "node_counts_by_label": node_counts,
            "relationship_counts_by_type": rel_counts,
            "critical_assets": critical_records,
            "status": "POPULATED" if node_counts else "EMPTY",
        }


# Global default ingestion service
default_ingestion_engine = GraphOpsIngestionEngine()


def run_sample_ingestion() -> IngestSummaryResponse:
    """Convenience helper to run sample ingestion via python script."""
    engine = GraphOpsIngestionEngine()
    return engine.ingest_sample_fixture()


if __name__ == "__main__":
    import json
    print("=" * 65)
    print("THREATLENS GRAPHOPS - SAMPLE ENTERPRISE INGESTION")
    print("=" * 65)
    summary = run_sample_ingestion()
    print(json.dumps(summary.model_dump(), indent=2))
