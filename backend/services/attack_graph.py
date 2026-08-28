"""
MailTrace AI - Attack Graph Builder Service
Feature 6: Attack Graph + Campaign Correlation
"""

from typing import List, Dict, Optional, Any, Set
from backend.models.graph import GraphNode, GraphEdge, AttackGraph, CampaignCluster, CaseRecord
from backend.models.forensics import ForensicEvidenceResult
from backend.models.ioc import IocExtractionResult
from backend.models.intel import ThreatIntelligenceResult, IocIntelligenceItem
from backend.models.threat import ThreatDetectionResult


class AttackGraphBuilder:
    """
    Constructs unified investigation relationship graphs from multi-feature forensic and intelligence outputs.
    """
    def __init__(self):
        pass

    def _get_intel_for_indicator(self, intel_res: Optional[ThreatIntelligenceResult], indicator_val: str) -> Optional[IocIntelligenceItem]:
        """Finds matching threat intelligence report for an indicator."""
        if not intel_res or not intel_res.results:
            return None
        target = indicator_val.strip().lower()
        for item in intel_res.results:
            if item.indicator.strip().lower() == target:
                return item
        return None

    def build_attack_graph_for_case(
        self,
        case_id: str,
        forensics: Optional[ForensicEvidenceResult],
        iocs: Optional[IocExtractionResult],
        intel: Optional[ThreatIntelligenceResult],
        threat_detection: Optional[ThreatDetectionResult],
        campaign_id: Optional[str] = None
    ) -> AttackGraph:
        """
        Builds a comprehensive investigation relationship graph for a single analyzed email.
        """
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        node_ids: Set[str] = set()
        edge_ids: Set[str] = set()

        def add_node(node: GraphNode):
            if node.id not in node_ids:
                node_ids.add(node.id)
                nodes.append(node)

        def add_edge(source: str, target: str, relationship: str, label: Optional[str] = None):
            edge_id = f"{source}->{target}:{relationship}"
            if edge_id not in edge_ids:
                edge_ids.add(edge_id)
                edges.append(GraphEdge(
                    id=edge_id,
                    source=source,
                    target=target,
                    relationship=relationship,
                    label=label or relationship.replace("_", " ").title()
                ))

        # 1. Root Email Node
        email_node_id = f"email:{case_id}"
        email_status = "UNKNOWN"
        if threat_detection:
            if threat_detection.risk_level in ["CRITICAL", "HIGH"]:
                email_status = "MALICIOUS"
            elif threat_detection.risk_level == "MEDIUM":
                email_status = "SUSPICIOUS"
            else:
                email_status = "CLEAN_REPORTED"

        subject = forensics.subject if forensics else "Analyzed Email Investigation"
        sender = forensics.sender_identity.from_address if forensics else "Unknown Sender"

        add_node(GraphNode(
            id=email_node_id,
            type="email",
            label=f"Case #{case_id}",
            status=email_status,
            data={
                "case_id": case_id,
                "subject": subject,
                "sender": sender,
                "threat_score": threat_detection.threat_score if threat_detection else 0,
                "risk_level": threat_detection.risk_level if threat_detection else "UNKNOWN",
                "primary_threat": threat_detection.primary_threat if threat_detection else "UNKNOWN"
            }
        ))

        # 2. Campaign Node Link (if associated)
        if campaign_id:
            camp_node_id = f"campaign:{campaign_id}"
            add_node(GraphNode(
                id=camp_node_id,
                type="campaign",
                label=f"Campaign {campaign_id}",
                status="MALICIOUS" if email_status == "MALICIOUS" else "SUSPICIOUS",
                data={"campaign_id": campaign_id}
            ))
            add_edge(email_node_id, camp_node_id, "PART_OF", "Part of Campaign")

        # 3. Domain Nodes
        if iocs and iocs.domains:
            for dom in iocs.domains:
                dom_node_id = f"domain:{dom.value}"
                dom_intel = self._get_intel_for_indicator(intel, dom.value)
                status = dom_intel.normalized_status if dom_intel else "UNKNOWN"

                add_node(GraphNode(
                    id=dom_node_id,
                    type="domain",
                    label=dom.value,
                    status=status,
                    data={
                        "domain": dom.value,
                        "registered_domain": dom.registered_domain,
                        "is_punycode": dom.is_punycode,
                        "intel": dom_intel.model_dump() if dom_intel else None
                    }
                ))
                add_edge(email_node_id, dom_node_id, "REFERENCES", "References Domain")

        # 4. URL Nodes & URL -> Domain Links
        if iocs and iocs.urls:
            for url in iocs.urls:
                url_node_id = f"url:{url.normalized}"
                url_intel = self._get_intel_for_indicator(intel, url.normalized)
                status = url_intel.normalized_status if url_intel else "UNKNOWN"

                add_node(GraphNode(
                    id=url_node_id,
                    type="url",
                    label=url.normalized if len(url.normalized) <= 35 else url.normalized[:32] + "...",
                    status=status,
                    data={
                        "url": url.normalized,
                        "hostname": url.hostname,
                        "path": url.path,
                        "intel": url_intel.model_dump() if url_intel else None
                    }
                ))
                add_edge(email_node_id, url_node_id, "CONTAINS", "Contains URL")

                # Connect URL to Domain if present
                if url.hostname:
                    dom_node_id = f"domain:{url.hostname}"
                    if dom_node_id in node_ids:
                        add_edge(url_node_id, dom_node_id, "HOSTED_ON", "Hosted On")

        # 5. IP Nodes & Domain -> IP / Email -> IP Links
        if iocs and iocs.ips:
            for ip in iocs.ips:
                ip_node_id = f"ip:{ip.value}"
                ip_intel = self._get_intel_for_indicator(intel, ip.value)
                status = ip_intel.normalized_status if ip_intel else ("UNKNOWN" if ip.scope != "private" else "CLEAN_REPORTED")

                add_node(GraphNode(
                    id=ip_node_id,
                    type="ip",
                    label=ip.value,
                    status=status,
                    data={
                        "ip": ip.value,
                        "scope": ip.scope,
                        "version": ip.version,
                        "intel": ip_intel.model_dump() if ip_intel else None
                    }
                ))
                # Connect directly to email if originating candidate or in relay
                add_edge(email_node_id, ip_node_id, "RECEIVED_FROM", f"Received from {ip.scope.title()} IP")

        # 6. SMTP Received Relay Transmission Chain
        if forensics and forensics.relay_path and len(forensics.relay_path) > 1:
            for i in range(len(forensics.relay_path) - 1):
                hop_curr = forensics.relay_path[i]
                hop_next = forensics.relay_path[i + 1]

                src_id = f"ip:{hop_curr.from_ip}" if hop_curr.from_ip else f"hostname:{hop_curr.from_host or f'hop_{i+1}'}"
                tgt_id = f"ip:{hop_next.from_ip}" if hop_next.from_ip else f"hostname:{hop_next.from_host or f'hop_{i+2}'}"

                # Ensure source & target exist as nodes
                if src_id not in node_ids:
                    add_node(GraphNode(
                        id=src_id,
                        type="hostname" if src_id.startswith("hostname:") else "ip",
                        label=hop_curr.from_ip or hop_curr.from_host or f"Hop #{i+1}",
                        status="UNKNOWN",
                        data={"relay_hop": hop_curr.hop_number}
                    ))
                if tgt_id not in node_ids:
                    add_node(GraphNode(
                        id=tgt_id,
                        type="hostname" if tgt_id.startswith("hostname:") else "ip",
                        label=hop_next.from_ip or hop_next.from_host or f"Hop #{i+2}",
                        status="UNKNOWN",
                        data={"relay_hop": hop_next.hop_number}
                    ))

                add_edge(src_id, tgt_id, "OBSERVED_RELAY", "Transmitted via SMTP")

        # 7. Attachment & Cryptographic Hash Nodes
        if forensics and forensics.attachments:
            for att in forensics.attachments:
                att_node_id = f"attachment:{att.filename}"
                has_warning = att.indicators and len(att.indicators) > 0
                att_status = "MALICIOUS" if has_warning else "CLEAN_REPORTED"

                add_node(GraphNode(
                    id=att_node_id,
                    type="attachment",
                    label=att.filename,
                    status=att_status,
                    data={
                        "filename": att.filename,
                        "size_bytes": att.size_bytes,
                        "sha256": att.sha256_hash,
                        "indicators": att.indicators
                    }
                ))
                add_edge(email_node_id, att_node_id, "HAS_ATTACHMENT", "Has Attachment")

                if att.sha256_hash:
                    hash_node_id = f"hash:{att.sha256_hash[:16]}"
                    hash_intel = self._get_intel_for_indicator(intel, att.sha256_hash)
                    hash_status = hash_intel.normalized_status if hash_intel else att_status

                    add_node(GraphNode(
                        id=hash_node_id,
                        type="hash",
                        label=f"SHA256: {att.sha256_hash[:8]}...",
                        status=hash_status,
                        data={
                            "hash": att.sha256_hash,
                            "algorithm": "SHA256",
                            "intel": hash_intel.model_dump() if hash_intel else None
                        }
                    ))
                    add_edge(att_node_id, hash_node_id, "CONTAINS", "Has Hash Signature")

        # Summary statistics
        stats = {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "malicious_nodes": sum(1 for n in nodes if n.status == "MALICIOUS"),
            "suspicious_nodes": sum(1 for n in nodes if n.status == "SUSPICIOUS"),
            "clean_nodes": sum(1 for n in nodes if n.status == "CLEAN_REPORTED")
        }

        return AttackGraph(
            case_id=case_id,
            nodes=nodes,
            edges=edges,
            stats=stats
        )

    def build_multi_case_campaign_graph(
        self,
        campaign: CampaignCluster,
        cases: List[CaseRecord]
    ) -> AttackGraph:
        """
        Builds a multi-case cluster graph showing convergence on shared infrastructure.
        """
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        node_ids: Set[str] = set()
        edge_ids: Set[str] = set()

        def add_node(node: GraphNode):
            if node.id not in node_ids:
                node_ids.add(node.id)
                nodes.append(node)

        def add_edge(source: str, target: str, relationship: str, label: Optional[str] = None):
            edge_id = f"{source}->{target}:{relationship}"
            if edge_id not in edge_ids:
                edge_ids.add(edge_id)
                edges.append(GraphEdge(
                    id=edge_id,
                    source=source,
                    target=target,
                    relationship=relationship,
                    label=label or relationship.replace("_", " ").title()
                ))

        # 1. Campaign Node
        camp_id = f"campaign:{campaign.campaign_id}"
        add_node(GraphNode(
            id=camp_id,
            type="campaign",
            label=f"Campaign: {campaign.name}",
            status="MALICIOUS" if campaign.correlation_score >= 70 else "SUSPICIOUS",
            data={
                "campaign_id": campaign.campaign_id,
                "correlation_score": campaign.correlation_score,
                "reasons": campaign.reasons
            }
        ))

        # 2. Shared Indicator Nodes
        for ind in campaign.shared_indicators:
            ind_node_id = f"{ind.type}:{ind.value}"
            add_node(GraphNode(
                id=ind_node_id,
                type=ind.type,
                label=ind.value if len(ind.value) <= 25 else ind.value[:22] + "...",
                status="MALICIOUS" if ind.type in ["domain", "ip", "url"] else "SUSPICIOUS",
                data={"shared_value": ind.value, "occurrences": ind.occurrences}
            ))
            add_edge(camp_id, ind_node_id, "SHARES_INFRASTRUCTURE", "Shared Infrastructure")

        # 3. Add each related email case and connect to shared indicators
        for case in cases:
            if case.case_id in campaign.case_ids:
                email_id = f"email:{case.case_id}"
                add_node(GraphNode(
                    id=email_id,
                    type="email",
                    label=f"Case #{case.case_id}",
                    status="MALICIOUS" if case.threat_score >= 70 else "SUSPICIOUS",
                    data={
                        "case_id": case.case_id,
                        "subject": case.subject,
                        "threat_score": case.threat_score,
                        "primary_threat": case.primary_threat
                    }
                ))
                add_edge(email_id, camp_id, "PART_OF", "Correlated in Campaign")

                # Connect case to any shared indicators it contains
                for ind in campaign.shared_indicators:
                    ind_node_id = f"{ind.type}:{ind.value}"
                    ioc_key = ind.type + "s" if ind.type in ["domain", "ip", "url", "hash"] else ind.type
                    if ioc_key in case.iocs and ind.value in case.iocs[ioc_key]:
                        add_edge(email_id, ind_node_id, "REFERENCES", "References")

        stats = {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "malicious_nodes": sum(1 for n in nodes if n.status == "MALICIOUS"),
            "suspicious_nodes": sum(1 for n in nodes if n.status == "SUSPICIOUS")
        }

        return AttackGraph(
            case_id=campaign.campaign_id,
            nodes=nodes,
            edges=edges,
            stats=stats
        )


# Global default attack graph builder
default_graph_builder = AttackGraphBuilder()
