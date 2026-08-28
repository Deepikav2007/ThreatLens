"""
MailTrace AI - Campaign Correlation Engine
Feature 6: Attack Graph + Campaign Correlation
"""

from typing import List, Dict, Tuple, Optional, Any, Set
from collections import defaultdict

from backend.models.graph import (
    SharedIndicator,
    CampaignCluster,
    CampaignCorrelationResult,
    CaseRecord
)
from backend.services.case_store import default_case_repo


class CampaignCorrelationEngine:
    """
    Transparent, rule-based correlation engine that detects coordinated phishing/malware campaigns
    across multiple email cases without black-box ML or unsupported attribution.
    """
    # Transparent correlation score weights
    WEIGHT_SHARED_IP = 30
    WEIGHT_SHARED_DOMAIN = 25
    WEIGHT_SHARED_URL = 30
    WEIGHT_SHARED_HASH = 35
    WEIGHT_SHARED_HOSTNAME = 20

    def __init__(self, case_repo=default_case_repo):
        self.repo = case_repo

    def calculate_pairwise_correlation(self, case_a: CaseRecord, case_b: CaseRecord) -> Tuple[int, List[SharedIndicator], List[str]]:
        """
        Calculates correlation score and evidence reasons between two email cases.
        """
        score = 0
        shared_iocs: List[SharedIndicator] = []
        reasons: List[str] = []

        # 1. Compare IP addresses (Skip private/local IPs from scoring)
        ips_a = set(case_a.iocs.get("ips", []))
        ips_b = set(case_b.iocs.get("ips", []))
        common_ips = ips_a.intersection(ips_b)
        public_common_ips = [ip for ip in common_ips if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."))]
        
        if public_common_ips:
            score += self.WEIGHT_SHARED_IP * len(public_common_ips)
            for ip in public_common_ips:
                shared_iocs.append(SharedIndicator(type="ip", value=ip, occurrences=2, case_ids=[case_a.case_id, case_b.case_id]))
                reasons.append(f"Shared originating infrastructure IP: {ip} (+{self.WEIGHT_SHARED_IP} pts)")

        # 2. Compare Domains
        doms_a = set(case_a.iocs.get("domains", []))
        doms_b = set(case_b.iocs.get("domains", []))
        # Exclude ubiquitous internal corporate domain if needed
        common_doms = [d for d in doms_a.intersection(doms_b) if d not in ["corporation.com", "gmail.com", "microsoft.com"]]
        if common_doms:
            score += self.WEIGHT_SHARED_DOMAIN * len(common_doms)
            for d in common_doms:
                shared_iocs.append(SharedIndicator(type="domain", value=d, occurrences=2, case_ids=[case_a.case_id, case_b.case_id]))
                reasons.append(f"Shared deceptive/external domain: {d} (+{self.WEIGHT_SHARED_DOMAIN} pts)")

        # 3. Compare URLs
        urls_a = set(case_a.iocs.get("urls", []))
        urls_b = set(case_b.iocs.get("urls", []))
        common_urls = urls_a.intersection(urls_b)
        if common_urls:
            score += self.WEIGHT_SHARED_URL * len(common_urls)
            for u in common_urls:
                shared_iocs.append(SharedIndicator(type="url", value=u, occurrences=2, case_ids=[case_a.case_id, case_b.case_id]))
                reasons.append(f"Identical target landing URL: {u} (+{self.WEIGHT_SHARED_URL} pts)")

        # 4. Compare Attachment Hashes
        hashes_a = set(case_a.iocs.get("hashes", []))
        hashes_b = set(case_b.iocs.get("hashes", []))
        common_hashes = hashes_a.intersection(hashes_b)
        if common_hashes:
            score += self.WEIGHT_SHARED_HASH * len(common_hashes)
            for h in common_hashes:
                shared_iocs.append(SharedIndicator(type="hash", value=h, occurrences=2, case_ids=[case_a.case_id, case_b.case_id]))
                reasons.append(f"Identical binary payload hash signature: {h[:16]}... (+{self.WEIGHT_SHARED_HASH} pts)")

        # Cap score at 100
        final_score = min(100, score)
        return final_score, shared_iocs, reasons

    def cluster_all_cases(self) -> List[CampaignCluster]:
        """
        Clusters all stored cases into campaign groups using graph component connectivity.
        """
        all_cases = self.repo.list_cases()
        if not all_cases:
            return []

        # Graph adjacency: case_id -> set of connected case_ids
        adj: Dict[str, Set[str]] = defaultdict(set)
        pair_data: Dict[Tuple[str, str], Tuple[int, List[SharedIndicator], List[str]]] = {}

        # Pairwise evaluation
        for i in range(len(all_cases)):
            for j in range(i + 1, len(all_cases)):
                c1 = all_cases[i]
                c2 = all_cases[j]
                c_score, shared_list, r_list = self.calculate_pairwise_correlation(c1, c2)
                if c_score >= 30:  # Meaningful relationship threshold
                    adj[c1.case_id].add(c2.case_id)
                    adj[c2.case_id].add(c1.case_id)
                    pair_data[(c1.case_id, c2.case_id)] = (c_score, shared_list, r_list)
                    pair_data[(c2.case_id, c1.case_id)] = (c_score, shared_list, r_list)

        # Connected component search (BFS)
        visited: Set[str] = set()
        clusters: List[CampaignCluster] = []
        cluster_idx = 1

        for case in all_cases:
            if case.case_id not in visited and case.case_id in adj:
                group: List[str] = []
                queue = [case.case_id]
                visited.add(case.case_id)

                while queue:
                    curr = queue.pop(0)
                    group.append(curr)
                    for neighbor in adj[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)

                if len(group) >= 2:
                    # Aggregate cluster metadata
                    group_cases = [c for c in all_cases if c.case_id in group]
                    shared_iocs_map: Dict[str, SharedIndicator] = {}
                    all_reasons: Set[str] = set()
                    max_score = 0

                    for i in range(len(group)):
                        for j in range(i + 1, len(group)):
                            pair_k = (group[i], group[j])
                            if pair_k in pair_data:
                                s, ioc_l, r_l = pair_data[pair_k]
                                max_score = max(max_score, s)
                                for ind in ioc_l:
                                    k = f"{ind.type}:{ind.value}"
                                    if k not in shared_iocs_map:
                                        shared_iocs_map[k] = SharedIndicator(
                                            type=ind.type,
                                            value=ind.value,
                                            occurrences=len(group),
                                            case_ids=group
                                        )
                                for r in r_l:
                                    all_reasons.add(r)

                    # Determine status
                    if max_score >= 70:
                        status = "STRONG_CAMPAIGN"
                    elif max_score >= 50:
                        status = "LIKELY_RELATED"
                    else:
                        status = "POSSIBLE_RELATIONSHIP"

                    # Primary threat
                    primary_threat = group_cases[0].primary_threat if group_cases else "PHISHING"
                    name = f"Campaign {primary_threat} Cluster #{cluster_idx}"

                    clusters.append(CampaignCluster(
                        campaign_id=f"CMP-{cluster_idx:03d}",
                        name=name,
                        status=status,
                        correlation_score=max_score,
                        case_ids=group,
                        primary_threat=primary_threat,
                        shared_indicators=list(shared_iocs_map.values()),
                        reasons=list(all_reasons),
                        first_seen=min(c.timestamp for c in group_cases),
                        last_seen=max(c.timestamp for c in group_cases)
                    ))
                    cluster_idx += 1

        return clusters

    def correlate_current_case(self, case_record: CaseRecord) -> CampaignCorrelationResult:
        """
        Indexes the current case in storage and resolves its campaign correlation against all historical records.
        """
        self.repo.save_case(case_record)
        all_campaigns = self.cluster_all_cases()

        # Find if current case is in any campaign
        matched_campaign = None
        for camp in all_campaigns:
            if case_record.case_id in camp.case_ids:
                matched_campaign = camp
                break

        return CampaignCorrelationResult(
            current_case_campaign=matched_campaign,
            all_campaigns=all_campaigns,
            total_cases_indexed=len(self.repo.list_cases()),
            total_campaigns_detected=len(all_campaigns)
        )

    def search_ioc(self, query: str) -> Dict[str, Any]:
        """
        Cross-email search across stored investigations for an indicator string.
        """
        clean_q = query.strip()
        matching_cases = self.repo.find_cases_by_ioc(clean_q)
        all_campaigns = self.cluster_all_cases()

        matching_campaigns = []
        matching_case_ids = {c.case_id for c in matching_cases}
        for camp in all_campaigns:
            if any(cid in matching_case_ids for cid in camp.case_ids) or \
               any(clean_q.lower() == ind.value.lower() for ind in camp.shared_indicators):
                matching_campaigns.append(camp)

        return {
            "query": clean_q,
            "total_matches": len(matching_cases),
            "matching_cases": matching_cases,
            "matching_campaigns": matching_campaigns
        }


# Global campaign correlation engine instance
default_correlation_engine = CampaignCorrelationEngine()
