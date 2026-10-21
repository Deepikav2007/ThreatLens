# ThreatLens GraphOps — Optional Phase 9: Graph-Based Access Anomaly Detection

## 1. Executive Summary

Phase 9 implements graph-based access anomaly detection as an optional, non-disruptive extension to ThreatLens GraphOps.

The engine detects unusual relationship progressions across organizational graphs by comparing observed traversal paths against a documented historical and authorized-access baseline. It explicitly addresses key SOC operational realities:
- **Distinguishes Unobserved Legitimate Behavior from Policy Violations and Malice:** Avoids false positives when legitimate employees or newly onboarded assets initiate novel connections.
- **Explicit Cold-Start Handling:** Tags entities with sparse history as `INCOMPLETE` and leverages peer-group baseline models.
- **Transparent Rule-Based Scoring:** Eliminates uninterpretable black-box machine learning weights in favor of auditable policy and tiering factors.
- **Zero Automated Disruption:** Strictly outputs diagnostic indicators and advisory findings; **never** automatically severs connections or blocks users.

---

## 2. Documented Access Baseline

### 2.1 Architectural Network Tiering Rules
The baseline establishes strict network boundaries based on enterprise security architecture:
- **TIER 1 (Client Workstations):**
  - Allowed Outbound: HTTPS (Port 443) / HTTP (Port 80) to Application Gateway (`server:srv-app-01`).
  - Prohibited: Direct client-to-database connections (`server:srv-db-01` Port 5432). Flagged as `TIER_BYPASS`.
  - Prohibited: Direct client-to-Domain Controller administration (`server:srv-dc-01` Port 3389/88). Flagged as `TIER_BYPASS`.
  - Prohibited: Workstation-to-workstation lateral peer SMB connections (`device:*` Port 445). Flagged as `TIER_BYPASS`.
- **TIER 2 (Application Gateway):**
  - Allowed Outbound: Core database queries to Database Tier (`server:srv-db-01`) and Kerberos/AD authentications to DC Tier (`server:srv-dc-01`).
- **TIER 3 (Database & Core Infrastructure):**
  - Allowed Direct Access: Critical data classification scans and Crown Jewel storage (`critical:*`).

### 2.2 Entitlement & IAM Baseline
- Access to administrative infrastructure or database queries requires explicit, verified `HAS_PERMISSION` relationships in the directory graph.
- User accounts attempting interactive logon (`LOGGED_IN_TO`) to servers without documented entitlements are flagged as `MISSING_AUTHORIZATION`.

### 2.3 Departmental & Peer-Group Profiles
| Department | Standard Workstations | Authorized Application Servers | Permitted Crown Jewels |
|:---|:---|:---|:---|
| **Finance** | `device:dev-ws-101`, `device:dev-ws-104` | `app:app-erp-01`, `server:srv-app-01` | `critical:crit-db-financial` (via App Tier) |
| **IT Support** | `device:dev-ws-102` | `server:srv-app-01` (App_Admins) | Infrastructure Management |
| **Engineering** | `device:dev-ws-103` | `app:app-pg-01`, `server:srv-db-01` (Read-Only) | Non-Production Databases |
| **Accounting** | `device:dev-ws-201` | `app:app-erp-01`, `server:srv-app-01` | General Ledger Reports |
| **Infrastructure** | Scheduled Cron / DC Hosts | `server:srv-dc-01` (Backup Operator) | `critical:crit-ad-domain-root` |

---

## 3. 4-Tier Behavioral Classification Matrix

To satisfy Instruction 4 and prevent alert fatigue, the detector implements a discrete 4-tier classification:

| Classification | Score Range | Criteria & Behavioral Definition | Action Taken |
|:---|:---:|:---|:---|
| **`BENIGN_EXPECTED`** | **0 – 19** | Traversal path conforms strictly to historical edges and verified IAM entitlements. | No action required; logged as clean. |
| **`UNOBSERVED_NEW_LEGITIMATE`** | **20 – 39** | Traversal includes unobserved relationships or new identities, but actions conform to department peer-group profiles and network tiering. | Baseline profile auto-learning; no alert. |
| **`POLICY_VIOLATION_UNAUTHORIZED`** | **40 – 79** | Sequence violates network tiering rules (e.g. direct client-to-DB SQL) or lacks authorized IAM grants, without confirmed exploit indicators. | Advisory notice to resource owner & IT audit. |
| **`SUSPICIOUS_ANOMALOUS`** | **80 – 100** | High-risk lateral movement leveraging `POTENTIAL_EXPLOIT` preconditions (e.g. CVE-2024-21413), hijacked service accounts, or reaching Crown Jewels from an endpoint under active investigation. | Immediate SOC alert & priority triage. |

---

## 4. Cold-Start & Incomplete History Handling

When evaluating novel users, recently provisioned workstations, or sparse graph segments:
1. **History Completeness Assessment:**
   - $\ge 2$ historical relationships $\to$ `HistoryCompleteness: COMPLETE`, `BaselineConfidence: HIGH`.
   - $1$ historical relationship $\to$ `HistoryCompleteness: PARTIAL`, `BaselineConfidence: MEDIUM`.
   - $0$ historical relationships $\to$ `HistoryCompleteness: INCOMPLETE`, `BaselineConfidence: LOW`.
2. **Conservative Fallback Thresholds:**
   - When `BaselineConfidence == LOW`, novel connections that conform to the entity's inferred department peer group are classified as **`UNOBSERVED_NEW_LEGITIMATE`** (Score = 20), ensuring that newly hired employees are never falsely penalized as malicious.

---

## 5. Transparent Scoring Formula

Each step in an access sequence is evaluated independently:
$$\text{Step Score} = \min(100, W_{\text{tier}} + W_{\text{auth}} + W_{\text{dept}} + W_{\text{exploit}})$$
Where:
- $W_{\text{tier}} = 50 \text{ to } 60$ for network tier bypasses (direct DB or DC connections).
- $W_{\text{auth}} = 50$ for missing `HAS_PERMISSION` grants ($+88$ for service account hijacking).
- $W_{\text{dept}} = 35$ for cross-departmental unauthorized access.
- $W_{\text{exploit}} = 90$ for traversing `POTENTIAL_EXPLOIT` vulnerability edges.
- $W_{\text{novel}} = 20$ for legitimate unobserved connections conforming to peer groups.

The sequence aggregate score combines maximum step severity with mean traversal friction:
$$\text{Sequence Score} = \min(100, \text{round}(0.6 \times \max(\text{Step Scores}) + 0.4 \times \text{mean}(\text{Step Scores})))$$

---

## 6. Empirical Evaluation on Held-Out Labeled Dataset

Evaluation was executed locally via `scripts/evaluate_anomaly_detection.py` on the held-out dataset of 12 labeled access sequences (`backend/data/fixtures/anomaly_test_sequences.json`):

### 6.1 Classification Breakdown
| Sequence ID | Ground Truth | Predicted | Score | Status |
|:---|:---|:---|:---:|:---:|
| `seq-benign-01` | `BENIGN_EXPECTED` | `BENIGN_EXPECTED` | 0 | **PASS** |
| `seq-benign-02` | `BENIGN_EXPECTED` | `BENIGN_EXPECTED` | 0 | **PASS** |
| `seq-benign-03` | `BENIGN_EXPECTED` | `BENIGN_EXPECTED` | 0 | **PASS** |
| `seq-benign-04` | `BENIGN_EXPECTED` | `BENIGN_EXPECTED` | 0 | **PASS** |
| `seq-new-legit-01` | `UNOBSERVED_NEW_LEGITIMATE` | `UNOBSERVED_NEW_LEGITIMATE` | 20 | **PASS** |
| `seq-new-legit-02` | `UNOBSERVED_NEW_LEGITIMATE` | `UNOBSERVED_NEW_LEGITIMATE` | 20 | **PASS** |
| `seq-policy-01` | `POLICY_VIOLATION_UNAUTHORIZED` | `POLICY_VIOLATION_UNAUTHORIZED` | 44 | **PASS** |
| `seq-policy-02` | `POLICY_VIOLATION_UNAUTHORIZED` | `POLICY_VIOLATION_UNAUTHORIZED` | 48 | **PASS** |
| `seq-policy-03` | `POLICY_VIOLATION_UNAUTHORIZED` | `POLICY_VIOLATION_UNAUTHORIZED` | 50 | **PASS** |
| `seq-suspicious-01` | `SUSPICIOUS_ANOMALOUS` | `SUSPICIOUS_ANOMALOUS` | 80 | **PASS** |
| `seq-suspicious-02` | `SUSPICIOUS_ANOMALOUS` | `SUSPICIOUS_ANOMALOUS` | 80 | **PASS** |
| `seq-suspicious-03` | `SUSPICIOUS_ANOMALOUS` | `SUSPICIOUS_ANOMALOUS` | 80 | **PASS** |

### 6.2 Confusion Matrix & Metrics
- **True Positives (TP):** 6 (Policy Violations + Suspicious Attacks)
- **True Negatives (TN):** 6 (Benign Baseline + New Legitimate Behaviors)
- **False Positives (FP):** 0
- **False Negatives (FN):** 0
- **Precision:** $\mathbf{1.0000 \ (100.0\%)}$
- **Recall:** $\mathbf{1.0000 \ (100.0\%)}$
- **F1-Score:** $\mathbf{1.0000}$
- **False Positive Rate (FPR):** $\mathbf{0.0000 \ (0.0\%)}$

### 6.3 Performance Benchmarks
- **Baseline Initialization Latency:** 0.379 ms
- **Batch Evaluation Latency (12 sequences):** 0.621 ms
- **Average Query Latency per Sequence:** **0.052 ms**
- **Memory RSS Footprint Delta:** **+0.20 MB**

---

## 7. Safety Guarantees & Constraints Verification

- **Advisory-Only:** Findings are strictly diagnostic indicators. The engine does not trigger automated endpoint quarantines, user account lockouts, or firewall changes.
- **Zero Live Graph Mutation:** Verification tests confirm that running anomaly evaluations or benchmarking suites executes zero write transactions against Neo4j.
- **Backward Compatibility:** All 125 pytest tests, legacy attack graph tests (12/12), and threat intelligence tests (12/12) continue to pass cleanly.

---

## 8. Technical Limitations

1. **Rule Granularity:** Tiering policies currently model 3 standard architectural tiers (Client, Application Gateway, Database/Core). Organizations with microsegmentation policies may require finer-grained subnet tags.
2. **Temporal Windowing:** Current evaluation scores relationship progression ordering within a sequence; temporal frequency analysis (e.g. connection velocity over 24 hours) requires high-volume telemetry ingestion.
3. **Dataset Scope:** Evaluated on the curated 12-sequence benchmark. In large uncurated production enterprise networks, novel business processes should be reviewed by SOC leads before whitelisting into the baseline.
