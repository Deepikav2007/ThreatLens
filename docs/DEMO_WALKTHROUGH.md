# ThreatLens GraphOps — Hackathon Demo Walkthrough Guide

## Overview: The 3-Minute SOC Analyst Story
Modern security operations suffer from a critical visibility gap: **Email security tools stop at the inbox, while infrastructure graphs stop at directory permissions.** ThreatLens GraphOps bridges this divide in real time.

This guide provides a scripted, 5-stage demonstration showing how a single spear-phishing incident is traced from email headers through lateral enterprise attack pathways directly to Crown Jewel assets, followed by safe What-If containment simulation.

---

## Stage 1: The Initial Security Event (Email Forensic Pipeline)

### Action
1. Open ThreatLens in the browser: `http://localhost:8000`
2. Navigate to the **Email Forensics** tab.
3. Select Case **`MT-101`** (Urgent Account Verification Phishing).
4. Review the automated analysis:
   - **Threat Score:** `100/100` (Phishing / High Confidence)
   - **Threat Actor Infrastructure:** `185.190.140.22` (WorldStream B.V., Netherlands)
   - **Lure URL:** `http://secure-login.alert-center.xyz/auth/verify`
   - **Target Recipient:** `victim1@corporation.com` (Finance Department)

### Talking Point
> *"Traditional email gateways stop here—they flag the email as malicious and quarantine it. But in a modern SOC, the critical question is: **If the user clicked, what could an attacker actually reach inside our corporate network?**"*

---

## Stage 2: The Forensic-to-Graph Bridge

### Action
1. Click the **"Pivot to GraphOps Blast Radius"** button on Case `MT-101` (or navigate to `#/graphops?case_id=MT-101`).
2. Notice the automated correlation in the GraphOps workspace header:
   - Target User resolved: `user:usr-101` (Alice Vance - Financial Operations)
   - Assigned Corporate Device resolved: `device:dev-ws-101` (`ws-fin-101.corp`, 10.0.1.101)
   - External IOCs quarantined: `185.190.140.22` and `alert-center.xyz` are properly isolated outside internal directory boundaries.

### API Reference
```bash
curl -X GET "http://localhost:8000/api/v1/graphops/bridge/case/MT-101"
```

### Talking Point
> *"ThreatLens automatically pivots from email metadata to our organizational identity graph. It correlates the recipient email address with Alice Vance's Active Directory account and identifies her physical workstation as the initial ground-zero compromise point."*

---

## Stage 3: Multi-Hop Blast-Radius Visualization

### Action
1. In the GraphOps workspace, select Starting Node: `device:dev-ws-101`.
2. Set Max Hops to **3** and Traversal Direction to **OUTGOING**.
3. Toggle **"Include Hypothetical Vulnerability Edges"** ON.
4. Click **"Calculate Blast Radius"**.
5. Observe the Cytoscape graph canvas and the summary stats:
   - **1-Hop Frontier:** Gateway server `server:srv-app-01` (accessible via SSH and NTLM relay vulnerability `CVE-2024-21413`).
   - **2-Hop Frontier:** Core database server `server:srv-db-01`, Domain Controller `server:srv-dc-01`, and internal ERP system `app:app-erp-01`.
   - **3-Hop Frontier (Critical Assets):**
     - `critical:crit-db-financial` (Financial Records DB)
     - `critical:crit-pii-customer` (Customer PII Lake)
     - `critical:crit-ad-domain-root` (Active Directory Root Forest)

### Talking Point
> *"Within 17 microseconds, ThreatLens expands the multi-hop radius. Alice's workstation is only 3 hops away from complete domain compromise and customer financial data exfiltration. The distinct concentric color coding clearly delineates the immediate pivot frontier from exposed Crown Jewels."*

---

## Stage 4: Attack Path Discovery & Choke-Point Analysis

### Action
1. Navigate to the **"Attack Paths"** panel in GraphOps.
2. Target Crown Jewel: `critical:crit-db-financial`.
3. Click **"Discover Attack Paths"**.
4. ThreatLens computes 10 distinct acyclic lateral movement paths and automatically executes **Choke-Point Betweenness Centrality**.
5. Inspect the Choke-Point Table:
   - **Rank #1 Choke Point:** `server:srv-app-01`
   - **Path Traversal Interception:** **10/10 paths (100.0%)**
   - **Centrality Score:** `1.000`
   - **Recommended Containment:** `ISOLATE_NODE`

### API Reference
```bash
curl -X POST "http://localhost:8000/api/v1/graphops/paths" \
  -H "Content-Type: application/json" \
  -d '{"start_node_id": "device:dev-ws-101", "target_node_id": "critical:crit-db-financial", "max_depth": 5}'

curl -X POST "http://localhost:8000/api/v1/graphops/choke-points" \
  -H "Content-Type: application/json" \
  -d '{"start_node_id": "device:dev-ws-101", "max_depth": 5}'
```

### Talking Point
> *"Instead of blindly playing whack-a-mole across 10 different lateral paths, our graph analytics algorithm identifies the single strategic transit hub: server `srv-app-01`. Remediating or isolating this single choke point cuts off every viable pathway to the Crown Jewels."*

---

## Stage 5: Safe "What-If" Containment Simulation

### Action
1. In the Choke-Point row for `server:srv-app-01`, click **"Simulate Containment"**.
2. Select Intervention: **"Isolate Compromised Node (`ISOLATE_NODE`)"**.
3. Click **"Run Simulation"**.
4. Observe the Before vs. After comparative telemetry:
   - **Baseline Viable Attack Paths:** `10`
   - **Simulated Viable Attack Paths:** `0`
   - **Paths Eliminated:** `10 (100.0% Risk Reduction)`
   - **Live Graph Modified:** `false` (Strict zero-side-effect guarantee)
   - **Safety Disclaimer:** Prominently displayed notice that live production routing was unaffected.

### API Reference
```bash
curl -X POST "http://localhost:8000/api/v1/graphops/simulate-containment" \
  -H "Content-Type: application/json" \
  -d '{
    "entry_node_id": "device:dev-ws-101",
    "target_asset_ids": ["critical:crit-db-financial"],
    "action": "ISOLATE_NODE",
    "target_entity_id": "server:srv-app-01"
  }'
```

### Talking Point
> *"Security teams often hesitate to isolate servers for fear of breaking services without knowing if it actually stops the attack. ThreatLens' What-If engine runs a mathematical in-memory projection: we prove to the SOC lead that isolating `srv-app-01` eliminates 100% of attack paths to financial records, without touching a single production network switch or altering the persistent graph."*

---

## Summary of Key Value Propositions

| Capability | Legacy Approach | ThreatLens GraphOps |
|:---|:---|:---|
| **Incident Context** | Disconnected email alert & separate IP lookup | Immediate bridge from recipient to identity & workstation |
| **Exposure Assessment** | Manual investigation across firewall & AD logs | Sub-millisecond 1/2/3-hop blast-radius calculation |
| **Mitigation Planning** | Ad-hoc endpoint isolation | Algorithmic choke-point ranking with betweenness centrality |
| **Decision Confidence** | Guesswork on operational impact | Safe What-If simulation with path reduction quantification |
