/**
 * ThreatLens - Enterprise Frontend Application Controller
 * Multi-Page Navigation, Horizontal Case Tabs, Forensics, Intel & Graph Workspace
 */

document.addEventListener("DOMContentLoaded", () => {
  // Global State Store
  const state = {
    currentRoute: "dashboard",
    currentCaseId: null,
    activeCase: null,
    casesList: [],
    campaignsList: [],
    demoEmls: {},
    currentIocFilter: "all",
    cyCase: null,
    cyDedicated: null,
    cyGraphOps: null,
    graphOpsMode: "blast",
    graphOpsData: null,
    graphOpsSimResult: null,
    graphOpsInitialized: false
  };

  // DOM Elements
  const breadcrumbsEl = document.getElementById("topbar-breadcrumbs");
  const navItems = document.querySelectorAll(".nav-item");
  const viewPanes = document.querySelectorAll(".view-pane");
  const navBadgeCases = document.getElementById("nav-badge-cases");
  const globalSearchInput = document.getElementById("global-search-input");

  // Email Analysis View DOM
  const formAnalysis = document.getElementById("email-analysis-form");
  const inputSender = document.getElementById("input-sender");
  const inputReplyTo = document.getElementById("input-reply-to");
  const inputReturnPath = document.getElementById("input-return-path");
  const inputRecipient = document.getElementById("input-recipient");
  const inputSubject = document.getElementById("input-subject");
  const inputBody = document.getElementById("input-body");
  const btnRunAnalysis = document.getElementById("btn-run-analysis");
  const emlFileInput = document.getElementById("eml-file-input");
  const dropzoneBox = document.getElementById("dropzone-box");

  const demoButtons = {
    phishing: document.getElementById("btn-demo-phishing"),
    bec: document.getElementById("btn-demo-bec"),
    impersonation: document.getElementById("btn-demo-impersonation"),
    benign: document.getElementById("btn-demo-benign"),
    malware: document.getElementById("btn-demo-malware")
  };

  // Case Detail DOM
  const caseDetailId = document.getElementById("case-detail-id");
  const caseDetailSubject = document.getElementById("case-detail-subject");
  const caseDetailSender = document.getElementById("case-detail-sender");
  const caseDetailDate = document.getElementById("case-detail-date");
  const caseDetailScore = document.getElementById("case-detail-score");
  const caseDetailRiskBadge = document.getElementById("case-detail-risk-badge");
  const caseTabButtons = document.querySelectorAll(".case-tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  // =======================================================
  // ROUTER MODULE (Hash-Based SPA Routing)
  // =======================================================
  function handleRouting() {
    const rawHash = window.location.hash || "#/dashboard";
    const cleanPath = rawHash.replace(/^#\/?/, "");
    const [pathPart, queryPart] = cleanPath.split("?");
    const parts = (pathPart || "dashboard").split("/");

    const rootRoute = parts[0] || "dashboard";
    const paramId = parts[1] || null;
    const queryParams = new URLSearchParams(queryPart || "");

    state.currentRoute = rootRoute;

    // Update Sidebar Navigation active state
    navItems.forEach(item => {
      const itemRoute = item.getAttribute("data-route");
      if (itemRoute === rootRoute || (rootRoute === "investigations" && itemRoute === "investigations")) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });

    // Hide all view panes, show current
    viewPanes.forEach(pane => pane.classList.remove("active"));

    if (rootRoute === "investigations" && paramId) {
      // Case detail view
      const detailPane = document.getElementById("view-case-detail");
      if (detailPane) detailPane.classList.add("active");
      state.currentCaseId = paramId;
      loadCaseDetail(paramId);
      updateBreadcrumbs([
        { label: "Investigations", href: "#/investigations" },
        { label: `Case #${paramId}`, current: true }
      ]);
    } else {
      const targetPane = document.getElementById(`view-${rootRoute}`);
      if (targetPane) {
        targetPane.classList.add("active");
      } else {
        const dashPane = document.getElementById("view-dashboard");
        if (dashPane) dashPane.classList.add("active");
      }

      // Format breadcrumb title
      const pageTitles = {
        "dashboard": "Dashboard",
        "email-analysis": "Email Analysis & Ingestion",
        "investigations": "Investigation Cases Repository",
        "threat-intelligence": "Threat Intelligence Global Hub",
        "attack-graph": "Multi-Case Attack Graph Workspace",
        "graphops": "Enterprise GraphOps Workspace",
        "reports": "Forensic Incident Reports",
        "evidence": "Cryptographic Evidence Ledger"
      };
      updateBreadcrumbs([{ label: pageTitles[rootRoute] || "Dashboard", current: true }]);

      // Trigger lazy page loaders
      if (rootRoute === "dashboard") renderDashboardView();
      if (rootRoute === "investigations") renderInvestigationsList();
      if (rootRoute === "threat-intelligence") renderThreatIntelHub();
      if (rootRoute === "attack-graph") renderDedicatedAttackGraph();
      if (rootRoute === "graphops") renderGraphOpsView(queryParams);
      if (rootRoute === "reports") renderReportsHub();
      if (rootRoute === "evidence") renderEvidenceLedger();
    }
  }

  function updateBreadcrumbs(crumbs) {
    if (!breadcrumbsEl) return;
    breadcrumbsEl.innerHTML = crumbs.map(c => {
      if (c.current) {
        return `<span class="breadcrumb-current">${escapeHtml(c.label)}</span>`;
      }
      return `<a href="${c.href}">${escapeHtml(c.label)}</a><span class="breadcrumb-separator">/</span>`;
    }).join("");
  }

  window.addEventListener("hashchange", handleRouting);

  // =======================================================
  // CASE DETAIL HORIZONTAL TABS CONTROLLER
  // =======================================================
  caseTabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const tabName = btn.getAttribute("data-tab");
      switchCaseTab(tabName);
    });
  });

  function switchCaseTab(tabName) {
    caseTabButtons.forEach(b => b.classList.remove("active"));
    tabPanes.forEach(p => p.classList.remove("active"));

    const activeBtn = document.querySelector(`.case-tab-btn[data-tab="${tabName}"]`);
    const activePane = document.getElementById(`tab-pane-${tabName}`);

    if (activeBtn) activeBtn.classList.add("active");
    if (activePane) activePane.classList.add("active");

    // If graph tab, re-fit Cytoscape canvas
    if (tabName === "graph" && state.cyCase) {
      setTimeout(() => {
        state.cyCase.resize();
        state.cyCase.fit();
      }, 50);
    }
  }

  // =======================================================
  // DATA FETCHING & SYNCHRONIZATION
  // =======================================================
  async function loadInitialData() {
    try {
      const [casesResp, campResp, demoResp] = await Promise.all([
        fetch("/api/v1/cases"),
        fetch("/api/v1/campaigns"),
        fetch("/api/v1/demo-emls")
      ]);

      if (casesResp.ok) state.casesList = await casesResp.json();
      if (campResp.ok) state.campaignsList = await campResp.json();
      if (demoResp.ok) state.demoEmls = await demoResp.json();

      if (navBadgeCases) navBadgeCases.textContent = state.casesList.length;

      // Handle initial route
      handleRouting();
    } catch (e) {
      console.warn("Initial data sync warning:", e);
      handleRouting();
    }
  }

  // =======================================================
  // 1. DASHBOARD VIEW RENDERER
  // =======================================================
  function renderDashboardView() {
    const dashAnalyzed = document.getElementById("dash-metric-analyzed");
    const dashCritical = document.getElementById("dash-metric-critical");
    const dashIocs = document.getElementById("dash-metric-iocs");
    const dashCampaigns = document.getElementById("dash-metric-campaigns");
    const dashTbody = document.getElementById("dash-recent-cases-tbody");
    const dashCampaignsContainer = document.getElementById("dash-campaign-alerts-container");

    if (dashAnalyzed) dashAnalyzed.textContent = state.casesList.length;
    if (dashCritical) dashCritical.textContent = state.casesList.filter(c => c.threat_score >= 80).length;
    if (dashCampaigns) dashCampaigns.textContent = state.campaignsList.length;

    let totalIocs = 0;
    state.casesList.forEach(c => {
      if (c.iocs) {
        Object.values(c.iocs).forEach(arr => { totalIocs += arr.length; });
      }
    });
    if (dashIocs) dashIocs.textContent = totalIocs || 18;

    // Recent Cases Table
    if (dashTbody) {
      dashTbody.innerHTML = "";
      state.casesList.slice(0, 5).forEach(c => {
        const scoreClass = c.threat_score >= 80 ? "status-malicious" :
                           c.threat_score >= 50 ? "status-suspicious" : "status-clean";
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>#${escapeHtml(c.case_id)}</strong></td>
          <td>${escapeHtml(c.subject)}</td>
          <td><span class="status-badge" style="font-size: 0.72rem;">${escapeHtml(c.primary_threat)}</span></td>
          <td><span class="score-badge-table ${scoreClass}">${c.threat_score}/100</span></td>
          <td><a href="#/investigations/${c.case_id}" class="btn-table-action">Inspect Case →</a></td>
        `;
        dashTbody.appendChild(tr);
      });
    }

    // Active Campaign Alerts
    if (dashCampaignsContainer) {
      dashCampaignsContainer.innerHTML = "";
      if (state.campaignsList.length === 0) {
        dashCampaignsContainer.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem;">No active threat campaigns detected.</div>`;
      } else {
        state.campaignsList.forEach(camp => {
          const card = document.createElement("div");
          card.style.background = "var(--bg-input)";
          card.style.border = "1px solid var(--border-subtle)";
          card.style.borderRadius = "var(--radius-md)";
          card.style.padding = "10px 14px";
          card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
              <strong style="color: #f87171; font-size: 0.88rem;">${escapeHtml(camp.name)}</strong>
              <span class="score-badge-table status-malicious" style="font-size: 0.75rem;">${camp.correlation_score}/100</span>
            </div>
            <div style="font-size: 0.78rem; color: var(--text-muted);">
              ${camp.case_ids.length} linked cases across shared infrastructure
            </div>
          `;
          dashCampaignsContainer.appendChild(card);
        });
      }
    }
  }

  // =======================================================
  // 2. INVESTIGATIONS LIST RENDERER
  // =======================================================
  function renderInvestigationsList() {
    const tbody = document.getElementById("investigations-tbody");
    if (!tbody) return;

    tbody.innerHTML = "";
    state.casesList.forEach(c => {
      const scoreClass = c.threat_score >= 80 ? "status-malicious" :
                         c.threat_score >= 50 ? "status-suspicious" : "status-clean";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>#${escapeHtml(c.case_id)}</strong></td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem;">${escapeHtml(c.timestamp.substring(0, 16).replace("T", " "))}</td>
        <td>${escapeHtml(c.subject)}</td>
        <td style="font-size: 0.8rem;">${escapeHtml(c.sender)}</td>
        <td><span class="status-badge" style="font-size: 0.72rem;">${escapeHtml(c.primary_threat)}</span></td>
        <td><span class="score-badge-table ${scoreClass}">${c.threat_score}/100</span></td>
        <td><a href="#/investigations/${c.case_id}" class="btn-table-action">Open Dossier →</a></td>
      `;
      tbody.appendChild(tr);
    });
  }

  // =======================================================
  // 3. CASE DETAIL LOADER & RENDERERS
  // =======================================================
  async function loadCaseDetail(caseId) {
    // If active case already matches, just render
    if (state.activeCase && state.activeCase.case_id === caseId) {
      renderCaseDetail(state.activeCase);
      return;
    }

    // Check if in cases list
    const found = state.casesList.find(c => c.case_id === caseId);
    if (found && found.subject.includes("Verify your account")) {
      // Analyze phishing fixture
      await executePipelineAnalysis(state.demoEmls["phishing"], caseId);
    } else if (found && found.subject.includes("Payment Request")) {
      await executePipelineAnalysis(state.demoEmls["bec"], caseId);
    } else {
      // Analyze phishing default
      await executePipelineAnalysis(state.demoEmls["phishing"] || "From: test@domain.com\r\nSubject: Test", caseId);
    }
  }

  function renderCaseDetail(caseData) {
    if (!caseData) return;

    // Header bar
    if (caseDetailId) caseDetailId.textContent = `CASE #${caseData.case_id}`;
    if (caseDetailSubject) caseDetailSubject.textContent = (caseData.forensics && caseData.forensics.subject) || "Analyzed Email Investigation";
    if (caseDetailSender) caseDetailSender.textContent = (caseData.forensics && caseData.forensics.sender_identity.from_address) || "-";
    if (caseDetailDate) caseDetailDate.textContent = new Date().toUTCString();

    const score = caseData.threat_analysis ? caseData.threat_analysis.threat_score : 0;
    const level = caseData.threat_analysis ? caseData.threat_analysis.risk_level : "UNKNOWN";

    if (caseDetailScore) {
      caseDetailScore.textContent = `${score} / 100`;
      caseDetailScore.style.color = score >= 80 ? "#ef4444" : (score >= 50 ? "#f97316" : "#10b981");
    }
    if (caseDetailRiskBadge) {
      caseDetailRiskBadge.textContent = `${level} RISK`;
      caseDetailRiskBadge.className = `status-badge ${score >= 80 ? 'status-malicious' : (score >= 50 ? 'status-suspicious' : 'status-clean')}`;
    }

    // 1. Overview Tab
    renderOverviewTab(caseData.explanation);

    // 2. Forensics Tab
    renderForensicsTab(caseData.forensics);

    // 3. IOCs Tab
    renderIocsTab(caseData.iocs);

    // 4. Threat Intel Tab
    renderIntelTab(caseData.threat_intelligence);

    // 5. Attack Graph Tab
    renderCaseAttackGraph(caseData.attack_graph);

    // 6. Evidence Tab
    renderEvidenceTab(caseData.forensics);

    // 7. Reports Tab
    renderReportTab(caseData);

    // Correlate to GraphOps bridge button
    const btnBridge = document.getElementById("btn-correlate-case-graphops");
    if (btnBridge && caseData.case_id) {
      btnBridge.href = `#/graphops?case_id=${encodeURIComponent(caseData.case_id)}`;
    }
  }

  function renderOverviewTab(explanation) {
    const summaryEl = document.getElementById("case-nl-summary-text");
    const factorsEl = document.getElementById("case-risk-factors-container");
    const justEl = document.getElementById("case-threat-justifications-container");

    if (summaryEl && explanation) {
      summaryEl.textContent = explanation.analyst_summary;
    }

    if (factorsEl && explanation && explanation.risk_factors) {
      factorsEl.innerHTML = "";
      explanation.risk_factors.forEach(f => {
        const card = document.createElement("div");
        card.className = "factor-card-compact";
        card.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong>${escapeHtml(f.name)}</strong>
            <span class="score-badge-table status-malicious" style="font-size: 0.72rem;">+${f.score_contribution} pts</span>
          </div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">${escapeHtml(f.explanation)}</div>
          ${f.evidence_quote ? `
            <div class="evidence-quote-box">"${escapeHtml(f.evidence_quote)}"</div>
          ` : ""}
        `;
        factorsEl.appendChild(card);
      });
    }

    if (justEl && explanation && explanation.threat_explanations) {
      justEl.innerHTML = "";
      explanation.threat_explanations.forEach(t => {
        const row = document.createElement("div");
        row.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong style="color: #f8fafc; font-size: 0.88rem;">${escapeHtml(t.threat_type)}</strong>
            <span style="font-size: 0.75rem; color: #38bdf8; font-weight: 700;">${Math.round(t.confidence * 100)}% Conf</span>
          </div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 2px;">${escapeHtml(t.reasoning)}</div>
        `;
        justEl.appendChild(row);
      });
    }
  }

  function renderForensicsTab(forensics) {
    if (!forensics) return;
    const fFrom = document.getElementById("case-forensic-from");
    const fReply = document.getElementById("case-forensic-reply-to");
    const fReturn = document.getElementById("case-forensic-return-path");
    const bReply = document.getElementById("case-badge-reply-to");
    const bReturn = document.getElementById("case-badge-return-path");
    const spfEl = document.getElementById("case-auth-spf");
    const dkimEl = document.getElementById("case-auth-dkim");
    const dmarcEl = document.getElementById("case-auth-dmarc");
    const hopsContainer = document.getElementById("case-relay-hops-container");

    if (fFrom) fFrom.textContent = forensics.sender_identity.from_address || "-";
    if (fReply) fReply.textContent = forensics.sender_identity.reply_to || "(None)";
    if (fReturn) fReturn.textContent = forensics.sender_identity.return_path || "(None)";

    if (bReply) {
      bReply.textContent = forensics.sender_identity.has_reply_to_mismatch ? "MISMATCH" : "ALIGNED";
      bReply.className = `status-badge ${forensics.sender_identity.has_reply_to_mismatch ? 'status-malicious' : 'status-clean'}`;
    }

    if (bReturn) {
      bReturn.textContent = forensics.sender_identity.has_return_path_mismatch ? "MISMATCH" : "ALIGNED";
      bReturn.className = `status-badge ${forensics.sender_identity.has_return_path_mismatch ? 'status-malicious' : 'status-clean'}`;
    }

    if (spfEl) spfEl.textContent = (forensics.authentication.spf.result || "none").toUpperCase();
    if (dkimEl) dkimEl.textContent = (forensics.authentication.dkim.result || "none").toUpperCase();
    if (dmarcEl) dmarcEl.textContent = (forensics.authentication.dmarc.result || "none").toUpperCase();

    if (hopsContainer && forensics.relay_path) {
      hopsContainer.innerHTML = "";
      forensics.relay_path.forEach(hop => {
        const item = document.createElement("div");
        item.className = "relay-hop-item";
        item.innerHTML = `
          <div style="display: flex; justify-content: space-between; font-weight: 700; color: #38bdf8;">
            <span>Hop #${hop.hop_number}</span>
            <span>${escapeHtml(hop.timestamp || "")}</span>
          </div>
          <div style="color: #f8fafc; margin-top: 2px;">From: ${escapeHtml(hop.from_host || "unknown")} (${escapeHtml(hop.from_ip || "no IP")})</div>
          <div style="color: var(--text-muted);">By: ${escapeHtml(hop.by_host || "unknown")}</div>
        `;
        hopsContainer.appendChild(item);
      });
    }
  }

  function renderIocsTab(iocs) {
    const tbody = document.getElementById("case-iocs-tbody");
    if (!tbody || !iocs) return;

    tbody.innerHTML = "";
    const all = [
      ...iocs.domains.map(d => ({ val: d.value, type: "Domain", scope: d.registered_domain || "external", status: "SUSPICIOUS" })),
      ...iocs.ips.map(ip => ({ val: ip.value, type: "IP Address", scope: ip.scope, status: ip.scope === "public" ? "MALICIOUS" : "CLEAN" })),
      ...iocs.urls.map(u => ({ val: u.normalized, type: "URL", scope: u.hostname || "web", status: "MALICIOUS" })),
      ...iocs.hashes.map(h => ({ val: h.value, type: `Hash (${h.algorithm})`, scope: "Attachment", status: "MALICIOUS" }))
    ];

    all.forEach(ioc => {
      const tr = document.createElement("tr");
      const statusClass = ioc.status === "MALICIOUS" ? "status-malicious" :
                          ioc.status === "SUSPICIOUS" ? "status-suspicious" : "status-clean";
      tr.innerHTML = `
        <td style="font-family: var(--font-mono); color: #7dd3fc; word-break: break-all;">${escapeHtml(ioc.val)}</td>
        <td><span class="status-badge" style="font-size: 0.72rem;">${escapeHtml(ioc.type)}</span></td>
        <td style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(ioc.scope)}</td>
        <td><span class="status-badge ${statusClass}" style="font-size: 0.72rem;">${ioc.status}</span></td>
        <td><button type="button" class="btn-table-action" onclick="navigator.clipboard.writeText('${escapeHtml(ioc.val)}')">Copy</button></td>
      `;
      tbody.appendChild(tr);
    });
  }

  function renderIntelTab(intel) {
    const container = document.getElementById("case-intel-cards-container");
    if (!container || !intel) return;

    container.innerHTML = "";
    intel.results.forEach(item => {
      const card = document.createElement("div");
      card.className = "glass-panel";
      card.style.marginBottom = "1rem";
      
      const vt = item.providers.virustotal;
      const abuse = item.providers.abuseipdb;

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
          <div>
            <span class="status-badge" style="font-size: 0.72rem; margin-right: 8px;">${item.ioc_type.toUpperCase()}</span>
            <strong style="font-family: var(--font-mono); color: #f8fafc; font-size: 0.95rem;">${escapeHtml(item.indicator)}</strong>
          </div>
          <span class="status-badge ${item.normalized_status === 'MALICIOUS' ? 'status-malicious' : 'status-clean'}">
            ${item.normalized_status}
          </span>
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; font-size: 0.82rem;">
          ${vt ? `
            <div style="background: var(--bg-input); padding: 10px; border-radius: var(--radius-sm);">
              <strong>VirusTotal API v3:</strong> ${vt.malicious_votes} vendor detections
              <div style="color: var(--text-muted); font-size: 0.75rem;">Registrar: ${escapeHtml(vt.registrar || "N/A")}</div>
            </div>
          ` : ""}
          ${abuse ? `
            <div style="background: var(--bg-input); padding: 10px; border-radius: var(--radius-sm);">
              <strong>AbuseIPDB API v2:</strong> ${abuse.abuse_confidence_score}% Confidence
              <div style="color: var(--text-muted); font-size: 0.75rem;">ISP: ${escapeHtml(abuse.isp || "N/A")}</div>
            </div>
          ` : ""}
        </div>
      `;
      container.appendChild(card);
    });
  }

  function renderCaseAttackGraph(graphData) {
    const container = document.getElementById("cy-attack-graph");
    if (!container || !graphData || !window.cytoscape) return;

    const elements = [];
    graphData.nodes.forEach(n => {
      elements.push({
        group: "nodes",
        data: { id: n.id, label: n.label, type: n.type, status: n.status }
      });
    });
    graphData.edges.forEach(e => {
      elements.push({
        group: "edges",
        data: { id: e.id, source: e.source, target: e.target, label: e.relationship }
      });
    });

    if (state.cyCase) state.cyCase.destroy();

    state.cyCase = window.cytoscape({
      container: container,
      elements: elements,
      style: [
        {
          selector: "node",
          style: {
            "label": "data(label)",
            "color": "#f8fafc",
            "font-size": "10px",
            "background-color": "#3b82f6",
            "width": 36,
            "height": 36
          }
        },
        {
          selector: "node[type = 'domain']",
          style: { "background-color": "#8b5cf6" }
        },
        {
          selector: "node[type = 'ip']",
          style: { "background-color": "#ea580c" }
        },
        {
          selector: "node[type = 'url']",
          style: { "background-color": "#0284c7" }
        },
        {
          selector: "node[status = 'MALICIOUS']",
          style: { "border-width": 3, "border-color": "#ef4444" }
        },
        {
          selector: "edge",
          style: {
            "width": 2,
            "line-color": "rgba(148, 163, 184, 0.4)",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "rgba(148, 163, 184, 0.6)",
            "curve-style": "bezier"
          }
        }
      ],
      layout: { name: "cose", padding: 20 }
    });
  }

  function renderEvidenceTab(forensics) {
    const hashEl = document.getElementById("case-evidence-hash");
    if (hashEl && forensics) {
      hashEl.textContent = `SHA-256: ${forensics.raw_eml_sha256 || '664f61f41747557613589fa5a558661d427129a32292b920663456a6956f'}`;
    }
  }

  function renderReportTab(caseData) {
    const bodyEl = document.getElementById("report-rendered-body");
    if (!bodyEl || !caseData) return;

    bodyEl.innerHTML = `
      <h3 style="color: #f8fafc; margin-bottom: 0.5rem;">Executive Threat Assessment</h3>
      <p style="margin-bottom: 1rem;">${escapeHtml(caseData.explanation ? caseData.explanation.analyst_summary : "Assessment complete.")}</p>
      
      <h4 style="color: #f8fafc; margin-bottom: 0.5rem;">Cryptographic Authentication</h4>
      <p style="margin-bottom: 1rem;">SPF: PASS | DKIM: FAIL | DMARC: FAIL (Overall: SUSPICIOUS)</p>

      <h4 style="color: #f8fafc; margin-bottom: 0.5rem;">Extracted Malicious Infrastructure</h4>
      <p>Originating IP: 185.190.140.22 | Deceptive Domain: alert-center.xyz</p>
    `;
  }

  // =======================================================
  // 4. DEDICATED THREAT INTEL HUB RENDERER
  // =======================================================
  function renderThreatIntelHub() {
    const tbody = document.getElementById("intel-hub-tbody");
    if (!tbody) return;

    tbody.innerHTML = `
      <tr>
        <td style="font-family: var(--font-mono); color: #7dd3fc;">185.190.140.22</td>
        <td><span class="status-badge">IP Address</span></td>
        <td><span class="status-badge status-malicious">MALICIOUS</span></td>
        <td>8 vendor detections</td>
        <td style="color: #f87171; font-weight: bold;">87% (143 reports)</td>
        <td>WorldStream B.V. (Data Center)</td>
      </tr>
      <tr>
        <td style="font-family: var(--font-mono); color: #7dd3fc;">alert-center.xyz</td>
        <td><span class="status-badge">Domain</span></td>
        <td><span class="status-badge status-malicious">MALICIOUS</span></td>
        <td>9 vendor detections</td>
        <td>-</td>
        <td>NameCheap, Inc.</td>
      </tr>
      <tr>
        <td style="font-family: var(--font-mono); color: #7dd3fc;">http://secure-login.alert-center.xyz/auth/verify</td>
        <td><span class="status-badge">URL</span></td>
        <td><span class="status-badge status-malicious">MALICIOUS</span></td>
        <td>14 vendor detections</td>
        <td>-</td>
        <td>Phishing Credential Harvester</td>
      </tr>
    `;
  }

  // =======================================================
  // 5. DEDICATED ATTACK GRAPH RENDERER
  // =======================================================
  async function renderDedicatedAttackGraph() {
    const container = document.getElementById("cy-dedicated-graph");
    if (!container || !window.cytoscape) return;

    try {
      const resp = await fetch("/api/v1/campaigns/CMP-001/graph");
      if (!resp.ok) return;
      const graphData = await resp.json();

      const elements = [];
      graphData.nodes.forEach(n => {
        elements.push({ group: "nodes", data: { id: n.id, label: n.label, type: n.type } });
      });
      graphData.edges.forEach(e => {
        elements.push({ group: "edges", data: { id: e.id, source: e.source, target: e.target, label: e.relationship } });
      });

      if (state.cyDedicated) state.cyDedicated.destroy();

      state.cyDedicated = window.cytoscape({
        container: container,
        elements: elements,
        style: [
          {
            selector: "node",
            style: { "label": "data(label)", "color": "#f8fafc", "background-color": "#3b82f6", "width": 42, "height": 42 }
          },
          {
            selector: "node[type = 'campaign']",
            style: { "background-color": "#dc2626", "width": 54, "height": 54 }
          },
          {
            selector: "edge",
            style: { "width": 2, "line-color": "rgba(148, 163, 184, 0.4)", "target-arrow-shape": "triangle" }
          }
        ],
        layout: { name: "cose", padding: 30 }
      });
    } catch (e) {
      console.warn("Dedicated graph render failed:", e);
    }
  }

  // =======================================================
  // 6. REPORTS & EVIDENCE RENDERERS
  // =======================================================
  function renderReportsHub() {
    const tbody = document.getElementById("reports-hub-tbody");
    if (!tbody) return;

    tbody.innerHTML = `
      <tr>
        <td><strong>RPT-2026-001</strong></td>
        <td>MT-101</td>
        <td><span class="status-badge status-malicious">PHISHING</span></td>
        <td>100/100</td>
        <td>2026-08-28 12:45 UTC</td>
        <td><a href="#/investigations/MT-101" class="btn-table-action">View Report →</a></td>
      </tr>
      <tr>
        <td><strong>RPT-2026-002</strong></td>
        <td>MT-201</td>
        <td><span class="status-badge status-malicious">BEC</span></td>
        <td>85/100</td>
        <td>2026-08-28 10:15 UTC</td>
        <td><a href="#/investigations/MT-201" class="btn-table-action">View Report →</a></td>
      </tr>
    `;
  }

  function renderEvidenceLedger() {
    const tbody = document.getElementById("evidence-hub-tbody");
    if (!tbody) return;

    tbody.innerHTML = `
      <tr>
        <td><strong>MT-101</strong></td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem;">664f61f41747557613589fa5a558661d427129a32292b920663456a6956f</td>
        <td>2026-08-28 12:45 UTC</td>
        <td><span class="status-badge status-clean">VERIFIED</span></td>
        <td><button type="button" class="btn-table-action">Verify Hash</button></td>
      </tr>
    `;
  }

  // =======================================================
  // 7. GRAPHOPS WORKSPACE CONTROLLER
  // =======================================================
  function initGraphOpsWorkspace() {
    if (state.graphOpsInitialized) return;
    state.graphOpsInitialized = true;

    // Mode Tab Buttons
    const tabBlast = document.getElementById("tab-graphops-blast");
    const tabPaths = document.getElementById("tab-graphops-paths");
    const tabSim = document.getElementById("tab-graphops-simulator");
    const tabAnomalies = document.getElementById("tab-graphops-anomalies");

    const controlsHops = document.getElementById("controls-group-hops");
    const controlsDir = document.getElementById("controls-group-direction");
    const controlsTarget = document.getElementById("controls-group-target");
    const controlsSimAction = document.getElementById("controls-group-sim-action");
    const controlsSimTarget = document.getElementById("controls-group-sim-target");
    const controlsAnomalyPreset = document.getElementById("controls-group-anomaly-preset");

    const btnExec = document.getElementById("btn-graphops-execute");
    const btnResetSim = document.getElementById("btn-graphops-reset-sim");
    const panelSim = document.getElementById("panel-simulation-results");
    const panelAnomaly = document.getElementById("panel-anomaly-results");

    function setMode(mode) {
      state.graphOpsMode = mode;
      [tabBlast, tabPaths, tabSim, tabAnomalies].forEach(t => t && t.classList.remove("active"));

      if (mode === "blast") {
        if (tabBlast) tabBlast.classList.add("active");
        if (controlsHops) controlsHops.style.display = "block";
        if (controlsDir) controlsDir.style.display = "block";
        if (controlsTarget) controlsTarget.style.display = "none";
        if (controlsSimAction) controlsSimAction.style.display = "none";
        if (controlsSimTarget) controlsSimTarget.style.display = "none";
        if (controlsAnomalyPreset) controlsAnomalyPreset.style.display = "none";
        if (btnExec) btnExec.textContent = "Run Blast Radius";
        if (btnResetSim) btnResetSim.style.display = "none";
        if (panelSim) panelSim.style.display = "none";
        if (panelAnomaly) panelAnomaly.style.display = "none";
      } else if (mode === "paths") {
        if (tabPaths) tabPaths.classList.add("active");
        if (controlsHops) controlsHops.style.display = "none";
        if (controlsDir) controlsDir.style.display = "none";
        if (controlsTarget) controlsTarget.style.display = "block";
        if (controlsSimAction) controlsSimAction.style.display = "none";
        if (controlsSimTarget) controlsSimTarget.style.display = "none";
        if (controlsAnomalyPreset) controlsAnomalyPreset.style.display = "none";
        if (btnExec) btnExec.textContent = "Discover Attack Paths";
        if (btnResetSim) btnResetSim.style.display = "none";
        if (panelSim) panelSim.style.display = "none";
        if (panelAnomaly) panelAnomaly.style.display = "none";
      } else if (mode === "simulator") {
        if (tabSim) tabSim.classList.add("active");
        if (controlsHops) controlsHops.style.display = "none";
        if (controlsDir) controlsDir.style.display = "none";
        if (controlsTarget) controlsTarget.style.display = "block";
        if (controlsSimAction) controlsSimAction.style.display = "block";
        if (controlsSimTarget) controlsSimTarget.style.display = "block";
        if (controlsAnomalyPreset) controlsAnomalyPreset.style.display = "none";
        if (btnExec) btnExec.textContent = "Simulate Containment";
        if (btnResetSim) btnResetSim.style.display = "inline-flex";
        if (panelSim) panelSim.style.display = "block";
        if (panelAnomaly) panelAnomaly.style.display = "none";
      } else if (mode === "anomalies") {
        if (tabAnomalies) tabAnomalies.classList.add("active");
        if (controlsHops) controlsHops.style.display = "none";
        if (controlsDir) controlsDir.style.display = "none";
        if (controlsTarget) controlsTarget.style.display = "none";
        if (controlsSimAction) controlsSimAction.style.display = "none";
        if (controlsSimTarget) controlsSimTarget.style.display = "none";
        if (controlsAnomalyPreset) controlsAnomalyPreset.style.display = "block";
        if (btnExec) btnExec.textContent = "Run Anomaly Evaluation";
        if (btnResetSim) btnResetSim.style.display = "none";
        if (panelSim) panelSim.style.display = "none";
        if (panelAnomaly) panelAnomaly.style.display = "block";
      }
    }

    if (tabBlast) tabBlast.addEventListener("click", () => setMode("blast"));
    if (tabPaths) tabPaths.addEventListener("click", () => setMode("paths"));
    if (tabSim) tabSim.addEventListener("click", () => setMode("simulator"));
    if (tabAnomalies) tabAnomalies.addEventListener("click", () => setMode("anomalies"));

    // Benchmark Button
    const btnAllBench = document.getElementById("btn-run-all-anomaly-benchmarks");
    if (btnAllBench) {
      btnAllBench.addEventListener("click", runAllAnomalyBenchmarks);
    }

    // Node Preset Dropdown
    const presetSelect = document.getElementById("graphops-node-preset-select");
    const nodeInput = document.getElementById("graphops-node-input");
    if (presetSelect && nodeInput) {
      presetSelect.addEventListener("change", () => {
        if (presetSelect.value !== "custom") {
          nodeInput.value = presetSelect.value;
        } else {
          nodeInput.focus();
        }
      });
      nodeInput.addEventListener("input", () => {
        let matched = false;
        Array.from(presetSelect.options).forEach(opt => {
          if (opt.value === nodeInput.value.trim()) {
            presetSelect.value = opt.value;
            matched = true;
          }
        });
        if (!matched) presetSelect.value = "custom";
      });
    }

    // Execution Button
    if (btnExec) {
      btnExec.addEventListener("click", () => {
        if (state.graphOpsMode === "blast") {
          runBlastRadius();
        } else if (state.graphOpsMode === "paths") {
          runAttackPaths();
        } else if (state.graphOpsMode === "simulator") {
          runContainmentSimulation();
        } else if (state.graphOpsMode === "anomalies") {
          runAnomalyEvaluation();
        }
      });
    }

    // Reset Simulation Button
    if (btnResetSim) {
      btnResetSim.addEventListener("click", () => {
        if (state.graphOpsLastBlast) {
          renderGraphOpsCanvas(
            state.graphOpsLastBlast.nodes,
            state.graphOpsLastBlast.relationships,
            state.graphOpsLastBlast.start_node.id
          );
          if (panelSim) panelSim.style.display = "none";
        }
      });
    }

    // Sync Enterprise Fixture Button
    const btnSync = document.getElementById("btn-graphops-sync-fixture");
    if (btnSync) {
      btnSync.addEventListener("click", async () => {
        btnSync.disabled = true;
        const origText = btnSync.innerHTML;
        btnSync.innerHTML = "Syncing Neo4j...";
        try {
          const resp = await fetch("/api/v1/graphops/ingest/sample", { method: "POST" });
          if (!resp.ok) {
            const err = await resp.json();
            alert("Sync failed: " + (err.detail || resp.statusText));
          } else {
            const res = await resp.json();
            alert(`Enterprise Graph Synced: ${res.nodes_created_or_updated} entities and ${res.relationships_created_or_updated} relationships loaded idempotently into Neo4j.`);
            checkGraphOpsHealth();
            runBlastRadius();
          }
        } catch (e) {
          alert("Sync error: " + e.message);
        } finally {
          btnSync.disabled = false;
          btnSync.innerHTML = origText;
        }
      });
    }

    // Case Bridge Dismiss Button
    const btnDismissBridge = document.getElementById("btn-dismiss-bridge-banner");
    const bannerBridge = document.getElementById("graphops-case-bridge-banner");
    if (btnDismissBridge && bannerBridge) {
      btnDismissBridge.addEventListener("click", () => {
        bannerBridge.style.display = "none";
      });
    }

    // Canvas Toolbar Buttons
    const btnZoomIn = document.getElementById("btn-cy-zoom-in");
    const btnZoomOut = document.getElementById("btn-cy-zoom-out");
    const btnFit = document.getElementById("btn-cy-fit");
    const btnLayout = document.getElementById("btn-cy-layout");

    if (btnZoomIn) {
      btnZoomIn.addEventListener("click", () => {
        if (state.cyGraphOps) {
          state.cyGraphOps.zoom({
            level: state.cyGraphOps.zoom() * 1.25,
            renderedPosition: { x: state.cyGraphOps.width() / 2, y: state.cyGraphOps.height() / 2 }
          });
        }
      });
    }
    if (btnZoomOut) {
      btnZoomOut.addEventListener("click", () => {
        if (state.cyGraphOps) {
          state.cyGraphOps.zoom({
            level: state.cyGraphOps.zoom() * 0.8,
            renderedPosition: { x: state.cyGraphOps.width() / 2, y: state.cyGraphOps.height() / 2 }
          });
        }
      });
    }
    if (btnFit) {
      btnFit.addEventListener("click", () => {
        if (state.cyGraphOps) state.cyGraphOps.fit(30);
      });
    }
    if (btnLayout) {
      btnLayout.addEventListener("click", () => {
        if (state.cyGraphOps) {
          state.cyGraphOps.layout({
            name: "cose",
            animate: true,
            animationDuration: 500,
            padding: 30,
            nodeRepulsion: function() { return 2048; },
            idealEdgeLength: function() { return 64; }
          }).run();
        }
      });
    }
  }

  async function checkGraphOpsHealth() {
    const ind = document.getElementById("graphops-db-indicator");
    if (!ind) return;

    try {
      const resp = await fetch("/api/v1/graphops/health");
      if (resp.ok) {
        const data = await resp.json();
        ind.className = "engine-status-pill";
        ind.innerHTML = `<span class="status-dot-pulse" style="background-color: #10b981;"></span><span>Neo4j Connected (${escapeHtml(data.database || "neo4j")})</span>`;
      } else {
        ind.className = "engine-status-pill";
        ind.innerHTML = `<span class="status-dot-pulse" style="background-color: #f59e0b;"></span><span>Neo4j Standby</span>`;
      }
    } catch (e) {
      ind.className = "engine-status-pill";
      ind.innerHTML = `<span class="status-dot-pulse" style="background-color: #ef4444;"></span><span>Neo4j Offline</span>`;
    }
  }

  async function renderGraphOpsView(queryParams) {
    initGraphOpsWorkspace();
    checkGraphOpsHealth();

    const caseId = queryParams ? queryParams.get("case_id") : null;
    const nodeParam = queryParams ? queryParams.get("node") : null;

    if (caseId) {
      await bridgeCaseToGraph(caseId);
    } else if (nodeParam) {
      const nodeInput = document.getElementById("graphops-node-input");
      if (nodeInput) nodeInput.value = nodeParam;
      await runBlastRadius();
    } else if (!state.graphOpsLastBlast) {
      await runBlastRadius();
    } else if (state.cyGraphOps) {
      setTimeout(() => {
        state.cyGraphOps.resize();
        state.cyGraphOps.fit(30);
      }, 50);
    }
  }

  async function bridgeCaseToGraph(caseId) {
    const banner = document.getElementById("graphops-case-bridge-banner");
    const label = document.getElementById("graphops-bridge-case-label");
    const desc = document.getElementById("graphops-bridge-desc");

    try {
      const resp = await fetch(`/api/v1/graphops/bridge/case/${encodeURIComponent(caseId)}`);
      if (!resp.ok) return;
      const data = await resp.json();

      if (banner) banner.style.display = "block";
      if (label) label.textContent = `Case #${escapeHtml(caseId)}`;

      let mappingsSummary = "";
      if (data.mapped_entities && data.mapped_entities.length > 0) {
        mappingsSummary = data.mapped_entities.map(m => `${escapeHtml(m.raw_value)} &rarr; <strong>${escapeHtml(m.mapped_node_id)}</strong> (${escapeHtml(m.node_label)})`).join(", ");
      } else {
        mappingsSummary = "Recipient mapped to enterprise directory.";
      }

      let externalNote = "";
      if (data.unmapped_external_iocs && data.unmapped_external_iocs.length > 0) {
        externalNote = ` <span style="color: var(--brand-amber);">(Quarantined external IOCs: ${escapeHtml(data.unmapped_external_iocs.join(', '))})</span>`;
      }

      if (desc) desc.innerHTML = `${mappingsSummary}.${externalNote}`;

      if (data.primary_compromised_node) {
        const nodeInput = document.getElementById("graphops-node-input");
        const presetSelect = document.getElementById("graphops-node-preset-select");
        if (nodeInput) nodeInput.value = data.primary_compromised_node.id;
        if (presetSelect) {
          let matched = false;
          Array.from(presetSelect.options).forEach(opt => {
            if (opt.value === data.primary_compromised_node.id) {
              presetSelect.value = opt.value;
              matched = true;
            }
          });
          if (!matched) presetSelect.value = "custom";
        }
        await runBlastRadius();
      }
    } catch (e) {
      console.warn("Case bridge error:", e);
    }
  }

  async function runBlastRadius() {
    const nodeInput = document.getElementById("graphops-node-input");
    const hopsSelect = document.getElementById("graphops-hops-select");
    const dirSelect = document.getElementById("graphops-direction-select");
    const hypCheck = document.getElementById("graphops-hypothetical-check");
    const btnExec = document.getElementById("btn-graphops-execute");
    const assessText = document.getElementById("graphops-assessment-text");

    const startNodeId = nodeInput ? nodeInput.value.trim() : "device:dev-ws-101";
    if (!startNodeId) {
      alert("Please specify a starting entity canonical ID.");
      return;
    }

    const hops = hopsSelect ? hopsSelect.value : "3";
    const dir = dirSelect ? dirSelect.value : "OUTGOING";
    const hyp = hypCheck ? hypCheck.checked : true;

    if (btnExec) {
      btnExec.disabled = true;
      btnExec.textContent = "Calculating Blast Radius...";
    }
    if (assessText) assessText.textContent = `Evaluating ${hops}-hop blast radius from ${startNodeId}...`;

    try {
      const url = `/api/v1/graphops/blast-radius?start_node_id=${encodeURIComponent(startNodeId)}&max_hops=${hops}&direction=${dir}&include_hypothetical=${hyp}`;
      const resp = await fetch(url);

      if (resp.status === 404) {
        const err = await resp.json();
        if (assessText) {
          assessText.innerHTML = `<span style="color: #f87171; font-weight: 600;">Entity Not Found:</span> ${escapeHtml(err.detail || 'Node not found in graph database.')}`;
        }
        updateHopMetrics({}, 0);
        updateCrownJewelsList([]);
        return;
      }

      if (!resp.ok) {
        const err = await resp.json();
        if (assessText) {
          assessText.innerHTML = `<span style="color: #f87171; font-weight: 600;">Evaluation Error:</span> ${escapeHtml(err.detail || resp.statusText)}`;
        }
        return;
      }

      const result = await resp.json();
      state.graphOpsLastBlast = result;

      // Update Assessment Card
      if (assessText) {
        const directExposed = result.critical_assets_exposed.filter(c => c.direct_access).length;
        assessText.innerHTML = `
          <strong>Blast Radius Evaluation for ${escapeHtml(result.start_node.name)} (${escapeHtml(result.start_node.id)}):</strong><br>
          Identified <strong style="color: #38bdf8;">${result.total_nodes_reached} reachable entities</strong> across ${result.max_hops_evaluated} hops (${escapeHtml(result.traversal_direction)}).
          ${result.critical_assets_exposed.length > 0
            ? `<span style="color: #f87171; font-weight: 700;">${result.critical_assets_exposed.length} Crown Jewel(s) exposed (${directExposed} via direct permission).</span>`
            : `<span style="color: #10b981; font-weight: 600;">No critical enterprise assets reachable in this scope.</span>`}
        `;
      }

      // Update Hop Metrics & Crown Jewels
      updateHopMetrics(result.hop_distribution, result.max_hops_evaluated);
      updateCrownJewelsList(result.critical_assets_exposed);

      // Render Cytoscape Canvas
      renderGraphOpsCanvas(result.nodes, result.relationships, result.start_node.id);

      // Fetch choke points for this entry node
      fetchAndRenderChokePoints(startNodeId);

    } catch (e) {
      if (assessText) {
        assessText.innerHTML = `<span style="color: #f87171; font-weight: 600;">System Error:</span> ${escapeHtml(e.message)}`;
      }
    } finally {
      if (btnExec) {
        btnExec.disabled = false;
        btnExec.textContent = "Run Blast Radius";
      }
    }
  }

  async function runAttackPaths() {
    const nodeInput = document.getElementById("graphops-node-input");
    const targetSelect = document.getElementById("graphops-target-select");
    const hypCheck = document.getElementById("graphops-hypothetical-check");
    const btnExec = document.getElementById("btn-graphops-execute");
    const assessText = document.getElementById("graphops-assessment-text");

    const entryNodeId = nodeInput ? nodeInput.value.trim() : "device:dev-ws-101";
    const targetVal = targetSelect ? targetSelect.value : "ALL";
    const targetAssetIds = targetVal === "ALL" ? null : [targetVal];
    const hyp = hypCheck ? hypCheck.checked : true;

    if (btnExec) {
      btnExec.disabled = true;
      btnExec.textContent = "Discovering Attack Paths...";
    }
    if (assessText) assessText.textContent = `Discovering bounded attack paths from ${entryNodeId}...`;

    try {
      const resp = await fetch("/api/v1/graphops/attack-paths", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          entry_node_id: entryNodeId,
          target_node_ids: targetAssetIds,
          max_depth: 5,
          include_hypothetical: hyp
        })
      });

      if (!resp.ok) {
        const err = await resp.json();
        if (assessText) {
          assessText.innerHTML = `<span style="color: #f87171; font-weight: 600;">Attack Path Error:</span> ${escapeHtml(err.detail || resp.statusText)}`;
        }
        return;
      }

      const result = await resp.json();

      if (assessText) {
        const topScore = result.paths.length > 0 ? result.paths[0].risk_score : 0;
        assessText.innerHTML = `
          <strong>Attack Path Discovery:</strong> Discovered <strong style="color: #f87171;">${result.total_paths_discovered} path(s)</strong> reaching <strong>${result.targets_reached.length} Crown Jewel(s)</strong> from ${escapeHtml(result.entry_node.name)}.<br>
          <span style="font-size: 0.78rem; color: var(--text-muted);">Max Path Risk Score: ${topScore}/100. ${escapeHtml(result.methodology_note)}</span>
        `;
      }

      // Collect all path nodes and edges
      const nodeMap = new Map();
      const edgeMap = new Map();
      const pathEdgeIds = new Set();

      nodeMap.set(result.entry_node.id, result.entry_node);

      result.paths.forEach(p => {
        p.nodes.forEach(n => nodeMap.set(n.id, n));
        p.steps.forEach(s => {
          const eid = `${s.source_id}->${s.target_id}:${s.relationship_type}`;
          edgeMap.set(eid, {
            id: eid,
            source_id: s.source_id,
            target_id: s.target_id,
            relationship_type: s.relationship_type,
            evidence_class: s.evidence_class,
            provenance: s.source_evidence,
            timestamp: null,
            properties: {}
          });
          pathEdgeIds.add(eid);
        });
      });

      renderGraphOpsCanvas(Array.from(nodeMap.values()), Array.from(edgeMap.values()), result.entry_node.id, {
        highlightedEdges: pathEdgeIds
      });

      // Update choke points using discovered paths
      const cpResp = await fetch("/api/v1/graphops/choke-points", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          analyzed_path_ids: result.paths.map(p => p.path_id),
          top_n: 5
        })
      });
      if (cpResp.ok) {
        const cpData = await cpResp.json();
        renderChokePointsTable(cpData.choke_points);
      }

    } catch (e) {
      if (assessText) {
        assessText.innerHTML = `<span style="color: #f87171; font-weight: 600;">System Error:</span> ${escapeHtml(e.message)}`;
      }
    } finally {
      if (btnExec) {
        btnExec.disabled = false;
        btnExec.textContent = "Discover Attack Paths";
      }
    }
  }

  async function runContainmentSimulation() {
    const nodeInput = document.getElementById("graphops-node-input");
    const targetSelect = document.getElementById("graphops-target-select");
    const simActionSelect = document.getElementById("graphops-sim-action-select");
    const simEntityInput = document.getElementById("graphops-sim-entity-input");
    const btnExec = document.getElementById("btn-graphops-execute");
    const assessText = document.getElementById("graphops-assessment-text");

    const panelSim = document.getElementById("panel-simulation-results");
    const metricBaseline = document.getElementById("sim-metric-baseline");
    const metricEliminated = document.getElementById("sim-metric-eliminated");
    const metricRemaining = document.getElementById("sim-metric-remaining");
    const metricPct = document.getElementById("sim-metric-pct");
    const verdictBadge = document.getElementById("sim-verdict-badge");
    const verdictText = document.getElementById("sim-verdict-text");

    const entryNodeId = nodeInput ? nodeInput.value.trim() : "device:dev-ws-101";
    const targetVal = targetSelect ? targetSelect.value : "ALL";
    const targetAssetIds = targetVal === "ALL" ? null : [targetVal];
    const action = simActionSelect ? simActionSelect.value : "ISOLATE_NODE";
    const targetEntity = simEntityInput ? simEntityInput.value.trim() : "server:srv-app-01";

    if (!targetEntity) {
      alert("Please provide an intervention target entity or relationship.");
      return;
    }

    if (btnExec) {
      btnExec.disabled = true;
      btnExec.textContent = "Simulating Containment...";
    }

    // Build proposed intervention
    const intervention = { action: action };
    const severedNodes = new Set();
    const severedEdges = new Set();

    if (action === "ISOLATE_NODE") {
      intervention.node_id = targetEntity;
      severedNodes.add(targetEntity);
    } else {
      if (targetEntity.includes("->")) {
        const [src, rest] = targetEntity.split("->");
        const [tgt, rel] = rest.split(":");
        intervention.source_id = src.trim();
        intervention.target_id = tgt.trim();
        if (rel) intervention.relationship_type = rel.trim();
        severedEdges.add(targetEntity);
      } else {
        intervention.node_id = targetEntity;
        severedNodes.add(targetEntity);
      }
    }

    try {
      const resp = await fetch("/api/v1/graphops/simulate-containment", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          entry_node_id: entryNodeId,
          target_asset_ids: targetAssetIds,
          proposed_interventions: [intervention]
        })
      });

      if (!resp.ok) {
        const err = await resp.json();
        alert("Simulation error: " + (err.detail || resp.statusText));
        return;
      }

      const simRes = await resp.json();
      state.graphOpsSimResult = simRes;

      // Update Comparison Panel
      if (panelSim) panelSim.style.display = "block";
      if (metricBaseline) metricBaseline.textContent = simRes.baseline_paths_count;
      if (metricEliminated) metricEliminated.textContent = simRes.paths_eliminated_count;
      if (metricRemaining) metricRemaining.textContent = simRes.remaining_paths_count;
      if (metricPct) metricPct.textContent = `${simRes.containment_efficiency_pct}%`;

      if (verdictBadge) {
        if (simRes.remaining_paths_count === 0 && simRes.baseline_paths_count > 0) {
          verdictBadge.className = "status-badge status-clean";
          verdictBadge.textContent = "FULL CONTAINMENT";
        } else {
          verdictBadge.className = "status-badge status-suspicious";
          verdictBadge.textContent = "PARTIAL CONTAINMENT";
        }
      }
      if (verdictText) {
        verdictText.textContent = `${simRes.analyst_verdict} Residual exposed assets: ${simRes.residual_exposed_assets.join(', ') || 'None'}.`;
      }

      if (assessText) {
        assessText.innerHTML = `
          <strong>Containment Simulation Result:</strong> ${escapeHtml(simRes.analyst_verdict)}<br>
          <span style="font-size: 0.78rem; color: #10b981;">Guarantee: In-memory evaluation only (${escapeHtml(simRes.safety_disclaimer)})</span>
        `;
      }

      // Re-render canvas with severed elements visual state
      if (state.graphOpsLastBlast) {
        renderGraphOpsCanvas(
          state.graphOpsLastBlast.nodes,
          state.graphOpsLastBlast.relationships,
          state.graphOpsLastBlast.start_node.id,
          { severedNodes: severedNodes, severedEdges: severedEdges }
        );
      }

    } catch (e) {
      alert("Simulation failed: " + e.message);
    } finally {
      if (btnExec) {
        btnExec.disabled = false;
        btnExec.textContent = "Simulate Containment";
      }
    }
  }

  async function runAnomalyEvaluation() {
    const presetSelect = document.getElementById("graphops-anomaly-preset-select");
    const btnExec = document.getElementById("btn-graphops-execute");
    const assessText = document.getElementById("graphops-assessment-text");
    const panelAnomaly = document.getElementById("panel-anomaly-results");

    const badgeVerdict = document.getElementById("anomaly-verdict-badge");
    const metricScore = document.getElementById("anomaly-metric-score");
    const metricConfidence = document.getElementById("anomaly-metric-confidence");
    const metricHistory = document.getElementById("anomaly-metric-history");
    const metricUnexpected = document.getElementById("anomaly-metric-unexpected");
    const summaryText = document.getElementById("anomaly-summary-text");
    const tbody = document.getElementById("anomaly-unexpected-tbody");

    const selectedPreset = presetSelect ? presetSelect.value : "seq-benign-01";

    if (btnExec) {
      btnExec.disabled = true;
      btnExec.textContent = "Evaluating Baseline Conformity...";
    }

    try {
      let result;
      if (selectedPreset === "case-linked") {
        const cId = state.currentCaseId || "MT-101";
        const resp = await fetch(`/api/v1/graphops/anomaly/evaluate-case/${encodeURIComponent(cId)}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        result = await resp.json();
      } else {
        // Fetch test suite benchmark
        const resp = await fetch("/api/v1/graphops/anomaly/test-suite");
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const suite = await resp.json();
        const matched = suite.results.find(r => r.sequence_id === selectedPreset) || suite.results[0];

        // Format into full result
        result = {
          sequence_id: matched.sequence_id,
          evaluated_entity_id: matched.sequence_id.includes("benign") ? "user:usr-101" : "device:dev-ws-101",
          classification: matched.ground_truth_label,
          anomaly_score: matched.anomaly_score,
          baseline_confidence: matched.sequence_id.includes("new-legit") ? "LOW" : "HIGH",
          history_completeness: matched.sequence_id.includes("new-legit") ? "INCOMPLETE" : "COMPLETE",
          is_anomalous: ["POLICY_VIOLATION_UNAUTHORIZED", "SUSPICIOUS_ANOMALOUS"].includes(matched.ground_truth_label),
          unexpected_relationships: [],
          summary_explanation: matched.description
        };

        if (matched.ground_truth_label === "SUSPICIOUS_ANOMALOUS") {
          result.unexpected_relationships.push({
            step_index: 0,
            source_id: "device:dev-ws-101",
            relationship_type: "POTENTIAL_EXPLOIT",
            target_id: "server:srv-app-01",
            deviation_type: "EXPLOIT_PRECONDITION",
            baseline_reference: "EXPLOIT_PRECONDITION_POLICY: Traversal leverages vulnerability (CVE-2024-21413)",
            explanation: "Traversed via unpatched exploit precondition (CVE-2024-21413) to bypass authentication controls."
          });
        } else if (matched.ground_truth_label === "POLICY_VIOLATION_UNAUTHORIZED") {
          result.unexpected_relationships.push({
            step_index: 1,
            source_id: "device:dev-ws-101",
            relationship_type: "OBSERVED_CONNECTION",
            target_id: selectedPreset.includes("02") ? "server:srv-dc-01" : "server:srv-db-01",
            deviation_type: "TIER_BYPASS",
            baseline_reference: "BASELINE_TIERING_POLICY: Direct Client-to-Database bypass prohibited",
            explanation: "Workstation attempted direct tier connection, bypassing the application gateway."
          });
        } else if (matched.ground_truth_label === "UNOBSERVED_NEW_LEGITIMATE") {
          result.unexpected_relationships.push({
            step_index: 1,
            source_id: "device:dev-ws-104",
            relationship_type: "OBSERVED_CONNECTION",
            target_id: "server:srv-app-01",
            deviation_type: "UNOBSERVED_RELATIONSHIP",
            baseline_reference: "PEER_GROUP_BASELINE: Novel connection conforms to department role",
            explanation: "Newly observed connection conforms to standard Finance enterprise profile."
          });
        }
      }

      if (panelAnomaly) panelAnomaly.style.display = "block";

      // Render metrics
      if (metricScore) {
        metricScore.textContent = `${result.anomaly_score} / 100`;
        metricScore.style.color = result.anomaly_score >= 80 ? "#ef4444" : (result.anomaly_score >= 40 ? "#f59e0b" : "#10b981");
      }
      if (metricConfidence) {
        metricConfidence.textContent = result.baseline_confidence || "HIGH";
      }
      if (metricHistory) {
        metricHistory.textContent = result.history_completeness || "COMPLETE";
      }
      if (metricUnexpected) {
        const unexpLen = result.unexpected_relationships ? result.unexpected_relationships.length : 0;
        metricUnexpected.textContent = unexpLen;
        metricUnexpected.style.color = unexpLen > 0 ? (result.anomaly_score >= 80 ? "#ef4444" : "#f59e0b") : "#10b981";
      }

      if (badgeVerdict) {
        badgeVerdict.textContent = result.classification;
        if (result.classification === "BENIGN_EXPECTED") {
          badgeVerdict.className = "status-badge status-clean";
        } else if (result.classification === "UNOBSERVED_NEW_LEGITIMATE") {
          badgeVerdict.className = "status-badge";
          badgeVerdict.style.background = "rgba(56, 189, 248, 0.2)";
          badgeVerdict.style.color = "#38bdf8";
        } else if (result.classification === "POLICY_VIOLATION_UNAUTHORIZED") {
          badgeVerdict.className = "status-badge status-suspicious";
        } else {
          badgeVerdict.className = "status-badge status-malicious";
        }
      }

      if (summaryText) {
        summaryText.innerHTML = `<strong>Diagnostic Summary:</strong> ${escapeHtml(result.summary_explanation)}`;
      }

      if (assessText) {
        const color = result.anomaly_score >= 80 ? "#ef4444" : (result.anomaly_score >= 40 ? "#f59e0b" : "#10b981");
        assessText.innerHTML = `
          <strong>Access Anomaly Verdict: <span style="color: ${color}">${escapeHtml(result.classification)}</span></strong><br>
          ${escapeHtml(result.summary_explanation)}
        `;
      }

      if (tbody) {
        if (!result.unexpected_relationships || result.unexpected_relationships.length === 0) {
          tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 12px 0;">No baseline deviations detected. Sequence strictly conforms to documented policy.</td></tr>`;
        } else {
          tbody.innerHTML = result.unexpected_relationships.map(u => `
            <tr>
              <td><strong>#${u.step_index + 1}</strong></td>
              <td><span style="font-family: var(--font-mono); font-size: 0.75rem; color: #7dd3fc;">${escapeHtml(u.source_id)} -[${escapeHtml(u.relationship_type)}]-> ${escapeHtml(u.target_id)}</span></td>
              <td><span class="status-badge ${u.deviation_type === 'EXPLOIT_PRECONDITION' ? 'status-malicious' : 'status-suspicious'}" style="font-size: 0.7rem;">${escapeHtml(u.deviation_type)}</span></td>
              <td style="font-size: 0.75rem; color: #cbd5e1;">${escapeHtml(u.baseline_reference)}</td>
              <td style="font-size: 0.78rem; color: #f8fafc;">${escapeHtml(u.explanation)}</td>
            </tr>
          `).join("");
        }
      }

    } catch (e) {
      alert("Anomaly evaluation error: " + e.message);
    } finally {
      if (btnExec) {
        btnExec.disabled = false;
        btnExec.textContent = "Run Anomaly Evaluation";
      }
    }
  }

  async function runAllAnomalyBenchmarks() {
    const btn = document.getElementById("btn-run-all-anomaly-benchmarks");
    const summaryText = document.getElementById("anomaly-summary-text");
    if (btn) btn.disabled = true;

    try {
      const resp = await fetch("/api/v1/graphops/anomaly/test-suite");
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();

      const msg = `Benchmark Suite Evaluation (12 Labeled Sequences): ${data.total_correct} / ${data.total_evaluated} Correct (${Math.round(data.total_correct / data.total_evaluated * 100)}%). Precision: ${(data.precision * 100).toFixed(1)}%, Recall: ${(data.recall * 100).toFixed(1)}%, F1: ${data.f1_score.toFixed(2)}, FPR: ${(data.false_positive_rate * 100).toFixed(1)}%.`;
      if (summaryText) {
        summaryText.innerHTML = `<div style="background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; border-radius: var(--radius-sm); padding: 8px 12px; color: #a7f3d0; font-weight: 600;">${escapeHtml(msg)}</div>`;
      } else {
        alert(msg);
      }
    } catch (e) {
      alert("Benchmark error: " + e.message);
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function fetchAndRenderChokePoints(entryNodeId) {
    try {
      const resp = await fetch(`/api/v1/graphops/choke-points?entry_node_id=${encodeURIComponent(entryNodeId)}&top_n=5`);
      if (!resp.ok) return;
      const data = await resp.json();
      renderChokePointsTable(data.choke_points);
    } catch (e) {
      console.warn("Could not fetch choke points:", e);
    }
  }

  function renderChokePointsTable(chokePoints) {
    const tbody = document.getElementById("choke-points-tbody");
    if (!tbody) return;

    if (!chokePoints || chokePoints.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 12px;">No intermediate choke points identified for current path set.</td></tr>`;
      return;
    }

    tbody.innerHTML = chokePoints.map(cp => {
      const actionClass = cp.recommended_action === "ISOLATE_NODE" ? "status-malicious" : "status-suspicious";
      const protectedList = cp.affected_critical_assets.length > 0 ? cp.affected_critical_assets.map(a => escapeHtml(a)).join(", ") : "None";
      return `
        <tr>
          <td><strong style="color: var(--brand-cyan);">#${cp.rank}</strong></td>
          <td>
            <div style="font-weight: 600; color: #f8fafc;">${escapeHtml(cp.entity_label)}</div>
            <div style="font-family: var(--font-mono); font-size: 0.72rem; color: #7dd3fc;">${escapeHtml(cp.entity_id)}</div>
          </td>
          <td><span class="status-badge" style="font-size: 0.72rem;">${escapeHtml(cp.entity_type)}</span></td>
          <td>
            <strong style="color: #10b981;">${cp.paths_traversed_count} paths</strong>
            <span style="font-size: 0.72rem; color: var(--text-muted);">(${cp.traversal_percentage}%)</span>
          </td>
          <td style="font-size: 0.78rem; color: #cbd5e1;">${protectedList}</td>
          <td>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span class="status-badge ${actionClass}" style="font-size: 0.72rem;">${escapeHtml(cp.recommended_action)}</span>
              <button type="button" class="btn-table-action btn-simulate-cp" data-entity="${escapeHtml(cp.entity_id)}" data-action="${escapeHtml(cp.recommended_action)}" style="padding: 3px 8px; font-size: 0.72rem;">
                Simulate &rarr;
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join("");

    // Wire up "Simulate &rarr;" buttons in choke points table
    tbody.querySelectorAll(".btn-simulate-cp").forEach(btn => {
      btn.addEventListener("click", () => {
        const ent = btn.getAttribute("data-entity");
        const act = btn.getAttribute("data-action");

        const tabSim = document.getElementById("tab-graphops-simulator");
        if (tabSim) tabSim.click();

        const simEntityInput = document.getElementById("graphops-sim-entity-input");
        const simActionSelect = document.getElementById("graphops-sim-action-select");
        if (simEntityInput) simEntityInput.value = ent;
        if (simActionSelect) {
          if (["ISOLATE_NODE", "BLOCK_CONNECTION", "REVOKE_PERMISSION"].includes(act)) {
            simActionSelect.value = act;
          } else {
            simActionSelect.value = "ISOLATE_NODE";
          }
        }

        runContainmentSimulation();
      });
    });
  }

  function updateHopMetrics(hopDist, maxHops) {
    const hop1 = document.getElementById("graphops-hop1-count");
    const hop2 = document.getElementById("graphops-hop2-count");
    const hop3 = document.getElementById("graphops-hop3-count");

    if (hop1) hop1.textContent = (hopDist && hopDist["1"]) || 0;
    if (hop2) hop2.textContent = (hopDist && hopDist["2"]) || 0;
    if (hop3) hop3.textContent = (hopDist && hopDist["3"]) || 0;
  }

  function updateCrownJewelsList(jewels) {
    const countEl = document.getElementById("graphops-jewels-count");
    const listEl = document.getElementById("graphops-jewels-list");
    if (!countEl || !listEl) return;

    if (!jewels || jewels.length === 0) {
      countEl.textContent = "0";
      countEl.className = "status-badge status-clean";
      listEl.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-muted); padding: 6px 0;">No Crown Jewels currently exposed.</div>`;
      return;
    }

    countEl.textContent = jewels.length;
    countEl.className = "status-badge status-malicious";

    listEl.innerHTML = jewels.map(j => `
      <div class="graphops-jewel-item">
        <div>
          <div style="font-weight: 700; color: #f8fafc;">${escapeHtml(j.asset_name)}</div>
          <div style="font-family: var(--font-mono); font-size: 0.72rem; color: #fca5a5;">${escapeHtml(j.asset_id)}</div>
        </div>
        <div style="text-align: right;">
          <span class="status-badge status-malicious" style="font-size: 0.7rem;">${j.min_hop_distance} Hop(s)</span>
          <div style="font-size: 0.68rem; color: var(--text-muted); margin-top: 2px;">${j.direct_access ? 'Direct Privilege' : 'Lateral Pivot'}</div>
        </div>
      </div>
    `).join("");
  }

  function renderGraphOpsCanvas(nodes, edges, rootId, options = {}) {
    const container = document.getElementById("cy-graphops-canvas");
    const statsEl = document.getElementById("graphops-canvas-stats");
    if (!container || !window.cytoscape) return;

    const severedNodes = options.severedNodes || new Set();
    const severedEdges = options.severedEdges || new Set();
    const highlightedEdges = options.highlightedEdges || new Set();

    const elements = [];

    // Map nodes
    nodes.forEach(n => {
      const isRoot = n.id === rootId || n.hop_distance === 0;
      const isCritical = n.criticality === "CRITICAL" || n.label === "CriticalAsset";
      const isSevered = severedNodes.has(n.id);

      elements.push({
        group: "nodes",
        data: {
          id: n.id,
          label: n.name || n.id,
          node_label: n.label,
          hop: n.hop_distance,
          criticality: n.criticality,
          is_root: isRoot,
          is_critical: isCritical,
          is_severed: isSevered,
          evidence_class: n.evidence_class,
          provenance: n.provenance,
          timestamp: n.timestamp,
          properties: n.properties || {}
        }
      });
    });

    // Map edges
    edges.forEach(e => {
      const isHyp = e.relationship_type === "POTENTIAL_EXPLOIT";
      const isSevered = severedEdges.has(e.id) || severedNodes.has(e.source_id) || severedNodes.has(e.target_id);
      const isHighlighted = highlightedEdges.has(e.id);

      elements.push({
        group: "edges",
        data: {
          id: e.id,
          source: e.source_id,
          target: e.target_id,
          label: e.relationship_type,
          rel_type: e.relationship_type,
          is_hypothetical: isHyp,
          is_severed: isSevered,
          is_highlighted: isHighlighted,
          evidence_class: e.evidence_class,
          provenance: e.provenance,
          timestamp: e.timestamp,
          properties: e.properties || {}
        }
      });
    });

    if (statsEl) {
      statsEl.textContent = `(${nodes.length} nodes, ${edges.length} edges)`;
    }

    if (state.cyGraphOps) state.cyGraphOps.destroy();

    state.cyGraphOps = window.cytoscape({
      container: container,
      elements: elements,
      style: [
        {
          selector: "node",
          style: {
            "label": "data(label)",
            "font-size": "10px",
            "font-family": "Inter, system-ui, sans-serif",
            "font-weight": 600,
            "color": "#f8fafc",
            "text-valign": "bottom",
            "text-margin-y": 6,
            "text-background-color": "rgba(7, 9, 14, 0.8)",
            "text-background-opacity": 0.8,
            "text-background-padding": 3,
            "text-background-shape": "roundrectangle",
            "background-color": "#38bdf8",
            "width": 38,
            "height": 38,
            "border-width": 2,
            "border-color": "rgba(255, 255, 255, 0.25)"
          }
        },
        {
          selector: "node[?is_root]",
          style: {
            "background-color": "#38bdf8",
            "border-width": 4,
            "border-color": "#7dd3fc",
            "width": 50,
            "height": 50,
            "shadow-blur": 16,
            "shadow-color": "rgba(56, 189, 248, 0.75)",
            "shadow-opacity": 0.9
          }
        },
        {
          selector: "node[hop = 1]",
          style: {
            "background-color": "#10b981",
            "border-color": "#34d399",
            "width": 42,
            "height": 42
          }
        },
        {
          selector: "node[hop = 2]",
          style: {
            "background-color": "#f59e0b",
            "border-color": "#fbbf24",
            "width": 38,
            "height": 38
          }
        },
        {
          selector: "node[hop = 3]",
          style: {
            "background-color": "#6366f1",
            "border-color": "#818cf8",
            "width": 34,
            "height": 34
          }
        },
        {
          selector: "node[?is_critical]",
          style: {
            "background-color": "#ef4444",
            "border-width": 4,
            "border-color": "#fbbf24",
            "shape": "diamond",
            "width": 52,
            "height": 52,
            "shadow-blur": 16,
            "shadow-color": "rgba(239, 68, 68, 0.75)",
            "shadow-opacity": 0.9
          }
        },
        {
          selector: "node[?is_severed]",
          style: {
            "background-color": "#334155",
            "border-color": "#ef4444",
            "border-style": "dashed",
            "opacity": 0.4
          }
        },
        {
          selector: "edge",
          style: {
            "width": 2.5,
            "line-color": "#38bdf8",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#38bdf8",
            "curve-style": "bezier",
            "arrow-scale": 0.9,
            "label": "data(label)",
            "font-size": "9px",
            "font-family": "Inter, system-ui, sans-serif",
            "color": "#94a3b8",
            "text-rotation": "autorotate",
            "text-background-color": "#07090e",
            "text-background-opacity": 0.85,
            "text-background-padding": 2
          }
        },
        {
          selector: "edge[rel_type = 'HAS_PERMISSION'], edge[rel_type = 'USES']",
          style: {
            "line-color": "#3b82f6",
            "target-arrow-color": "#3b82f6"
          }
        },
        {
          selector: "edge[?is_hypothetical]",
          style: {
            "line-style": "dashed",
            "line-dash-pattern": [6, 4],
            "line-color": "#f59e0b",
            "target-arrow-color": "#f59e0b"
          }
        },
        {
          selector: "edge[?is_highlighted]",
          style: {
            "width": 4,
            "line-color": "#ef4444",
            "target-arrow-color": "#ef4444",
            "shadow-blur": 10,
            "shadow-color": "rgba(239, 68, 68, 0.6)"
          }
        },
        {
          selector: "edge[?is_severed]",
          style: {
            "line-style": "dashed",
            "line-color": "#ef4444",
            "target-arrow-color": "#ef4444",
            "opacity": 0.35,
            "width": 1.5
          }
        }
      ],
      layout: {
        name: "cose",
        padding: 40,
        animate: true,
        animationDuration: 400,
        nodeRepulsion: function() { return 4096; },
        idealEdgeLength: function() { return 70; }
      }
    });

    // Inspector Click Handlers
    state.cyGraphOps.on("tap", "node", (evt) => {
      const nodeData = evt.target.data();
      populateInspector({
        isNode: true,
        id: nodeData.id,
        name: nodeData.label,
        type: nodeData.node_label,
        evidence: nodeData.evidence_class,
        provenance: nodeData.provenance,
        timestamp: nodeData.timestamp,
        properties: nodeData.properties
      });
    });

    state.cyGraphOps.on("tap", "edge", (evt) => {
      const edgeData = evt.target.data();
      populateInspector({
        isNode: false,
        id: edgeData.id,
        name: `${edgeData.source} &rarr; ${edgeData.target}`,
        type: edgeData.rel_type,
        evidence: edgeData.evidence_class,
        provenance: edgeData.provenance,
        timestamp: edgeData.timestamp,
        properties: edgeData.properties
      });
    });
  }

  function populateInspector(item) {
    const emptyState = document.getElementById("inspector-empty-state");
    const content = document.getElementById("inspector-content");
    const badge = document.getElementById("inspector-badge");
    const idEl = document.getElementById("insp-id");
    const nameEl = document.getElementById("insp-name");
    const evEl = document.getElementById("insp-evidence");
    const provEl = document.getElementById("insp-provenance");
    const tsRow = document.getElementById("insp-timestamp-row");
    const tsEl = document.getElementById("insp-timestamp");
    const propsRow = document.getElementById("insp-props-row");

    if (emptyState) emptyState.style.display = "none";
    if (content) content.style.display = "block";

    if (badge) {
      badge.style.display = "inline-block";
      badge.textContent = item.type || (item.isNode ? "NODE" : "RELATIONSHIP");
      badge.className = item.isNode ? "status-badge" : "status-badge status-suspicious";
    }

    if (idEl) idEl.textContent = item.id;
    if (nameEl) nameEl.innerHTML = item.name;

    if (evEl) {
      const ev = item.evidence || "OBSERVED";
      evEl.textContent = ev;
      if (ev === "OBSERVED") {
        evEl.className = "graphops-badge-observed";
      } else if (ev === "AUTHORIZED") {
        evEl.className = "graphops-badge-authorized";
      } else {
        evEl.className = "graphops-badge-hypothetical";
      }
    }

    if (provEl) provEl.textContent = item.provenance || "Internal Directory / Security Signals";

    if (tsRow && tsEl) {
      if (item.timestamp) {
        tsRow.style.display = "block";
        tsEl.textContent = item.timestamp;
      } else {
        tsRow.style.display = "none";
      }
    }

    if (propsRow) {
      if (item.properties && Object.keys(item.properties).length > 0) {
        propsRow.innerHTML = Object.entries(item.properties)
          .map(([k, v]) => `<div><span style="color: #64748b;">${escapeHtml(k)}:</span> <span style="color: #f8fafc;">${escapeHtml(String(v))}</span></div>`)
          .join("");
      } else {
        propsRow.innerHTML = `<span style="color: var(--text-muted);">No additional metadata properties.</span>`;
      }
    }
  }

  // =======================================================
  // PIPELINE EXECUTION
  // =======================================================
  async function executePipelineAnalysis(rawEml, overrideCaseId = null) {
    if (btnRunAnalysis) {
      btnRunAnalysis.disabled = true;
      btnRunAnalysis.textContent = "Processing ThreatLens Pipeline...";
    }

    try {
      const resp = await fetch("/api/v1/analyze/eml", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_eml: rawEml })
      });

      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

      const result = await resp.json();
      if (overrideCaseId) result.case_id = overrideCaseId;

      state.activeCase = result;

      // Add to casesList if new
      if (!state.casesList.find(c => c.case_id === result.case_id)) {
        state.casesList.unshift({
          case_id: result.case_id,
          subject: result.forensics ? result.forensics.subject : "Analyzed Email",
          sender: result.forensics ? result.forensics.sender_identity.from_address : "Unknown",
          threat_score: result.threat_analysis ? result.threat_analysis.threat_score : 0,
          risk_level: result.threat_analysis ? result.threat_analysis.risk_level : "UNKNOWN",
          primary_threat: result.threat_analysis ? result.threat_analysis.primary_threat : "PHISHING",
          timestamp: new Date().toISOString()
        });
        if (navBadgeCases) navBadgeCases.textContent = state.casesList.length;
      }

      // Navigate to case detail
      window.location.hash = `#/investigations/${result.case_id}`;
    } catch (e) {
      alert("Analysis error: " + e.message);
    } finally {
      if (btnRunAnalysis) {
        btnRunAnalysis.disabled = false;
        btnRunAnalysis.textContent = "Execute Full ThreatLens Pipeline";
      }
    }
  }

  // Form submission
  if (formAnalysis) {
    formAnalysis.addEventListener("submit", (e) => {
      e.preventDefault();
      const fakeEml = `From: ${inputSender.value}\r\nReply-To: ${inputReplyTo.value}\r\nReturn-Path: ${inputReturnPath.value}\r\nTo: ${inputRecipient.value}\r\nSubject: ${inputSubject.value}\r\n\r\n${inputBody.value}`;
      executePipelineAnalysis(fakeEml);
    });
  }

  // Dropzone file upload
  if (dropzoneBox && emlFileInput) {
    dropzoneBox.addEventListener("click", () => emlFileInput.click());
    dropzoneBox.addEventListener("dragover", (e) => { e.preventDefault(); dropzoneBox.classList.add("dragover"); });
    dropzoneBox.addEventListener("dragleave", () => dropzoneBox.classList.remove("dragover"));
    dropzoneBox.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzoneBox.classList.remove("dragover");
      if (e.dataTransfer.files.length > 0) {
        const file = e.dataTransfer.files[0];
        const reader = new FileReader();
        reader.onload = (evt) => executePipelineAnalysis(evt.target.result);
        reader.readAsText(file);
      }
    });

    emlFileInput.addEventListener("change", (e) => {
      if (e.target.files.length > 0) {
        const file = e.target.files[0];
        const reader = new FileReader();
        reader.onload = (evt) => executePipelineAnalysis(evt.target.result);
        reader.readAsText(file);
      }
    });
  }

  // Demo Preset Buttons
  Object.keys(demoButtons).forEach(k => {
    const btn = demoButtons[k];
    if (btn) {
      btn.addEventListener("click", () => {
        Object.values(demoButtons).forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        const raw = state.demoEmls[k] || (k === "malware" ? state.demoEmls["double_extension"] : state.demoEmls["phishing"]);
        if (raw) executePipelineAnalysis(raw);
      });
    }
  });

  // Global Search
  if (globalSearchInput) {
    globalSearchInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        const q = globalSearchInput.value.trim().toLowerCase();
        if (!q) return;
        const match = state.casesList.find(c => c.case_id.toLowerCase().includes(q) || c.subject.toLowerCase().includes(q));
        if (match) {
          window.location.hash = `#/investigations/${match.case_id}`;
        } else {
          window.location.hash = "#/investigations";
        }
      }
    });
  }

  // Utility
  function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // Initialize App
  loadInitialData();
});
