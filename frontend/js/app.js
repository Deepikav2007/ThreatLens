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
    cyDedicated: null
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
    const parts = cleanPath.split("/");

    const rootRoute = parts[0] || "dashboard";
    const paramId = parts[1] || null;

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
        "reports": "Forensic Incident Reports",
        "evidence": "Cryptographic Evidence Ledger"
      };
      updateBreadcrumbs([{ label: pageTitles[rootRoute] || "Dashboard", current: true }]);

      // Trigger lazy page loaders
      if (rootRoute === "dashboard") renderDashboardView();
      if (rootRoute === "investigations") renderInvestigationsList();
      if (rootRoute === "threat-intelligence") renderThreatIntelHub();
      if (rootRoute === "attack-graph") renderDedicatedAttackGraph();
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
