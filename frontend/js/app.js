/**
 * MailTrace AI - Frontend Controller
 * Features 1–5: Threat Detection, Explainable AI, Forensics, IOCs & Threat Intelligence
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const form = document.getElementById("email-analysis-form");
  const inputSender = document.getElementById("input-sender");
  const inputReplyTo = document.getElementById("input-reply-to");
  const inputReturnPath = document.getElementById("input-return-path");
  const inputRecipient = document.getElementById("input-recipient");
  const inputSubject = document.getElementById("input-subject");
  const inputBody = document.getElementById("input-body");
  const inputSpf = document.getElementById("input-spf");
  const inputDkim = document.getElementById("input-dkim");
  const inputDmarc = document.getElementById("input-dmarc");
  const btnAnalyze = document.getElementById("btn-run-analysis");

  // Feature 1 DOM
  const scoreHero = document.getElementById("score-hero-container");
  const threatScoreVal = document.getElementById("threat-score-value");
  const riskLevelBadge = document.getElementById("risk-level-badge");
  const primaryThreatName = document.getElementById("primary-threat-name");
  const primaryThreatConfidence = document.getElementById("primary-threat-confidence");
  const secondaryThreatsList = document.getElementById("secondary-threats-list");

  // Feature 2 DOM
  const nlSummaryContent = document.getElementById("nl-summary-content");
  const benignBox = document.getElementById("benign-box-container");
  const benignAssurancesList = document.getElementById("benign-assurances-list");
  const riskFactorsContainer = document.getElementById("risk-factors-container");
  const threatJustificationsContainer = document.getElementById("threat-justifications-container");
  const trustNoteContent = document.getElementById("trust-note-content");

  // Feature 3 DOM
  const evidenceHashVal = document.getElementById("evidence-hash-value");
  const forensicFrom = document.getElementById("forensic-from");
  const forensicReplyTo = document.getElementById("forensic-reply-to");
  const forensicReturnPath = document.getElementById("forensic-return-path");
  const forensicMessageId = document.getElementById("forensic-message-id");
  const badgeReplyToStatus = document.getElementById("badge-reply-to-status");
  const badgeReturnPathStatus = document.getElementById("badge-return-path-status");
  const authSpfStatus = document.getElementById("auth-spf-status");
  const authDkimStatus = document.getElementById("auth-dkim-status");
  const authDmarcStatus = document.getElementById("auth-dmarc-status");
  const overallAuthBadge = document.getElementById("overall-auth-badge");
  const relayHopsContainer = document.getElementById("relay-hops-container");
  const originatingCandidateText = document.getElementById("originating-candidate-text");
  const forensicAnomaliesList = document.getElementById("forensic-anomalies-list");
  const forensicAttachmentsList = document.getElementById("forensic-attachments-list");

  // Feature 4 DOM
  const btnCopyAllIocs = document.getElementById("btn-copy-all-iocs");
  const btnExportIocJson = document.getElementById("btn-export-ioc-json");
  const iocCountUrls = document.getElementById("ioc-count-urls");
  const iocCountDomains = document.getElementById("ioc-count-domains");
  const iocCountIps = document.getElementById("ioc-count-ips");
  const iocCountEmails = document.getElementById("ioc-count-emails");
  const iocCountHashes = document.getElementById("ioc-count-hashes");
  const iocCountHostnames = document.getElementById("ioc-count-hostnames");
  const iocCountAttachments = document.getElementById("ioc-count-attachments");
  
  const iocListUrls = document.getElementById("ioc-list-urls");
  const iocListDomains = document.getElementById("ioc-list-domains");
  const iocListIps = document.getElementById("ioc-list-ips");
  const iocListHashes = document.getElementById("ioc-list-hashes");
  const iocListEmails = document.getElementById("ioc-list-emails");
  const iocListHostnames = document.getElementById("ioc-list-hostnames");

  // Feature 5 DOM
  const intelModeBadge = document.getElementById("intel-mode-badge");
  const intelCountAnalyzed = document.getElementById("intel-count-analyzed");
  const intelCountMalicious = document.getElementById("intel-count-malicious");
  const intelCountSuspicious = document.getElementById("intel-count-suspicious");
  const intelCountClean = document.getElementById("intel-count-clean");
  const intelCountUnknown = document.getElementById("intel-count-unknown");
  const intelCardsContainer = document.getElementById("intel-cards-container");

  // Demo & Upload DOM
  const btnUploadEml = document.getElementById("btn-upload-eml");
  const emlFileInput = document.getElementById("eml-file-input");
  const demoButtons = {
    phishing: document.getElementById("btn-demo-phishing"),
    bec: document.getElementById("btn-demo-bec"),
    impersonation: document.getElementById("btn-demo-impersonation"),
    benign: document.getElementById("btn-demo-benign"),
    malware: document.getElementById("btn-demo-malware")
  };

  let cachedDemoEmls = {};
  let currentIocResult = null;

  // Fetch demo EML fixtures
  async function loadDemoCatalog() {
    try {
      const resp = await fetch("/api/v1/demo-emls");
      if (resp.ok) {
        cachedDemoEmls = await resp.json();
      }
    } catch (e) {
      console.warn("Could not preload demo EMLs:", e);
    }
  }

  // Load a demo scenario
  async function activateDemo(scenarioKey) {
    Object.values(demoButtons).forEach(btn => btn && btn.classList.remove("active"));
    if (demoButtons[scenarioKey]) {
      demoButtons[scenarioKey].classList.add("active");
    }

    const rawEml = cachedDemoEmls[scenarioKey] || cachedDemoEmls["phishing"];
    if (rawEml) {
      await executeEmlAnalysis(rawEml);
    }
  }

  // Execute complete EML analysis (Features 1, 2, 3, 4, and 5)
  async function executeEmlAnalysis(rawEmlContent) {
    btnAnalyze.disabled = true;
    btnAnalyze.innerHTML = `<span>Querying Forensics, Threat Intelligence & IOCs...</span>`;

    try {
      const resp = await fetch("/api/v1/analyze/eml", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_eml: rawEmlContent })
      });

      if (!resp.ok) {
        throw new Error(`Server returned status ${resp.status}`);
      }

      const result = await resp.json();

      // Synchronize form inputs with parsed email data
      syncFormFromForensics(result.forensics);

      // Render all 5 feature panels
      renderThreatDetection(result.threat_analysis);
      renderExplainableAI(result.explanation);
      renderEmailForensics(result.forensics);
      renderIocExtraction(result.iocs);
      renderThreatIntelligence(result.threat_intelligence);

    } catch (err) {
      console.error("EML Analysis failed:", err);
      alert("Error analyzing email: " + err.message);
    } finally {
      btnAnalyze.disabled = false;
      btnAnalyze.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
        </svg>
        Execute Threat, Forensic, IOC & Intel Analysis
      `;
    }
  }

  // Synchronize input fields with parsed email
  function syncFormFromForensics(forensics) {
    if (!forensics) return;
    const sender = forensics.sender_identity.display_name 
      ? `${forensics.sender_identity.display_name} <${forensics.sender_identity.from_address}>`
      : forensics.sender_identity.from_address;
    
    inputSender.value = sender || "";
    inputReplyTo.value = forensics.sender_identity.reply_to_address || "";
    inputReturnPath.value = forensics.sender_identity.return_path_address || "";
    inputRecipient.value = forensics.headers["To"] || forensics.headers["to"] || "";
    inputSubject.value = forensics.subject || "";
    inputBody.value = forensics.mime_analysis.plain_text_preview || "";

    if (forensics.authentication.spf.result) {
      inputSpf.value = forensics.authentication.spf.result.toLowerCase();
    }
    if (forensics.authentication.dkim.result) {
      inputDkim.value = forensics.authentication.dkim.result.toLowerCase();
    }
    if (forensics.authentication.dmarc.result) {
      inputDmarc.value = forensics.authentication.dmarc.result.toLowerCase();
    }
  }

  // Render Feature 1: AI Threat Detection
  function renderThreatDetection(threatData) {
    if (!threatData) return;

    threatScoreVal.textContent = threatData.threat_score;
    riskLevelBadge.textContent = `${threatData.risk_level} RISK`;
    riskLevelBadge.className = `risk-badge risk-${threatData.risk_level.toLowerCase()}`;

    scoreHero.className = `score-hero`;
    if (threatData.risk_level === "CRITICAL") scoreHero.style.setProperty("--risk-critical", "#ef4444");

    primaryThreatName.textContent = threatData.primary_threat;
    const primaryConf = threatData.threat_types.find(t => t.type === threatData.primary_threat);
    primaryThreatConfidence.textContent = primaryConf ? `${Math.round(primaryConf.confidence * 100)}% Conf` : "Detected";

    secondaryThreatsList.innerHTML = "";
    const secondaries = threatData.threat_types.filter(t => t.type !== threatData.primary_threat);
    if (secondaries.length === 0) {
      secondaryThreatsList.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-dim);">No elevated secondary vectors.</div>`;
    } else {
      secondaries.forEach(item => {
        const row = document.createElement("div");
        row.className = "threat-row";
        row.innerHTML = `
          <span class="threat-row-name">${item.type}</span>
          <span class="threat-confidence">${Math.round(item.confidence * 100)}%</span>
        `;
        secondaryThreatsList.appendChild(row);
      });
    }
  }

  // Render Feature 2: Explainable AI (XAI)
  function renderExplainableAI(xaiData) {
    if (!xaiData) return;

    nlSummaryContent.textContent = xaiData.summary;

    if (xaiData.is_benign && xaiData.benign_assurances && xaiData.benign_assurances.length > 0) {
      benignBox.style.display = "block";
      benignAssurancesList.innerHTML = xaiData.benign_assurances.map(item => `
        <div class="benign-check-item">
          <span class="check-icon">&#10003;</span>
          <span>${escapeHtml(item)}</span>
        </div>
      `).join("");
    } else {
      benignBox.style.display = "none";
      benignAssurancesList.innerHTML = "";
    }

    riskFactorsContainer.innerHTML = "";
    if (xaiData.risk_factors.length === 0) {
      riskFactorsContainer.innerHTML = `
        <div class="factor-card" style="text-align: center; color: #34d399; padding: 2rem;">
          <div style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem;">&#10003; Zero Elevated Risk Factors Detected</div>
          <div style="font-size: 0.85rem; color: var(--text-muted);">This message does not exhibit social engineering or protocol anomaly markers.</div>
        </div>
      `;
    } else {
      xaiData.risk_factors.forEach(factor => {
        const pct = Math.min(100, Math.round((factor.contribution / 20) * 100));
        const dotClass = `dot-${factor.severity.toLowerCase()}`;
        const card = document.createElement("div");
        card.className = "factor-card";
        card.innerHTML = `
          <div class="factor-top">
            <div class="factor-name-wrapper">
              <span class="factor-severity-dot ${dotClass}"></span>
              <span class="factor-title">${escapeHtml(factor.label)}</span>
              <span class="factor-category-tag">${escapeHtml(factor.category)}</span>
            </div>
            <span class="factor-score-pill">+${factor.contribution}</span>
          </div>
          <div class="contrib-bar-container">
            <div class="contrib-bar-fill" style="width: ${pct}%;"></div>
          </div>
          <div class="factor-desc">${escapeHtml(factor.explanation)}</div>
          ${factor.evidence ? `
            <div class="evidence-quote">
              <span class="evidence-label">Evidence:</span>
              <span>${escapeHtml(factor.evidence)}</span>
            </div>
          ` : ""}
        `;
        riskFactorsContainer.appendChild(card);
      });
    }

    threatJustificationsContainer.innerHTML = "";
    xaiData.threat_explanations.forEach(item => {
      const el = document.createElement("div");
      el.className = "threat-explanation-item";
      el.innerHTML = `
        <div class="threat-explanation-top">
          <div class="threat-type-heading">
            ${escapeHtml(item.type)}
            <span class="threat-type-badge">${Math.round(item.confidence * 100)}% Conf</span>
          </div>
          <div class="threat-confidence-meter">Certainty: ${Math.round(item.confidence * 100)}%</div>
        </div>
        <div class="threat-type-reason">${escapeHtml(item.explanation)}</div>
      `;
      threatJustificationsContainer.appendChild(el);
    });

    if (xaiData.confidence_note) {
      trustNoteContent.innerHTML = `
        <strong>Assessment Boundaries & Uncertainty Note</strong><br>
        ${escapeHtml(xaiData.confidence_note)}
      `;
    }
  }

  // Render Feature 3: Email Forensics
  function renderEmailForensics(forensics) {
    if (!forensics) return;

    evidenceHashVal.textContent = forensics.raw_evidence_hash;
    evidenceHashVal.title = `SHA-256: ${forensics.raw_evidence_hash}`;

    forensicFrom.textContent = forensics.sender_identity.from_address || "(None)";
    forensicReplyTo.textContent = forensics.sender_identity.reply_to_address || "(None)";
    forensicReturnPath.textContent = forensics.sender_identity.return_path_address || "(None)";
    forensicMessageId.textContent = forensics.message_id || "(Not Present)";

    if (forensics.sender_identity.reply_to_mismatch) {
      badgeReplyToStatus.className = "mismatch-badge";
      badgeReplyToStatus.innerHTML = `&#9888; Mismatch`;
    } else {
      badgeReplyToStatus.className = "match-badge";
      badgeReplyToStatus.textContent = "Aligned";
    }

    if (forensics.sender_identity.return_path_mismatch) {
      badgeReturnPathStatus.className = "mismatch-badge";
      badgeReturnPathStatus.innerHTML = `&#9888; Mismatch`;
    } else {
      badgeReturnPathStatus.className = "match-badge";
      badgeReturnPathStatus.textContent = "Aligned";
    }

    const renderAuthPill = (statusStr) => {
      const s = (statusStr || "unknown").toLowerCase();
      if (s === "pass") return `<span class="auth-matrix-status auth-pass">PASS</span>`;
      if (s === "fail") return `<span class="auth-matrix-status auth-fail">FAIL</span>`;
      if (s === "neutral" || s === "softfail") return `<span class="auth-matrix-status auth-neutral">${s.toUpperCase()}</span>`;
      return `<span class="auth-matrix-status auth-unknown">${s.toUpperCase()}</span>`;
    };

    authSpfStatus.innerHTML = renderAuthPill(forensics.authentication.spf.result);
    authDkimStatus.innerHTML = renderAuthPill(forensics.authentication.dkim.result);
    authDmarcStatus.innerHTML = renderAuthPill(forensics.authentication.dmarc.result);

    overallAuthBadge.textContent = forensics.authentication.overall_status;
    if (forensics.authentication.overall_status === "VERIFIED") {
      overallAuthBadge.style.color = "#10b981";
    } else if (forensics.authentication.overall_status === "PARTIALLY_VERIFIED") {
      overallAuthBadge.style.color = "#38bdf8";
    } else {
      overallAuthBadge.style.color = "#ef4444";
    }

    relayHopsContainer.innerHTML = "";
    if (!forensics.relay_path || forensics.relay_path.length === 0) {
      relayHopsContainer.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-dim);">No Received headers present in email.</div>`;
    } else {
      forensics.relay_path.forEach((hop, i) => {
        const hopDiv = document.createElement("div");
        hopDiv.className = "relay-hop-card";
        hopDiv.innerHTML = `
          <div class="relay-hop-top">
            <span class="hop-tag">HOP #${hop.hop_number}</span>
            <span class="hop-time">${hop.delay_seconds !== null ? `delay: +${hop.delay_seconds}s` : "transit start"}</span>
          </div>
          <div class="hop-route">
            <strong>from:</strong> ${escapeHtml(hop.from_host || "unknown")} 
            ${hop.from_ip ? `<span style="color:#38bdf8;">(${escapeHtml(hop.from_ip)})</span>` : ""}
            <br><strong>by:</strong> ${escapeHtml(hop.by_host || "unknown")}
          </div>
          <div class="hop-meta">
            <span>protocol: ${escapeHtml(hop.protocol || "SMTP")}</span>
            ${hop.timestamp_iso ? `<span>${escapeHtml(hop.timestamp_iso.replace("T", " "))}</span>` : ""}
          </div>
        `;
        relayHopsContainer.appendChild(hopDiv);

        if (i < forensics.relay_path.length - 1) {
          const arrow = document.createElement("div");
          arrow.className = "relay-connector-arrow";
          arrow.textContent = "↓";
          relayHopsContainer.appendChild(arrow);
        }
      });
    }

    originatingCandidateText.textContent = forensics.routing_analysis.originating_infrastructure_candidate || "Undetermined";

    forensicAnomaliesList.innerHTML = "";
    if (!forensics.anomalies || forensics.anomalies.length === 0) {
      forensicAnomaliesList.innerHTML = `<div style="font-size: 0.8rem; color: #34d399;">&#10003; No structural routing anomalies detected.</div>`;
    } else {
      forensics.anomalies.forEach(anom => {
        const row = document.createElement("div");
        row.className = "anomaly-row";
        const badgeClass = `anomaly-${(anom.severity || "medium").toLowerCase()}`;
        row.innerHTML = `
          <span class="anomaly-badge ${badgeClass}">${escapeHtml(anom.severity)}</span>
          <div>
            <div style="font-weight: 600; color: var(--text-main); font-size: 0.78rem;">${escapeHtml(anom.type.replace(/_/g, " "))}</div>
            <div style="color: var(--text-muted); font-size: 0.74rem;">${escapeHtml(anom.description)}</div>
          </div>
        `;
        forensicAnomaliesList.appendChild(row);
      });
    }

    forensicAttachmentsList.innerHTML = "";
    if (!forensics.attachments || forensics.attachments.length === 0) {
      forensicAttachmentsList.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-dim);">No attachments detected in MIME structure.</div>`;
    } else {
      forensics.attachments.forEach(att => {
        const attCard = document.createElement("div");
        attCard.className = "attachment-row";
        const hasWarning = att.indicators && att.indicators.length > 0;
        attCard.innerHTML = `
          <div class="attachment-row-top">
            <span class="attachment-filename">
              &#128206; ${escapeHtml(att.filename)}
            </span>
            <span class="attachment-size">${formatBytes(att.size_bytes)}</span>
          </div>
          <div class="attachment-hash">SHA-256: ${att.sha256_hash}</div>
          ${hasWarning ? att.indicators.map(ind => `
            <span class="attachment-warning-tag">&#9888; ${escapeHtml(ind.replace(/_/g, " "))}</span>
          `).join(" ") : ""}
        `;
        forensicAttachmentsList.appendChild(attCard);
      });
    }
  }

  // Render Feature 4: IOC Extraction
  function renderIocExtraction(iocs) {
    if (!iocs) return;
    currentIocResult = iocs;

    // Summary counts
    iocCountUrls.textContent = iocs.summary.urls;
    iocCountDomains.textContent = iocs.summary.domains;
    iocCountIps.textContent = iocs.summary.ips;
    iocCountEmails.textContent = iocs.summary.emails;
    iocCountHashes.textContent = iocs.summary.hashes;
    iocCountHostnames.textContent = iocs.summary.hostnames;
    iocCountAttachments.textContent = iocs.summary.attachments;

    // 1. URLs
    iocListUrls.innerHTML = "";
    if (iocs.urls.length === 0) {
      iocListUrls.innerHTML = `<div style="font-size: 0.78rem; color: var(--text-dim);">No URLs extracted.</div>`;
    } else {
      iocs.urls.forEach(u => {
        const item = document.createElement("div");
        item.className = "ioc-item";
        item.innerHTML = `
          <div class="ioc-item-row">
            <span class="ioc-val">${escapeHtml(u.normalized)}</span>
            <button type="button" class="btn-copy-single" title="Copy URL" onclick="navigator.clipboard.writeText('${escapeJs(u.normalized)}')">
              &#128203;
            </button>
          </div>
          <div style="display: flex; gap: 4px; flex-wrap: wrap;">
            ${u.sources.map(s => `<span class="ioc-source-badge">${escapeHtml(s)}</span>`).join("")}
          </div>
        `;
        iocListUrls.appendChild(item);
      });
    }

    // 2. Domains
    iocListDomains.innerHTML = "";
    if (iocs.domains.length === 0) {
      iocListDomains.innerHTML = `<div style="font-size: 0.78rem; color: var(--text-dim);">No domains extracted.</div>`;
    } else {
      iocs.domains.forEach(d => {
        const item = document.createElement("div");
        item.className = "ioc-item";
        item.innerHTML = `
          <div class="ioc-item-row">
            <span class="ioc-val">${escapeHtml(d.value)}</span>
            <button type="button" class="btn-copy-single" title="Copy Domain" onclick="navigator.clipboard.writeText('${escapeJs(d.value)}')">
              &#128203;
            </button>
          </div>
          <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
            ${d.registered_domain ? `<span style="font-size: 0.7rem; color: var(--accent-cyan);">root: ${escapeHtml(d.registered_domain)}</span>` : ""}
            ${d.is_punycode ? `<span class="mismatch-badge">IDN Punycode</span>` : ""}
            ${d.sources.map(s => `<span class="ioc-source-badge">${escapeHtml(s)}</span>`).join("")}
          </div>
        `;
        iocListDomains.appendChild(item);
      });
    }

    // 3. IP Addresses
    iocListIps.innerHTML = "";
    if (iocs.ips.length === 0) {
      iocListIps.innerHTML = `<div style="font-size: 0.78rem; color: var(--text-dim);">No IP addresses extracted.</div>`;
    } else {
      iocs.ips.forEach(ip => {
        const item = document.createElement("div");
        item.className = "ioc-item";
        const scopeClass = `scope-${ip.scope.toLowerCase()}`;
        item.innerHTML = `
          <div class="ioc-item-row">
            <span class="ioc-val">${escapeHtml(ip.value)}</span>
            <div style="display: flex; gap: 6px; align-items: center;">
              <span class="scope-badge ${scopeClass}">${escapeHtml(ip.scope)}</span>
              <button type="button" class="btn-copy-single" title="Copy IP" onclick="navigator.clipboard.writeText('${escapeJs(ip.value)}')">
                &#128203;
              </button>
            </div>
          </div>
          <div style="display: flex; gap: 4px; flex-wrap: wrap;">
            <span style="font-size: 0.7rem; color: var(--text-dim);">IPv${ip.version}</span>
            ${ip.sources.map(s => `<span class="ioc-source-badge">${escapeHtml(s)}</span>`).join("")}
          </div>
        `;
        iocListIps.appendChild(item);
      });
    }

    // 4. Hashes
    iocListHashes.innerHTML = "";
    if (iocs.hashes.length === 0) {
      iocListHashes.innerHTML = `<div style="font-size: 0.78rem; color: var(--text-dim);">No cryptographic hashes extracted.</div>`;
    } else {
      iocs.hashes.forEach(h => {
        const item = document.createElement("div");
        item.className = "ioc-item";
        item.innerHTML = `
          <div class="ioc-item-row">
            <span style="font-weight: 700; font-size: 0.75rem; color: #a855f7;">${escapeHtml(h.algorithm)}</span>
            <button type="button" class="btn-copy-single" title="Copy Hash" onclick="navigator.clipboard.writeText('${escapeJs(h.value)}')">
              &#128203;
            </button>
          </div>
          <span class="ioc-val" style="color: #e9d5ff;">${escapeHtml(h.value)}</span>
          <div style="display: flex; gap: 4px; flex-wrap: wrap;">
            ${h.sources.map(s => `<span class="ioc-source-badge">${escapeHtml(s)}</span>`).join("")}
          </div>
        `;
        iocListHashes.appendChild(item);
      });
    }

    // 5. Emails
    iocListEmails.innerHTML = "";
    if (iocs.emails.length === 0) {
      iocListEmails.innerHTML = `<div style="font-size: 0.78rem; color: var(--text-dim);">No email addresses extracted.</div>`;
    } else {
      iocs.emails.forEach(e => {
        const item = document.createElement("div");
        item.className = "ioc-item";
        item.innerHTML = `
          <div class="ioc-item-row">
            <span class="ioc-val" style="color: #38bdf8;">${escapeHtml(e.value)}</span>
            <button type="button" class="btn-copy-single" title="Copy Email" onclick="navigator.clipboard.writeText('${escapeJs(e.value)}')">
              &#128203;
            </button>
          </div>
          <div style="display: flex; gap: 4px; flex-wrap: wrap;">
            ${e.sources.map(s => `<span class="ioc-source-badge">${escapeHtml(s)}</span>`).join("")}
          </div>
        `;
        iocListEmails.appendChild(item);
      });
    }

    // 6. Hostnames
    iocListHostnames.innerHTML = "";
    if (iocs.hostnames.length === 0) {
      iocListHostnames.innerHTML = `<div style="font-size: 0.78rem; color: var(--text-dim);">No hostnames extracted.</div>`;
    } else {
      iocs.hostnames.forEach(hn => {
        const item = document.createElement("div");
        item.className = "ioc-item";
        item.innerHTML = `
          <div class="ioc-item-row">
            <span class="ioc-val">${escapeHtml(hn.value)}</span>
            <button type="button" class="btn-copy-single" title="Copy Hostname" onclick="navigator.clipboard.writeText('${escapeJs(hn.value)}')">
              &#128203;
            </button>
          </div>
          <div style="display: flex; gap: 4px; flex-wrap: wrap;">
            ${hn.sources.map(s => `<span class="ioc-source-badge">${escapeHtml(s)}</span>`).join("")}
          </div>
        `;
        iocListHostnames.appendChild(item);
      });
    }
  }

  // Render Feature 5: Threat Intelligence
  function renderThreatIntelligence(intel) {
    if (!intel) return;

    // Summary counts
    intelCountAnalyzed.textContent = intel.summary.total_analyzed;
    intelCountMalicious.textContent = intel.summary.malicious_count;
    intelCountSuspicious.textContent = intel.summary.suspicious_count;
    intelCountClean.textContent = intel.summary.clean_reported_count;
    intelCountUnknown.textContent = intel.summary.unknown_count;

    // Mode Badge
    if (intel.summary.is_demo_mode) {
      intelModeBadge.className = "intel-mode-pill intel-mode-demo";
      intelModeBadge.innerHTML = `<span>⚡ Demo Intelligence</span>`;
    } else {
      intelModeBadge.className = "intel-mode-pill intel-mode-live";
      intelModeBadge.innerHTML = `<span>🟢 Live Intel</span>`;
    }

    // Render Cards
    intelCardsContainer.innerHTML = "";
    if (!intel.results || intel.results.length === 0) {
      intelCardsContainer.innerHTML = `<div style="font-size: 0.85rem; color: var(--text-dim); text-align: center; padding: 1.5rem;">No indicators queried.</div>`;
      return;
    }

    intel.results.forEach(item => {
      const card = document.createElement("div");
      card.className = "intel-card";

      // Status badge styling
      let statusClass = "intel-status-unknown";
      let statusIcon = "⚪";
      if (item.normalized_status === "MALICIOUS") {
        statusClass = "intel-status-malicious";
        statusIcon = "🔴";
      } else if (item.normalized_status === "SUSPICIOUS") {
        statusClass = "intel-status-suspicious";
        statusIcon = "🟠";
      } else if (item.normalized_status === "CLEAN_REPORTED") {
        statusClass = "intel-status-clean";
        statusIcon = "🟢";
      } else if (item.normalized_status === "NOT_CONFIGURED") {
        statusClass = "intel-status-unconfigured";
        statusIcon = "⚙";
      }

      // Provider blocks
      const vt = item.providers.virustotal;
      const abuse = item.providers.abuseipdb;

      let providerRowsHtml = "";

      // VirusTotal block
      if (vt) {
        providerRowsHtml += `
          <div class="provider-box">
            <div class="provider-box-header">
              <span class="provider-name">VirusTotal API v3</span>
              <span style="font-size: 0.7rem; color: var(--text-dim);">${escapeHtml(vt.status)}</span>
            </div>
            <div class="provider-stat">
              <span class="provider-stat-label">Vendor Detections:</span>
              <span class="provider-stat-value" style="color: ${vt.malicious_votes > 0 ? '#f87171' : '#34d399'};">
                ${vt.malicious_votes || 0} malicious ${vt.suspicious_votes ? `(${vt.suspicious_votes} suspicious)` : ""}
              </span>
            </div>
            ${vt.reputation !== null && vt.reputation !== undefined ? `
              <div class="provider-stat">
                <span class="provider-stat-label">Community Reputation:</span>
                <span class="provider-stat-value">${vt.reputation}</span>
              </div>
            ` : ""}
            ${vt.categories && vt.categories.length > 0 ? `
              <div class="provider-stat">
                <span class="provider-stat-label">Categories:</span>
                <span style="font-size: 0.75rem; color: #cbd5e1;">${escapeHtml(vt.categories.join(", "))}</span>
              </div>
            ` : ""}
            ${vt.country ? `
              <div class="provider-stat">
                <span class="provider-stat-label">Country / ASN:</span>
                <span class="provider-stat-value">${escapeHtml(vt.country)} ${vt.asn ? `(AS${vt.asn})` : ""}</span>
              </div>
            ` : ""}
          </div>
        `;
      }

      // AbuseIPDB block
      if (abuse && abuse.status !== "SKIPPED") {
        providerRowsHtml += `
          <div class="provider-box">
            <div class="provider-box-header">
              <span class="provider-name">AbuseIPDB API v2</span>
              <span style="font-size: 0.7rem; color: var(--text-dim);">${escapeHtml(abuse.status)}</span>
            </div>
            <div class="provider-stat">
              <span class="provider-stat-label">Abuse Confidence:</span>
              <span class="provider-stat-value" style="color: ${abuse.abuse_confidence > 20 ? '#f87171' : '#34d399'};">
                ${abuse.abuse_confidence}%
              </span>
            </div>
            <div class="provider-stat">
              <span class="provider-stat-label">Reported Incidents:</span>
              <span class="provider-stat-value">${abuse.total_reports} reports</span>
            </div>
            ${abuse.isp ? `
              <div class="provider-stat">
                <span class="provider-stat-label">ISP:</span>
                <span style="font-size: 0.75rem; color: #cbd5e1;">${escapeHtml(abuse.isp)}</span>
              </div>
            ` : ""}
            ${abuse.usage_type ? `
              <div class="provider-stat">
                <span class="provider-stat-label">Usage:</span>
                <span style="font-size: 0.75rem; color: var(--text-dim);">${escapeHtml(abuse.usage_type)}</span>
              </div>
            ` : ""}
          </div>
        `;
      } else if (abuse && abuse.status === "SKIPPED") {
        providerRowsHtml += `
          <div class="provider-box" style="opacity: 0.7;">
            <div class="provider-box-header">
              <span class="provider-name">AbuseIPDB</span>
              <span style="font-size: 0.7rem; color: #f59e0b;">SKIPPED</span>
            </div>
            <div style="font-size: 0.75rem; color: var(--text-dim);">
              Non-public / private network scope. External lookup prohibited for data privacy.
            </div>
          </div>
        `;
      }

      card.innerHTML = `
        <div class="intel-card-top">
          <div class="intel-indicator-wrap">
            <span class="intel-type-tag">${escapeHtml(item.ioc_type)}</span>
            <span class="intel-indicator-val">${escapeHtml(item.indicator)}</span>
          </div>
          <div class="intel-status-badge ${statusClass}">
            <span>${statusIcon}</span>
            <span>${escapeHtml(item.normalized_status.replace(/_/g, " "))}</span>
          </div>
        </div>
        <div class="provider-intel-row">
          ${providerRowsHtml}
        </div>
        <div class="intel-reason-box">
          <strong>Intelligence Assessment:</strong> ${escapeHtml(item.status_reason)}
        </div>
      `;

      intelCardsContainer.appendChild(card);
    });
  }

  // Copy All IOCs Handler
  btnCopyAllIocs.addEventListener("click", () => {
    if (!currentIocResult) return;
    const lines = ["# MailTrace AI - Extracted Indicators of Compromise (IOCs)"];

    if (currentIocResult.urls.length) {
      lines.push("\n## URLs");
      currentIocResult.urls.forEach(u => lines.push(u.normalized));
    }
    if (currentIocResult.domains.length) {
      lines.push("\n## Domains");
      currentIocResult.domains.forEach(d => lines.push(d.value));
    }
    if (currentIocResult.ips.length) {
      lines.push("\n## IP Addresses");
      currentIocResult.ips.forEach(i => lines.push(`${i.value} (${i.scope})`));
    }
    if (currentIocResult.emails.length) {
      lines.push("\n## Email Addresses");
      currentIocResult.emails.forEach(e => lines.push(e.value));
    }
    if (currentIocResult.hashes.length) {
      lines.push("\n## Cryptographic Hashes");
      currentIocResult.hashes.forEach(h => lines.push(`${h.algorithm}: ${h.value}`));
    }

    navigator.clipboard.writeText(lines.join("\n")).then(() => {
      btnCopyAllIocs.innerHTML = `&#10003; Copied!`;
      setTimeout(() => {
        btnCopyAllIocs.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
          Copy All IOCs
        `;
      }, 2000);
    });
  });

  // Export IOC JSON Handler
  btnExportIocJson.addEventListener("click", () => {
    if (!currentIocResult) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentIocResult, null, 2));
    const dlAnchor = document.createElement("a");
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", "mailtrace_iocs.json");
    dlAnchor.click();
  });

  // Format bytes helper
  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }

  // HTML escaping helper
  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function escapeJs(str) {
    if (!str) return "";
    return String(str).replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  }

  // Handle manual form submission
  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const rawEml = [
      `From: ${inputSender.value}`,
      `To: ${inputRecipient.value}`,
      inputReplyTo.value ? `Reply-To: ${inputReplyTo.value}` : "",
      inputReturnPath.value ? `Return-Path: ${inputReturnPath.value}` : "",
      `Subject: ${inputSubject.value}`,
      `Date: ${new Date().toUTCString()}`,
      `Authentication-Results: local-relay; spf=${inputSpf.value}; dkim=${inputDkim.value}; dmarc=${inputDmarc.value}`,
      `Content-Type: text/plain; charset=utf-8`,
      "",
      inputBody.value
    ].filter(line => line !== null).join("\r\n");

    await executeEmlAnalysis(rawEml);
  });

  // Handle .eml file upload
  btnUploadEml.addEventListener("click", () => {
    emlFileInput.click();
  });

  emlFileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (event) => {
      const content = event.target.result;
      await executeEmlAnalysis(content);
    };
    reader.readAsText(file);
  });

  // Demo button click handlers
  Object.keys(demoButtons).forEach(key => {
    if (demoButtons[key]) {
      demoButtons[key].addEventListener("click", () => activateDemo(key));
    }
  });

  // Initialize application
  loadDemoCatalog().then(() => {
    activateDemo("phishing");
  });
});
