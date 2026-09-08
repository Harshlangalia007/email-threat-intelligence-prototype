/**
 * SOC Analyst Platform Application Controller for SIH26106
 * Manages view routing, REST API communication, sample loading, telemetry,
 * forensic timeline rendering, graph inspection, and unified report generation.
 */

class SocPlatformApp {
  constructor() {
    this.currentCase = null;
    this.graphVisualizer = null;
    this.viewMode = localStorage.getItem('soc_view_mode') || 'simple';
    this.activeTab = this.viewMode === 'soc' ? 'threat' : 'simple';

    this.init();
  }

  async init() {
    this.bindNavigation();
    this.bindAudienceModeToggle();
    this.bindProgressiveDisclosure();
    this.bindSampleButtons();
    this.bindMailboxEvents();
    this.initGraph();
    await this.refreshDashboardMetrics();
    await this.loadRecentCases();
    await this.checkMailboxStatus();

    // Auto-load Sample 2 (Phishing) by default so the user immediately lands on results
    this.loadSample('sample_2_phishing');
  }

  // =========================================================================
  // NAVIGATION & TAB SWITCHING
  // =========================================================================

  bindNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const tab = item.dataset.tab;
        this.switchTab(tab);
      });
    });
  }

  switchTab(tabName) {
    this.activeTab = tabName;
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.tab === tabName);
    });

    document.querySelectorAll('.tab-pane').forEach(el => {
      el.classList.toggle('active', el.id === `tab-${tabName}`);
    });

    if (tabName === 'graph' && this.graphVisualizer && this.currentCase) {
      setTimeout(() => {
        this.graphVisualizer._setupCanvas();
        if (this.currentCase.graph_data) {
          this.graphVisualizer.loadGraphData(this.currentCase.graph_data);
        }
      }, 50);
    }
  }

  bindAudienceModeToggle() {
    const btnSimple = document.getElementById('btn-mode-simple');
    const btnSoc = document.getElementById('btn-mode-soc');
    const socNavItems = document.querySelectorAll('.soc-only');
    const badgeText = document.getElementById('soc-badge-text');

    const setMode = (mode) => {
      this.viewMode = mode;
      localStorage.setItem('soc_view_mode', mode);

      if (btnSimple && btnSoc) {
        btnSimple.classList.toggle('active', mode === 'simple');
        btnSoc.classList.toggle('active', mode === 'soc');
        btnSoc.classList.toggle('soc-active', mode === 'soc');
      }

      if (mode === 'simple') {
        socNavItems.forEach(el => el.style.display = 'none');
        if (badgeText) badgeText.textContent = 'SHIELD ACTIVE';
        this.switchTab('simple');
      } else {
        socNavItems.forEach(el => el.style.display = 'inline-flex');
        if (badgeText) badgeText.textContent = 'SOC SENSORS ACTIVE';
        if (this.activeTab === 'simple') {
          this.switchTab('threat');
        }
      }
    };

    if (btnSimple) {
      btnSimple.addEventListener('click', () => setMode('simple'));
    }

    if (btnSoc) {
      btnSoc.addEventListener('click', () => setMode('soc'));
    }

    // Initialize mode
    setMode(this.viewMode);
  }

  bindProgressiveDisclosure() {
    const toggleBtn = document.getElementById('btn-toggle-tech-details');
    const panel = document.getElementById('tech-details-panel');
    const chevron = document.getElementById('accordion-chevron');

    if (toggleBtn && panel) {
      toggleBtn.addEventListener('click', () => {
        const isOpen = panel.classList.toggle('open');
        toggleBtn.classList.toggle('open', isOpen);
        if (chevron) chevron.innerHTML = isOpen ? '&#x25B2;' : '&#x25BC;';
      });
    }

    // Copy Raw Headers
    const copyBtn = document.getElementById('btn-copy-headers');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        const rawPre = document.getElementById('simple-raw-headers-pre');
        if (rawPre && rawPre.textContent) {
          navigator.clipboard.writeText(rawPre.textContent);
          this.showToast("Raw RFC 5322 email headers copied to clipboard!");
        }
      });
    }

    // Report Phishing Button
    const reportBtn = document.getElementById('btn-report-phishing');
    if (reportBtn) {
      reportBtn.addEventListener('click', () => {
        this.showToast("🚨 Email successfully reported to IT Security Operations. Thank you for protecting your organization!");
      });
    }

    // Mark as Safe Button
    const markSafeBtn = document.getElementById('btn-mark-safe');
    if (markSafeBtn) {
      markSafeBtn.addEventListener('click', () => {
        this.showToast("✓ Sender marked as known contact in your security profile.");
      });
    }

    // Jump Links to Full SOC Specialist Cockpit
    const jumpThreatBtn = document.getElementById('btn-switch-to-soc-threat');
    if (jumpThreatBtn) {
      jumpThreatBtn.addEventListener('click', () => {
        const btnSoc = document.getElementById('btn-mode-soc');
        if (btnSoc) btnSoc.click();
        this.switchTab('threat');
      });
    }

    const jumpGraphBtn = document.getElementById('btn-switch-to-soc-graph');
    if (jumpGraphBtn) {
      jumpGraphBtn.addEventListener('click', () => {
        const btnSoc = document.getElementById('btn-mode-soc');
        if (btnSoc) btnSoc.click();
        this.switchTab('graph');
      });
    }
  }

  showToast(message) {
    let toast = document.getElementById('soc-toast-notification');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'soc-toast-notification';
      toast.className = 'soc-toast';
      document.body.appendChild(toast);
    }
    toast.innerHTML = `<span>${this.escapeHtml(message)}</span>`;
    toast.style.display = 'flex';

    clearTimeout(this._toastTimeout);
    this._toastTimeout = setTimeout(() => {
      toast.style.display = 'none';
    }, 4500);
  }

  // =========================================================================
  // SAMPLE LOADER & FILE UPLOAD
  // =========================================================================

  bindSampleButtons() {
    document.querySelectorAll('.sample-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const sampleId = btn.dataset.sampleId;
        this.loadSample(sampleId);
      });
    });

    // Modal open/close
    const modalBackdrop = document.getElementById('eml-modal');
    const openBtn = document.getElementById('btn-open-upload');
    const closeBtn = document.getElementById('btn-close-modal');

    if (openBtn && modalBackdrop) {
      openBtn.addEventListener('click', () => modalBackdrop.classList.add('open'));
    }
    if (closeBtn && modalBackdrop) {
      closeBtn.addEventListener('click', () => modalBackdrop.classList.remove('open'));
    }

    // Modal analyze button
    const analyzeBtn = document.getElementById('btn-analyze-pasted');
    if (analyzeBtn) {
      analyzeBtn.addEventListener('click', () => this.analyzePastedEml());
    }

    // File input / dropzone
    const fileInput = document.getElementById('eml-file-input');
    const dropzone = document.getElementById('eml-dropzone');

    if (dropzone && fileInput) {
      dropzone.addEventListener('click', () => fileInput.click());
      dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
      dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
      dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
          this.uploadEmlFile(e.dataTransfer.files[0]);
        }
      });
      fileInput.addEventListener('change', () => {
        if (fileInput.files.length) {
          this.uploadEmlFile(fileInput.files[0]);
        }
      });
    }

    // Print Report
    const printBtn = document.getElementById('btn-print-report');
    if (printBtn) {
      printBtn.addEventListener('click', () => window.print());
    }

    // Export IOCs
    const exportIocsBtn = document.getElementById('btn-export-iocs');
    if (exportIocsBtn) {
      exportIocsBtn.addEventListener('click', () => this.exportIocsAsJson());
    }
  }

  async loadSample(sampleId) {
    document.querySelectorAll('.sample-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.sampleId === sampleId);
    });

    try {
      this.showGlobalSpinner("Fetching & Analyzing Sample...");
      const res = await fetch(`/api/samples/${sampleId}`);
      const data = await res.json();
      if (data.status === 'success' && data.sample) {
        await this.runAnalysis(data.sample.raw_eml, 'sample');
      }
    } catch (err) {
      console.error("Error loading sample:", err);
    } finally {
      this.hideGlobalSpinner();
    }
  }

  async analyzePastedEml() {
    const textarea = document.getElementById('raw-eml-textarea');
    const raw = textarea ? textarea.value.trim() : '';
    if (!raw) {
      alert("Please paste email headers or message content before analyzing.");
      return;
    }

    const modalBackdrop = document.getElementById('eml-modal');
    if (modalBackdrop) modalBackdrop.classList.remove('open');

    this.showGlobalSpinner("Running Full Email Forensics Pipeline...");
    try {
      const ok = await this.runAnalysis(raw, 'paste');
      if (ok) {
        this.switchTab(this.viewMode === 'soc' ? 'threat' : 'simple');
      }
    } catch (err) {
      console.error("Paste analysis error:", err);
      alert("Analysis error: " + err.message);
    } finally {
      this.hideGlobalSpinner();
    }
  }

  async uploadEmlFile(file) {
    const modalBackdrop = document.getElementById('eml-modal');
    if (modalBackdrop) modalBackdrop.classList.remove('open');

    const formData = new FormData();
    formData.append('file', file);

    this.showGlobalSpinner("Uploading & Parsing .eml File...");
    try {
      const res = await fetch('/api/analyze', { method: 'POST', body: formData });
      const data = await res.json();
      if (data.status === 'success') {
        this.renderCase(data.dossier);
        await this.refreshDashboardMetrics();
        await this.loadRecentCases();
        this.switchTab(this.viewMode === 'soc' ? 'threat' : 'simple');
      } else {
        alert("Analysis Error: " + (data.message || "Unknown error"));
      }
    } catch (err) {
      console.error(err);
      alert("Network Error during upload: " + err.message);
    } finally {
      this.hideGlobalSpinner();
    }
  }

  async runAnalysis(rawEml, sourceType) {
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_eml: rawEml, source: sourceType })
      });
      const data = await res.json();
      if (data.status === 'success' && data.dossier) {
        this.renderCase(data.dossier);
        await this.refreshDashboardMetrics();
        await this.loadRecentCases();
        this.switchTab(this.viewMode === 'soc' ? 'threat' : 'simple');
        return true;
      } else {
        alert("Analysis Error: " + (data.message || "Analysis failed on server"));
        return false;
      }
    } catch (err) {
      console.error("Analysis execution failed:", err);
      alert("Analysis request failed: " + err.message);
      return false;
    }
  }

  // =========================================================================
  // UI RENDERING ENGINES
  // =========================================================================

  renderCase(dossier) {
    this.currentCase = dossier;
    const parsed = dossier.parsed_email || {};
    const ident = parsed.identity || {};
    const threat = dossier.threat_detection || {};
    const forensic = dossier.forensic_investigation || {};
    const ai = dossier.ai_synthesis || {};

    // 0. Render End-User Summary (Plain English assessment for employees & non-technical users)
    this.renderEndUserSummary(dossier);

    // 1. Render Module 1: Threat Detection
    this.renderThreatModule(ident, threat, parsed);

    // 2. Render Module 2: Forensic Origin & Location Analysis
    this.renderForensicModule(ident, forensic);

    // 3. Render Module 3: Infrastructure Relationship Graph
    if (this.graphVisualizer && dossier.graph_data) {
      this.graphVisualizer.loadGraphData(dossier.graph_data);
    }

    // 4. Render Module 4: Unified SOC Investigation Report
    this.renderUnifiedReport(dossier);
  }

  renderEndUserSummary(dossier) {
    const summary = dossier.end_user_summary || {};
    const parsed = dossier.parsed_email || {};
    const ident = parsed.identity || {};
    const originMta = dossier.forensic_investigation?.origin_mta || {};

    // 1. Hero Card styling and headline
    const heroCard = document.getElementById('simple-hero-card');
    const bigIcon = document.getElementById('simple-big-icon');
    const headline = document.getElementById('simple-verdict-headline');
    const subtitle = document.getElementById('simple-verdict-subtitle');
    const badge = document.getElementById('simple-verdict-badge');
    const subject = document.getElementById('simple-subject-text');
    const recBox = document.getElementById('simple-recommendation-box');

    const color = summary.risk_color || (summary.is_safe ? 'safe' : (summary.risk_score >= 70 ? 'danger' : 'caution'));

    if (heroCard) {
      heroCard.className = `enduser-hero-card ${color}`;
    }

    if (bigIcon) {
      bigIcon.textContent = summary.is_safe ? '✅' : (summary.risk_score >= 70 ? '🚨' : '⚠️');
    }

    if (headline) {
      headline.textContent = summary.verdict_headline || (summary.is_safe ? 'This email appears safe to read' : 'This email appears suspicious');
    }

    if (subtitle) {
      subtitle.textContent = summary.verdict_subtitle || '';
    }

    if (badge) {
      badge.textContent = summary.risk_badge ? summary.risk_badge.toUpperCase() : `${summary.risk_score || 0}/100`;
    }

    if (subject) {
      subject.textContent = ident.subject ? `Subject: ${ident.subject}` : 'No Subject';
    }

    if (recBox) {
      recBox.innerHTML = `
        <span style="font-size: 16px; margin-right: 4px;">${summary.is_safe ? '🛡️' : '🚫'}</span>
        <span>${this.escapeHtml(summary.recommendation || '')}</span>
      `;
    }

    // 2. Why is it suspicious? (Plain English Reasons)
    const reasonsContainer = document.getElementById('simple-reasons-container');
    if (reasonsContainer) {
      const reasons = summary.plain_reasons || [];
      if (reasons.length === 0) {
        reasonsContainer.innerHTML = `<div class="plain-reason-card"><span class="reason-bullet-icon" style="color:var(--emerald-core);">&#10003;</span><span>No suspicious patterns detected.</span></div>`;
      } else {
        reasonsContainer.innerHTML = reasons.map(r => `
          <div class="plain-reason-card">
            <span class="reason-bullet-icon" style="color: ${summary.is_safe ? 'var(--emerald-core)' : 'var(--crimson-core)'};">
              ${summary.is_safe ? '&#10003;' : '&#8226;'}
            </span>
            <span>${this.escapeHtml(r)}</span>
          </div>
        `).join('');
      }
    }

    // 3. What should I do? (Action Items)
    const actionsContainer = document.getElementById('simple-actions-container');
    if (actionsContainer) {
      const actions = summary.action_checklist || [];
      actionsContainer.innerHTML = actions.map(act => {
        let badgeClass = 'info';
        let badgeLabel = 'INFO';
        if (act.type === 'dont') { badgeClass = 'dont'; badgeLabel = 'DO NOT'; }
        else if (act.type === 'do') { badgeClass = 'do'; badgeLabel = 'SAFE'; }
        else if (act.type === 'report') { badgeClass = 'report'; badgeLabel = 'ACTION'; }

        return `
          <div class="action-checklist-item">
            <span class="action-badge ${badgeClass}">${badgeLabel}</span>
            <span style="color: ${act.type === 'dont' ? '#fecdd3' : '#ffffff'};">${this.escapeHtml(act.text)}</span>
          </div>
        `;
      }).join('');
    }

    // 4. Who does it appear to come from? (Identity Breakdown)
    const identBreakdown = summary.identity_breakdown || {};
    const nameEl = document.getElementById('simple-ident-name');
    const emailEl = document.getElementById('simple-ident-email');
    const replyToRow = document.getElementById('simple-ident-replyto-row');
    const replyToEl = document.getElementById('simple-ident-replyto');
    const expText = document.getElementById('simple-ident-exp-text');

    if (nameEl) nameEl.textContent = identBreakdown.displayed_name || ident.from_name || '(None)';
    if (emailEl) emailEl.textContent = identBreakdown.actual_email || ident.from_email || '(None)';

    if (replyToRow && replyToEl) {
      if (identBreakdown.reply_to) {
        replyToRow.style.display = 'flex';
        replyToEl.textContent = identBreakdown.reply_to;
      } else {
        replyToRow.style.display = 'none';
      }
    }

    if (expText) {
      expText.textContent = identBreakdown.plain_explanation || 'Sender identity evaluated.';
    }

    // 5. Where did the email come through? (Transit Journey)
    const journeyContainer = document.getElementById('simple-journey-container');
    const journeySummary = document.getElementById('simple-journey-summary');
    const journeyData = summary.simplified_journey || {};

    if (journeyContainer) {
      const stages = journeyData.stages || [];
      journeyContainer.innerHTML = `
        <div class="simple-journey-flow">
          ${stages.map((st, i) => `
            <div class="journey-step-box ${st.status === 'warning' ? 'warning' : ''}">
              <div class="journey-step-num">Step ${st.step}</div>
              <div class="journey-step-title">${this.escapeHtml(st.title)}</div>
              <div class="journey-step-desc">${this.escapeHtml(st.desc)}</div>
            </div>
            ${i < stages.length - 1 ? '<div class="journey-arrow">&rarr;</div>' : ''}
          `).join('')}
        </div>
      `;
    }

    if (journeySummary) {
      journeySummary.textContent = journeyData.summary || '';
    }

    // 6. Related Suspicious Activity
    const activityText = document.getElementById('simple-activity-text');
    if (activityText) {
      activityText.textContent = summary.related_activity || 'No related campaigns found.';
    }

    // 7. Progressive Disclosure Technical Panel
    const techAuthMatrix = document.getElementById('simple-tech-auth-matrix');
    if (techAuthMatrix) {
      const auth = dossier.threat_detection?.auth_analysis || {};
      techAuthMatrix.innerHTML = `
        <div class="auth-box">
          <div class="auth-title">SPF</div>
          <div class="auth-badge ${auth.spf?.is_pass ? 'pass' : (auth.spf?.status === 'FAIL' ? 'fail' : 'unknown')}">
            ${auth.spf?.status || 'UNKNOWN'}
          </div>
          <div class="auth-desc">${this.escapeHtml(auth.spf?.detail || '')}</div>
        </div>
        <div class="auth-box">
          <div class="auth-title">DKIM</div>
          <div class="auth-badge ${auth.dkim?.is_pass ? 'pass' : (auth.dkim?.status === 'FAIL' ? 'fail' : 'unknown')}">
            ${auth.dkim?.status || 'UNKNOWN'}
          </div>
          <div class="auth-desc">${this.escapeHtml(auth.dkim?.detail || '')}</div>
        </div>
        <div class="auth-box">
          <div class="auth-title">DMARC</div>
          <div class="auth-badge ${auth.dmarc?.is_pass ? 'pass' : (auth.dmarc?.status === 'FAIL' ? 'fail' : 'unknown')}">
            ${auth.dmarc?.status || 'UNKNOWN'}
          </div>
          <div class="auth-desc">${this.escapeHtml(auth.dmarc?.detail || '')}</div>
        </div>
      `;
    }

    const techOriginBox = document.getElementById('simple-tech-origin-box');
    if (techOriginBox) {
      techOriginBox.innerHTML = `
        <div style="font-size: 12px; line-height: 1.6;">
          <div><strong style="color: var(--cyan-core);">Ingress IP:</strong> <span style="font-family: var(--text-mono);">${this.escapeHtml(originMta.ip || 'N/A')}</span></div>
          <div><strong style="color: var(--violet-core);">Location:</strong> ${this.escapeHtml(originMta.city || '?')}, ${this.escapeHtml(originMta.country || '?')}</div>
          <div><strong style="color: var(--amber-core);">Autonomous System:</strong> ${this.escapeHtml(originMta.asn || 'N/A')} (${this.escapeHtml(originMta.isp || originMta.org || 'N/A')})</div>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px; font-style: italic;">
            Observed sending infrastructure location does not necessarily represent the physical location of the attacker.
          </div>
        </div>
      `;
    }

    const rawHeadersPre = document.getElementById('simple-raw-headers-pre');
    if (rawHeadersPre) {
      rawHeadersPre.textContent = dossier.raw_eml || 'No raw headers available.';
    }
  }

  renderThreatModule(ident, threat, parsed) {
    const score = threat.risk_score || 0;
    const level = threat.risk_level || 'INFO';
    const isCritical = (score >= 70);

    // Risk verdict banner
    const banner = document.getElementById('threat-verdict-banner');
    if (banner) {
      banner.className = `verdict-banner ${isCritical ? 'critical' : 'clean'}`;
      banner.innerHTML = `
        <div class="verdict-left">
          <div class="risk-circle ${isCritical ? '' : 'clean'}">
            <span class="risk-number" style="color: ${isCritical ? 'var(--crimson-core)' : 'var(--emerald-core)'}">${score}</span>
            <span class="risk-max">/ 100</span>
          </div>
          <div class="verdict-info">
            <h3 style="color: ${isCritical ? 'var(--crimson-core)' : 'var(--emerald-core)'}">
              ${threat.classification.toUpperCase()} — ${level} RISK
            </h3>
            <p>Subject: <strong>${this.escapeHtml(ident.subject || 'No Subject')}</strong></p>
            <span class="confidence-badge">Classification Confidence: ${threat.confidence}%</span>
          </div>
        </div>
        <div class="verdict-right" style="text-align: right;">
          <div style="font-family: var(--text-mono); font-size: 11px; color: var(--text-muted);">Sender Identity</div>
          <div style="font-size: 13px; font-weight: bold; color: var(--text-primary);">${this.escapeHtml(ident.from_email || '')}</div>
          <div style="font-size: 11px; color: var(--cyan-core);">${this.escapeHtml(ident.from_name || 'No Display Name')}</div>
        </div>
      `;
    }

    // Authentication Matrix
    const auth = threat.auth_analysis || {};
    const authMatrix = document.getElementById('auth-matrix-container');
    if (authMatrix) {
      authMatrix.innerHTML = `
        <div class="auth-box">
          <div class="auth-title">SPF STATUS</div>
          <div class="auth-badge ${auth.spf?.is_pass ? 'pass' : (auth.spf?.status === 'FAIL' ? 'fail' : 'unknown')}">
            ${auth.spf?.status || 'UNKNOWN'}
          </div>
          <div class="auth-desc">${this.escapeHtml(auth.spf?.detail || '')}</div>
        </div>
        <div class="auth-box">
          <div class="auth-title">DKIM CRYPTO</div>
          <div class="auth-badge ${auth.dkim?.is_pass ? 'pass' : (auth.dkim?.status === 'FAIL' ? 'fail' : 'unknown')}">
            ${auth.dkim?.status || 'UNKNOWN'}
          </div>
          <div class="auth-desc">${this.escapeHtml(auth.dkim?.detail || '')}</div>
        </div>
        <div class="auth-box">
          <div class="auth-title">DMARC POLICY</div>
          <div class="auth-badge ${auth.dmarc?.is_pass ? 'pass' : (auth.dmarc?.status === 'FAIL' ? 'fail' : 'unknown')}">
            ${auth.dmarc?.status || 'UNKNOWN'}
          </div>
          <div class="auth-desc">${this.escapeHtml(auth.dmarc?.detail || '')}</div>
        </div>
        <div class="auth-box">
          <div class="auth-title">IDENTIFIER ALIGNMENT</div>
          <div class="auth-badge ${auth.alignment?.spf_aligned && auth.alignment?.dkim_aligned ? 'pass' : 'fail'}">
            ${auth.alignment?.status || 'NO ALIGNMENT'}
          </div>
          <div class="auth-desc">Sender domain match against SPF & DKIM keys</div>
        </div>
      `;
    }

    // Explainability Factor Breakdown
    const reasonList = document.getElementById('threat-reasons-list');
    if (reasonList) {
      let itemsHtml = '';
      (threat.risk_factors || []).forEach(rf => {
        itemsHtml += `
          <li class="telemetry-item risk">
            <span class="telemetry-icon red">&#9888;</span>
            <div><strong>Risk Indicator:</strong> ${this.escapeHtml(rf)}</div>
          </li>
        `;
      });
      (threat.mitigating_factors || []).forEach(mf => {
        itemsHtml += `
          <li class="telemetry-item mitigating">
            <span class="telemetry-icon green">&#10004;</span>
            <div><strong>Verified Standard:</strong> ${this.escapeHtml(mf)}</div>
          </li>
        `;
      });
      reasonList.innerHTML = itemsHtml || '<li class="telemetry-item">No significant anomalies detected.</li>';
    }

    // Social Engineering Triggers
    const socialContainer = document.getElementById('social-engineering-container');
    if (socialContainer) {
      const se = threat.social_engineering || {};
      const categories = se.detected_categories || [];
      if (categories.length === 0) {
        socialContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 12px;">No social engineering coercion or urgency tactics detected.</div>';
      } else {
        socialContainer.innerHTML = categories.map(c => `
          <div style="background: var(--bg-card); border-left: 3px solid var(--amber-core); padding: 10px 14px; border-radius: var(--radius-sm); margin-bottom: 8px;">
            <div style="font-weight: bold; text-transform: uppercase; font-size: 11px; color: var(--amber-core);">${c.replace('_', ' ')}</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">Behavioral intent detected matching deceptive pattern library.</div>
          </div>
        `).join('');
      }
    }

    // URLs Table
    const urlContainer = document.getElementById('extracted-urls-container');
    if (urlContainer) {
      const urls = parsed.urls || [];
      if (urls.length === 0) {
        urlContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 12px;">No embedded links or web addresses found in body.</div>';
      } else {
        urlContainer.innerHTML = `
          <table class="soc-table">
            <thead>
              <tr><th>Domain / Host</th><th>Scheme</th><th>Analysis Details</th><th>Status</th></tr>
            </thead>
            <tbody>
              ${urls.map(u => `
                <tr>
                  <td style="font-family: var(--text-mono); color: var(--cyan-core);">${this.escapeHtml(u.domain || '')}</td>
                  <td>${u.scheme || 'https'}</td>
                  <td style="font-size: 11px; color: var(--text-secondary);">${this.escapeHtml(u.url.length > 50 ? u.url.substring(0, 50) + '...' : u.url)}</td>
                  <td><span class="sample-tag ${u.is_ip_domain ? 'threat' : 'clean'}">${u.is_ip_domain ? 'RAW IP HOST' : 'STATIC CHECK'}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `;
      }
    }
  }

  renderForensicModule(ident, forensic) {
    const relay = forensic.relay_path || {};
    const hops = relay.hops || [];
    const origin = relay.origin_mta || {};
    const loc = forensic.location_analysis || {};

    // Mandatory attribution warning container
    const caveatContainer = document.getElementById('forensic-caveat-container');
    if (caveatContainer) {
      caveatContainer.innerHTML = `
        <div class="forensic-caveat-box">
          <div class="caveat-title">
            <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
            SOC FORENSIC ATTRIBUTION CAVEAT & GEOLOCATION ADVISORY
          </div>
          <div class="mandatory-quote">
            <strong>${this.escapeHtml(loc.mandatory_statement || '')}</strong><br/>
            <em>${this.escapeHtml(loc.disclaimer || '')}</em>
          </div>
          <ul class="caveat-list">
            ${(loc.caveats || []).map(c => `<li>${this.escapeHtml(c)}</li>`).join('')}
          </ul>
        </div>
      `;
    }

    // Earliest trustworthy infrastructure card
    const originCard = document.getElementById('origin-mta-card');
    if (originCard) {
      originCard.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px;">
          <div>
            <div class="hop-key">Origin Ingress IP</div>
            <div class="hop-val" style="color: var(--crimson-core); font-weight: bold; font-size: 14px;">${origin.ip || 'N/A'}</div>
          </div>
          <div>
            <div class="hop-key">Observed Location</div>
            <div class="hop-val">${loc.observed_city || 'Unknown'}, ${loc.observed_country || 'Unknown'}</div>
          </div>
          <div>
            <div class="hop-key">Network / ASN</div>
            <div class="hop-val">${origin.asn || 'N/A'} — ${origin.org || 'Unknown'}</div>
          </div>
          <div>
            <div class="hop-key">Infrastructure Type</div>
            <div class="hop-val">${origin.is_bulletproof ? 'BULLETPROOF / HIGH-RISK' : (origin.is_cloud ? 'Cloud VPS Datacenter' : 'Standard Mail Relay')}</div>
          </div>
        </div>
      `;
    }

    // Relay Path Timeline
    const timeline = document.getElementById('relay-path-timeline');
    if (timeline) {
      timeline.innerHTML = hops.map(h => {
        const isOrigin = (h.hop_number === origin.hop_number);
        return `
          <div class="relay-hop-card ${isOrigin ? 'origin' : ''}">
            <div class="hop-node-dot"></div>
            <div class="hop-header">
              <div class="hop-badge-title">
                <span>Hop ${h.hop_number}: ${this.escapeHtml(h.from_host || 'Client')} &rarr; ${this.escapeHtml(h.by_host || 'Gateway')}</span>
                ${isOrigin ? '<span class="origin-tag">Earliest Reliable Ingress</span>' : ''}
              </div>
              <div style="font-family: var(--text-mono); font-size: 11px; color: var(--text-muted);">${this.escapeHtml(h.protocol || 'SMTP')}</div>
            </div>
            <div class="hop-grid">
              <div class="hop-data-bit">
                <span class="hop-key">IP Address</span>
                <span class="hop-val">${h.ip || 'Hidden/Internal'} ${h.is_private ? '(Private)' : ''}</span>
              </div>
              <div class="hop-data-bit">
                <span class="hop-key">ISP / Autonomous System</span>
                <span class="hop-val">${h.asn || 'N/A'} (${this.escapeHtml(h.org || 'Local')})</span>
              </div>
              <div class="hop-data-bit">
                <span class="hop-key">Geography</span>
                <span class="hop-val">${h.city || 'Unknown'}, ${h.country || 'Unknown'}</span>
              </div>
              <div class="hop-data-bit">
                <span class="hop-key">Reputation / Threat Flags</span>
                <span class="hop-val" style="color: ${h.reputation_score > 50 ? 'var(--crimson-core)' : 'var(--emerald-core)'}">
                  ${h.threat_flags?.length ? h.threat_flags.join(', ') : 'Clean Hop'}
                </span>
              </div>
            </div>
          </div>
        `;
      }).join('');
    }

    // DNS Records
    const dnsContainer = document.getElementById('dns-investigation-container');
    if (dnsContainer) {
      const domainInv = forensic.domain_investigation || {};
      const dns = domainInv.dns_records || {};
      dnsContainer.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; font-family: var(--text-mono); font-size: 11px;">
          <div style="background: var(--bg-card); padding: 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <strong style="color: var(--cyan-core);">MX Records:</strong><br/>
            ${dns.mx?.length ? dns.mx.join('<br/>') : '<span style="color:var(--text-muted)">None</span>'}
          </div>
          <div style="background: var(--bg-card); padding: 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <strong style="color: var(--cyan-core);">A / Host Records:</strong><br/>
            ${dns.a?.length ? dns.a.join('<br/>') : '<span style="color:var(--text-muted)">None</span>'}
          </div>
          <div style="background: var(--bg-card); padding: 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <strong style="color: var(--cyan-core);">TXT / SPF Policy:</strong><br/>
            ${dns.txt?.length ? dns.txt.join('<br/>') : '<span style="color:var(--text-muted)">None</span>'}
          </div>
          <div style="background: var(--bg-card); padding: 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <strong style="color: var(--cyan-core);">Nameservers:</strong><br/>
            ${dns.ns?.length ? dns.ns.join('<br/>') : '<span style="color:var(--text-muted)">None</span>'}
          </div>
        </div>
      `;
    }
  }

  renderUnifiedReport(dossier) {
    const ident = dossier.parsed_email?.identity || {};
    const threat = dossier.threat_detection || {};
    const forensic = dossier.forensic_investigation || {};
    const loc = forensic.location_analysis || {};
    const ai = dossier.ai_synthesis || {};
    const origin = forensic.relay_path?.origin_mta || {};

    const reportContainer = document.getElementById('unified-report-body');
    if (!reportContainer) return;

    reportContainer.innerHTML = `
      <div style="border-bottom: 2px solid var(--border-subtle); padding-bottom: 16px; margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: baseline;">
          <h2 style="font-size: 20px; font-weight: 800; color: #ffffff;">FORENSIC INCIDENT INVESTIGATION REPORT</h2>
          <span style="font-family: var(--text-mono); color: var(--cyan-core); font-weight: bold;">${dossier.case_id}</span>
        </div>
        <div style="color: var(--text-muted); font-size: 11px; margin-top: 4px;">
          Generated on: ${dossier.date_str} | Classification: <strong>${threat.classification}</strong> (Risk: ${threat.risk_score}/100)
        </div>
      </div>

      <!-- Executive AI Summary -->
      <div style="background: rgba(0, 240, 255, 0.04); border: 1px solid rgba(0, 240, 255, 0.2); border-radius: var(--radius-md); padding: 16px; margin-bottom: 20px;">
        <div style="font-weight: 700; font-size: 13px; color: var(--cyan-core); margin-bottom: 6px;">EXECUTIVE SECURITY SUMMARY</div>
        <p style="font-size: 13px; line-height: 1.6; color: var(--text-primary);">${this.escapeHtml(ai.executive_summary || '')}</p>
      </div>

      <!-- Technical Dossier Grid -->
      <div class="two-col-grid" style="margin-bottom: 20px;">
        <div class="cyber-card" style="margin-bottom: 0;">
          <div class="card-header-soc"><span class="card-title">1. SENDER & IDENTITY FORENSICS</span></div>
          <div class="card-body-soc" style="font-size: 12px; display: flex; flex-direction: column; gap: 8px;">
            <div><strong>From Header:</strong> ${this.escapeHtml(ident.from_raw || 'N/A')}</div>
            <div><strong>Reply-To Header:</strong> ${this.escapeHtml(ident.reply_to_raw || 'Matches Sender')}</div>
            <div><strong>Return-Path:</strong> ${this.escapeHtml(ident.return_path || 'N/A')}</div>
            <div><strong>Subject:</strong> ${this.escapeHtml(ident.subject || 'N/A')}</div>
            <div><strong>Display Spoofing:</strong> <span style="color:${threat.identity_analysis?.is_display_spoofed ? 'var(--crimson-core)' : 'var(--emerald-core)'}">${threat.identity_analysis?.is_display_spoofed ? 'CONFIRMED SPOOF' : 'CLEAN'}</span></div>
            <div><strong>Domain Typosquatting:</strong> <span style="color:${threat.identity_analysis?.is_lookalike_domain ? 'var(--crimson-core)' : 'var(--emerald-core)'}">${threat.identity_analysis?.is_lookalike_domain ? 'CONFIRMED LOOKALIKE' : 'CLEAN'}</span></div>
          </div>
        </div>

        <div class="cyber-card" style="margin-bottom: 0;">
          <div class="card-header-soc"><span class="card-title">2. INFRASTRUCTURE & ROUTING ATTRIBUTION</span></div>
          <div class="card-body-soc" style="font-size: 12px; display: flex; flex-direction: column; gap: 8px;">
            <div><strong>Earliest Ingress IP:</strong> <span style="font-family:var(--text-mono); color:var(--crimson-core);">${origin.ip || 'N/A'}</span></div>
            <div><strong>Observed Routing Geo:</strong> ${loc.observed_city || 'Unknown'}, ${loc.observed_country || 'Unknown'}</div>
            <div><strong>ASN & Hosting:</strong> ${origin.asn || 'N/A'} (${origin.org || 'Unknown'})</div>
            <div><strong>Total Relay Hops:</strong> ${forensic.relay_path?.total_hops || 0}</div>
            <div><strong>Attribution Caveat:</strong> <em style="color:var(--amber-core);">${loc.disclaimer}</em></div>
          </div>
        </div>
      </div>

      <!-- Actionable Playbook Recommendations -->
      <div class="cyber-card" style="margin-bottom: 0;">
        <div class="card-header-soc"><span class="card-title">3. RECOMMENDED SOC INCIDENT RESPONSE PLAYBOOK</span></div>
        <div class="card-body-soc">
          <div class="action-card-playbook">
            ${(ai.recommended_actions || []).map(a => `
              <div class="playbook-step">
                <div>
                  <div style="font-weight: 700; font-size: 13px; color: #ffffff;">${this.escapeHtml(a.action)}</div>
                  <div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">${this.escapeHtml(a.detail)}</div>
                </div>
                <span class="playbook-priority ${a.priority.includes('P1') ? 'priority-p1' : (a.priority.includes('P2') ? 'priority-p2' : 'priority-p3')}">
                  ${a.priority}
                </span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  }

  // =========================================================================
  // GRAPH VISUALIZER & INSPECTOR
  // =========================================================================

  initGraph() {
    this.graphVisualizer = new InteractiveGraphVisualizer('infrastructure-canvas', (node) => {
      this.showNodeInspector(node);
    });

    const closeDrawerBtn = document.getElementById('drawer-close-btn');
    if (closeDrawerBtn) {
      closeDrawerBtn.addEventListener('click', () => {
        document.getElementById('graph-inspector-drawer').style.display = 'none';
      });
    }

    const fitBtn = document.getElementById('btn-graph-fit');
    if (fitBtn) {
      fitBtn.addEventListener('click', () => this.graphVisualizer.fitView());
    }
  }

  showNodeInspector(node) {
    const drawer = document.getElementById('graph-inspector-drawer');
    const title = document.getElementById('drawer-node-title');
    const content = document.getElementById('drawer-node-content');
    if (!drawer || !title || !content) return;

    title.innerText = `${node.type.toUpperCase()}: ${node.label}`;
    drawer.style.display = 'block';

    const details = node.details || {};
    content.innerHTML = `
      <div style="font-size: 12px; display: flex; flex-direction: column; gap: 8px;">
        <div style="padding-bottom: 6px; border-bottom: 1px solid var(--border-subtle);">
          <span style="color: var(--text-muted); font-size: 10px; text-transform: uppercase;">Type</span><br/>
          <strong style="color: var(--cyan-core);">${node.type.toUpperCase()}</strong>
        </div>
        ${Object.entries(details).map(([k, v]) => `
          <div>
            <span style="color: var(--text-muted); font-size: 10px; text-transform: uppercase;">${k.replace('_', ' ')}</span><br/>
            <span style="font-family: var(--text-mono); color: var(--text-primary);">${this.escapeHtml(String(v))}</span>
          </div>
        `).join('')}
      </div>
    `;
  }

  // =========================================================================
  // METRICS & RECENT CASES
  // =========================================================================

  async refreshDashboardMetrics() {
    try {
      const res = await fetch('/api/metrics');
      const data = await res.json();
      if (data.status === 'success') {
        const m = data.metrics || {};
        document.getElementById('stat-total-analyzed').innerText = m.total_analyzed || 0;
        document.getElementById('stat-high-risk').innerText = m.high_risk_count || 0;
        document.getElementById('stat-phishing').innerText = m.phishing_count || 0;
        document.getElementById('stat-bec').innerText = m.bec_count || 0;
        document.getElementById('stat-domains').innerText = m.suspicious_domains || 0;
        document.getElementById('stat-ips').innerText = m.suspicious_ips || 0;
      }
    } catch (e) {
      console.warn("Metrics error:", e);
    }
  }

  async loadRecentCases() {
    try {
      const res = await fetch('/api/cases?limit=10');
      const data = await res.json();
      const container = document.getElementById('recent-cases-tbody');
      if (container && data.status === 'success') {
        container.innerHTML = (data.cases || []).map(c => `
          <tr style="cursor: pointer;" onclick="window.socApp.loadCaseById('${c.case_id}')">
            <td style="font-family: var(--text-mono); color: var(--cyan-core);">${c.case_id}</td>
            <td>${this.escapeHtml(c.subject.length > 28 ? c.subject.substring(0, 28) + '...' : c.subject)}</td>
            <td><span class="sample-tag ${c.risk_score >= 70 ? 'threat' : 'clean'}">${c.classification}</span></td>
            <td style="font-family: var(--text-mono); font-weight: bold; color: ${c.risk_score >= 70 ? 'var(--crimson-core)' : 'var(--emerald-core)'};">${c.risk_score}/100</td>
            <td style="font-family: var(--text-mono);">${c.origin_ip || 'N/A'} (${c.origin_country || '?'})</td>
            <td style="color: var(--text-muted);">${c.date_str}</td>
          </tr>
        `).join('');
      }
    } catch (e) {
      console.warn("Recent cases error:", e);
    }
  }

  async loadCaseById(caseId) {
    try {
      this.showGlobalSpinner(`Loading Investigation ${caseId}...`);
      const res = await fetch(`/api/cases/${caseId}`);
      const data = await res.json();
      if (data.status === 'success') {
        this.renderCase(data.case);
        this.switchTab(this.viewMode === 'soc' ? 'threat' : 'simple');
      }
    } catch (err) {
      console.error(err);
    } finally {
      this.hideGlobalSpinner();
    }
  }

  exportIocsAsJson() {
    if (!this.currentCase) return;
    const iocs = this.currentCase.forensic_investigation?.threat_intelligence || {};
    const blob = new Blob([JSON.stringify(iocs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IOCs_${this.currentCase.case_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // =========================================================================
  // DIRECT MAILBOX INTEGRATION (GMAIL / OUTLOOK / IMAP)
  // =========================================================================

  bindMailboxEvents() {
    // 1. Open / Close Mailbox Modal
    const mboxModal = document.getElementById('mailbox-modal');
    const btnOpenMbox = document.getElementById('btn-open-mailbox');
    const btnCloseMbox = document.getElementById('btn-close-mailbox');

    if (btnOpenMbox && mboxModal) {
      btnOpenMbox.addEventListener('click', () => {
        mboxModal.classList.add('open');
        this.checkMailboxStatus();
      });
    }

    if (btnCloseMbox && mboxModal) {
      btnCloseMbox.addEventListener('click', () => {
        mboxModal.classList.remove('open');
      });
    }

    // 2. Provider Tabs Switching
    document.querySelectorAll('.mbox-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const provider = btn.dataset.provider;
        document.querySelectorAll('.mbox-tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        // Toggle setup panels
        const pGmail = document.getElementById('mbox-panel-gmail');
        const pOutlook = document.getElementById('mbox-panel-outlook');
        const pImap = document.getElementById('mbox-panel-imap');

        if (pGmail) pGmail.style.display = (provider === 'gmail' ? 'block' : 'none');
        if (pOutlook) pOutlook.style.display = (provider === 'outlook' ? 'block' : 'none');
        if (pImap) pImap.style.display = (provider === 'imap' ? 'block' : 'none');
      });
    });

    // 3. Demo Mailbox Triggers
    const btnDemoGmail = document.getElementById('btn-demo-gmail');
    if (btnDemoGmail) {
      btnDemoGmail.addEventListener('click', () => this.connectMailbox('gmail', { mode: 'demo' }));
    }

    const btnDemoOutlook = document.getElementById('btn-demo-outlook');
    if (btnDemoOutlook) {
      btnDemoOutlook.addEventListener('click', () => this.connectMailbox('outlook', { mode: 'demo' }));
    }

    const btnDemoImap = document.getElementById('btn-demo-imap');
    if (btnDemoImap) {
      btnDemoImap.addEventListener('click', () => this.connectMailbox('imap', { mode: 'demo' }));
    }

    // 4. Live OAuth & IMAP Connectors
    const btnAuthGmail = document.getElementById('btn-auth-gmail');
    if (btnAuthGmail) {
      btnAuthGmail.addEventListener('click', () => {
        const clientId = document.getElementById('gmail-client-id')?.value.trim();
        const clientSecret = document.getElementById('gmail-client-secret')?.value.trim();
        if (!clientId) {
          alert('Please enter your Google Cloud OAuth Client ID, or click "Launch Demo Mailbox".');
          return;
        }
        this.startOAuthFlow('gmail', clientId, clientSecret);
      });
    }

    const btnAuthOutlook = document.getElementById('btn-auth-outlook');
    if (btnAuthOutlook) {
      btnAuthOutlook.addEventListener('click', () => {
        const clientId = document.getElementById('outlook-client-id')?.value.trim();
        const clientSecret = document.getElementById('outlook-client-secret')?.value.trim();
        const tenant = document.getElementById('outlook-tenant-id')?.value.trim() || 'common';
        if (!clientId) {
          alert('Please enter your Azure AD Application (Client) ID, or click "Launch Demo Mailbox".');
          return;
        }
        this.startOAuthFlow('outlook', clientId, clientSecret, tenant);
      });
    }

    const btnConnectImap = document.getElementById('btn-connect-imap');
    if (btnConnectImap) {
      btnConnectImap.addEventListener('click', () => {
        const host = document.getElementById('imap-host')?.value.trim();
        const port = parseInt(document.getElementById('imap-port')?.value || '993', 10);
        const username = document.getElementById('imap-username')?.value.trim();
        const password = document.getElementById('imap-password')?.value || '';

        if (!host || !username) {
          alert('Please enter IMAP Server Host and Username/Email, or click "Launch Demo Mailbox".');
          return;
        }
        this.connectMailbox('imap', { host, port, username, password });
      });
    }

    // 5. Session Controls (Refresh & Disconnect)
    const btnRefresh = document.getElementById('btn-refresh-mbox');
    if (btnRefresh) {
      btnRefresh.addEventListener('click', () => this.loadMailboxMessages());
    }

    const btnDisconnect = document.getElementById('btn-disconnect-mbox');
    if (btnDisconnect) {
      btnDisconnect.addEventListener('click', () => this.disconnectMailbox());
    }

    // 6. Search Filter
    const searchInput = document.getElementById('mbox-search-input');
    if (searchInput) {
      let debounceTimer = null;
      searchInput.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          this.loadMailboxMessages(searchInput.value.trim());
        }, 300);
      });
    }

    // 7. OAuth Message Listener for Popups
    window.addEventListener('message', async (event) => {
      if (event.data && event.data.type === 'OAUTH_CODE' && event.data.code) {
        console.log('[SOC Mailbox] Received OAuth callback code:', event.data.code);
        if (this._pendingOauth) {
          await this.connectMailbox(this._pendingOauth.provider, {
            code: event.data.code,
            client_id: this._pendingOauth.clientId,
            client_secret: this._pendingOauth.clientSecret,
            redirect_uri: this._pendingOauth.redirectUri,
            tenant: this._pendingOauth.tenant
          });
          this._pendingOauth = null;
        }
      }
    });
  }

  startOAuthFlow(provider, clientId, clientSecret, tenant = 'common') {
    const redirectUri = `${window.location.origin}/api/mailbox/oauth/callback`;
    this._pendingOauth = { provider, clientId, clientSecret, redirectUri, tenant };

    let authUrlEndpoint = `/api/mailbox/oauth/url?provider=${encodeURIComponent(provider)}&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
    if (provider === 'outlook') {
      authUrlEndpoint += `&tenant=${encodeURIComponent(tenant)}`;
    }

    fetch(authUrlEndpoint)
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success' && data.auth_url) {
          window.open(data.auth_url, 'soc_oauth_popup', 'width=600,height=700,scrollbars=yes');
        } else {
          alert('Failed to generate OAuth URL: ' + (data.message || 'Unknown error'));
        }
      })
      .catch(err => {
        alert('OAuth error: ' + err.message);
      });
  }

  async checkMailboxStatus() {
    try {
      const res = await fetch('/api/mailbox/status');
      const data = await res.json();
      if (data.status === 'success') {
        this.renderMailboxState(data.mailbox);
      }
    } catch (e) {
      console.warn("Error checking mailbox status:", e);
    }
  }

  renderMailboxState(mbox) {
    const connectedView = document.getElementById('mbox-connected-view');
    const setupCard = document.getElementById('mbox-setup-card');
    const messagesSection = document.getElementById('mbox-messages-section');
    const statusBadge = document.getElementById('mbox-header-status-badge');
    const titleEl = document.getElementById('mbox-active-account-title');
    const emailEl = document.getElementById('mbox-active-account-email');

    if (mbox && mbox.connected) {
      if (statusBadge) {
        statusBadge.textContent = `CONNECTED (${(mbox.provider || '').toUpperCase()})`;
        statusBadge.className = 'sample-tag clean';
      }
      if (titleEl) {
        titleEl.textContent = `${mbox.provider ? mbox.provider.toUpperCase() : 'MAILBOX'} (${mbox.is_demo ? 'Interactive Demo Sandbox' : 'Authenticated Live Read-Only'})`;
      }
      if (emailEl) {
        emailEl.textContent = `Account: ${mbox.account || 'Active Session'} | Read-Only MIME Protocol`;
      }

      if (connectedView) connectedView.style.display = 'flex';
      if (setupCard) setupCard.style.display = 'none';
      if (messagesSection) messagesSection.style.display = 'block';

      this.loadMailboxMessages();
    } else {
      if (statusBadge) {
        statusBadge.textContent = 'DISCONNECTED';
        statusBadge.className = 'sample-tag';
        statusBadge.style.background = 'rgba(255,255,255,0.06)';
        statusBadge.style.color = 'var(--text-muted)';
      }
      if (connectedView) connectedView.style.display = 'none';
      if (setupCard) setupCard.style.display = 'block';
      if (messagesSection) messagesSection.style.display = 'none';
    }
  }

  async connectMailbox(provider, credentials) {
    try {
      this.showGlobalSpinner(`Connecting to ${provider.toUpperCase()} Mailbox...`);
      const res = await fetch('/api/mailbox/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, credentials })
      });
      const data = await res.json();
      if (data.status === 'connected') {
        await this.checkMailboxStatus();
      } else {
        alert(`Connection Failed: ${data.message || 'Unknown error'}`);
      }
    } catch (err) {
      console.error("Connect mailbox error:", err);
      alert("Error connecting to mailbox: " + err.message);
    } finally {
      this.hideGlobalSpinner();
    }
  }

  async loadMailboxMessages(query = '') {
    const tbody = document.getElementById('mbox-messages-tbody');
    const countEl = document.getElementById('mbox-msg-count');
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--cyan-core); padding: 20px;">Fetching mailbox messages...</td></tr>`;

    try {
      let url = '/api/mailbox/messages';
      if (query) url += `?query=${encodeURIComponent(query)}`;

      const res = await fetch(url);
      const data = await res.json();

      if (data.status === 'success' && data.messages) {
        const msgs = data.messages;
        if (countEl) countEl.textContent = msgs.length;

        if (msgs.length === 0) {
          tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 20px;">No messages found in mailbox.</td></tr>`;
          return;
        }

        tbody.innerHTML = msgs.map(m => {
          const isSuspicious = (m.subject && (
            m.subject.toLowerCase().includes('urgent') || 
            m.subject.toLowerCase().includes('wire') || 
            m.subject.toLowerCase().includes('reset') || 
            m.subject.toLowerCase().includes('statement') || 
            m.subject.toLowerCase().includes('suspend')
          ));
          return `
            <tr style="transition: background 0.15s ease;">
              <td style="font-family: var(--text-mono); font-size: 11px; color: var(--cyan-core); word-break: break-word;">
                ${this.escapeHtml(m.from || 'Unknown')}
              </td>
              <td>
                <div style="font-weight: 600; color: ${isSuspicious ? 'var(--amber-core)' : '#ffffff'}; font-size: 12px; margin-bottom: 3px;">
                  ${isSuspicious ? '<span style="color:var(--crimson-core); margin-right:4px;">&#9888;</span>' : ''}${this.escapeHtml(m.subject || '(No Subject)')}
                </div>
                <div style="font-size: 11px; color: var(--text-muted); max-height: 32px; overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;">
                  ${this.escapeHtml(m.snippet || '')}
                </div>
              </td>
              <td style="font-family: var(--text-mono); font-size: 11px; color: var(--text-secondary); white-space: nowrap;">
                ${this.escapeHtml(m.date || '')}
              </td>
              <td style="text-align: right; white-space: nowrap;">
                <button class="btn-cyber-solid btn-analyze-msg" data-msg-id="${this.escapeHtml(m.id)}" style="background: var(--cyan-core); color: #000; font-size: 11px; padding: 5px 12px; font-weight: 700;">
                  Analyze Email &rarr;
                </button>
              </td>
            </tr>
          `;
        }).join('');

        // Attach action handlers
        tbody.querySelectorAll('.btn-analyze-msg').forEach(btn => {
          btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const msgId = btn.dataset.msgId;
            this.analyzeMailboxMessage(msgId);
          });
        });
      } else {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--crimson-core); padding: 20px;">Failed to load messages: ${this.escapeHtml(data.message || 'Error')}</td></tr>`;
      }
    } catch (err) {
      console.error("Error loading mailbox messages:", err);
      tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--crimson-core); padding: 20px;">Network error loading messages.</td></tr>`;
    }
  }

  async analyzeMailboxMessage(messageId) {
    const mboxModal = document.getElementById('mailbox-modal');
    if (mboxModal) mboxModal.classList.remove('open');

    this.showGlobalSpinner("Ingesting RFC 822 MIME from Mailbox & Running 7-Step Forensics Pipeline...");

    try {
      const res = await fetch('/api/mailbox/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message_id: messageId })
      });

      const data = await res.json();
      if (data.status === 'success' && data.dossier) {
        this.renderCase(data.dossier);
        this.switchTab(this.viewMode === 'soc' ? 'threat' : 'simple');
        await this.refreshDashboardMetrics();
        await this.loadRecentCases();
      } else {
        alert("Mailbox Analysis Error: " + (data.message || "Unknown error"));
      }
    } catch (err) {
      console.error("Mailbox analysis error:", err);
      alert("Analysis error: " + err.message);
    } finally {
      this.hideGlobalSpinner();
    }
  }

  async disconnectMailbox() {
    try {
      this.showGlobalSpinner("Disconnecting Mailbox...");
      await fetch('/api/mailbox/disconnect', { method: 'POST' });
      await this.checkMailboxStatus();
    } catch (err) {
      console.error("Disconnect error:", err);
    } finally {
      this.hideGlobalSpinner();
    }
  }

  // =========================================================================
  // UTILITY HELPERS
  // =========================================================================

  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  showGlobalSpinner(msg = "Analyzing...") {
    let spinner = document.getElementById('soc-global-spinner');
    if (!spinner) {
      spinner = document.createElement('div');
      spinner.id = 'soc-global-spinner';
      spinner.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.7);backdrop-filter:blur(4px);display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:9999;color:#00f0ff;font-family:var(--font-sans);font-weight:bold;';
      spinner.innerHTML = '<div class="pulse-dot" style="width:24px;height:24px;margin-bottom:12px;"></div><span id="spinner-msg"></span>';
      document.body.appendChild(spinner);
    }
    document.getElementById('spinner-msg').innerText = msg;
    spinner.style.display = 'flex';
  }

  hideGlobalSpinner() {
    const spinner = document.getElementById('soc-global-spinner');
    if (spinner) spinner.style.display = 'none';
  }
}

// Global initialization on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  window.socApp = new SocPlatformApp();
});
