/**
 * SOC Analyst Platform Application Controller for SIH26106
 * Manages view routing, REST API communication, sample loading, telemetry,
 * forensic timeline rendering, graph inspection, and unified report generation.
 */

class SocPlatformApp {
  constructor() {
    this.currentCase = null;
    this.graphVisualizer = null;
    this.activeTab = 'dashboard';

    this.init();
  }

  async init() {
    this.bindNavigation();
    this.bindSampleButtons();
    this.bindModalEvents();
    this.initGraph();
    await this.refreshDashboardMetrics();
    await this.loadRecentCases();

    // Auto-load Sample 2 (Phishing) by default so the analyst lands on rich telemetry immediately
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
        this.switchTab('threat');
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
        this.switchTab('threat');
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
        this.switchTab('threat');
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
