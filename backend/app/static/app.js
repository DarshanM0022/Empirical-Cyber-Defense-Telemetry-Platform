// ==========================================================================
// AegisX SOC — Professional Enterprise Cybersecurity Client Engine
// ==========================================================================

let currentAssets = [];
let allFindings = [];
let allEvents = [];
let activeFindingSeverityFilter = "all";
let activeAssetEnvFilter = "all";

document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initInspectorTabs();
    initFilterHandlers();
    initSearchAndHotkeys();
    initFastActions();
    loadAllData();

    // Check URL hash for direct tab linking (e.g. #findings, #siem)
    const initialHash = window.location.hash.replace("#", "");
    if (initialHash && ["overview", "assets", "findings", "siem", "incidents", "audit"].includes(initialHash)) {
        switchTab(initialHash);
    }

    // Auto-refresh posture every 12 seconds
    setInterval(loadPostureOverview, 12000);
});

// Toast System
function showToast(title, message, type = "info") {
    const container = document.getElementById("soc-toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `soc-toast ${type}`;

    let icon = "ℹ️";
    if (type === "success") icon = "✅";
    if (type === "alert") icon = "🚨";
    if (type === "warning") icon = "⚠️";

    toast.innerHTML = `
        <div class="toast-icon">${icon}</div>
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            <div class="toast-desc">${message}</div>
        </div>
    `;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(20px)";
        toast.style.transition = "all 0.25s ease";
        setTimeout(() => toast.remove(), 250);
    }, 4500);
}

// Navigation & Tab Switching
function initNavigation() {
    const navItems = document.querySelectorAll(".soc-nav-item");
    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const tabId = item.getAttribute("data-tab");
            switchTab(tabId);
        });
    });

    document.getElementById("btn-quick-audit-log")?.addEventListener("click", () => {
        switchTab("audit");
    });
}

function switchTab(tabId) {
    document.querySelectorAll(".soc-nav-item").forEach(n => n.classList.remove("active"));
    document.querySelectorAll(".soc-tab").forEach(p => p.classList.remove("active"));

    const navItem = document.querySelector(`.soc-nav-item[data-tab="${tabId}"]`);
    const pane = document.getElementById(`tab-${tabId}`);

    if (navItem) navItem.classList.add("active");
    if (pane) pane.classList.add("active");

    if (tabId === "assets") loadAssets();
    if (tabId === "findings") loadFindings();
    if (tabId === "siem") { loadEvents(); loadDetections(); }
    if (tabId === "incidents") loadIncidents();
    if (tabId === "audit") loadAudit();
}

// Modal Management
function openModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.add("active");
}

function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.remove("active");
}

// Hotkey Search ('/' to focus)
function initSearchAndHotkeys() {
    const searchInput = document.getElementById("global-search-input");
    window.addEventListener("keydown", (e) => {
        if (e.key === "/" && document.activeElement !== searchInput) {
            e.preventDefault();
            searchInput.focus();
        }
        if (e.key === "Escape") {
            document.querySelectorAll(".soc-modal.active").forEach(m => m.classList.remove("active"));
        }
    });

    searchInput?.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase().trim();
        filterFindingsList(query);
    });

    document.getElementById("btn-open-asset-modal")?.addEventListener("click", () => openModal("modal-asset"));
    document.getElementById("btn-open-event-modal")?.addEventListener("click", () => {
        populateAssetSelect();
        openModal("modal-event");
    });

    document.getElementById("form-create-asset")?.addEventListener("submit", handleCreateAsset);
    document.getElementById("form-authorize-asset")?.addEventListener("submit", handleAuthorizeAsset);
    document.getElementById("form-ingest-event")?.addEventListener("submit", handleIngestEvent);
    document.getElementById("btn-recalc-risk")?.addEventListener("click", () => {
        loadPostureOverview();
        showToast("Posture Recalculated", "Empirical factors updated from current telemetry.", "info");
    });
}

// Fast Action Presets
function initFastActions() {
    document.getElementById("quick-action-scan")?.addEventListener("click", async () => {
        if (currentAssets.length === 0) {
            showToast("No Assets Available", "Register and authorize an asset first.", "warning");
            switchTab("assets");
            openModal("modal-asset");
            return;
        }
        const targetAsset = currentAssets[0];
        triggerScan(targetAsset.id);
    });

    document.getElementById("quick-action-brute")?.addEventListener("click", async () => {
        showToast("Simulating Telemetry", "Streaming 5 real failed authentications into SIEM pipeline...", "info");
        const actor = `analyst_test_${Math.floor(Math.random() * 900 + 100)}`;
        const assetId = currentAssets.length > 0 ? currentAssets[0].id : null;

        for (let i = 1; i <= 5; i++) {
            await fetch("/api/v1/events", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    source: "identity-provider",
                    event_type: "authentication",
                    action: "login",
                    actor_id: actor,
                    result: "failure",
                    source_ip: "198.51.100.22",
                    asset_id: assetId
                })
            });
        }

        showToast("Brute Force Detected", `Deterministic rule triggered on 5th failed auth for '${actor}'.`, "alert");
        await loadEvents();
        await loadDetections();
        await loadIncidents();
        await loadPostureOverview();
    });
}

// Filter Buttons
function initFilterHandlers() {
    document.querySelectorAll("#findings-severity-filters .filter-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("#findings-severity-filters .filter-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            activeFindingSeverityFilter = btn.getAttribute("data-severity");
            renderFindingsTable();
        });
    });

    document.querySelectorAll("[data-filter-env]").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("[data-filter-env]").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            activeAssetEnvFilter = btn.getAttribute("data-filter-env");
            renderAssetsTable();
        });
    });
}

// Evidence Inspector Tabs
function initInspectorTabs() {
    document.querySelectorAll(".inspector-tabs .tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".inspector-tabs .tab-btn").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".inspector-pane").forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const tabKey = btn.getAttribute("data-ev-tab");
            const pane = document.getElementById(`ev-pane-${tabKey}`);
            if (pane) pane.classList.add("active");
        });
    });
}

// --------------------------------------------------------------------------
// Data Loading & API Interactivity
// --------------------------------------------------------------------------

async function loadAllData() {
    await loadPostureOverview();
    await loadAssets();
    await loadFindings();
    await loadEvents();
    await loadDetections();
    await loadIncidents();
    await loadAudit();
}

// 1. Security Posture & Gauge
async function loadPostureOverview() {
    try {
        const res = await fetch("/api/v1/risk/overview");
        if (!res.ok) return;
        const data = await res.json();

        // Update HUD metrics
        document.getElementById("hud-risk-level").textContent = data.overall_risk_level;
        document.getElementById("hud-risk-score").textContent = data.overall_risk_score;
        document.getElementById("hud-critical-findings").textContent = data.critical_findings;
        document.getElementById("hud-active-incidents").textContent = data.active_incidents;
        document.getElementById("hud-high-risk-assets").textContent = data.high_risk_assets;
        document.getElementById("hud-suspicious-events").textContent = data.suspicious_events;

        // Animate Circular Gauge
        updatePostureGauge(data.overall_risk_score, data.overall_risk_level);

        // Fetch Telemetry Stats
        const statRes = await fetch("/api/v1/events/stats");
        if (statRes.ok) {
            const stats = await statRes.json();
            const counts = stats.telemetry_counts;
            document.getElementById("stat-auth-attempts").textContent = counts.authentication_attempts;
            document.getElementById("stat-failed-auth").textContent = counts.failed_authentication;
            document.getElementById("stat-new-device").textContent = counts.new_device_events;
            document.getElementById("stat-suspicious-auth").textContent = counts.suspicious_authentication_detections;
        }

        // Update Risk Waterfall breakdown from first asset
        if (currentAssets.length > 0) {
            const firstAsset = currentAssets[0];
            const riskRes = await fetch(`/api/v1/risk/assets/${firstAsset.id}`);
            if (riskRes.ok) {
                const rData = await riskRes.json();
                renderRiskWaterfall(rData.factors, firstAsset.name);
            }
        }
    } catch (e) {
        console.error("Failed to load posture:", e);
    }
}

function updatePostureGauge(score, level) {
    const gaugeFill = document.getElementById("posture-gauge-fill");
    if (!gaugeFill) return;

    // Circumference = 2 * PI * 42 ≈ 264
    const circumference = 264;
    const offset = circumference - (circumference * (score / 100));
    gaugeFill.style.strokeDashoffset = offset;

    // Severity color matching
    if (score >= 75) {
        gaugeFill.style.stroke = "var(--sev-critical)";
        document.getElementById("hud-risk-level").style.color = "var(--sev-critical)";
    } else if (score >= 50) {
        gaugeFill.style.stroke = "var(--sev-high)";
        document.getElementById("hud-risk-level").style.color = "var(--sev-high)";
    } else if (score >= 25) {
        gaugeFill.style.stroke = "var(--sev-medium)";
        document.getElementById("hud-risk-level").style.color = "var(--sev-medium)";
    } else {
        gaugeFill.style.stroke = "var(--accent-emerald)";
        document.getElementById("hud-risk-level").style.color = "var(--accent-emerald)";
    }
}

function renderRiskWaterfall(factors, assetName) {
    const container = document.getElementById("overview-risk-reasons");
    if (!factors || factors.length === 0) {
        container.innerHTML = `<div class="state-empty">No active risk factors evaluated for monitored assets.</div>`;
        return;
    }

    container.innerHTML = factors.map(f => {
        const isPlus = f.delta >= 0;
        const sign = isPlus ? `+${f.delta}` : `${f.delta}`;
        return `
            <div class="waterfall-item ${isPlus ? 'plus' : 'minus'}">
                <div class="wf-info">
                    <div class="wf-title">${f.factor_name}</div>
                    <div class="wf-sub">${f.rationale} &bull; <span class="tag tag-mono">${f.source}</span></div>
                </div>
                <div class="wf-delta ${isPlus ? 'plus' : 'minus'}">${sign}</div>
            </div>
        `;
    }).join("");
}

// 2. Asset Management & Authorization
async function loadAssets() {
    try {
        const res = await fetch("/api/v1/assets");
        currentAssets = await res.json();
        document.getElementById("nav-badge-assets").textContent = currentAssets.length;
        renderAssetsTable();
    } catch (e) {
        console.error("Failed to load assets:", e);
    }
}

function renderAssetsTable() {
    const tbody = document.getElementById("assets-table-body");
    let filtered = currentAssets;
    if (activeAssetEnvFilter !== "all") {
        filtered = filtered.filter(a => a.environment.toLowerCase() === activeAssetEnvFilter);
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="state-empty">No target assets registered in scope. Click '+ Register Target Asset' above.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(asset => {
        const activeAuth = asset.authorizations.find(a => a.status === "verified");
        const authBadge = activeAuth
            ? `<span class="badge-auth verified">VERIFIED (${activeAuth.authorization_method})</span>`
            : `<span class="badge-auth unauthorized">UNAUTHORIZED (BLOCKED)</span>`;

        return `
            <tr>
                <td><strong>${asset.name}</strong><br><small class="text-muted font-mono">${asset.id}</small></td>
                <td><code>${asset.target}</code><br><span class="tag">${asset.asset_type}</span></td>
                <td><span class="tag">${asset.environment}</span></td>
                <td><span class="badge-sev ${asset.criticality}">${asset.criticality}</span></td>
                <td>${authBadge}</td>
                <td id="asset-score-${asset.id}"><span class="text-muted">Loading...</span></td>
                <td class="text-right">
                    <div style="display:flex; justify-content: flex-end; gap:6px;">
                        ${!activeAuth ? `<button class="btn btn-soc-secondary btn-sm" onclick="showAuthorizeModal('${asset.id}', '${asset.target}')">Authorize</button>` : ''}
                        <button class="btn btn-soc-primary btn-sm" onclick="triggerScan('${asset.id}')">Run Scan</button>
                        <a href="/api/v1/reports/assets/${asset.id}/html" target="_blank" class="btn btn-soc-outline btn-sm">Report</a>
                    </div>
                </td>
            </tr>
        `;
    }).join("");

    // Populate live scores for each asset
    filtered.forEach(async (asset) => {
        const rRes = await fetch(`/api/v1/risk/assets/${asset.id}`);
        if (rRes.ok) {
            const rData = await rRes.json();
            const cell = document.getElementById(`asset-score-${asset.id}`);
            if (cell) {
                cell.innerHTML = `<span class="badge-sev ${rData.level.toLowerCase()}">${rData.level} (${rData.score})</span>`;
            }
        }
    });
}

async function handleCreateAsset(e) {
    e.preventDefault();
    const payload = {
        name: document.getElementById("asset-name").value,
        asset_type: document.getElementById("asset-type").value,
        target: document.getElementById("asset-target").value,
        environment: document.getElementById("asset-env").value,
        criticality: document.getElementById("asset-criticality").value,
        owner: "security-team"
    };

    const res = await fetch("/api/v1/assets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    if (res.ok) {
        closeModal("modal-asset");
        document.getElementById("form-create-asset").reset();
        showToast("Asset Registered", `Target '${payload.name}' added. Grant authorization to enable scans.`, "success");
        await loadAssets();
        await loadPostureOverview();
    } else {
        showToast("Registration Failed", "Unable to register target asset.", "alert");
    }
}

function showAuthorizeModal(assetId, target) {
    document.getElementById("auth-asset-id").value = assetId;
    document.getElementById("auth-scope").value = target.includes("://") ? target : `https://${target}`;
    openModal("modal-authorize");
}

async function handleAuthorizeAsset(e) {
    e.preventDefault();
    const assetId = document.getElementById("auth-asset-id").value;
    const payload = {
        scope: document.getElementById("auth-scope").value,
        authorized_by: document.getElementById("auth-by").value,
        authorization_method: document.getElementById("auth-method").value,
        expires_days: parseInt(document.getElementById("auth-days").value)
    };

    const res = await fetch(`/api/v1/assets/${assetId}/authorize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    if (res.ok) {
        closeModal("modal-authorize");
        showToast("Authorization Granted", "Explicit permission verified. Safe scans unlocked.", "success");
        await loadAssets();
        await loadAudit();
    } else {
        showToast("Authorization Failed", "Could not verify authorization request.", "alert");
    }
}

async function triggerScan(assetId) {
    showToast("Initiating Assessment", "Connecting to SNI 443 & port 80 socket...", "info");

    try {
        const res = await fetch("/api/v1/scans", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ asset_id: assetId, scan_type: "web_security_audit" })
        });
        const scan = await res.json();

        if (scan.status === "rejected_unauthorized") {
            showToast("Scanner Gate Aborted", scan.error_message, "alert");
        } else {
            showToast("Scan Complete", `Analyzed target in ${scan.duration_seconds}s. Discovered ${scan.findings_count} verifiable findings.`, "success");
        }

        await loadAssets();
        await loadFindings();
        await loadPostureOverview();
        await loadAudit();
    } catch (e) {
        showToast("Scanner Error", e.message, "alert");
    }
}

// 3. Findings & Raw Evidence
async function loadFindings() {
    try {
        const res = await fetch("/api/v1/findings");
        allFindings = await res.json();
        document.getElementById("nav-badge-findings").textContent = allFindings.length;
        renderFindingsTable();
    } catch (e) {
        console.error("Failed to load findings:", e);
    }
}

function renderFindingsTable(customList = null) {
    const list = customList || allFindings;
    const tbody = document.getElementById("findings-table-body");

    let filtered = list;
    if (activeFindingSeverityFilter !== "all") {
        filtered = filtered.filter(f => f.severity.toLowerCase() === activeFindingSeverityFilter);
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="state-empty">No empirical findings matching criteria.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(f => {
        const shaShort = f.evidence?.evidence_sha256 ? f.evidence.evidence_sha256.substring(0, 16) + "..." : "N/A";
        return `
            <tr>
                <td><span class="badge-sev ${f.severity}">${f.severity}</span></td>
                <td><strong>${f.title}</strong><br><small class="text-muted font-mono">Asset ID: ${f.asset_id}</small></td>
                <td><span class="tag">${f.category}</span></td>
                <td><span class="text-cyan font-mono">${f.confidence.toUpperCase()}</span></td>
                <td><code class="font-mono">${shaShort}</code></td>
                <td class="text-right">
                    <button class="btn btn-soc-secondary btn-sm" onclick="inspectEvidence('${f.id}')">Inspect Evidence</button>
                </td>
            </tr>
        `;
    }).join("");
}

function filterFindingsList(query) {
    if (!query) {
        renderFindingsTable();
        return;
    }
    const filtered = allFindings.filter(f => 
        f.title.toLowerCase().includes(query) ||
        f.category.toLowerCase().includes(query) ||
        (f.evidence?.evidence_sha256 && f.evidence.evidence_sha256.toLowerCase().includes(query))
    );
    renderFindingsTable(filtered);
}

function inspectEvidence(findingId) {
    const finding = allFindings.find(f => f.id === findingId);
    if (!finding) return;

    document.getElementById("ev-title").textContent = finding.title;
    document.getElementById("ev-category").textContent = finding.category;
    const sevBadge = document.getElementById("ev-severity");
    sevBadge.textContent = finding.severity.toUpperCase();
    sevBadge.className = `badge-sev ${finding.severity}`;

    const ev = finding.evidence || {};
    document.getElementById("ev-timestamp").textContent = ev.timestamp || "N/A";
    document.getElementById("ev-sha").textContent = ev.evidence_sha256 || "N/A";

    // Format Request
    document.getElementById("ev-request").textContent = `${ev.request_method || 'GET'} ${ev.request_url || 'N/A'}\nUser-Agent: AegisX-Defensive-Security-Scanner/0.1\nAccept: */*`;

    // Format Headers syntax like Wireshark/Burp
    let rawHeaders = ev.response_headers || "{}";
    try {
        const parsed = JSON.parse(rawHeaders);
        let headerText = `HTTP/1.1 ${ev.response_status_code || 200} OK\n`;
        for (const [k, v] of Object.entries(parsed)) {
            headerText += `${k}: ${v}\n`;
        }
        rawHeaders = headerText;
    } catch (_) {}
    document.getElementById("ev-headers").textContent = rawHeaders;

    document.getElementById("ev-recommendation").textContent = finding.recommendation;
    openModal("modal-evidence");
}

function copyEvidenceHash() {
    const hash = document.getElementById("ev-sha").textContent;
    navigator.clipboard.writeText(hash).then(() => {
        showToast("Hash Copied", "SHA-256 provenance digest copied to clipboard.", "success");
    });
}

// 4. SIEM & Telemetry
async function loadEvents() {
    try {
        const res = await fetch("/api/v1/events?limit=50");
        allEvents = await res.json();
        document.getElementById("nav-badge-events").textContent = allEvents.length;
        const tbody = document.getElementById("events-table-body");

        if (allEvents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="state-empty">No telemetry events logged. Ingest an event to test SIEM pipeline.</td></tr>`;
            return;
        }

        tbody.innerHTML = allEvents.map(e => `
            <tr>
                <td><small class="font-mono text-cyan">${new Date(e.timestamp).toLocaleTimeString()}</small></td>
                <td><span class="tag">${e.source}</span></td>
                <td><strong>${e.event_type}</strong> / ${e.action}</td>
                <td><code>${e.actor_id}</code> ${e.is_new_device ? '<span class="tag" style="color:var(--sev-high);">NEW DEV</span>' : ''}</td>
                <td><span class="badge-sev ${e.result === 'success' ? 'low' : 'critical'}">${e.result}</span></td>
                <td><code class="font-mono">${e.source_ip || 'N/A'}</code></td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Failed to load events:", e);
    }
}

async function loadDetections() {
    try {
        const res = await fetch("/api/v1/detections");
        const dets = await res.json();
        const tbody = document.getElementById("detections-table-body");

        if (dets.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="state-empty">No threat detection rule thresholds triggered.</td></tr>`;
            return;
        }

        tbody.innerHTML = dets.map(d => `
            <tr>
                <td><span class="badge-sev ${d.severity}">${d.severity}</span></td>
                <td><strong>${d.rule_name}</strong></td>
                <td>${d.description}</td>
                <td><code class="font-mono text-cyan">${d.event_count}</code></td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Failed to load detections:", e);
    }
}

function populateAssetSelect() {
    const sel = document.getElementById("event-asset-select");
    sel.innerHTML = `<option value="">(Platform-wide / Unassociated)</option>` + 
        currentAssets.map(a => `<option value="${a.id}">${a.name} (${a.target})</option>`).join("");
}

async function handleIngestEvent(e) {
    e.preventDefault();
    const payload = {
        source: document.getElementById("event-source").value,
        actor_id: document.getElementById("event-actor").value,
        action: document.getElementById("event-action").value,
        result: document.getElementById("event-result").value,
        source_ip: document.getElementById("event-ip").value || null,
        device_id: document.getElementById("event-device").value || null,
        is_new_device: document.getElementById("event-new-device").checked,
        event_type: "authentication",
        asset_id: document.getElementById("event-asset-select").value || null
    };

    const res = await fetch("/api/v1/events", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    if (res.ok) {
        const outcome = await res.json();
        closeModal("modal-event");
        await loadEvents();
        await loadDetections();
        await loadPostureOverview();

        if (outcome.detections_triggered > 0) {
            showToast("Detection Triggered", `Deterministic rule fired! Triggered ${outcome.detections_triggered} threat detection(s).`, "alert");
        } else {
            showToast("Event Ingested", `Security log recorded from '${payload.source}'.`, "info");
        }
    } else {
        showToast("Ingest Error", "Failed to ingest telemetry event.", "alert");
    }
}

// 5. Correlated Incidents
async function loadIncidents() {
    try {
        const res = await fetch("/api/v1/incidents");
        const incidents = await res.json();
        document.getElementById("nav-badge-incidents").textContent = incidents.length;
        const tbody = document.getElementById("incidents-table-body");

        if (incidents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="state-empty">No active security incidents. All monitored assets secure.</td></tr>`;
            return;
        }

        tbody.innerHTML = incidents.map(inc => `
            <tr>
                <td><span class="badge-sev ${inc.severity}">${inc.severity}</span></td>
                <td><strong>${inc.title}</strong><br><small class="text-muted">${inc.summary}</small></td>
                <td><code>${inc.asset_id}</code></td>
                <td><span class="badge-sev ${inc.status === 'open' ? 'critical' : 'medium'}">${inc.status.toUpperCase()}</span></td>
                <td><small class="font-mono text-muted">${new Date(inc.first_observed_at).toLocaleString()}</small></td>
                <td><code class="font-mono">${inc.related_finding_id || 'None'}</code></td>
                <td class="text-right">
                    ${inc.status !== 'resolved' ? `<button class="btn btn-soc-secondary btn-sm" onclick="resolveIncident('${inc.id}')">Resolve</button>` : '<span class="text-emerald font-mono">CLOSED</span>'}
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Failed to load incidents:", e);
    }
}

async function resolveIncident(incId) {
    const res = await fetch(`/api/v1/incidents/${incId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "resolved" })
    });
    if (res.ok) {
        showToast("Incident Resolved", `Incident ${incId} marked as resolved.`, "success");
        await loadIncidents();
        await loadPostureOverview();
    }
}

// 6. Cryptographic Audit Log
async function loadAudit() {
    try {
        const res = await fetch("/api/v1/audit?limit=50");
        const logs = await res.json();
        const tbody = document.getElementById("audit-table-body");

        if (logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="state-empty">No audit events recorded.</td></tr>`;
            return;
        }

        tbody.innerHTML = logs.map(l => `
            <tr>
                <td><small class="font-mono text-cyan">${new Date(l.timestamp).toLocaleTimeString()}</small></td>
                <td><code>${l.actor}</code></td>
                <td><strong>${l.action}</strong></td>
                <td><span class="tag">${l.resource_type}</span></td>
                <td><code class="font-mono text-muted">${l.resource_id}</code></td>
                <td><small class="text-secondary">${l.details}</small></td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Failed to load audit:", e);
    }
}
