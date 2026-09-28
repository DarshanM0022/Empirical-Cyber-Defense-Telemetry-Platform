// AegisX Web Console Client-Side Logic

let currentAssets = [];
let allFindings = [];

document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initModals();
    loadAllData();

    // Auto-refresh posture every 15s
    setInterval(loadPostureOverview, 15000);
});

// Tab Navigation
function initTabs() {
    const navItems = document.querySelectorAll(".nav-item");
    navItems.forEach(item => {
        item.addEventListener("click", () => {
            navItems.forEach(n => n.classList.remove("active"));
            document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

            item.classList.add("active");
            const tabId = item.getAttribute("data-tab");
            const pane = document.getElementById(`tab-${tabId}`);
            if (pane) pane.classList.add("active");

            // Refresh tab content
            if (tabId === "assets") loadAssets();
            if (tabId === "findings") loadFindings();
            if (tabId === "siem") { loadEvents(); loadDetections(); }
            if (tabId === "incidents") loadIncidents();
            if (tabId === "audit") loadAudit();
        });
    });
}

// Modal management
function openModal(id) {
    const m = document.getElementById(id);
    if (m) m.classList.add("active");
}

function closeModal(id) {
    const m = document.getElementById(id);
    if (m) m.classList.remove("active");
}

function initModals() {
    document.getElementById("btn-open-asset-modal")?.addEventListener("click", () => openModal("modal-asset"));
    document.getElementById("btn-open-event-modal")?.addEventListener("click", () => {
        populateAssetSelect();
        openModal("modal-event");
    });

    document.getElementById("form-create-asset")?.addEventListener("submit", handleCreateAsset);
    document.getElementById("form-authorize-asset")?.addEventListener("submit", handleAuthorizeAsset);
    document.getElementById("form-ingest-event")?.addEventListener("submit", handleIngestEvent);
}

// Initial Data Load
async function loadAllData() {
    await loadPostureOverview();
    await loadAssets();
    await loadFindings();
    await loadEvents();
    await loadDetections();
    await loadIncidents();
    await loadAudit();
}

// 1. Posture Overview
async function loadPostureOverview() {
    try {
        const res = await fetch("/api/v1/risk/overview");
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById("top-risk-level").textContent = data.overall_risk_level;
        document.getElementById("top-risk-score").textContent = data.overall_risk_score;
        document.getElementById("top-critical-findings").textContent = data.critical_findings;
        document.getElementById("top-active-incidents").textContent = data.active_incidents;
        document.getElementById("top-high-risk-assets").textContent = data.high_risk_assets;
        document.getElementById("top-suspicious-events").textContent = data.suspicious_events;

        // Fetch telemetry stats
        const statRes = await fetch("/api/v1/events/stats");
        if (statRes.ok) {
            const stats = await statRes.json();
            const counts = stats.telemetry_counts;
            document.getElementById("stat-auth-attempts").textContent = counts.authentication_attempts;
            document.getElementById("stat-failed-auth").textContent = counts.failed_authentication;
            document.getElementById("stat-new-device").textContent = counts.new_device_events;
            document.getElementById("stat-suspicious-auth").textContent = counts.suspicious_authentication_detections;
        }

        // Load risk breakdown if assets exist
        if (currentAssets.length > 0) {
            const firstAsset = currentAssets[0];
            const riskRes = await fetch(`/api/v1/risk/assets/${firstAsset.id}`);
            if (riskRes.ok) {
                const rData = await riskRes.json();
                renderRiskFactors(rData.factors);
            }
        }
    } catch (e) {
        console.error("Failed to load posture:", e);
    }
}

function renderRiskFactors(factors) {
    const container = document.getElementById("overview-risk-reasons");
    if (!factors || factors.length === 0) {
        container.innerHTML = `<div class="empty-state">No risk factors evaluated yet.</div>`;
        return;
    }

    container.innerHTML = factors.map(f => {
        const isPlus = f.delta >= 0;
        const sign = isPlus ? `+${f.delta}` : `${f.delta}`;
        return `
            <div class="risk-factor-item ${isPlus ? 'plus' : 'minus'}">
                <div>
                    <div class="risk-factor-title">${f.factor_name}</div>
                    <div class="risk-factor-rationale">${f.rationale} <span style="color:#6b7280;">(${f.source})</span></div>
                </div>
                <div class="risk-factor-delta ${isPlus ? 'plus' : 'minus'}">${sign}</div>
            </div>
        `;
    }).join("");
}

// 2. Assets & Authorization
async function loadAssets() {
    try {
        const res = await fetch("/api/v1/assets");
        currentAssets = await res.json();
        const tbody = document.getElementById("assets-table-body");

        if (currentAssets.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center">No assets registered yet. Click '+ Register New Asset' to add your target.</td></tr>`;
            return;
        }

        tbody.innerHTML = currentAssets.map(asset => {
            const activeAuth = asset.authorizations.find(a => a.status === "verified");
            const authBadge = activeAuth 
                ? `<span class="badge verified">Verified (${activeAuth.authorization_method})</span>`
                : `<span class="badge rejected">Unauthorized</span>`;

            return `
                <tr>
                    <td><strong>${asset.name}</strong><br><small style="color:#6b7280;">ID: ${asset.id}</small></td>
                    <td><code>${asset.target}</code><br><small>${asset.asset_type}</small></td>
                    <td>${asset.environment}</td>
                    <td><span class="badge ${asset.criticality}">${asset.criticality}</span></td>
                    <td>${authBadge}</td>
                    <td id="asset-score-${asset.id}">Loading...</td>
                    <td>
                        <div style="display:flex; gap:6px;">
                            ${!activeAuth ? `<button class="btn btn-secondary btn-sm" onclick="showAuthorizeModal('${asset.id}', '${asset.target}')">Authorize</button>` : ''}
                            <button class="btn btn-primary btn-sm" onclick="triggerScan('${asset.id}')">Run Scan</button>
                            <a href="/api/v1/reports/assets/${asset.id}/html" target="_blank" class="btn btn-secondary btn-sm">Report</a>
                        </div>
                    </td>
                </tr>
            `;
        }).join("");

        // Populate risk scores for each asset
        currentAssets.forEach(async (asset) => {
            const rRes = await fetch(`/api/v1/risk/assets/${asset.id}`);
            if (rRes.ok) {
                const rData = await rRes.json();
                const cell = document.getElementById(`asset-score-${asset.id}`);
                if (cell) {
                    cell.innerHTML = `<span class="badge ${rData.level.toLowerCase()}">${rData.level} (${rData.score})</span>`;
                }
            }
        });
    } catch (e) {
        console.error("Error loading assets:", e);
    }
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
        await loadAssets();
        await loadPostureOverview();
    } else {
        alert("Failed to register asset.");
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
        await loadAssets();
        await loadAudit();
        alert("Authorization verified! You can now run safe scans against this asset.");
    } else {
        alert("Authorization failed.");
    }
}

async function triggerScan(assetId) {
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = "Scanning...";

    try {
        const res = await fetch("/api/v1/scans", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ asset_id: assetId, scan_type: "web_security_audit" })
        });
        const scan = await res.json();

        if (scan.status === "rejected_unauthorized") {
            alert(`⚠️ Scan Rejected: ${scan.error_message}`);
        } else {
            alert(`Scan completed in ${scan.duration_seconds}s! Discovered ${scan.findings_count} findings backed by raw evidence.`);
        }

        await loadAssets();
        await loadFindings();
        await loadPostureOverview();
        await loadAudit();
    } catch (e) {
        alert("Error executing scan: " + e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = "Run Scan";
    }
}

// 3. Findings & Evidence
async function loadFindings() {
    try {
        const res = await fetch("/api/v1/findings");
        allFindings = await res.json();
        const tbody = document.getElementById("findings-table-body");

        if (allFindings.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center">No empirical findings recorded. Run a scan on an authorized asset.</td></tr>`;
            return;
        }

        tbody.innerHTML = allFindings.map(f => {
            const sha = f.evidence?.evidence_sha256 ? f.evidence.evidence_sha256.substring(0, 14) + "..." : "N/A";
            return `
                <tr>
                    <td><span class="badge ${f.severity}">${f.severity}</span></td>
                    <td><strong>${f.title}</strong><br><small style="color:#6b7280;">Asset: ${f.asset_id}</small></td>
                    <td>${f.category}</td>
                    <td>${f.confidence}</td>
                    <td><code>${sha}</code></td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="viewEvidence('${f.id}')">Inspect Evidence</button>
                    </td>
                </tr>
            `;
        }).join("");
    } catch (e) {
        console.error("Error loading findings:", e);
    }
}

function viewEvidence(findingId) {
    const finding = allFindings.find(f => f.id === findingId);
    if (!finding) return;

    document.getElementById("ev-title").textContent = finding.title;
    document.getElementById("ev-category").textContent = finding.category;
    const sevBadge = document.getElementById("ev-severity");
    sevBadge.textContent = finding.severity.toUpperCase();
    sevBadge.className = `badge ${finding.severity}`;

    const ev = finding.evidence || {};
    document.getElementById("ev-timestamp").textContent = ev.timestamp || "N/A";
    document.getElementById("ev-sha").textContent = ev.evidence_sha256 || "N/A";

    document.getElementById("ev-request").textContent = `${ev.request_method || 'GET'} ${ev.request_url || 'N/A'}`;
    
    let rawHeaders = ev.response_headers || "{}";
    try {
        const parsed = JSON.parse(rawHeaders);
        rawHeaders = JSON.stringify(parsed, null, 2);
    } catch (_) {}
    document.getElementById("ev-headers").textContent = rawHeaders;

    document.getElementById("ev-recommendation").textContent = finding.recommendation;
    openModal("modal-evidence");
}

// 4. SIEM & Telemetry
async function loadEvents() {
    try {
        const res = await fetch("/api/v1/events?limit=50");
        const events = await res.json();
        const tbody = document.getElementById("events-table-body");

        if (events.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center">No telemetry events logged yet. Ingest an event to test SIEM.</td></tr>`;
            return;
        }

        tbody.innerHTML = events.map(e => `
            <tr>
                <td><small>${new Date(e.timestamp).toLocaleTimeString()}</small></td>
                <td>${e.source}</td>
                <td><strong>${e.event_type}</strong> / ${e.action}</td>
                <td>${e.actor_id} ${e.is_new_device ? '<span class="badge warning">NEW DEV</span>' : ''}</td>
                <td><span class="badge ${e.result === 'success' ? 'verified' : 'rejected'}">${e.result}</span></td>
                <td><code>${e.source_ip || 'N/A'}</code></td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Error loading events:", e);
    }
}

async function loadDetections() {
    try {
        const res = await fetch("/api/v1/detections");
        const dets = await res.json();
        const tbody = document.getElementById("detections-table-body");

        if (dets.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center">No security detections triggered.</td></tr>`;
            return;
        }

        tbody.innerHTML = dets.map(d => `
            <tr>
                <td><span class="badge ${d.severity}">${d.severity}</span></td>
                <td><strong>${d.rule_name}</strong></td>
                <td>${d.description}</td>
                <td><code>${d.event_count}</code></td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Error loading detections:", e);
    }
}

function populateAssetSelect() {
    const sel = document.getElementById("event-asset-select");
    sel.innerHTML = `<option value="">(None)</option>` + currentAssets.map(a => `<option value="${a.id}">${a.name} (${a.target})</option>`).join("");
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
            alert(`🚨 Event Ingested! Deterministic rule triggered ${outcome.detections_triggered} detection(s).`);
        }
    } else {
        alert("Failed to ingest event.");
    }
}

// 5. Incidents
async function loadIncidents() {
    try {
        const res = await fetch("/api/v1/incidents");
        const incidents = await res.json();
        const tbody = document.getElementById("incidents-table-body");

        if (incidents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center">No open incidents. All monitored assets stable.</td></tr>`;
            return;
        }

        tbody.innerHTML = incidents.map(inc => `
            <tr>
                <td><span class="badge ${inc.severity}">${inc.severity}</span></td>
                <td><strong>${inc.title}</strong><br><small style="color:#6b7280;">${inc.summary}</small></td>
                <td><span class="badge ${inc.status === 'open' ? 'rejected' : 'warning'}">${inc.status}</span></td>
                <td><small>${new Date(inc.first_observed_at).toLocaleString()}</small></td>
                <td><code>${inc.related_finding_id || 'None'}</code></td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="resolveIncident('${inc.id}')">Resolve</button>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Error loading incidents:", e);
    }
}

async function resolveIncident(incId) {
    const res = await fetch(`/api/v1/incidents/${incId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "resolved" })
    });
    if (res.ok) {
        await loadIncidents();
        await loadPostureOverview();
    }
}

// 6. Audit Trail
async function loadAudit() {
    try {
        const res = await fetch("/api/v1/audit?limit=50");
        const logs = await res.json();
        const tbody = document.getElementById("audit-table-body");

        if (logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center">No audit records logged yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = logs.map(l => `
            <tr>
                <td><small>${new Date(l.timestamp).toLocaleTimeString()}</small></td>
                <td><code>${l.actor}</code></td>
                <td><strong>${l.action}</strong></td>
                <td>${l.resource_type}</td>
                <td><code>${l.resource_id}</code></td>
                <td><small>${l.details}</small></td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Error loading audit:", e);
    }
}
