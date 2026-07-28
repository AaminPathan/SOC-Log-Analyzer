/**
 * SOC FALCON ENTERPRISE DASHBOARD APPLICATION
 */

let selectedFile = null;
let currentInputTab = 'paste';
let latestAnalysisData = null;

// Sample Log Stream matching backend log parser format
const SAMPLE_LOG_DATA = `2026-07-07 09:00:12 Failed User:admin IP:192.168.1.10
2026-07-07 09:01:20 Failed User:admin IP:192.168.1.10
2026-07-07 09:02:45 Failed User:admin IP:192.168.1.10
2026-07-07 09:03:30 Failed User:admin IP:192.168.1.10
2026-07-07 09:04:12 Failed User:admin IP:192.168.1.10
2026-07-07 09:05:18 Failed User:admin IP:192.168.1.10
2026-07-07 09:06:55 Success User:admin IP:192.168.1.10

2026-07-07 09:10:02 Failed User:root IP:10.10.10.1
2026-07-07 09:11:15 Failed User:root IP:10.10.10.1
2026-07-07 09:12:40 Success User:root IP:10.10.10.1

2026-07-07 09:20:10 Failed User:guest IP:172.16.1.25
2026-07-07 09:21:05 Failed User:guest IP:172.16.1.25
2026-07-07 09:22:18 Failed User:guest IP:172.16.1.25
2026-07-07 09:23:30 Failed User:guest IP:172.16.1.25
2026-07-07 09:24:55 Failed User:guest IP:172.16.1.25
2026-07-07 09:25:40 Failed User:guest IP:172.16.1.25

2026-07-07 09:30:15 Success User:developer IP:192.168.1.15
2026-07-07 09:31:05 Success User:developer IP:192.168.1.15
2026-07-07 09:32:50 Failed User:test IP:192.168.1.50
2026-07-07 09:33:15 Failed User:test IP:192.168.1.50
2026-07-07 09:34:45 Success User:test IP:192.168.1.50

2026-07-07 09:40:12 Failed User:backup IP:172.20.10.8
2026-07-07 09:41:20 Failed User:backup IP:172.20.10.8
2026-07-07 09:42:18 Failed User:backup IP:172.20.10.8
2026-07-07 09:43:11 Failed User:backup IP:172.20.10.8
2026-07-07 09:44:25 Success User:backup IP:172.20.10.8

2026-07-07 09:50:30 Failed User:student IP:192.168.100.25
2026-07-07 09:51:44 Success User:student IP:192.168.100.25
2026-07-07 09:32:50 Failed IP:192.168.100.26 User:shaam`;

// Sidebar Collapse Handler
function toggleSidebar() {
    const layout = document.getElementById('soc-layout');
    layout.classList.toggle('collapsed');
}

// Navigation Tabs Handler
function switchNavTab(tabName) {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => item.classList.remove('active'));
    
    const activeItem = document.querySelector(`.nav-item[href="#${tabName}"]`) || document.querySelector(`.nav-item[onclick*="${tabName}"]`);
    if (activeItem) activeItem.classList.add('active');
}

// Input Tabs Handler
function switchInputTab(tabName) {
    currentInputTab = tabName;
    const pasteBtn = document.getElementById('tab-btn-paste');
    const fileBtn = document.getElementById('tab-btn-file');
    const panePaste = document.getElementById('pane-paste');
    const paneFile = document.getElementById('pane-file');

    if (tabName === 'paste') {
        pasteBtn.classList.add('active');
        fileBtn.classList.remove('active');
        panePaste.style.display = 'block';
        paneFile.style.display = 'none';
    } else {
        fileBtn.classList.add('active');
        pasteBtn.classList.remove('active');
        paneFile.style.display = 'block';
        panePaste.style.display = 'none';
    }
    hideErrorToast();
}

// Load Sample Logs
function loadSampleLogs() {
    switchInputTab('paste');
    const textarea = document.getElementById('log-text-input');
    textarea.value = SAMPLE_LOG_DATA;
    textarea.focus();
    hideErrorToast();
}

// Clear Inputs
function clearInput() {
    document.getElementById('log-text-input').value = '';
    removeSelectedFile();
    hideErrorToast();
}

// Drag & Drop File Handlers
function triggerFileInput() {
    document.getElementById('file-input').click();
}

function handleFileSelected(event) {
    const files = event.target.files;
    if (files && files.length > 0) {
        processFile(files[0]);
    }
}

function handleDragOver(event) {
    event.preventDefault();
    event.stopPropagation();
    document.getElementById('drop-zone').classList.add('dragover');
}

function handleDragLeave(event) {
    event.preventDefault();
    event.stopPropagation();
    document.getElementById('drop-zone').classList.remove('dragover');
}

function handleDrop(event) {
    event.preventDefault();
    event.stopPropagation();
    document.getElementById('drop-zone').classList.remove('dragover');
    const files = event.dataTransfer.files;
    if (files && files.length > 0) {
        processFile(files[0]);
    }
}

function processFile(file) {
    const nameLower = file.name.toLowerCase();
    if (!nameLower.endsWith('.txt') && !nameLower.endsWith('.log') && !nameLower.endsWith('.dat')) {
        showErrorToast("Invalid evidence format. Upload plain text authentication logs (.txt, .log)");
        return;
    }
    if (file.size === 0) {
        showErrorToast("The selected log artifact is empty.");
        return;
    }

    selectedFile = file;
    document.getElementById('banner-filename').textContent = file.name;
    document.getElementById('banner-filesize').textContent = formatBytes(file.size);
    document.getElementById('file-banner').style.display = 'inline-flex';
    document.querySelector('.vault-icon').style.display = 'none';
    document.querySelector('.vault-text').style.display = 'none';
    document.querySelector('.vault-subtext').style.display = 'none';
    hideErrorToast();
}

function removeSelectedFile(event) {
    if (event) event.stopPropagation();
    selectedFile = null;
    document.getElementById('file-input').value = '';
    document.getElementById('file-banner').style.display = 'none';
    document.querySelector('.vault-icon').style.display = 'block';
    document.querySelector('.vault-text').style.display = 'block';
    document.querySelector('.vault-subtext').style.display = 'block';
}

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    else return (bytes / 1048576).toFixed(2) + ' MB';
}

// Error Toast UI Helpers
function showErrorToast(msg) {
    const toast = document.getElementById('error-toast');
    document.getElementById('error-toast-msg').textContent = msg;
    toast.style.display = 'flex';
}

function hideErrorToast() {
    document.getElementById('error-toast').style.display = 'none';
}

// Status Updates
function setTopnavStatus(state, text) {
    const badge = document.getElementById('topnav-status');
    const statusText = document.getElementById('topnav-status-text');

    badge.className = 'soc-status-badge';
    if (state === 'analyzing') {
        badge.classList.add('status-analyzing');
    } else {
        badge.classList.add('status-ready');
    }
    statusText.textContent = text;
}

// Run Analysis Execution API Call
async function runAnalysis() {
    hideErrorToast();

    let formData = null;
    let jsonBody = null;

    if (currentInputTab === 'file') {
        if (!selectedFile) {
            showErrorToast("Select or drop a log evidence file to execute threat analysis.");
            return;
        }
        formData = new FormData();
        formData.append('file', selectedFile);
    } else {
        const logVal = document.getElementById('log-text-input').value.trim();
        if (!logVal) {
            showErrorToast("Paste log data stream into the input pane before running analysis.");
            return;
        }
        jsonBody = JSON.stringify({ log_text: logVal });
    }

    const btn = document.getElementById('btn-analyze');
    const spinner = document.getElementById('btn-spinner');
    const btnText = document.getElementById('btn-analyze-text');

    btn.disabled = true;
    spinner.style.display = 'inline-block';
    btnText.textContent = 'ANALYZING...';
    setTopnavStatus('analyzing', 'ANALYZING LOG STREAM...');

    try {
        let response = null;
        if (formData) {
            response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            });
        } else {
            response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody
            });
        }

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Analysis engine failed to process log stream.");
        }

        latestAnalysisData = data;
        renderAnalysisDashboard(data);
        setTopnavStatus('ready', 'ANALYZER READY');

    } catch (err) {
        showErrorToast(err.message || "Failed to communicate with SOC backend server.");
        setTopnavStatus('ready', 'ANALYZER READY');
    } finally {
        btn.disabled = false;
        spinner.style.display = 'none';
        btnText.textContent = 'ANALYZE LOGS';
    }
}

// Render Dashboard View
function renderAnalysisDashboard(data) {
    const results = data.results || {};
    const enriched = data.enriched || {};
    const reportText = data.report || "";

    // Reveal Dashboard
    document.getElementById('empty-state').style.display = 'none';
    document.getElementById('results-dashboard').style.display = 'block';

    // 1. Topnav Threat Pill & Gauge
    const threatPill = document.getElementById('topnav-threat-pill');
    const threatVal = document.getElementById('topnav-threat-val');
    const levelStr = enriched.threat_level || 'NORMAL';
    threatVal.textContent = levelStr;

    threatPill.className = 'threat-pill';
    if (levelStr === 'CRITICAL') threatPill.classList.add('threat-pill-critical');
    else if (levelStr === 'ELEVATED') threatPill.classList.add('threat-pill-elevated');
    else threatPill.classList.add('threat-pill-normal');

    // Gauge Ring Widget
    const scoreNum = enriched.threat_score || 0;
    document.getElementById('gauge-num').textContent = scoreNum;
    const gaugeLabel = document.getElementById('gauge-status-label');
    gaugeLabel.textContent = levelStr === 'CRITICAL' ? 'CRITICAL THREAT' : (levelStr === 'ELEVATED' ? 'ELEVATED THREAT' : 'SYSTEM CLEAN');
    gaugeLabel.style.color = levelStr === 'CRITICAL' ? 'var(--soc-danger)' : (levelStr === 'ELEVATED' ? 'var(--soc-warning)' : 'var(--soc-success)');

    // Hero Meta Last Time
    document.getElementById('hero-last-time').textContent = enriched.last_analysis_time || 'Just Now';

    // 2. Summary Metrics
    const summary = results.summary || {};
    const total = summary.total_login_attempts || 0;
    const failed = summary.failed_login_attempts || 0;
    const success = summary.successful_login_attempts || 0;
    const malformed = summary.malformed_log_entries || 0;

    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-failed').textContent = failed;
    document.getElementById('stat-success').textContent = success;
    document.getElementById('stat-malformed').textContent = malformed;

    const failedPct = total > 0 ? ((failed / total) * 100).toFixed(1) : '0';
    const successPct = total > 0 ? ((success / total) * 100).toFixed(1) : '0';
    const malformedPct = total > 0 ? ((malformed / total) * 100).toFixed(1) : '0';

    document.getElementById('stat-failed-pct').textContent = `${failedPct}% failure rate`;
    document.getElementById('stat-success-pct').textContent = `${successPct}% success rate`;

    // Threat Velocity Distribution Bar
    document.getElementById('dist-bar-failed').style.width = `${failedPct}%`;
    document.getElementById('dist-bar-success').style.width = `${successPct}%`;
    document.getElementById('dist-bar-malformed').style.width = `${malformedPct}%`;

    // 3. Active Detections
    const detections = results.detections || {};
    const bruteData = detections.brute_force || {};
    const sprayData = detections.password_spraying || {};

    let activeAlertCount = 0;
    if (bruteData.detected) activeAlertCount += (bruteData.alerts ? bruteData.alerts.length : 1);
    if (sprayData.detected) activeAlertCount += (sprayData.alerts ? sprayData.alerts.length : 1);

    document.getElementById('sidebar-alert-count').textContent = activeAlertCount;
    document.getElementById('notif-dot').style.display = activeAlertCount > 0 ? 'block' : 'none';

    // Brute Force Alert Card
    const brutePill = document.getElementById('brute-status-pill');
    const bruteBody = document.getElementById('brute-card-body');
    const bruteRing = document.getElementById('brute-ring');

    if (bruteData.detected && bruteData.alerts && bruteData.alerts.length > 0) {
        brutePill.textContent = 'DETECTED';
        brutePill.className = 'status-pill pill-detected';
        bruteRing.style.background = 'var(--soc-danger-glow)';
        bruteRing.style.color = 'var(--soc-danger)';

        let html = '';
        bruteData.alerts.forEach(a => {
            html += `
                <div class="alert-item-box">
                    <span class="alert-ip">IP: ${escapeHtml(a.ip)}</span>
                    <span class="alert-meta text-danger"><strong>${a.attempts} attempts</strong> in ${a.time_window_seconds}s</span>
                </div>
            `;
        });
        bruteBody.innerHTML = html;
    } else {
        brutePill.textContent = 'CLEAR';
        brutePill.className = 'status-pill pill-clear';
        bruteRing.style.background = 'var(--soc-success-glow)';
        bruteRing.style.color = 'var(--soc-success)';
        bruteBody.innerHTML = `<div class="text-muted" style="font-size: 0.8rem;">No brute-force patterns detected.</div>`;
    }

    // Password Spraying Alert Card
    const sprayPill = document.getElementById('spray-status-pill');
    const sprayBody = document.getElementById('spray-card-body');
    const sprayRing = document.getElementById('spray-ring');

    if (sprayData.detected && sprayData.alerts && sprayData.alerts.length > 0) {
        sprayPill.textContent = 'DETECTED';
        sprayPill.className = 'status-pill pill-detected';
        sprayRing.style.background = 'var(--soc-danger-glow)';
        sprayRing.style.color = 'var(--soc-danger)';

        let html = '';
        sprayData.alerts.forEach(a => {
            const users = a.unique_users ? a.unique_users.join(', ') : '';
            html += `
                <div class="alert-item-box">
                    <span class="alert-ip">IP: ${escapeHtml(a.ip)}</span>
                    <span class="alert-meta text-danger">Targeted <strong>${a.user_count} accounts</strong> (${escapeHtml(users)})</span>
                </div>
            `;
        });
        sprayBody.innerHTML = html;
    } else {
        sprayPill.textContent = 'CLEAR';
        sprayPill.className = 'status-pill pill-clear';
        sprayRing.style.background = 'var(--soc-success-glow)';
        sprayRing.style.color = 'var(--soc-success)';
        sprayBody.innerHTML = `<div class="text-muted" style="font-size: 0.8rem;">No password spraying patterns detected.</div>`;
    }

    // 4. Failed Login Visual Charts
    const failedUsersMap = results.failed_logins_by_user || {};
    const sortedUsers = Object.entries(failedUsersMap).sort((a, b) => b[1] - a[1]);
    const maxUserAttempts = sortedUsers.length > 0 ? sortedUsers[0][1] : 1;

    const userBarsContainer = document.getElementById('chart-user-bars');
    userBarsContainer.innerHTML = '';
    if (sortedUsers.length === 0) {
        userBarsContainer.innerHTML = `<div class="text-muted" style="font-size: 0.8rem;">No failed login user data.</div>`;
    } else {
        sortedUsers.forEach(([username, count]) => {
            const pct = Math.min(100, Math.round((count / maxUserAttempts) * 100));
            const isTop = (results.highest_failed_user && results.highest_failed_user.username === username);
            userBarsContainer.innerHTML += `
                <div class="bar-row">
                    <div class="bar-label-line">
                        <span class="bar-key">${escapeHtml(username)} ${isTop ? '<span class="risk-tag risk-critical" style="font-size: 0.6rem; padding: 1px 4px; margin-left: 4px;">TOP TARGET</span>' : ''}</span>
                        <span class="bar-count">${count} failed</span>
                    </div>
                    <div class="bar-track">
                        <div class="bar-fill ${isTop ? 'fill-danger' : ''}" style="width: ${pct}%;"></div>
                    </div>
                </div>
            `;
        });
    }

    const failedIpsMap = results.failed_logins_by_ip || {};
    const sortedIps = Object.entries(failedIpsMap).sort((a, b) => b[1] - a[1]);
    const maxIpAttempts = sortedIps.length > 0 ? sortedIps[0][1] : 1;

    const ipBarsContainer = document.getElementById('chart-ip-bars');
    ipBarsContainer.innerHTML = '';
    if (sortedIps.length === 0) {
        ipBarsContainer.innerHTML = `<div class="text-muted" style="font-size: 0.8rem;">No failed login IP data.</div>`;
    } else {
        sortedIps.forEach(([ip, count]) => {
            const pct = Math.min(100, Math.round((count / maxIpAttempts) * 100));
            const isTop = (results.most_suspicious_ip && results.most_suspicious_ip.ip === ip);
            ipBarsContainer.innerHTML += `
                <div class="bar-row">
                    <div class="bar-label-line">
                        <span class="bar-key">${escapeHtml(ip)} ${isTop ? '<span class="risk-tag risk-critical" style="font-size: 0.6rem; padding: 1px 4px; margin-left: 4px;">MOST SUSPICIOUS</span>' : ''}</span>
                        <span class="bar-count">${count} failed</span>
                    </div>
                    <div class="bar-track">
                        <div class="bar-fill ${isTop ? 'fill-danger' : ''}" style="width: ${pct}%;"></div>
                    </div>
                </div>
            `;
        });
    }

    // 5. Enterprise Data Grids
    const ipsGridData = enriched.suspicious_ips_grid || [];
    document.getElementById('ip-grid-count').textContent = `${ipsGridData.length} IPs`;
    const ipsTbody = document.getElementById('tbody-suspicious-ips');
    ipsTbody.innerHTML = '';

    if (ipsGridData.length === 0) {
        ipsTbody.innerHTML = `<tr><td colspan="6" class="text-muted">No suspicious IP records.</td></tr>`;
    } else {
        ipsGridData.forEach(row => {
            const riskClass = row.risk_score === 'CRITICAL' ? 'risk-critical' : (row.risk_score === 'HIGH' ? 'risk-high' : (row.risk_score === 'MEDIUM' ? 'risk-medium' : 'risk-low'));
            ipsTbody.innerHTML += `
                <tr>
                    <td class="font-mono"><strong>${escapeHtml(row.ip)}</strong></td>
                    <td><strong>${row.failed_attempts}</strong></td>
                    <td><span class="risk-tag ${riskClass}">${row.risk_score}</span></td>
                    <td class="text-muted">${escapeHtml(row.location)}</td>
                    <td><span class="risk-tag ${riskClass}">${row.status}</span></td>
                    <td class="text-muted">${row.last_seen}</td>
                </tr>
            `;
        });
    }

    const usersGridData = enriched.targeted_users_grid || [];
    document.getElementById('user-grid-count').textContent = `${usersGridData.length} Users`;
    const usersTbody = document.getElementById('tbody-targeted-users');
    usersTbody.innerHTML = '';

    if (usersGridData.length === 0) {
        usersTbody.innerHTML = `<tr><td colspan="4" class="text-muted">No targeted user records.</td></tr>`;
    } else {
        usersGridData.forEach(row => {
            const riskClass = row.risk_score === 'HIGH' || row.risk_score === 'CRITICAL' ? 'risk-critical' : (row.risk_score === 'MEDIUM' ? 'risk-high' : 'risk-low');
            usersTbody.innerHTML += `
                <tr>
                    <td class="font-mono"><strong>${escapeHtml(row.username)}</strong></td>
                    <td><strong>${row.failed_attempts}</strong></td>
                    <td><span class="risk-tag ${riskClass}">${row.risk_score}</span></td>
                    <td><span class="risk-tag ${riskClass}">${row.status}</span></td>
                </tr>
            `;
        });
    }

    // 6. Audit Execution Timeline
    const timelineData = enriched.activity_timeline || [];
    const timelineContainer = document.getElementById('timeline-container');
    timelineContainer.innerHTML = '';

    timelineData.forEach(step => {
        timelineContainer.innerHTML += `
            <div class="step-item">
                <div class="step-node"></div>
                <div class="step-body">
                    <span class="step-title">${escapeHtml(step.title)}</span>
                    <span class="step-desc">${escapeHtml(step.desc)}</span>
                    <span class="step-time">${escapeHtml(step.time)}</span>
                </div>
            </div>
        `;
    });

    // 7. Inspection Panel
    document.getElementById('json-code-block').textContent = JSON.stringify(results, null, 2);
    document.getElementById('report-code-block').textContent = reportText || "Report generation pending.";

    // 8. Right Sidebar Widgets
    const topIpObj = results.most_suspicious_ip || {};
    const topUserObj = results.highest_failed_user || {};
    document.getElementById('widget-top-ip').textContent = topIpObj.ip ? `${topIpObj.ip} (${topIpObj.failed_attempts} fails)` : 'None';
    document.getElementById('widget-top-user').textContent = topUserObj.username ? `${topUserObj.username} (${topUserObj.failed_attempts} fails)` : 'None';

    // Scroll to dashboard canvas
    document.getElementById('results-dashboard').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Data Grid Filter
function filterIpGrid() {
    const q = document.getElementById('ip-search').value.toLowerCase();
    const rows = document.querySelectorAll('#tbody-suspicious-ips tr');
    rows.forEach(row => {
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(q) ? '' : 'none';
    });
}

function handleGlobalSearch(e) {
    const q = e.target.value.toLowerCase();
    const ipRows = document.querySelectorAll('#tbody-suspicious-ips tr');
    ipRows.forEach(row => row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none');
    
    const userRows = document.querySelectorAll('#tbody-targeted-users tr');
    userRows.forEach(row => row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none');
}

// Subtab Toggle
function switchInspectionSubtab(type) {
    const jsonBtn = document.getElementById('subtab-btn-json');
    const reportBtn = document.getElementById('subtab-btn-report');
    const jsonBlock = document.getElementById('json-code-block');
    const reportBlock = document.getElementById('report-code-block');

    if (type === 'json') {
        jsonBtn.classList.add('active');
        reportBtn.classList.remove('active');
        jsonBlock.style.display = 'block';
        reportBlock.style.display = 'none';
    } else {
        reportBtn.classList.add('active');
        jsonBtn.classList.remove('active');
        reportBlock.style.display = 'block';
        jsonBlock.style.display = 'none';
    }
}

// Copy JSON helper
function copyJsonToClipboard() {
    if (!latestAnalysisData || !latestAnalysisData.results) return;
    const jsonStr = JSON.stringify(latestAnalysisData.results, null, 2);
    navigator.clipboard.writeText(jsonStr).then(() => {
        alert("Structured JSON copied to clipboard!");
    }).catch(() => {
        alert("Failed to copy JSON.");
    });
}

// Utility: HTML Escaping
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
