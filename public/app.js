'use strict';

document.documentElement.classList.add('js');

let currentTab = 'overview';
let reportFilterType = '';
let reportPage = 1;
let banFilterStatus = 'active';
let activeModalReport = null;

function esc(val) {
  return String(val ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function shortHwid(hwid) {
  if (!hwid) return '<span class="cell-sub">គ្មាន</span>';
  const s = String(hwid);
  if (s.length <= 16) return `<code>${esc(s)}</code>`;
  return `<code title="${esc(s)}">${esc(s.slice(0, 10))}…${esc(s.slice(-6))}</code>`;
}

function typeBadge(type) {
  const t = String(type || '').toUpperCase();
  if (t === 'BAN') return '<span class="badge badge-ban">Ban</span>';
  if (t === 'WARNING') return '<span class="badge badge-warning">Warning</span>';
  return '<span class="badge badge-tracking">Tracking</span>';
}

function renderLoadingRows(colspan, count = 3) {
  return Array.from({ length: count })
    .map(
      () =>
        `<tr class="state-row"><td colspan="${colspan}"><span class="skeleton-line"></span></td></tr>`
    )
    .join('');
}

function renderEmptyRow(colspan, title, detail, actionHtml = '') {
  return `<tr class="state-row"><td colspan="${colspan}"><div class="state-block"><strong>${esc(title)}</strong><span>${esc(detail)}</span>${actionHtml ? `<div>${actionHtml}</div>` : ''}</div></td></tr>`;
}

function renderErrorRow(colspan, errMsg) {
  return `<tr class="state-row"><td colspan="${colspan}"><div class="state-block"><strong>ផ្ទុកទិន្នន័យមិនបានសម្រេច</strong><span>${esc(errMsg)}</span><div><button type="button" class="btn btn-ghost btn-sm" onclick="refreshCurrentTab()">ព្យាយាមម្ដងទៀត</button></div></div></td></tr>`;
}

function toast(msg, kind = 'info') {
  const box = document.getElementById('toastContainer');
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => el.remove(), 3600);
}

function readUrlState() {
  const params = new URLSearchParams(window.location.search);
  const tab = params.get('tab');
  if (tab && TAB_TITLES[tab]) currentTab = tab;
  const rType = params.get('type');
  if (rType !== null) reportFilterType = rType;
  const rPage = Number(params.get('page') || 1);
  if (rPage >= 1) reportPage = rPage;
  const bStatus = params.get('status');
  if (bStatus) banFilterStatus = bStatus;
}

function writeUrlState() {
  const params = new URLSearchParams();
  if (currentTab !== 'overview') params.set('tab', currentTab);
  if (currentTab === 'reports') {
    if (reportFilterType) params.set('type', reportFilterType);
    if (reportPage > 1) params.set('page', String(reportPage));
  }
  if (currentTab === 'bans' && banFilterStatus !== 'active') {
    params.set('status', banFilterStatus);
  }
  const qs = params.toString();
  const nextUrl = qs ? `${window.location.pathname}?${qs}` : window.location.pathname;
  window.history.replaceState(null, '', nextUrl);
}

async function api(url, options = {}) {
  const opts = {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  };
  if (opts.body && typeof opts.body === 'object') {
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(url, opts);
  if (res.status === 401 && !url.includes('/api/admin/login')) {
    showLogin();
    throw new Error('Session expired');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.success === false) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

async function withBusyButton(formOrBtn, task) {
  const btn =
    formOrBtn instanceof HTMLFormElement
      ? formOrBtn.querySelector('button[type="submit"]')
      : formOrBtn;
  if (btn) {
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
  }
  try {
    return await task();
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.removeAttribute('aria-busy');
    }
  }
}

function showLogin() {
  document.getElementById('appShell').classList.add('hidden');
  document.getElementById('loginView').classList.remove('hidden');
}

function showApp(username) {
  document.getElementById('loginView').classList.add('hidden');
  document.getElementById('appShell').classList.remove('hidden');
  document.getElementById('adminLabel').textContent = username;
}

const TAB_TITLES = {
  overview: ['ទិដ្ឋភាពទូទៅ (Overview)', 'តាមដានស្ថានភាពការពារការโกงរបស់ ndev-core-five ផ្ទាល់។'],
  reports: ['របាយការណ៍ & រូបភាពអេក្រង់ (Reports)', 'ពិនិត្យភស្តុតាងរូបភាពពី Discord និងអ្វីដែល Scanner ចាប់បាន។'],
  bans: ['គ្រប់គ្រងបញ្ជី HWID Ban', 'ដាក់ Ban ឬដោះ Ban ម៉ាស៊ីនអ្នកលេងតាម Motherboard HWID ឬ Email ភ្លាមៗ។'],
  players: ['បញ្ជីអ្នកលេង (Known players)', 'ប្រវត្តិអត្តសញ្ញាណអ្នកលេង និងការភ្ជាប់ Motherboard, Discord និង Email។'],
  detections: ['កម្មវិធីហាមឃាត់ (Process blacklist)', 'កែប្រែបញ្ជីកម្មវិធីហាមឃាត់ពីចម្ងាយដោយមិនបាច់ Build Client ថ្មី។'],
  logs: ['កំណត់ហេតុបិទហ្គេម (Enforcement logs)', 'កំណត់ត្រាពេលម៉ាស៊ីនជាប់ Ban ត្រូវបានបិទនៅពេលបើកហ្គេម។'],
  settings: ['ការកំណត់ប្រព័ន្ធ & Discord Webhooks', 'គ្រប់គ្រង Auto-Ban, Webhooks និងសុវត្ថិភាពគណនី Admin។'],
};

window.switchTab = function switchTab(tab) {
  currentTab = TAB_TITLES[tab] ? tab : 'overview';
  document.querySelectorAll('.nav-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.tab === currentTab);
  });
  document.querySelectorAll('.tab-section').forEach((s) => {
    s.classList.toggle('hidden', s.id !== `tab-${currentTab}`);
  });
  const [title, sub] = TAB_TITLES[currentTab];
  document.getElementById('pageHeading').textContent = title;
  document.getElementById('pageSubheading').textContent = sub;
  writeUrlState();
  refreshCurrentTab();
};

window.refreshCurrentTab = async function refreshCurrentTab() {
  try {
    await loadNavBadges();
    if (currentTab === 'overview') await loadOverview();
    else if (currentTab === 'reports') await loadReports();
    else if (currentTab === 'bans') await loadBans();
    else if (currentTab === 'players') await loadPlayers();
    else if (currentTab === 'detections') await loadDetections();
    else if (currentTab === 'logs') await loadLogs();
    else if (currentTab === 'settings') await loadSettings();
  } catch (err) {
    if (err.message !== 'Session expired') toast(err.message, 'error');
  }
};

async function loadNavBadges() {
  const data = await api('/api/admin/stats');
  const s = data.stats;
  document.getElementById('navBanCount').textContent = s.banReports;
  document.getElementById('navActiveBans').textContent = s.activeBans;
  document.getElementById('navDetectionsCount').textContent = s.enabledDetections;

  const badge = document.getElementById('autoBanStatusBadge');
  if (s.autoBanEnabled) {
    badge.className = 'badge badge-ok';
    badge.textContent = 'Auto-Ban: On';
  } else {
    badge.className = 'badge badge-warning';
    badge.textContent = 'Auto-Ban: Off';
  }
  return data;
}

async function loadOverview() {
  const alertsBody = document.getElementById('overviewAlertsBody');
  const bansBody = document.getElementById('overviewBansBody');
  alertsBody.innerHTML = renderLoadingRows(5, 3);
  bansBody.innerHTML = renderLoadingRows(3, 3);

  try {
    const data = await loadNavBadges();
    const s = data.stats;
    document.getElementById('statBans').textContent = s.banReports;
    document.getElementById('statWarnings').textContent = s.warningReports;
    document.getElementById('statActiveBans').textContent = s.activeBans;
    document.getElementById('statPlayers').textContent = s.knownPlayers;
    document.getElementById('statDetections').textContent = s.enabledDetections;
    document.getElementById('statToday').textContent = s.reportsToday;

    if (!data.recentAlerts.length) {
      alertsBody.innerHTML = renderEmptyRow(
        5,
        'មិនទាន់មានរបាយការណ៍ Ban ឬ Warning នៅឡើយទេ',
        'រាល់ការចាប់បានកម្មវិធី Cheat ពី ndev-core-five នឹងបង្ហាញនៅទីនេះភ្លាមៗ។',
        `<button type="button" class="btn btn-ghost btn-sm" onclick="switchTab('detections')">ពិនិត្យបញ្ជីកម្មវិធីហាមឃាត់</button>`
      );
    } else {
      alertsBody.innerHTML = data.recentAlerts
        .map(
          (r) => `
        <tr class="row-interactive" onclick="openReportModal(${r.id})">
          <td>${typeBadge(r.alert_type)}</td>
          <td>
            <div class="cell-primary">${esc(r.username || 'Unknown')}</div>
            <div class="cell-sub">${esc(r.email || r.computer_name || '')}</div>
          </td>
          <td class="cell-clamp">${esc(r.summary || '')}</td>
          <td>
            ${
              r.primary_screenshot && String(r.primary_screenshot).startsWith('http')
                ? `<img class="thumb" width="84" height="48" src="${esc(r.primary_screenshot)}" alt="ភស្តុតាងអេក្រង់" />`
                : '<span class="cell-sub">គ្មានរូបភាព</span>'
            }
          </td>
          <td class="cell-sub mono">${esc(r.created_at)}</td>
        </tr>`
        )
        .join('');
    }

    if (!data.recentBans.length) {
      bansBody.innerHTML = renderEmptyRow(
        3,
        'មិនទាន់មានម៉ាស៊ីនជាប់ HWID Ban ទេ',
        'អ្នកអាចដាក់ Ban ម៉ាស៊ីនដោយផ្ទាល់ ឬបើក Auto-Ban នៅក្នុងការកំណត់។',
        `<button type="button" class="btn btn-ghost btn-sm" onclick="switchTab('bans')">ទៅកាន់ផ្ទាំងដាក់ Ban</button>`
      );
    } else {
      bansBody.innerHTML = data.recentBans
        .map(
          (b) => `
        <tr>
          <td>
            <div class="cell-primary">${esc(b.username || 'Unknown')}</div>
            <div class="cell-sub">${esc(b.email || '')}</div>
            <div>${shortHwid(b.hwid)}</div>
          </td>
          <td>${esc(b.reason)}</td>
          <td><span class="badge badge-ban">${b.hit_count || 0}x</span></td>
        </tr>`
        )
        .join('');
    }
  } catch (err) {
    alertsBody.innerHTML = renderErrorRow(5, err.message);
    bansBody.innerHTML = renderErrorRow(3, err.message);
  }
}

async function loadReports() {
  const tbody = document.getElementById('reportsTableBody');
  tbody.innerHTML = renderLoadingRows(9, 4);

  try {
    const search = document.getElementById('reportSearch').value.trim();
    const qs = new URLSearchParams({
      page: String(reportPage),
      limit: '15',
      type: reportFilterType,
      search,
    });
    const data = await api(`/api/admin/reports?${qs}`);

    if (!data.items.length) {
      tbody.innerHTML = renderEmptyRow(
        9,
        'រកមិនឃើញទិន្នន័យរបាយការណ៍ទេ',
        'សាកល្បងផ្លាស់ប្ដូរប្រភេទតម្រង ឬពាក្យស្វែងរកខាងលើ។'
      );
    } else {
      tbody.innerHTML = data.items
        .map(
          (r) => `
        <tr>
          <td class="mono">#${r.id}</td>
          <td>${typeBadge(r.alert_type)}</td>
          <td>
            <div class="cell-primary">${esc(r.username || 'Unknown')}</div>
            <div class="cell-sub">${esc(r.email || '')}</div>
            ${r.discord_id ? `<div class="cell-signal mono">Discord: ${esc(r.discord_id)}</div>` : ''}
          </td>
          <td>
            <div>${shortHwid(r.hwid || r.hwid_raw)}</div>
            ${r.motherboard ? `<div class="cell-sub">${esc(r.motherboard)}</div>` : ''}
          </td>
          <td class="cell-clamp">
            <div>${esc(r.summary || '')}</div>
            <div class="cell-sub">${r.findings_count} findings (${r.critical_count} critical)</div>
          </td>
          <td>
            ${
              r.primary_screenshot && String(r.primary_screenshot).startsWith('http')
                ? `<img class="thumb" width="84" height="48" onclick="openReportModal(${r.id})" src="${esc(r.primary_screenshot)}" alt="ភស្តុតាងអេក្រង់" />`
                : '<span class="cell-sub">គ្មានរូបភាព</span>'
            }
          </td>
          <td>
            ${
              r.is_hwid_banned
                ? '<span class="badge badge-ban">Banned</span>'
                : '<span class="badge badge-ok">Active</span>'
            }
          </td>
          <td class="cell-sub mono">${esc(r.created_at)}</td>
          <td>
            <div class="action-cluster">
              <button type="button" class="btn btn-ghost btn-sm" onclick="openReportModal(${r.id})">ពិនិត្យលម្អិត</button>
              ${
                r.hwid
                  ? `<button type="button" class="btn btn-danger btn-sm" onclick="forceClosePlayerGame('${esc(r.hwid)}','${esc(r.username || '')}')">បិទហ្គេម</button>`
                  : ''
              }
            </div>
          </td>
        </tr>`
        )
        .join('');
    }

    const totalPages = Math.max(1, Math.ceil(data.total / data.limit));
    document.getElementById('reportsPageInfo').textContent =
      `ទំព័រ ${data.page} នៃ ${totalPages} (សរុប ${data.total} របាយការណ៍)`;
    document.getElementById('reportsPrevBtn').disabled = data.page <= 1;
    document.getElementById('reportsNextBtn').disabled = data.page >= totalPages;
  } catch (err) {
    tbody.innerHTML = renderErrorRow(9, err.message);
  }
}

window.openReportModal = async function openReportModal(id) {
  try {
    const { report } = await api(`/api/admin/reports/${id}`);
    activeModalReport = report;

    document.getElementById('modalTitle').textContent =
      `Report #${report.id} (${report.alert_type}) — ${report.username || 'Unknown Player'}`;
    document.getElementById('modalSubtitle').textContent =
      `កាលបរិច្ឆេទ: ${report.created_at} | IP: ${report.ip_address || 'គ្មាន'} | Monitors: ${report.monitor_count || 0}`;

    const actionsEl = document.getElementById('modalBanActions');
    if (report.hwid) {
      const quitBtn = `<button type="button" class="btn btn-ghost btn-sm" onclick="forceClosePlayerGame('${esc(report.hwid)}','${esc(report.username || '')}')">បិទហ្គេមអ្នកលេង</button>`;
      if (report.is_hwid_banned) {
        actionsEl.innerHTML = `${quitBtn}<button type="button" class="btn btn-success btn-sm" onclick="quickUnbanHwid('${esc(report.hwid)}', true)">ដោះ Ban HWID</button>`;
      } else {
        actionsEl.innerHTML = `${quitBtn}<button type="button" class="btn btn-primary btn-sm" onclick="quickBanFromReport()">ដាក់ Ban HWID នេះភ្លាម</button>`;
      }
    } else {
      actionsEl.innerHTML = '';
    }

    const screenSec = document.getElementById('modalScreenSection');
    const allImgs = (
      Array.isArray(report.screenshots) && report.screenshots.length
        ? report.screenshots
        : report.primary_screenshot
          ? [report.primary_screenshot]
          : []
    ).filter((u) => typeof u === 'string' && u.startsWith('http'));

    if (allImgs.length > 0) {
      screenSec.classList.remove('hidden');
      const mainImg = document.getElementById('modalMainImage');
      mainImg.src = allImgs[0];

      const tabsEl = document.getElementById('modalMonitorTabs');
      tabsEl.innerHTML = allImgs
        .map(
          (url, idx) => `
          <button type="button" class="tab-btn ${idx === 0 ? 'active' : ''}" onclick="selectModalScreen(this, '${encodeURIComponent(url)}')">
            ${idx === 0 ? 'អេក្រង់រួម (Discord CDN)' : `Monitor ${idx}`}
          </button>`
        )
        .join('');
    } else {
      screenSec.classList.add('hidden');
    }

    const findingsEl = document.getElementById('modalFindingsList');
    if (!report.findings || !report.findings.length) {
      findingsEl.innerHTML = `<div class="finding-item"><span class="cell-sub">គ្មានការចាប់បានកម្មវិធីសង្ស័យទេ (កត់ត្រាព័ត៌មានពេលបើកហ្គេមដំបូង — គ្មាន Screenshot)។</span></div>`;
    } else {
      findingsEl.innerHTML = report.findings
        .map(
          (f) => `
        <div class="finding-item">
          <div class="finding-head">
            <span class="cell-primary">${esc(f.name || 'Detection')}</span>
            <span class="badge ${String(f.severity).toLowerCase() === 'critical' ? 'badge-ban' : 'badge-warning'}">${esc(f.severity || 'Info')}</span>
          </div>
          <div class="cell-sub">
            ប្រភេទ: <code>${esc(f.category || '')}</code> | ប្រភព: <code>${esc(f.source_type || '')}</code> | សកម្មភាព: <code>${esc(f.action || '')}</code>
          </div>
          <div class="finding-path mono">${esc(f.path || '')}</div>
          ${
            f.details && Object.keys(f.details).length
              ? `<pre class="finding-pre mono">${esc(JSON.stringify(f.details, null, 2))}</pre>`
              : ''
          }
        </div>`
        )
        .join('');
    }

    const tokenListHtml =
      Array.isArray(report.hw_tokens) && report.hw_tokens.length
        ? `<div class="token-cluster">${report.hw_tokens
            .map(
              (t) =>
                `<span class="badge badge-tracking mono">${esc(t.split(':')[0])}:${esc(t.split(':')[1]?.slice(0, 8))}…</span>`
            )
            .join('')}</div>`
        : '<span class="cell-sub">គ្មាន</span>';

    document.getElementById('modalIdentityCard').innerHTML = `
      <dl class="kv-grid">
        <div class="kv-row"><dt class="kv-key">Username</dt><dd class="kv-val">${esc(report.username || 'គ្មាន')}</dd></div>
        <div class="kv-row"><dt class="kv-key">Email</dt><dd class="kv-val">${esc(report.email || 'គ្មាន')}</dd></div>
        <div class="kv-row"><dt class="kv-key">Discord ID</dt><dd class="kv-val mono">${esc(report.discord_id || 'គ្មាន')}</dd></div>
        <div class="kv-row"><dt class="kv-key">Steam ID</dt><dd class="kv-val mono">${esc(report.steam_id || 'គ្មាន')}</dd></div>
        <div class="kv-row"><dt class="kv-key">License</dt><dd class="kv-val mono">${esc(report.license || 'គ្មាន')}</dd></div>
        <div class="kv-row"><dt class="kv-key">Motherboard</dt><dd class="kv-val cell-primary">${esc(report.motherboard || 'Unknown Board')}</dd></div>
        <div class="kv-row"><dt class="kv-key">Master HWID</dt><dd class="kv-val mono">${esc(report.hwid || 'គ្មាន')}</dd></div>
        <div class="kv-row"><dt class="kv-key">Tokens (${(report.hw_tokens || []).length})</dt><dd class="kv-val">${tokenListHtml}</dd></div>
        <div class="kv-row"><dt class="kv-key">MachineGuid</dt><dd class="kv-val mono">${esc(report.hwid_raw || 'គ្មាន')}</dd></div>
        <div class="kv-row"><dt class="kv-key">PC / User</dt><dd class="kv-val">${esc(report.computer_name || '?')} / ${esc(report.windows_user || '?')}</dd></div>
        <div class="kv-row"><dt class="kv-key">OS Version</dt><dd class="kv-val">${esc(report.os_version || 'គ្មាន')}</dd></div>
        <div class="kv-row"><dt class="kv-key">ស្ថានភាព Ban</dt><dd class="kv-val">${
          report.is_hwid_banned
            ? `<span class="badge badge-ban">Banned (${esc(report.active_ban_reason || '')})</span>`
            : '<span class="badge badge-ok">Not banned</span>'
        }</dd></div>
      </dl>
    `;

    document.getElementById('modalDeleteBtn').onclick = async () => {
      if (!confirm(`តើបងពិតជាចង់លុប Report #${report.id} មែនទេ?`)) return;
      await api(`/api/admin/reports/${report.id}`, { method: 'DELETE' });
      toast(`បានលុប Report #${report.id}`, 'success');
      closeReportModal();
      refreshCurrentTab();
    };

    document.getElementById('reportModal').classList.remove('hidden');
  } catch (err) {
    toast(err.message, 'error');
  }
};

window.selectModalScreen = function selectModalScreen(btn, encodedUrl) {
  document.querySelectorAll('#modalMonitorTabs .tab-btn').forEach((b) => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('modalMainImage').src = decodeURIComponent(encodedUrl);
};

window.closeReportModal = function closeReportModal() {
  document.getElementById('reportModal').classList.add('hidden');
  activeModalReport = null;
};

window.quickBanFromReport = async function quickBanFromReport() {
  if (!activeModalReport || !activeModalReport.hwid) return;
  const defaultReason =
    activeModalReport.alert_type === 'TRACKING' || !activeModalReport.summary
      ? 'Detected cheating by Ndev Anti-Cheat'
      : activeModalReport.summary;
  const reason = prompt('បញ្ចូលមូលហេតុ Ban HWID:', defaultReason);
  if (!reason) return;
  try {
    await api('/api/admin/bans', {
      method: 'POST',
      body: {
        hwid: activeModalReport.hwid,
        hwid_raw: activeModalReport.hwid_raw,
        username: activeModalReport.username,
        email: activeModalReport.email,
        discord_id: activeModalReport.discord_id,
        license: activeModalReport.license,
        report_id: activeModalReport.id,
        reason,
      },
    });
    toast('បានដាក់ Ban HWID ដោយជោគជ័យ។', 'success');
    await openReportModal(activeModalReport.id);
    refreshCurrentTab();
  } catch (err) {
    toast(err.message, 'error');
  }
};

window.quickUnbanHwid = async function quickUnbanHwid(hwid, reopenModal = false) {
  if (!confirm(`តើបងចង់ដោះ Ban ម៉ាស៊ីន HWID:\n${hwid} មែនទេ?`)) return;
  try {
    await api(`/api/admin/bans/${encodeURIComponent(hwid)}`, { method: 'DELETE' });
    toast('បានដោះ Ban HWID រួចរាល់។', 'success');
    if (reopenModal && activeModalReport) {
      await openReportModal(activeModalReport.id);
    }
    refreshCurrentTab();
  } catch (err) {
    toast(err.message, 'error');
  }
};

window.quickBanPlayer = async function quickBanPlayer(hwid, username, email, discordId) {
  const reason = prompt(
    `ដាក់ Ban HWID របស់ ${username || hwid} (បញ្ចូលមូលហេតុ):`,
    'Motherboard / HWID banned by an administrator'
  );
  if (!reason) return;
  try {
    await api('/api/admin/bans', {
      method: 'POST',
      body: { hwid, username, email, discord_id: discordId, reason },
    });
    toast('បានដាក់ Ban HWID ដោយជោគជ័យ។', 'success');
    refreshCurrentTab();
  } catch (err) {
    toast(err.message, 'error');
  }
};

window.forceClosePlayerGame = async function forceClosePlayerGame(hwid, username) {
  const label = username ? `${username} (${hwid.slice(0, 10)}…)` : hwid;
  if (!confirm(`បញ្ជាបិទហ្គេមរបស់ "${label}" ពីចម្ងាយឥឡូវនេះមែនទេ?\n(បិទហ្គេមស្ងាត់ៗតែ ១ ដង ដោយមិនជាប់ HWID Ban ទេ)`)) {
    return;
  }
  try {
    const res = await api('/api/admin/players/force-quit', {
      method: 'POST',
      body: {
        hwid,
        reason: `Closed remotely by administrator (${username || 'Player'})`,
      },
    });
    toast(
      res.isOnline
        ? `បានផ្ញើបញ្ជាបិទហ្គេមទៅកាន់ ${username || 'អ្នកលេង'} (នឹងបិទក្នុង ៥ វិនាទី)។`
        : `បានដាក់បញ្ជាបិទហ្គេមរង់ចាំសម្រាប់ ${username || 'អ្នកលេង'}។`,
      'success'
    );
    if (currentTab === 'players') loadPlayers();
  } catch (err) {
    toast(err.message, 'error');
  }
};

async function loadBans() {
  const tbody = document.getElementById('bansTableBody');
  tbody.innerHTML = renderLoadingRows(7, 3);

  try {
    const search = document.getElementById('banSearch').value.trim();
    const qs = new URLSearchParams({ status: banFilterStatus, search });
    const data = await api(`/api/admin/bans?${qs}`);

    if (!data.items.length) {
      tbody.innerHTML = renderEmptyRow(
        7,
        'មិនមានទិន្នន័យ HWID Ban ក្នុងបញ្ជីនេះទេ',
        'ប្រើទម្រង់ខាងលើដើម្បីដាក់ Ban តាមលេខកូដ HWID ឬអ៊ីមែលអ្នកលេង។'
      );
      return;
    }

    tbody.innerHTML = data.items
      .map(
        (b) => `
      <tr>
        <td>
          <div class="cell-primary">${esc(b.username || 'Unknown')}</div>
          <div class="cell-sub">${esc(b.email || '')}</div>
          ${b.discord_id ? `<div class="cell-signal mono">Discord: ${esc(b.discord_id)}</div>` : ''}
        </td>
        <td>
          <div>${shortHwid(b.hwid)}</div>
          ${b.motherboard ? `<div class="cell-signal">${esc(b.motherboard)}</div>` : ''}
          <div class="cell-sub">Tokens locked: ${b.token_count || 0}${b.last_matched_token ? ` | Last hit: <code>${esc(String(b.last_matched_token).split(':')[0])}</code>` : ''}</div>
        </td>
        <td>${esc(b.reason)}</td>
        <td>
          <div>${esc(b.banned_by)}</div>
          <div class="cell-sub">${esc(b.source)}</div>
        </td>
        <td class="mono">${b.expires_at ? esc(b.expires_at) : '<span class="badge badge-ban">Permanent</span>'}</td>
        <td><span class="badge badge-warning">${b.hit_count || 0} ដង</span></td>
        <td>
          ${
            b.active
              ? `<button type="button" class="btn btn-success btn-sm" onclick="quickUnbanHwid('${esc(b.hwid)}')">ដោះ Ban</button>`
              : `<button type="button" class="btn btn-danger btn-sm" onclick="quickBanPlayer('${esc(b.hwid)}','${esc(b.username || '')}','${esc(b.email || '')}','${esc(b.discord_id || '')}')">ដាក់ Ban ឡើងវិញ</button>`
          }
        </td>
      </tr>`
      )
      .join('');
  } catch (err) {
    tbody.innerHTML = renderErrorRow(7, err.message);
  }
}

async function loadPlayers() {
  const tbody = document.getElementById('playersTableBody');
  tbody.innerHTML = renderLoadingRows(8, 4);

  try {
    const search = document.getElementById('playerSearch').value.trim();
    const data = await api(`/api/admin/players?search=${encodeURIComponent(search)}`);

    if (!data.items.length) {
      tbody.innerHTML = renderEmptyRow(
        8,
        'មិនទាន់មានទិន្នន័យអ្នកលេងនៅឡើយទេ',
        'ទិន្នន័យអ្នកលេង និង Motherboard នឹងកត់ត្រាដោយស្វ័យប្រវត្តិពេល Client ផ្ញើរបាយការណ៍មក /submit។'
      );
      return;
    }

    tbody.innerHTML = data.items
      .map(
        (p) => `
      <tr>
        <td>
          <div class="cell-primary">${esc(p.username || 'Unknown')}</div>
          <div class="cell-sub">
            ${
              p.is_online
                ? '<span class="badge badge-ok">Online</span>'
                : '<span class="badge badge-tracking">Offline</span>'
            }
            ${p.pending_quit > 0 ? '<span class="badge badge-warning">កំពុងបញ្ជាបិទ…</span>' : ''}
          </div>
        </td>
        <td>
          <div>${esc(p.email || 'គ្មាន')}</div>
          <div class="cell-sub mono">${esc(p.license ? p.license.slice(0, 14) + '…' : '')}</div>
        </td>
        <td class="mono">
          <div>DC: ${esc(p.discord_id || 'គ្មាន')}</div>
          <div class="cell-sub">Steam: ${esc(p.steam_id || 'គ្មាន')}</div>
        </td>
        <td>
          <div>${shortHwid(p.hwid)}</div>
          ${p.motherboard ? `<div class="cell-sub">${esc(p.motherboard)}</div>` : ''}
        </td>
        <td>
          <div>${esc(p.computer_name || 'គ្មាន')}</div>
          <div class="cell-sub mono">${esc(p.last_ip || '')}</div>
        </td>
        <td class="mono">
          <span>${p.report_count}</span>
          ${p.ban_report_count > 0 ? `<span class="badge badge-ban">${p.ban_report_count} Ban</span>` : ''}
        </td>
        <td class="cell-sub mono">${esc(p.last_seen_at)}</td>
        <td>
          <div class="action-cluster">
            <button type="button" class="btn btn-ghost btn-sm" onclick="forceClosePlayerGame('${esc(p.hwid)}','${esc(p.username || '')}')">បិទហ្គេម</button>
            ${
              p.is_banned
                ? `<button type="button" class="btn btn-success btn-sm" onclick="quickUnbanHwid('${esc(p.hwid)}')">ដោះ Ban</button>`
                : `<button type="button" class="btn btn-danger btn-sm" onclick="quickBanPlayer('${esc(p.hwid)}','${esc(p.username || '')}','${esc(p.email || '')}','${esc(p.discord_id || '')}')">ដាក់ Ban HWID</button>`
            }
          </div>
        </td>
      </tr>`
      )
      .join('');
  } catch (err) {
    tbody.innerHTML = renderErrorRow(8, err.message);
  }
}

async function loadDetections() {
  const tbody = document.getElementById('detectionsTableBody');
  tbody.innerHTML = renderLoadingRows(6, 4);

  try {
    const search = document.getElementById('detSearch').value.trim();
    const data = await api(`/api/admin/detections?search=${encodeURIComponent(search)}`);

    if (!data.items.length) {
      tbody.innerHTML = renderEmptyRow(
        6,
        'រកមិនឃើញឈ្មោះកម្មវិធីហាមឃាត់ទេ',
        'បន្ថែមឈ្មោះ .exe ថ្មីនៅខាងលើ ឬចុចស្ដារបញ្ជីដើមឡើងវិញ។'
      );
      return;
    }

    tbody.innerHTML = data.items
      .map(
        (d) => `
      <tr>
        <td>
          <label class="toggle-wrap">
            <span class="visually-hidden">បើក ឬបិទ ${esc(d.exe_name)}</span>
            <input type="checkbox" class="toggle-input" ${d.enabled ? 'checked' : ''} onchange="toggleDetection(${d.id}, this.checked)" />
          </label>
        </td>
        <td class="mono cell-primary">${esc(d.exe_name)}</td>
        <td>${esc(d.display_name)}</td>
        <td><span class="badge badge-tracking">${esc(d.category)}</span></td>
        <td class="cell-sub">${d.is_builtin ? 'Built-in C++' : 'Custom'}</td>
        <td>
          <button type="button" class="btn btn-ghost btn-sm" onclick="deleteDetection(${d.id}, '${esc(d.exe_name)}')">លុបចេញ</button>
        </td>
      </tr>`
      )
      .join('');
  } catch (err) {
    tbody.innerHTML = renderErrorRow(6, err.message);
  }
}

window.toggleDetection = async function toggleDetection(id, enabled) {
  try {
    await api(`/api/admin/detections/${id}`, { method: 'PATCH', body: { enabled } });
    loadNavBadges();
  } catch (err) {
    toast(err.message, 'error');
    loadDetections();
  }
};

window.deleteDetection = async function deleteDetection(id, exeName) {
  if (!confirm(`លុប "${exeName}" ចេញពីបញ្ជីហាមឃាត់?`)) return;
  try {
    await api(`/api/admin/detections/${id}`, { method: 'DELETE' });
    toast(`បានលុប ${exeName}`, 'success');
    loadDetections();
    loadNavBadges();
  } catch (err) {
    toast(err.message, 'error');
  }
};

async function loadLogs() {
  const tbody = document.getElementById('logsTableBody');
  tbody.innerHTML = renderLoadingRows(7, 3);

  try {
    const data = await api('/api/admin/logs');

    if (!data.items.length) {
      tbody.innerHTML = renderEmptyRow(
        7,
        'មិនទាន់មានកំណត់ហេតុបិទហ្គេមនៅឡើយទេ',
        'រាល់ពេលម៉ាស៊ីនដែលជាប់ HWID Ban ព្យាយាមបើក NPKP.exe កំណត់ត្រានឹងលោតចូលទីនេះ។'
      );
      return;
    }

    tbody.innerHTML = data.items
      .map(
        (l) => `
      <tr>
        <td class="mono">#${l.id}</td>
        <td><span class="badge badge-ban">${esc(l.event_type)}</span></td>
        <td>
          <div class="cell-primary">${esc(l.username || 'Unknown')}</div>
          <div class="cell-sub">${esc(l.email || '')}${l.discord_id ? ` | DC: ${esc(l.discord_id)}` : ''}</div>
        </td>
        <td>${shortHwid(l.hwid)}</td>
        <td>${esc(l.reason || '')}</td>
        <td class="mono cell-sub">${esc(l.ip_address || '')}</td>
        <td class="mono cell-sub">${esc(l.created_at)}</td>
      </tr>`
      )
      .join('');
  } catch (err) {
    tbody.innerHTML = renderErrorRow(7, err.message);
  }
}

async function loadSettings() {
  const { settings } = await api('/api/admin/settings');
  document.getElementById('setAutoBan').checked = !!settings.auto_ban_on_critical;
  document.getElementById('setWebhookBan').value = settings.discord_webhook_ban || '';
  document.getElementById('setWebhookWarning').value = settings.discord_webhook_warning || '';
  document.getElementById('setWebhookTracking').value = settings.discord_webhook_tracking || '';
  document.getElementById('setWebhookLogs').value = settings.discord_webhook_logs || '';
  document.getElementById('setScannerPin').value = settings.scanner_pin || '';
  document.getElementById('setLogSecret').value = settings.anticheat_log_secret || '';
  document.getElementById('newAdminUsername').value = settings.admin_username || 'admin';
}

window.testWebhook = async function testWebhook(inputId) {
  const url = document.getElementById(inputId).value.trim();
  if (!url) return toast('សូមបញ្ចូល Discord Webhook URL ជាមុនសិន។', 'error');
  try {
    await api('/api/admin/settings/test-webhook', { method: 'POST', body: { url } });
    toast('ផ្ញើសារសាកល្បងទៅ Discord ជោគជ័យ។', 'success');
  } catch (err) {
    toast(err.message, 'error');
  }
};

document.addEventListener('DOMContentLoaded', async () => {
  readUrlState();

  document.querySelectorAll('.nav-btn').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  document.getElementById('refreshBtn').addEventListener('click', refreshCurrentTab);

  document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusyButton(e.currentTarget, async () => {
      try {
        const username = document.getElementById('loginUsername').value.trim();
        const password = document.getElementById('loginPassword').value;
        const res = await api('/api/admin/login', {
          method: 'POST',
          body: { username, password },
        });
        document.getElementById('loginPassword').value = '';
        showApp(res.admin.username);
        switchTab(currentTab);
      } catch (err) {
        toast(err.message, 'error');
      }
    });
  });

  document.getElementById('logoutBtn').addEventListener('click', async () => {
    await api('/api/admin/logout', { method: 'POST' }).catch(() => {});
    showLogin();
  });

  document.querySelectorAll('#reportTypeTabs .tab-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.type === reportFilterType);
    btn.addEventListener('click', () => {
      document.querySelectorAll('#reportTypeTabs .tab-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      reportFilterType = btn.dataset.type;
      reportPage = 1;
      writeUrlState();
      loadReports();
    });
  });

  let searchTimer;
  const debounce = (fn) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(fn, 280);
  };

  document.getElementById('reportSearch').addEventListener('input', () =>
    debounce(() => {
      reportPage = 1;
      loadReports();
    })
  );
  document.getElementById('banSearch').addEventListener('input', () => debounce(loadBans));
  document.getElementById('playerSearch').addEventListener('input', () => debounce(loadPlayers));
  document.getElementById('detSearch').addEventListener('input', () => debounce(loadDetections));

  document.getElementById('reportsPrevBtn').addEventListener('click', () => {
    if (reportPage > 1) {
      reportPage--;
      writeUrlState();
      loadReports();
    }
  });
  document.getElementById('reportsNextBtn').addEventListener('click', () => {
    reportPage++;
    writeUrlState();
    loadReports();
  });

  document.getElementById('purgeTrackingBtn').addEventListener('click', async () => {
    if (!confirm('លុបរបាយការណ៍ប្រភេទ Tracking ទាំងអស់ដើម្បីសម្អាតទិន្នន័យមែនទេ?')) return;
    const res = await api('/api/admin/reports/purge-tracking', { method: 'POST' });
    toast(`បានសម្អាត ${res.deleted} tracking reports`, 'success');
    loadReports();
    loadNavBadges();
  });

  document.querySelectorAll('#banStatusTabs .tab-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.status === banFilterStatus);
    btn.addEventListener('click', () => {
      document.querySelectorAll('#banStatusTabs .tab-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      banFilterStatus = btn.dataset.status;
      writeUrlState();
      loadBans();
    });
  });

  document.getElementById('manualBanForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusyButton(e.currentTarget, async () => {
      try {
        await api('/api/admin/bans', {
          method: 'POST',
          body: {
            hwid: document.getElementById('banHwidInput').value.trim(),
            duration_hours: document.getElementById('banDurationInput').value || null,
            username: document.getElementById('banUsernameInput').value.trim() || null,
            email: document.getElementById('banEmailInput').value.trim() || null,
            reason: document.getElementById('banReasonInput').value.trim(),
          },
        });
        e.target.reset();
        toast('បានដាក់ Ban HWID ដោយជោគជ័យ។', 'success');
        loadBans();
        loadNavBadges();
      } catch (err) {
        toast(err.message, 'error');
      }
    });
  });

  document.getElementById('emailBanForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusyButton(e.currentTarget, async () => {
      try {
        const res = await api('/api/hwid/admin/ban-hwid-by-email', {
          method: 'POST',
          body: {
            email: document.getElementById('emailBanAddress').value.trim(),
            reason: document.getElementById('emailBanReason').value.trim(),
          },
        });
        e.target.reset();
        toast(`បានដាក់ Ban ចំនួន ${res.count} ម៉ាស៊ីនសម្រាប់ Email នេះ។`, 'success');
        loadBans();
        loadNavBadges();
      } catch (err) {
        toast(err.message, 'error');
      }
    });
  });

  document.getElementById('addDetectionForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusyButton(e.currentTarget, async () => {
      try {
        await api('/api/admin/detections', {
          method: 'POST',
          body: {
            exe_name: document.getElementById('detExeInput').value.trim(),
            display_name: document.getElementById('detNameInput').value.trim(),
            category: document.getElementById('detCategoryInput').value.trim() || 'Custom Cheat',
          },
        });
        document.getElementById('detExeInput').value = '';
        document.getElementById('detNameInput').value = '';
        toast('បានបន្ថែមចូលបញ្ជីហាមឃាត់។', 'success');
        loadDetections();
        loadNavBadges();
      } catch (err) {
        toast(err.message, 'error');
      }
    });
  });

  document.getElementById('resetDetectionsBtn').addEventListener('click', async () => {
    if (!confirm('ស្ដារ និងបើកបញ្ជីកម្មវិធីហាមឃាត់ដើមទាំងអស់ឡើងវិញមែនទេ?')) return;
    await api('/api/admin/detections/reset-defaults', { method: 'POST' });
    toast('បានស្ដារបញ្ជីដើមរួចរាល់។', 'success');
    loadDetections();
    loadNavBadges();
  });

  document.getElementById('settingsForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusyButton(e.currentTarget, async () => {
      try {
        await api('/api/admin/settings', {
          method: 'PUT',
          body: {
            auto_ban_on_critical: document.getElementById('setAutoBan').checked,
            discord_webhook_ban: document.getElementById('setWebhookBan').value.trim(),
            discord_webhook_warning: document.getElementById('setWebhookWarning').value.trim(),
            discord_webhook_tracking: document.getElementById('setWebhookTracking').value.trim(),
            discord_webhook_logs: document.getElementById('setWebhookLogs').value.trim(),
            scanner_pin: document.getElementById('setScannerPin').value.trim(),
            anticheat_log_secret: document.getElementById('setLogSecret').value.trim(),
          },
        });
        toast('បានរក្សាទុកការកំណត់ដោយជោគជ័យ។', 'success');
        loadNavBadges();
      } catch (err) {
        toast(err.message, 'error');
      }
    });
  });

  document.getElementById('passwordForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusyButton(e.currentTarget, async () => {
      try {
        const newUsername = document.getElementById('newAdminUsername').value.trim();
        await api('/api/admin/settings/password', {
          method: 'POST',
          body: {
            new_username: newUsername,
            current_password: document.getElementById('currentAdminPassword').value,
            new_password: document.getElementById('newAdminPassword').value,
          },
        });
        document.getElementById('currentAdminPassword').value = '';
        document.getElementById('newAdminPassword').value = '';
        document.getElementById('adminLabel').textContent = newUsername;
        toast('បានផ្លាស់ប្ដូរលេខសម្ងាត់ Admin ដោយជោគជ័យ។', 'success');
      } catch (err) {
        toast(err.message, 'error');
      }
    });
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeReportModal();
  });
  document.getElementById('reportModal').addEventListener('click', (e) => {
    if (e.target.id === 'reportModal') closeReportModal();
  });

  try {
    const me = await api('/api/admin/me');
    showApp(me.admin.username);
    switchTab(currentTab);
  } catch {
    showLogin();
  }
});
