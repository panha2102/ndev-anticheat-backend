'use strict';

const express = require('express');
const config = require('../config');
const db = require('../db');
const { DEFAULT_BANNED_PROCESSES } = require('../defaults');
const {
  COOKIE_NAME,
  TOKEN_TTL_MS,
  signToken,
  requireAdmin,
  verifyLogSecret,
} = require('../middleware/auth');
const {
  expireOutdatedBans,
  banHwid,
  unbanHwid,
  banHwidsByEmail,
} = require('../services/banService');
const { sendTestWebhook } = require('../services/discord');

const router = express.Router();

// Allows either logged-in Dashboard Admin OR external server/bot passing X-Anticheat-Secret
function requireAdminOrApiSecret(req, res, next) {
  const secretHeader = req.headers['x-anticheat-secret'];
  if (secretHeader && verifyLogSecret(secretHeader)) {
    req.admin = { username: 'API-Service' };
    return next();
  }
  return requireAdmin(req, res, next);
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------
router.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  const expectedUser = db.getSetting('admin_username', config.INITIAL_ADMIN_USERNAME);
  const salt = db.getSetting('admin_password_salt', '');
  const hash = db.getSetting('admin_password_hash', '');

  if (
    !username ||
    !password ||
    String(username).trim() !== expectedUser ||
    !db.verifyPassword(password, salt, hash)
  ) {
    return res.status(401).json({
      success: false,
      error: 'ឈ្មោះគណនី ឬលេខសម្ងាត់មិនត្រឹមត្រូវ (Invalid credentials)',
    });
  }

  const token = signToken(expectedUser);
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: TOKEN_TTL_MS,
    path: '/',
  });

  return res.json({
    success: true,
    token,
    admin: { username: expectedUser },
  });
});

router.post('/api/admin/logout', (_req, res) => {
  res.clearCookie(COOKIE_NAME, { path: '/' });
  return res.json({ success: true });
});

router.get('/api/admin/me', requireAdmin, (req, res) => {
  return res.json({ success: true, admin: req.admin });
});

// ---------------------------------------------------------------------------
// Dashboard Overview Stats
// ---------------------------------------------------------------------------
router.get('/api/admin/stats', requireAdmin, (_req, res) => {
  expireOutdatedBans();

  const totalReports = db.get(`SELECT COUNT(*) AS c FROM reports`)?.c || 0;
  const banReports = db.get(`SELECT COUNT(*) AS c FROM reports WHERE alert_type = 'BAN'`)?.c || 0;
  const warningReports = db.get(`SELECT COUNT(*) AS c FROM reports WHERE alert_type = 'WARNING'`)?.c || 0;
  const trackingReports = db.get(`SELECT COUNT(*) AS c FROM reports WHERE alert_type = 'TRACKING'`)?.c || 0;
  const activeBans = db.get(`SELECT COUNT(*) AS c FROM banned_hwids WHERE active = 1`)?.c || 0;
  const knownPlayers = db.get(`SELECT COUNT(*) AS c FROM players`)?.c || 0;
  const enabledDetections = db.get(`SELECT COUNT(*) AS c FROM banned_processes WHERE enabled = 1`)?.c || 0;
  const blockedAttempts = db.get(`SELECT COUNT(*) AS c FROM enforcement_logs`)?.c || 0;
  const reportsToday =
    db.get(`SELECT COUNT(*) AS c FROM reports WHERE date(created_at) = date('now')`)?.c || 0;

  const recentAlerts = db.all(
    `SELECT id, alert_type, summary, findings_count, critical_count,
            username, email, discord_id, hwid, computer_name, primary_screenshot, auto_banned, created_at
     FROM reports
     WHERE alert_type IN ('BAN', 'WARNING')
     ORDER BY id DESC
     LIMIT 8`
  );

  const recentBans = db.all(
    `SELECT * FROM banned_hwids WHERE active = 1 ORDER BY updated_at DESC LIMIT 6`
  );

  const dailySeries = db.all(
    `SELECT date(created_at) AS day,
            SUM(CASE WHEN alert_type = 'BAN' THEN 1 ELSE 0 END) AS bans,
            SUM(CASE WHEN alert_type = 'WARNING' THEN 1 ELSE 0 END) AS warnings,
            SUM(CASE WHEN alert_type = 'TRACKING' THEN 1 ELSE 0 END) AS tracking
     FROM reports
     WHERE datetime(created_at) >= datetime('now', '-7 days')
     GROUP BY date(created_at)
     ORDER BY day ASC`
  );

  return res.json({
    success: true,
    stats: {
      totalReports,
      banReports,
      warningReports,
      trackingReports,
      activeBans,
      knownPlayers,
      enabledDetections,
      blockedAttempts,
      reportsToday,
      autoBanEnabled: db.getSetting('auto_ban_on_critical', 'true') === 'true',
    },
    recentAlerts,
    recentBans,
    dailySeries,
  });
});

// ---------------------------------------------------------------------------
// Reports & Screenshots
// ---------------------------------------------------------------------------
router.get('/api/admin/reports', requireAdmin, (req, res) => {
  const page = Math.max(1, Number(req.query.page || 1));
  const limit = Math.min(100, Math.max(5, Number(req.query.limit || 20)));
  const offset = (page - 1) * limit;
  const type = String(req.query.type || '').toUpperCase();
  const search = String(req.query.search || '').trim();

  const where = [];
  const params = [];

  if (['BAN', 'WARNING', 'TRACKING'].includes(type)) {
    where.push(`r.alert_type = ?`);
    params.push(type);
  } else if (type === 'ALERTS') {
    where.push(`r.alert_type IN ('BAN', 'WARNING')`);
  }

  if (search) {
    where.push(
      `(r.username LIKE ? OR r.email LIKE ? OR r.hwid LIKE ? OR r.discord_id LIKE ? OR r.summary LIKE ? OR r.computer_name LIKE ?)`
    );
    const like = `%${search}%`;
    params.push(like, like, like, like, like, like);
  }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const total =
    db.get(`SELECT COUNT(*) AS c FROM reports r ${whereSql}`, params)?.c || 0;

  const items = db.all(
    `SELECT r.id, r.alert_type, r.summary, r.findings_count, r.critical_count,
            r.username, r.email, r.discord_id, r.steam_id, r.license, r.hwid, r.hwid_raw,
            r.motherboard, r.computer_name, r.windows_user, r.os_version, r.monitor_count,
            r.primary_screenshot, r.ip_address, r.auto_banned, r.created_at,
            CASE WHEN bh.active = 1 THEN 1 ELSE 0 END AS is_hwid_banned
     FROM reports r
     LEFT JOIN banned_hwids bh ON bh.hwid = r.hwid
     ${whereSql}
     ORDER BY r.id DESC
     LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );

  return res.json({
    success: true,
    total,
    page,
    limit,
    items,
  });
});

router.get('/api/admin/reports/:id', requireAdmin, (req, res) => {
  const row = db.get(
    `SELECT r.*,
            CASE WHEN bh.active = 1 THEN 1 ELSE 0 END AS is_hwid_banned,
            bh.reason AS active_ban_reason
     FROM reports r
     LEFT JOIN banned_hwids bh ON bh.hwid = r.hwid
     WHERE r.id = ?`,
    [Number(req.params.id)]
  );

  if (!row) {
    return res.status(404).json({ success: false, error: 'Report not found' });
  }

  let screenshots = [];
  let findings = [];
  let artifacts = {};
  let hwTokens = [];
  try { screenshots = JSON.parse(row.screenshots_json || '[]'); } catch {}
  try { findings = JSON.parse(row.findings_json || '[]'); } catch {}
  try { artifacts = JSON.parse(row.artifacts_json || '{}'); } catch {}
  try { hwTokens = JSON.parse(row.hw_tokens_json || '[]'); } catch {}

  return res.json({
    success: true,
    report: {
      ...row,
      screenshots,
      findings,
      artifacts,
      hw_tokens: hwTokens,
    },
  });
});

router.delete('/api/admin/reports/:id', requireAdmin, (req, res) => {
  const row = db.get(`SELECT id FROM reports WHERE id = ?`, [Number(req.params.id)]);
  if (!row) {
    return res.status(404).json({ success: false, error: 'Report not found' });
  }

  db.run(`DELETE FROM reports WHERE id = ?`, [row.id]);
  return res.json({ success: true });
});

router.post('/api/admin/reports/purge-tracking', requireAdmin, (_req, res) => {
  const info = db.run(`DELETE FROM reports WHERE alert_type = 'TRACKING'`);
  return res.json({ success: true, deleted: Number(info.changes || 0) });
});

// ---------------------------------------------------------------------------
// HWID Ban Management + NdevAnticheat.h documented routes
// ---------------------------------------------------------------------------
router.get('/api/admin/bans', requireAdmin, (req, res) => {
  expireOutdatedBans();
  const status = String(req.query.status || 'active');
  const search = String(req.query.search || '').trim();

  const where = [];
  const params = [];

  if (status === 'active') where.push(`active = 1`);
  else if (status === 'inactive') where.push(`active = 0`);

  if (search) {
    const like = `%${search}%`;
    where.push(`(hwid LIKE ? OR motherboard LIKE ? OR username LIKE ? OR email LIKE ? OR discord_id LIKE ? OR reason LIKE ?)`);
    params.push(like, like, like, like, like, like);
  }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const items = db
    .all(`SELECT * FROM banned_hwids ${whereSql} ORDER BY updated_at DESC LIMIT 500`, params)
    .map((b) => {
      let tokens = [];
      try { tokens = JSON.parse(b.hw_tokens_json || '[]'); } catch {}
      return { ...b, token_count: tokens.length, hw_tokens: tokens };
    });

  return res.json({ success: true, items });
});

function handleCreateBan(req, res) {
  try {
    const b = req.body || {};
    let hwTokens = b.hw_tokens || b.hwTokens || [];
    let motherboard = b.motherboard || null;

    // If banning from a specific report, pull all hardware tokens & motherboard from that report too
    if (b.report_id) {
      const rep = db.get(`SELECT motherboard, hw_tokens_json FROM reports WHERE id = ?`, [Number(b.report_id)]);
      if (rep) {
        if (!motherboard && rep.motherboard) motherboard = rep.motherboard;
        if ((!hwTokens || !hwTokens.length) && rep.hw_tokens_json) {
          try { hwTokens = JSON.parse(rep.hw_tokens_json); } catch {}
        }
      }
    }

    const record = banHwid({
      hwid: b.hwid,
      hwidRaw: b.hwid_raw || b.hwidRaw || null,
      hwTokens,
      motherboard,
      username: b.username || null,
      email: b.email || null,
      discordId: b.discord_id || b.discordId || null,
      license: b.license || null,
      reason: b.reason || 'Motherboard / HWID banned by an administrator',
      bannedBy: req.admin?.username || b.banned_by || 'Admin',
      source: b.source || 'manual',
      reportId: b.report_id ? Number(b.report_id) : null,
      durationHours: b.duration_hours || b.durationHours || null,
    });
    return res.json({ success: true, ban: record });
  } catch (err) {
    return res.status(err.statusCode || 500).json({ success: false, error: err.message });
  }
}

router.post('/api/admin/bans', requireAdmin, handleCreateBan);
router.post('/api/hwid/anticheat/ban', requireAdminOrApiSecret, handleCreateBan);

router.post('/api/hwid/admin/ban-hwid-by-email', requireAdminOrApiSecret, (req, res) => {
  try {
    const { email, reason, duration_hours, durationHours } = req.body || {};
    const records = banHwidsByEmail({
      email,
      reason,
      bannedBy: req.admin?.username || 'Admin',
      durationHours: duration_hours || durationHours || null,
    });
    return res.json({
      success: true,
      count: records.length,
      bans: records,
    });
  } catch (err) {
    return res.status(err.statusCode || 500).json({ success: false, error: err.message });
  }
});

function handleUnban(req, res) {
  const hwid = req.params.hwid || req.body?.hwid || '';
  const updated = unbanHwid(hwid);
  if (!updated) {
    return res.status(404).json({ success: false, error: 'HWID ban not found' });
  }
  return res.json({ success: true, ban: updated });
}

router.delete('/api/admin/bans/:hwid', requireAdmin, handleUnban);
router.post('/api/hwid/admin/unban-hwid', requireAdminOrApiSecret, handleUnban);

// ---------------------------------------------------------------------------
// Players Directory & Remote Force-Quit Command
// ---------------------------------------------------------------------------
router.get('/api/admin/players', requireAdmin, (req, res) => {
  const search = String(req.query.search || '').trim();
  const params = [];
  let whereSql = '';

  if (search) {
    const like = `%${search}%`;
    whereSql = `WHERE p.username LIKE ? OR p.email LIKE ? OR p.hwid LIKE ? OR p.discord_id LIKE ? OR p.steam_id LIKE ? OR p.computer_name LIKE ?`;
    params.push(like, like, like, like, like, like);
  }

  const items = db.all(
    `SELECT p.*,
            CASE WHEN bh.active = 1 THEN 1 ELSE 0 END AS is_banned,
            bh.reason AS ban_reason,
            CASE WHEN datetime(p.last_seen_at) >= datetime('now', '-25 seconds') THEN 1 ELSE 0 END AS is_online,
            (SELECT COUNT(*) FROM client_commands cc WHERE cc.hwid = p.hwid AND cc.status = 'pending') AS pending_quit
     FROM players p
     LEFT JOIN banned_hwids bh ON bh.hwid = p.hwid
     ${whereSql}
     ORDER BY is_online DESC, p.last_seen_at DESC
     LIMIT 300`,
    params
  );

  return res.json({ success: true, items });
});

router.post('/api/admin/players/force-quit', requireAdminOrApiSecret, (req, res) => {
  const hwid = String(req.body?.hwid || '').trim().toLowerCase();
  const reason = String(req.body?.reason || 'Admin remote close game').trim();

  if (!/^[0-9a-f]{32,64}$/.test(hwid)) {
    return res.status(400).json({ success: false, error: 'លេខកូដ HWID មិនត្រឹមត្រូវ (Invalid HWID)' });
  }

  // Clear duplicate pending commands for this HWID so only one fires
  db.run(
    `UPDATE client_commands SET status = 'superseded' WHERE hwid = ? AND status = 'pending'`,
    [hwid]
  );

  const info = db.run(
    `INSERT INTO client_commands (hwid, command, reason, issued_by, status, created_at)
     VALUES (?, 'force_quit', ?, ?, 'pending', datetime('now'))`,
    [hwid, reason, req.admin?.username || 'Admin']
  );

  const player = db.get(
    `SELECT username, CASE WHEN datetime(last_seen_at) >= datetime('now', '-25 seconds') THEN 1 ELSE 0 END AS is_online
     FROM players WHERE hwid = ?`,
    [hwid]
  );

  return res.json({
    success: true,
    commandId: Number(info.lastInsertRowid),
    hwid,
    isOnline: Boolean(player?.is_online),
    username: player?.username || null,
  });
});

// ---------------------------------------------------------------------------
// Dynamic Banned Processes List (/api/anticheat/detections management)
// ---------------------------------------------------------------------------
router.get('/api/admin/detections', requireAdmin, (req, res) => {
  const search = String(req.query.search || '').trim();
  const params = [];
  let whereSql = '';
  if (search) {
    const like = `%${search}%`;
    whereSql = `WHERE exe_name LIKE ? OR display_name LIKE ? OR category LIKE ?`;
    params.push(like, like, like);
  }

  const items = db.all(
    `SELECT * FROM banned_processes ${whereSql} ORDER BY enabled DESC, display_name ASC, exe_name ASC`,
    params
  );
  return res.json({ success: true, items });
});

router.post('/api/admin/detections', requireAdmin, (req, res) => {
  const exeName = String(req.body?.exe_name || '').trim().toLowerCase();
  const displayName = String(req.body?.display_name || '').trim();
  const category = String(req.body?.category || 'Custom Cheat').trim();

  if (!exeName || !displayName) {
    return res.status(400).json({ success: false, error: 'exe_name and display_name are required' });
  }

  db.run(
    `INSERT INTO banned_processes (exe_name, display_name, category, enabled, is_builtin, created_at)
     VALUES (?, ?, ?, 1, 0, datetime('now'))
     ON CONFLICT(exe_name) DO UPDATE SET
       display_name = excluded.display_name,
       category = excluded.category,
       enabled = 1`,
    [exeName, displayName, category]
  );

  const item = db.get(`SELECT * FROM banned_processes WHERE exe_name = ?`, [exeName]);
  return res.json({ success: true, item });
});

router.patch('/api/admin/detections/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const existing = db.get(`SELECT * FROM banned_processes WHERE id = ?`, [id]);
  if (!existing) {
    return res.status(404).json({ success: false, error: 'Detection rule not found' });
  }

  const enabled =
    req.body?.enabled !== undefined ? (req.body.enabled ? 1 : 0) : existing.enabled;
  const displayName =
    req.body?.display_name !== undefined ? String(req.body.display_name).trim() : existing.display_name;
  const category =
    req.body?.category !== undefined ? String(req.body.category).trim() : existing.category;

  db.run(
    `UPDATE banned_processes SET enabled = ?, display_name = ?, category = ? WHERE id = ?`,
    [enabled, displayName, category, id]
  );

  return res.json({
    success: true,
    item: db.get(`SELECT * FROM banned_processes WHERE id = ?`, [id]),
  });
});

router.delete('/api/admin/detections/:id', requireAdmin, (req, res) => {
  db.run(`DELETE FROM banned_processes WHERE id = ?`, [Number(req.params.id)]);
  return res.json({ success: true });
});

router.post('/api/admin/detections/reset-defaults', requireAdmin, (_req, res) => {
  for (const proc of DEFAULT_BANNED_PROCESSES) {
    db.run(
      `INSERT INTO banned_processes (exe_name, display_name, category, enabled, is_builtin)
       VALUES (?, ?, ?, 1, 1)
       ON CONFLICT(exe_name) DO UPDATE SET enabled = 1, display_name = excluded.display_name`,
      [proc.exe_name.toLowerCase(), proc.display_name, proc.category]
    );
  }
  return res.json({ success: true });
});

// ---------------------------------------------------------------------------
// Enforcement Logs (from NdevAnticheat.cpp /api/anticheat/logs)
// ---------------------------------------------------------------------------
router.get('/api/admin/logs', requireAdmin, (_req, res) => {
  const items = db.all(
    `SELECT * FROM enforcement_logs ORDER BY id DESC LIMIT 200`
  );
  return res.json({ success: true, items });
});

// ---------------------------------------------------------------------------
// Settings & Webhooks
// ---------------------------------------------------------------------------
router.get('/api/admin/settings', requireAdmin, (_req, res) => {
  const map = db.getAllSettingsMap();
  return res.json({
    success: true,
    settings: {
      admin_username: map.admin_username || 'admin',
      scanner_pin: map.scanner_pin || '',
      anticheat_log_secret: map.anticheat_log_secret || '',
      auto_ban_on_critical: map.auto_ban_on_critical === 'true',
      discord_webhook_ban: map.discord_webhook_ban || '',
      discord_webhook_warning: map.discord_webhook_warning || '',
      discord_webhook_tracking: map.discord_webhook_tracking || '',
      discord_webhook_logs: map.discord_webhook_logs || '',
    },
  });
});

router.put('/api/admin/settings', requireAdmin, (req, res) => {
  const b = req.body || {};
  const allowedKeys = [
    'scanner_pin',
    'anticheat_log_secret',
    'discord_webhook_ban',
    'discord_webhook_warning',
    'discord_webhook_tracking',
    'discord_webhook_logs',
  ];

  for (const k of allowedKeys) {
    if (b[k] !== undefined) {
      db.setSetting(k, String(b[k]).trim());
    }
  }

  if (b.auto_ban_on_critical !== undefined) {
    db.setSetting('auto_ban_on_critical', b.auto_ban_on_critical ? 'true' : 'false');
  }

  return res.json({ success: true });
});

router.post('/api/admin/settings/password', requireAdmin, (req, res) => {
  const { current_password, new_username, new_password } = req.body || {};
  const salt = db.getSetting('admin_password_salt', '');
  const hash = db.getSetting('admin_password_hash', '');

  if (!db.verifyPassword(current_password || '', salt, hash)) {
    return res.status(400).json({ success: false, error: 'លេខសម្ងាត់បច្ចុប្បន្នមិនត្រឹមត្រូវ' });
  }

  if (new_username && String(new_username).trim().length >= 3) {
    db.setSetting('admin_username', String(new_username).trim());
  }

  if (new_password) {
    if (String(new_password).length < 6) {
      return res.status(400).json({ success: false, error: 'លេខសម្ងាត់ថ្មីត្រូវមានយ៉ាងតិច ៦ តួអក្សរ' });
    }
    const next = db.hashPassword(new_password);
    db.setSetting('admin_password_salt', next.salt);
    db.setSetting('admin_password_hash', next.hash);
  }

  return res.json({ success: true });
});

router.post('/api/admin/settings/test-webhook', requireAdmin, async (req, res) => {
  const url = String(req.body?.url || '').trim();
  if (!url.startsWith('http')) {
    return res.status(400).json({ success: false, error: 'Invalid Discord Webhook URL' });
  }
  const ok = await sendTestWebhook(url);
  if (!ok) {
    return res.status(502).json({ success: false, error: 'Discord rejected the webhook request' });
  }
  return res.json({ success: true });
});

module.exports = router;
