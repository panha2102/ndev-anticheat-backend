'use strict';

const express = require('express');
const db = require('../db');
const { verifyScannerPin, verifyLogSecret } = require('../middleware/auth');
const {
  isValidHexHwid,
  deriveSha256HwidFromGuid,
  normalizeHwTokens,
  checkHwidBan,
  banHwid,
} = require('../services/banService');
const {
  sendReportWebhook,
  sendEnforcementLogWebhook,
} = require('../services/discord');

const router = express.Router();

// Tracks active client sessions so legacy periodic TRACKING pings (every 5s-60s)
// are ignored after the initial game-launch snapshot, until the game closes (>90s idle).
const LEGACY_TRACKING_SESSION_TTL_MS = 90 * 1000;
const activeTrackingSessions = new Map();

function shouldSkipPeriodicTracking(sessionKey, isExplicitSessionStart) {
  const now = Date.now();

  if (activeTrackingSessions.size > 2000) {
    for (const [k, ts] of activeTrackingSessions) {
      if (now - ts > LEGACY_TRACKING_SESSION_TTL_MS * 2) {
        activeTrackingSessions.delete(k);
      }
    }
  }

  const prev = activeTrackingSessions.get(sessionKey) || 0;
  activeTrackingSessions.set(sessionKey, now);

  if (isExplicitSessionStart) {
    return false;
  }

  return prev > 0 && now - prev < LEGACY_TRACKING_SESSION_TTL_MS;
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

// Decodes Base64 JPEG into an in-memory Buffer ONLY (never written to local disk).
function decodeBase64JpegToMemory(b64) {
  if (!b64 || typeof b64 !== 'string') return null;
  const stripped = b64.replace(/^data:image\/[a-zA-Z0-9+.-]+;base64,/, '').trim();
  if (stripped.length < 32) return null;
  try {
    const buf = Buffer.from(stripped, 'base64');
    return buf.length >= 16 ? buf : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 1. GET /api/anticheat/detections
//    Consumed by Scanner::FetchDetectionList() in ScreenshotCapture.cpp
// ---------------------------------------------------------------------------
router.get('/api/anticheat/detections', (_req, res) => {
  const rows = db.all(
    `SELECT exe_name, display_name FROM banned_processes WHERE enabled = 1 ORDER BY exe_name ASC`
  );
  const bannedProcesses = {};
  for (const row of rows) {
    bannedProcesses[row.exe_name.toLowerCase()] = row.display_name;
  }
  return res.json({
    success: true,
    count: rows.length,
    bannedProcesses,
  });
});

// ---------------------------------------------------------------------------
// 2. POST /submit  (and alias /api/anticheat/submit)
//    Consumed by Scanner::SubmitResults() in Scanner.cpp
//    Screenshots are decoded in RAM only and forwarded directly to Discord!
// ---------------------------------------------------------------------------
async function handleScannerSubmit(req, res) {
  const body = req.body || {};

  if (!verifyScannerPin(body.pin)) {
    return res.status(403).json({ success: false, error: 'Invalid scanner PIN' });
  }

  const rawType = String(body.type || 'WARNING').toUpperCase();
  const alertType = ['BAN', 'WARNING', 'TRACKING'].includes(rawType) ? rawType : 'WARNING';

  const findings = Array.isArray(body.findings) ? body.findings : [];
  const artifacts = body.artifacts && typeof body.artifacts === 'object' ? body.artifacts : {};
  const sysInfo = artifacts.SYSTEM_INFO && typeof artifacts.SYSTEM_INFO === 'object' ? artifacts.SYSTEM_INFO : {};
  const identities = artifacts.IDENTITIES && typeof artifacts.IDENTITIES === 'object' ? artifacts.IDENTITIES : {};

  let username = identities.username || null;
  let email = identities.email || null;
  let discordId =
    identities.discord_id && identities.discord_id !== 'N/A' ? String(identities.discord_id) : null;
  let steamId = identities.steam_id_active ? String(identities.steam_id_active) : null;
  let license = identities.license || null;
  let motherboard = identities.motherboard ? String(identities.motherboard).trim() : null;
  let hwTokens = normalizeHwTokens(identities.hw_tokens || identities.hwid_tokens || []);

  let rawGuid = identities.hwid_raw || null;
  let hexHwid = '';

  if (identities.hwid) {
    const candidate = String(identities.hwid).trim();
    if (isValidHexHwid(candidate)) {
      hexHwid = candidate.toLowerCase();
    } else {
      rawGuid = rawGuid || candidate;
      hexHwid = deriveSha256HwidFromGuid(candidate);
    }
  } else if (rawGuid) {
    hexHwid = deriveSha256HwidFromGuid(rawGuid);
  }

  let computerName = sysInfo.computer_name || null;
  let windowsUser = sysInfo.user_name || null;
  let osVersion = sysInfo.os_version
    ? `${sysInfo.os_version}${sysInfo.os_build ? ` (Build ${sysInfo.os_build})` : ''}`
    : null;

  const monitorCount = Number(body.monitorCount || 0);
  const ipAddress = getClientIp(req);

  // Enrich missing identity/hardware fields from known `players` profile (e.g. if a critical
  // BAN fired at second 0 before the player signed into the launcher UI on this run, or if
  // anticheat_identity.json was deleted on disk while `/api/hwid/check-hwid` already saw them).
  let knownPlayer = hexHwid
    ? db.get(`SELECT * FROM players WHERE hwid = ?`, [hexHwid])
    : null;

  if (!knownPlayer && !hexHwid && ipAddress && ipAddress !== 'unknown') {
    const recentSameIp = db.all(
      `SELECT * FROM players
       WHERE last_ip = ? AND datetime(last_seen_at) >= datetime('now', '-60 seconds')
       ORDER BY last_seen_at DESC LIMIT 2`,
      [ipAddress]
    );
    // Only attribute by IP when there is a single unambiguous active client on that IP
    if (recentSameIp.length === 1) {
      knownPlayer = recentSameIp[0];
      hexHwid = knownPlayer.hwid;
    }
  }

  if (knownPlayer) {
    username = username || knownPlayer.username || null;
    email = email || knownPlayer.email || null;
    discordId = discordId || knownPlayer.discord_id || null;
    steamId = steamId || knownPlayer.steam_id || null;
    license = license || knownPlayer.license || null;
    motherboard = motherboard || knownPlayer.motherboard || null;
    rawGuid = rawGuid || knownPlayer.hwid_raw || null;
    computerName = computerName || knownPlayer.computer_name || null;
    windowsUser = windowsUser || knownPlayer.windows_user || null;
    osVersion = osVersion || knownPlayer.os_version || null;
    if (!hwTokens.length && knownPlayer.hw_tokens_json) {
      try {
        hwTokens = normalizeHwTokens(JSON.parse(knownPlayer.hw_tokens_json));
      } catch {}
    }
  }

  username = username || windowsUser || null;

  const skipPeriodicTracking =
    alertType === 'TRACKING' &&
    shouldSkipPeriodicTracking(
      hexHwid || rawGuid || ipAddress,
      body.session_start === true
    );

  // Decode ALL screenshots in RAM ONLY for BAN/WARNING detections (composite + every connected monitor).
  const imageBuffers = [];
  if (alertType !== 'TRACKING') {
    if (body.screenshot) {
      const mainBuf = decodeBase64JpegToMemory(body.screenshot);
      if (mainBuf) {
        imageBuffers.push({ filename: 'evidence.jpg', buffer: mainBuf });
      }
    }
    if (Array.isArray(body.screenshots)) {
      // Avoid sending a redundant duplicate file when the user only has 1 monitor
      // (since `evidence.jpg` is already the full capture of that single screen).
      const skipSingleDuplicate =
        body.screenshots.length === 1 &&
        imageBuffers.length === 1 &&
        body.screenshots[0] === body.screenshot;

      if (!skipSingleDuplicate) {
        for (let i = 0; i < body.screenshots.length && i < 16; i++) {
          const monBuf = decodeBase64JpegToMemory(body.screenshots[i]);
          if (monBuf) {
            imageBuffers.push({ filename: `monitor_${i + 1}.jpg`, buffer: monBuf });
          }
        }
      }
    }
  }

  const criticalCount = findings.filter(
    (f) => String(f?.severity || '').toLowerCase() === 'critical'
  ).length;

  const summary =
    findings.length > 0
      ? findings
          .slice(0, 3)
          .map((f) => `${f.name || 'Detection'}${f.path ? ` (${f.path})` : ''}`)
          .join(' • ')
      : 'Game launch tracking snapshot';

  // Upsert player directory if we have a valid HWID
  if (hexHwid) {
    const reportIncrement = skipPeriodicTracking ? 0 : 1;
    db.run(
      `INSERT INTO players (
         hwid, hwid_raw, motherboard, hw_tokens_json,
         username, email, discord_id, steam_id, license,
         computer_name, windows_user, os_version, last_ip,
         report_count, ban_report_count, first_seen_at, last_seen_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
       ON CONFLICT(hwid) DO UPDATE SET
         hwid_raw = COALESCE(excluded.hwid_raw, players.hwid_raw),
         motherboard = COALESCE(excluded.motherboard, players.motherboard),
         hw_tokens_json = CASE WHEN excluded.hw_tokens_json != '[]' THEN excluded.hw_tokens_json ELSE players.hw_tokens_json END,
         username = COALESCE(excluded.username, players.username),
         email = COALESCE(excluded.email, players.email),
         discord_id = COALESCE(excluded.discord_id, players.discord_id),
         steam_id = COALESCE(excluded.steam_id, players.steam_id),
         license = COALESCE(excluded.license, players.license),
         computer_name = COALESCE(excluded.computer_name, players.computer_name),
         windows_user = COALESCE(excluded.windows_user, players.windows_user),
         os_version = COALESCE(excluded.os_version, players.os_version),
         last_ip = excluded.last_ip,
         report_count = players.report_count + excluded.report_count,
         ban_report_count = players.ban_report_count + excluded.ban_report_count,
         last_seen_at = datetime('now')`,
      [
        hexHwid,
        rawGuid,
        motherboard,
        JSON.stringify(hwTokens),
        username,
        email,
        discordId,
        steamId,
        license,
        computerName,
        windowsUser,
        osVersion,
        ipAddress,
        reportIncrement,
        alertType === 'BAN' ? 1 : 0,
      ]
    );
  }

  if (skipPeriodicTracking) {
    return res.json({
      success: true,
      reportId: null,
      alertType,
      autoBanned: false,
      skippedPeriodic: true,
    });
  }

  const insertResult = db.run(
    `INSERT INTO reports (
       alert_type, summary, findings_count, critical_count,
       username, email, discord_id, steam_id, license, hwid, hwid_raw,
       motherboard, hw_tokens_json,
       computer_name, windows_user, os_version, monitor_count,
       primary_screenshot, screenshots_json, findings_json, artifacts_json,
       ip_address, auto_banned, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '[]', ?, ?, ?, 0, datetime('now'))`,
    [
      alertType,
      summary,
      findings.length,
      criticalCount,
      username,
      email,
      discordId,
      steamId,
      license,
      hexHwid || null,
      rawGuid,
      motherboard,
      JSON.stringify(hwTokens),
      computerName,
      windowsUser,
      osVersion,
      monitorCount,
      JSON.stringify(findings),
      JSON.stringify(artifacts),
      ipAddress,
    ]
  );

  const reportId = Number(insertResult.lastInsertRowid);

  // Auto-ban Motherboard + Multi-Tokens when alertType === 'BAN' and auto_ban_on_critical is enabled
  let autoBanned = false;
  const autoBanEnabled = db.getSetting('auto_ban_on_critical', 'true') === 'true';

  if (alertType === 'BAN' && autoBanEnabled && hexHwid && isValidHexHwid(hexHwid)) {
    try {
      const topFinding = findings[0];
      const autoReason = topFinding
        ? `Auto-Ban: ${topFinding.name || 'Critical Cheat'}${topFinding.path ? ` [${topFinding.path}]` : ''}`
        : 'Auto-Ban: Critical anti-cheat violation';

      banHwid({
        hwid: hexHwid,
        hwidRaw: rawGuid,
        hwTokens,
        motherboard,
        username,
        email,
        discordId,
        license,
        reason: autoReason,
        bannedBy: 'Auto-Ban (Scanner)',
        source: 'auto_ban',
        reportId,
      });

      db.run(`UPDATE reports SET auto_banned = 1 WHERE id = ?`, [reportId]);
      autoBanned = true;
    } catch (err) {
      console.error('[AutoBan] Failed to auto-ban HWID:', err.message);
    }
  }

  const savedReport = db.get(`SELECT * FROM reports WHERE id = ?`, [reportId]);

  // Forward RAM image buffers straight to Discord Webhook (0 local disk usage).
  // If Discord returns CDN URLs for the uploaded images, store ONLY those Discord URLs in SQLite!
  setImmediate(async () => {
    try {
      const discordUrls = await sendReportWebhook({
        report: savedReport,
        findings,
        imageBuffers,
        autoBanned,
      });
      if (Array.isArray(discordUrls) && discordUrls.length > 0) {
        db.run(
          `UPDATE reports SET primary_screenshot = ?, screenshots_json = ? WHERE id = ?`,
          [discordUrls[0], JSON.stringify(discordUrls), reportId]
        );
      }
    } catch {}
  });

  return res.json({
    success: true,
    reportId,
    alertType,
    autoBanned,
  });
}

router.post('/submit', handleScannerSubmit);
router.post('/api/anticheat/submit', handleScannerSubmit);

// ---------------------------------------------------------------------------
// 3. POST /api/hwid/check-hwid  (& /api/hwid/check-hwid-detailed)
//    Consumed by NdevAnticheat.cpp::CheckHwidBan() every 5s
// ---------------------------------------------------------------------------
function handleCheckHwid(req, res) {
  const b = req.body || {};
  const candidate = String(b.hwid || req.headers['x-hwid'] || '').trim().toLowerCase();
  const hwTokens = normalizeHwTokens(b.hw_tokens || b.hwid_tokens || []);
  const motherboard = b.motherboard ? String(b.motherboard).trim() : null;
  const ipAddress = getClientIp(req);

  // Update live player heartbeat & online presence whenever a valid HWID checks in
  if (isValidHexHwid(candidate)) {
    const pUser = b.username ? String(b.username).trim() : null;
    const pEmail = b.email ? String(b.email).trim() : null;
    const pDiscord = b.discord_id ? String(b.discord_id).trim() : null;
    const pLicense = b.license ? String(b.license).trim() : null;
    const pComp = b.computer_name ? String(b.computer_name).trim() : null;

    db.run(
      `INSERT INTO players (
         hwid, motherboard, hw_tokens_json, username, email, discord_id, license,
         computer_name, last_ip, report_count, ban_report_count, first_seen_at, last_seen_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, datetime('now'), datetime('now'))
       ON CONFLICT(hwid) DO UPDATE SET
         motherboard = COALESCE(excluded.motherboard, players.motherboard),
         hw_tokens_json = CASE WHEN excluded.hw_tokens_json != '[]' THEN excluded.hw_tokens_json ELSE players.hw_tokens_json END,
         username = COALESCE(excluded.username, players.username),
         email = COALESCE(excluded.email, players.email),
         discord_id = COALESCE(excluded.discord_id, players.discord_id),
         license = COALESCE(excluded.license, players.license),
         computer_name = COALESCE(excluded.computer_name, players.computer_name),
         last_ip = excluded.last_ip,
         last_seen_at = datetime('now')`,
      [
        candidate,
        motherboard,
        JSON.stringify(hwTokens),
        pUser,
        pEmail,
        pDiscord,
        pLicense,
        pComp,
        ipAddress,
      ]
    );
  }

  // 1. Check active Motherboard / HWID Ban
  const result = checkHwidBan(candidate, hwTokens, motherboard);
  if (result.isBanned) {
    return res.json({
      success: true,
      isBanned: true,
      banned: true,
      reason: result.reason,
      matchedBy: result.matchedBy || 'master_hwid',
      expiresAt: result.ban?.expires_at || null,
    });
  }

  // 2. Check pending one-shot Remote Close Game command (valid for 10 minutes)
  if (isValidHexHwid(candidate)) {
    db.run(
      `UPDATE client_commands
       SET status = 'expired'
       WHERE status = 'pending' AND datetime(created_at) <= datetime('now', '-10 minutes')`
    );

    const pendingCmd = db.get(
      `SELECT * FROM client_commands
       WHERE hwid = ? AND status = 'pending' AND command = 'force_quit'
       ORDER BY id ASC LIMIT 1`,
      [candidate]
    );

    if (pendingCmd) {
      db.run(
        `UPDATE client_commands
         SET status = 'executed', executed_at = datetime('now')
         WHERE hwid = ? AND status = 'pending' AND command = 'force_quit'`,
        [candidate]
      );

      return res.json({
        success: true,
        isBanned: false,
        banned: false,
        forceQuit: true,
        reason: pendingCmd.reason || 'Closed remotely by administrator',
      });
    }
  }

  return res.json({
    success: true,
    isBanned: false,
    banned: false,
    forceQuit: false,
  });
}

router.post('/api/hwid/check-hwid', handleCheckHwid);
router.post('/api/hwid/check-hwid-detailed', handleCheckHwid);

// ---------------------------------------------------------------------------
// 4. POST /api/anticheat/logs
//    Consumed by NdevAnticheat.cpp::SendAntiCheatLog() when FailClosed runs
// ---------------------------------------------------------------------------
router.post('/api/anticheat/logs', (req, res) => {
  const secret = req.headers['x-anticheat-secret'] || '';
  if (!verifyLogSecret(secret)) {
    return res.status(403).json({ success: false, error: 'Invalid X-Anticheat-Secret' });
  }

  const body = req.body || {};
  const ipAddress = getClientIp(req);

  const insertResult = db.run(
    `INSERT INTO enforcement_logs (
       event_type, severity, reason, process_id,
       username, email, discord_id, hwid, license, meta_json, ip_address, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
    [
      body.event_type || 'unknown',
      body.severity || 'info',
      body.reason || null,
      body.process_id ? Number(body.process_id) : null,
      body.username || null,
      body.email || null,
      body.discord_id || null,
      body.hwid ? String(body.hwid).toLowerCase() : null,
      body.license || null,
      JSON.stringify(body.meta || {}),
      ipAddress,
    ]
  );

  const logEntry = db.get(`SELECT * FROM enforcement_logs WHERE id = ?`, [
    Number(insertResult.lastInsertRowid),
  ]);

  setImmediate(() => {
    sendEnforcementLogWebhook(logEntry).catch(() => {});
  });

  return res.json({ success: true, id: logEntry.id });
});

module.exports = router;
