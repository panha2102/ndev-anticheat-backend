'use strict';

const crypto = require('node:crypto');
const db = require('../db');

function normalizeHwid(raw) {
  if (!raw || typeof raw !== 'string') return '';
  return raw.trim().toLowerCase();
}

function isValidHexHwid(hwid) {
  const h = normalizeHwid(hwid);
  return /^[0-9a-f]{32,64}$/.test(h);
}

// Mirrors ConnectToNative.cpp: sha256(lowercase MachineGuid without dashes) -> 64 lowercase hex chars
function deriveSha256HwidFromGuid(rawGuid) {
  if (!rawGuid || typeof rawGuid !== 'string') return '';
  const stripped = rawGuid.replace(/[{}-\s]/g, '').trim().toLowerCase();
  if (!stripped) return '';
  if (/^[0-9a-f]{64}$/.test(stripped)) {
    return stripped;
  }
  return crypto.createHash('sha256').update(stripped, 'utf8').digest('hex');
}

// Validates & normalizes typed hardware tokens: e.g. "mb_uuid:<64hex>", "tpm_ek:<64hex>", "disk:<64hex>"
function normalizeHwTokens(tokensInput) {
  let list = [];
  if (Array.isArray(tokensInput)) {
    list = tokensInput;
  } else if (typeof tokensInput === 'string' && tokensInput.trim().startsWith('[')) {
    try { list = JSON.parse(tokensInput); } catch {}
  }

  const out = [];
  const seen = new Set();
  for (const raw of list) {
    if (typeof raw !== 'string') continue;
    const t = raw.trim().toLowerCase();
    // Accept "<prefix>:<32..64 hex>" (e.g. mb_uuid:..., mb_serial:..., tpm_ek:..., disk:..., mac:..., guid:...)
    if (!/^[a-z0-9_]{1,20}:[0-9a-f]{32,64}$/.test(t)) continue;
    if (!seen.has(t)) {
      seen.add(t);
      out.push(t);
    }
  }
  return out;
}

function extractTokenType(token) {
  const idx = token.indexOf(':');
  return idx > 0 ? token.slice(0, idx) : 'hw';
}

function attachTokensToBan(banId, tokens) {
  const cleanTokens = normalizeHwTokens(tokens);
  if (!banId || cleanTokens.length === 0) return [];

  for (const token of cleanTokens) {
    db.run(
      `INSERT INTO banned_hw_tokens (ban_id, token, token_type, created_at)
       VALUES (?, ?, ?, datetime('now'))
       ON CONFLICT(ban_id, token) DO NOTHING`,
      [banId, token, extractTokenType(token)]
    );
  }

  const allForBan = db
    .all(`SELECT token FROM banned_hw_tokens WHERE ban_id = ? ORDER BY id ASC`, [banId])
    .map((r) => r.token);

  db.run(
    `UPDATE banned_hwids SET hw_tokens_json = ? WHERE id = ?`,
    [JSON.stringify(allForBan), banId]
  );

  return allForBan;
}

function expireOutdatedBans() {
  db.run(
    `UPDATE banned_hwids
     SET active = 0, updated_at = datetime('now')
     WHERE active = 1 AND expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')`
  );
}

// Vanguard-style multi-layer check:
//   1. Checks primary master HWID
//   2. Checks every individual hardware token (mb_uuid, mb_serial, tpm_ek, chassis, disk, mac, guid)
//   3. Auto-links newly observed tokens/HWID when a partial hardware match occurs (defeats OS reinstall / SSD swap)!
function checkHwidBan(rawHwid, rawHwTokens = [], motherboard = null) {
  const hwid = normalizeHwid(rawHwid);
  const hwTokens = normalizeHwTokens(rawHwTokens);

  if (!isValidHexHwid(hwid) && hwTokens.length === 0) {
    return { isBanned: false, reason: null, matchedBy: null, ban: null };
  }

  expireOutdatedBans();

  let ban = null;
  let matchedBy = null;

  // 1. Direct primary HWID check
  if (isValidHexHwid(hwid)) {
    ban = db.get(
      `SELECT * FROM banned_hwids WHERE hwid = ? AND active = 1 LIMIT 1`,
      [hwid]
    );
    if (ban) {
      matchedBy = 'master_hwid';
    }
  }

  // 2. Multi-component token check (SMBIOS UUID, Board Serial, TPM EK, Disk Serial, Permanent MAC, GUID)
  if (!ban && hwTokens.length > 0) {
    const placeholders = hwTokens.map(() => '?').join(', ');
    const tokenMatch = db.get(
      `SELECT bh.*, bht.token AS matched_token, bht.token_type AS matched_type
       FROM banned_hw_tokens bht
       INNER JOIN banned_hwids bh ON bh.id = bht.ban_id
       WHERE bh.active = 1 AND bht.token IN (${placeholders})
       ORDER BY
         CASE bht.token_type
           WHEN 'tpm_ek' THEN 1
           WHEN 'mb_serial' THEN 2
           WHEN 'mb_uuid' THEN 3
           WHEN 'chassis' THEN 4
           WHEN 'disk' THEN 5
           WHEN 'mac' THEN 6
           ELSE 7
         END ASC
       LIMIT 1`,
      hwTokens
    );

    if (tokenMatch) {
      ban = tokenMatch;
      matchedBy = tokenMatch.matched_token;
    }
  }

  if (!ban) {
    return { isBanned: false, reason: null, matchedBy: null, ban: null };
  }

  // 3. Vanguard Auto-Link Ban Evasion:
  // Bind any newly swapped hardware tokens (e.g. new SSD or fresh Windows MachineGuid)
  // onto the matched active ban record so future attempts are caught even faster!
  if (hwTokens.length > 0) {
    attachTokensToBan(ban.id, hwTokens);
  }

  db.run(
    `UPDATE banned_hwids
     SET hit_count = hit_count + 1,
         last_blocked_at = datetime('now'),
         last_matched_token = ?,
         motherboard = COALESCE(?, banned_hwids.motherboard)
     WHERE id = ?`,
    [matchedBy, motherboard || null, ban.id]
  );

  return {
    isBanned: true,
    reason: ban.reason || 'Motherboard / Hardware banned by an administrator',
    matchedBy,
    ban,
  };
}

function banHwid({
  hwid,
  hwidRaw = null,
  hwTokens = [],
  motherboard = null,
  username = null,
  email = null,
  discordId = null,
  license = null,
  reason = 'Motherboard / HWID banned by an administrator',
  bannedBy = 'Admin',
  source = 'manual',
  reportId = null,
  durationHours = null,
}) {
  let normalized = normalizeHwid(hwid);
  if (!isValidHexHwid(normalized) && hwidRaw) {
    normalized = deriveSha256HwidFromGuid(hwidRaw);
  }
  if (!isValidHexHwid(normalized)) {
    const err = new Error('Invalid HWID format (expected 32-64 hex characters)');
    err.statusCode = 400;
    throw err;
  }

  // Enrich missing identity & hardware tokens from players table if known
  const knownPlayer = db.get(`SELECT * FROM players WHERE hwid = ?`, [normalized]);
  const finalUsername = username || knownPlayer?.username || null;
  const finalEmail = email || knownPlayer?.email || null;
  const finalDiscord = discordId || knownPlayer?.discord_id || null;
  const finalLicense = license || knownPlayer?.license || null;
  const finalHwidRaw = hwidRaw || knownPlayer?.hwid_raw || null;
  const finalMotherboard = motherboard || knownPlayer?.motherboard || null;

  const mergedTokens = [
    ...normalizeHwTokens(hwTokens),
    ...normalizeHwTokens(knownPlayer?.hw_tokens_json || '[]'),
  ];

  let expiresAt = null;
  if (durationHours && Number(durationHours) > 0) {
    const d = new Date(Date.now() + Number(durationHours) * 3600 * 1000);
    expiresAt = d.toISOString().replace('T', ' ').slice(0, 19);
  }

  db.run(
    `INSERT INTO banned_hwids (
       hwid, hwid_raw, motherboard, username, email, discord_id, license,
       reason, banned_by, source, report_id, active, expires_at, created_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, datetime('now'), datetime('now'))
     ON CONFLICT(hwid) DO UPDATE SET
       hwid_raw = COALESCE(excluded.hwid_raw, banned_hwids.hwid_raw),
       motherboard = COALESCE(excluded.motherboard, banned_hwids.motherboard),
       username = COALESCE(excluded.username, banned_hwids.username),
       email = COALESCE(excluded.email, banned_hwids.email),
       discord_id = COALESCE(excluded.discord_id, banned_hwids.discord_id),
       license = COALESCE(excluded.license, banned_hwids.license),
       reason = excluded.reason,
       banned_by = excluded.banned_by,
       source = excluded.source,
       report_id = COALESCE(excluded.report_id, banned_hwids.report_id),
       active = 1,
       expires_at = excluded.expires_at,
       updated_at = datetime('now')`,
    [
      normalized,
      finalHwidRaw,
      finalMotherboard,
      finalUsername,
      finalEmail,
      finalDiscord,
      finalLicense,
      reason,
      bannedBy,
      source,
      reportId,
      expiresAt,
    ]
  );

  const savedBan = db.get(`SELECT * FROM banned_hwids WHERE hwid = ?`, [normalized]);
  if (savedBan && mergedTokens.length > 0) {
    attachTokensToBan(savedBan.id, mergedTokens);
  }

  return db.get(`SELECT * FROM banned_hwids WHERE hwid = ?`, [normalized]);
}

function unbanHwid(rawHwid) {
  const normalized = normalizeHwid(rawHwid);
  const existing = db.get(`SELECT * FROM banned_hwids WHERE hwid = ?`, [normalized]);
  if (!existing) return null;

  db.run(
    `UPDATE banned_hwids SET active = 0, updated_at = datetime('now') WHERE hwid = ?`,
    [normalized]
  );
  return db.get(`SELECT * FROM banned_hwids WHERE hwid = ?`, [normalized]);
}

function banHwidsByEmail({ email, reason, bannedBy = 'Admin', durationHours = null }) {
  const cleanEmail = String(email || '').trim().toLowerCase();
  if (!cleanEmail) {
    const err = new Error('Email is required');
    err.statusCode = 400;
    throw err;
  }

  const matchedPlayers = db.all(
    `SELECT * FROM players WHERE LOWER(email) = ?`,
    [cleanEmail]
  );

  const reportHwids = db.all(
    `SELECT DISTINCT hwid, hwid_raw, motherboard, hw_tokens_json, username, email, discord_id, license
     FROM reports
     WHERE LOWER(email) = ? AND hwid IS NOT NULL AND hwid != ''`,
    [cleanEmail]
  );

  const targets = new Map();
  for (const p of matchedPlayers) {
    if (isValidHexHwid(p.hwid)) targets.set(p.hwid, p);
  }
  for (const r of reportHwids) {
    if (isValidHexHwid(r.hwid) && !targets.has(r.hwid)) targets.set(r.hwid, r);
  }

  if (targets.size === 0) {
    const err = new Error(`No known HWID found for email: ${cleanEmail}`);
    err.statusCode = 404;
    throw err;
  }

  const bannedRecords = [];
  for (const [hwid, info] of targets.entries()) {
    const rec = banHwid({
      hwid,
      hwidRaw: info.hwid_raw,
      hwTokens: normalizeHwTokens(info.hw_tokens_json || '[]'),
      motherboard: info.motherboard || null,
      username: info.username,
      email: info.email || cleanEmail,
      discordId: info.discord_id,
      license: info.license,
      reason: reason || `Motherboard & Account Banned by Email (${cleanEmail})`,
      bannedBy,
      source: 'email_ban',
      durationHours,
    });
    bannedRecords.push(rec);
  }

  return bannedRecords;
}

module.exports = {
  normalizeHwid,
  isValidHexHwid,
  deriveSha256HwidFromGuid,
  normalizeHwTokens,
  expireOutdatedBans,
  checkHwidBan,
  banHwid,
  unbanHwid,
  banHwidsByEmail,
};
