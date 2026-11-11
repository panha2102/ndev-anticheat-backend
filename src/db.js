'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const config = require('./config');
const { DEFAULT_BANNED_PROCESSES } = require('./defaults');

fs.mkdirSync(config.DATA_DIR, { recursive: true });

const rawDb = new DatabaseSync(config.DB_PATH);
rawDb.exec('PRAGMA journal_mode = WAL;');
rawDb.exec('PRAGMA synchronous = NORMAL;');
rawDb.exec('PRAGMA foreign_keys = ON;');

function sanitizeParam(val) {
  if (val === undefined || val === null) return null;
  if (typeof val === 'boolean') return val ? 1 : 0;
  return val;
}

function run(sql, params = []) {
  const stmt = rawDb.prepare(sql);
  return stmt.run(...params.map(sanitizeParam));
}

function get(sql, params = []) {
  const stmt = rawDb.prepare(sql);
  return stmt.get(...params.map(sanitizeParam)) || null;
}

function all(sql, params = []) {
  const stmt = rawDb.prepare(sql);
  return stmt.all(...params.map(sanitizeParam));
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  if (!salt || !expectedHash) return false;
  const computed = crypto.scryptSync(String(password), salt, 64);
  const expected = Buffer.from(expectedHash, 'hex');
  if (computed.length !== expected.length) return false;
  return crypto.timingSafeEqual(computed, expected);
}

function initSchema() {
  rawDb.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS banned_processes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      exe_name TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'Prohibited Tool',
      enabled INTEGER NOT NULL DEFAULT 1,
      is_builtin INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS players (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hwid TEXT NOT NULL UNIQUE,
      hwid_raw TEXT,
      username TEXT,
      email TEXT,
      discord_id TEXT,
      steam_id TEXT,
      license TEXT,
      computer_name TEXT,
      windows_user TEXT,
      os_version TEXT,
      last_ip TEXT,
      report_count INTEGER NOT NULL DEFAULT 0,
      ban_report_count INTEGER NOT NULL DEFAULT 0,
      first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_seen_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_players_email ON players(email);
    CREATE INDEX IF NOT EXISTS idx_players_discord ON players(discord_id);
    CREATE INDEX IF NOT EXISTS idx_players_username ON players(username);

    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      alert_type TEXT NOT NULL,
      summary TEXT,
      findings_count INTEGER NOT NULL DEFAULT 0,
      critical_count INTEGER NOT NULL DEFAULT 0,
      username TEXT,
      email TEXT,
      discord_id TEXT,
      steam_id TEXT,
      license TEXT,
      hwid TEXT,
      hwid_raw TEXT,
      computer_name TEXT,
      windows_user TEXT,
      os_version TEXT,
      monitor_count INTEGER NOT NULL DEFAULT 0,
      primary_screenshot TEXT,
      screenshots_json TEXT NOT NULL DEFAULT '[]',
      findings_json TEXT NOT NULL DEFAULT '[]',
      artifacts_json TEXT NOT NULL DEFAULT '{}',
      ip_address TEXT,
      auto_banned INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_reports_type_created ON reports(alert_type, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_reports_hwid ON reports(hwid);
    CREATE INDEX IF NOT EXISTS idx_reports_email ON reports(email);

    CREATE TABLE IF NOT EXISTS banned_hwids (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hwid TEXT NOT NULL UNIQUE,
      hwid_raw TEXT,
      username TEXT,
      email TEXT,
      discord_id TEXT,
      license TEXT,
      reason TEXT NOT NULL,
      banned_by TEXT NOT NULL DEFAULT 'System',
      source TEXT NOT NULL DEFAULT 'manual',
      report_id INTEGER,
      active INTEGER NOT NULL DEFAULT 1,
      expires_at TEXT,
      hit_count INTEGER NOT NULL DEFAULT 0,
      last_blocked_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_banned_hwids_active ON banned_hwids(hwid, active);
    CREATE INDEX IF NOT EXISTS idx_banned_hwids_email ON banned_hwids(email);

    CREATE TABLE IF NOT EXISTS enforcement_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'info',
      reason TEXT,
      process_id INTEGER,
      username TEXT,
      email TEXT,
      discord_id TEXT,
      hwid TEXT,
      license TEXT,
      meta_json TEXT NOT NULL DEFAULT '{}',
      ip_address TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_enforcement_logs_created ON enforcement_logs(created_at DESC);

    CREATE TABLE IF NOT EXISTS banned_hw_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ban_id INTEGER NOT NULL,
      token TEXT NOT NULL,
      token_type TEXT NOT NULL DEFAULT 'hw',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(ban_id, token),
      FOREIGN KEY (ban_id) REFERENCES banned_hwids(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_banned_hw_tokens_token ON banned_hw_tokens(token);

    CREATE TABLE IF NOT EXISTS client_commands (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hwid TEXT NOT NULL,
      command TEXT NOT NULL DEFAULT 'force_quit',
      reason TEXT,
      issued_by TEXT NOT NULL DEFAULT 'Admin',
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      executed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_client_commands_pending ON client_commands(hwid, status);
  `);

  // Safe schema migrations for existing SQLite files
  const safeAlter = (sql) => {
    try { rawDb.exec(sql); } catch {}
  };
  safeAlter(`ALTER TABLE players ADD COLUMN motherboard TEXT;`);
  safeAlter(`ALTER TABLE players ADD COLUMN hw_tokens_json TEXT NOT NULL DEFAULT '[]';`);
  safeAlter(`ALTER TABLE reports ADD COLUMN motherboard TEXT;`);
  safeAlter(`ALTER TABLE reports ADD COLUMN hw_tokens_json TEXT NOT NULL DEFAULT '[]';`);
  safeAlter(`ALTER TABLE banned_hwids ADD COLUMN motherboard TEXT;`);
  safeAlter(`ALTER TABLE banned_hwids ADD COLUMN hw_tokens_json TEXT NOT NULL DEFAULT '[]';`);
  safeAlter(`ALTER TABLE banned_hwids ADD COLUMN last_matched_token TEXT;`);

  // Seed default settings if missing
  const { salt, hash } = hashPassword(config.INITIAL_ADMIN_PASSWORD);
  const defaultSettings = {
    admin_username: config.INITIAL_ADMIN_USERNAME,
    admin_password_salt: salt,
    admin_password_hash: hash,
    scanner_pin: config.INITIAL_SCANNER_PIN,
    anticheat_log_secret: config.INITIAL_LOG_SECRET,
    auto_ban_on_critical: 'true',
    discord_webhook_ban: config.INITIAL_WEBHOOKS.ban,
    discord_webhook_warning: config.INITIAL_WEBHOOKS.warning,
    discord_webhook_tracking: config.INITIAL_WEBHOOKS.tracking,
    discord_webhook_logs: config.INITIAL_WEBHOOKS.logs,
  };

  for (const [key, value] of Object.entries(defaultSettings)) {
    run(
      `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`,
      [key, String(value)]
    );
  }

  // If Discord webhooks are provided in .env and the DB still has an empty string, sync them in
  const envWebhookMap = {
    discord_webhook_ban: config.INITIAL_WEBHOOKS.ban,
    discord_webhook_warning: config.INITIAL_WEBHOOKS.warning,
    discord_webhook_tracking: config.INITIAL_WEBHOOKS.tracking,
    discord_webhook_logs: config.INITIAL_WEBHOOKS.logs,
  };
  for (const [key, envVal] of Object.entries(envWebhookMap)) {
    if (envVal && String(envVal).trim()) {
      run(
        `UPDATE settings SET value = ?, updated_at = datetime('now') WHERE key = ? AND (value IS NULL OR value = '')`,
        [String(envVal).trim(), key]
      );
    }
  }

  // Seed default prohibited processes if table is empty
  const existingCount = get(`SELECT COUNT(*) AS cnt FROM banned_processes`);
  if (!existingCount || existingCount.cnt === 0) {
    rawDb.exec('BEGIN');
    try {
      for (const proc of DEFAULT_BANNED_PROCESSES) {
        run(
          `INSERT INTO banned_processes (exe_name, display_name, category, enabled, is_builtin)
           VALUES (?, ?, ?, 1, 1)
           ON CONFLICT(exe_name) DO NOTHING`,
          [proc.exe_name.toLowerCase(), proc.display_name, proc.category]
        );
      }
      rawDb.exec('COMMIT');
    } catch (err) {
      rawDb.exec('ROLLBACK');
      throw err;
    }
  }
}

function getSetting(key, fallback = '') {
  const row = get(`SELECT value FROM settings WHERE key = ?`, [key]);
  return row ? row.value : fallback;
}

function setSetting(key, value) {
  run(
    `INSERT INTO settings (key, value, updated_at)
     VALUES (?, ?, datetime('now'))
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`,
    [key, String(value ?? '')]
  );
}

function getAllSettingsMap() {
  const rows = all(`SELECT key, value FROM settings`);
  const map = {};
  for (const r of rows) map[r.key] = r.value;
  return map;
}

initSchema();

module.exports = {
  rawDb,
  run,
  get,
  all,
  getSetting,
  setSetting,
  getAllSettingsMap,
  hashPassword,
  verifyPassword,
};
