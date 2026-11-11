'use strict';

const path = require('node:path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const ROOT_DIR = path.resolve(__dirname, '..');
const DATA_DIR = path.resolve(ROOT_DIR, process.env.DATA_DIR || './storage');
const DB_PATH = path.join(DATA_DIR, 'anticheat.sqlite');

module.exports = {
  PORT: Number(process.env.PORT || 3005),
  HOST: process.env.HOST || '0.0.0.0',
  ROOT_DIR,
  DATA_DIR,
  DB_PATH,
  INITIAL_ADMIN_USERNAME: process.env.ADMIN_USERNAME || 'admin',
  INITIAL_ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'changeme123',
  JWT_SECRET: process.env.JWT_SECRET || 'ndev-anticheat-super-secret-change-me-2026',
  INITIAL_SCANNER_PIN: process.env.SCANNER_PIN || 'NDEV@LAUNCHER@2026',
  INITIAL_LOG_SECRET: process.env.ANTICHEAT_LOG_SECRET || 'replace-with-private-secret',
  INITIAL_WEBHOOKS: {
    ban: process.env.DISCORD_WEBHOOK_BAN || '',
    warning: process.env.DISCORD_WEBHOOK_WARNING || '',
    tracking: process.env.DISCORD_WEBHOOK_TRACKING || '',
    logs: process.env.DISCORD_WEBHOOK_LOGS || '',
  },
};
