'use strict';

const crypto = require('node:crypto');
const config = require('../config');
const db = require('../db');

const COOKIE_NAME = 'ndev_ac_session';
const TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

function signToken(username) {
  const payload = Buffer.from(
    JSON.stringify({
      sub: username,
      exp: Date.now() + TOKEN_TTL_MS,
      nonce: crypto.randomBytes(8).toString('hex'),
    })
  ).toString('base64url');

  const sig = crypto
    .createHmac('sha256', config.JWT_SECRET)
    .update(payload)
    .digest('base64url');

  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;

  const expectedSig = crypto
    .createHmac('sha256', config.JWT_SECRET)
    .update(payload)
    .digest('base64url');

  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!parsed.exp || Date.now() > parsed.exp) return null;
    return parsed;
  } catch {
    return null;
  }
}

function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = decodeURIComponent(part.slice(idx + 1).trim());
    out[k] = v;
  }
  return out;
}

function extractAdminToken(req) {
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  if (req.headers['x-admin-token']) {
    return String(req.headers['x-admin-token']).trim();
  }
  const cookies = parseCookies(req.headers.cookie);
  return cookies[COOKIE_NAME] || null;
}

function requireAdmin(req, res, next) {
  const token = extractAdminToken(req);
  const session = verifyToken(token);
  if (!session) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  req.admin = { username: session.sub };
  next();
}

function safeEqualString(a, b) {
  const bufA = Buffer.from(String(a ?? ''), 'utf8');
  const bufB = Buffer.from(String(b ?? ''), 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function verifyScannerPin(pin) {
  const expected = db.getSetting('scanner_pin', config.INITIAL_SCANNER_PIN);
  if (!expected) return true;
  return safeEqualString(pin, expected);
}

function verifyLogSecret(secret) {
  const expected = db.getSetting('anticheat_log_secret', config.INITIAL_LOG_SECRET);
  if (!expected) return true;
  return safeEqualString(secret, expected);
}

module.exports = {
  COOKIE_NAME,
  TOKEN_TTL_MS,
  signToken,
  verifyToken,
  requireAdmin,
  verifyScannerPin,
  verifyLogSecret,
};
