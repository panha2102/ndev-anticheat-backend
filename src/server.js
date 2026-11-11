'use strict';

const path = require('node:path');
const express = require('express');
const config = require('./config');
const clientRoutes = require('./routes/client');
const adminRoutes = require('./routes/admin');

const app = express();

app.disable('x-powered-by');

// Basic CORS for flexibility if dashboard or game server calls cross-origin
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Admin-Token, X-Anticheat-Secret, X-HWID'
  );
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// High payload limit to accommodate multi-monitor Base64 JPEG screenshots from ndev-core-five
app.use(express.json({ limit: '60mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'ndev-anticheat-backend',
    time: new Date().toISOString(),
  });
});

// Mount routes
app.use(clientRoutes);
app.use(adminRoutes);

// Static Admin Dashboard SPA
const publicDir = path.join(__dirname, '..', 'public');
app.use(express.static(publicDir));

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/submit') {
    return next();
  }
  return res.sendFile(path.join(publicDir, 'index.html'));
});

// Error handler
app.use((err, _req, res, _next) => {
  console.error('[ServerError]', err);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal Server Error',
  });
});

if (require.main === module) {
  app.listen(config.PORT, config.HOST, () => {
    console.log('==========================================================');
    console.log(`  NPKP / ndev-core-five Anti-Cheat Backend & Dashboard`);
    console.log(`  Dashboard UI : http://localhost:${config.PORT}`);
    console.log(`  Submit API   : http://localhost:${config.PORT}/submit`);
    console.log(`  Detections   : http://localhost:${config.PORT}/api/anticheat/detections`);
    console.log(`  HWID Check   : http://localhost:${config.PORT}/api/hwid/check-hwid`);
    console.log('==========================================================');
  });
}

module.exports = app;
