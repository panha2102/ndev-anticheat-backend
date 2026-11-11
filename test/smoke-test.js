'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

// Isolate test storage in a temp folder
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ndev-ac-test-'));
process.env.DATA_DIR = tmpDir;
process.env.ADMIN_USERNAME = 'admin';
process.env.ADMIN_PASSWORD = 'testpassword123';
process.env.SCANNER_PIN = 'NDEV@LAUNCHER@2026';
process.env.ANTICHEAT_LOG_SECRET = 'test-log-secret-999';

const app = require('../src/server');

// Tiny valid 1x1 JPEG base64
const TINY_JPEG_B64 =
  '/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=';

const SAMPLE_HWID = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
const MB_UUID_TOKEN = 'mb_uuid:1111111111111111111111111111111111111111111111111111111111111111';
const TPM_EK_TOKEN  = 'tpm_ek:2222222222222222222222222222222222222222222222222222222222222222';
const OLD_DISK_TOKEN = 'disk:3333333333333333333333333333333333333333333333333333333333333333';
const NEW_DISK_TOKEN = 'disk:9999999999999999999999999999999999999999999999999999999999999999';
const SPOOFED_MASTER_HWID = 'ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000';

async function runTests() {
  let discordReceivedMultipart = false;
  const mockDiscord = await new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const ct = req.headers['content-type'] || '';
      if (ct.includes('multipart/form-data')) {
        discordReceivedMultipart = true;
      }
      req.resume();
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            id: '999',
            attachments: [
              { url: 'https://cdn.discordapp.com/attachments/1/2/evidence.jpg' },
              { url: 'https://cdn.discordapp.com/attachments/1/2/monitor_1.jpg' },
            ],
          })
        );
      });
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
  const mockWebhookUrl = `http://127.0.0.1:${mockDiscord.address().port}/webhook`;

  const db = require('../src/db');
  db.setSetting('discord_webhook_ban', mockWebhookUrl);

  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  console.log(`[SmokeTest] Server running at ${baseUrl}`);

  try {
    // 1. Health check
    let res = await fetch(`${baseUrl}/api/health`);
    assert.equal(res.status, 200);

    // 2. GET /api/anticheat/detections (Client startup list)
    res = await fetch(`${baseUrl}/api/anticheat/detections`);
    let data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.bannedProcesses['eulen.exe'], 'Eulen');
    assert.equal(data.bannedProcesses['420services.exe'], '420 Service');
    console.log(`[SmokeTest] ✔ GET /api/anticheat/detections (${data.count} processes)`);

    // 3. POST /api/hwid/check-hwid (Clean HWID -> not banned)
    res = await fetch(`${baseUrl}/api/hwid/check-hwid`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-HWID': SAMPLE_HWID },
      body: JSON.stringify({ hwid: SAMPLE_HWID }),
    });
    data = await res.json();
    assert.equal(data.isBanned, false);
    assert.equal(data.banned, false);
    console.log(`[SmokeTest] ✔ POST /api/hwid/check-hwid (clean = false)`);

    // 4. Reject invalid PIN on POST /submit
    res = await fetch(`${baseUrl}/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin: 'WRONG_PIN', type: 'BAN' }),
    });
    assert.equal(res.status, 403);

    // 5. POST /submit (BAN report -> saves screenshots + triggers Auto-Ban HWID!)
    res = await fetch(`${baseUrl}/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pin: 'NDEV@LAUNCHER@2026',
        type: 'BAN',
        monitorCount: 2,
        screenshot: TINY_JPEG_B64,
        screenshots: [TINY_JPEG_B64, TINY_JPEG_B64],
        findings: [
          {
            category: 'Prohibited Tool',
            name: 'Banned Software Running',
            severity: 'Critical',
            path: 'Eulen (process: eulen.exe)',
            action: 'Force Quit Launcher',
            source_type: 'EnforcementScan',
            details: { enforcement: 'force_quit' },
          },
        ],
        artifacts: {
          SYSTEM_INFO: {
            computer_name: 'GAMING-PC',
            user_name: 'Sokha',
            os_version: '10.0',
            os_build: 26200,
          },
          IDENTITIES: {
            username: 'SokhaRP',
            email: 'sokha@example.com',
            discord_id: '123456789012345678',
            steam_id_active: '76561198000000000',
            hwid: SAMPLE_HWID,
            hwid_raw: '12345678-1234-1234-1234-123456789abc',
            motherboard: 'ASUSTeK COMPUTER INC. ROG STRIX B650-A GAMING WIFI',
            hw_tokens: [MB_UUID_TOKEN, TPM_EK_TOKEN, OLD_DISK_TOKEN],
            license: 'abcdef1234567890abcdef1234567890abcdef12',
          },
        },
      }),
    });
    data = await res.json();
    assert.equal(res.status, 200);
    assert.equal(data.success, true);
    assert.equal(data.autoBanned, true);
    console.log(`[SmokeTest] ✔ POST /submit (Report #${data.reportId}, Auto-Banned = true)`);

    // 6. POST /api/hwid/check-hwid (Now must return isBanned: true!)
    res = await fetch(`${baseUrl}/api/hwid/check-hwid`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-HWID': SAMPLE_HWID },
      body: JSON.stringify({ hwid: SAMPLE_HWID }),
    });
    data = await res.json();
    assert.equal(data.isBanned, true);
    assert.equal(data.banned, true);
    assert.ok(data.reason.includes('Auto-Ban'));
    console.log(`[SmokeTest] ✔ POST /api/hwid/check-hwid (banned = true, reason = "${data.reason}")`);

    // 6b. VANGUARD EVASION TEST:
    // Cheater wipes Windows, buys a brand-new SSD (NEW_DISK_TOKEN), spoofs master HWID (SPOOFED_MASTER_HWID),
    // and even flashes SMBIOS UUID, leaving ONLY the TPM 2.0 Endorsement Key (TPM_EK_TOKEN) on the motherboard!
    res = await fetch(`${baseUrl}/api/hwid/check-hwid`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-HWID': SPOOFED_MASTER_HWID },
      body: JSON.stringify({
        hwid: SPOOFED_MASTER_HWID,
        motherboard: 'Spoofed Vendor Board',
        hw_tokens: [TPM_EK_TOKEN, NEW_DISK_TOKEN],
      }),
    });
    data = await res.json();
    assert.equal(data.isBanned, true);
    assert.equal(data.matchedBy, TPM_EK_TOKEN);
    console.log(`[SmokeTest] ✔ Vanguard Evasion Caught via TPM 2.0 EK (${data.matchedBy}) & Auto-Linked new SSD!`);

    // 6c. Verify that the newly swapped SSD (NEW_DISK_TOKEN) is now ALSO permanently chained into the ban!
    res = await fetch(`${baseUrl}/api/hwid/check-hwid`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-HWID': SPOOFED_MASTER_HWID },
      body: JSON.stringify({
        hwid: SPOOFED_MASTER_HWID,
        hw_tokens: [NEW_DISK_TOKEN],
      }),
    });
    data = await res.json();
    assert.equal(data.isBanned, true);
    assert.equal(data.matchedBy, NEW_DISK_TOKEN);
    console.log(`[SmokeTest] ✔ Chained Ban Evasion verified (new SSD alone now triggers ban)!`);

    // 7. POST /api/anticheat/logs (NdevAnticheat.cpp FailClosed telemetry)
    res = await fetch(`${baseUrl}/api/anticheat/logs`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Anticheat-Secret': 'test-log-secret-999',
      },
      body: JSON.stringify({
        event_type: 'hwid_banned',
        severity: 'critical',
        reason: 'hwid banned: Auto-Ban',
        process_id: 9876,
        username: 'SokhaRP',
        email: 'sokha@example.com',
        discord_id: '123456789012345678',
        hwid: SAMPLE_HWID,
      }),
    });
    data = await res.json();
    assert.equal(res.status, 200);
    assert.equal(data.success, true);
    console.log(`[SmokeTest] ✔ POST /api/anticheat/logs (Log #${data.id})`);

    // 8. Admin Login + Stats + Report Detail + Screenshot Fetch + Unban + Ban-by-Email + Add Detection
    res = await fetch(`${baseUrl}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'testpassword123' }),
    });
    data = await res.json();
    assert.equal(res.status, 200);
    const authHeaders = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${data.token}`,
    };
    console.log(`[SmokeTest] ✔ POST /api/admin/login`);

    res = await fetch(`${baseUrl}/api/admin/stats`, { headers: authHeaders });
    data = await res.json();
    assert.equal(data.stats.banReports, 1);
    assert.equal(data.stats.activeBans, 1);

    // Wait briefly for async Discord webhook upload to complete
    await new Promise((r) => setTimeout(r, 150));

    // Verify ZERO screenshot files/folders exist on local storage!
    assert.equal(fs.existsSync(path.join(tmpDir, 'screenshots')), false);
    const storedFiles = fs.readdirSync(tmpDir);
    assert.equal(storedFiles.some((f) => f.endsWith('.jpg') || f.endsWith('.png')), false);
    assert.equal(discordReceivedMultipart, true);

    res = await fetch(`${baseUrl}/api/admin/reports/1`, { headers: authHeaders });
    data = await res.json();
    assert.equal(
      data.report.primary_screenshot,
      'https://cdn.discordapp.com/attachments/1/2/evidence.jpg'
    );
    console.log(`[SmokeTest] ✔ Zero local image storage verified (RAM -> Discord Webhook only)`);

    // Unban HWID
    res = await fetch(`${baseUrl}/api/hwid/admin/unban-hwid`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ hwid: SAMPLE_HWID }),
    });
    assert.equal(res.status, 200);

    res = await fetch(`${baseUrl}/api/hwid/check-hwid`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hwid: SAMPLE_HWID }),
    });
    data = await res.json();
    assert.equal(data.isBanned, false);
    console.log(`[SmokeTest] ✔ Unban HWID verified`);

    // Ban HWID by Email
    res = await fetch(`${baseUrl}/api/hwid/admin/ban-hwid-by-email`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ email: 'sokha@example.com', reason: 'Admin email ban test' }),
    });
    data = await res.json();
    assert.equal(data.count, 1);
    console.log(`[SmokeTest] ✔ Ban HWID by Email verified`);

    // Add custom prohibited exe and verify client /api/anticheat/detections sees it immediately
    res = await fetch(`${baseUrl}/api/admin/detections`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        exe_name: 'superhack2026.exe',
        display_name: 'SuperHack 2026',
        category: 'Custom Cheat',
      }),
    });
    assert.equal(res.status, 200);

    res = await fetch(`${baseUrl}/api/anticheat/detections`);
    data = await res.json();
    assert.equal(data.bannedProcesses['superhack2026.exe'], 'SuperHack 2026');
    console.log(`[SmokeTest] ✔ Dynamic detection rule live in /api/anticheat/detections`);

    // 9. Remote Force-Quit (One-Shot Silent Close Game) + Online Presence test
    const ONLINE_PLAYER_HWID = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
    res = await fetch(`${baseUrl}/api/hwid/check-hwid`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-HWID': ONLINE_PLAYER_HWID },
      body: JSON.stringify({
        hwid: ONLINE_PLAYER_HWID,
        username: 'DaraLive',
        email: 'dara@example.com',
        computer_name: 'DARA-PC',
        motherboard: 'MSI MAG B760 TOMAHAWK',
      }),
    });
    data = await res.json();
    assert.equal(data.isBanned, false);
    assert.equal(data.forceQuit, false);

    // Admin queues remote Close Game command
    res = await fetch(`${baseUrl}/api/admin/players/force-quit`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ hwid: ONLINE_PLAYER_HWID, reason: 'Admin silent close test' }),
    });
    data = await res.json();
    assert.equal(res.status, 200);
    assert.equal(data.isOnline, true);

    // Next 5s client poll receives forceQuit: true ONCE
    res = await fetch(`${baseUrl}/api/hwid/check-hwid`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-HWID': ONLINE_PLAYER_HWID },
      body: JSON.stringify({ hwid: ONLINE_PLAYER_HWID, username: 'DaraLive' }),
    });
    data = await res.json();
    assert.equal(data.isBanned, false);
    assert.equal(data.forceQuit, true);

    // Player relaunches game -> forceQuit is now false (one-shot, NOT permanently banned!)
    res = await fetch(`${baseUrl}/api/hwid/check-hwid`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-HWID': ONLINE_PLAYER_HWID },
      body: JSON.stringify({ hwid: ONLINE_PLAYER_HWID, username: 'DaraLive' }),
    });
    data = await res.json();
    assert.equal(data.isBanned, false);
    assert.equal(data.forceQuit, false);
    console.log(`[SmokeTest] ✔ One-shot Remote Close Game (forceQuit) verified!`);

    // 10. Game-launch-only TRACKING snapshot (Info only, NO screenshot, skips periodic duplicates)
    const TRACKING_HWID = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    db.setSetting('discord_webhook_tracking', mockWebhookUrl);
    discordReceivedMultipart = false;

    // Initial launch TRACKING (even if legacy client passes screenshot, backend must strip screenshot!)
    res = await fetch(`${baseUrl}/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pin: 'NDEV@LAUNCHER@2026',
        type: 'TRACKING',
        monitorCount: 2,
        screenshot: TINY_JPEG_B64,
        screenshots: [TINY_JPEG_B64],
        findings: [],
        artifacts: {
          SYSTEM_INFO: { computer_name: 'CHANTHA-PC', user_name: 'Chantha', os_version: '10.0', os_build: 26200 },
          IDENTITIES: {
            username: 'ChanthaRP',
            email: 'chantha@example.com',
            discord_id: '888888888888888888',
            hwid: TRACKING_HWID,
            motherboard: 'GIGABYTE B760M GAMING X',
          },
        },
      }),
    });
    data = await res.json();
    assert.equal(res.status, 200);
    assert.equal(data.alertType, 'TRACKING');
    assert.ok(data.reportId > 0);
    const trackingReportId = data.reportId;

    await new Promise((r) => setTimeout(r, 120));
    assert.equal(discordReceivedMultipart, false);

    res = await fetch(`${baseUrl}/api/admin/reports/${trackingReportId}`, { headers: authHeaders });
    data = await res.json();
    assert.equal(data.report.primary_screenshot, null);
    assert.deepEqual(data.report.screenshots, []);
    assert.equal(data.report.username, 'ChanthaRP');
    assert.equal(data.report.motherboard, 'GIGABYTE B760M GAMING X');

    // Legacy periodic follow-up TRACKING 5s later (no session_start) -> skipped!
    res = await fetch(`${baseUrl}/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pin: 'NDEV@LAUNCHER@2026',
        type: 'TRACKING',
        monitorCount: 2,
        findings: [],
        artifacts: {
          SYSTEM_INFO: { computer_name: 'CHANTHA-PC', user_name: 'Chantha' },
          IDENTITIES: { username: 'ChanthaRP', hwid: TRACKING_HWID },
        },
      }),
    });
    data = await res.json();
    assert.equal(res.status, 200);
    assert.equal(data.skippedPeriodic, true);
    assert.equal(data.reportId, null);

    // Explicit new game launch (session_start: true from updated C++ client) -> recorded!
    res = await fetch(`${baseUrl}/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pin: 'NDEV@LAUNCHER@2026',
        type: 'TRACKING',
        session_start: true,
        monitorCount: 2,
        findings: [],
        artifacts: {
          SYSTEM_INFO: { computer_name: 'CHANTHA-PC', user_name: 'Chantha' },
          IDENTITIES: { username: 'ChanthaRP', hwid: TRACKING_HWID },
        },
      }),
    });
    data = await res.json();
    assert.equal(res.status, 200);
    assert.ok(data.reportId > trackingReportId);
    console.log(`[SmokeTest] ✔ Launch-only Info-only TRACKING snapshot (no screenshot) verified!`);

    // 11. Early-boot Critical BAN enrichment: if a player's HWID is already known in `players`,
    // even if a boot-time BAN arrives before launcher login (missing username/email/discord in payload),
    // Backend enriches full identity AND triggers Motherboard/HWID Auto-Ban immediately!
    res = await fetch(`${baseUrl}/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pin: 'NDEV@LAUNCHER@2026',
        type: 'BAN',
        monitorCount: 1,
        screenshot: TINY_JPEG_B64,
        findings: [
          {
            category: 'Prohibited Tool',
            name: 'Banned Software Running',
            severity: 'Critical',
            path: 'Ndev Decryptor (window: Ndev Decryptor V2222)',
            action: 'Force Quit Launcher',
            source_type: 'EnforcementScan',
          },
        ],
        artifacts: {
          SYSTEM_INFO: { computer_name: 'CHANTHA-PC', user_name: 'Chantha', os_version: '10.0', os_build: 26200 },
          IDENTITIES: {
            hwid: TRACKING_HWID,
            motherboard: 'GIGABYTE B760M GAMING X',
          },
        },
      }),
    });
    data = await res.json();
    assert.equal(res.status, 200);
    assert.equal(data.autoBanned, true);

    res = await fetch(`${baseUrl}/api/admin/reports/${data.reportId}`, { headers: authHeaders });
    const enrichedBan = (await res.json()).report;
    assert.equal(enrichedBan.username, 'ChanthaRP');
    assert.equal(enrichedBan.email, 'chantha@example.com');
    assert.equal(enrichedBan.discord_id, '888888888888888888');
    assert.equal(enrichedBan.motherboard, 'GIGABYTE B760M GAMING X');
    assert.equal(enrichedBan.hwid, TRACKING_HWID);
    assert.equal(enrichedBan.os_version, '10.0 (Build 26200)');
    assert.equal(enrichedBan.is_hwid_banned, 1);
    console.log(`[SmokeTest] ✔ Early-boot Critical BAN identity enrichment + Auto-Ban verified!`);

    // 12. Multi-monitor capture (e.g. 6 connected monitors: composite + all 6 per-monitor screens)
    db.setSetting('discord_webhook_warning', mockWebhookUrl);
    let lastMultipartBodyBytes = 0;
    mockDiscord.removeAllListeners('request');
    mockDiscord.on('request', (req, res) => {
      let bytes = 0;
      req.on('data', (c) => { bytes += c.length; });
      req.on('end', () => {
        lastMultipartBodyBytes = bytes;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            id: '1000',
            attachments: [
              { url: 'https://cdn.discordapp.com/attachments/1/2/evidence.jpg' },
              { url: 'https://cdn.discordapp.com/attachments/1/2/monitor_1.jpg' },
              { url: 'https://cdn.discordapp.com/attachments/1/2/monitor_2.jpg' },
              { url: 'https://cdn.discordapp.com/attachments/1/2/monitor_3.jpg' },
              { url: 'https://cdn.discordapp.com/attachments/1/2/monitor_4.jpg' },
              { url: 'https://cdn.discordapp.com/attachments/1/2/monitor_5.jpg' },
              { url: 'https://cdn.discordapp.com/attachments/1/2/monitor_6.jpg' },
            ],
          })
        );
      });
    });

    res = await fetch(`${baseUrl}/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pin: 'NDEV@LAUNCHER@2026',
        type: 'WARNING',
        monitorCount: 6,
        screenshot: TINY_JPEG_B64,
        screenshots: Array.from({ length: 6 }, () => TINY_JPEG_B64),
        findings: [
          {
            category: 'Overlay Detection',
            name: 'Suspicious Graphics Hook',
            severity: 'High',
            path: 'Monitor 6 Overlay',
          },
        ],
        artifacts: {
          SYSTEM_INFO: { computer_name: 'MULTI-MON-PC', user_name: 'Sokha' },
          IDENTITIES: { username: 'Sokha6Mon', hwid: TRACKING_HWID },
        },
      }),
    });
    const multiData = await res.json();
    assert.equal(res.status, 200);
    await new Promise((r) => setTimeout(r, 150));

    res = await fetch(`${baseUrl}/api/admin/reports/${multiData.reportId}`, { headers: authHeaders });
    const multiReport = (await res.json()).report;
    assert.equal(multiReport.monitor_count, 6);
    assert.equal(multiReport.screenshots.length, 7); // 1 composite + all 6 individual screens!
    assert.ok(lastMultipartBodyBytes > 500);
    console.log(`[SmokeTest] ✔ All 6 monitors + composite screen captured & forwarded to Discord/Dashboard!`);

    console.log('\nALL SMOKE TESTS PASSED SUCCESSFULLY!');
  } finally {
    server.close();
    mockDiscord.close();
  }
}

runTests().catch((err) => {
  console.error('[SmokeTest] FAILED:', err);
  process.exit(1);
});
