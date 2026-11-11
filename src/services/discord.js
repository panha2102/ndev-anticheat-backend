'use strict';

const db = require('../db');

const COLORS = {
  BAN: 0xef4444,
  WARNING: 0xf59e0b,
  TRACKING: 0x3b82f6,
  HWID_LOG: 0xa855f7,
};

function getWebhookForType(alertType) {
  const t = String(alertType || '').toUpperCase();
  if (t === 'BAN') return db.getSetting('discord_webhook_ban', '');
  if (t === 'WARNING') return db.getSetting('discord_webhook_warning', '');
  if (t === 'TRACKING') return db.getSetting('discord_webhook_tracking', '');
  if (t === 'HWID_LOG') return db.getSetting('discord_webhook_logs', '');
  return '';
}

function truncate(str, max = 1000) {
  const s = String(str ?? '');
  if (s.length <= max) return s || 'N/A';
  return s.slice(0, max - 3) + '...';
}

function withWaitParam(webhookUrl) {
  try {
    const u = new URL(webhookUrl);
    u.searchParams.set('wait', 'true');
    return u.toString();
  } catch {
    return webhookUrl;
  }
}

// Sends report + in-memory JPEG Buffers directly to Discord without touching server disk.
// Returns an array of Discord CDN attachment URLs if Discord accepted the upload.
async function sendReportWebhook({ report, findings, imageBuffers = [], autoBanned }) {
  const webhookUrl = getWebhookForType(report.alert_type);
  if (!webhookUrl || !webhookUrl.startsWith('http')) return [];

  try {
    const findingsText =
      findings && findings.length
        ? findings
            .slice(0, 8)
            .map(
              (f, idx) =>
                `**${idx + 1}. [${f.severity || 'Info'}]** \`${f.name || 'Detection'}\` — ${f.path || 'N/A'} *(${f.category || 'General'})*`
            )
            .join('\n')
        : 'No threat findings (initial game launch snapshot)';

    const identityLines = [
      `**Username:** ${report.username || 'Unknown'}`,
      `**Email:** ${report.email || 'N/A'}`,
      `**Discord ID:** ${report.discord_id && report.discord_id !== 'N/A' ? `<@${report.discord_id}> (\`${report.discord_id}\`)` : 'N/A'}`,
      `**Steam ID:** \`${report.steam_id || 'N/A'}\``,
      `**Motherboard:** \`${report.motherboard || 'Unknown Board'}\``,
      `**Master HWID:** \`${report.hwid || report.hwid_raw || 'N/A'}\``,
      `**PC / OS:** \`${report.computer_name || '?'} / ${report.windows_user || '?'} (Win ${report.os_version || '?'})\``,
    ].join('\n');

    const titlePrefix =
      report.alert_type === 'BAN'
        ? '🚨 [NDEV ANTI-CHEAT] CRITICAL BAN DETECTION'
        : report.alert_type === 'WARNING'
          ? '⚠️ [NDEV ANTI-CHEAT] SUSPICIOUS WARNING'
          : '📡 [NDEV ANTI-CHEAT] GAME LAUNCH TRACKING';

    const embed = {
      title: `${titlePrefix} (#${report.id})`,
      color: COLORS[report.alert_type] || COLORS.WARNING,
      fields: [
        { name: '👤 Player & Hardware Identity', value: truncate(identityLines, 1024), inline: false },
        { name: `🔍 Findings (${findings?.length || 0})`, value: truncate(findingsText, 1024), inline: false },
        {
          name: '🛡️ Enforcement Status',
          value: autoBanned
            ? '✅ **Motherboard / HWID Auto-Banned** & Client Terminated'
            : report.alert_type === 'BAN'
              ? '⛔ Client Force-Terminated (Manual Review)'
              : '📝 Logged for Admin Review',
          inline: true,
        },
        {
          name: '🖥️ Monitors',
          value: `${report.monitor_count || 0} connected`,
          inline: true,
        },
      ],
      footer: { text: `ndev-core-five • IP: ${report.ip_address || 'unknown'}` },
      timestamp: new Date().toISOString(),
    };

    const validImages = Array.isArray(imageBuffers)
      ? imageBuffers.filter((item) => item && Buffer.isBuffer(item.buffer) && item.buffer.length > 16)
      : [];

    if (validImages.length > 0) {
      const collectedUrls = [];
      // Discord allows up to 10 file attachments & 10 embeds per webhook message.
      // Chunk by 10 so even 10+ monitor setups upload 100% of screens cleanly.
      const chunkSize = 10;

      for (let offset = 0; offset < validImages.length; offset += chunkSize) {
        const batch = validImages.slice(offset, offset + chunkSize);
        const form = new FormData();
        const embeds = [];

        batch.forEach((img, idx) => {
          const globalIdx = offset + idx;
          const fileName =
            img.filename || (globalIdx === 0 ? 'evidence.jpg' : `monitor_${globalIdx}.jpg`);
          const blob = new Blob([img.buffer], { type: 'image/jpeg' });
          form.append(`files[${idx}]`, blob, fileName);

          if (globalIdx === 0) {
            embed.image = { url: `attachment://${fileName}` };
            embeds.push(embed);
          } else {
            embeds.push({
              title: `🖥️ Screen ${globalIdx} (${fileName})`,
              color: COLORS[report.alert_type] || COLORS.WARNING,
              image: { url: `attachment://${fileName}` },
            });
          }
        });

        form.append(
          'payload_json',
          JSON.stringify({
            username: 'NPKP Anti-Cheat',
            embeds,
          })
        );

        const resp = await fetch(withWaitParam(webhookUrl), { method: 'POST', body: form });
        if (resp.ok) {
          const msg = await resp.json().catch(() => null);
          if (msg && Array.isArray(msg.attachments)) {
            collectedUrls.push(...msg.attachments.map((a) => a.url).filter(Boolean));
          }
        }
      }

      return collectedUrls;
    } else {
      const resp = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'NPKP Anti-Cheat',
          embeds: [embed],
        }),
      });
      return resp.ok ? [] : [];
    }
  } catch (err) {
    console.error('[DiscordWebhook] Failed to send report webhook:', err.message);
    return [];
  }
}

async function sendEnforcementLogWebhook(logEntry) {
  const webhookUrl =
    getWebhookForType('HWID_LOG') || getWebhookForType('BAN');
  if (!webhookUrl || !webhookUrl.startsWith('http')) return false;

  try {
    const isRemoteQuit = logEntry.event_type === 'remote_force_quit';
    const embed = {
      title: isRemoteQuit
        ? '⚡ [NDEV ANTI-CHEAT] Game Remotely Closed by Admin'
        : '🔒 [NDEV ANTI-CHEAT] Banned Device Blocked at Launch',
      color: COLORS.HWID_LOG,
      fields: [
        { name: 'Event', value: `\`${logEntry.event_type}\` (${logEntry.severity})`, inline: true },
        { name: 'Player', value: `${logEntry.username || 'Unknown'} (${logEntry.email || 'N/A'})`, inline: true },
        { name: 'Discord', value: logEntry.discord_id ? `<@${logEntry.discord_id}> (\`${logEntry.discord_id}\`)` : 'N/A', inline: true },
        { name: 'HWID', value: `\`${logEntry.hwid || 'N/A'}\``, inline: false },
        { name: 'Reason', value: truncate(logEntry.reason, 512), inline: false },
      ],
      footer: { text: `ndev-anticheat • IP: ${logEntry.ip_address || 'unknown'}` },
      timestamp: new Date().toISOString(),
    };

    const resp = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'NPKP Anti-Cheat', embeds: [embed] }),
    });
    return resp.ok;
  } catch (err) {
    console.error('[DiscordWebhook] Failed to send enforcement log webhook:', err.message);
    return false;
  }
}

async function sendTestWebhook(webhookUrl) {
  const resp = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'NPKP Anti-Cheat',
      embeds: [
        {
          title: '✅ Ndev Anti-Cheat Webhook Connected!',
          description: 'ការភ្ជាប់ Discord Webhook ជាមួយ **ndev-anticheat-backend** ដំណើរការដោយជោគជ័យ (រូបភាពនឹងផ្ញើមក Discord ផ្ទាល់ដោយមិនរក្សាទុកក្នុង Storage)។',
          color: 0x10b981,
          timestamp: new Date().toISOString(),
        },
      ],
    }),
  });
  return resp.ok;
}

module.exports = {
  sendReportWebhook,
  sendEnforcementLogWebhook,
  sendTestWebhook,
};
