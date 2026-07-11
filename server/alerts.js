// Alert delivery: webhook (JSON POST) + email (SMTP via nodemailer, optional).
const nodemailer = require('nodemailer');

function smtpConfigured() {
  return Boolean(process.env.SMTP_HOST);
}

async function sendWebhook(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(10000)
  });
  if (!res.ok) throw new Error(`webhook HTTP ${res.status}`);
}

async function sendEmail(to, subject, payload) {
  if (!smtpConfigured()) return false; // soft skip
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
  });
  await transport.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject,
    text: Object.entries(payload).map(([k, v]) => `${k}: ${v}`).join('\n')
  });
  return true;
}

// Records every attempt in the alerts table; never throws.
async function deliver(db, domain, { kind, threshold = null, certExpiresAt = null, payload }) {
  const results = [];
  const record = (channel, ok, error = null) => {
    db.prepare(`
      INSERT INTO alerts (domain_id, kind, threshold, cert_expires_at, channel, sent_at, ok, error)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(domain.id, kind, threshold, certExpiresAt, channel, Date.now(), ok ? 1 : 0, error);
    results.push({ channel, ok, error });
  };

  if (domain.alert_webhook_url) {
    try {
      await sendWebhook(domain.alert_webhook_url, payload);
      record('webhook', true);
    } catch (e) {
      record('webhook', false, e.message);
    }
  }
  if (domain.alert_email) {
    try {
      const sent = await sendEmail(domain.alert_email, payload.subject || `[certwatch] ${payload.event} — ${domain.hostname}`, payload);
      if (sent) record('email', true);
      else record('email', false, 'SMTP not configured');
    } catch (e) {
      record('email', false, e.message);
    }
  }
  return results;
}

module.exports = { deliver, smtpConfigured };
