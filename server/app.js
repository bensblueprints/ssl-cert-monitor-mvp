// Certwatch server — SSL/TLS + domain expiry monitoring.
const path = require('path');
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const { openDb, genSessionToken } = require('./db');
const { startScheduler, runCheck, refreshWhois } = require('./scheduler');
const { daysLeft, statusFor } = require('./checker');
const { deliver } = require('./alerts');

const SESSION_COOKIE = 'cw_session';

function createApp({ dbPath, adminPassword, autologinToken = null, checkIntervalMs = 6 * 3600 * 1000 } = {}) {
  const db = openDb(dbPath);
  const app = express();
  app.disable('x-powered-by');
  app.use(cookieParser());
  app.use(express.json());
  app.locals.db = db;
  app.locals.stopScheduler = startScheduler(db, checkIntervalMs);

  const findDomain = db.prepare('SELECT * FROM domains WHERE id = ?');

  function requireAuth(req, res, next) {
    const token = req.cookies[SESSION_COOKIE];
    if (token && db.prepare('SELECT id FROM sessions WHERE token = ?').get(token)) return next();
    res.status(401).json({ error: 'unauthorized' });
  }

  function createSession(res) {
    const token = genSessionToken();
    db.prepare('INSERT INTO sessions (token, created_at) VALUES (?, ?)').run(token, Date.now());
    res.cookie(SESSION_COOKIE, token, { httpOnly: true, sameSite: 'lax' });
  }

  function serializeDomain(d) {
    const last = db.prepare('SELECT * FROM cert_checks WHERE domain_id = ? ORDER BY checked_at DESC LIMIT 1').get(d.id);
    const whois = db.prepare('SELECT * FROM domain_whois WHERE domain_id = ?').get(d.id);
    const lastCheck = last
      ? { ...last, ok: !!last.ok, chain: last.chain_json ? JSON.parse(last.chain_json) : [], chain_json: undefined }
      : null;
    return {
      ...d,
      last_check: lastCheck,
      days_left: last && last.ok ? daysLeft(last.expires_at) : null,
      status: d.paused ? 'paused' : statusFor(lastCheck ? { ok: lastCheck.ok, expires_at: lastCheck.expires_at } : null),
      whois: whois ? { expires_at: whois.expires_at, checked_at: whois.checked_at, error: whois.error, days_left: whois.expires_at ? daysLeft(whois.expires_at) : null } : null
    };
  }

  // ── auth ───────────────────────────────────────────────────────────────────
  app.get('/api/health', (req, res) => res.json({ ok: true, app: 'certwatch' }));

  app.post('/api/login', (req, res) => {
    if ((req.body || {}).password !== adminPassword) return res.status(401).json({ error: 'wrong password' });
    createSession(res);
    res.json({ ok: true });
  });

  app.post('/api/logout', (req, res) => {
    const token = req.cookies[SESSION_COOKIE];
    if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    res.clearCookie(SESSION_COOKIE);
    res.json({ ok: true });
  });

  app.get('/auth/auto', (req, res) => {
    if (autologinToken && req.query.token === autologinToken) createSession(res);
    res.redirect('/');
  });

  app.get('/api/me', requireAuth, (req, res) => res.json({ ok: true }));

  // ── domains ────────────────────────────────────────────────────────────────
  function validateDomainInput(body, res) {
    const hostname = String(body.hostname || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!hostname || /\s/.test(hostname)) { res.status(400).json({ error: 'valid hostname required' }); return null; }
    const port = Math.floor(Number(body.port)) || 443;
    if (port < 1 || port > 65535) { res.status(400).json({ error: 'invalid port' }); return null; }
    const thresholds = String(body.thresholds || '30,14,7,1');
    if (!/^\d+(,\d+)*$/.test(thresholds.replace(/\s/g, ''))) { res.status(400).json({ error: 'thresholds must be comma-separated day counts' }); return null; }
    return {
      hostname, port,
      thresholds: thresholds.replace(/\s/g, ''),
      alert_email: String(body.alert_email || '').trim(),
      alert_webhook_url: String(body.alert_webhook_url || '').trim(),
      check_whois: body.check_whois === false ? 0 : 1
    };
  }

  app.get('/api/domains', requireAuth, (req, res) => {
    const rows = db.prepare('SELECT * FROM domains ORDER BY hostname').all();
    res.json(rows.map(serializeDomain));
  });

  app.post('/api/domains', requireAuth, (req, res) => {
    const v = validateDomainInput(req.body || {}, res);
    if (!v) return;
    try {
      const info = db.prepare(`
        INSERT INTO domains (hostname, port, alert_email, alert_webhook_url, thresholds, check_whois, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(v.hostname, v.port, v.alert_email, v.alert_webhook_url, v.thresholds, v.check_whois, Date.now());
      const domain = findDomain.get(info.lastInsertRowid);
      // immediate first check (fire and forget; UI can also force-check)
      runCheck(db, domain).catch(() => {});
      refreshWhois(db, domain).catch(() => {});
      res.status(201).json(serializeDomain(domain));
    } catch {
      res.status(409).json({ error: 'domain already monitored' });
    }
  });

  app.put('/api/domains/:id', requireAuth, (req, res) => {
    const d = findDomain.get(req.params.id);
    if (!d) return res.status(404).json({ error: 'not found' });
    const v = validateDomainInput({ ...d, ...(req.body || {}) }, res);
    if (!v) return;
    db.prepare(`
      UPDATE domains SET hostname = ?, port = ?, alert_email = ?, alert_webhook_url = ?, thresholds = ?, check_whois = ?
      WHERE id = ?
    `).run(v.hostname, v.port, v.alert_email, v.alert_webhook_url, v.thresholds, v.check_whois, d.id);
    res.json(serializeDomain(findDomain.get(d.id)));
  });

  app.delete('/api/domains/:id', requireAuth, (req, res) => {
    const d = findDomain.get(req.params.id);
    if (!d) return res.status(404).json({ error: 'not found' });
    db.prepare('DELETE FROM cert_checks WHERE domain_id = ?').run(d.id);
    db.prepare('DELETE FROM alerts WHERE domain_id = ?').run(d.id);
    db.prepare('DELETE FROM domain_whois WHERE domain_id = ?').run(d.id);
    db.prepare('DELETE FROM domains WHERE id = ?').run(d.id);
    res.json({ ok: true });
  });

  app.post('/api/domains/:id/pause', requireAuth, (req, res) => {
    db.prepare('UPDATE domains SET paused = 1 - paused WHERE id = ?').run(req.params.id);
    const d = findDomain.get(req.params.id);
    if (!d) return res.status(404).json({ error: 'not found' });
    res.json(serializeDomain(d));
  });

  app.post('/api/domains/:id/check', requireAuth, async (req, res) => {
    const d = findDomain.get(req.params.id);
    if (!d) return res.status(404).json({ error: 'not found' });
    await runCheck(db, d);
    await refreshWhois(db, d).catch(() => {});
    res.json(serializeDomain(findDomain.get(d.id)));
  });

  app.post('/api/domains/:id/test-alert', requireAuth, async (req, res) => {
    const d = findDomain.get(req.params.id);
    if (!d) return res.status(404).json({ error: 'not found' });
    if (!d.alert_webhook_url && !d.alert_email) return res.status(400).json({ error: 'no alert channels configured' });
    const results = await deliver(db, d, {
      kind: 'test',
      payload: { event: 'test', domain: d.hostname, port: d.port, message: 'Certwatch test alert' }
    });
    res.json({ ok: results.every((r) => r.ok), results });
  });

  app.get('/api/domains/:id/history', requireAuth, (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 1000);
    const rows = db.prepare('SELECT * FROM cert_checks WHERE domain_id = ? ORDER BY checked_at DESC LIMIT ?')
      .all(req.params.id, limit);
    res.json(rows.map((r) => ({ ...r, chain: r.chain_json ? JSON.parse(r.chain_json) : [], chain_json: undefined })));
  });

  app.get('/api/alerts', requireAuth, (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 1000);
    const rows = db.prepare(`
      SELECT a.*, d.hostname FROM alerts a LEFT JOIN domains d ON d.id = a.domain_id
      ORDER BY a.sent_at DESC LIMIT ?
    `).all(limit);
    res.json(rows);
  });

  // ── static frontend ────────────────────────────────────────────────────────
  const dist = path.join(__dirname, '..', 'dist');
  if (fs.existsSync(dist)) {
    app.use(express.static(dist));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api')) return next();
      res.sendFile(path.join(dist, 'index.html'));
    });
  }

  return app;
}

module.exports = { createApp };
