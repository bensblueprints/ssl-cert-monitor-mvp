// In-process scheduler: re-checks each domain's cert on an interval, refreshes
// WHOIS daily, and fires threshold alerts (30/14/7/1d by default) exactly once
// per (threshold, cert-expiry) pair.
const { checkCert, daysLeft } = require('./checker');
const { whoisExpiry } = require('./whois');
const { deliver } = require('./alerts');

const WHOIS_TTL_MS = 24 * 3600 * 1000;

async function runCheck(db, domain) {
  const result = await checkCert(domain.hostname, domain.port);
  db.prepare(`
    INSERT INTO cert_checks (domain_id, checked_at, ok, expires_at, issued_at, issuer, subject, key_type,
                             key_bits, weak_key, chain_valid, chain_error, self_signed, chain_json, error, duration_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    domain.id, result.checked_at, result.ok ? 1 : 0, result.expires_at || null, result.issued_at || null,
    result.issuer || null, result.subject || null, result.key_type || null, result.key_bits || null,
    result.weak_key ? 1 : 0, result.chain_valid ? 1 : 0, result.chain_error || null,
    result.self_signed ? 1 : 0, result.chain ? JSON.stringify(result.chain) : null,
    result.error || null, result.duration_ms
  );
  await evaluateAlerts(db, domain, result);
  return result;
}

async function evaluateAlerts(db, domain, result) {
  if (domain.paused) return;
  if (!result.ok) {
    // one 'error' alert per stretch of failures: skip if the previous check also failed
    const prev = db.prepare('SELECT ok FROM cert_checks WHERE domain_id = ? ORDER BY checked_at DESC LIMIT 2 OFFSET 1').get(domain.id);
    if (!prev || prev.ok) {
      await deliver(db, domain, {
        kind: 'error',
        payload: { event: 'check_failed', domain: domain.hostname, port: domain.port, error: result.error }
      });
    }
    return;
  }

  const d = daysLeft(result.expires_at);
  const thresholds = String(domain.thresholds || '30,14,7,1')
    .split(',').map((t) => parseInt(t, 10)).filter((t) => Number.isFinite(t)).sort((a, b) => a - b);

  // fire the SMALLEST crossed threshold not yet alerted for this cert expiry
  for (const t of thresholds) {
    if (d > t) continue;
    const already = db.prepare(
      'SELECT id FROM alerts WHERE domain_id = ? AND kind = ? AND threshold = ? AND cert_expires_at = ?'
    ).get(domain.id, 'expiry', t, result.expires_at);
    if (already) break; // this and larger thresholds handled
    await deliver(db, domain, {
      kind: 'expiry',
      threshold: t,
      certExpiresAt: result.expires_at,
      payload: {
        event: 'cert_expiring',
        domain: domain.hostname,
        port: domain.port,
        days_left: d,
        threshold_days: t,
        expires_at: new Date(result.expires_at).toISOString(),
        issuer: result.issuer
      }
    });
    break;
  }

  if (!result.chain_valid) {
    const already = db.prepare(
      "SELECT id FROM alerts WHERE domain_id = ? AND kind = 'invalid' AND cert_expires_at = ?"
    ).get(domain.id, result.expires_at);
    if (!already) {
      await deliver(db, domain, {
        kind: 'invalid',
        certExpiresAt: result.expires_at,
        payload: {
          event: 'cert_invalid',
          domain: domain.hostname,
          port: domain.port,
          chain_error: result.chain_error,
          self_signed: !!result.self_signed
        }
      });
    }
  }
}

async function refreshWhois(db, domain) {
  if (!domain.check_whois) return;
  const row = db.prepare('SELECT * FROM domain_whois WHERE domain_id = ?').get(domain.id);
  if (row && Date.now() - row.checked_at < WHOIS_TTL_MS) return;
  const w = await whoisExpiry(domain.hostname);
  db.prepare(`
    INSERT INTO domain_whois (domain_id, expires_at, checked_at, error)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(domain_id) DO UPDATE SET expires_at = excluded.expires_at, checked_at = excluded.checked_at, error = excluded.error
  `).run(domain.id, w.ok ? w.expires_at : null, Date.now(), w.ok ? null : w.error);
}

function startScheduler(db, intervalMs = 6 * 3600 * 1000) {
  let running = false;
  async function sweep() {
    if (running) return;
    running = true;
    try {
      const domains = db.prepare('SELECT * FROM domains WHERE paused = 0').all();
      for (const domain of domains) {
        const last = db.prepare('SELECT checked_at FROM cert_checks WHERE domain_id = ? ORDER BY checked_at DESC LIMIT 1').get(domain.id);
        if (!last || Date.now() - last.checked_at >= intervalMs) {
          await runCheck(db, domain).catch((e) => console.warn('[check]', domain.hostname, e.message));
        }
        await refreshWhois(db, domain).catch(() => {});
      }
    } finally {
      running = false;
    }
  }
  const tick = setInterval(sweep, Math.min(intervalMs, 60000));
  setTimeout(sweep, 1500);
  return () => clearInterval(tick);
}

module.exports = { startScheduler, runCheck, refreshWhois };
