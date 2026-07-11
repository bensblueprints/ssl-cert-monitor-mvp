// Certwatch smoke test — generates a REAL short-lived TLS cert (openssl),
// serves it from a local TLS server, and exercises the full pipeline:
// add domain → real handshake check → parsed expiry/issuer/chain in SQLite →
// traffic-light status → threshold webhook alert (7d fires for a 5-day cert) →
// invalid-chain alert (self-signed) → history → unreachable-host error path.
// Kills ONLY the spawned server child.
const { spawn, execFileSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const tls = require('node:tls');
const http = require('node:http');
const assert = require('node:assert');

const ROOT = path.join(__dirname, '..');
const TEST_PORT = 5396;        // certwatch app
const TLS_PORT = 5397;         // our disposable TLS target
const WEBHOOK_PORT = 5398;     // alert receiver
const ADMIN_PASSWORD = 'smoke-admin-pw';
const DB_PATH = path.join(__dirname, 'smoke.db');
const BASE = `http://127.0.0.1:${TEST_PORT}`;
const CERT_DAYS = 5;

for (const f of [DB_PATH, DB_PATH + '-wal', DB_PATH + '-shm']) if (fs.existsSync(f)) fs.unlinkSync(f);

let serverProc = null;
let tlsServer = null;
let webhookServer = null;
const webhookHits = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fn, label, tries = 40, delay = 250) {
  for (let i = 0; i < tries; i++) {
    try { const v = await fn(); if (v) return v; } catch { /* retry */ }
    await sleep(delay);
  }
  throw new Error(`Timed out waiting for: ${label}`);
}

let cookie = '';
async function api(pathname, options = {}) {
  const res = await fetch(BASE + pathname, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}), ...options.headers },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  return { status: res.status, data: await res.json().catch(() => ({})) };
}

function makeCert(tmpDir) {
  const key = path.join(tmpDir, 'key.pem');
  const crt = path.join(tmpDir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', key, '-out', crt,
    '-days', String(CERT_DAYS),
    '-subj', '/CN=smoke.local/O=Certwatch Smoke CA'
  ], { stdio: 'pipe' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
}

async function main() {
  console.log('1. Generating a real 5-day self-signed cert + local TLS server');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'certwatch-smoke-'));
  const pem = makeCert(tmp);
  tlsServer = tls.createServer({ key: pem.key, cert: pem.cert }, (s) => s.end());
  await new Promise((r) => tlsServer.listen(TLS_PORT, '127.0.0.1', r));

  webhookServer = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      webhookHits.push(JSON.parse(body));
      res.writeHead(200).end('{"ok":true}');
    });
  });
  await new Promise((r) => webhookServer.listen(WEBHOOK_PORT, '127.0.0.1', r));

  console.log('2. Booting Certwatch on port', TEST_PORT);
  serverProc = spawn(process.execPath, ['server/index.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(TEST_PORT), ADMIN_PASSWORD, DB_PATH, CHECK_INTERVAL_MS: '3600000' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  serverProc.stdout.on('data', (d) => process.stdout.write(`   [server] ${d}`));
  serverProc.stderr.on('data', (d) => process.stderr.write(`   [server] ${d}`));
  await waitFor(async () => (await api('/api/health')).data.ok, 'server health');

  console.log('3. Auth gates');
  assert.strictEqual((await api('/api/domains')).status, 401);
  assert.strictEqual((await api('/api/login', { method: 'POST', body: { password: 'no' } })).status, 401);
  assert.strictEqual((await api('/api/login', { method: 'POST', body: { password: ADMIN_PASSWORD } })).status, 200);

  console.log('4. Add domain → real TLS handshake check');
  const created = await api('/api/domains', {
    method: 'POST',
    body: {
      hostname: '127.0.0.1', port: TLS_PORT,
      thresholds: '30,14,7,1',
      alert_webhook_url: `http://127.0.0.1:${WEBHOOK_PORT}/hook`,
      check_whois: false
    }
  });
  assert.strictEqual(created.status, 201);
  const domainId = created.data.id;
  const d = await waitFor(async () => {
    const r = await api('/api/domains');
    const x = r.data.find((y) => y.id === domainId);
    return x && x.last_check ? x : null;
  }, 'first cert check');

  assert.strictEqual(d.last_check.ok, true, 'handshake check must succeed');
  const dl = d.days_left;
  assert.ok(dl === CERT_DAYS - 1 || dl === CERT_DAYS, `days_left ~${CERT_DAYS} (got ${dl})`);
  assert.ok(String(d.last_check.issuer).includes('Certwatch Smoke CA'), 'issuer parsed from cert');
  assert.strictEqual(d.last_check.chain_valid, 0, 'self-signed → chain invalid');
  assert.strictEqual(d.last_check.self_signed, 1, 'detected as self-signed');
  assert.ok(d.last_check.key_type.includes('RSA 2048'), 'key strength parsed');
  assert.strictEqual(d.status, 'red', 'expiring in <7d → red traffic light');
  console.log(`   ✓ parsed: issuer=${d.last_check.issuer}, ${dl}d left, status=${d.status}`);

  console.log('5. Rows in SQLite + threshold/invalid alerts fired');
  const Database = require('better-sqlite3');
  const db = new Database(DB_PATH, { readonly: true });
  const checkRow = db.prepare('SELECT * FROM cert_checks WHERE domain_id = ? ORDER BY checked_at DESC LIMIT 1').get(domainId);
  assert.ok(checkRow && checkRow.expires_at > Date.now(), 'check row with future expiry in SQLite');
  assert.ok(JSON.parse(checkRow.chain_json).length >= 1, 'chain stored');

  const expiryAlert = await waitFor(
    () => db.prepare("SELECT * FROM alerts WHERE domain_id = ? AND kind = 'expiry' AND ok = 1").get(domainId),
    'expiry alert row'
  );
  assert.strictEqual(expiryAlert.threshold, 7, '5-day cert fires the 7-day threshold');
  const invalidAlert = db.prepare("SELECT * FROM alerts WHERE domain_id = ? AND kind = 'invalid'").get(domainId);
  assert.ok(invalidAlert, 'invalid-chain alert recorded');
  await waitFor(() => webhookHits.some((h) => h.event === 'cert_expiring'), 'expiry webhook received');
  const hook = webhookHits.find((h) => h.event === 'cert_expiring');
  assert.strictEqual(hook.threshold_days, 7);
  assert.strictEqual(hook.domain, '127.0.0.1');
  assert.ok(webhookHits.some((h) => h.event === 'cert_invalid'), 'invalid webhook received');
  console.log(`   ✓ webhook: cert_expiring threshold=${hook.threshold_days} days_left=${hook.days_left}`);

  console.log('6. Re-check does NOT duplicate the threshold alert');
  await api(`/api/domains/${domainId}/check`, { method: 'POST' });
  const expiryAlerts = db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE domain_id = ? AND kind = 'expiry'").get(domainId);
  assert.strictEqual(expiryAlerts.n, 1, 'one expiry alert per threshold per cert');

  console.log('7. History endpoint');
  const hist = await api(`/api/domains/${domainId}/history`);
  assert.ok(hist.data.length >= 2, 'history has both checks');
  assert.ok(hist.data[0].chain.length >= 1, 'history rows include parsed chain');

  console.log('8. Unreachable host → error recorded, status red');
  const dead = await api('/api/domains', {
    method: 'POST',
    body: { hostname: '127.0.0.1', port: 5399, check_whois: false } // nothing listens here
  });
  assert.strictEqual(dead.status, 201);
  const deadD = await waitFor(async () => {
    const r = await api('/api/domains');
    const x = r.data.find((y) => y.id === dead.data.id);
    return x && x.last_check ? x : null;
  }, 'dead host check');
  assert.strictEqual(deadD.last_check.ok, false, 'unreachable host check fails');
  assert.ok(deadD.last_check.error, 'error message recorded');
  assert.strictEqual(deadD.status, 'red');

  db.close();
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log('\n✅ All Certwatch smoke tests passed');
}

async function cleanup(code) {
  if (serverProc && !serverProc.killed) serverProc.kill();
  if (tlsServer) tlsServer.close();
  if (webhookServer) { webhookServer.close(); webhookServer.closeAllConnections?.(); }
  await sleep(300);
  for (const f of [DB_PATH, DB_PATH + '-wal', DB_PATH + '-shm']) {
    try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch { /* windows lock */ }
  }
  process.exit(code);
}

main()
  .then(() => cleanup(0))
  .catch(async (err) => {
    console.error('\n❌ Smoke test failed:', err.message);
    await cleanup(1);
  });
