const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

function nativeBindingPath() {
  if (!process.versions.electron) return null;
  const p = path.join(__dirname, '..', 'vendor', 'better_sqlite3-electron.node');
  return fs.existsSync(p) ? p : null;
}

function openDb(dbPath) {
  fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
  const nativeBinding = nativeBindingPath();
  const db = new Database(dbPath, nativeBinding ? { nativeBinding } : {});
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS domains (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hostname TEXT NOT NULL,
      port INTEGER NOT NULL DEFAULT 443,
      alert_email TEXT DEFAULT '',
      alert_webhook_url TEXT DEFAULT '',
      thresholds TEXT NOT NULL DEFAULT '30,14,7,1',   -- days-before-expiry alert points
      check_whois INTEGER NOT NULL DEFAULT 1,
      paused INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      UNIQUE(hostname, port)
    );
    CREATE TABLE IF NOT EXISTS cert_checks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain_id INTEGER NOT NULL,
      checked_at INTEGER NOT NULL,
      ok INTEGER NOT NULL,
      expires_at INTEGER,
      issued_at INTEGER,
      issuer TEXT,
      subject TEXT,
      key_type TEXT,
      key_bits INTEGER,
      weak_key INTEGER,
      chain_valid INTEGER,
      chain_error TEXT,
      self_signed INTEGER,
      chain_json TEXT,
      error TEXT,
      duration_ms INTEGER
    );
    CREATE TABLE IF NOT EXISTS domain_whois (
      domain_id INTEGER PRIMARY KEY,
      expires_at INTEGER,
      checked_at INTEGER,
      error TEXT
    );
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain_id INTEGER NOT NULL,
      kind TEXT NOT NULL,               -- expiry|invalid|error|recovered|test
      threshold INTEGER,                -- days threshold that fired (expiry alerts)
      cert_expires_at INTEGER,          -- dedupe key: one alert per threshold per cert
      channel TEXT NOT NULL,            -- webhook|email
      sent_at INTEGER NOT NULL,
      ok INTEGER NOT NULL DEFAULT 0,
      error TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_checks_domain ON cert_checks(domain_id, checked_at);
    CREATE INDEX IF NOT EXISTS idx_alerts_domain ON alerts(domain_id, sent_at);
  `);

  return db;
}

function genSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { openDb, genSessionToken };
