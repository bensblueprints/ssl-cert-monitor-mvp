// TLS certificate checker — Node built-in `tls`, no external calls beyond the
// target host itself.
const tls = require('tls');

function checkCert(hostname, port = 443, { timeoutMs = 10000, servername } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    let settled = false;
    const done = (result) => {
      if (!settled) {
        settled = true;
        resolve({ checked_at: started, duration_ms: Date.now() - started, ...result });
      }
    };

    let socket;
    try {
      socket = tls.connect({
        host: hostname,
        port,
        servername: servername || (require('net').isIP(hostname) ? undefined : hostname),
        rejectUnauthorized: false, // we WANT to inspect invalid/expired certs
        timeout: timeoutMs
      });
    } catch (e) {
      return done({ ok: false, error: e.message });
    }

    socket.setTimeout(timeoutMs, () => {
      done({ ok: false, error: 'connection timed out' });
      socket.destroy();
    });

    socket.on('secureConnect', () => {
      try {
        const cert = socket.getPeerCertificate(true);
        if (!cert || !cert.valid_to) {
          done({ ok: false, error: 'no certificate presented' });
          return socket.end();
        }
        const chain = [];
        let c = cert;
        const seen = new Set();
        while (c && !seen.has(c.fingerprint256)) {
          seen.add(c.fingerprint256);
          chain.push({
            subject: c.subject?.CN || JSON.stringify(c.subject || {}),
            issuer: c.issuer?.CN || c.issuer?.O || 'unknown',
            valid_from: c.valid_from,
            valid_to: c.valid_to,
            fingerprint256: c.fingerprint256
          });
          c = c.issuerCertificate && c.issuerCertificate !== c ? c.issuerCertificate : null;
        }
        const expiresAt = Date.parse(cert.valid_to);
        const keyBits = cert.bits || null;
        const altNames = String(cert.subjectaltname || '')
          .split(',').map((s) => s.trim().replace(/^DNS:/, '')).filter(Boolean);

        done({
          ok: true,
          expires_at: expiresAt,
          issued_at: Date.parse(cert.valid_from) || null,
          issuer: cert.issuer?.O || cert.issuer?.CN || 'unknown',
          subject: cert.subject?.CN || hostname,
          alt_names: altNames,
          key_bits: keyBits,
          key_type: cert.asn1Curve ? `EC ${cert.asn1Curve}` : keyBits ? `RSA ${keyBits}` : 'unknown',
          weak_key: keyBits ? (cert.asn1Curve ? keyBits < 224 : keyBits < 2048) : false,
          chain_valid: socket.authorized,
          chain_error: socket.authorized ? null : (socket.authorizationError ? String(socket.authorizationError) : 'unknown'),
          self_signed: chain.length === 1 && chain[0].subject === chain[0].issuer,
          chain
        });
      } catch (e) {
        done({ ok: false, error: e.message });
      } finally {
        socket.end();
      }
    });

    socket.on('error', (e) => done({ ok: false, error: e.message }));
  });
}

function daysLeft(expiresAt, now = Date.now()) {
  if (!expiresAt) return null;
  return Math.floor((expiresAt - now) / 86400000);
}

// green > 30d, yellow <= 30d, red < 7d or expired/invalid
function statusFor(check) {
  if (!check || !check.ok) return 'red';
  const d = daysLeft(check.expires_at);
  if (d == null || d < 7) return 'red';
  if (d <= 30) return 'yellow';
  return 'green';
}

module.exports = { checkCert, daysLeft, statusFor };
