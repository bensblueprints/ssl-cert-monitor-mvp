// Best-effort WHOIS domain-expiry lookup over raw TCP 43 (no dependencies).
// Many TLDs have no public WHOIS or rate-limit hard — this is explicitly
// best-effort and failures are non-fatal.
const net = require('net');

const SERVERS = {
  com: 'whois.verisign-grs.com',
  net: 'whois.verisign-grs.com',
  org: 'whois.publicinterestregistry.org',
  info: 'whois.nic.info',
  io: 'whois.nic.io',
  co: 'whois.nic.co',
  dev: 'whois.nic.google',
  app: 'whois.nic.google',
  ai: 'whois.nic.ai',
  me: 'whois.nic.me',
  us: 'whois.nic.us',
  uk: 'whois.nic.uk',
  de: 'whois.denic.de',
  fr: 'whois.nic.fr',
  nl: 'whois.domain-registry.nl',
  xyz: 'whois.nic.xyz',
  sh: 'whois.nic.sh',
  gg: 'whois.gg'
};

const EXPIRY_PATTERNS = [
  /Registry Expiry Date:\s*(.+)/i,
  /Registrar Registration Expiration Date:\s*(.+)/i,
  /Expiry date:\s*(.+)/i,
  /Expiration Date:\s*(.+)/i,
  /paid-till:\s*(.+)/i,
  /renewal date:\s*(.+)/i
];

function rootDomain(hostname) {
  const parts = String(hostname).toLowerCase().split('.').filter(Boolean);
  if (parts.length < 2) return null;
  // naive two-label root (fine for best-effort; co.uk style handled as 3)
  const twoLevel = ['co.uk', 'org.uk', 'ac.uk', 'com.au', 'co.nz', 'co.jp'];
  const lastTwo = parts.slice(-2).join('.');
  if (twoLevel.includes(lastTwo) && parts.length >= 3) return parts.slice(-3).join('.');
  return lastTwo;
}

function query(server, text, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(43, server);
    let buf = '';
    socket.setTimeout(timeoutMs, () => { socket.destroy(); reject(new Error('whois timeout')); });
    socket.on('connect', () => socket.write(text + '\r\n'));
    socket.on('data', (d) => (buf += d.toString('utf8')));
    socket.on('end', () => resolve(buf));
    socket.on('error', reject);
  });
}

async function whoisExpiry(hostname) {
  const domain = rootDomain(hostname);
  if (!domain) return { ok: false, error: 'not a registrable domain' };
  if (net.isIP(hostname)) return { ok: false, error: 'IP address — no WHOIS' };
  const tld = domain.split('.').pop();
  const server = SERVERS[tld];
  if (!server) return { ok: false, error: `no WHOIS server known for .${tld}` };
  try {
    const text = await query(server, tld === 'de' ? `-T dn ${domain}` : domain);
    for (const re of EXPIRY_PATTERNS) {
      const m = text.match(re);
      if (m) {
        const ts = Date.parse(m[1].trim());
        if (!Number.isNaN(ts)) return { ok: true, domain, expires_at: ts };
      }
    }
    return { ok: false, domain, error: 'no expiry date in WHOIS response' };
  } catch (e) {
    return { ok: false, domain, error: e.message };
  }
}

module.exports = { whoisExpiry, rootDomain };
