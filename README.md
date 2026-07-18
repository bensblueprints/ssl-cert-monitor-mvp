# 🛡️ Certwatch

## Demo



https://github.com/user-attachments/assets/a481faf7-b118-4449-9fe1-006ca6377e3f



**SSL certificate + domain expiry monitoring you own forever. One expired cert is a 2am page — this is $24 once, not a line item on your monitoring bill.**

![MIT](https://img.shields.io/badge/license-MIT-green) ![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)

Certwatch does a real TLS handshake against every site you care about, on a schedule, and tells you — by email or webhook — at 30/14/7/1 days before a certificate (or the domain registration itself) expires. Plus chain validity, key strength, and a full check history.

![screenshot](docs/screenshot.png)

## Features

- 🚦 **Traffic-light dashboard** — green >30d, yellow ≤30d, red <7d / expired / invalid / unreachable.
- 🤝 **Real TLS handshake checks** (Node `tls`) — expiry, issuer, SAN list, chain validity, self-signed detection, weak-key flags (RSA <2048 / EC <224).
- 🌐 **Domain (WHOIS) expiry** — best-effort registry lookups so the *domain* doesn't lapse either.
- 🔔 **Threshold alerts** — configurable days (default 30,14,7,1), delivered via webhook (JSON POST) and/or email (SMTP). Exactly one alert per threshold per certificate — no alert spam.
- ⛓ **Chain viewer** — the full presented chain per check, in the UI.
- 📜 **History** — every check stored; unreachable hosts recorded with the error.
- 🖥 **Desktop mode or VPS** — Electron app or `docker compose up -d`.

## Quick start

```bash
npm i
npm run build
npm start          # → http://localhost:5346
```

**Run it as a desktop app, or deploy to a $5 VPS when you need it public:**

```bash
npm run desktop
# or
docker compose up -d
```

## Certwatch vs paid SSL monitors

| | Certwatch | Uptime-tool SSL add-ons / SSLMate-style |
|---|---|---|
| Price | **$24 once** | $10–20/**month** |
| 3 years, 50 domains | **$24** | $360–720 |
| Handshake checks (expiry, chain, keys) | ✅ | ✅ |
| Domain (WHOIS) expiry | ✅ best-effort | sometimes |
| Email + webhook alerts | ✅ | ✅ |
| Data on your server | ✅ | ❌ |
| Domain limits | none | usually tiered |
| Source you can read | ✅ MIT | ❌ |

## Honest limitations

- WHOIS is best-effort: some TLDs publish no expiry, some rate-limit. Certificate checks are the reliable signal; WHOIS is a bonus.
- Email alerts need your SMTP credentials in `.env`; webhooks work with zero config.
- The checker connects directly to your hosts — monitor from a box that can reach them.

## Tech stack

Node 20+ · Express · better-sqlite3 · React + Vite + Tailwind + Framer Motion + Lucide · Node `tls`/`net` (no external checker APIs) · nodemailer · Electron desktop wrapper.

## ☕ Skip the setup — get the 1-click installer

Grab the packaged version: **[https://whop.com/benjisaiempire/certwatch](https://whop.com/benjisaiempire/certwatch)** — pay once, own it forever, no subscription.

## License

MIT © 2026 Ben (bensblueprints)

## macOS build

See [MAC-BUILD.md](MAC-BUILD.md). Quickest path: GitHub **Actions** tab -> run the **Mac Build** (`mac-build.yml`) workflow to get a downloadable `.dmg` (unsigned - right-click -> Open on first launch).
