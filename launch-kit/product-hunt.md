# Product Hunt — Certwatch

**Name:** Certwatch

**Tagline (60 chars):** SSL & domain expiry alerts before the 2am outage. $24 once.

**Description (260 chars):**
Certwatch monitors SSL/TLS certificates and domain expiry across all your sites: real handshake checks, chain validation, weak-key flags, WHOIS lookups, and 30/14/7/1-day alerts via email or webhook. Self-hosted, traffic-light dashboard, pay once — own forever.

**Full description:**
An expired certificate is the dumbest possible outage: fully predictable, completely preventable, and it still happens to everyone — because the reminder lives in a $15/month monitoring add-on someone unsubscribed from.

Certwatch is the pay-once fix:

- Real TLS handshakes (not just port checks): expiry, issuer, chain validity, self-signed detection, key strength
- Best-effort WHOIS so the domain registration doesn't lapse either
- Traffic-light grid: green >30d, yellow <30d, red <7d/expired/invalid
- Alerts at 30/14/7/1 days (configurable) via webhook + email — exactly one per threshold, no spam
- Certificate chain viewer and full check history
- Docker deploy or desktop app; unlimited domains

**Maker first comment:**
Hey PH 👋 I got tired of paying monthly for what is fundamentally a cron job around a TLS handshake. Certwatch does the handshake with Node's own `tls` module, stores every check in SQLite, and pings my Slack webhook at 30/14/7/1 days out — with dedup so a 6-hour check interval doesn't mean 4 alerts a day. It also does best-effort WHOIS, because the only thing dumber than an expired cert is an expired domain. $24 once, unlimited domains, MIT source. Honest caveat: WHOIS coverage varies by TLD — cert checks are the reliable half. AMA!

**Gallery shots (5):**
1. Traffic-light dashboard — mixed green/yellow/red rows with days-left badges.
2. Expanded row — certificate chain viewer + check history side by side.
3. Slack/webhook alert payload: "cert_expiring, days_left: 6, threshold: 7".
4. Add-domain modal with threshold configuration.
5. Math card: "50 domains × $15/mo SSL add-on = $540/yr. Certwatch: $24 once."
