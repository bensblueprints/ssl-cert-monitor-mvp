# Launch strategy — Certwatch

## Target communities

- **r/selfhosted** — perfect fit; post as "self-hosted SSL + domain expiry monitor, MIT, Docker one-liner." Show the compose file and a screenshot.
- **r/sysadmin** — every expired-cert postmortem thread is an opening. Participate genuinely; the "one alert per threshold, no spam" design detail lands well here. No naked link drops (sub rule) — frame as tooling show-and-tell.
- **r/devops** — angle: kill the monitoring-suite add-on line item; mention webhook → Slack/PagerDuty integration.
- **r/webdev / r/SideProject** — the "$24 once vs $15/mo" math post.
- **Hacker News** — see Show HN below; expired-cert war stories reliably generate comments.

## Show HN draft

**Title:** Show HN: Certwatch – self-hosted SSL and domain expiry monitoring ($24 once)

**Body:**
Every team I've worked with has had an expired-cert incident, and every monitoring vendor sells the fix as a monthly add-on. It's a TLS handshake on a schedule.

Certwatch does the handshake with Node's `tls` module (expiry, issuer, chain validity, self-signed detection, key strength), best-effort WHOIS for domain expiry, and fires webhook/email alerts at 30/14/7/1 days — deduplicated per threshold per cert, so frequent checks don't mean alert spam. SQLite for history, React dashboard with a traffic-light grid, Docker or Electron.

Honest limitations: WHOIS coverage is patchy by TLD, and it monitors from wherever you run it — no global probe network. For "is my cert going to expire," that's all you need.

MIT source; the checker is ~100 lines if you want to audit what it does to your hosts.

## SEO keywords (10)

1. ssl expiry monitor
2. certificate expiration alert tool
3. ssl certificate monitoring self hosted
4. domain expiry monitor self hosted
5. ssl monitoring free alternative
6. tls certificate expiry alerts
7. certificate chain checker self hosted
8. whois domain expiration alert
9. ssl monitor webhook slack
10. ssl certificate dashboard open source

## AppSumo / PitchGround pitch

Certwatch turns the most preventable outage in tech — the expired SSL certificate — into a solved problem for a one-time $24. It performs real TLS handshakes against every domain a buyer runs (expiry, chain validity, weak keys), adds best-effort WHOIS domain-expiry tracking, and alerts by webhook or email at 30/14/7/1 days with per-threshold deduplication. Unlimited domains, self-hosted via Docker or as a desktop app, MIT source. Agencies and freelancers managing dozens of client sites currently pay $10–20/month for this as an add-on; a lifetime deal here is the easiest expense line they'll ever delete.

## Pricing math

**$24 one-time.** SSL monitoring add-ons run $10–20/month → **Certwatch pays for itself in under 2.5 months** at the cheapest tier. An agency with 50 client domains on a $15/mo add-on spends $540/year; Certwatch is $24, forever, with no domain limit.
