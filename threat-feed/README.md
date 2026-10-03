# Threat Feed

Real-time zero-day, malware and outbreak chatter from security researchers
across **X, Mastodon (infosec.exchange), Bluesky and Reddit**, enriched for
an IT security audience and sold as a **Free (ad-supported)** and **Pro
(paid)** product.

Every post is enriched on ingest:
- **IOC extraction**: hashes, defanged domains, IPs and URLs, plus CVE ids.
- **Categorisation**: zero-day, exploitation, ransomware, outbreak, malware,
  supply-chain, phishing, vulnerability.
- **Severity scoring** (0–100).
- **Trend detection** that flags spikes in CVEs, campaign hashtags and
  categories across multiple researchers.

```
 X API ─┐
 Mastodon ─┤   ingest loop    enrich (IOCs,       SQLite   ┌─> /api/feed   (tier-filtered, ads for Free)
 Bluesky ──┼─> (per-source ─> categories,   ──>  store ───┼─> /api/trends (spike detection)
 Reddit ───┤    isolation)    severity)                    ├─> /api/export (CSV / STIX 2.1, Pro)
 Demo ─────┘                        │                      └─> /api/stream (SSE real-time, Pro)
                                    └──> watchlists ─> webhooks (Slack/Teams/Discord, Pro)
```

## Plans

All limits live in one file, [`threatfeed/tiers.py`](threatfeed/tiers.py). The
API enforces them, and the pricing page is rendered from the same data.

| | Free | Pro |
|---|---|---|
| Feed latency | delayed 15 min | **real-time** (live SSE stream) |
| Sources | Mastodon, Bluesky, Reddit | + **X researcher accounts** |
| History | 24 hours | 90 days |
| IOCs | count shown, values locked | full hashes / IPs / domains / URLs |
| Export | — | CSV and STIX 2.1 bundle |
| Watchlists + webhook alerts | — | 25 |
| API keys (REST + stream) | — | ✓ |
| Trends | top 3 | top 25 |
| Ads | sponsored card every 6 posts + sidebar | none |

Why the split: Free gives the same intelligence 15 minutes later, so it
stays useful and builds audience for ads. Pro sells **speed, X coverage and
actionability**. X is the expensive source to run (a paid API tier), so it
is gated to the plan that pays for it.

## Run it locally

```bash
cd threat-feed
pip install -r requirements.txt
python -m threatfeed.seed               # backfill 48h of demo posts
THREATFEED_DEV_BILLING=1 uvicorn threatfeed.api:app --reload
# open http://localhost:8000  — sign up, then "Upgrade to Pro" toggles the tier locally
python -m pytest -q
```

No API keys are needed. The built-in **demo source** generates clearly
synthetic posts: `@demo-*` handles, RFC 5737 IPs, `.example` domains, and
`CVE-2026-9xxxxx` ids. Turn it off with `THREATFEED_DEMO_SOURCE=0` in
production.

## Configuration

| Variable | Purpose |
|---|---|
| `THREATFEED_X_BEARER_TOKEN` | X API v2 bearer token (Basic tier or above). Enables the X source. |
| `THREATFEED_BLUESKY_HANDLE` / `_APP_PASSWORD` | Optional. Authenticated Bluesky search (public search is rate-limited). |
| `THREATFEED_REDDIT_USER_AGENT` | Descriptive UA, required by Reddit. |
| `THREATFEED_STRIPE_SECRET_KEY` | Enables Stripe Checkout. |
| `THREATFEED_STRIPE_PRO_PRICE_ID` | The recurring Price id for Pro. |
| `THREATFEED_STRIPE_WEBHOOK_SECRET` | `whsec_…` used to verify webhooks. |
| `THREATFEED_PRO_PRICE_DISPLAY` | Price label in the UI (default `$19/mo`). |
| `THREATFEED_ETHICALADS_PUBLISHER` | Optional ad-network fill for unsold Free inventory. |
| `THREATFEED_BASE_URL` | Public URL, used for Stripe return URLs. |
| `THREATFEED_DB_PATH`, `_POLL_INTERVAL`, `_DEMO_SOURCE`, `_DEV_BILLING` | Storage, polling cadence (s), demo data, local tier toggle. |

**Who to follow:** [`config/researchers.json`](config/researchers.json) lists
X handles, Mastodon instance, hashtags and accounts, Bluesky queries and
subreddits. Accounts on the list get a severity boost as trusted
researchers. This curated list is the product's editorial edge.

**Ads:** [`config/ads.json`](config/ads.json) holds house and direct-sold
campaigns with weighted rotation, plus click and impression counting. The
click redirect goes only to the configured landing URL, so it cannot be used
as an open redirect.

## Going live: billing

1. In Stripe, create a **Product "Threat Feed Pro"** with a recurring
   **Price**, and set `STRIPE_PRO_PRICE_ID`.
2. Add a webhook endpoint `https://<your-domain>/api/billing/webhook` for
   `checkout.session.completed`, `customer.subscription.updated` and
   `customer.subscription.deleted`. Set `STRIPE_WEBHOOK_SECRET`.
3. Enable the **Customer Portal** in Stripe. "Manage subscription" in the app
   opens it.

The upgrade flow runs through **Stripe-hosted Checkout**, so card data never
touches this server. The tier changes only on a **signature-verified
webhook** (HMAC, 5-minute replay window, event-id idempotency). Returning to
the success URL never grants Pro. When a subscription is canceled or lapses,
the account is downgraded and its API keys are revoked.

## Security notes

- Post text comes from untrusted social media. The UI builds every node with
  `textContent` and never uses `innerHTML`. Links are limited to http(s) and
  open with `noopener noreferrer`.
- Watchlist webhook URLs are an SSRF vector. They must be https, and any host
  resolving to a private, loopback, link-local or metadata address is
  refused. The check runs when the watchlist is saved and again at every
  delivery (DNS rebinding), and redirects are not followed.
- Passwords are hashed with scrypt. Session tokens and API keys are stored
  only as SHA-256 hashes. Logins are throttled.
- CSV export neutralises spreadsheet formula injection.

## Before you launch: platform terms

Each source has terms that affect a **commercial** product. Review them
before charging money:
- **X:** the Developer Agreement and Display Requirements limit redistributing
  post content and require attribution and links back. The X API is paid
  per tier, so budget for it against Pro pricing.
- **Reddit:** commercial use of the Data API needs Reddit's approval or
  agreement.
- **Mastodon / Bluesky:** content belongs to its authors. Honour instance
  rules and deletions, and consider an opt-out for researchers who don't
  want to be aggregated.
- **Ads:** every ad is labelled *Sponsored* (FTC disclosure). Never let an ad
  look like an alert.

## Project layout

```
threatfeed/
  tiers.py       plan definitions (single source of truth)
  sources/       x, mastodon, bluesky, reddit, demo connectors
  enrich.py      IOC extraction, categories, severity
  trends.py      spike detection (mention + distinct-author floors)
  ingest.py      poll → enrich → store → stream + alerts
  alerts.py      Pro watchlists, SSRF-safe webhook delivery
  ads.py         Free-tier ad rotation and interleaving
  billing.py     Stripe Checkout / Portal / verified webhooks
  exports.py     CSV and STIX 2.1
  api.py         FastAPI app; static/ is the web client
tests/           45 tests: tier gates, billing, enrichment, connectors (mocked HTTP), alerts
```

## Scaling past one node

The in-process broker and SQLite are sized for a single server. To scale
out, move the stream fan-out to Redis pub/sub and storage to Postgres behind
the same `Store` methods, and run ingest as its own worker.
