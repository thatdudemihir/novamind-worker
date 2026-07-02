# SoleDrop — Cloudflare Worker

A self-contained Cloudflare Worker serving the **SoleDrop** sneaker-drop storefront. No Python, no server — a single `worker.js` file deployed directly to Cloudflare's edge.

Doubles as the live attack target for the **ThreatOps CTF** ("Drop-Day Bot Swarm" scenario). The attack simulator fires real HTTP traffic at this site; participants observe impact in Cloudflare WAF / Bot Management logs and the SentinelOne AI-SIEM, then work the remediation checklist on `/status`.

## Routes

| Route | Purpose |
|---|---|
| `/` | Storefront — hero, **live drop countdown**, product grid |
| `/products` | Full sneaker catalog |
| `/drops` | Release calendar |
| `/login` | Customer sign-in |
| `/chat` | SoleDrop Concierge (support chat, mock responses; auth required) |
| `/dashboard` | Member account — Heat Points, raffles, orders (auth required) |
| `/user` | Profile page (auth required) |
| `/admin` | Admin console (auth required; 401 otherwise — intentional attack surface) |
| `/status` | Live system status — flips to incident mode during CTF attacks |
| `/api/v1/products` | Public product list |
| `/api/v1/chat` | Concierge endpoint — prompt-injection attack surface |
| `/api/v1/customers` | Customer list (auth required) — bulk-exfil target |
| `/api/v1/users` | User list (auth required) |
| `/api/v1/admin` | Always 401 — WAF attack surface |
| `/api/incident` | Incident control: GET state, POST to flip (key required) |
| `/healthz` | Health check |

> **Back-compat:** the CTF simulator's original paths (`/api/v1/models`, `/api/v1/training-data`) are still served as aliases so existing attack scripts keep working unchanged.

## Deploy

### 1. Install Wrangler

```bash
npm install
```

### 2. Create the KV namespace

```bash
npx wrangler kv namespace create INCIDENT_KV
npx wrangler kv namespace create INCIDENT_KV --preview
```

Paste both IDs into `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "INCIDENT_KV"
id = "your-namespace-id"
preview_id = "your-preview-namespace-id"
```

### 3. Set secrets

```bash
npx wrangler secret put SECRET_KEY      # openssl rand -hex 32
npx wrangler secret put APP_PASSWORD    # demo store password
npx wrangler secret put INCIDENT_KEY    # must match the attack simulator's incident key
```

`APP_USERNAME` defaults to `admin` — override in `wrangler.toml` `[vars]` if needed.

### 4. Deploy

```bash
npm run deploy
```

### 5. Add custom domain

Cloudflare dashboard → Workers & Pages → **soledrop** → Settings → Domains & Routes → Add custom domain → `shop.soledrop.co` (the apex `soledrop.co` is reserved for a separate landing page).

## Local dev

```bash
npm run dev
# http://localhost:8787
```

For secrets locally, create `.dev.vars` (git-ignored):

```
SECRET_KEY=any-local-secret
APP_PASSWORD=soledrop
INCIDENT_KEY=your-local-test-key
```

## Incident state

The attack simulator calls `POST /api/incident` when the CTF scenario starts/stops. State is persisted in Workers KV so it survives across all edge instances. `/status` polls `/api/incident` every 5s and flips into incident mode.

Valid `affected_services` values (match the status page service list): `Storefront`, `Checkout API`, `Inventory`, `Customer Accounts`, `Search`, `CDN`.

```bash
# Trigger incident manually (for testing):
curl -X POST https://shop.soledrop.co/api/incident \
  -H "Content-Type: application/json" \
  -d '{
    "key": "your-incident-key",
    "active": true,
    "title": "Drop-Day Bot Swarm Detected",
    "message": "We are mitigating automated traffic affecting checkout. Real customers may see a waiting room.",
    "severity": "critical",
    "affected_services": ["Storefront", "Checkout API", "Customer Accounts"]
  }'

# Clear incident:
curl -X POST https://shop.soledrop.co/api/incident \
  -H "Content-Type: application/json" \
  -d '{"key": "your-incident-key", "active": false}'
```

## Architecture

```
Attack Simulator (bot swarm / credential stuffing / carding)
    │  fires HTTP traffic at the drop
    ▼
Cloudflare (WAF + Bot Management (JA4) + Rate Limiting + Waiting Room)
    │  proxies allowed requests; logs everything to Logpush → S1 AI-SIEM
    ▼
SoleDrop Worker (this repo — Cloudflare Workers)
    │  returns real HTML/JSON responses
    ▼
/status polls /api/incident every 5s → KV read → live incident banner + timeline
```
