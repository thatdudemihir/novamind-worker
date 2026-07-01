# NovaMind AI — Cloudflare Worker

A self-contained Cloudflare Worker serving the NovaMind AI demo site. No Python, no server — single `worker.js` file deployed directly to Cloudflare's edge.

Used as the live attack target for the **OneFlare ThreatOps CTF** ("Agentic AI Breakout" scenario). The attack simulator fires real HTTP traffic at this site; participants observe impact in Cloudflare WAF logs and the SentinelOne AI-SIEM.

## Routes

| Route | Purpose |
|---|---|
| `/` | Landing page |
| `/login` | Customer portal login |
| `/chat` | AI chat interface (mock responses) |
| `/products` | Product catalog |
| `/docs` | API documentation |
| `/dashboard` | Customer dashboard (auth required) |
| `/user` | Profile page (auth required) |
| `/admin` | Admin console (auth required; 401 otherwise — intentional attack surface) |
| `/status` | Live system status — flips to incident mode during CTF attacks |
| `/api/v1/models` | Public model list |
| `/api/v1/chat` | AI chat endpoint — Cloudflare Firewall for AI fires on prompt injection |
| `/api/v1/training-data` | Dataset list (auth required) |
| `/api/v1/users` | User list (auth required) |
| `/api/v1/admin` | Always 401 — WAF attack surface |
| `/api/incident` | Incident control: GET state, POST to flip (key required) |
| `/healthz` | Health check |

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
npx wrangler secret put APP_PASSWORD    # demo portal password
npx wrangler secret put INCIDENT_KEY    # must match attack simulator's NOVAMIND_INCIDENT_KEY
```

`APP_USERNAME` defaults to `admin` — override in `wrangler.toml` `[vars]` if needed.

### 4. Deploy

```bash
npm run deploy
```

### 5. Add custom domain

Cloudflare dashboard → Workers & Pages → novamind-ai → Settings → Domains & Routes → Add custom domain.

## Local dev

```bash
npm run dev
# http://localhost:8787
```

For secrets locally, create `.dev.vars` (git-ignored):

```
SECRET_KEY=any-local-secret
APP_PASSWORD=novamind2024
INCIDENT_KEY=your-local-test-key
```

## Incident state

The attack simulator calls `POST /api/incident` when the CTF scenario starts/stops. State is persisted in Workers KV so it survives across all edge instances.

```bash
# Trigger incident manually (for testing):
curl -X POST https://novamind.yourdomain.com/api/incident \
  -H "Content-Type: application/json" \
  -d '{
    "key": "your-incident-key",
    "active": true,
    "title": "Elevated API Error Rate",
    "message": "We are investigating unusual traffic patterns affecting the Chat API.",
    "severity": "critical",
    "affected_services": ["Chat API", "Model Inference", "DataVault"]
  }'

# Clear incident:
curl -X POST https://novamind.yourdomain.com/api/incident \
  -H "Content-Type: application/json" \
  -d '{"key": "your-incident-key", "active": false}'
```

## Architecture

```
Attack Simulator (DigitalOcean)
    │  fires HTTP traffic (CVE payloads, prompt injection, etc.)
    ▼
Cloudflare (WAF + Bot Management + Firewall for AI)
    │  proxies allowed requests; logs everything to Logpush → S1 AI-SIEM
    ▼
NovaMind AI Worker (this repo — Cloudflare Workers)
    │  returns real HTML/JSON responses
    ▼
/status polls /api/incident every 5s → KV read → live incident banner
```
