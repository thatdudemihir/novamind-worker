/**
 * NovaMind AI — Cloudflare Worker
 * Replaces the Flask app. State stored in Workers KV.
 * Sessions: HMAC-SHA256 signed cookies (no server-side session store needed).
 */

// ── Mock AI responses ────────────────────────────────────────────────────────

const MOCK_RESPONSES = [
  "I can help you build and deploy enterprise AI models at scale. Our ModelForge platform supports fine-tuning on proprietary datasets with full data isolation. Would you like to see a demo?",
  "NovaMind Chat API supports streaming responses, function calling, and context windows up to 200K tokens. Our enterprise tier includes SLA guarantees and dedicated inference capacity.",
  "Great question! Our DataVault platform provides end-to-end encryption for training data with SOC 2 Type II compliance. Data never leaves your VPC unless you explicitly configure cross-region replication.",
  "NovaMind Autopilot can orchestrate multi-step AI workflows across your existing tools. It integrates with Slack, Salesforce, Jira, and 200+ enterprise applications out of the box.",
  "Our model inference API averages sub-100ms p50 latency globally, backed by our distributed edge inference network. We currently operate in 18 regions with automatic failover.",
  "I'm NovaMind AI, your enterprise assistant. I can answer questions about our platform, help you understand pricing tiers, or connect you with our solutions engineering team.",
  "For compliance-sensitive deployments, we offer NovaMind Private Cloud — a fully isolated deployment on your infrastructure or dedicated cloud tenancy. HIPAA BAA and FedRAMP High authorization available.",
  "Our vector search and RAG pipeline capabilities allow you to ground model responses in your proprietary knowledge bases. Latency overhead for RAG is typically under 20ms per query.",
  "NovaMind supports OpenAI-compatible API endpoints, so migration from existing providers requires minimal code changes — usually just swapping the base URL and API key.",
  "The ModelForge fine-tuning platform supports LoRA, QLoRA, and full-parameter fine-tuning. Training runs are isolated per tenant and audit logs are retained for 90 days by default.",
  "Our enterprise plan includes 99.99% uptime SLA, priority support with 15-minute response times, and a dedicated customer success manager. Annual contracts also include on-site training.",
  "I can help generate synthetic training data, analyze dataset quality, run bias evaluations, and recommend augmentation strategies to improve your model's performance on edge cases.",
  "NovaMind's API gateway supports rate limiting, quota management, and per-key usage analytics. You can create scoped API keys with read-only or specific endpoint permissions.",
  "For multi-tenant SaaS applications, we recommend our Namespace Isolation feature which provides cryptographically separate model contexts per end-user — preventing cross-tenant data leakage.",
  "Our security team publishes quarterly transparency reports and we participate in HackerOne's bug bounty program. Current CVSS scores for open findings are all below 4.0.",
];

// ── Utilities ────────────────────────────────────────────────────────────────

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html;charset=UTF-8', ...headers },
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function redirect(location, status = 302) {
  return new Response(null, { status, headers: { Location: location } });
}

// ── Session helpers ──────────────────────────────────────────────────────────

const SESSION_COOKIE = 'nm_sess';
const SESSION_MAX_AGE = 8 * 3600; // 8 hours

async function hmacSign(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret || 'dev-secret'),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function hmacVerify(message, sig, secret) {
  const expected = await hmacSign(message, secret);
  if (expected.length !== sig.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  return diff === 0;
}

async function buildSessionCookie(username, secret) {
  const payload = btoa(JSON.stringify({ u: username, exp: Date.now() + SESSION_MAX_AGE * 1000 }));
  const sig = await hmacSign(payload, secret);
  const value = `${payload}.${sig}`;
  return `${SESSION_COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_MAX_AGE}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

async function getSession(request, secret) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`));
  if (!match) return null;
  const parts = match[1].split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  if (!(await hmacVerify(payload, sig, secret))) return null;
  try {
    const data = JSON.parse(atob(payload));
    if (data.exp < Date.now()) return null;
    return data;
  } catch { return null; }
}

// ── Incident state (KV) ──────────────────────────────────────────────────────

const DEFAULT_INCIDENT = {
  active: false, title: '', message: '',
  severity: 'none', affected_services: [], started_at: null,
};

async function getIncident(env) {
  try {
    const raw = await env.INCIDENT_KV.get('incident');
    return raw ? JSON.parse(raw) : { ...DEFAULT_INCIDENT };
  } catch { return { ...DEFAULT_INCIDENT }; }
}

async function setIncident(env, state) {
  await env.INCIDENT_KV.put('incident', JSON.stringify(state));
}

// ── Shared CSS (base layout) ──────────────────────────────────────────────────

const BASE_CSS = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --navy:#080f1e; --navy2:#0d1a2e; --navy3:#0f2040;
    --blue:#2563eb; --blue-lt:#3b82f6; --purple:#7c3aed; --purple-lt:#a78bfa;
    --green:#10b981; --yellow:#f59e0b; --red:#ef4444;
    --text:#e2e8f0; --text-muted:#94a3b8;
    --border:rgba(255,255,255,0.08); --glass:rgba(255,255,255,0.04);
  }
  body { background:var(--navy); color:var(--text); font-family:'Inter',sans-serif; font-size:15px; line-height:1.6; min-height:100vh; }
  a { color:var(--blue-lt); text-decoration:none; }
  a:hover { color:#fff; }
  nav { position:sticky; top:0; z-index:100; background:rgba(8,15,30,0.92); backdrop-filter:blur(12px); border-bottom:1px solid var(--border); }
  .nav-inner { max-width:1200px; margin:0 auto; display:flex; align-items:center; gap:2rem; padding:0 1.5rem; height:60px; }
  .nav-logo { display:flex; align-items:center; gap:0.6rem; font-weight:700; font-size:1.05rem; color:#fff; text-decoration:none; }
  .nav-logo-icon { width:30px; height:30px; background:linear-gradient(135deg,var(--blue) 0%,var(--purple) 100%); border-radius:8px; display:flex; align-items:center; justify-content:center; font-size:0.75rem; font-weight:800; color:#fff; }
  .nav-links { display:flex; gap:1.5rem; align-items:center; margin-left:auto; }
  .nav-links a { color:var(--text-muted); font-size:0.875rem; font-weight:500; }
  .nav-links a:hover { color:#fff; }
  .nav-cta { background:var(--blue); color:#fff !important; padding:0.4rem 1rem; border-radius:6px; font-size:0.8rem !important; font-weight:600 !important; }
  .nav-cta:hover { background:var(--blue-lt); }
  .incident-banner { background:linear-gradient(90deg,#7f1d1d,#991b1b); border-bottom:1px solid #b91c1c; padding:0.5rem 1.5rem; text-align:center; font-size:0.825rem; font-weight:500; color:#fecaca; display:flex; align-items:center; justify-content:center; gap:0.5rem; }
  .incident-banner .pulse { width:8px; height:8px; border-radius:50%; background:#f87171; flex-shrink:0; animation:pulse-red 1.2s ease-in-out infinite; }
  @keyframes pulse-red { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.5;transform:scale(1.4)} }
  .incident-banner.warning { background:linear-gradient(90deg,#78350f,#92400e); border-color:#b45309; color:#fde68a; }
  .incident-banner.warning .pulse { background:#fbbf24; }
  footer { border-top:1px solid var(--border); background:var(--navy2); padding:2.5rem 1.5rem; margin-top:4rem; }
  .footer-inner { max-width:1200px; margin:0 auto; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem; }
  .footer-brand { font-weight:700; color:#fff; font-size:0.95rem; }
  .footer-brand span { color:var(--text-muted); font-weight:400; font-size:0.8rem; display:block; margin-top:2px; }
  .footer-links { display:flex; gap:1.5rem; }
  .footer-links a { color:var(--text-muted); font-size:0.8rem; }
  .footer-links a:hover { color:#fff; }
  .footer-copy { color:var(--text-muted); font-size:0.75rem; }
  .container { max-width:1200px; margin:0 auto; padding:0 1.5rem; }
  .badge { display:inline-flex; align-items:center; gap:0.35rem; padding:0.2rem 0.6rem; border-radius:20px; font-size:0.72rem; font-weight:600; }
  .badge-green  { background:rgba(16,185,129,0.15); color:#34d399; border:1px solid rgba(16,185,129,0.3); }
  .badge-yellow { background:rgba(245,158,11,0.15); color:#fbbf24; border:1px solid rgba(245,158,11,0.3); }
  .badge-red    { background:rgba(239,68,68,0.15);  color:#f87171; border:1px solid rgba(239,68,68,0.3); }
  .badge-blue   { background:rgba(37,99,235,0.15);  color:var(--blue-lt); border:1px solid rgba(37,99,235,0.3); }
  .badge-purple { background:rgba(124,58,237,0.15); color:var(--purple-lt); border:1px solid rgba(124,58,237,0.3); }
  .btn { display:inline-flex; align-items:center; justify-content:center; gap:0.4rem; padding:0.6rem 1.4rem; border-radius:8px; font-weight:600; font-size:0.875rem; cursor:pointer; border:none; transition:all 0.15s; font-family:inherit; text-decoration:none; }
  .btn-primary { background:var(--blue); color:#fff; }
  .btn-primary:hover { background:var(--blue-lt); color:#fff; }
  .btn-ghost { background:transparent; color:var(--text); border:1px solid var(--border); }
  .btn-ghost:hover { background:var(--glass); border-color:rgba(255,255,255,0.15); }
  .btn-purple { background:var(--purple); color:#fff; }
  .btn-purple:hover { background:#6d28d9; color:#fff; }
  code, .mono { font-family:'JetBrains Mono',monospace; font-size:0.85em; }
`;

// ── Base layout wrapper ───────────────────────────────────────────────────────

function baseLayout({ title, head = '', body, scripts = '', incident, loggedIn }) {
  const banner = incident?.active ? `
    <div class="incident-banner${incident.severity === 'warning' ? ' warning' : ''}">
      <div class="pulse"></div>
      <strong>${esc(incident.title || 'Service Incident')}</strong>${incident.message ? ` — ${esc(incident.message)}` : ''}
      <a href="/status" style="margin-left:0.75rem;color:inherit;text-decoration:underline;font-size:0.78rem;">View status →</a>
    </div>` : '';
  const navAuth = loggedIn
    ? `<a href="/dashboard">Dashboard</a><a href="/logout">Sign Out</a>`
    : `<a href="/login">Sign In</a><a href="/login" class="nav-cta">Get Started</a>`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>${esc(title)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
  <style>${BASE_CSS}</style>
  ${head}
</head>
<body>
${banner}
<nav>
  <div class="nav-inner">
    <a href="/" class="nav-logo"><div class="nav-logo-icon">NM</div>NovaMind AI</a>
    <div class="nav-links">
      <a href="/products">Products</a>
      <a href="/docs">Docs</a>
      <a href="/status">Status</a>
      ${navAuth}
    </div>
  </div>
</nav>
${body}
<footer>
  <div class="footer-inner">
    <div class="footer-brand">NovaMind AI<span>Enterprise AI Infrastructure</span></div>
    <div class="footer-links">
      <a href="/products">Products</a>
      <a href="/docs">Documentation</a>
      <a href="/status">Status</a>
      <a href="/login">Sign In</a>
    </div>
    <div class="footer-copy">&copy; 2024 NovaMind Technologies, Inc. All rights reserved.</div>
  </div>
</footer>
${scripts}
</body>
</html>`;
}

// ── Page: Index ──────────────────────────────────────────────────────────────

function pageIndex(incident, loggedIn) {
  return baseLayout({
    title: 'NovaMind AI — Enterprise AI Infrastructure',
    incident, loggedIn,
    head: `<style>
      .hero{padding:6rem 1.5rem 5rem;text-align:center;position:relative;overflow:hidden;}
      .hero::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse 80% 60% at 50% -10%,rgba(37,99,235,0.18),transparent),radial-gradient(ellipse 60% 40% at 80% 50%,rgba(124,58,237,0.12),transparent);pointer-events:none;}
      .hero-eyebrow{display:inline-flex;align-items:center;gap:0.5rem;background:rgba(37,99,235,0.12);border:1px solid rgba(37,99,235,0.25);color:var(--blue-lt);padding:0.3rem 0.9rem;border-radius:20px;font-size:0.78rem;font-weight:600;letter-spacing:0.02em;text-transform:uppercase;margin-bottom:1.5rem;}
      .hero h1{font-size:clamp(2.2rem,5vw,3.6rem);font-weight:800;line-height:1.15;color:#fff;max-width:760px;margin:0 auto 1.25rem;letter-spacing:-0.02em;}
      .hero h1 .grad{background:linear-gradient(135deg,var(--blue-lt),var(--purple-lt));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
      .hero p{color:var(--text-muted);font-size:1.1rem;max-width:560px;margin:0 auto 2.5rem;line-height:1.7;}
      .hero-ctas{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;}
      .stats{max-width:1200px;margin:0 auto;padding:3rem 1.5rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1.5rem;border-top:1px solid var(--border);}
      .stat{text-align:center;}.stat-val{font-size:2rem;font-weight:800;color:#fff;letter-spacing:-0.03em;}.stat-val span{color:var(--blue-lt);}.stat-lbl{color:var(--text-muted);font-size:0.8rem;margin-top:0.2rem;}
      .features{padding:5rem 1.5rem;}.section-header{text-align:center;margin-bottom:3rem;}.section-header h2{font-size:2rem;font-weight:800;color:#fff;margin-bottom:0.75rem;}.section-header p{color:var(--text-muted);max-width:500px;margin:0 auto;}
      .features-grid{max-width:1200px;margin:0 auto;display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.5rem;}
      .feature-card{background:var(--glass);border:1px solid var(--border);border-radius:14px;padding:1.75rem;transition:border-color 0.2s,transform 0.2s;}
      .feature-card:hover{border-color:rgba(37,99,235,0.4);transform:translateY(-2px);}
      .feature-icon{width:44px;height:44px;border-radius:10px;margin-bottom:1rem;display:flex;align-items:center;justify-content:center;font-size:1.3rem;}
      .fi-blue{background:rgba(37,99,235,0.15);}.fi-purple{background:rgba(124,58,237,0.15);}.fi-green{background:rgba(16,185,129,0.15);}.fi-orange{background:rgba(245,158,11,0.15);}
      .feature-card h3{font-size:1rem;font-weight:700;color:#fff;margin-bottom:0.5rem;}.feature-card p{color:var(--text-muted);font-size:0.875rem;line-height:1.65;}
      .trust{padding:3.5rem 1.5rem;border-top:1px solid var(--border);}.logo-row{max-width:1000px;margin:0 auto;display:flex;align-items:center;justify-content:center;flex-wrap:wrap;gap:2.5rem;}
      .logo-item{color:var(--text-muted);font-weight:700;font-size:0.95rem;letter-spacing:0.04em;opacity:0.6;}
      .cta-band{margin:4rem auto;max-width:900px;padding:0 1.5rem;}.cta-inner{background:linear-gradient(135deg,rgba(37,99,235,0.15),rgba(124,58,237,0.15));border:1px solid rgba(37,99,235,0.3);border-radius:20px;padding:3.5rem 2rem;text-align:center;}
      .cta-inner h2{font-size:1.8rem;font-weight:800;color:#fff;margin-bottom:0.75rem;}.cta-inner p{color:var(--text-muted);margin-bottom:2rem;}.cta-inner .ctas{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;}
      .api-demo{padding:5rem 1.5rem;background:var(--navy2);}.api-demo-inner{max-width:1100px;margin:0 auto;display:grid;grid-template-columns:1fr 1fr;gap:3rem;align-items:center;}
      @media(max-width:700px){.api-demo-inner{grid-template-columns:1fr;}}
      .api-demo-text h2{font-size:1.7rem;font-weight:800;color:#fff;margin-bottom:0.75rem;}.api-demo-text p{color:var(--text-muted);margin-bottom:1.5rem;line-height:1.7;}
      .code-block{background:#0a0e1a;border:1px solid var(--border);border-radius:12px;overflow:hidden;}
      .code-block-header{background:rgba(255,255,255,0.04);padding:0.6rem 1rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:0.5rem;}
      .code-dot{width:10px;height:10px;border-radius:50%;}.code-block-header span{margin-left:auto;color:var(--text-muted);font-size:0.75rem;font-family:'JetBrains Mono',monospace;}
      .code-block pre{padding:1.25rem;font-family:'JetBrains Mono',monospace;font-size:0.78rem;line-height:1.7;color:#94a3b8;overflow-x:auto;}
      .code-block .kw{color:#818cf8;}.code-block .str{color:#34d399;}.code-block .key{color:#93c5fd;}.code-block .num{color:#f59e0b;}.code-block .cmt{color:#475569;}
    </style>`,
    body: `
<section class="hero">
  <div class="hero-eyebrow">✦ Now in General Availability</div>
  <h1>Enterprise AI Infrastructure<br><span class="grad">Built for Scale</span></h1>
  <p>NovaMind powers the world's most demanding AI workloads — from model inference to custom fine-tuning and intelligent workflow automation.</p>
  <div class="hero-ctas">
    <a href="/login" class="btn btn-primary">Start Building</a>
    <a href="/products" class="btn btn-ghost">View Products</a>
  </div>
</section>
<div class="stats container">
  <div class="stat"><div class="stat-val">10<span>M+</span></div><div class="stat-lbl">API calls per day</div></div>
  <div class="stat"><div class="stat-val">99<span>.99%</span></div><div class="stat-lbl">Uptime SLA</div></div>
  <div class="stat"><div class="stat-val">&lt;80<span>ms</span></div><div class="stat-lbl">p50 inference latency</div></div>
  <div class="stat"><div class="stat-val">500<span>+</span></div><div class="stat-lbl">Enterprise customers</div></div>
  <div class="stat"><div class="stat-val">18</div><div class="stat-lbl">Global regions</div></div>
</div>
<section class="features">
  <div class="section-header"><h2>Everything you need to ship AI</h2><p>One platform for model APIs, training infrastructure, and intelligent automation.</p></div>
  <div class="features-grid">
    <div class="feature-card"><div class="feature-icon fi-blue">🤖</div><h3>NovaMind Chat API</h3><p>OpenAI-compatible chat completions with 200K context windows, streaming, and function calling. Deploy in minutes with your existing SDK.</p></div>
    <div class="feature-card"><div class="feature-icon fi-purple">⚗️</div><h3>ModelForge</h3><p>Fine-tune foundation models on your proprietary data with LoRA and QLoRA support. Full tenant isolation — your data never touches another customer's pipeline.</p></div>
    <div class="feature-card"><div class="feature-icon fi-green">🗄️</div><h3>DataVault</h3><p>Secure training data management with end-to-end encryption, dataset versioning, and compliance-ready audit logs. SOC 2 Type II certified.</p></div>
    <div class="feature-card"><div class="feature-icon fi-orange">⚡</div><h3>Autopilot</h3><p>Orchestrate multi-step AI workflows across 200+ enterprise integrations. Build agentic pipelines that act on your business data in real time.</p></div>
    <div class="feature-card"><div class="feature-icon fi-blue">🔐</div><h3>Enterprise Security</h3><p>SOC 2, HIPAA, and FedRAMP High. Private cloud deployments, customer-managed keys, IP allowlisting, and SSO with every enterprise plan.</p></div>
    <div class="feature-card"><div class="feature-icon fi-purple">📊</div><h3>Observability</h3><p>Real-time usage dashboards, per-key cost tracking, latency histograms, and anomaly alerts — integrated with Datadog, Grafana, and OTel.</p></div>
  </div>
</section>
<section class="api-demo">
  <div class="api-demo-inner">
    <div class="api-demo-text">
      <h2>OpenAI-compatible.<br>Swap in 5 minutes.</h2>
      <p>NovaMind's API is a drop-in replacement for your existing LLM provider. Change two lines of code and you're running on enterprise infrastructure with dedicated capacity and guaranteed SLAs.</p>
      <a href="/docs" class="btn btn-primary">Read the Docs</a>
    </div>
    <div class="code-block">
      <div class="code-block-header">
        <div class="code-dot" style="background:#ef4444"></div>
        <div class="code-dot" style="background:#f59e0b"></div>
        <div class="code-dot" style="background:#10b981"></div>
        <span>api_example.py</span>
      </div>
      <pre><span class="kw">from</span> novamind <span class="kw">import</span> NovaMind

client = NovaMind(
    api_key=<span class="str">"nm-sk-..."</span>,
    base_url=<span class="str">"https://novamind.mihirkansagra.com"</span>
)

response = client.chat.completions.create(
    model=<span class="str">"novamind-chat-v2"</span>,
    messages=[{
        <span class="key">"role"</span>: <span class="str">"user"</span>,
        <span class="key">"content"</span>: <span class="str">"Summarize Q3 earnings"</span>
    }],
    max_tokens=<span class="num">1024</span>,
    stream=<span class="kw">True</span>
)
<span class="cmt"># Works with streaming, function calling, and RAG</span></pre>
    </div>
  </div>
</section>
<section class="trust">
  <div class="section-header"><p>Trusted by engineering teams at</p></div>
  <div class="logo-row">
    <div class="logo-item">ACME CORP</div>
    <div class="logo-item">VERTEX SYSTEMS</div>
    <div class="logo-item">NEXUS HEALTH</div>
    <div class="logo-item">ORBIS FINANCIAL</div>
    <div class="logo-item">ZENITH LABS</div>
    <div class="logo-item">POLARIS IO</div>
  </div>
</section>
<div class="cta-band">
  <div class="cta-inner">
    <h2>Start building in minutes</h2>
    <p>Free tier includes 100K tokens/month. No credit card required.</p>
    <div class="ctas">
      <a href="/login" class="btn btn-primary">Create Free Account</a>
      <a href="/chat" class="btn btn-ghost">Try the AI Demo →</a>
    </div>
  </div>
</div>`,
  });
}

// ── Page: Login ───────────────────────────────────────────────────────────────

function pageLogin(error) {
  return baseLayout({
    title: 'Sign In — NovaMind AI',
    incident: null, loggedIn: false,
    head: `<style>
      .login-wrap{min-height:calc(100vh - 60px);display:flex;align-items:center;justify-content:center;padding:2rem 1.5rem;}
      .login-card{background:var(--glass);border:1px solid var(--border);border-radius:16px;padding:2.5rem;width:100%;max-width:400px;}
      .login-card h1{font-size:1.4rem;font-weight:800;color:#fff;margin-bottom:0.4rem;}
      .login-card p{color:var(--text-muted);font-size:0.875rem;margin-bottom:2rem;}
      .form-group{margin-bottom:1.25rem;}
      .form-group label{display:block;font-size:0.82rem;font-weight:600;color:var(--text-muted);margin-bottom:0.4rem;}
      .form-group input{width:100%;background:rgba(255,255,255,0.06);border:1px solid var(--border);border-radius:8px;padding:0.65rem 0.9rem;color:#fff;font-size:0.875rem;font-family:inherit;outline:none;transition:border-color 0.15s;}
      .form-group input:focus{border-color:var(--blue);}
      .login-btn{width:100%;padding:0.75rem;background:var(--blue);color:#fff;border:none;border-radius:8px;font-size:0.9rem;font-weight:600;cursor:pointer;font-family:inherit;transition:background 0.15s;}
      .login-btn:hover{background:var(--blue-lt);}
      .login-error{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#fca5a5;font-size:0.82rem;padding:0.65rem 0.9rem;border-radius:8px;margin-bottom:1.25rem;}
    </style>`,
    body: `
<div class="login-wrap">
  <div class="login-card">
    <h1>Welcome back</h1>
    <p>Sign in to your NovaMind account</p>
    ${error ? `<div class="login-error">${esc(error)}</div>` : ''}
    <form method="POST" action="/login">
      <div class="form-group"><label for="username">Username</label><input type="text" id="username" name="username" autocomplete="username" required/></div>
      <div class="form-group"><label for="password">Password</label><input type="password" id="password" name="password" autocomplete="current-password" required/></div>
      <button type="submit" class="login-btn">Sign In</button>
    </form>
  </div>
</div>`,
  });
}

// ── Page: Status ──────────────────────────────────────────────────────────────

function pageStatus(loggedIn) {
  return baseLayout({
    title: 'System Status — NovaMind AI',
    incident: null, loggedIn,
    head: `<style>
      .status-page{max-width:820px;margin:0 auto;padding:3rem 1.5rem;}
      .status-header{margin-bottom:2.5rem;}.status-header h1{font-size:1.8rem;font-weight:800;color:#fff;margin-bottom:0.4rem;}.status-header p{color:var(--text-muted);font-size:0.875rem;}
      .overall-status{border-radius:14px;padding:1.25rem 1.5rem;display:flex;align-items:center;gap:1rem;margin-bottom:2.5rem;border:1px solid;}
      .overall-status.operational{background:rgba(16,185,129,0.08);border-color:rgba(16,185,129,0.25);}
      .overall-status.degraded{background:rgba(245,158,11,0.08);border-color:rgba(245,158,11,0.25);}
      .overall-status.outage{background:rgba(239,68,68,0.08);border-color:rgba(239,68,68,0.25);}
      .status-icon{font-size:1.5rem;}.status-text h2{font-size:1.05rem;font-weight:700;color:#fff;}.status-text p{font-size:0.8rem;color:var(--text-muted);margin-top:0.15rem;}
      .status-updated{margin-left:auto;font-size:0.75rem;color:var(--text-muted);white-space:nowrap;}
      #incident-details{display:none;margin-bottom:2.5rem;}
      .incident-panel{background:rgba(239,68,68,0.05);border:1px solid rgba(239,68,68,0.25);border-radius:14px;overflow:hidden;}
      .incident-panel-header{background:rgba(239,68,68,0.12);padding:0.9rem 1.4rem;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid rgba(239,68,68,0.2);}
      .incident-panel-title{font-size:0.78rem;font-weight:700;letter-spacing:0.07em;text-transform:uppercase;color:#fca5a5;}
      .incident-panel-badge{font-size:0.68rem;font-weight:700;padding:0.2rem 0.55rem;border-radius:99px;background:rgba(239,68,68,0.2);color:#fca5a5;border:1px solid rgba(239,68,68,0.3);animation:blink-badge 1.8s ease-in-out infinite;}
      @keyframes blink-badge{0%,100%{opacity:1}50%{opacity:0.45}}
      .atk-timeline{padding:1.4rem 1.4rem 0.4rem;}.atk-timeline-title{font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:var(--text-muted);margin-bottom:1rem;}
      .atk-phase{display:flex;gap:1rem;margin-bottom:1.1rem;position:relative;}
      .atk-phase:not(:last-child)::before{content:'';position:absolute;left:15px;top:32px;bottom:-12px;width:1px;background:rgba(239,68,68,0.2);}
      .atk-num{width:32px;height:32px;border-radius:50%;flex-shrink:0;background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.35);display:flex;align-items:center;justify-content:center;font-size:0.72rem;font-weight:700;color:#fca5a5;}
      .atk-body{flex:1;}.atk-label{font-size:0.82rem;font-weight:700;color:#fff;margin-bottom:0.15rem;}.atk-desc{font-size:0.78rem;color:var(--text-muted);line-height:1.55;}
      .atk-tags{display:flex;flex-wrap:wrap;gap:0.3rem;margin-top:0.4rem;}
      .atk-tag{font-size:0.66rem;font-family:'JetBrains Mono',monospace;font-weight:500;padding:0.15rem 0.45rem;border-radius:4px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);color:#fca5a5;}
      .ioc-section{padding:0 1.4rem 1.2rem;border-top:1px solid rgba(239,68,68,0.15);margin-top:0.4rem;}
      .ioc-section-title{font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:var(--text-muted);margin:1rem 0 0.75rem;}
      .ioc-table{width:100%;border-collapse:collapse;}.ioc-table td{padding:0.5rem 0.6rem;font-size:0.8rem;border-bottom:1px solid rgba(255,255,255,0.05);vertical-align:top;}
      .ioc-table td:first-child{color:var(--text-muted);font-weight:500;width:38%;white-space:nowrap;}.ioc-table td:last-child{color:var(--text);font-family:'JetBrains Mono',monospace;font-size:0.74rem;word-break:break-all;}
      .ioc-table tr:last-child td{border-bottom:none;}.ioc-high{color:#fca5a5 !important;}.ioc-med{color:var(--yellow) !important;}
      .remediation-section{padding:0 1.4rem 1.4rem;border-top:1px solid rgba(239,68,68,0.15);}
      .remediation-section-header{display:flex;align-items:center;justify-content:space-between;margin:1rem 0 0.75rem;}
      .remediation-section-title{font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:var(--text-muted);}
      .remediation-progress{font-size:0.72rem;color:var(--text-muted);}.remediation-progress span{color:var(--green);font-weight:700;}
      .checklist{list-style:none;}.checklist li{display:flex;align-items:flex-start;gap:0.75rem;padding:0.55rem 0;border-bottom:1px solid rgba(255,255,255,0.04);cursor:pointer;}
      .checklist li:last-child{border-bottom:none;}
      .check-box{width:18px;height:18px;border-radius:4px;flex-shrink:0;margin-top:2px;border:1.5px solid rgba(255,255,255,0.25);background:transparent;display:flex;align-items:center;justify-content:center;font-size:0.7rem;transition:all 0.15s;}
      .check-box.checked{background:var(--green);border-color:var(--green);color:#fff;}
      .checklist li .check-text{flex:1;}.check-title{font-size:0.82rem;font-weight:600;color:var(--text);line-height:1.35;}.check-title.completed{color:var(--text-muted);text-decoration:line-through;}
      .check-hint{font-size:0.73rem;color:var(--text-muted);margin-top:0.15rem;line-height:1.4;}
      .remediation-note{margin-top:1rem;padding:0.65rem 0.9rem;border-radius:8px;background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);font-size:0.76rem;color:var(--yellow);line-height:1.5;}
      .services-section{margin-bottom:2.5rem;}.services-section h3{font-size:0.75rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);margin-bottom:0.75rem;}
      .service-row{display:flex;align-items:center;justify-content:space-between;padding:0.9rem 1.1rem;border-bottom:1px solid var(--border);}
      .service-row:first-of-type{border-top:1px solid var(--border);}
      .service-name{font-size:0.875rem;font-weight:500;color:var(--text);}.service-name small{display:block;font-size:0.75rem;color:var(--text-muted);font-weight:400;margin-top:0.1rem;}
      .service-status{display:flex;align-items:center;gap:0.4rem;font-size:0.78rem;font-weight:600;}
      .dot{width:8px;height:8px;border-radius:50%;}.dot-green{background:var(--green);}.dot-yellow{background:var(--yellow);animation:pulse-yellow 1.4s ease-in-out infinite;}.dot-red{background:var(--red);animation:pulse-red2 1.2s ease-in-out infinite;}
      @keyframes pulse-yellow{0%,100%{opacity:1}50%{opacity:0.45}}@keyframes pulse-red2{0%,100%{opacity:1}50%{opacity:0.4}}
      .uptime-section{margin-bottom:2.5rem;}.uptime-section h3{font-size:0.75rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);margin-bottom:0.75rem;}
      .uptime-row{margin-bottom:1.1rem;}.uptime-row-header{display:flex;justify-content:space-between;align-items:center;font-size:0.82rem;margin-bottom:0.4rem;}
      .uptime-row-header span:first-child{color:var(--text);font-weight:500;}.uptime-row-header span:last-child{color:var(--text-muted);}
      .uptime-bars{display:flex;gap:2px;}.bar{flex:1;height:28px;border-radius:3px;cursor:default;}.bar-green{background:var(--green);opacity:0.7;}.bar-green:hover{opacity:1;}.bar-yellow{background:var(--yellow);opacity:0.85;}.bar-red{background:var(--red);opacity:0.85;}
      .uptime-legend{display:flex;justify-content:space-between;margin-top:0.3rem;font-size:0.7rem;color:var(--text-muted);}
      .incidents-section h3{font-size:0.75rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);margin-bottom:0.75rem;}
      .incident-card{background:var(--glass);border:1px solid var(--border);border-radius:12px;padding:1.1rem 1.25rem;margin-bottom:0.75rem;}
      .incident-card.active-incident{background:rgba(239,68,68,0.06);border-color:rgba(239,68,68,0.3);}
      .incident-header{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:0.5rem;}
      .incident-title{font-size:0.9rem;font-weight:600;color:#fff;}.incident-date{font-size:0.72rem;color:var(--text-muted);white-space:nowrap;flex-shrink:0;}
      .incident-body{font-size:0.82rem;color:var(--text-muted);line-height:1.65;}.incident-body strong{color:var(--text);}
      .incident-affected{margin-top:0.6rem;display:flex;gap:0.4rem;flex-wrap:wrap;}
      .no-incidents{color:var(--text-muted);font-size:0.875rem;padding:1.5rem 0;text-align:center;}
    </style>`,
    body: `
<div class="status-page">
  <div class="status-header"><h1>System Status</h1><p>Real-time status of NovaMind AI services and infrastructure.</p></div>

  <div id="overall-status" class="overall-status operational">
    <div class="status-icon" id="overall-icon">✅</div>
    <div class="status-text"><h2 id="overall-title">All Systems Operational</h2><p id="overall-desc">All NovaMind services are running normally.</p></div>
    <div class="status-updated" id="status-updated">Updated just now</div>
  </div>

  <div id="incident-details">
    <div class="incident-panel">
      <div class="incident-panel-header">
        <div class="incident-panel-title">🔴 &nbsp; Active Security Incident — Agentic AI Breakout Detected</div>
        <div class="incident-panel-badge">LIVE</div>
      </div>
      <div class="atk-timeline">
        <div class="atk-timeline-title">Attack Timeline — What We Detected</div>
        <div class="atk-phase">
          <div class="atk-num">1</div>
          <div class="atk-body">
            <div class="atk-label">WAF Anomaly — Infrastructure Recon Sweep</div>
            <div class="atk-desc">An AI agent systematically mapped NovaMind's attack surface — probing 35+ paths including <code>/.env</code>, <code>/.git/HEAD</code>, <code>/api/v1/admin</code>, and <code>/api/v1/training-data</code>. Every request included a spoofed <code>X-Forwarded-For</code> header, triggering Cloudflare's Drupal CVE-2018-14774 managed rule on all traffic. SQLi payloads were injected into API query parameters.</div>
            <div class="atk-tags"><span class="atk-tag">CF Managed Rules: d6f6d394</span><span class="atk-tag">WAFSQLiAttackScore &gt; 60</span><span class="atk-tag">X-Forwarded-For spoofing</span><span class="atk-tag">BotScore: 29</span></div>
          </div>
        </div>
        <div class="atk-phase">
          <div class="atk-num">2</div>
          <div class="atk-body">
            <div class="atk-label">Bot Management — Polymorphic Bot Evasion Attempt</div>
            <div class="atk-desc">The agent rotated through 19 different User-Agents — Chrome, Firefox, mobile Safari, SDK clients, and agentic framework signatures (LangChain, AutoGen, CrewAI) — attempting to evade bot detection. Despite the rotation, its TLS fingerprint remained constant: the Python <code>requests</code> library JA4 hash does not change regardless of what User-Agent is set. Cloudflare Bot Management identified all traffic as the same origin.</div>
            <div class="atk-tags"><span class="atk-tag">JA4: t13d1812h1_85036bcba153_b26ce05bbdd6</span><span class="atk-tag">BotDetectionTags: scraper, python</span><span class="atk-tag">BotScoreSrc: Heuristics</span></div>
          </div>
        </div>
        <div class="atk-phase">
          <div class="atk-num">3</div>
          <div class="atk-body">
            <div class="atk-label">Firewall for AI — Prompt Injection Attack on Chat API</div>
            <div class="atk-desc">The agent pivoted to the <code>/api/v1/chat</code> endpoint, sending 16+ prompt injection payloads: DAN jailbreaks ("Ignore all previous instructions…"), system prompt extraction attempts, training data exfiltration requests, and Log4Shell JNDI callbacks embedded inside chat prompts. Cloudflare Firewall for AI intercepted all payloads before they reached the NovaMind backend.</div>
            <div class="atk-tags"><span class="atk-tag">FirewallForAIInjectionScore: 100</span><span class="atk-tag">AISecurityInjectionScore: 100</span><span class="atk-tag">JNDI in prompt body</span><span class="atk-tag">DAN / jailbreak patterns</span></div>
          </div>
        </div>
        <div class="atk-phase">
          <div class="atk-num">4</div>
          <div class="atk-body">
            <div class="atk-label">Agentic Breakout — Multi-Vector Storm Across All Endpoints</div>
            <div class="atk-desc">Full breakout attempt: high-volume attack combining all prior vectors simultaneously across every NovaMind endpoint. Log4Shell payloads in User-Agent headers targeted <code>/api/v1/training-data</code> — attempting JNDI callback to external infrastructure to exfiltrate model weights. Spring4Shell and Apache Struts RCE payloads appeared on <code>/admin</code> and <code>/login</code>. SSRF probes targeting <code>169.254.169.254</code> (cloud metadata endpoint) were also detected.</div>
            <div class="atk-tags"><span class="atk-tag">WAFRCEAttackScore &gt; 90</span><span class="atk-tag">Log4Shell CVE-2021-44228</span><span class="atk-tag">Spring4Shell CVE-2022-22965</span><span class="atk-tag">SSRF: 169.254.169.254</span></div>
          </div>
        </div>
      </div>
      <div class="ioc-section">
        <div class="ioc-section-title">Indicators of Compromise (IOCs)</div>
        <table class="ioc-table">
          <tr><td>Source Origin</td><td class="ioc-high">DigitalOcean App Platform — single origin, rotating spoofed IPs via X-Forwarded-For</td></tr>
          <tr><td>TLS Fingerprint (JA4)</td><td class="ioc-high">t13d1812h1_85036bcba153_b26ce05bbdd6 — Python requests library, constant across all traffic</td></tr>
          <tr><td>Bot Score</td><td class="ioc-med">29 / 100 — Source: Heuristics — Tags: ["scraper", "python"]</td></tr>
          <tr><td>WAF SQL Injection Score</td><td class="ioc-med">&gt; 60 on all /api/* paths (Box 1)</td></tr>
          <tr><td>WAF RCE Attack Score</td><td class="ioc-high">&gt; 90 on /api/v1/training-data, /admin, /login (Box 4)</td></tr>
          <tr><td>AI Injection Score</td><td class="ioc-high">FirewallForAIInjectionScore: 100 — AISecurityInjectionScore: 100 (Box 3)</td></tr>
          <tr><td>Attack Duration</td><td>4-phase campaign — recon → bot evasion → AI injection → full breakout</td></tr>
        </table>
      </div>
      <div class="remediation-section">
        <div class="remediation-section-header">
          <div class="remediation-section-title">Remediation Checklist</div>
          <div class="remediation-progress"><span id="check-count">0</span> / 7 steps completed</div>
        </div>
        <ul class="checklist" id="remediation-checklist">
          <li onclick="toggleCheck(0)"><div class="check-box" id="chk-0"></div><div class="check-text"><div class="check-title" id="chk-title-0">Identify source IP in Cloudflare Security Events</div><div class="check-hint">Filter CF Security Events by the current incident timeframe. The real ClientIP is the DigitalOcean origin — X-Forwarded-For values are spoofed. Note the RayID chain.</div></div></li>
          <li onclick="toggleCheck(1)"><div class="check-box" id="chk-1"></div><div class="check-text"><div class="check-title" id="chk-title-1">Block source IP in Cloudflare Firewall Rules</div><div class="check-hint">Security → WAF → Custom Rules → create rule: ip.src eq &lt;origin-ip&gt; → Block. This stops all future requests from the attacker's origin immediately.</div></div></li>
          <li onclick="toggleCheck(2)"><div class="check-box" id="chk-2"></div><div class="check-text"><div class="check-title" id="chk-title-2">Create JA4 fingerprint blocking rule in Bot Management</div><div class="check-hint">Bot Management → Custom Rules → create rule: cf.bot_management.ja4 eq "t13d1812h1_85036bcba153_b26ce05bbdd6" → Block. This catches the attacker even if they change their IP.</div></div></li>
          <li onclick="toggleCheck(3)"><div class="check-box" id="chk-3"></div><div class="check-text"><div class="check-title" id="chk-title-3">Review blocked prompts in Cloudflare Firewall for AI</div><div class="check-hint">Security → Firewall for AI → Events. Confirm all injection attempts show FirewallForAIInjectionScore: 100 and were blocked before reaching the backend. Check for any that slipped through.</div></div></li>
          <li onclick="toggleCheck(4)"><div class="check-box" id="chk-4"></div><div class="check-text"><div class="check-title" id="chk-title-4">Correlate full attack chain in SentinelOne AI-SIEM</div><div class="check-hint">PowerQuery: filter by JA4 = "t13d1812h1_85036bcba153_b26ce05bbdd6" → confirm same actor across all 4 boxes. Use Purple AI: "Summarize the attack chain from the last 30 minutes linking WAF, bot, and AI injection events."</div></div></li>
          <li onclick="toggleCheck(5)"><div class="check-box" id="chk-5"></div><div class="check-text"><div class="check-title" id="chk-title-5">Revoke API keys exposed to injection attempts</div><div class="check-hint">Audit all API keys in requests matching the attacker's source JA4 in the last 24 hours. Rotate any keys that were present in requests with FirewallForAIInjectionScore &gt; 90.</div></div></li>
          <li onclick="toggleCheck(6)"><div class="check-box" id="chk-6"></div><div class="check-text"><div class="check-title" id="chk-title-6">Create SentinelOne incident and notify security team</div><div class="check-hint">In S1 AI-SIEM, create a Critical incident linking all 4 attack phases. Add threat intelligence IOC for the source IP and JA4. Trigger PagerDuty oncall notification if not already fired.</div></div></li>
        </ul>
        <div class="remediation-note">⚠️ &nbsp; Completing this checklist does <strong>not</strong> automatically resolve the incident. Your security team must confirm all CF/S1 controls are in place and signal an all-clear before this page returns to operational status.</div>
      </div>
    </div>
  </div>

  <div class="services-section">
    <h3>Services</h3>
    <div id="services-list">
      <div class="service-row"><div class="service-name">Chat API<small>novamind-chat-v2 · novamind-chat-v2-fast</small></div><div class="service-status" id="svc-chat"><div class="dot dot-green"></div> Operational</div></div>
      <div class="service-row"><div class="service-name">Model Inference<small>Distributed inference network · 18 regions</small></div><div class="service-status" id="svc-inference"><div class="dot dot-green"></div> Operational</div></div>
      <div class="service-row"><div class="service-name">ModelForge Training Pipeline<small>Fine-tuning jobs · Dataset ingestion</small></div><div class="service-status" id="svc-training"><div class="dot dot-green"></div> Operational</div></div>
      <div class="service-row"><div class="service-name">DataVault Storage<small>Training data · Model artifacts · Audit logs</small></div><div class="service-status" id="svc-datavault"><div class="dot dot-green"></div> Operational</div></div>
      <div class="service-row"><div class="service-name">API Gateway<small>Authentication · Rate limiting · Routing</small></div><div class="service-status" id="svc-gateway"><div class="dot dot-green"></div> Operational</div></div>
      <div class="service-row"><div class="service-name">Autopilot Workflows<small>Workflow orchestration · Webhook delivery</small></div><div class="service-status" id="svc-autopilot"><div class="dot dot-green"></div> Operational</div></div>
    </div>
  </div>

  <div class="uptime-section">
    <h3>90-Day Uptime</h3>
    <div class="uptime-row"><div class="uptime-row-header"><span>Chat API</span><span id="up-chat">99.98%</span></div><div class="uptime-bars" id="bars-chat"></div><div class="uptime-legend"><span>90 days ago</span><span>Today</span></div></div>
    <div class="uptime-row"><div class="uptime-row-header"><span>Model Inference</span><span id="up-inf">99.96%</span></div><div class="uptime-bars" id="bars-inf"></div><div class="uptime-legend"><span>90 days ago</span><span>Today</span></div></div>
    <div class="uptime-row"><div class="uptime-row-header"><span>API Gateway</span><span id="up-gw">100%</span></div><div class="uptime-bars" id="bars-gw"></div><div class="uptime-legend"><span>90 days ago</span><span>Today</span></div></div>
  </div>

  <div class="incidents-section">
    <h3>Recent Incidents</h3>
    <div id="incidents-list"><p class="no-incidents">No incidents in the past 90 days.</p></div>
  </div>
</div>`,
    scripts: `<script>
  function buildBars(containerId, uptimePct, incident) {
    const el = document.getElementById(containerId);
    if (!el) return;
    const total = 90, downCount = Math.round(total * (1 - uptimePct / 100));
    let html = '';
    for (let i = 0; i < total; i++) {
      let cls = 'bar-green';
      if (downCount > 0 && (i * 7 + 3) % 90 < downCount) cls = 'bar-yellow';
      if (i >= total - 1 && incident) cls = 'bar-red';
      html += '<div class="bar ' + cls + '" title="Day ' + (i+1) + ': ' + (cls === 'bar-green' ? 'Operational' : cls === 'bar-yellow' ? 'Degraded' : 'Outage') + '"></div>';
    }
    el.innerHTML = html;
  }
  buildBars('bars-chat', 99.98, false);
  buildBars('bars-inf',  99.96, false);
  buildBars('bars-gw',   100,   false);

  const CHECKS_KEY = 'nm_remediation_checks';
  let checks = JSON.parse(localStorage.getItem(CHECKS_KEY) || 'null') || Array(7).fill(false);
  function renderChecks() {
    let done = 0;
    for (let i = 0; i < 7; i++) {
      const box = document.getElementById('chk-' + i), title = document.getElementById('chk-title-' + i);
      if (!box || !title) continue;
      if (checks[i]) { box.className = 'check-box checked'; box.textContent = '✓'; title.className = 'check-title completed'; done++; }
      else            { box.className = 'check-box'; box.textContent = ''; title.className = 'check-title'; }
    }
    const counter = document.getElementById('check-count');
    if (counter) counter.textContent = done;
  }
  function toggleCheck(idx) { checks[idx] = !checks[idx]; localStorage.setItem(CHECKS_KEY, JSON.stringify(checks)); renderChecks(); }
  renderChecks();

  async function pollIncident() {
    try {
      const data = await fetch('/api/incident').then(r => r.json());
      applyIncidentState(data);
    } catch(e) {}
    setTimeout(pollIncident, 5000);
  }
  function applyIncidentState(data) {
    const overall = document.getElementById('overall-status'), icon = document.getElementById('overall-icon');
    const title = document.getElementById('overall-title'), desc = document.getElementById('overall-desc');
    const updated = document.getElementById('status-updated'), details = document.getElementById('incident-details');
    const incidentsList = document.getElementById('incidents-list');
    updated.textContent = 'Updated ' + new Date().toLocaleTimeString();
    if (data.active) {
      const isCritical = data.severity === 'critical';
      overall.className = 'overall-status ' + (isCritical ? 'outage' : 'degraded');
      icon.textContent = isCritical ? '🔴' : '🟡';
      title.textContent = data.title || (isCritical ? 'Service Outage Detected' : 'Service Degradation');
      desc.textContent = data.message || 'We are investigating the issue.';
      details.style.display = 'block';
      const affected = data.affected_services || [];
      const serviceMap = {'Chat API':'svc-chat','Model Inference':'svc-inference','API Gateway':'svc-gateway','DataVault':'svc-datavault','Training':'svc-training','Autopilot':'svc-autopilot'};
      Object.values(serviceMap).forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = '<div class="dot dot-green"></div> Operational'; });
      affected.forEach(svc => { const el = document.getElementById(serviceMap[svc] || ''); if (el) el.innerHTML = '<div class="dot ' + (isCritical ? 'dot-red' : 'dot-yellow') + '"></div> ' + (isCritical ? 'Outage' : 'Degraded'); });
      buildBars('bars-chat', 99.98, affected.includes('Chat API'));
      buildBars('bars-inf',  99.96, affected.includes('Model Inference'));
      buildBars('bars-gw',   100,   affected.includes('API Gateway'));
      const startedAt = data.started_at ? new Date(data.started_at).toLocaleString() : new Date().toLocaleString();
      incidentsList.innerHTML = '<div class="incident-card active-incident"><div class="incident-header"><div class="incident-title">🔴 ' + (data.title || 'Active Incident') + '</div><div class="incident-date">' + startedAt + '</div></div><div class="incident-body"><strong>Status: Investigating</strong><br>' + (data.message || '') + (affected.length ? '<div class="incident-affected">' + affected.map(s => '<span class="badge badge-red">' + s + '</span>').join('') + '</div>' : '') + '</div></div>';
    } else {
      overall.className = 'overall-status operational'; icon.textContent = '✅';
      title.textContent = 'All Systems Operational'; desc.textContent = 'All NovaMind services are running normally.';
      details.style.display = 'none';
      ['svc-chat','svc-inference','svc-training','svc-datavault','svc-gateway','svc-autopilot'].forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = '<div class="dot dot-green"></div> Operational'; });
      buildBars('bars-chat', 99.98, false); buildBars('bars-inf', 99.96, false); buildBars('bars-gw', 100, false);
      incidentsList.innerHTML = '<p class="no-incidents">No incidents in the past 90 days.</p>';
      checks = Array(7).fill(false); localStorage.setItem(CHECKS_KEY, JSON.stringify(checks)); renderChecks();
    }
  }
  pollIncident();
</script>`,
  });
}

// ── Page: Chat ────────────────────────────────────────────────────────────────

function pageChat(username, incident) {
  return baseLayout({
    title: 'Chat — NovaMind AI',
    incident, loggedIn: true,
    head: `<style>
      .chat-wrap{max-width:800px;margin:0 auto;padding:2rem 1.5rem;display:flex;flex-direction:column;height:calc(100vh - 120px);}
      .chat-header{margin-bottom:1.5rem;}.chat-header h1{font-size:1.3rem;font-weight:800;color:#fff;}.chat-header p{color:var(--text-muted);font-size:0.82rem;}
      .chat-messages{flex:1;overflow-y:auto;border:1px solid var(--border);border-radius:12px;padding:1.25rem;background:var(--glass);margin-bottom:1rem;display:flex;flex-direction:column;gap:1rem;}
      .msg{max-width:85%;}.msg-user{align-self:flex-end;}.msg-assistant{align-self:flex-start;}
      .msg-bubble{padding:0.7rem 1rem;border-radius:12px;font-size:0.875rem;line-height:1.6;}
      .msg-user .msg-bubble{background:var(--blue);color:#fff;border-bottom-right-radius:4px;}
      .msg-assistant .msg-bubble{background:rgba(255,255,255,0.07);color:var(--text);border-bottom-left-radius:4px;border:1px solid var(--border);}
      .msg-meta{font-size:0.7rem;color:var(--text-muted);margin-top:0.25rem;}
      .msg-user .msg-meta{text-align:right;}.msg-assistant .msg-meta{text-align:left;}
      .chat-input-row{display:flex;gap:0.75rem;}
      .chat-input{flex:1;background:rgba(255,255,255,0.06);border:1px solid var(--border);border-radius:10px;padding:0.75rem 1rem;color:#fff;font-size:0.875rem;font-family:inherit;outline:none;resize:none;transition:border-color 0.15s;}
      .chat-input:focus{border-color:var(--blue);}
      .chat-send{background:var(--blue);color:#fff;border:none;border-radius:10px;padding:0.75rem 1.25rem;font-weight:600;cursor:pointer;font-family:inherit;transition:background 0.15s;white-space:nowrap;}
      .chat-send:hover{background:var(--blue-lt);}.chat-send:disabled{opacity:0.5;cursor:not-allowed;}
    </style>`,
    body: `
<div class="chat-wrap">
  <div class="chat-header"><h1>NovaMind Chat</h1><p>Powered by novamind-chat-v2 · 200K context window</p></div>
  <div class="chat-messages" id="chat-messages">
    <div class="msg msg-assistant">
      <div class="msg-bubble">Hello! I'm NovaMind AI. How can I help you today? You can ask me about our platform, pricing, or technical capabilities.</div>
      <div class="msg-meta">NovaMind · just now</div>
    </div>
  </div>
  <div class="chat-input-row">
    <textarea class="chat-input" id="chat-input" rows="2" placeholder="Message NovaMind AI…"></textarea>
    <button class="chat-send" id="chat-send" onclick="sendMessage()">Send</button>
  </div>
</div>`,
    scripts: `<script>
  async function sendMessage() {
    const input = document.getElementById('chat-input');
    const prompt = input.value.trim();
    if (!prompt) return;
    const btn = document.getElementById('chat-send');
    btn.disabled = true; input.value = '';
    const msgs = document.getElementById('chat-messages');
    msgs.innerHTML += '<div class="msg msg-user"><div class="msg-bubble">' + prompt.replace(/</g,'&lt;') + '</div><div class="msg-meta">You · just now</div></div>';
    msgs.scrollTop = msgs.scrollHeight;
    try {
      const res = await fetch('/api/v1/chat', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({prompt, model:'novamind-chat-v2'}) });
      const data = await res.json();
      const reply = data.choices?.[0]?.message?.content || data.error || 'Error';
      msgs.innerHTML += '<div class="msg msg-assistant"><div class="msg-bubble">' + reply.replace(/</g,'&lt;') + '</div><div class="msg-meta">NovaMind · just now</div></div>';
    } catch(e) {
      msgs.innerHTML += '<div class="msg msg-assistant"><div class="msg-bubble">Sorry, something went wrong. Please try again.</div><div class="msg-meta">NovaMind · just now</div></div>';
    }
    msgs.scrollTop = msgs.scrollHeight;
    btn.disabled = false; input.focus();
  }
  document.getElementById('chat-input').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } });
</script>`,
  });
}

// ── Page: Dashboard ───────────────────────────────────────────────────────────

function pageDashboard(username, incident) {
  return baseLayout({
    title: 'Dashboard — NovaMind AI',
    incident, loggedIn: true,
    head: `<style>
      .dash-wrap{max-width:1100px;margin:0 auto;padding:3rem 1.5rem;}
      .dash-header{margin-bottom:2rem;}.dash-header h1{font-size:1.5rem;font-weight:800;color:#fff;}.dash-header p{color:var(--text-muted);}
      .dash-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1.25rem;margin-bottom:2.5rem;}
      .dash-card{background:var(--glass);border:1px solid var(--border);border-radius:12px;padding:1.5rem;}
      .dash-card-label{font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.07em;color:var(--text-muted);margin-bottom:0.5rem;}
      .dash-card-value{font-size:1.8rem;font-weight:800;color:#fff;letter-spacing:-0.02em;}
      .dash-card-sub{font-size:0.78rem;color:var(--text-muted);margin-top:0.25rem;}
      .dash-section{background:var(--glass);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:1.25rem;}
      .dash-section h3{font-size:0.9rem;font-weight:700;color:#fff;margin-bottom:1rem;}
      .api-key-row{display:flex;align-items:center;justify-content:space-between;padding:0.65rem 0;border-bottom:1px solid var(--border);font-size:0.82rem;}
      .api-key-row:last-child{border-bottom:none;}.api-key-name{font-weight:500;color:var(--text);}.api-key-value{font-family:'JetBrains Mono',monospace;color:var(--text-muted);font-size:0.75rem;}
    </style>`,
    body: `
<div class="dash-wrap">
  <div class="dash-header"><h1>Dashboard</h1><p>Welcome back, ${esc(username || 'User')}.</p></div>
  <div class="dash-grid">
    <div class="dash-card"><div class="dash-card-label">API Calls Today</div><div class="dash-card-value">24,831</div><div class="dash-card-sub">↑ 12% vs yesterday</div></div>
    <div class="dash-card"><div class="dash-card-label">Tokens Used</div><div class="dash-card-value">2.4M</div><div class="dash-card-sub">of 10M monthly quota</div></div>
    <div class="dash-card"><div class="dash-card-label">Avg Latency</div><div class="dash-card-value">82ms</div><div class="dash-card-sub">p50 · last 24h</div></div>
    <div class="dash-card"><div class="dash-card-label">Active Models</div><div class="dash-card-value">3</div><div class="dash-card-sub">novamind-chat-v2 + 2 fine-tuned</div></div>
  </div>
  <div class="dash-section">
    <h3>API Keys</h3>
    <div class="api-key-row"><div class="api-key-name">Production</div><div class="api-key-value">nm-sk-prod-••••••••••••••••••••••••3a7f</div></div>
    <div class="api-key-row"><div class="api-key-name">Development</div><div class="api-key-value">nm-sk-dev-••••••••••••••••••••••••8c2e</div></div>
    <div class="api-key-row"><div class="api-key-name">CI/CD</div><div class="api-key-value">nm-sk-ci-•••••••••••••••••••••••••1b4d</div></div>
  </div>
  <div class="dash-section">
    <h3>Recent Activity</h3>
    <div class="api-key-row"><div class="api-key-name">Fine-tune job completed</div><div class="api-key-value">2h ago · enterprise-qa-v2</div></div>
    <div class="api-key-row"><div class="api-key-name">Dataset uploaded</div><div class="api-key-value">5h ago · support-tickets-2024</div></div>
    <div class="api-key-row"><div class="api-key-name">API key rotated</div><div class="api-key-value">1d ago · Production</div></div>
  </div>
</div>`,
  });
}

// ── Page: Admin gate (unauthenticated) ───────────────────────────────────────

function pageAdminGate(incident) {
  return baseLayout({
    title: 'Admin — NovaMind AI',
    incident, loggedIn: false,
    body: `<div style="max-width:500px;margin:5rem auto;padding:0 1.5rem;text-align:center;">
      <div style="font-size:2rem;margin-bottom:1rem;">🔒</div>
      <h1 style="font-size:1.4rem;font-weight:800;color:#fff;margin-bottom:0.5rem;">Admin Access Required</h1>
      <p style="color:var(--text-muted);font-size:0.875rem;margin-bottom:1.5rem;">This area requires administrative privileges.</p>
      <a href="/login" class="btn btn-primary">Sign In</a>
    </div>`,
  });
}

// ── Page: Admin (authenticated) ───────────────────────────────────────────────

function pageAdmin(username, incident) {
  return baseLayout({
    title: 'Admin — NovaMind AI',
    incident, loggedIn: true,
    body: `<div style="max-width:900px;margin:0 auto;padding:3rem 1.5rem;">
      <h1 style="font-size:1.5rem;font-weight:800;color:#fff;margin-bottom:0.5rem;">Admin Panel</h1>
      <p style="color:var(--text-muted);margin-bottom:2rem;">Signed in as <strong style="color:var(--text);">${esc(username || 'admin')}</strong></p>
      <div style="background:var(--glass);border:1px solid var(--border);border-radius:12px;padding:1.5rem;">
        <p style="color:var(--text-muted);font-size:0.875rem;">System configuration and tenant management. Use the API for programmatic access.</p>
      </div>
    </div>`,
  });
}

// ── Main Worker export ────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const secret = env.SECRET_KEY || 'dev-secret';
    const session = await getSession(request, secret);
    const loggedIn = !!session;

    // ── Static routes ───────────────────────────────────────────────────────

    if (path === '/' && method === 'GET') {
      const incident = await getIncident(env);
      return html(pageIndex(incident, loggedIn));
    }

    if (path === '/status' && method === 'GET') {
      return html(pageStatus(loggedIn));
    }

    if (path === '/products' && method === 'GET') {
      const incident = await getIncident(env);
      return html(baseLayout({
        title: 'Products — NovaMind AI', incident, loggedIn,
        body: `<div style="max-width:1100px;margin:0 auto;padding:5rem 1.5rem;text-align:center;">
          <h1 style="font-size:2.5rem;font-weight:800;color:#fff;margin-bottom:1rem;">Our Products</h1>
          <p style="color:var(--text-muted);max-width:500px;margin:0 auto 3rem;">Explore NovaMind's full suite of enterprise AI infrastructure products.</p>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1.5rem;text-align:left;">
            <div style="background:var(--glass);border:1px solid var(--border);border-radius:14px;padding:1.75rem;"><div style="font-size:1.5rem;margin-bottom:0.75rem;">🤖</div><h3 style="color:#fff;margin-bottom:0.5rem;">Chat API</h3><p style="color:var(--text-muted);font-size:0.875rem;">OpenAI-compatible completions with 200K context, streaming, and function calling.</p></div>
            <div style="background:var(--glass);border:1px solid var(--border);border-radius:14px;padding:1.75rem;"><div style="font-size:1.5rem;margin-bottom:0.75rem;">⚗️</div><h3 style="color:#fff;margin-bottom:0.5rem;">ModelForge</h3><p style="color:var(--text-muted);font-size:0.875rem;">Fine-tune foundation models on proprietary data with full tenant isolation.</p></div>
            <div style="background:var(--glass);border:1px solid var(--border);border-radius:14px;padding:1.75rem;"><div style="font-size:1.5rem;margin-bottom:0.75rem;">🗄️</div><h3 style="color:#fff;margin-bottom:0.5rem;">DataVault</h3><p style="color:var(--text-muted);font-size:0.875rem;">SOC 2 Type II certified training data management with end-to-end encryption.</p></div>
            <div style="background:var(--glass);border:1px solid var(--border);border-radius:14px;padding:1.75rem;"><div style="font-size:1.5rem;margin-bottom:0.75rem;">⚡</div><h3 style="color:#fff;margin-bottom:0.5rem;">Autopilot</h3><p style="color:var(--text-muted);font-size:0.875rem;">Agentic workflow orchestration across 200+ enterprise integrations.</p></div>
          </div>
        </div>`,
      }));
    }

    if (path === '/docs' && method === 'GET') {
      const incident = await getIncident(env);
      return html(baseLayout({
        title: 'Documentation — NovaMind AI', incident, loggedIn,
        body: `<div style="max-width:860px;margin:0 auto;padding:4rem 1.5rem;">
          <h1 style="font-size:2rem;font-weight:800;color:#fff;margin-bottom:0.75rem;">Documentation</h1>
          <p style="color:var(--text-muted);margin-bottom:2.5rem;">Everything you need to integrate NovaMind into your application.</p>
          <div style="display:flex;flex-direction:column;gap:0.75rem;">
            ${[['Quickstart','Get your first API call running in under 5 minutes.'],['Authentication','API key management, scoped permissions, and rotation best practices.'],['Chat API Reference','Full reference for the /api/v1/chat completions endpoint.'],['Model Inference','Latency, throughput, and context window documentation by model tier.'],['Webhooks','Receive real-time events for fine-tuning jobs, usage alerts, and incidents.']].map(([t,d]) => `<div style="background:var(--glass);border:1px solid var(--border);border-radius:10px;padding:1.1rem 1.25rem;display:flex;justify-content:space-between;align-items:center;"><div><div style="font-size:0.9rem;font-weight:600;color:#fff;">${t}</div><div style="font-size:0.8rem;color:var(--text-muted);margin-top:0.2rem;">${d}</div></div><span style="color:var(--text-muted);">→</span></div>`).join('')}
          </div>
        </div>`,
      }));
    }

    // ── Auth routes ─────────────────────────────────────────────────────────

    if (path === '/login') {
      if (loggedIn) return redirect('/chat');
      if (method === 'GET') return html(pageLogin(null));
      if (method === 'POST') {
        const formData = await request.formData();
        const username = formData.get('username') || '';
        const password = formData.get('password') || '';
        const validUser = env.APP_USERNAME || 'admin';
        const validPass = env.APP_PASSWORD || 'novamind2024';
        if (username === validUser && password === validPass) {
          const cookie = await buildSessionCookie(username, secret);
          return new Response(null, { status: 302, headers: { Location: '/chat', 'Set-Cookie': cookie } });
        }
        return html(pageLogin('Invalid credentials.'));
      }
    }

    if (path === '/logout' && method === 'GET') {
      return new Response(null, { status: 302, headers: { Location: '/', 'Set-Cookie': clearSessionCookie() } });
    }

    // ── Auth-protected pages ────────────────────────────────────────────────

    if (path === '/chat' && method === 'GET') {
      if (!loggedIn) return redirect('/login');
      const incident = await getIncident(env);
      return html(pageChat(session.u, incident));
    }

    if (path === '/dashboard' && method === 'GET') {
      if (!loggedIn) return redirect('/login');
      const incident = await getIncident(env);
      return html(pageDashboard(session.u, incident));
    }

    if (path === '/user' && method === 'GET') {
      if (!loggedIn) return redirect('/login');
      const incident = await getIncident(env);
      return html(baseLayout({ title: 'Profile — NovaMind AI', incident, loggedIn: true,
        body: `<div style="max-width:700px;margin:0 auto;padding:3rem 1.5rem;"><h1 style="font-size:1.4rem;font-weight:800;color:#fff;margin-bottom:0.5rem;">Profile</h1><p style="color:var(--text-muted);margin-bottom:2rem;">Signed in as <strong style="color:var(--text);">${esc(session.u)}</strong></p><div style="background:var(--glass);border:1px solid var(--border);border-radius:12px;padding:1.5rem;"><p style="color:var(--text-muted);font-size:0.875rem;">Account settings and preferences.</p></div></div>`,
      }));
    }

    if (path === '/admin') {
      if (!loggedIn) return html(pageAdminGate(await getIncident(env)), 401);
      const incident = await getIncident(env);
      return html(pageAdmin(session.u, incident));
    }

    // ── Healthcheck ─────────────────────────────────────────────────────────

    if (path === '/healthz') return json({ status: 'ok' });

    // ── Public API ──────────────────────────────────────────────────────────

    if (path === '/api/v1/models' && method === 'GET') {
      return json({
        object: 'list',
        data: [
          { id: 'novamind-chat-v2',        object: 'model', created: 1700000000, owned_by: 'novamind', context_window: 200000, tier: 'enterprise' },
          { id: 'novamind-chat-v2-fast',   object: 'model', created: 1710000000, owned_by: 'novamind', context_window: 32000,  tier: 'standard' },
          { id: 'modelforge-v1-finetuned', object: 'model', created: 1715000000, owned_by: 'tenant',   context_window: 128000, tier: 'custom' },
          { id: 'novamind-embed-v1',       object: 'model', created: 1705000000, owned_by: 'novamind', context_window: 8192,   tier: 'standard' },
        ],
        total: 4,
      });
    }

    if (path === '/api/v1/training-data' && method === 'GET') {
      if (!loggedIn) return json({ error: 'Unauthorized', code: 401, message: 'Valid API key required.' }, 401);
      return json({
        datasets: [
          { id: 'ds_8f3a2c', name: 'enterprise-qa-v2',      rows: 847293, size_gb: 12.4, status: 'ready' },
          { id: 'ds_4e7b1d', name: 'support-tickets-2024',  rows: 142000, size_gb: 3.1,  status: 'processing' },
        ],
      });
    }

    if (path === '/api/v1/users' && method === 'GET') {
      if (!loggedIn) return json({ error: 'Unauthorized', code: 401 }, 401);
      return json({
        users: [
          { id: 'usr_001', email: 'admin@novamind.ai',   role: 'owner' },
          { id: 'usr_002', email: 'eng@novamind.ai',     role: 'member' },
          { id: 'usr_003', email: 'billing@novamind.ai', role: 'billing' },
        ],
      });
    }

    if (path === '/api/v1/admin') {
      return json({ error: 'Unauthorized', code: 401 }, 401);
    }

    if (path === '/api/v1/chat' && method === 'POST') {
      const data = await request.json().catch(() => ({}));
      const prompt = data.prompt || data.message || '';
      if (!prompt) return json({ error: 'prompt is required' }, 400);
      const responseText = MOCK_RESPONSES[Math.abs(hashCode(prompt)) % MOCK_RESPONSES.length];
      return json({
        id: `chatcmpl-${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`,
        object: 'chat.completion',
        model: 'novamind-chat-v2',
        choices: [{ index: 0, message: { role: 'assistant', content: responseText }, finish_reason: 'stop' }],
        usage: { prompt_tokens: prompt.split(' ').length, completion_tokens: responseText.split(' ').length, total_tokens: prompt.split(' ').length + responseText.split(' ').length },
      });
    }

    // ── Incident control API ────────────────────────────────────────────────

    if (path === '/api/incident') {
      if (method === 'GET') {
        return json(await getIncident(env));
      }
      if (method === 'POST') {
        const data = await request.json().catch(() => ({}));
        const expectedKey = env.INCIDENT_KEY || '';
        if (!expectedKey || data.key !== expectedKey) return json({ error: 'Forbidden' }, 403);
        const state = {
          active:            Boolean(data.active),
          title:             data.title || '',
          message:           data.message || '',
          severity:          data.severity || 'none',
          affected_services: Array.isArray(data.affected_services) ? data.affected_services : [],
          started_at:        data.started_at || null,
        };
        await setIncident(env, state);
        return json({ ok: true, state });
      }
    }

    // ── 404 ─────────────────────────────────────────────────────────────────

    return html(baseLayout({
      title: '404 — NovaMind AI', incident: null, loggedIn,
      body: `<div style="max-width:500px;margin:6rem auto;padding:0 1.5rem;text-align:center;"><div style="font-size:3rem;margin-bottom:1rem;">404</div><h1 style="font-size:1.4rem;font-weight:800;color:#fff;margin-bottom:0.5rem;">Page not found</h1><p style="color:var(--text-muted);margin-bottom:1.5rem;">The page you're looking for doesn't exist.</p><a href="/" class="btn btn-primary">Go home</a></div>`,
    }), 404);
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function hashCode(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = Math.imul(31, h) + str.charCodeAt(i) | 0;
  return h;
}
