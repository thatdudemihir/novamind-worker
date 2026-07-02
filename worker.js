/**
 * SoleDrop — Cloudflare Worker
 * A hyped sneaker-drop storefront. State stored in Workers KV.
 * Sessions: HMAC-SHA256 signed cookies (no server-side session store needed).
 *
 * Doubles as the live attack target for the ThreatOps CTF ("Drop-Day Bot Swarm"):
 * the attack simulator fires real HTTP traffic at these paths and flips the
 * /status page into incident mode via POST /api/incident.
 */

// ── Mock support-concierge responses ──────────────────────────────────────────

const MOCK_RESPONSES = [
  "Thanks for reaching out to SoleDrop! The next drop is this Saturday at 11:00 AM ET. Add the release to your notifications and we'll ping you 15 minutes before it goes live.",
  "All SoleDrop pairs are 100% authentic and pass a multi-point verification before they ship. Every order includes a SoleDrop authenticity tag with a scannable QR code.",
  "Raffle entries are free — one entry per verified account. Winners are drawn 24 hours before the drop and charged automatically if a card is on file. Good luck!",
  "Standard shipping is 3–5 business days and free on orders over $150. Express (1–2 days) is available at checkout. You'll get a tracking link the moment your pair leaves the warehouse.",
  "Sizing runs true to size on most models. The Volt Runner OG and Apex Trail 2 run about a half size large — we'd suggest going down half a size for those two.",
  "Returns are accepted within 14 days on unworn pairs with the original box and tags. Raffle-win pairs are final sale. Start a return from your account dashboard under Orders.",
  "If a pair sold out, hit 'Notify Me' on the product — we release restock pairs from cancelled orders every Tuesday, and notified members get first access.",
  "We ship worldwide! International duties are calculated at checkout so there are no surprise fees on delivery. Delivery is typically 7–12 business days outside the US.",
  "Your saved payment methods and addresses live in your account settings. We never store full card numbers — payments are tokenized through our PCI-compliant processor.",
  "During a drop, checkout can get busy — if you hit the waiting room, don't refresh! Your place in line is held automatically and you'll be let through in order.",
  "SoleDrop members earn 'Heat Points' on every purchase that unlock early access to future drops. You're currently building toward Early Access tier — nice.",
  "We take bots seriously. One pair per customer per drop, verified accounts only, and our edge protection blocks automated checkout attempts to keep drops fair for real people.",
  "Cancelled an order by mistake? Reach out within 30 minutes and we can usually reinstate it if the pair hasn't been released back to the pool yet.",
  "The Grail High 'Panda' is one of our most-wanted pairs — it's raffle-only this drop. Enter the raffle from the product page before Friday 5 PM ET to be in the draw.",
  "Need help with an order? Share your order number (starts with SD-) and I can pull up the status, tracking, and estimated delivery for you right here.",
];

// ── Product catalog ────────────────────────────────────────────────────────────

const PRODUCTS = [
  { id: 'volt-runner-og',  name: 'Volt Runner OG',   colorway: 'Solar Flare',   price: 220, c1: '#ff6a00', c2: '#ff2d55', badge: 'JUST DROPPED', state: 'shop' },
  { id: 'apex-trail-2',    name: 'Apex Trail 2',      colorway: 'Midnight Navy', price: 180, c1: '#1a5cff', c2: '#00d4ff', badge: '',            state: 'shop' },
  { id: 'cinder-low',      name: 'Cinder Low',        colorway: 'Ember Red',     price: 160, c1: '#e5342b', c2: '#ff8a00', badge: 'RAFFLE',      state: 'raffle' },
  { id: 'grail-high',      name: 'Grail High',        colorway: 'Panda',         price: 250, c1: '#141210', c2: '#8a8a8a', badge: 'RAFFLE',      state: 'raffle' },
  { id: 'pulse-knit',      name: 'Pulse Knit',        colorway: 'Lime Shock',    price: 150, c1: '#9ef01a', c2: '#00c46a', badge: 'LOW STOCK',   state: 'shop' },
  { id: 'drift-mesh',      name: 'Drift Mesh',        colorway: 'Arctic Blue',   price: 140, c1: '#00b4d8', c2: '#7cf5ff', badge: '',            state: 'shop' },
  { id: 'nova-court-97',   name: "Nova Court '97",    colorway: 'Cream / Gold',  price: 200, c1: '#e0b978', c2: '#fff3d6', badge: 'SOLD OUT',    state: 'soldout' },
  { id: 'vault-23-retro',  name: 'Vault 23 Retro',    colorway: 'Royal',         price: 210, c1: '#2536ff', c2: '#6a5cff', badge: 'SOLD OUT',    state: 'soldout' },
];

// SVG sneaker silhouette, tinted per product.
function sneakerSVG(c1, c2, key) {
  const g = `grad-${key}`;
  return `<svg viewBox="0 0 200 120" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
    <defs><linearGradient id="${g}" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="${c1}"/><stop offset="1" stop-color="${c2}"/>
    </linearGradient></defs>
    <path d="M12 78 C12 70 20 66 30 66 L58 66 C70 66 80 60 92 52 C104 44 120 40 138 44 C160 49 176 58 186 68 C192 74 190 84 180 86 L34 90 C20 92 12 88 12 78 Z"
      fill="url(#${g})" stroke="rgba(0,0,0,0.22)" stroke-width="2"/>
    <path d="M16 84 L184 80 C186 88 180 94 168 94 L30 96 C20 96 15 91 16 84 Z" fill="rgba(255,255,255,0.85)"/>
    <path d="M96 54 C104 60 116 62 128 60" fill="none" stroke="rgba(255,255,255,0.55)" stroke-width="3" stroke-linecap="round"/>
    <path d="M108 48 C116 54 128 56 140 54" fill="none" stroke="rgba(255,255,255,0.4)" stroke-width="3" stroke-linecap="round"/>
    <circle cx="150" cy="60" r="4" fill="rgba(255,255,255,0.7)"/>
  </svg>`;
}

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

const SESSION_COOKIE = 'sd_sess';
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

// ── Shared CSS (bright streetwear theme) ───────────────────────────────────────

const BASE_CSS = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:#faf6ee; --bg2:#ffffff; --panel:#ffffff;
    --ink:#151210; --ink2:#3a352f; --muted:#6f675d;
    --accent:#ff4d17; --accent-dk:#e23c0a; --blue:#1a5cff; --lime:#8fdd00; --hot:#ff2d78;
    --good:#12a150; --warn:#e08a00; --bad:#e5342b;
    --line:rgba(21,18,16,0.12); --line-soft:rgba(21,18,16,0.07);
    --shadow:0 10px 30px rgba(21,18,16,0.08); --shadow-sm:0 3px 12px rgba(21,18,16,0.07);
  }
  body { background:var(--bg); color:var(--ink); font-family:'Inter',system-ui,sans-serif; font-size:15px; line-height:1.6; min-height:100vh; -webkit-font-smoothing:antialiased; }
  a { color:var(--ink); text-decoration:none; }
  a:hover { color:var(--accent); }
  .container { max-width:1200px; margin:0 auto; padding:0 1.5rem; }

  /* Drop ticker marquee */
  .ticker { background:var(--ink); color:#fff; font-size:0.74rem; font-weight:700; letter-spacing:0.14em; text-transform:uppercase; overflow:hidden; white-space:nowrap; padding:0.45rem 0; }
  .ticker span { display:inline-block; padding-left:100%; animation:ticker 22s linear infinite; }
  .ticker b { color:var(--lime); }
  @keyframes ticker { 0%{transform:translateX(0)} 100%{transform:translateX(-100%)} }

  nav { position:sticky; top:0; z-index:100; background:rgba(255,255,255,0.9); backdrop-filter:blur(12px); border-bottom:1px solid var(--line); }
  .nav-inner { max-width:1200px; margin:0 auto; display:flex; align-items:center; gap:2rem; padding:0 1.5rem; height:64px; }
  .nav-logo { display:flex; align-items:center; gap:0.55rem; font-weight:900; font-size:1.15rem; letter-spacing:-0.02em; color:var(--ink); text-transform:uppercase; }
  .nav-logo:hover { color:var(--ink); }
  .nav-logo-icon { width:32px; height:32px; background:var(--ink); border-radius:9px; display:flex; align-items:center; justify-content:center; font-size:1rem; }
  .nav-logo em { color:var(--accent); font-style:normal; }
  .nav-links { display:flex; gap:1.5rem; align-items:center; margin-left:auto; }
  .nav-links a { color:var(--ink2); font-size:0.82rem; font-weight:700; text-transform:uppercase; letter-spacing:0.03em; }
  .nav-links a:hover { color:var(--accent); }
  .nav-cta { background:var(--accent); color:#fff !important; padding:0.5rem 1.1rem; border-radius:999px; font-size:0.78rem !important; }
  .nav-cta:hover { background:var(--accent-dk); }

  .incident-banner { background:linear-gradient(90deg,#e5342b,#ff5a1f); border-bottom:1px solid #b91c1c; padding:0.55rem 1.5rem; text-align:center; font-size:0.83rem; font-weight:600; color:#fff; display:flex; align-items:center; justify-content:center; gap:0.5rem; }
  .incident-banner a { color:#fff; }
  .incident-banner .pulse { width:8px; height:8px; border-radius:50%; background:#fff; flex-shrink:0; animation:pulse-red 1.2s ease-in-out infinite; }
  @keyframes pulse-red { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.4;transform:scale(1.5)} }
  .incident-banner.warning { background:linear-gradient(90deg,#e08a00,#f5b301); border-color:#b45309; color:#1a1206; }
  .incident-banner.warning .pulse { background:#1a1206; }

  footer { border-top:1px solid var(--line); background:var(--bg2); padding:2.5rem 1.5rem; margin-top:4rem; }
  .footer-inner { max-width:1200px; margin:0 auto; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem; }
  .footer-brand { font-weight:900; color:var(--ink); font-size:1rem; text-transform:uppercase; letter-spacing:-0.01em; }
  .footer-brand em { color:var(--accent); font-style:normal; }
  .footer-brand span { color:var(--muted); font-weight:500; font-size:0.78rem; display:block; margin-top:2px; letter-spacing:0; text-transform:none; }
  .footer-links { display:flex; gap:1.5rem; }
  .footer-links a { color:var(--muted); font-size:0.8rem; font-weight:600; }
  .footer-links a:hover { color:var(--accent); }
  .footer-copy { color:var(--muted); font-size:0.75rem; }

  .badge { display:inline-flex; align-items:center; gap:0.35rem; padding:0.2rem 0.6rem; border-radius:999px; font-size:0.68rem; font-weight:800; letter-spacing:0.04em; text-transform:uppercase; }
  .badge-green  { background:rgba(18,161,80,0.14); color:#0e7a3d; }
  .badge-yellow { background:rgba(224,138,0,0.16); color:#a35d00; }
  .badge-red    { background:rgba(229,52,43,0.14); color:#b91c1c; }
  .badge-accent { background:rgba(255,77,23,0.14); color:var(--accent-dk); }
  .badge-ink    { background:var(--ink); color:#fff; }

  .btn { display:inline-flex; align-items:center; justify-content:center; gap:0.4rem; padding:0.7rem 1.5rem; border-radius:999px; font-weight:800; font-size:0.82rem; text-transform:uppercase; letter-spacing:0.03em; cursor:pointer; border:none; transition:all 0.15s; font-family:inherit; text-decoration:none; }
  .btn-primary { background:var(--ink); color:#fff; }
  .btn-primary:hover { background:#000; color:#fff; transform:translateY(-1px); }
  .btn-accent { background:var(--accent); color:#fff; }
  .btn-accent:hover { background:var(--accent-dk); color:#fff; transform:translateY(-1px); }
  .btn-ghost { background:transparent; color:var(--ink); border:2px solid var(--ink); }
  .btn-ghost:hover { background:var(--ink); color:#fff; }
  .btn:disabled { opacity:0.45; cursor:not-allowed; transform:none; }
  code, .mono { font-family:'JetBrains Mono',monospace; font-size:0.85em; }
`;

// ── Base layout wrapper ───────────────────────────────────────────────────────

function baseLayout({ title, head = '', body, scripts = '', incident, loggedIn, ticker = true }) {
  const banner = incident?.active ? `
    <div class="incident-banner${incident.severity === 'warning' ? ' warning' : ''}">
      <div class="pulse"></div>
      <strong>${esc(incident.title || 'Service Incident')}</strong>${incident.message ? ` — ${esc(incident.message)}` : ''}
      <a href="/status" style="margin-left:0.75rem;text-decoration:underline;font-size:0.78rem;">View status →</a>
    </div>` : '';
  const tick = ticker ? `<div class="ticker"><span>🔥 THIS SATURDAY 11:00 AM ET — <b>VOLT RUNNER OG "SOLAR FLARE"</b> &nbsp;•&nbsp; FREE SHIPPING OVER $150 &nbsp;•&nbsp; ONE PAIR PER CUSTOMER &nbsp;•&nbsp; RAFFLE CLOSES FRIDAY 5PM &nbsp;•&nbsp; 🔥 THIS SATURDAY 11:00 AM ET — <b>VOLT RUNNER OG "SOLAR FLARE"</b> &nbsp;•&nbsp; FREE SHIPPING OVER $150 &nbsp;•&nbsp; ONE PAIR PER CUSTOMER &nbsp;•&nbsp; RAFFLE CLOSES FRIDAY 5PM &nbsp;•&nbsp; </span></div>` : '';
  const navAuth = loggedIn
    ? `<a href="/dashboard">Account</a><a href="/logout">Sign Out</a>`
    : `<a href="/login">Sign In</a><a href="/login" class="nav-cta">Join SoleDrop</a>`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>${esc(title)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet"/>
  <style>${BASE_CSS}</style>
  ${head}
</head>
<body>
${banner}
${tick}
<nav>
  <div class="nav-inner">
    <a href="/" class="nav-logo"><div class="nav-logo-icon">👟</div>Sole<em>Drop</em></a>
    <div class="nav-links">
      <a href="/products">Shop</a>
      <a href="/drops">Drops</a>
      <a href="/status">Status</a>
      ${navAuth}
    </div>
  </div>
</nav>
${body}
<footer>
  <div class="footer-inner">
    <div class="footer-brand">Sole<em>Drop</em><span>Limited sneaker drops, done right.</span></div>
    <div class="footer-links">
      <a href="/products">Shop</a>
      <a href="/drops">Drops</a>
      <a href="/status">Status</a>
      <a href="/login">Sign In</a>
    </div>
    <div class="footer-copy">&copy; 2026 SoleDrop, Inc. All rights reserved.</div>
  </div>
</footer>
${scripts}
</body>
</html>`;
}

// ── Product card render ─────────────────────────────────────────────────────

function productCard(p) {
  const badgeCls = p.state === 'soldout' ? 'badge-red' : p.state === 'raffle' ? 'badge-accent' : p.badge === 'LOW STOCK' ? 'badge-yellow' : 'badge-green';
  const badge = p.badge ? `<span class="pc-badge badge ${badgeCls}">${esc(p.badge)}</span>` : '';
  const btn = p.state === 'soldout'
    ? `<button class="btn btn-ghost" style="width:100%;" data-act="notify" data-name="${esc(p.name)}">Notify Me</button>`
    : p.state === 'raffle'
      ? `<button class="btn btn-accent" style="width:100%;" data-act="raffle" data-name="${esc(p.name)}">Enter Raffle</button>`
      : `<button class="btn btn-primary" style="width:100%;" data-act="cop" data-name="${esc(p.name)}">Cop · $${p.price}</button>`;
  return `<div class="pc">
    <div class="pc-img" style="background:linear-gradient(135deg,${p.c1}22,${p.c2}33);">
      ${badge}
      <div class="pc-shoe">${sneakerSVG(p.c1, p.c2, p.id)}</div>
    </div>
    <div class="pc-body">
      <div class="pc-name">${esc(p.name)}</div>
      <div class="pc-color">${esc(p.colorway)}</div>
      <div class="pc-price">$${p.price}</div>
      ${btn}
    </div>
  </div>`;
}

const STORE_SCRIPTS = `<script>
  document.addEventListener('click', function(e){
    const b = e.target.closest('[data-act]'); if (!b) return;
    const name = b.getAttribute('data-name') || 'this pair';
    const act = b.getAttribute('data-act');
    if (act === 'cop')         alert('🔥 Added to cart: ' + name + '\\n\\n(Demo store — checkout is disabled.)');
    else if (act === 'notify') alert('🔔 We will notify you when ' + name + ' restocks.');
    else if (act === 'raffle') alert('🎟️ Raffle entry received for ' + name + '. Winners drawn 24h before the drop!');
  });
</script>`;

// ── Page: Index (storefront + drop countdown) ──────────────────────────────────

function pageIndex(incident, loggedIn) {
  const featured = PRODUCTS.filter(p => p.state !== 'soldout').slice(0, 8).map(productCard).join('');
  return baseLayout({
    title: 'SoleDrop — Limited Sneaker Drops',
    incident, loggedIn,
    head: `<style>
      .hero{position:relative;overflow:hidden;background:var(--ink);color:#fff;}
      .hero::before{content:'';position:absolute;inset:0;background:radial-gradient(circle at 15% 20%,rgba(255,77,23,0.4),transparent 45%),radial-gradient(circle at 85% 80%,rgba(26,92,255,0.35),transparent 45%);}
      .hero-inner{position:relative;max-width:1200px;margin:0 auto;padding:4rem 1.5rem 4.5rem;display:grid;grid-template-columns:1.1fr 0.9fr;gap:2.5rem;align-items:center;}
      @media(max-width:820px){.hero-inner{grid-template-columns:1fr;text-align:center;}}
      .hero-eyebrow{display:inline-flex;align-items:center;gap:0.5rem;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);color:#fff;padding:0.35rem 0.9rem;border-radius:999px;font-size:0.72rem;font-weight:800;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:1.25rem;}
      .hero h1{font-size:clamp(2.6rem,6vw,4.4rem);font-weight:900;line-height:0.98;letter-spacing:-0.03em;margin-bottom:1rem;text-transform:uppercase;}
      .hero h1 .flare{color:var(--accent);}
      .hero p{color:rgba(255,255,255,0.75);font-size:1.05rem;max-width:440px;margin-bottom:1.75rem;}
      @media(max-width:820px){.hero p{margin-left:auto;margin-right:auto;}}
      .hero-ctas{display:flex;gap:0.75rem;flex-wrap:wrap;}
      @media(max-width:820px){.hero-ctas{justify-content:center;}}
      .countdown{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.14);border-radius:20px;padding:1.75rem;backdrop-filter:blur(6px);}
      .cd-label{font-size:0.72rem;font-weight:800;letter-spacing:0.14em;text-transform:uppercase;color:var(--lime);margin-bottom:0.35rem;}
      .cd-model{font-size:1.35rem;font-weight:900;text-transform:uppercase;letter-spacing:-0.01em;margin-bottom:1.25rem;}
      .cd-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:0.6rem;}
      .cd-cell{background:var(--bg2);color:var(--ink);border-radius:12px;padding:0.85rem 0.4rem;text-align:center;}
      .cd-num{font-family:'JetBrains Mono',monospace;font-size:1.9rem;font-weight:700;line-height:1;letter-spacing:-0.02em;}
      .cd-unit{font-size:0.62rem;font-weight:800;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted);margin-top:0.35rem;}
      .cd-live{display:none;background:var(--accent);color:#fff;text-align:center;padding:1.4rem;border-radius:12px;font-weight:900;text-transform:uppercase;letter-spacing:0.05em;font-size:1.15rem;}

      .drop-section{padding:3.5rem 1.5rem 1rem;}
      .sec-head{max-width:1200px;margin:0 auto 1.75rem;display:flex;align-items:flex-end;justify-content:space-between;gap:1rem;flex-wrap:wrap;}
      .sec-head h2{font-size:1.9rem;font-weight:900;text-transform:uppercase;letter-spacing:-0.02em;}
      .sec-head p{color:var(--muted);font-size:0.9rem;}
      .grid{max-width:1200px;margin:0 auto;display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:1.25rem;}
      .pc{background:var(--panel);border:1px solid var(--line-soft);border-radius:16px;overflow:hidden;box-shadow:var(--shadow-sm);transition:transform 0.15s,box-shadow 0.15s;}
      .pc:hover{transform:translateY(-4px);box-shadow:var(--shadow);}
      .pc-img{position:relative;aspect-ratio:4/3;display:flex;align-items:center;justify-content:center;padding:1.25rem;}
      .pc-shoe{width:82%;filter:drop-shadow(0 8px 10px rgba(0,0,0,0.12));}
      .pc-badge{position:absolute;top:0.75rem;left:0.75rem;}
      .pc-body{padding:1rem 1.1rem 1.2rem;}
      .pc-name{font-weight:800;font-size:1rem;letter-spacing:-0.01em;}
      .pc-color{color:var(--muted);font-size:0.8rem;margin-bottom:0.15rem;}
      .pc-price{font-weight:800;font-size:0.95rem;margin:0.4rem 0 0.85rem;}

      .strip{background:var(--bg2);border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin-top:3rem;}
      .strip-inner{max-width:1100px;margin:0 auto;padding:2.5rem 1.5rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1.5rem;text-align:center;}
      .strip .n{font-size:1.8rem;font-weight:900;letter-spacing:-0.02em;}
      .strip .n em{color:var(--accent);font-style:normal;}
      .strip .l{color:var(--muted);font-size:0.8rem;margin-top:0.15rem;}
    </style>`,
    body: `
<section class="hero">
  <div class="hero-inner">
    <div>
      <div class="hero-eyebrow">🔥 Drop 042 — Loading</div>
      <h1>Cop the<br><span class="flare">heat.</span><br>Skip the resell.</h1>
      <p>Limited pairs. Fair drops. Every SoleDrop release is verified authentic and one-per-customer — no bots, no scalpers, no games.</p>
      <div class="hero-ctas">
        <a href="/products" class="btn btn-accent">Shop the Drop</a>
        <a href="/drops" class="btn btn-ghost" style="border-color:#fff;color:#fff;">Release Calendar</a>
      </div>
    </div>
    <div class="countdown" id="countdown">
      <div class="cd-label">Next Drop</div>
      <div class="cd-model">Volt Runner OG · "Solar Flare"</div>
      <div class="cd-grid" id="cd-grid">
        <div class="cd-cell"><div class="cd-num" id="cd-d">--</div><div class="cd-unit">Days</div></div>
        <div class="cd-cell"><div class="cd-num" id="cd-h">--</div><div class="cd-unit">Hrs</div></div>
        <div class="cd-cell"><div class="cd-num" id="cd-m">--</div><div class="cd-unit">Min</div></div>
        <div class="cd-cell"><div class="cd-num" id="cd-s">--</div><div class="cd-unit">Sec</div></div>
      </div>
      <div class="cd-live" id="cd-live">🔥 Drop is LIVE — Shop now</div>
    </div>
  </div>
</section>

<section class="drop-section">
  <div class="sec-head">
    <div><h2>This Week's Drop</h2><p>Fresh pairs, released in limited runs.</p></div>
    <a href="/products" class="btn btn-ghost">View All →</a>
  </div>
  <div class="grid">${featured}</div>
</section>

<div class="strip">
  <div class="strip-inner">
    <div><div class="n">1<em>M+</em></div><div class="l">Pairs shipped</div></div>
    <div><div class="n">100<em>%</em></div><div class="l">Verified authentic</div></div>
    <div><div class="n">1</div><div class="l">Pair per customer</div></div>
    <div><div class="n">0</div><div class="l">Bots at checkout</div></div>
  </div>
</div>`,
    scripts: `${STORE_SCRIPTS}
<script>
  function nextDropDate(){
    const now = new Date();
    const t = new Date(now);
    t.setHours(11,0,0,0);              // 11:00 local
    let add = (6 - now.getDay() + 7) % 7;   // days until Saturday (6)
    if (add === 0 && t <= now) add = 7;
    t.setDate(t.getDate() + add);
    return t;
  }
  function pad(n){ return String(n).padStart(2,'0'); }
  function tick(){
    const target = nextDropDate();
    let diff = Math.floor((target - new Date())/1000);
    const grid = document.getElementById('cd-grid'), live = document.getElementById('cd-live');
    if (diff <= 0){ if(grid) grid.style.display='none'; if(live) live.style.display='block'; return; }
    const d = Math.floor(diff/86400); diff%=86400;
    const h = Math.floor(diff/3600);  diff%=3600;
    const m = Math.floor(diff/60);    const s = diff%60;
    const set=(id,v)=>{const el=document.getElementById(id); if(el) el.textContent=v;};
    set('cd-d', pad(d)); set('cd-h', pad(h)); set('cd-m', pad(m)); set('cd-s', pad(s));
  }
  tick(); setInterval(tick, 1000);
</script>`,
  });
}

// ── Page: Products (full catalog) ──────────────────────────────────────────────

function pageProducts(incident, loggedIn) {
  const cards = PRODUCTS.map(productCard).join('');
  return baseLayout({
    title: 'Shop — SoleDrop',
    incident, loggedIn,
    head: `<style>
      .shop-wrap{max-width:1200px;margin:0 auto;padding:3rem 1.5rem 1rem;}
      .shop-head{margin-bottom:1.75rem;}
      .shop-head h1{font-size:2.2rem;font-weight:900;text-transform:uppercase;letter-spacing:-0.02em;}
      .shop-head p{color:var(--muted);}
      .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:1.25rem;}
      .pc{background:var(--panel);border:1px solid var(--line-soft);border-radius:16px;overflow:hidden;box-shadow:var(--shadow-sm);transition:transform 0.15s,box-shadow 0.15s;}
      .pc:hover{transform:translateY(-4px);box-shadow:var(--shadow);}
      .pc-img{position:relative;aspect-ratio:4/3;display:flex;align-items:center;justify-content:center;padding:1.25rem;}
      .pc-shoe{width:82%;filter:drop-shadow(0 8px 10px rgba(0,0,0,0.12));}
      .pc-badge{position:absolute;top:0.75rem;left:0.75rem;}
      .pc-body{padding:1rem 1.1rem 1.2rem;}
      .pc-name{font-weight:800;font-size:1rem;letter-spacing:-0.01em;}
      .pc-color{color:var(--muted);font-size:0.8rem;margin-bottom:0.15rem;}
      .pc-price{font-weight:800;font-size:0.95rem;margin:0.4rem 0 0.85rem;}
    </style>`,
    body: `
<div class="shop-wrap">
  <div class="shop-head"><h1>Shop the Drop</h1><p>${PRODUCTS.length} styles · new pairs every Saturday.</p></div>
  <div class="grid">${cards}</div>
</div>`,
    scripts: STORE_SCRIPTS,
  });
}

// ── Page: Drops (release calendar) ─────────────────────────────────────────────

function pageDrops(incident, loggedIn) {
  const drops = [
    ['SAT · THIS WEEK', 'Volt Runner OG', '"Solar Flare"', 'Live raffle + shop', 'accent'],
    ['NEXT SAT', 'Grail High', '"Panda"', 'Raffle only', 'ink'],
    ['IN 2 WEEKS', 'Apex Trail 2', '"Trail Pack"', 'General release', 'ink'],
    ['IN 3 WEEKS', 'Cinder Low', '"Ember Restock"', 'Restock — notify list first', 'ink'],
  ];
  const rows = drops.map(([when, model, cw, note, kind]) => `
    <div class="drop-row">
      <div class="drop-when badge ${kind === 'accent' ? 'badge-accent' : 'badge-ink'}">${esc(when)}</div>
      <div class="drop-info"><div class="drop-model">${esc(model)} <span>${esc(cw)}</span></div><div class="drop-note">${esc(note)}</div></div>
      <a href="/products" class="btn btn-ghost drop-cta">Details →</a>
    </div>`).join('');
  return baseLayout({
    title: 'Release Calendar — SoleDrop',
    incident, loggedIn,
    head: `<style>
      .cal-wrap{max-width:860px;margin:0 auto;padding:3.5rem 1.5rem 1rem;}
      .cal-wrap h1{font-size:2.2rem;font-weight:900;text-transform:uppercase;letter-spacing:-0.02em;margin-bottom:0.4rem;}
      .cal-wrap>p{color:var(--muted);margin-bottom:2.25rem;}
      .drop-row{display:flex;align-items:center;gap:1.25rem;background:var(--panel);border:1px solid var(--line-soft);border-radius:14px;padding:1.1rem 1.25rem;margin-bottom:0.9rem;box-shadow:var(--shadow-sm);}
      .drop-when{white-space:nowrap;}
      .drop-info{flex:1;}
      .drop-model{font-weight:800;font-size:1.05rem;}
      .drop-model span{color:var(--accent);font-weight:700;}
      .drop-note{color:var(--muted);font-size:0.82rem;margin-top:0.15rem;}
      .drop-cta{padding:0.45rem 1rem;font-size:0.72rem;}
      @media(max-width:600px){.drop-cta{display:none;}}
    </style>`,
    body: `
<div class="cal-wrap">
  <h1>Release Calendar</h1>
  <p>Every drop goes live Saturday at 11:00 AM ET. Set your notifications so you never miss a pair.</p>
  ${rows}
</div>`,
  });
}

// ── Page: Login ───────────────────────────────────────────────────────────────

function pageLogin(error) {
  return baseLayout({
    title: 'Sign In — SoleDrop',
    incident: null, loggedIn: false, ticker: false,
    head: `<style>
      .login-wrap{min-height:calc(100vh - 128px);display:flex;align-items:center;justify-content:center;padding:2rem 1.5rem;}
      .login-card{background:var(--panel);border:1px solid var(--line-soft);border-radius:20px;padding:2.5rem;width:100%;max-width:400px;box-shadow:var(--shadow);}
      .login-card h1{font-size:1.5rem;font-weight:900;text-transform:uppercase;letter-spacing:-0.01em;margin-bottom:0.35rem;}
      .login-card>p{color:var(--muted);font-size:0.875rem;margin-bottom:2rem;}
      .form-group{margin-bottom:1.25rem;}
      .form-group label{display:block;font-size:0.75rem;font-weight:800;text-transform:uppercase;letter-spacing:0.05em;color:var(--ink2);margin-bottom:0.4rem;}
      .form-group input{width:100%;background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:0.7rem 0.9rem;color:var(--ink);font-size:0.9rem;font-family:inherit;outline:none;transition:border-color 0.15s;}
      .form-group input:focus{border-color:var(--accent);}
      .login-btn{width:100%;padding:0.8rem;background:var(--accent);color:#fff;border:none;border-radius:999px;font-size:0.85rem;font-weight:800;text-transform:uppercase;letter-spacing:0.03em;cursor:pointer;font-family:inherit;transition:background 0.15s;}
      .login-btn:hover{background:var(--accent-dk);}
      .login-error{background:rgba(229,52,43,0.1);border:1px solid rgba(229,52,43,0.3);color:#b91c1c;font-size:0.82rem;padding:0.65rem 0.9rem;border-radius:10px;margin-bottom:1.25rem;}
      .login-hint{text-align:center;font-size:0.78rem;color:var(--muted);margin-top:1.25rem;}
    </style>`,
    body: `
<div class="login-wrap">
  <div class="login-card">
    <h1>Welcome back</h1>
    <p>Sign in to enter raffles, cop drops, and track orders.</p>
    ${error ? `<div class="login-error">${esc(error)}</div>` : ''}
    <form method="POST" action="/login">
      <div class="form-group"><label for="username">Email or Username</label><input type="text" id="username" name="username" autocomplete="username" required/></div>
      <div class="form-group"><label for="password">Password</label><input type="password" id="password" name="password" autocomplete="current-password" required/></div>
      <button type="submit" class="login-btn">Sign In</button>
    </form>
    <div class="login-hint">New here? Membership is free — creating an account gets you drop alerts.</div>
  </div>
</div>`,
  });
}

// ── Page: Status ──────────────────────────────────────────────────────────────

function pageStatus(loggedIn) {
  return baseLayout({
    title: 'System Status — SoleDrop',
    incident: null, loggedIn, ticker: false,
    head: `<style>
      .status-page{max-width:820px;margin:0 auto;padding:3rem 1.5rem;}
      .status-header{margin-bottom:2.5rem;}.status-header h1{font-size:1.9rem;font-weight:900;text-transform:uppercase;letter-spacing:-0.02em;margin-bottom:0.4rem;}.status-header p{color:var(--muted);font-size:0.875rem;}
      .overall-status{border-radius:14px;padding:1.25rem 1.5rem;display:flex;align-items:center;gap:1rem;margin-bottom:2.5rem;border:1px solid;}
      .overall-status.operational{background:rgba(18,161,80,0.09);border-color:rgba(18,161,80,0.3);}
      .overall-status.degraded{background:rgba(224,138,0,0.1);border-color:rgba(224,138,0,0.35);}
      .overall-status.outage{background:rgba(229,52,43,0.09);border-color:rgba(229,52,43,0.3);}
      .status-icon{font-size:1.5rem;}.status-text h2{font-size:1.1rem;font-weight:800;color:var(--ink);}.status-text p{font-size:0.8rem;color:var(--muted);margin-top:0.15rem;}
      .status-updated{margin-left:auto;font-size:0.75rem;color:var(--muted);white-space:nowrap;}
      #incident-details{display:none;margin-bottom:2.5rem;}
      .incident-panel{background:rgba(229,52,43,0.04);border:1px solid rgba(229,52,43,0.28);border-radius:14px;overflow:hidden;}
      .incident-panel-header{background:rgba(229,52,43,0.1);padding:0.9rem 1.4rem;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid rgba(229,52,43,0.2);}
      .incident-panel-title{font-size:0.78rem;font-weight:800;letter-spacing:0.06em;text-transform:uppercase;color:#b91c1c;}
      .incident-panel-badge{font-size:0.68rem;font-weight:800;padding:0.2rem 0.55rem;border-radius:99px;background:#e5342b;color:#fff;animation:blink-badge 1.8s ease-in-out infinite;}
      @keyframes blink-badge{0%,100%{opacity:1}50%{opacity:0.45}}
      .atk-timeline{padding:1.4rem 1.4rem 0.4rem;}.atk-timeline-title{font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted);margin-bottom:1rem;}
      .atk-phase{display:flex;gap:1rem;margin-bottom:1.1rem;position:relative;}
      .atk-phase:not(:last-child)::before{content:'';position:absolute;left:15px;top:32px;bottom:-12px;width:1px;background:rgba(229,52,43,0.25);}
      .atk-num{width:32px;height:32px;border-radius:50%;flex-shrink:0;background:rgba(229,52,43,0.12);border:1px solid rgba(229,52,43,0.35);display:flex;align-items:center;justify-content:center;font-size:0.72rem;font-weight:800;color:#b91c1c;}
      .atk-body{flex:1;}.atk-label{font-size:0.85rem;font-weight:800;color:var(--ink);margin-bottom:0.15rem;}.atk-desc{font-size:0.8rem;color:var(--ink2);line-height:1.6;}
      .atk-desc code{background:rgba(21,18,16,0.06);padding:0.05rem 0.3rem;border-radius:4px;}
      .atk-tags{display:flex;flex-wrap:wrap;gap:0.3rem;margin-top:0.45rem;}
      .atk-tag{font-size:0.66rem;font-family:'JetBrains Mono',monospace;font-weight:500;padding:0.15rem 0.45rem;border-radius:4px;background:rgba(229,52,43,0.08);border:1px solid rgba(229,52,43,0.2);color:#b91c1c;}
      .ioc-section{padding:0 1.4rem 1.2rem;border-top:1px solid rgba(229,52,43,0.15);margin-top:0.4rem;}
      .ioc-section-title{font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted);margin:1rem 0 0.75rem;}
      .ioc-table{width:100%;border-collapse:collapse;}.ioc-table td{padding:0.5rem 0.6rem;font-size:0.8rem;border-bottom:1px solid var(--line-soft);vertical-align:top;}
      .ioc-table td:first-child{color:var(--muted);font-weight:600;width:38%;white-space:nowrap;}.ioc-table td:last-child{color:var(--ink);font-family:'JetBrains Mono',monospace;font-size:0.74rem;word-break:break-all;}
      .ioc-table tr:last-child td{border-bottom:none;}.ioc-high{color:#b91c1c !important;}.ioc-med{color:#a35d00 !important;}
      .remediation-section{padding:0 1.4rem 1.4rem;border-top:1px solid rgba(229,52,43,0.15);}
      .remediation-section-header{display:flex;align-items:center;justify-content:space-between;margin:1rem 0 0.75rem;}
      .remediation-section-title{font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted);}
      .remediation-progress{font-size:0.72rem;color:var(--muted);}.remediation-progress span{color:var(--good);font-weight:800;}
      .checklist{list-style:none;}.checklist li{display:flex;align-items:flex-start;gap:0.75rem;padding:0.55rem 0;border-bottom:1px solid var(--line-soft);cursor:pointer;}
      .checklist li:last-child{border-bottom:none;}
      .check-box{width:18px;height:18px;border-radius:5px;flex-shrink:0;margin-top:2px;border:1.5px solid rgba(21,18,16,0.28);background:transparent;display:flex;align-items:center;justify-content:center;font-size:0.7rem;transition:all 0.15s;}
      .check-box.checked{background:var(--good);border-color:var(--good);color:#fff;}
      .checklist li .check-text{flex:1;}.check-title{font-size:0.85rem;font-weight:700;color:var(--ink);line-height:1.35;}.check-title.completed{color:var(--muted);text-decoration:line-through;}
      .check-hint{font-size:0.75rem;color:var(--muted);margin-top:0.15rem;line-height:1.45;}
      .remediation-note{margin-top:1rem;padding:0.65rem 0.9rem;border-radius:10px;background:rgba(224,138,0,0.1);border:1px solid rgba(224,138,0,0.25);font-size:0.76rem;color:#a35d00;line-height:1.5;}
      .services-section{margin-bottom:2.5rem;}.services-section h3,.uptime-section h3,.incidents-section h3{font-size:0.75rem;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted);margin-bottom:0.75rem;}
      .service-row{display:flex;align-items:center;justify-content:space-between;padding:0.9rem 1.1rem;border-bottom:1px solid var(--line-soft);}
      .service-row:first-of-type{border-top:1px solid var(--line-soft);}
      .service-name{font-size:0.875rem;font-weight:600;color:var(--ink);}.service-name small{display:block;font-size:0.75rem;color:var(--muted);font-weight:400;margin-top:0.1rem;}
      .service-status{display:flex;align-items:center;gap:0.4rem;font-size:0.78rem;font-weight:700;}
      .dot{width:8px;height:8px;border-radius:50%;}.dot-green{background:var(--good);}.dot-yellow{background:var(--warn);animation:pulse-yellow 1.4s ease-in-out infinite;}.dot-red{background:var(--bad);animation:pulse-red2 1.2s ease-in-out infinite;}
      @keyframes pulse-yellow{0%,100%{opacity:1}50%{opacity:0.45}}@keyframes pulse-red2{0%,100%{opacity:1}50%{opacity:0.4}}
      .uptime-section{margin-bottom:2.5rem;}
      .uptime-row{margin-bottom:1.1rem;}.uptime-row-header{display:flex;justify-content:space-between;align-items:center;font-size:0.82rem;margin-bottom:0.4rem;}
      .uptime-row-header span:first-child{color:var(--ink);font-weight:600;}.uptime-row-header span:last-child{color:var(--muted);}
      .uptime-bars{display:flex;gap:2px;}.bar{flex:1;height:28px;border-radius:3px;cursor:default;}.bar-green{background:var(--good);opacity:0.55;}.bar-green:hover{opacity:1;}.bar-yellow{background:var(--warn);opacity:0.85;}.bar-red{background:var(--bad);opacity:0.9;}
      .uptime-legend{display:flex;justify-content:space-between;margin-top:0.3rem;font-size:0.7rem;color:var(--muted);}
      .incident-card{background:var(--panel);border:1px solid var(--line-soft);border-radius:12px;padding:1.1rem 1.25rem;margin-bottom:0.75rem;box-shadow:var(--shadow-sm);}
      .incident-card.active-incident{background:rgba(229,52,43,0.05);border-color:rgba(229,52,43,0.3);}
      .incident-header{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:0.5rem;}
      .incident-title{font-size:0.9rem;font-weight:700;color:var(--ink);}.incident-date{font-size:0.72rem;color:var(--muted);white-space:nowrap;flex-shrink:0;}
      .incident-body{font-size:0.82rem;color:var(--ink2);line-height:1.65;}.incident-body strong{color:var(--ink);}
      .incident-affected{margin-top:0.6rem;display:flex;gap:0.4rem;flex-wrap:wrap;}
      .no-incidents{color:var(--muted);font-size:0.875rem;padding:1.5rem 0;text-align:center;}
    </style>`,
    body: `
<div class="status-page">
  <div class="status-header"><h1>System Status</h1><p>Real-time status of the SoleDrop storefront and drop infrastructure.</p></div>

  <div id="overall-status" class="overall-status operational">
    <div class="status-icon" id="overall-icon">✅</div>
    <div class="status-text"><h2 id="overall-title">All Systems Operational</h2><p id="overall-desc">The storefront and checkout are running normally.</p></div>
    <div class="status-updated" id="status-updated">Updated just now</div>
  </div>

  <div id="incident-details">
    <div class="incident-panel">
      <div class="incident-panel-header">
        <div class="incident-panel-title">🔴 &nbsp; Active Security Incident — Drop-Day Bot Swarm Detected</div>
        <div class="incident-panel-badge">LIVE</div>
      </div>
      <div class="atk-timeline">
        <div class="atk-timeline-title">Attack Timeline — What We Detected</div>
        <div class="atk-phase">
          <div class="atk-num">1</div>
          <div class="atk-body">
            <div class="atk-label">WAF Anomaly — Automated Inventory Recon</div>
            <div class="atk-desc">Ahead of the drop, an automated client enumerated hidden release URLs and scraped stock — hammering <code>/api/v1/products</code> and probing <code>/search</code>, <code>/.env</code>, and <code>/api/v1/admin</code>. SQL injection payloads were injected into the search query parameters to dump the product/inventory tables. Every request carried a spoofed <code>X-Forwarded-For</code> header.</div>
            <div class="atk-tags"><span class="atk-tag">WAFSQLiAttackScore &gt; 60</span><span class="atk-tag">path enumeration</span><span class="atk-tag">X-Forwarded-For spoofing</span><span class="atk-tag">BotScore: 24</span></div>
          </div>
        </div>
        <div class="atk-phase">
          <div class="atk-num">2</div>
          <div class="atk-body">
            <div class="atk-label">Bot Management — Sneaker-Bot Swarm at Drop Time</div>
            <div class="atk-desc">At 11:00 the storefront took a coordinated swarm — thousands of add-to-cart requests per second from a rotating pool of residential proxies and 22 different User-Agents. Despite the rotation, the TLS fingerprint stayed constant: a headless-automation JA4 hash that does not change with the User-Agent. Cloudflare Bot Management flagged the entire swarm as a single automated origin.</div>
            <div class="atk-tags"><span class="atk-tag">JA4: t13d1516h2_8daaf6152771_b0da82dd1658</span><span class="atk-tag">BotDetectionTags: automation, checkout</span><span class="atk-tag">3,400 req/s</span></div>
          </div>
        </div>
        <div class="atk-phase">
          <div class="atk-num">3</div>
          <div class="atk-body">
            <div class="atk-label">Credential Stuffing — Account Takeover on /login</div>
            <div class="atk-desc">The bot replayed a leaked credential list against <code>/login</code> — 60k+ attempts — hunting for accounts with saved payment methods and existing raffle entries to hijack. The 401 error rate on the auth endpoint spiked 400×. Successful logins from the swarm's JA4 were flagged as suspected account takeover.</div>
            <div class="atk-tags"><span class="atk-tag">401 rate spike &gt; 400x</span><span class="atk-tag">credential stuffing</span><span class="atk-tag">leaked combolist</span><span class="atk-tag">ATO suspected</span></div>
          </div>
        </div>
        <div class="atk-phase">
          <div class="atk-num">4</div>
          <div class="atk-body">
            <div class="atk-label">Checkout Abuse — Carding &amp; Inventory Hoarding</div>
            <div class="atk-desc">Full breakout: automated checkout against <code>/api/v1/checkout</code> combined with carding (rapid-fire validation of stolen card numbers) and cart-hoarding to lock inventory away from real buyers. An SSRF probe targeting <code>169.254.169.254</code> (cloud metadata endpoint) was injected into a webhook URL field. Cloudflare Rate Limiting and the checkout Waiting Room absorbed the flood.</div>
            <div class="atk-tags"><span class="atk-tag">Rate limit exceeded</span><span class="atk-tag">carding pattern</span><span class="atk-tag">SSRF: 169.254.169.254</span><span class="atk-tag">inventory hoarding</span></div>
          </div>
        </div>
      </div>
      <div class="ioc-section">
        <div class="ioc-section-title">Indicators of Compromise (IOCs)</div>
        <table class="ioc-table">
          <tr><td>Source Origin</td><td class="ioc-high">Datacenter ASN + residential proxy pool — rotating spoofed IPs via X-Forwarded-For</td></tr>
          <tr><td>TLS Fingerprint (JA4)</td><td class="ioc-high">t13d1516h2_8daaf6152771_b0da82dd1658 — headless automation, constant across all traffic</td></tr>
          <tr><td>Bot Score</td><td class="ioc-med">24 / 100 — Source: Heuristics — Tags: ["automation", "checkout"]</td></tr>
          <tr><td>Peak Request Rate</td><td class="ioc-med">3,400 req/s against /api/v1/products and /api/v1/checkout</td></tr>
          <tr><td>Credential Stuffing</td><td class="ioc-high">60k+ attempts on /login — 401 rate spike &gt; 400x baseline</td></tr>
          <tr><td>Attack Duration</td><td>4-phase campaign — recon → bot swarm → credential stuffing → checkout abuse</td></tr>
        </table>
      </div>
      <div class="remediation-section">
        <div class="remediation-section-header">
          <div class="remediation-section-title">Remediation Checklist</div>
          <div class="remediation-progress"><span id="check-count">0</span> / 7 steps completed</div>
        </div>
        <ul class="checklist" id="remediation-checklist">
          <li onclick="toggleCheck(0)"><div class="check-box" id="chk-0"></div><div class="check-text"><div class="check-title" id="chk-title-0">Identify bot origin in Cloudflare Security Events</div><div class="check-hint">Filter CF Security Events by the drop timeframe. The real ClientIP is the datacenter/proxy origin — X-Forwarded-For values are spoofed. Note the RayID chain and the source ASN.</div></div></li>
          <li onclick="toggleCheck(1)"><div class="check-box" id="chk-1"></div><div class="check-text"><div class="check-title" id="chk-title-1">Block source IP / ASN in Cloudflare WAF</div><div class="check-hint">Security → WAF → Custom Rules → create rule: ip.src eq &lt;origin-ip&gt; (or ip.geoip.asnum eq &lt;asn&gt;) → Block. Stops the swarm's origin immediately.</div></div></li>
          <li onclick="toggleCheck(2)"><div class="check-box" id="chk-2"></div><div class="check-text"><div class="check-title" id="chk-title-2">Create JA4 fingerprint block in Bot Management</div><div class="check-hint">Bot Management → Custom Rules → cf.bot_management.ja4 eq "t13d1516h2_8daaf6152771_b0da82dd1658" → Block. Catches the bot even when it rotates IPs and User-Agents.</div></div></li>
          <li onclick="toggleCheck(3)"><div class="check-box" id="chk-3"></div><div class="check-text"><div class="check-title" id="chk-title-3">Enable Rate Limiting + Waiting Room on checkout</div><div class="check-hint">Turn on the drop-day Waiting Room for /products and /api/v1/checkout, and add a Rate Limiting rule (e.g. 10 req/10s per IP) on add-to-cart. Consider "Under Attack" mode if the swarm persists.</div></div></li>
          <li onclick="toggleCheck(4)"><div class="check-box" id="chk-4"></div><div class="check-text"><div class="check-title" id="chk-title-4">Correlate the full attack chain in SentinelOne AI-SIEM</div><div class="check-hint">PowerQuery: filter by JA4 = "t13d1516h2_8daaf6152771_b0da82dd1658" → confirm the same actor across recon, swarm, credential stuffing, and checkout abuse. Use Purple AI: "Summarize the drop-day bot attack linking WAF, Bot Management, and login events."</div></div></li>
          <li onclick="toggleCheck(5)"><div class="check-box" id="chk-5"></div><div class="check-text"><div class="check-title" id="chk-title-5">Force reset + revoke sessions on stuffed accounts</div><div class="check-hint">Identify accounts with successful logins from the attacker's JA4 in the last 24h. Force a password reset, revoke active sessions, and flag any raffle entries or orders placed from those sessions.</div></div></li>
          <li onclick="toggleCheck(6)"><div class="check-box" id="chk-6"></div><div class="check-text"><div class="check-title" id="chk-title-6">Open SentinelOne incident + notify fraud/security</div><div class="check-hint">Create a Critical incident linking all 4 phases. Add IOCs for the source ASN and JA4, block the carding BIN ranges with the payment processor, and page on-call if not already fired.</div></div></li>
        </ul>
        <div class="remediation-note">⚠️ &nbsp; Completing this checklist does <strong>not</strong> automatically resolve the incident. Your security team must confirm all Cloudflare/S1 controls are in place and signal an all-clear before this page returns to operational status.</div>
      </div>
    </div>
  </div>

  <div class="services-section">
    <h3>Services</h3>
    <div id="services-list">
      <div class="service-row"><div class="service-name">Storefront<small>shop.soledrop.co · web &amp; mobile</small></div><div class="service-status" id="svc-store"><div class="dot dot-green"></div> Operational</div></div>
      <div class="service-row"><div class="service-name">Checkout API<small>Cart · payments · order placement</small></div><div class="service-status" id="svc-checkout"><div class="dot dot-green"></div> Operational</div></div>
      <div class="service-row"><div class="service-name">Inventory Service<small>Stock counts · reservations · raffles</small></div><div class="service-status" id="svc-inventory"><div class="dot dot-green"></div> Operational</div></div>
      <div class="service-row"><div class="service-name">Customer Accounts<small>Login · profiles · saved payment</small></div><div class="service-status" id="svc-accounts"><div class="dot dot-green"></div> Operational</div></div>
      <div class="service-row"><div class="service-name">Search &amp; Catalog<small>Product search · browse</small></div><div class="service-status" id="svc-search"><div class="dot dot-green"></div> Operational</div></div>
      <div class="service-row"><div class="service-name">CDN / Edge<small>Images · assets · caching</small></div><div class="service-status" id="svc-cdn"><div class="dot dot-green"></div> Operational</div></div>
    </div>
  </div>

  <div class="uptime-section">
    <h3>90-Day Uptime</h3>
    <div class="uptime-row"><div class="uptime-row-header"><span>Storefront</span><span id="up-store">99.98%</span></div><div class="uptime-bars" id="bars-store"></div><div class="uptime-legend"><span>90 days ago</span><span>Today</span></div></div>
    <div class="uptime-row"><div class="uptime-row-header"><span>Checkout API</span><span id="up-checkout">99.95%</span></div><div class="uptime-bars" id="bars-checkout"></div><div class="uptime-legend"><span>90 days ago</span><span>Today</span></div></div>
    <div class="uptime-row"><div class="uptime-row-header"><span>CDN / Edge</span><span id="up-cdn">100%</span></div><div class="uptime-bars" id="bars-cdn"></div><div class="uptime-legend"><span>90 days ago</span><span>Today</span></div></div>
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
  buildBars('bars-store',    99.98, false);
  buildBars('bars-checkout', 99.95, false);
  buildBars('bars-cdn',      100,   false);

  const CHECKS_KEY = 'sd_remediation_checks';
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

  const SERVICE_MAP = {
    'Storefront':'svc-store', 'Checkout API':'svc-checkout', 'Inventory':'svc-inventory',
    'Inventory Service':'svc-inventory', 'Customer Accounts':'svc-accounts', 'Accounts':'svc-accounts',
    'Search':'svc-search', 'Search & Catalog':'svc-search', 'CDN':'svc-cdn', 'CDN / Edge':'svc-cdn'
  };
  const ALL_SVC = ['svc-store','svc-checkout','svc-inventory','svc-accounts','svc-search','svc-cdn'];

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
      ALL_SVC.forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = '<div class="dot dot-green"></div> Operational'; });
      affected.forEach(svc => { const el = document.getElementById(SERVICE_MAP[svc] || ''); if (el) el.innerHTML = '<div class="dot ' + (isCritical ? 'dot-red' : 'dot-yellow') + '"></div> ' + (isCritical ? 'Outage' : 'Degraded'); });
      buildBars('bars-store',    99.98, affected.includes('Storefront'));
      buildBars('bars-checkout', 99.95, affected.includes('Checkout API'));
      buildBars('bars-cdn',      100,   affected.includes('CDN') || affected.includes('CDN / Edge'));
      const startedAt = data.started_at ? new Date(data.started_at).toLocaleString() : new Date().toLocaleString();
      incidentsList.innerHTML = '<div class="incident-card active-incident"><div class="incident-header"><div class="incident-title">🔴 ' + (data.title || 'Active Incident') + '</div><div class="incident-date">' + startedAt + '</div></div><div class="incident-body"><strong>Status: Investigating</strong><br>' + (data.message || '') + (affected.length ? '<div class="incident-affected">' + affected.map(s => '<span class="badge badge-red">' + s + '</span>').join('') + '</div>' : '') + '</div></div>';
    } else {
      overall.className = 'overall-status operational'; icon.textContent = '✅';
      title.textContent = 'All Systems Operational'; desc.textContent = 'The storefront and checkout are running normally.';
      details.style.display = 'none';
      ALL_SVC.forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = '<div class="dot dot-green"></div> Operational'; });
      buildBars('bars-store', 99.98, false); buildBars('bars-checkout', 99.95, false); buildBars('bars-cdn', 100, false);
      incidentsList.innerHTML = '<p class="no-incidents">No incidents in the past 90 days.</p>';
      checks = Array(7).fill(false); localStorage.setItem(CHECKS_KEY, JSON.stringify(checks)); renderChecks();
    }
  }
  pollIncident();
</script>`,
  });
}

// ── Page: Chat (SoleDrop Concierge) ────────────────────────────────────────────

function pageChat(username, incident) {
  return baseLayout({
    title: 'Concierge — SoleDrop',
    incident, loggedIn: true, ticker: false,
    head: `<style>
      .chat-wrap{max-width:800px;margin:0 auto;padding:2rem 1.5rem;display:flex;flex-direction:column;height:calc(100vh - 150px);}
      .chat-header{margin-bottom:1.5rem;}.chat-header h1{font-size:1.4rem;font-weight:900;text-transform:uppercase;letter-spacing:-0.01em;}.chat-header p{color:var(--muted);font-size:0.82rem;}
      .chat-messages{flex:1;overflow-y:auto;border:1px solid var(--line-soft);border-radius:16px;padding:1.25rem;background:var(--panel);margin-bottom:1rem;display:flex;flex-direction:column;gap:1rem;box-shadow:var(--shadow-sm);}
      .msg{max-width:85%;}.msg-user{align-self:flex-end;}.msg-assistant{align-self:flex-start;}
      .msg-bubble{padding:0.7rem 1rem;border-radius:14px;font-size:0.875rem;line-height:1.6;}
      .msg-user .msg-bubble{background:var(--accent);color:#fff;border-bottom-right-radius:4px;}
      .msg-assistant .msg-bubble{background:var(--bg);color:var(--ink);border-bottom-left-radius:4px;border:1px solid var(--line-soft);}
      .msg-meta{font-size:0.7rem;color:var(--muted);margin-top:0.25rem;}
      .msg-user .msg-meta{text-align:right;}.msg-assistant .msg-meta{text-align:left;}
      .chat-input-row{display:flex;gap:0.75rem;}
      .chat-input{flex:1;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:0.75rem 1rem;color:var(--ink);font-size:0.875rem;font-family:inherit;outline:none;resize:none;transition:border-color 0.15s;}
      .chat-input:focus{border-color:var(--accent);}
      .chat-send{background:var(--accent);color:#fff;border:none;border-radius:12px;padding:0.75rem 1.4rem;font-weight:800;text-transform:uppercase;letter-spacing:0.03em;font-size:0.78rem;cursor:pointer;font-family:inherit;transition:background 0.15s;white-space:nowrap;}
      .chat-send:hover{background:var(--accent-dk);}.chat-send:disabled{opacity:0.5;cursor:not-allowed;}
    </style>`,
    body: `
<div class="chat-wrap">
  <div class="chat-header"><h1>SoleDrop Concierge</h1><p>Ask about drops, raffles, sizing, shipping &amp; orders</p></div>
  <div class="chat-messages" id="chat-messages">
    <div class="msg msg-assistant">
      <div class="msg-bubble">Hey${username ? ' ' + esc(username) : ''}! 👟 I'm the SoleDrop Concierge. Ask me about the next drop, raffle entries, sizing, shipping, or your orders.</div>
      <div class="msg-meta">SoleDrop · just now</div>
    </div>
  </div>
  <div class="chat-input-row">
    <textarea class="chat-input" id="chat-input" rows="2" placeholder="Ask SoleDrop…"></textarea>
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
      const res = await fetch('/api/v1/chat', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({prompt, model:'soledrop-concierge-v1'}) });
      const data = await res.json();
      const reply = data.choices?.[0]?.message?.content || data.error || 'Error';
      msgs.innerHTML += '<div class="msg msg-assistant"><div class="msg-bubble">' + reply.replace(/</g,'&lt;') + '</div><div class="msg-meta">SoleDrop · just now</div></div>';
    } catch(e) {
      msgs.innerHTML += '<div class="msg msg-assistant"><div class="msg-bubble">Sorry, something went wrong. Please try again.</div><div class="msg-meta">SoleDrop · just now</div></div>';
    }
    msgs.scrollTop = msgs.scrollHeight;
    btn.disabled = false; input.focus();
  }
  document.getElementById('chat-input').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } });
</script>`,
  });
}

// ── Page: Dashboard (customer account) ─────────────────────────────────────────

function pageDashboard(username, incident) {
  return baseLayout({
    title: 'Account — SoleDrop',
    incident, loggedIn: true, ticker: false,
    head: `<style>
      .dash-wrap{max-width:1100px;margin:0 auto;padding:3rem 1.5rem;}
      .dash-header{margin-bottom:2rem;}.dash-header h1{font-size:1.7rem;font-weight:900;text-transform:uppercase;letter-spacing:-0.02em;}.dash-header p{color:var(--muted);}
      .dash-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1.25rem;margin-bottom:2.5rem;}
      .dash-card{background:var(--panel);border:1px solid var(--line-soft);border-radius:14px;padding:1.5rem;box-shadow:var(--shadow-sm);}
      .dash-card-label{font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted);margin-bottom:0.5rem;}
      .dash-card-value{font-size:1.9rem;font-weight:900;color:var(--ink);letter-spacing:-0.02em;}
      .dash-card-value em{color:var(--accent);font-style:normal;}
      .dash-card-sub{font-size:0.78rem;color:var(--muted);margin-top:0.25rem;}
      .dash-section{background:var(--panel);border:1px solid var(--line-soft);border-radius:14px;padding:1.5rem;margin-bottom:1.25rem;box-shadow:var(--shadow-sm);}
      .dash-section h3{font-size:0.95rem;font-weight:800;color:var(--ink);margin-bottom:1rem;text-transform:uppercase;letter-spacing:-0.01em;}
      .row{display:flex;align-items:center;justify-content:space-between;padding:0.7rem 0;border-bottom:1px solid var(--line-soft);font-size:0.85rem;}
      .row:last-child{border-bottom:none;}.row .name{font-weight:600;color:var(--ink);}.row .meta{color:var(--muted);font-size:0.78rem;}
    </style>`,
    body: `
<div class="dash-wrap">
  <div class="dash-header"><h1>Hey, ${esc(username || 'Member')} 👟</h1><p>Your drops, raffles, and orders.</p></div>
  <div class="dash-grid">
    <div class="dash-card"><div class="dash-card-label">Heat Points</div><div class="dash-card-value">2,<em>480</em></div><div class="dash-card-sub">520 to Early Access tier</div></div>
    <div class="dash-card"><div class="dash-card-label">Raffle Entries</div><div class="dash-card-value">3</div><div class="dash-card-sub">This week's drop</div></div>
    <div class="dash-card"><div class="dash-card-label">Orders</div><div class="dash-card-value">7</div><div class="dash-card-sub">1 in transit</div></div>
    <div class="dash-card"><div class="dash-card-label">Member Since</div><div class="dash-card-value">'24</div><div class="dash-card-sub">Verified member</div></div>
  </div>
  <div class="dash-section">
    <h3>Active Raffle Entries</h3>
    <div class="row"><div class="name">Grail High "Panda"</div><div class="meta">Draw Fri 5PM ET · pending</div></div>
    <div class="row"><div class="name">Cinder Low "Ember Red"</div><div class="meta">Draw Sat 9AM ET · pending</div></div>
    <div class="row"><div class="name">Volt Runner OG "Solar Flare"</div><div class="meta">Draw Sat 9AM ET · pending</div></div>
  </div>
  <div class="dash-section">
    <h3>Recent Orders</h3>
    <div class="row"><div class="name">Apex Trail 2 "Midnight Navy"</div><div class="meta">SD-48213 · in transit</div></div>
    <div class="row"><div class="name">Drift Mesh "Arctic Blue"</div><div class="meta">SD-47990 · delivered</div></div>
    <div class="row"><div class="name">Pulse Knit "Lime Shock"</div><div class="meta">SD-47651 · delivered</div></div>
  </div>
</div>`,
  });
}

// ── Page: Admin gate (unauthenticated) ───────────────────────────────────────

function pageAdminGate(incident) {
  return baseLayout({
    title: 'Admin — SoleDrop',
    incident, loggedIn: false, ticker: false,
    body: `<div style="max-width:500px;margin:5rem auto;padding:0 1.5rem;text-align:center;">
      <div style="font-size:2rem;margin-bottom:1rem;">🔒</div>
      <h1 style="font-size:1.5rem;font-weight:900;text-transform:uppercase;letter-spacing:-0.01em;color:var(--ink);margin-bottom:0.5rem;">Admin Access Required</h1>
      <p style="color:var(--muted);font-size:0.875rem;margin-bottom:1.5rem;">This area requires administrative privileges.</p>
      <a href="/login" class="btn btn-accent">Sign In</a>
    </div>`,
  });
}

// ── Page: Admin (authenticated) ───────────────────────────────────────────────

function pageAdmin(username, incident) {
  return baseLayout({
    title: 'Admin — SoleDrop',
    incident, loggedIn: true, ticker: false,
    body: `<div style="max-width:900px;margin:0 auto;padding:3rem 1.5rem;">
      <h1 style="font-size:1.7rem;font-weight:900;text-transform:uppercase;letter-spacing:-0.02em;color:var(--ink);margin-bottom:0.5rem;">Admin Panel</h1>
      <p style="color:var(--muted);margin-bottom:2rem;">Signed in as <strong style="color:var(--ink);">${esc(username || 'admin')}</strong></p>
      <div style="background:var(--panel);border:1px solid var(--line-soft);border-radius:14px;padding:1.5rem;box-shadow:var(--shadow-sm);">
        <p style="color:var(--muted);font-size:0.875rem;">Drop scheduling, inventory, and raffle management. Use the API for programmatic access.</p>
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
      return html(pageProducts(incident, loggedIn));
    }

    if (path === '/drops' && method === 'GET') {
      const incident = await getIncident(env);
      return html(pageDrops(incident, loggedIn));
    }

    // ── Auth routes ─────────────────────────────────────────────────────────

    if (path === '/login') {
      if (loggedIn) return redirect('/dashboard');
      if (method === 'GET') return html(pageLogin(null));
      if (method === 'POST') {
        const formData = await request.formData();
        const username = formData.get('username') || '';
        const password = formData.get('password') || '';
        const validUser = env.APP_USERNAME || 'admin';
        const validPass = env.APP_PASSWORD || 'soledrop';
        if (username === validUser && password === validPass) {
          const cookie = await buildSessionCookie(username, secret);
          return new Response(null, { status: 302, headers: { Location: '/dashboard', 'Set-Cookie': cookie } });
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
      return html(baseLayout({ title: 'Profile — SoleDrop', incident, loggedIn: true, ticker: false,
        body: `<div style="max-width:700px;margin:0 auto;padding:3rem 1.5rem;"><h1 style="font-size:1.5rem;font-weight:900;text-transform:uppercase;letter-spacing:-0.01em;color:var(--ink);margin-bottom:0.5rem;">Profile</h1><p style="color:var(--muted);margin-bottom:2rem;">Signed in as <strong style="color:var(--ink);">${esc(session.u)}</strong></p><div style="background:var(--panel);border:1px solid var(--line-soft);border-radius:14px;padding:1.5rem;box-shadow:var(--shadow-sm);"><p style="color:var(--muted);font-size:0.875rem;">Account settings, saved addresses, and payment methods.</p></div></div>`,
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

    if (path === '/api/v1/products' && method === 'GET') {
      return json({
        object: 'list',
        data: PRODUCTS.map(p => ({
          id: p.id, name: p.name, colorway: p.colorway, price_usd: p.price,
          status: p.state === 'soldout' ? 'sold_out' : p.state === 'raffle' ? 'raffle' : 'available',
        })),
        total: PRODUCTS.length,
      });
    }

    // Back-compat alias — some clients/simulators still hit /api/v1/models.
    if (path === '/api/v1/models' && method === 'GET') {
      return json({
        object: 'list',
        data: PRODUCTS.map(p => ({ id: p.id, object: 'product', owned_by: 'soledrop', price_usd: p.price })),
        total: PRODUCTS.length,
      });
    }

    if (path === '/api/v1/customers' && method === 'GET') {
      if (!loggedIn) return json({ error: 'Unauthorized', code: 401, message: 'Valid API key required.' }, 401);
      return json({
        customers: [
          { id: 'cus_8f3a2c', email: 'hypebeast@example.com', orders: 12, heat_points: 8400, tier: 'grail' },
          { id: 'cus_4e7b1d', email: 'sneakerfiend@example.com', orders: 3, heat_points: 620, tier: 'member' },
        ],
      });
    }

    // Back-compat alias for the CTF simulator's exfil target.
    if (path === '/api/v1/training-data' && method === 'GET') {
      if (!loggedIn) return json({ error: 'Unauthorized', code: 401, message: 'Valid API key required.' }, 401);
      return json({
        datasets: [
          { id: 'ds_8f3a2c', name: 'customer-orders-2026', rows: 847293, size_gb: 12.4, status: 'ready' },
          { id: 'ds_4e7b1d', name: 'raffle-entries-current', rows: 142000, size_gb: 3.1, status: 'processing' },
        ],
      });
    }

    if (path === '/api/v1/users' && method === 'GET') {
      if (!loggedIn) return json({ error: 'Unauthorized', code: 401 }, 401);
      return json({
        users: [
          { id: 'usr_001', email: 'admin@soledrop.co',   role: 'owner' },
          { id: 'usr_002', email: 'ops@soledrop.co',     role: 'member' },
          { id: 'usr_003', email: 'billing@soledrop.co', role: 'billing' },
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
        model: 'soledrop-concierge-v1',
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
      title: '404 — SoleDrop', incident: null, loggedIn, ticker: false,
      body: `<div style="max-width:500px;margin:6rem auto;padding:0 1.5rem;text-align:center;"><div style="font-size:3rem;font-weight:900;">404</div><h1 style="font-size:1.5rem;font-weight:900;text-transform:uppercase;color:var(--ink);margin-bottom:0.5rem;">Page not found</h1><p style="color:var(--muted);margin-bottom:1.5rem;">This pair's gone. The page you're looking for doesn't exist.</p><a href="/" class="btn btn-accent">Back to the Drop</a></div>`,
    }), 404);
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function hashCode(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = Math.imul(31, h) + str.charCodeAt(i) | 0;
  return h;
}
