const express = require('express');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const GOOGLE_KEY = process.env.GOOGLE_API_KEY;
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const JWT_SECRET = process.env.JWT_SECRET || 'leadharvest-change-this-secret';
const BASE_URL = process.env.BASE_URL || 'https://lead-harvest-production.up.railway.app';

// ── PLAN CONFIG ──
// Enrichment = ~10% of leads per tier
const PLANS = {
  free:    { credits: 20,     enrichLimit: 2,    price: 0   },
  starter: { credits: 300,    enrichLimit: 30,   price: 49  },
  pro:     { credits: 800,    enrichLimit: 80,   price: 99  },
  agency:  { credits: 2000,   enrichLimit: 200,  price: 199 }
};

// Paste your Stripe Price IDs here after creating them in the Stripe dashboard
const STRIPE_PRICES = {
  starter: process.env.STRIPE_PRICE_STARTER || '',
  pro:     process.env.STRIPE_PRICE_PRO || '',
  agency:  process.env.STRIPE_PRICE_AGENCY || ''
};

// Stripe webhook needs raw body
app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── DATABASE ──
const DB_PATH = path.join(__dirname, 'users.json');
function readDB() {
  if (!fs.existsSync(DB_PATH)) fs.writeFileSync(DB_PATH, JSON.stringify({ users: [] }));
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function writeDB(data) { fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2)); }
function getUser(id) { return readDB().users.find(u => u.id === id); }
function updateUser(id, updates) {
  const db = readDB();
  const idx = db.users.findIndex(u => u.id === id);
  if (idx === -1) return null;
  db.users[idx] = { ...db.users[idx], ...updates };
  writeDB(db);
  return db.users[idx];
}

// ── MONTHLY CREDIT RESET ──
function checkMonthlyReset(user) {
  const now = new Date();
  const lastReset = new Date(user.lastReset || user.createdAt);
  const monthsSince = (now.getFullYear() - lastReset.getFullYear()) * 12 + (now.getMonth() - lastReset.getMonth());
  if (monthsSince >= 1) {
    const plan = PLANS[user.plan] || PLANS.free;
    const updated = updateUser(user.id, {
      credits: plan.credits,
      enrichThisMonth: 0,
      lastReset: now.toISOString()
    });
    return updated || user;
  }
  return user;
}

// ── AUTH MIDDLEWARE ──
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Session expired — please log in again' }); }
}

function safeUser(u) {
  const plan = PLANS[u.plan] || PLANS.free;
  return {
    id: u.id, name: u.name, email: u.email,
    plan: u.plan, credits: u.credits,
    enrichThisMonth: u.enrichThisMonth || 0,
    enrichLimit: plan.enrichLimit
  };
}

// ════════════════════════════
// AUTH
// ════════════════════════════
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) return res.status(400).json({ error: 'Name, email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const db = readDB();
  if (db.users.find(u => u.email === email.toLowerCase())) return res.status(400).json({ error: 'Account already exists with this email' });
  const user = {
    id: uuidv4(), name, email: email.toLowerCase(),
    password: await bcrypt.hash(password, 10),
    plan: 'free', credits: PLANS.free.credits,
    enrichThisMonth: 0, creditsUsed: 0,
    createdAt: new Date().toISOString(),
    lastReset: new Date().toISOString(),
    stripeCustomerId: null, stripeSubscriptionId: null
  };
  db.users.push(user); writeDB(db);
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: safeUser(user) });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const db = readDB();
  let user = db.users.find(u => u.email === email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'No account found with this email' });
  if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Incorrect password' });
  user = checkMonthlyReset(user);
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: safeUser(user) });
});

app.get('/api/auth/me', auth, (req, res) => {
  let user = getUser(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user = checkMonthlyReset(user);
  res.json(safeUser(user));
});

// ════════════════════════════
// SEARCH
// ════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    google: GOOGLE_KEY ? '✅ configured' : '❌ missing',
    anthropic: ANTHROPIC_KEY ? '✅ configured' : '❌ missing',
    stripe: STRIPE_SECRET ? '✅ configured' : '⚠️ not configured'
  });
});

app.get('/api/geocode', auth, async (req, res) => {
  if (!GOOGLE_KEY) return res.status(500).json({ error: 'Google API key not configured' });
  try {
    const r = await axios.get('https://maps.googleapis.com/maps/api/geocode/json', {
      params: { address: req.query.location, key: GOOGLE_KEY }
    });
    if (r.data.status !== 'OK') return res.status(400).json({ error: 'Location not found. Try a different place name.' });
    res.json(r.data.results[0].geometry.location);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PLACES — multi-point grid search for maximum results ──
// Google caps each search at 60 results. We work around this by searching
// from multiple points across a grid covering the requested area, then
// deduplicating by place_id to return far more unique results.
app.get('/api/places', auth, async (req, res) => {
  let user = getUser(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user = checkMonthlyReset(user);
  if (user.credits <= 0) return res.status(403).json({ error: 'No credits remaining. Please upgrade your plan.' });
  if (!GOOGLE_KEY) return res.status(500).json({ error: 'Google API key not configured' });

  try {
    const { lat, lng, radius, keyword } = req.query;
    const r = parseFloat(radius) || 5000;

    // Build a grid of search points covering the area.
    // Smaller radius = tighter grid = more overlap coverage.
    // Each grid cell searches with radius = gridSpacing*1.2 to ensure overlap.
    const gridSpacing = Math.min(r * 0.6, 3000); // metres between grid points
    const gridSteps = Math.ceil(r / gridSpacing);
    const searchRadius = Math.round(gridSpacing * 1.3);

    const EARTH_RADIUS = 6371000;
    const latOffset = (gridSpacing / EARTH_RADIUS) * (180 / Math.PI);
    const lngOffset = latOffset / Math.cos(parseFloat(lat) * Math.PI / 180);

    // Generate grid points within the search radius
    const points = [];
    for (let dy = -gridSteps; dy <= gridSteps; dy++) {
      for (let dx = -gridSteps; dx <= gridSteps; dx++) {
        const pLat = parseFloat(lat) + dy * latOffset;
        const pLng = parseFloat(lng) + dx * lngOffset;
        // Only include points within the overall search radius
        const distLat = dy * gridSpacing;
        const distLng = dx * gridSpacing;
        const dist = Math.sqrt(distLat*distLat + distLng*distLng);
        if (dist <= r) points.push({ lat: pLat, lng: pLng });
      }
    }

    // Cap at 9 grid points for free plan, unlimited for paid
    const maxPoints = user.plan === 'free' ? 1 : (user.plan === 'starter' ? 4 : points.length);
    const searchPoints = points.slice(0, maxPoints);

    const seen = new Set();
    const allResults = [];

    // Search each grid point (with rate limiting to respect Google API)
    for (let i = 0; i < searchPoints.length; i++) {
      const pt = searchPoints[i];
      let nextPageToken = null;

      for (let p = 0; p < 3; p++) {
        const params = {
          location: `${pt.lat},${pt.lng}`,
          radius: searchRadius,
          keyword,
          key: GOOGLE_KEY
        };
        if (nextPageToken) params.pagetoken = nextPageToken;
        if (p > 0) await new Promise(resolve => setTimeout(resolve, 2000));

        const resp = await axios.get('https://maps.googleapis.com/maps/api/place/nearbysearch/json', { params });

        if (resp.data.status === 'REQUEST_DENIED') {
          return res.status(403).json({ error: 'Google key denied. Enable Places API and check billing is active.' });
        }
        if (!['OK', 'ZERO_RESULTS'].includes(resp.data.status)) break;

        for (const place of (resp.data.results || [])) {
          if (!seen.has(place.place_id)) {
            seen.add(place.place_id);
            allResults.push(place);
          }
        }

        nextPageToken = resp.data.next_page_token;
        if (!nextPageToken) break;
      }

      // Small delay between grid points
      if (i < searchPoints.length - 1) await new Promise(resolve => setTimeout(resolve, 500));
    }

    res.json({ results: allResults, total: allResults.length, gridPoints: searchPoints.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/place-details', auth, async (req, res) => {
  if (!GOOGLE_KEY) return res.status(500).json({ error: 'Google API key not configured' });
  try {
    const r = await axios.get('https://maps.googleapis.com/maps/api/place/details/json', {
      params: {
        place_id: req.query.place_id,
        fields: 'name,formatted_phone_number,website,opening_hours,formatted_address,rating,user_ratings_total,types',
        key: GOOGLE_KEY
      }
    });
    // Deduct 1 credit
    const user = getUser(req.user.id);
    if (user) updateUser(user.id, { credits: Math.max(0, user.credits - 1), creditsUsed: (user.creditsUsed || 0) + 1 });
    res.json(r.data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────────
// ENRICHMENT HELPERS
// ─────────────────────────────────────────────────
const dns = require('dns').promises;

// Scrape a URL server-side and return the raw HTML text
async function fetchPage(url, timeout = 8000) {
  const resp = await axios.get(url, {
    timeout,
    maxRedirects: 5,
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-GB,en;q=0.9',
    }
  });
  return resp.data || '';
}

// Extract emails from raw HTML/text using regex
function extractEmails(text) {
  if (!text) return [];
  const mailto = [...text.matchAll(/mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/gi)].map(m => m[1]);
  const general = [...text.matchAll(/\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b/g)].map(m => m[1]);
  return [...new Set([...mailto, ...general])].filter(e =>
    !e.match(/\.(png|jpg|jpeg|gif|svg|webp|ico|css|js)$/i) &&
    !e.includes('example.') && !e.includes('sentry.') &&
    !e.includes('wix.') && !e.includes('wordpress.') &&
    !e.includes('@2x') && !e.includes('schema.org') &&
    !e.includes('w3.org') && !e.includes('yourdomain') &&
    !e.includes('email@') && !e.includes('name@') &&
    e.length < 80 && e.split('@')[0].length > 1
  );
}

// Extract social links from HTML
function extractSocials(html) {
  const find = (pattern) => { const m = html.match(pattern); return m ? m[0] : null; };
  return {
    facebook:  find(/https?:\/\/(www\.)?facebook\.com\/(?!sharer|share|dialog)[\w.\-]+/),
    instagram: find(/https?:\/\/(www\.)?instagram\.com\/[\w.\-]+/),
    twitter:   find(/https?:\/\/(www\.)?(twitter|x)\.com\/[\w.\-]+/),
    linkedin:  find(/https?:\/\/(www\.)?linkedin\.com\/(company|in)\/[\w.\-]+/),
    tiktok:    find(/https?:\/\/(www\.)?tiktok\.com\/@[\w.\-]+/),
    youtube:   find(/https?:\/\/(www\.)?youtube\.com\/(channel|c|@)[\w.\-]+/),
  };
}

// Find internal page URLs matching a keyword
function findPageUrls(html, baseUrl, keywords) {
  const urls = new Set();
  const pattern = new RegExp(`href=["']((?:https?://[^"']*|/[^"']*)?(?:${keywords.join('|')})[^"']*?)["']`, 'gi');
  const base = (() => { try { return new URL(baseUrl); } catch { return null; } })();
  if (!base) return [];
  for (const m of html.matchAll(pattern)) {
    const href = m[1];
    try {
      const full = href.startsWith('http') ? href : `${base.origin}${href.startsWith('/') ? '' : '/'}${href}`;
      const u = new URL(full);
      if (u.hostname === base.hostname) urls.add(full);
    } catch {}
  }
  return [...urls].slice(0, 3); // max 3 pages per keyword group
}

// Check if a domain has valid MX records (can receive email)
async function hasMxRecords(domain) {
  try {
    const records = await dns.resolveMx(domain);
    return records && records.length > 0;
  } catch { return false; }
}

// Generate likely email patterns for a domain and verify via MX
async function suggestEmails(domain) {
  if (!domain) return [];
  const hasMx = await hasMxRecords(domain);
  if (!hasMx) return []; // domain can't receive email, don't suggest
  const prefixes = ['info', 'hello', 'contact', 'enquiries', 'admin'];
  return prefixes.map(p => `${p}@${domain}`);
}

// ─────────────────────────────────────────────────
// AI ENRICHMENT — server scraping + AI fallback
// ─────────────────────────────────────────────────
app.post('/api/enrich', auth, async (req, res) => {
  if (!ANTHROPIC_KEY) return res.status(500).json({ error: 'Anthropic API key not configured' });
  let user = getUser(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user = checkMonthlyReset(user);

  const plan = PLANS[user.plan] || PLANS.free;
  const enrichUsed = user.enrichThisMonth || 0;

  if (enrichUsed >= plan.enrichLimit) {
    return res.status(403).json({
      error: `Monthly enrichment limit reached (${plan.enrichLimit} for ${user.plan} plan). Upgrade for more.`,
      enrichLimitReached: true
    });
  }
  if (user.credits < 2) return res.status(403).json({ error: 'Not enough credits. Please upgrade your plan.' });

  try {
    const { url, bizName, address, phone } = req.body;
    let domain = null;
    try { domain = new URL(url).hostname.replace('www.', ''); } catch(e) {}

    let emails = [];
    let socials = {};
    let contactHtml = '';
    let hasContactForm = false;
    let scrapedDesc = '';

    // ── STEP 1: Scrape homepage ──
    let homeHtml = '';
    try {
      homeHtml = await fetchPage(url);
      emails.push(...extractEmails(homeHtml));
      socials = extractSocials(homeHtml);
      hasContactForm = /contact.*form|<form/i.test(homeHtml);
    } catch(e) { /* homepage blocked */ }

    // ── STEP 2: Scrape contact, about, team, and footer pages ──
    if (homeHtml) {
      const extraPages = findPageUrls(homeHtml, url, ['contact', 'about', 'team', 'staff', 'people', 'meet', 'us']);
      for (const pageUrl of extraPages) {
        if (pageUrl === url) continue;
        try {
          const pageHtml = await fetchPage(pageUrl, 6000);
          emails.push(...extractEmails(pageHtml));
          if (!hasContactForm) hasContactForm = /contact.*form|<form/i.test(pageHtml);
          const pageSocials = extractSocials(pageHtml);
          Object.keys(pageSocials).forEach(k => { if (!socials[k] && pageSocials[k]) socials[k] = pageSocials[k]; });
        } catch(e) { /* page failed, continue */ }
      }
    }

    // Deduplicate emails found so far
    emails = [...new Set(emails)];

    // ── STEP 3: MX record check + suggest likely emails if none found ──
    let suggestedEmails = [];
    if (emails.length === 0 && domain) {
      suggestedEmails = await suggestEmails(domain);
      // Mark these as suggestions, not confirmed
    }

    // ── STEP 3: Use AI to search for anything we didn't find ──
    // Always run AI — it searches Google for the email even if scraping worked,
    // giving us the best possible chance of finding something
    const scrapeResults = emails.length > 0
      ? `Server scraping found these CONFIRMED emails: ${emails.join(', ')}.`
      : suggestedEmails.length > 0
        ? `Server scraping found no confirmed emails. Domain has valid MX records so it CAN receive email. Likely email patterns to verify: ${suggestedEmails.join(', ')} — search the web to confirm which is real.`
        : `Server scraping found no emails. Use web search to find them.`;

    const prompt = `You are finding contact details for a UK business. ${scrapeResults}

Business: ${bizName}
Website: ${url}
Domain: ${domain || 'unknown'}
Address: ${address || 'unknown'}
Phone: ${phone || 'unknown'}

Run these web searches to find missing contact details:
1. Search: "${domain ? '@' + domain : bizName + ' email'}"
2. Search: "${bizName} email contact ${address ? address.split(',')[0] : ''}"
3. Search: "${bizName} companies house director"

Also identify: owner/director name, and any social media profiles not already found.

Socials already found by scraping: ${JSON.stringify(socials)}

Return ONLY valid JSON, no other text:
{
  "emails": ${JSON.stringify(emails)},
  "owner_name": null,
  "job_title": null,
  "facebook": ${JSON.stringify(socials.facebook || null)},
  "instagram": ${JSON.stringify(socials.instagram || null)},
  "twitter": ${JSON.stringify(socials.twitter || null)},
  "linkedin": ${JSON.stringify(socials.linkedin || null)},
  "tiktok": ${JSON.stringify(socials.tiktok || null)},
  "youtube": ${JSON.stringify(socials.youtube || null)},
  "has_contact_form": ${hasContactForm},
  "description": "one sentence about the business"
}

Add any NEW emails found via search to the emails array. Fill in owner_name and description. Keep existing values unless you find better ones.`;

    const r = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 2000,
      tools: [{ type: 'web_search_20250305', name: 'web_search' }],
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: { 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }
    });

    const text = r.data.content.filter(b => b.type === 'text').map(b => b.text).join('');
    const match = text.match(/\{[\s\S]*\}/);

    let result = { emails, ...socials, has_contact_form: hasContactForm, owner_name: null, job_title: null, description: '' };

    if (match) {
      try {
        const aiResult = JSON.parse(match[0]);
        // Merge AI results with scraped results — combine emails from both
        const allEmails = [...new Set([...emails, ...(aiResult.emails || [])])].filter(e =>
          typeof e === 'string' && e.includes('@') && e.includes('.') &&
          !e.includes('example.') && !e.includes('placeholder') && e.length < 80
        );
        result = {
          ...result,
          ...aiResult,
          emails: allEmails,
          // Don't overwrite scraped socials with null
          facebook:  aiResult.facebook  || socials.facebook  || null,
          instagram: aiResult.instagram || socials.instagram || null,
          twitter:   aiResult.twitter   || socials.twitter   || null,
          linkedin:  aiResult.linkedin  || socials.linkedin  || null,
          tiktok:    aiResult.tiktok    || socials.tiktok    || null,
          youtube:   aiResult.youtube   || socials.youtube   || null,
        };
      } catch(e) { /* use scrape-only result */ }
    }

    updateUser(user.id, {
      credits: Math.max(0, user.credits - 2),
      creditsUsed: (user.creditsUsed || 0) + 2,
      enrichThisMonth: enrichUsed + 1
    });

    res.json({ ...result, suggested_emails: result.emails.length === 0 ? suggestedEmails : [], enrichRemaining: plan.enrichLimit - enrichUsed - 1 });

  } catch (e) {
    res.status(500).json({ error: e.response?.data?.error?.message || e.message });
  }
});

// ════════════════════════════
// STRIPE PAYMENTS
// ════════════════════════════

// Create checkout session
app.post('/api/stripe/create-checkout', auth, async (req, res) => {
  if (!STRIPE_SECRET) return res.status(500).json({ error: 'Stripe not configured. Add STRIPE_SECRET_KEY to Railway variables.' });
  const { plan } = req.body;
  const priceId = STRIPE_PRICES[plan];
  if (!priceId) return res.status(400).json({ error: `Stripe price not set for ${plan}. Add STRIPE_PRICE_${plan.toUpperCase()} to Railway variables.` });

  try {
    const stripe = require('stripe')(STRIPE_SECRET);
    const user = getUser(req.user.id);
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${BASE_URL}/?upgraded=true&plan=${plan}`,
      cancel_url: `${BASE_URL}/?cancelled=true`,
      customer_email: user.email,
      metadata: { userId: user.id, plan }
    });
    res.json({ url: session.url });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Stripe webhook — auto-upgrades users after payment
app.post('/api/stripe/webhook', async (req, res) => {
  if (!STRIPE_SECRET || !STRIPE_WEBHOOK_SECRET) return res.sendStatus(200);
  const stripe = require('stripe')(STRIPE_SECRET);
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (e) { console.error('Webhook error:', e.message); return res.status(400).send(`Webhook error: ${e.message}`); }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const { userId, plan } = session.metadata || {};
    if (userId && plan && PLANS[plan]) {
      updateUser(userId, {
        plan, credits: PLANS[plan].credits,
        enrichThisMonth: 0, lastReset: new Date().toISOString(),
        stripeCustomerId: session.customer,
        stripeSubscriptionId: session.subscription
      });
      console.log(`✅ Upgraded ${userId} to ${plan}`);
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    const db = readDB();
    const user = db.users.find(u => u.stripeSubscriptionId === sub.id);
    if (user) {
      updateUser(user.id, { plan: 'free', credits: PLANS.free.credits, enrichThisMonth: 0 });
      console.log(`⚠️ Downgraded ${user.email} to free — subscription cancelled`);
    }
  }

  res.sendStatus(200);
});

// ── ADMIN ──
app.get('/api/admin/users', (req, res) => {
  if (req.headers['x-admin-secret'] !== (process.env.ADMIN_SECRET || 'changeme123')) return res.status(403).json({ error: 'Forbidden' });
  const db = readDB();
  res.json(db.users.map(u => ({ id: u.id, name: u.name, email: u.email, plan: u.plan, credits: u.credits, enrichThisMonth: u.enrichThisMonth, createdAt: u.createdAt })));
});

// ── FRONTEND ROUTES ──
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/pricing', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pricing.html')));
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ LeadHarvest v3 running on port ${PORT}`);
  console.log(`   Google:    ${GOOGLE_KEY ? '✅' : '❌ MISSING'}`);
  console.log(`   Anthropic: ${ANTHROPIC_KEY ? '✅' : '❌ MISSING'}`);
  console.log(`   Stripe:    ${STRIPE_SECRET ? '✅' : '⚠️  not configured'}\n`);
});
