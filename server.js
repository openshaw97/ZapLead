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
const PLANS = {
  free:    { credits: 10,     enrichLimit: 5,    price: 0 },
  starter: { credits: 500,    enrichLimit: 100,  price: 19 },
  pro:     { credits: 2000,   enrichLimit: 300,  price: 49 },
  agency:  { credits: 999999, enrichLimit: 9999, price: 149 }
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

// ── PLACES — up to 60 results via pagination ──
app.get('/api/places', auth, async (req, res) => {
  let user = getUser(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user = checkMonthlyReset(user);
  if (user.credits <= 0) return res.status(403).json({ error: 'No credits remaining. Please upgrade your plan.' });
  if (!GOOGLE_KEY) return res.status(500).json({ error: 'Google API key not configured' });

  try {
    const { lat, lng, radius, keyword } = req.query;
    let allResults = [];
    let nextPageToken = null;

    for (let p = 0; p < 3; p++) {
      const params = { location: `${lat},${lng}`, radius: radius || 5000, keyword, key: GOOGLE_KEY };
      if (nextPageToken) params.pagetoken = nextPageToken;
      if (p > 0) await new Promise(r => setTimeout(r, 2000)); // Google requires delay between pages

      const r = await axios.get('https://maps.googleapis.com/maps/api/place/nearbysearch/json', { params });

      if (r.data.status === 'REQUEST_DENIED') return res.status(403).json({ error: 'Google key denied. Enable Places API and check billing is active in Google Cloud.' });
      if (r.data.status === 'ZERO_RESULTS' && p === 0) return res.json({ results: [] });
      if (!['OK', 'ZERO_RESULTS'].includes(r.data.status)) break;

      allResults = allResults.concat(r.data.results || []);
      nextPageToken = r.data.next_page_token;
      if (!nextPageToken) break;
    }

    res.json({ results: allResults });
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

// ── AI ENRICHMENT with monthly limit ──
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
    const { url, bizName } = req.body;
    const r = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 600,
      tools: [{ type: 'web_search_20250305', name: 'web_search' }],
      messages: [{ role: 'user', content: `Visit this business website and extract contact information.\nBusiness: ${bizName}\nWebsite: ${url}\n\nReturn ONLY a JSON object with no other text:\n{"emails":[],"owner_name":null,"facebook":null,"instagram":null,"twitter":null,"linkedin":null,"tiktok":null,"description":"one sentence about the business"}` }]
    }, {
      headers: { 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }
    });

    const text = r.data.content.filter(b => b.type === 'text').map(b => b.text).join('');
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) return res.status(500).json({ error: 'Could not parse AI response' });

    updateUser(user.id, {
      credits: Math.max(0, user.credits - 2),
      creditsUsed: (user.creditsUsed || 0) + 2,
      enrichThisMonth: enrichUsed + 1
    });

    res.json({
      ...JSON.parse(match[0]),
      enrichRemaining: plan.enrichLimit - enrichUsed - 1
    });
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
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ LeadHarvest v3 running on port ${PORT}`);
  console.log(`   Google:    ${GOOGLE_KEY ? '✅' : '❌ MISSING'}`);
  console.log(`   Anthropic: ${ANTHROPIC_KEY ? '✅' : '❌ MISSING'}`);
  console.log(`   Stripe:    ${STRIPE_SECRET ? '✅' : '⚠️  not configured'}\n`);
});
