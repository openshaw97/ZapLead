const express = require('express');
const compression = require('compression');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const GOOGLE_KEY = process.env.GOOGLE_API_KEY;
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const JWT_SECRET = process.env.JWT_SECRET || 'zaplead-secret-change-me';
const BASE_URL = process.env.BASE_URL || 'https://lead-harvest-production.up.railway.app';
const MONGODB_URI = process.env.MONGODB_URI;

// ── MONGODB ──
mongoose.connect(MONGODB_URI || 'mongodb://localhost/zaplead')
  .then(() => console.log('✅ MongoDB connected'))
  .catch(e => console.error('❌ MongoDB error:', e.message));

// ── USER SCHEMA ──
const userSchema = new mongoose.Schema({
  id:                   { type: String, default: () => uuidv4() },
  name:                 String,
  email:                { type: String, unique: true, lowercase: true, trim: true },
  password:             String,
  plan:                 { type: String, default: 'free' },
  leadsUsed:            { type: Number, default: 0 },
  lastReset:            { type: Date, default: Date.now },
  savedLeads:           { type: Array, default: [] },
  savedSearches:        { type: Array, default: [] },
  exportHistory:        { type: Array, default: [] },
  stripeCustomerId:     { type: String, default: null },
  stripeSubscriptionId: { type: String, default: null },
  createdAt:            { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// ── PLANS ──
// free.monthly = false means one-off (no monthly reset)
const PLANS = {
  free:       { leads: 50,   price: 0,   label: 'Free',       monthly: false, users: 1 },
  starter:    { leads: 300,  price: 29,  label: 'Starter',    monthly: true,  users: 1 },
  pro:        { leads: 1000, price: 59,  label: 'Pro',        monthly: true,  users: 2 },
  enterprise: { leads: 3000, price: 149, label: 'Enterprise', monthly: true,  users: 5 }
};

const STRIPE_PRICES = {
  starter:    process.env.STRIPE_PRICE_STARTER    || '',
  pro:        process.env.STRIPE_PRICE_PRO        || '',
  enterprise: process.env.STRIPE_PRICE_ENTERPRISE || ''
};

app.use(compression()); // gzip compression for better performance and SEO
app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── MONTHLY RESET ──
async function checkReset(user) {
  const plan = PLANS[user.plan] || PLANS.free;
  // Free plan is one-off — never resets
  if (!plan.monthly) return user;
  const now = new Date();
  const last = new Date(user.lastReset);
  const months = (now.getFullYear() - last.getFullYear()) * 12 + (now.getMonth() - last.getMonth());
  if (months >= 1) {
    user.leadsUsed = 0;
    user.lastReset = now;
    await user.save();
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
  const leadsUsed = u.leadsUsed || 0;
  const leadsRemaining = Math.max(0, plan.leads - leadsUsed);
  return {
    id: u.id, name: u.name, email: u.email,
    plan: u.plan, planLabel: plan.label,
    exportCredits: plan.leads,
    leadsAllowed: plan.leads,
    leadsUsed, leadsRemaining,
    isMonthly: plan.monthly,
    maxUsers: plan.users,
    savedLeads: u.savedLeads || [],
    savedSearches: u.savedSearches || [],
    exportHistory: (u.exportHistory || []).slice(0, 20)
  };
}

// ════════════════════════════
// AUTH
// ════════════════════════════
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(400).json({ error: 'Account already exists with this email' });
    const user = await User.create({ name, email, password: await bcrypt.hash(password, 10) });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: safeUser(user) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    let user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'No account found with this email' });
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Incorrect password' });
    user = await checkReset(user);
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: safeUser(user) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    let user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    user = await checkReset(user);
    res.json(safeUser(user));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SAVE LEADS ──
app.post('/api/leads/save', auth, async (req, res) => {
  try {
    const { lead } = req.body;
    if (!lead) return res.status(400).json({ error: 'Lead data required' });
    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.savedLeads.find(l => l.id === lead.id)) {
      user.savedLeads.push({ ...lead, savedAt: new Date() });
      await user.save();
    }
    res.json({ saved: user.savedLeads.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/leads/save/:id', auth, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.savedLeads = user.savedLeads.filter(l => l.id !== req.params.id);
    await user.save();
    res.json({ saved: user.savedLeads.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SAVED SEARCHES ──
app.post('/api/searches/save', auth, async (req, res) => {
  try {
    const { search } = req.body;
    if (!search || !search.keyword || !search.location) return res.status(400).json({ error: 'Search data required' });
    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (['free'].includes(user.plan)) return res.status(403).json({ error: 'Upgrade to save searches' });
    // Don't save duplicates
    const exists = user.savedSearches.find(s => s.keyword === search.keyword && s.location === search.location);
    if (!exists) {
      user.savedSearches.push({ ...search, savedAt: new Date(), id: uuidv4() });
      await user.save();
    }
    res.json({ savedSearches: user.savedSearches });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/searches/save/:id', auth, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.savedSearches = user.savedSearches.filter(s => s.id !== req.params.id);
    await user.save();
    res.json({ savedSearches: user.savedSearches });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════
// SEARCH
// ════════════════════════════
app.get('/api/health', (req, res) => {
  const dbState = ['disconnected','connected','connecting','disconnecting'][mongoose.connection.readyState] || 'unknown';
  res.json({ status: 'ok', database: dbState, google: GOOGLE_KEY ? '✅' : '❌', stripe: STRIPE_SECRET ? '✅' : '⚠️' });
});

app.get('/api/geocode', auth, async (req, res) => {
  if (!GOOGLE_KEY) return res.status(500).json({ error: 'Google API key not configured' });
  try {
    const r = await axios.get('https://maps.googleapis.com/maps/api/geocode/json', {
      params: { address: req.query.location, key: GOOGLE_KEY }
    });
    if (r.data.status !== 'OK') return res.status(400).json({ error: 'Location not found — try a different town or postcode' });
    res.json(r.data.results[0].geometry.location);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── KEYWORD MAP ──
const KEYWORD_MAP = {
  'takeaway': 'meal_takeaway', 'takeaways': 'meal_takeaway',
  'fish and chips': 'meal_takeaway', 'fast food': 'fast_food_restaurant',
  'chinese takeaway': 'chinese_restaurant', 'indian takeaway': 'indian_restaurant',
  'pizza': 'meal_takeaway', 'kebab': 'meal_takeaway',
  'cafe': 'cafe', 'coffee shop': 'cafe', 'coffee': 'cafe',
  'pub': 'bar', 'bar': 'bar', 'nightclub': 'night_club', 'night club': 'night_club',
  'car garage': 'car_repair', 'garage': 'car_repair', 'mot': 'car_repair',
  'car repair': 'car_repair', 'car dealer': 'car_dealer', 'car wash': 'car_wash',
  'car park': 'parking', 'petrol station': 'gas_station',
  'gym': 'gym', 'fitness': 'gym', 'fitness centre': 'gym',
  'hairdresser': 'hair_salon', 'hair salon': 'hair_salon', 'barber': 'barber_shop',
  'beauty salon': 'beauty_salon', 'nail salon': 'nail_salon',
  'dentist': 'dentist', 'doctor': 'doctor', 'gp': 'doctor', 'surgery': 'doctor',
  'pharmacy': 'pharmacy', 'chemist': 'pharmacy', 'optician': 'optician',
  'hospital': 'hospital', 'vet': 'veterinary_care', 'veterinary': 'veterinary_care',
  'hotel': 'lodging', 'b&b': 'lodging', 'guest house': 'lodging',
  'estate agent': 'real_estate_agency', 'letting agent': 'real_estate_agency',
  'solicitor': 'lawyer', 'accountant': 'accounting', 'bank': 'bank',
  'supermarket': 'supermarket', 'grocery': 'grocery_or_supermarket',
  'florist': 'florist', 'bakery': 'bakery', 'butcher': 'butcher_shop',
  'off licence': 'liquor_store', 'school': 'school', 'nursery': 'preschool',
  'church': 'church', 'storage': 'storage', 'launderette': 'laundry',
  'restaurant': 'restaurant', 'food': 'restaurant',
  'plumber': 'plumber', 'electrician': 'electrician',
};
function mapKeyword(kw) { return KEYWORD_MAP[kw.toLowerCase().trim()] || kw; }

// ── PLACES — aggressive multi-point grid, max results ──
app.get('/api/places', auth, async (req, res) => {
  if (!GOOGLE_KEY) return res.status(500).json({ error: 'Google API key not configured' });
  try {
    const { lat, lng, radius, keyword } = req.query;
    const searchRadius = parseFloat(radius) || 5000;
    const clat = parseFloat(lat);
    const clng = parseFloat(lng);
    const mappedKeyword = mapKeyword(keyword);

    // Key insight: each Google search returns max 60 results (3 pages x 20)
    // To get 250+ results we need enough grid points to cover the area with overlap
    // Cell size = 1000m means each search covers a 1500m radius circle
    // For a 5km search radius this gives ~25 points = up to 1500 results
    // For a 10km radius we use larger cells to stay within timeout
    const CELL = searchRadius <= 5000 ? 1000 :
                 searchRadius <= 10000 ? 1500 :
                 searchRadius <= 25000 ? 2500 : 3500;
    const SEARCH_R = Math.round(CELL * 1.6); // 60% overlap between cells
    const EARTH = 6371000;
    const latOff = (CELL / EARTH) * (180 / Math.PI);
    const lngOff = latOff / Math.cos(clat * Math.PI / 180);
    const gridSteps = Math.ceil(searchRadius / CELL);

    const allPoints = [];
    for (let dy = -gridSteps; dy <= gridSteps; dy++) {
      for (let dx = -gridSteps; dx <= gridSteps; dx++) {
        const dist = Math.sqrt((dy * CELL) ** 2 + (dx * CELL) ** 2);
        if (dist <= searchRadius) allPoints.push({ lat: clat + dy * latOff, lng: clng + dx * lngOff });
      }
    }

    // No artificial cap — run as many points as needed
    // Railway has a 60s timeout so cap at 40 points max to be safe
    // Each point takes ~2-3s with pagination so 40 pts = ~80-100s worst case
    // In practice most points have no next_page_token so it's much faster
    const MAX_POINTS = 40;
    const searchPoints = allPoints.slice(0, MAX_POINTS);

    const seen = new Set();
    const allResults = [];

    console.log(`"${keyword}"→"${mappedKeyword}" | ${searchPoints.length}/${allPoints.length} pts | cell=${CELL}m | searchR=${SEARCH_R}m`);

    for (let i = 0; i < searchPoints.length; i++) {
      const pt = searchPoints[i];
      let nextToken = null;
      for (let p = 0; p < 3; p++) {
        const params = { key: GOOGLE_KEY };
        if (nextToken) {
          params.pagetoken = nextToken;
        } else {
          params.location = `${pt.lat},${pt.lng}`;
          params.radius = SEARCH_R;
          if (mappedKeyword !== keyword) params.type = mappedKeyword;
          else params.keyword = keyword;
        }
        if (p > 0) await new Promise(r => setTimeout(r, 2000));
        const resp = await axios.get('https://maps.googleapis.com/maps/api/place/nearbysearch/json', { params });
        if (resp.data.status === 'REQUEST_DENIED') return res.status(403).json({ error: 'Google API key denied — enable Places API and check billing is active' });
        if (!['OK', 'ZERO_RESULTS'].includes(resp.data.status)) break;
        for (const pl of (resp.data.results || [])) {
          if (!seen.has(pl.place_id)) { seen.add(pl.place_id); allResults.push(pl); }
        }
        nextToken = resp.data.next_page_token;
        if (!nextToken) break;
      }
      // No delay between points — run fast
    }

    console.log(`✅ Found ${allResults.length} unique results for "${keyword}"`);
    res.json({ results: allResults, total: allResults.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/place-details', auth, async (req, res) => {
  if (!GOOGLE_KEY) return res.status(500).json({ error: 'Google API key not configured' });
  try {
    const r = await axios.get('https://maps.googleapis.com/maps/api/place/details/json', {
      params: {
        place_id: req.query.place_id,
        fields: 'name,formatted_phone_number,website,formatted_address,rating,user_ratings_total,types',
        key: GOOGLE_KEY
      }
    });
    res.json(r.data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── EXPORT ──
app.post('/api/export', auth, async (req, res) => {
  try {
    const { count, keyword, location } = req.body;
    if (!count || count < 1) return res.status(400).json({ error: 'Invalid export count' });
    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    await checkReset(user);
    const plan = PLANS[user.plan] || PLANS.free;
    const remaining = plan.leads - (user.leadsUsed || 0);
    if (remaining <= 0) return res.status(403).json({ error: 'No export credits remaining. Upgrade or wait for monthly reset.', limitReached: true });
    const canExport = Math.min(count, remaining);
    user.leadsUsed = (user.leadsUsed || 0) + canExport;
    await user.save();
    // Log to export history
  user.exportHistory = user.exportHistory || [];
  user.exportHistory.unshift({
    id: uuidv4(),
    keyword: req.body.keyword || 'Unknown',
    location: req.body.location || 'Unknown',
    count: canExport,
    exportedAt: new Date()
  });
  if (user.exportHistory.length > 50) user.exportHistory = user.exportHistory.slice(0, 50);
  await user.save();

  res.json({ approved: canExport, remaining: remaining - canExport, message: canExport < count ? `Only ${canExport} export credits remaining` : null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════
// STRIPE
// ════════════════════════════
app.post('/api/stripe/create-checkout', auth, async (req, res) => {
  if (!STRIPE_SECRET) return res.status(500).json({ error: 'Stripe not configured' });
  const { plan } = req.body;
  const priceId = STRIPE_PRICES[plan];
  if (!priceId) return res.status(400).json({ error: `Stripe price not set for ${plan}` });
  try {
    const stripe = require('stripe')(STRIPE_SECRET);
    const user = await User.findOne({ id: req.user.id });
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription', payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${BASE_URL}/app?upgraded=true&plan=${plan}`,
      cancel_url: `${BASE_URL}/app?cancelled=true`,
      customer_email: user.email,
      metadata: { userId: user.id, plan }
    });
    res.json({ url: session.url });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/stripe/webhook', async (req, res) => {
  if (!STRIPE_SECRET || !STRIPE_WEBHOOK_SECRET) return res.sendStatus(200);
  const stripe = require('stripe')(STRIPE_SECRET);
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET); }
  catch(e) { return res.status(400).send(`Webhook error: ${e.message}`); }
  if (event.type === 'checkout.session.completed') {
    const { userId, plan } = event.data.object.metadata || {};
    if (userId && plan && PLANS[plan]) {
      await User.findOneAndUpdate({ id: userId }, { plan, leadsUsed: 0, lastReset: new Date(), stripeCustomerId: event.data.object.customer, stripeSubscriptionId: event.data.object.subscription });
      console.log(`✅ Upgraded ${userId} to ${plan}`);
    }
  }
  if (event.type === 'customer.subscription.deleted') {
    await User.findOneAndUpdate({ stripeSubscriptionId: event.data.object.id }, { plan: 'free', leadsUsed: 0 });
  }
  res.sendStatus(200);
});

// ── ADMIN ──
function adminAuth(req, res, next) {
  if (req.headers['x-admin-secret'] !== (process.env.ADMIN_SECRET || 'admin123')) return res.status(403).json({ error: 'Forbidden' });
  next();
}

app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, '-password');
    res.json(users.map(u => ({
      id: u.id, name: u.name, email: u.email,
      plan: u.plan, leadsUsed: u.leadsUsed,
      savedLeads: (u.savedLeads||[]).length,
      createdAt: u.createdAt
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/set-plan', adminAuth, async (req, res) => {
  try {
    const { userId, plan } = req.body;
    if (!PLANS[plan]) return res.status(400).json({ error: 'Invalid plan' });
    const user = await User.findOneAndUpdate(
      { id: userId },
      { plan, leadsUsed: 0, lastReset: new Date() },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, plan: user.plan });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/reset-credits', adminAuth, async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findOneAndUpdate(
      { id: userId },
      { leadsUsed: 0, lastReset: new Date() },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ROUTES ──
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/pricing', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pricing.html')));
app.get('/sitemap.xml', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sitemap.xml')));
app.get('/robots.txt', (req, res) => res.sendFile(path.join(__dirname, 'public', 'robots.txt')));
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
// SEO location pages
app.get('/leads/:biz/:city', (req, res) => {
  const file = path.join(__dirname, 'public', 'leads', req.params.biz, req.params.city + '.html');
  const fs = require('fs');
  if (fs.existsSync(file)) res.sendFile(file);
  else res.redirect('/register');
});
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ ZapLead running on port ${PORT}`);
  console.log(`   Google:  ${GOOGLE_KEY ? '✅' : '❌ MISSING'}`);
  console.log(`   Stripe:  ${STRIPE_SECRET ? '✅' : '⚠️  not set'}`);
  console.log(`   MongoDB: ${MONGODB_URI ? '✅' : '⚠️  using localhost'}\n`);
});
