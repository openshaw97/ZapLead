
// ── LEADS SEO PAGES ──
// Add this to server.js after your existing routes

// Hub pages: /leads/telecoms, /leads/solar-panels, etc.
app.get('/leads/:businessType', (req, res) => {
  const fs = require('fs');
  const file = path.join(__dirname, 'public', 'leads', req.params.businessType, 'index.html');
  if (fs.existsSync(file)) res.sendFile(file);
  else res.redirect('/');
});

// City pages: /leads/telecoms/manchester, etc.
app.get('/leads/:businessType/:city', (req, res) => {
  const fs = require('fs');
  const file = path.join(__dirname, 'public', 'leads', req.params.businessType, req.params.city, 'index.html');
  if (fs.existsSync(file)) res.sendFile(file);
  else res.redirect('/leads/' + req.params.businessType);
});
