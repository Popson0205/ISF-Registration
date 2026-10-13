const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');

const { DATABASE_URL, ADMIN_PASSWORD, TOKEN_SECRET } = process.env;
if (!DATABASE_URL || !ADMIN_PASSWORD || !TOKEN_SECRET) {
  console.error('Set DATABASE_URL, ADMIN_PASSWORD and TOKEN_SECRET.');
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5 });
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---- tiny in-memory rate limiter (per IP) ----
const hits = new Map();
const limit = (max, windowMs) => (req, res, next) => {
  const k = req.path + req.ip, now = Date.now();
  const h = (hits.get(k) || []).filter(t => now - t < windowMs);
  if (h.length >= max) return res.status(429).json({ error: 'Too many attempts. Wait a few minutes' });
  h.push(now); hits.set(k, h); next();
};
setInterval(() => hits.clear(), 3600e3).unref();

// ---- admin auth: signed 8h token ----
const sign = s => crypto.createHmac('sha256', TOKEN_SECRET).update(s).digest('hex');
const safeEq = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const makeToken = () => { const exp = Date.now() + 8 * 3600e3; return `${exp}.${sign(String(exp))}`; };
const auth = (req, res, next) => {
  const [exp, sig] = (req.headers.authorization || '').replace('Bearer ', '').split('.');
  if (!exp || !sig || Date.now() > +exp || !safeEq(sig, sign(exp))) return res.status(401).json({ error: 'Not signed in' });
  next();
};

app.get('/health', (_req, res) => res.send('ok'));

// ---- public: register (re-registering the same email updates it, so people can re-download) ----
const clean = (v, n) => String(v || '').trim().replace(/\s+/g, ' ').slice(0, n);
app.post('/api/register', limit(15, 10 * 60e3), async (req, res) => {
  const b = req.body || {};
  const r = {
    name: clean(b.name, 60), phone: clean(b.phone, 20).replace(/[\s-]/g, ''), email: clean(b.email, 120).toLowerCase(),
    role: clean(b.role, 40), org: clean(b.org, 40), days: clean(b.days, 20), interest: clean(b.interest, 40)
  };
  if (r.name.length < 3) return res.status(400).json({ error: 'Enter your full name' });
  if (!/^(\+?234|0)?[789]\d{9}$/.test(r.phone)) return res.status(400).json({ error: 'Enter a valid Nigerian phone number' });
  if (!/^\S+@\S+\.\S+$/.test(r.email)) return res.status(400).json({ error: 'Enter a valid email' });
  try {
    await pool.query(
      `INSERT INTO registrations (name,phone,email,role,org,days,interest) VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (email) DO UPDATE SET name=$1,phone=$2,role=$4,org=$5,days=$6,interest=$7`,
      [r.name, r.phone, r.email, r.role, r.org, r.days, r.interest]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ---- admin ----
app.post('/api/admin/login', limit(8, 10 * 60e3), (req, res) => {
  if (!safeEq(String((req.body || {}).password || ''), ADMIN_PASSWORD)) return res.status(401).json({ error: 'Wrong password' });
  res.json({ token: makeToken() });
});

app.get('/api/admin/registrations', auth, async (req, res) => {
  const q = `%${clean(req.query.q, 60)}%`;
  try {
    const rows = (await pool.query(
      `SELECT * FROM registrations WHERE name ILIKE $1 OR email ILIKE $1 OR phone ILIKE $1 OR org ILIKE $1 ORDER BY created_at DESC LIMIT 1000`, [q])).rows;
    const s = (await pool.query(
      `SELECT count(*)::int total, count(*) FILTER (WHERE created_at > now() - interval '24 hours')::int today,
       count(*) FILTER (WHERE days IN ('Both days','Day 1 only'))::int day1,
       count(*) FILTER (WHERE days IN ('Both days','Day 2 only'))::int day2 FROM registrations`)).rows[0];
    res.json({ rows, stats: s });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/admin/registrations/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM registrations WHERE id=$1', [+req.params.id || 0]);
  res.json({ ok: true });
});

const csvCell = v => { v = String(v ?? ''); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return `"${v.replace(/"/g, '""')}"`; };
app.get('/api/admin/export.csv', auth, async (_req, res) => {
  const { rows } = await pool.query('SELECT * FROM registrations ORDER BY created_at');
  const cols = ['id', 'name', 'phone', 'email', 'role', 'org', 'days', 'interest', 'created_at'];
  res.type('text/csv').send([cols.join(','), ...rows.map(r => cols.map(c => csvCell(r[c])).join(','))].join('\n'));
});

(async () => {
  await pool.query(`CREATE TABLE IF NOT EXISTS registrations (
    id SERIAL PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
    role TEXT, org TEXT, days TEXT, interest TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  app.listen(process.env.PORT || 3000, () => console.log('Summit portal running'));
})().catch(e => { console.error(e); process.exit(1); });
