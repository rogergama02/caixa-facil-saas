// server.js - CaixaFácil SaaS backend + static hosting
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN || "";   // Backend
const MP_PUBLIC_KEY = process.env.MP_PUBLIC_KEY || "";       // Frontend
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const PORT = process.env.PORT || 3000;

const app = express();

// ---- DB setup ----
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
const dbFile = path.join(dataDir, 'caixafacil.db');
const db = new Database(dbFile);
db.pragma('journal_mode = wal');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT,
  password_hash TEXT NOT NULL,
  subscription_active INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS transactions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  type TEXT NOT NULL,
  desc TEXT NOT NULL,
  amount REAL NOT NULL,
  cat TEXT,
  paid INTEGER DEFAULT 1,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
`);

// ---- Middlewares ----
app.use(cookieParser());
app.use(express.json({ limit: '2mb' }));

// ---- Helpers ----
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function authRequired(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'unauthenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'invalid token' });
  }
}

function subscriptionRequired(req, res, next) {
  const row = db.prepare('SELECT subscription_active FROM users WHERE id = ?').get(req.user.id);
  if (!row || !row.subscription_active) return res.status(402).json({ error: 'payment_required' });
  next();
}

// ---- Auth ----
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const hash = await bcrypt.hash(password, 10);
  try {
    const info = db.prepare('INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)').run(
      email.trim().toLowerCase(),
      name || '',
      hash
    );
    const token = signToken({ id: info.lastInsertRowid, email: email.trim().toLowerCase() });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    res.status(201).json({ ok: true, subscription_active: 0, email });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'email_exists' });
    return res.status(500).json({ error: 'db_error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim().toLowerCase());
  if (!user) return res.status(404).json({ error: 'user_not_found' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid_password' });

  const token = signToken({ id: user.id, email: user.email });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
  res.json({ ok: true, subscription_active: user.subscription_active });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', authRequired, (req, res) => {
  const row = db.prepare('SELECT id, email, name, subscription_active FROM users WHERE id = ?').get(req.user.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  res.json(row);
});

// ---- Transactions ----
app.get('/api/tx', authRequired, subscriptionRequired, (req, res) => {
  const txs = db.prepare('SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC').all(req.user.id);
  res.json(txs);
});

app.post('/api/tx', authRequired, subscriptionRequired, (req, res) => {
  const t = req.body || {};
  if (!t.id || !t.date || !t.type || !t.desc || typeof t.amount !== 'number')
    return res.status(400).json({ error: 'invalid_payload' });

  const existing = db.prepare('SELECT id FROM transactions WHERE id = ? AND user_id = ?').get(t.id, req.user.id);
  if (existing) {
    db.prepare(
      'UPDATE transactions SET date=?, type=?, desc=?, amount=?, cat=?, paid=? WHERE id=? AND user_id=?'
    ).run(t.date, t.type, t.desc, t.amount, t.cat || '', t.paid ? 1 : 0, t.id, req.user.id);
  } else {
    db.prepare(
      'INSERT INTO transactions (id, user_id, date, type, desc, amount, cat, paid) VALUES (?,?,?,?,?,?,?,?)'
    ).run(t.id, req.user.id, t.date, t.type, t.desc, t.amount, t.cat || '', t.paid ? 1 : 0);
  }

  res.json({ ok: true });
});

app.delete('/api/tx/:id', authRequired, subscriptionRequired, (req, res) => {
  db.prepare('DELETE FROM transactions WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ---- Mercado Pago ----
app.post('/api/create_preference', authRequired, async (req, res) => {
  if (!MP_ACCESS_TOKEN) return res.status(500).json({ error: 'mp_not_configured' });

  const preferenceData = {
    items: [{ title: "Assinatura CaixaFácil", quantity: 1, unit_price: 700 }],
    back_urls: {
      success: `${req.protocol}://${req.get('host')}/payment-success.html`,
      failure: `${req.protocol}://${req.get('host')}/payment.html`,
      pending: `${req.protocol}://${req.get('host')}/payment.html`
    },
    auto_return: "approved",
    metadata: { user_id: req.user.id }
  };

  try {
    const mpRes = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${MP_ACCESS_TOKEN}` },
      body: JSON.stringify(preferenceData)
    });

    const data = await mpRes.json();
    if (!data.id) return res.status(500).json({ error: 'mp_error', details: data });

    res.json({ preferenceId: data.id });
  } catch (e) {
    res.status(500).json({ error: 'mp_exception', details: e.message });
  }
});

// ---- Webhook Mercado Pago ----
app.post('/api/mp/webhook', express.json(), async (req, res) => {
  const { type, data } = req.body || {};
  if (type !== 'payment') return res.sendStatus(200);

  try {
    const mpRes = await fetch(`https://api.mercadopago.com/v1/payments/${data.id}`, {
      headers: { Authorization: `Bearer ${MP_ACCESS_TOKEN}` }
    });
    const payment = await mpRes.json();

    if (payment.status === 'approved' && payment.metadata?.user_id) {
      db.prepare('UPDATE users SET subscription_active = 1 WHERE id = ?').run(payment.metadata.user_id);
      console.log(`✅ Pagamento aprovado para usuário ${payment.metadata.user_id}`);
    }
  } catch (e) {
    console.error("❌ Webhook error", e);
  }

  res.sendStatus(200);
});

// ---- Static Frontend ----
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.use('/api', (req, res) => res.status(404).json({ error: 'not_found' }));

// ---- Start server ----
app.listen(PORT, () => {
  console.log(`CaixaFácil server running on http://localhost:${PORT}`);
  if (!MP_ACCESS_TOKEN) console.log('⚠️ Mercado Pago não configurado. /api/create_preference não vai funcionar.');
});
