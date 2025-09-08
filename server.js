// server-render-sqlite3.js - CaixaFácil SaaS para Render usando sqlite3
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN;
const MP_PUBLIC_KEY = process.env.MP_PUBLIC_KEY;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const PORT = process.env.PORT || 3000;

const app = express();

// ---- DB setup ----
const dataDir = path.join(process.env.DATA_DIR || path.join(__dirname, 'data'));
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
const dbFile = path.join(dataDir, 'caixafacil.db');

const db = new sqlite3.Database(dbFile, (err) => {
  if (err) console.error("DB error:", err);
  else console.log("✅ SQLite3 database connected");
});

// Criação das tabelas
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      name TEXT,
      password_hash TEXT NOT NULL,
      subscription_active INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
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
    )
  `);
});

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
  db.get('SELECT subscription_active FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err || !row || !row.subscription_active) return res.status(402).json({ error: 'payment_required' });
    next();
  });
}

// ---- Auth ----
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const hash = await bcrypt.hash(password, 10);
  const emailLower = email.trim().toLowerCase();
  db.run('INSERT INTO users (email, name, password_hash) VALUES (?,?,?)', [emailLower, name || '', hash], function(err) {
    if (err) {
      if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'email_exists' });
      return res.status(500).json({ error: 'db_error' });
    }
    const token = signToken({ id: this.lastID, email: emailLower });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    res.status(201).json({ ok: true, subscription_active: 0, email: emailLower });
  });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  db.get('SELECT * FROM users WHERE email = ?', [email.trim().toLowerCase()], async (err, user) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_password' });

    const token = signToken({ id: user.id, email: user.email });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    res.json({ ok: true, subscription_active: user.subscription_active });
  });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', authRequired, (req, res) => {
  db.get('SELECT id, email, name, subscription_active FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'not_found' });
    res.json(row);
  });
});

// ---- Transactions ----
app.get('/api/tx', authRequired, subscriptionRequired, (req, res) => {
  db.all('SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

app.post('/api/tx', authRequired, subscriptionRequired, (req, res) => {
  const t = req.body || {};
  if (!t.id || !t.date || !t.type || !t.desc || typeof t.amount !== 'number')
    return res.status(400).json({ error: 'invalid_payload' });

  db.get('SELECT id FROM transactions WHERE id = ? AND user_id = ?', [t.id, req.user.id], (err, existing) => {
    if (err) return res.status(500).json({ error: 'db_error' });

    if (existing) {
      db.run(
        'UPDATE transactions SET date=?, type=?, desc=?, amount=?, cat=?, paid=? WHERE id=? AND user_id=?',
        [t.date, t.type, t.desc, t.amount, t.cat || '', t.paid ? 1 : 0, t.id, req.user.id]
      );
    } else {
      db.run(
        'INSERT INTO transactions (id, user_id, date, type, desc, amount, cat, paid) VALUES (?,?,?,?,?,?,?,?)',
        [t.id, req.user.id, t.date, t.type, t.desc, t.amount, t.cat || '', t.paid ? 1 : 0]
      );
    }

    res.json({ ok: true });
  });
});

app.delete('/api/tx/:id', authRequired, subscriptionRequired, (req, res) => {
  db.run('DELETE FROM transactions WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  res.json({ ok: true });
});

// ---- Mercado Pago ----
// Mantém igual, sem alterações necessárias

// ---- Static Frontend ----
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.use('/api', (req, res) => res.status(404).json({ error: 'not_found' }));

// ---- Start server ----
app.listen(PORT, () => {
  console.log(`CaixaFácil server running on port ${PORT}`);
  if (!MP_ACCESS_TOKEN) console.log('⚠️ Mercado Pago não configurado. /api/create_preference não vai funcionar.');
});
