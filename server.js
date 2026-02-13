const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');

const sqlite3 = require('sqlite3');
const { open } = require('sqlite');

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'app.db');
const SESSION_COOKIE = 'we_session';
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 7);

function sha256Hex(input){
  return crypto.createHash('sha256').update(input).digest('hex');
}

function base64url(buf){
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function isValidEmail(email){
  if (!email) return false;
  const s = String(email).trim().toLowerCase();
  // simpele (maar nuttige) check
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

function passwordPolicyOk(pw){
  const s = String(pw || '');
  return s.length >= 8 && s.length <= 128;
}

async function main(){
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  const db = await open({ filename: DB_FILE, driver: sqlite3.Database });

  await db.exec('PRAGMA journal_mode = WAL;');
  await db.exec('PRAGMA foreign_keys = ON;');

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
  `);

  const app = express();

  app.use(helmet({
    contentSecurityPolicy: false, // omdat de app externe cdn's gebruikt voor globe libs
    crossOriginEmbedderPolicy: false
  }));

  app.use(express.json({ limit: '64kb' }));
  app.use(cookieParser());

  // basic hardening
  app.disable('x-powered-by');

  // Rate limit auth endpoints (basic brute-force bescherming)
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 50,
    standardHeaders: true,
    legacyHeaders: false
  });

  async function cleanupExpiredSessions(){
    try{
      await db.run('DELETE FROM sessions WHERE expires_at <= ?', Date.now());
    } catch {}
  }

  async function createSession(res, userId){
    await cleanupExpiredSessions();

    const rawToken = base64url(crypto.randomBytes(32));
    const tokenHash = sha256Hex(rawToken);
    const now = Date.now();
    const expiresAt = now + SESSION_DAYS * 24 * 60 * 60 * 1000;

    await db.run(
      'INSERT INTO sessions (user_id, token_hash, created_at, expires_at) VALUES (?,?,?,?)',
      userId, tokenHash, now, expiresAt
    );

    res.cookie(SESSION_COOKIE, rawToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: IS_PROD,
      maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
      path: '/'
    });
  }

  async function authMiddleware(req, res, next){
    const token = req.cookies?.[SESSION_COOKIE];
    if (!token) return res.status(401).json({ error: 'not_authenticated' });

    const row = await db.get(
      `SELECT s.id AS session_id, u.id AS user_id, u.email AS email
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > ?
       LIMIT 1`,
      sha256Hex(String(token)),
      Date.now()
    );

    if (!row) return res.status(401).json({ error: 'not_authenticated' });

    req.user = { id: row.user_id, email: row.email, sessionId: row.session_id };
    next();
  }

  // ===== API =====

  app.get('/api/me', authMiddleware, (req, res) => {
    res.json({ email: req.user.email });
  });

  app.post('/api/logout', async (req, res) => {
    const token = req.cookies?.[SESSION_COOKIE];
    if (token){
      await db.run('DELETE FROM sessions WHERE token_hash = ?', sha256Hex(String(token))).catch(()=>{});
    }
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    res.json({ ok: true });
  });

  app.post('/api/register', authLimiter, async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (!isValidEmail(email)) return res.status(400).json({ error: 'bad_email', message: 'Voer een geldig e-mail adres in.' });
    if (!passwordPolicyOk(password)) return res.status(400).json({ error: 'bad_password', message: 'Wachtwoord moet minimaal 8 tekens zijn.' });

    const existing = await db.get('SELECT id FROM users WHERE email = ? LIMIT 1', email);
    if (existing) return res.status(409).json({ error: 'email_taken', message: 'Dit e-mail adres is al geregistreerd.' });

    const pwHash = await bcrypt.hash(password, 12);
    const now = Date.now();

    const result = await db.run(
      'INSERT INTO users (email, password_hash, created_at) VALUES (?,?,?)',
      email, pwHash, now
    );

    await createSession(res, result.lastID);
    res.json({ ok: true, email });
  });

  app.post('/api/login', authLimiter, async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (!isValidEmail(email)) return res.status(400).json({ error: 'bad_email', message: 'Voer een geldig e-mail adres in.' });

    const user = await db.get('SELECT id, email, password_hash FROM users WHERE email = ? LIMIT 1', email);
    if (!user) return res.status(401).json({ error: 'invalid_login', message: 'Onjuiste e-mail of wachtwoord.' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_login', message: 'Onjuiste e-mail of wachtwoord.' });

    await createSession(res, user.id);
    res.json({ ok: true, email: user.email });
  });

  // ===== Static =====
  const publicDir = path.join(__dirname, 'public');
  app.use(express.static(publicDir, {
    extensions: ['html'],
    setHeaders(res, filePath){
      if (String(filePath).endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-store');
      }
    }
  }));

  // SPA-like fallbacks
  app.get('/', (req, res) => res.sendFile(path.join(publicDir, 'index.html')));

  app.listen(PORT, () => {
    console.log(`WereldExplorer server draait op http://localhost:${PORT}`);
    console.log(`Database: ${DB_FILE}`);
  });
}

main().catch((err) => {
  console.error('Fout bij opstarten:', err);
  process.exit(1);
});
