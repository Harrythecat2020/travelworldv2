const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const sqlite3 = require('sqlite3');
const { open } = require('sqlite');

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'app.db');
const SESSION_COOKIE = 'we_session';
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 7);

// Comma-separated list of allowed frontend origins (scheme + host + optional port)
// Example: FRONTEND_ORIGINS="https://username.github.io,http://localhost:3000"
const FRONTEND_ORIGINS = String(process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

function sha256Hex(input){
  return crypto.createHash('sha256').update(input).digest('hex');
}

function base64url(buf){
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function isValidEmail(email){
  if (!email) return false;
  const s = String(email).trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

function passwordPolicyOk(pw){
  const s = String(pw || '');
  return s.length >= 8 && s.length <= 128;
}

function getReqToken(req){
  const cookieToken = req.cookies?.[SESSION_COOKIE];
  if (cookieToken) return String(cookieToken);

  const auth = req.get('authorization') || '';
  const m = auth.match(/^\s*bearer\s+(.+)$/i);
  if (m) return String(m[1]).trim();

  return '';
}

function originAllowed(origin){
  if (!origin) return true; // same-origin / curl
  try{
    const u = new URL(origin);
    const host = String(u.hostname || '').toLowerCase();

    if (FRONTEND_ORIGINS.includes(origin)) return true;

    // Dev-friendly defaults if no allowlist is set
    if (FRONTEND_ORIGINS.length === 0){
      if (host === 'localhost' || host === '127.0.0.1') return true;
      if (host === 'github.io' || host.endsWith('.github.io')) return true;
    }

    return false;
  } catch {
    return false;
  }
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

  // If behind a proxy (Render/Railway), this allows secure cookies to work correctly.
  app.set('trust proxy', 1);

  app.use(helmet({
    contentSecurityPolicy: false, // the app uses external CDN scripts
    crossOriginEmbedderPolicy: false
  }));

  // CORS for GitHub Pages / other frontends
  app.use(cors({
    origin: (origin, cb) => {
      if (originAllowed(origin)) return cb(null, origin || true);
      return cb(null, false);
    },
    credentials: true
  }));

  app.use(express.json({ limit: '64kb' }));
  app.use(cookieParser());
  app.disable('x-powered-by');

  // Rate limit auth endpoints (basic brute-force protection)
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 50,
    standardHeaders: true,
    legacyHeaders: false
  });

  async function cleanupExpiredSessions(){
    try{ await db.run('DELETE FROM sessions WHERE expires_at <= ?', Date.now()); } catch {}
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

    // Cross-site cookie support (GitHub Pages -> Render) requires SameSite=None; Secure.
    // Some browsers block third-party cookies; therefore the API ALSO returns the token
    // so the frontend can send it as Authorization: Bearer <token>.
    res.cookie(SESSION_COOKIE, rawToken, {
      httpOnly: true,
      sameSite: IS_PROD ? 'none' : 'lax',
      secure: IS_PROD,
      maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
      path: '/'
    });

    return rawToken;
  }

  async function authMiddleware(req, res, next){
    const token = getReqToken(req);
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
    const token = getReqToken(req);
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

    const token = await createSession(res, result.lastID);
    res.json({ ok: true, email, token });
  });

  app.post('/api/login', authLimiter, async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (!isValidEmail(email)) return res.status(400).json({ error: 'bad_email', message: 'Voer een geldig e-mail adres in.' });

    const user = await db.get('SELECT id, email, password_hash FROM users WHERE email = ? LIMIT 1', email);
    if (!user) return res.status(401).json({ error: 'invalid_login', message: 'Onjuiste e-mail of wachtwoord.' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_login', message: 'Onjuiste e-mail of wachtwoord.' });

    const token = await createSession(res, user.id);
    res.json({ ok: true, email: user.email, token });
  });

  // ===== Static =====
  // Serve frontend files from project root (works with your "alles uit public gehaald" change).
  // If you prefer a folder, set STATIC_DIR=/path/to/folder
  const staticDir = process.env.STATIC_DIR
    ? path.resolve(process.env.STATIC_DIR)
    : __dirname;

  app.use(express.static(staticDir, {
    extensions: ['html'],
    setHeaders(res, filePath){
      if (String(filePath).endsWith('.html')) res.setHeader('Cache-Control', 'no-store');
    }
  }));

  app.get('/', (req, res) => res.sendFile(path.join(staticDir, 'index.html')));

  app.listen(PORT, () => {
    console.log(`WereldExplorer server draait op http://localhost:${PORT}`);
    console.log(`Database: ${DB_FILE}`);
    if (FRONTEND_ORIGINS.length) console.log(`Allowed origins: ${FRONTEND_ORIGINS.join(', ')}`);
  });
}

main().catch((err) => {
  console.error('Fout bij opstarten:', err);
  process.exit(1);
});
