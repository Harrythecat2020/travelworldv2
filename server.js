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
const WDQS_ENDPOINT = 'https://query.wikidata.org/sparql';

const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'app.db');
const SESSION_COOKIE = 'we_session';
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 7);
const WDQS_CACHE_TTL_MS = Number(process.env.WDQS_CACHE_TTL_MS || 15 * 60 * 1000);
const WDQS_MAX_CACHE_ENTRIES = Number(process.env.WDQS_MAX_CACHE_ENTRIES || 250);

const wdqsCache = new Map();

function normalizeSparqlQuery(input){
  return String(input || '').replace(/\s+/g, ' ').trim();
}

function normalizeCacheKey(input){
  return normalizeSparqlQuery(input).toLowerCase();
}

function getCachedWdqsResult(cacheKey){
  const cached = wdqsCache.get(cacheKey);
  if (!cached) return null;
  if (cached.expiresAt < Date.now()) {
    wdqsCache.delete(cacheKey);
    return null;
  }
  return cached.payload;
}

function setCachedWdqsResult(cacheKey, payload){
  wdqsCache.set(cacheKey, { payload, expiresAt: Date.now() + WDQS_CACHE_TTL_MS });
  while (wdqsCache.size > WDQS_MAX_CACHE_ENTRIES) {
    const first = wdqsCache.keys().next().value;
    wdqsCache.delete(first);
  }
}

function qidFromUri(uri){
  const m = String(uri || '').match(/Q\d+$/i);
  return m ? m[0].toUpperCase() : '';
}

function normalizeCountryName(input = ''){
  return String(input || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

function pickBestCountryBinding(bindings, countryName = ''){
  const normalizedNeedle = normalizeCountryName(countryName);
  const scored = (Array.isArray(bindings) ? bindings : []).map((row) => {
    const label = row?.countryLabel?.value || '';
    const aliases = (row?.aliases?.value || '').split('|').filter(Boolean);
    const allNames = [label, ...aliases].map(normalizeCountryName).filter(Boolean);
    const hasExactName = normalizedNeedle ? allNames.includes(normalizedNeedle) : false;
    const hasCloseName = normalizedNeedle
      ? allNames.some((n) => n.startsWith(normalizedNeedle) || normalizedNeedle.startsWith(n))
      : false;
    const isSovereignState = row?.isSovereignState?.value === 'true';
    const hasPopulation = Boolean(row?.population?.value);
    const score = (hasExactName ? 100 : 0)
      + (hasCloseName ? 25 : 0)
      + (isSovereignState ? 12 : 0)
      + (hasPopulation ? 3 : 0);
    return { row, score };
  });

  scored.sort((a, b) => b.score - a.score);
  return scored[0]?.row || null;
}

function parsePointLiteral(value){
  const m = String(value || '').match(/Point\(([-+\d.]+)\s+([-+\d.]+)\)/);
  if (!m) return null;
  const lng = Number(m[1]);
  const lat = Number(m[2]);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  return { lat, lng };
}

function commonsImageUrl(fileName, width = 640){
  const name = String(fileName || '').replace(/^File:/i, '').trim();
  if (!name) return '';
  const encoded = encodeURIComponent(name.replace(/ /g, '_'));
  return `https://commons.wikimedia.org/wiki/Special:FilePath/${encoded}?width=${width}`;
}

async function fetchWdqsJson(sparql, { timeoutMs = 9000, maxAttempts = 4 } = {}){
  const normalized = normalizeSparqlQuery(sparql);
  const cacheKey = normalizeCacheKey(normalized);
  const cached = getCachedWdqsResult(cacheKey);
  if (cached) return { cached: true, data: cached };

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const upstreamUrl = `${WDQS_ENDPOINT}?format=json&query=${encodeURIComponent(normalized)}`;
      const upstreamRes = await fetch(upstreamUrl, {
        method: 'GET',
        headers: {
          Accept: 'application/sparql-results+json',
          'User-Agent': 'WereldExplorer/2.0 (tourism-country-places)'
        },
        signal: controller.signal
      });

      if (upstreamRes.ok) {
        const data = await upstreamRes.json();
        setCachedWdqsResult(cacheKey, data);
        return { cached: false, data };
      }

      const info = classifyWdqsError(upstreamRes.status);
      const retryAllowed = info.retryable && attempt < maxAttempts - 1;
      const bodyText = await upstreamRes.text().catch(() => '');
      if (retryAllowed) {
        await new Promise(resolve => setTimeout(resolve, 400 * (2 ** attempt)));
        continue;
      }

      const err = new Error(info.message);
      err.info = info;
      err.details = { status: upstreamRes.status, upstreamMessage: bodyText.slice(0, 240) };
      throw err;
    } catch (err) {
      const aborted = err?.name === 'AbortError';
      const isFinalAttempt = attempt >= maxAttempts - 1;
      if (!isFinalAttempt && !err?.info) {
        await new Promise(resolve => setTimeout(resolve, 400 * (2 ** attempt)));
        continue;
      }

      if (aborted) {
        const timeoutErr = new Error('Timeout bij Wikidata.');
        timeoutErr.info = { code: 'timeout', message: 'Timeout bij Wikidata.', httpStatus: 504, retryable: true };
        throw timeoutErr;
      }
      if (err?.info) throw err;

      const networkErr = new Error('Kan Wikidata tijdelijk niet bereiken.');
      networkErr.info = { code: 'upstream_unreachable', message: 'Kan Wikidata tijdelijk niet bereiken.', httpStatus: 502, retryable: true };
      networkErr.details = { detail: String(err?.message || err) };
      throw networkErr;
    } finally {
      clearTimeout(timeout);
    }
  }

  const e = new Error('Wikidata tijdelijk niet beschikbaar.');
  e.info = { code: 'temporary_outage', message: 'Wikidata tijdelijk niet beschikbaar.', httpStatus: 503, retryable: true };
  throw e;
}

function classifyWdqsError(status){
  if (status === 400) return { code: 'invalid_query', message: 'SPARQL-query is ongeldig.', httpStatus: 400, retryable: false };
  if (status === 403) return { code: 'forbidden', message: 'Wikidata weigert deze query tijdelijk.', httpStatus: 502, retryable: true };
  if (status === 429) return { code: 'rate_limited', message: 'Wikidata rate-limit bereikt.', httpStatus: 429, retryable: true };
  if (status === 408 || status === 504) return { code: 'timeout', message: 'Timeout bij Wikidata.', httpStatus: 504, retryable: true };
  if ([500, 502, 503].includes(status)) return { code: 'temporary_outage', message: 'Wikidata tijdelijk niet beschikbaar.', httpStatus: 503, retryable: true };
  return { code: 'upstream_error', message: 'Onverwachte fout van Wikidata.', httpStatus: 502, retryable: false };
}

function sendApiError(res, info, details){
  return res.status(info.httpStatus).json({
    ok: false,
    error: {
      code: info.code,
      message: info.message,
      retryable: info.retryable,
      ...details
    }
  });
}

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

  app.get('/api/countries/:isoCode/places', async (req, res) => {
    const isoCode = String(req.params.isoCode || '').trim();
    const countryName = String(req.query?.countryName || '').trim();
    const limit = Math.max(5, Math.min(80, Number(req.query?.limit) || 40));

    const isNumeric = /^\d{3}$/.test(isoCode);
    const isAlpha3 = /^[A-Za-z]{3}$/.test(isoCode);
    if (!isNumeric && !isAlpha3) {
      return sendApiError(res, { code: 'invalid_country_mapping', message: 'Ongeldige landcode.', httpStatus: 400, retryable: false });
    }

    const isoClause = isNumeric
      ? `?country wdt:P299 ?isoNumeric . FILTER(STR(?isoNumeric) = "${isoCode}")`
      : `?country wdt:P298 ?isoAlpha3 . FILTER(UCASE(STR(?isoAlpha3)) = "${isoCode.toUpperCase()}")`;

    const lookupSparql = `
      SELECT ?country ?countryLabel ?capitalLabel ?continentLabel ?population ?isoAlpha3 ?isoNumeric
             (GROUP_CONCAT(DISTINCT ?alias; separator="|") AS ?aliases)
             (SAMPLE(IF(?instance = wd:Q3624078, true, false)) AS ?isSovereignState)
      WHERE {
        ?country wdt:P31/wdt:P279* wd:Q6256 .
        ${isoClause}
        OPTIONAL { ?country wdt:P298 ?isoAlpha3 . }
        OPTIONAL { ?country wdt:P299 ?isoNumeric . }
        OPTIONAL { ?country wdt:P36 ?capital . }
        OPTIONAL { ?country wdt:P30 ?continent . }
        OPTIONAL { ?country wdt:P1082 ?population . }
        OPTIONAL { ?country skos:altLabel ?alias . FILTER(LANG(?alias) IN ("nl", "en")) }
        OPTIONAL { ?country wdt:P31 ?instance . }
        SERVICE wikibase:label { bd:serviceParam wikibase:language "nl,en". }
      }
      GROUP BY ?country ?countryLabel ?capitalLabel ?continentLabel ?population ?isoAlpha3 ?isoNumeric
      LIMIT 15
    `;

    try {
      const lookupData = (await fetchWdqsJson(lookupSparql, { timeoutMs: 9000 })).data;
      const candidates = lookupData?.results?.bindings || [];
      const countryBinding = pickBestCountryBinding(candidates, countryName);
      if (!countryBinding?.country?.value) {
        return sendApiError(res, { code: 'invalid_country_mapping', message: 'Geen land gevonden voor deze code.', httpStatus: 404, retryable: false });
      }

      const countryQid = qidFromUri(countryBinding.country.value);
      const placesSparql = `
        SELECT ?place ?placeLabel ?placeDescription ?coord ?image ?kindLabel ?sitelinks WHERE {
          BIND(wd:${countryQid} AS ?country)
          {
            ?place wdt:P17 ?country .
          } UNION {
            ?place wdt:P131* ?country .
          }
          ?place wdt:P625 ?coord .
          OPTIONAL { ?place wdt:P18 ?image . }
          OPTIONAL { ?place wdt:P31 ?kind . }
          OPTIONAL { ?place wikibase:sitelinks ?sitelinks . }
          SERVICE wikibase:label { bd:serviceParam wikibase:language "nl,en". }
          FILTER (!BOUND(?sitelinks) || ?sitelinks >= 2)
        }
        ORDER BY DESC(COALESCE(?sitelinks, 0))
        LIMIT ${limit}
      `;

      const placesData = (await fetchWdqsJson(placesSparql, { timeoutMs: 16000 })).data;
      const places = [];
      for (const row of placesData?.results?.bindings || []) {
        const qid = qidFromUri(row.place?.value);
        const point = parsePointLiteral(row.coord?.value);
        if (!qid || !point) continue;
        places.push({
          qid,
          label: row.placeLabel?.value || qid,
          desc: row.placeDescription?.value || '',
          type: row.kindLabel?.value || '',
          lat: point.lat,
          lng: point.lng,
          image: row.image?.value ? commonsImageUrl(row.image.value, 640) : '',
          sitelinks: row.sitelinks?.value ? Number(row.sitelinks.value) : 0,
          wikidataUrl: row.place?.value || ''
        });
      }

      return res.json({
        ok: true,
        country: {
          qid: countryQid,
          name: countryBinding.countryLabel?.value || countryName || countryQid,
          isoAlpha3: countryBinding.isoAlpha3?.value || (isAlpha3 ? isoCode.toUpperCase() : ''),
          isoNumeric: countryBinding.isoNumeric?.value || (isNumeric ? isoCode : ''),
          capital: countryBinding.capitalLabel?.value || '—',
          continent: countryBinding.continentLabel?.value || '—',
          population: countryBinding.population?.value || '',
          wikidataUrl: `https://www.wikidata.org/wiki/${countryQid}`
        },
        places
      });
    } catch (err) {
      return sendApiError(res, err.info || { code: 'upstream_error', message: 'Onverwachte fout van Wikidata.', httpStatus: 502, retryable: false }, err.details || {});
    }
  });

  app.get('/api/places/:placeQid', async (req, res) => {
    const placeQid = String(req.params.placeQid || '').toUpperCase();
    if (!/^Q\d+$/.test(placeQid)) {
      return sendApiError(res, { code: 'invalid_place_id', message: 'Ongeldige plaats-id.', httpStatus: 400, retryable: false });
    }

    const sparql = `
      SELECT ?placeLabel ?placeDescription (GROUP_CONCAT(DISTINCT ?typeLabel; separator=", ") AS ?types)
             (SAMPLE(?website) AS ?website) (SAMPLE(?inception) AS ?inception)
             (SAMPLE(?population) AS ?population) (SAMPLE(?area) AS ?area)
             (SAMPLE(?countryLabel) AS ?countryLabel) (SAMPLE(?adminLabel) AS ?adminLabel) (SAMPLE(?image) AS ?image)
      WHERE {
        BIND(wd:${placeQid} AS ?place)
        OPTIONAL { ?place wdt:P31 ?type . }
        OPTIONAL { ?place wdt:P856 ?website . }
        OPTIONAL { ?place wdt:P571 ?inception . }
        OPTIONAL { ?place wdt:P1082 ?population . }
        OPTIONAL { ?place wdt:P2046 ?area . }
        OPTIONAL { ?place wdt:P17 ?country . }
        OPTIONAL { ?place wdt:P131 ?admin . }
        OPTIONAL { ?place wdt:P18 ?image . }
        SERVICE wikibase:label { bd:serviceParam wikibase:language "nl,en". }
      }
      GROUP BY ?placeLabel ?placeDescription
      LIMIT 1
    `;

    try {
      const data = (await fetchWdqsJson(sparql, { timeoutMs: 12000 })).data;
      const b = (data?.results?.bindings || [])[0] || {};
      return res.json({
        ok: true,
        details: {
          ts: Date.now(),
          types: b.types?.value || '',
          website: b.website?.value || '',
          inception: b.inception?.value || '',
          population: b.population?.value || '',
          area: b.area?.value || '',
          country: b.countryLabel?.value || '',
          admin: b.adminLabel?.value || '',
          image: b.image?.value ? commonsImageUrl(b.image.value, 760) : ''
        }
      });
    } catch (err) {
      return sendApiError(res, err.info || { code: 'upstream_error', message: 'Onverwachte fout van Wikidata.', httpStatus: 502, retryable: false }, err.details || {});
    }
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
