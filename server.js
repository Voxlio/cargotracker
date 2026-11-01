/**
 * CargoTracker - Logistics & Tracking Backend (hardened, Vercel-ready)
 *
 * Storage:
 *  - On Vercel: Upstash Redis (Vercel > Storage / Marketplace).
 *  - Locally (no Redis env vars): falls back to database.json on disk.
 *
 * Required environment variables (the server refuses to start without them):
 *  - ADMIN_USER     staff username
 *  - ADMIN_PASS     staff password (12+ characters)
 *  - TOKEN_SECRET   random string (32+ characters) used to sign login tokens
 *
 * Optional:
 *  - ALLOWED_ORIGINS  comma-separated list of websites allowed to call the API
 *                     from a browser, e.g. https://mysite.com,https://www.mysite.com
 *                     (if empty, any origin may call the PUBLIC lookup; staff
 *                     routes are still protected by the Bearer token)
 *  - APP_TIMEZONE     IANA timezone for server-generated dates (default UTC)
 *
 * Run locally:  npm install && npm start  ->  http://localhost:3000  and /admin
 */

try { require('dotenv').config(); } catch (e) { /* dotenv is optional */ }

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.json');
const IS_VERCEL = !!process.env.VERCEL;

// ==========================================
// CONFIG & STARTUP CHECKS (fail closed)
// ==========================================
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;
const TOKEN_SECRET = process.env.TOKEN_SECRET;
const APP_TZ = process.env.APP_TIMEZONE || 'UTC';

const configErrors = [];
if (!ADMIN_USER) configErrors.push('ADMIN_USER is not set.');
if (!ADMIN_PASS || ADMIN_PASS.length < 12) configErrors.push('ADMIN_PASS must be set and at least 12 characters.');
if (!TOKEN_SECRET || TOKEN_SECRET.length < 32) configErrors.push('TOKEN_SECRET must be set and at least 32 characters.');
try { new Intl.DateTimeFormat('en-US', { timeZone: APP_TZ }); } catch (e) { configErrors.push('APP_TIMEZONE "' + APP_TZ + '" is not a valid timezone.'); }
if (configErrors.length) {
    throw new Error('Configuration error:\n - ' + configErrors.join('\n - '));
}

const TOKEN_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours
const LOGIN_MAX_FAILS = 5;               // failed logins allowed per window, per IP
const LOGIN_WINDOW_SEC = 15 * 60;        // 15 minutes

const STATUSES = ['Sorting Depot', 'Customs Exception', 'In Transit', 'Delivered'];
const SERVICES = [
    'Express Air Freight Priority',
    'Overland Road Freight Cold-Chain',
    'Ocean Carrier Vessel Consignee'
];

// ==========================================
// MIDDLEWARE
// ==========================================
app.disable('x-powered-by');
app.set('trust proxy', 1);

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
    origin: allowedOrigins.length ? allowedOrigins : true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600
}));

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (req.path.startsWith('/api/') || req.path === '/admin') {
        res.setHeader('Cache-Control', 'no-store');
    }
    next();
});

app.use(express.json({ limit: '20kb' })); // small body limit blocks oversized payloads
app.use(express.static(path.join(__dirname, 'public')));

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function clientIp(req) {
    if (IS_VERCEL) {
        const h = req.headers['x-vercel-forwarded-for'] || req.headers['x-real-ip'];
        if (h) return String(h).split(',')[0].trim();
    }
    return req.ip || 'unknown';
}

// ==========================================
// PERSISTENT STORAGE (Upstash Redis on Vercel, JSON file locally)
// ==========================================
const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
const HASH_KEY = 'cargotracker:shipments';
const SEED_KEY = 'cargotracker:seeded';

function readSeedFile() {
    try {
        return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (e) {
        return {};
    }
}

let redis = null;
let storage;

if (REDIS_URL && REDIS_TOKEN) {
    const { Redis } = require('@upstash/redis');
    redis = new Redis({ url: REDIS_URL, token: REDIS_TOKEN });
    let seedChecked = false;

    async function seedOnce() {
        if (seedChecked) return;
        const alreadySeeded = await redis.get(SEED_KEY);
        if (!alreadySeeded) {
            const seed = readSeedFile();
            for (const [id, rec] of Object.entries(seed)) {
                await redis.hsetnx(HASH_KEY, id, rec);
            }
            await redis.set(SEED_KEY, '1');
        }
        seedChecked = true;
    }

    storage = {
        name: 'redis',
        async all() { await seedOnce(); return (await redis.hgetall(HASH_KEY)) || {}; },
        async get(id) { await seedOnce(); return (await redis.hget(HASH_KEY, id)) || null; },
        async exists(id) { await seedOnce(); return (await redis.hexists(HASH_KEY, id)) === 1; },
        async set(id, rec) { await seedOnce(); await redis.hset(HASH_KEY, { [id]: rec }); },
        async del(id) { await seedOnce(); return (await redis.hdel(HASH_KEY, id)) > 0; }
    };
} else if (IS_VERCEL) {
    const fail = async () => { throw new Error('No database connected. Add Upstash Redis in Vercel > Storage and redeploy.'); };
    storage = { name: 'none', all: fail, get: fail, exists: fail, set: fail, del: fail };
} else {
    const load = () => { try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { return {}; } };
    const save = (d) => fs.writeFileSync(DB_FILE, JSON.stringify(d, null, 4), 'utf8');
    storage = {
        name: 'file',
        async all() { return load(); },
        async get(id) { return load()[id] || null; },
        async exists(id) { return id in load(); },
        async set(id, rec) { const d = load(); d[id] = rec; save(d); },
        async del(id) { const d = load(); if (!(id in d)) return false; delete d[id]; save(d); return true; }
    };
}

// ==========================================
// RATE LIMITING (Redis-backed on Vercel so it works across serverless instances)
// ==========================================
const memHits = new Map();

async function rlCount(key) {
    if (redis) return Number(await redis.get('cargotracker:rl:' + key)) || 0;
    const e = memHits.get(key);
    if (!e || e.exp < Date.now()) { memHits.delete(key); return 0; }
    return e.n;
}

async function rlHit(key, windowSec) {
    if (redis) {
        const k = 'cargotracker:rl:' + key;
        const n = await redis.incr(k);
        if (n === 1) await redis.expire(k, windowSec);
        return n;
    }
    const now = Date.now();
    if (memHits.size > 5000) {
        for (const [k, v] of memHits) if (v.exp < now) memHits.delete(k);
    }
    let e = memHits.get(key);
    if (!e || e.exp < now) { e = { n: 0, exp: now + windowSec * 1000 }; memHits.set(key, e); }
    e.n++;
    return e.n;
}

async function rlClear(key) {
    if (redis) await redis.del('cargotracker:rl:' + key);
    else memHits.delete(key);
}

function limitRequests(name, max, windowSec) {
    return asyncHandler(async (req, res, next) => {
        const n = await rlHit(name + ':' + clientIp(req), windowSec);
        if (n > max) {
            res.setHeader('Retry-After', String(windowSec));
            return res.status(429).json({ error: 'Too many requests. Please slow down.' });
        }
        next();
    });
}

// ==========================================
// STAFF AUTH (signed, expiring token - no server memory needed)
// ==========================================
function sha256(s) {
    return crypto.createHash('sha256').update(String(s)).digest();
}

// Constant-time string comparison (hashes first so lengths always match)
function safeEqual(a, b) {
    return crypto.timingSafeEqual(sha256(a), sha256(b));
}

function sign(exp) {
    return crypto.createHmac('sha256', TOKEN_SECRET).update('staff.' + exp).digest('hex');
}

function signToken() {
    const exp = Date.now() + TOKEN_TTL_MS;
    return exp + '.' + sign(exp);
}

function verifyToken(token) {
    if (typeof token !== 'string' || token.length > 200) return false;
    const parts = token.split('.');
    if (parts.length !== 2) return false;
    const [exp, sig] = parts;
    const expNum = Number(exp);
    if (!Number.isFinite(expNum) || expNum < Date.now()) return false;
    const a = Buffer.from(sig);
    const b = Buffer.from(sign(exp));
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requireAuth(req, res, next) {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!verifyToken(token)) return res.status(401).json({ error: 'Staff login required.' });
    next();
}

// ==========================================
// HELPERS
// ==========================================
const ID_RE = /^[A-Z0-9-]{3,32}$/;
function cleanId(raw) {
    const id = String(raw || '').trim().toUpperCase();
    return ID_RE.test(id) ? id : null;
}

// Trim, strip control characters, cap length. Non-strings become the fallback.
function str(v, max, fallback = '') {
    if (typeof v !== 'string') return fallback;
    return v.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
}

function formatBackendDateTime(dateObj, longFormat = true) {
    if (!dateObj) return null;
    const d = new Date(dateObj);
    if (isNaN(d.getTime())) return null;

    const p = {};
    new Intl.DateTimeFormat('en-US', {
        timeZone: APP_TZ, month: 'short', day: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hour12: true
    }).formatToParts(d).forEach(x => { p[x.type] = x.value; });

    const timeStr = p.hour + ':' + p.minute + ' ' + p.dayPeriod;
    return longFormat
        ? p.month + ' ' + p.day + ', ' + p.year + ' - ' + timeStr
        : p.month + ' ' + p.day + ', ' + timeStr;
}

function statusMeta(status) {
    switch (status) {
        case 'In Transit':
            return { step: 3, badge: 'bg-amber-500/10 text-amber-500 border border-amber-500/30', icon: 'fa-truck-fast' };
        case 'Delivered':
            return { step: 4, badge: 'bg-emerald-500/10 text-[#22C55E] border border-emerald-500/30', icon: 'fa-circle-check' };
        case 'Customs Exception':
            return { step: 2, badge: 'bg-rose-500/10 text-rose-500 border border-rose-500/30', icon: 'fa-circle-exclamation' };
        default:
            return { step: 1, badge: 'bg-sky-500/10 text-sky-500 border border-sky-500/30', icon: status === 'Sorting Depot' ? 'fa-warehouse' : 'fa-clock' };
    }
}

// ==========================================
// REST API ROUTING ENDPOINTS
// ==========================================

// Authenticate Admin Staff Credentials
app.post('/api/auth/login', asyncHandler(async (req, res) => {
    const ipKey = 'login:' + clientIp(req);

    if ((await rlCount(ipKey)) >= LOGIN_MAX_FAILS) {
        res.setHeader('Retry-After', String(LOGIN_WINDOW_SEC));
        return res.status(429).json({ success: false, error: 'Too many failed attempts. Try again in 15 minutes.' });
    }

    const { username, password } = req.body || {};
    const userOk = typeof username === 'string' && safeEqual(username, ADMIN_USER);
    const passOk = typeof password === 'string' && safeEqual(password, ADMIN_PASS);

    if (userOk && passOk) {
        await rlClear(ipKey);
        return res.status(200).json({ success: true, token: signToken(), user: 'Operations Admin' });
    }

    await rlHit(ipKey, LOGIN_WINDOW_SEC);
    await new Promise(r => setTimeout(r, 300)); // small delay slows down guessing
    res.status(401).json({ success: false, error: 'Invalid staff credentials' });
}));

// Fetch all registered cargo containers (staff only)
app.get('/api/shipments', requireAuth, asyncHandler(async (req, res) => {
    res.status(200).json(await storage.all());
}));

// Public lookup of a single tracking ID (rate limited to stop ID enumeration)
app.get('/api/shipments/:id', limitRequests('lookup', 60, 60), asyncHandler(async (req, res) => {
    const cargoId = cleanId(req.params.id);
    const record = cargoId ? await storage.get(cargoId) : null;

    if (record) {
        res.status(200).json(record);
    } else {
        res.status(404).json({ error: 'Tracking identifier not recognized in active database manifests.' });
    }
}));

// Register and Generate brand new waybill (staff only)
app.post('/api/shipments/create', requireAuth, asyncHandler(async (req, res) => {
    const b = req.body || {};

    const shipper = str(b.shipper, 120);
    const receiver = str(b.receiver, 120);
    if (!shipper || !receiver) {
        return res.status(400).json({ error: 'Origin shipper and destination receiver details are mandatory.' });
    }

    const status = b.status === undefined || b.status === '' ? 'Sorting Depot' : b.status;
    if (!STATUSES.includes(status)) {
        return res.status(400).json({ error: 'Invalid status value.' });
    }
    const service = b.service === undefined || b.service === '' ? SERVICES[0] : b.service;
    if (!SERVICES.includes(service)) {
        return res.status(400).json({ error: 'Invalid service level.' });
    }

    const weight = str(b.weight, 30);
    const dimensions = str(b.dimensions, 40);
    const temp = str(b.temp, 20);
    const m1 = str(b.m1, 120), m2 = str(b.m2, 120), m3 = str(b.m3, 120), m4 = str(b.m4, 120);

    const initiatedDate = str(b.initiatedDate, 40), initiatedDateShort = str(b.initiatedDateShort, 40);
    const departedDate = str(b.departedDate, 40), departedDateShort = str(b.departedDateShort, 40);
    const onTransitDate = str(b.onTransitDate, 40), onTransitDateShort = str(b.onTransitDateShort, 40);
    const deliveredDate = str(b.deliveredDate, 40), deliveredDateShort = str(b.deliveredDateShort, 40);

    // Generate an unused random 5-digit ID using a cryptographic RNG
    let randomNumber, generatedID;
    let tries = 0;
    do {
        if (++tries > 50) return res.status(503).json({ error: 'Could not allocate a tracking ID. Try again.' });
        randomNumber = crypto.randomInt(10000, 100000);
        generatedID = 'SH-' + randomNumber;
    } while (await storage.exists(generatedID));

    const meta = statusMeta(status);
    const step = meta.step;

    // Chronological fallbacks when custom form dates are empty
    const now = new Date();
    const at = (hours) => new Date(now.getTime() + hours * 60 * 60 * 1000);

    const fallbackInitiated = formatBackendDateTime(now, true);
    const fallbackDeparted = formatBackendDateTime(at(4), true);
    const fallbackOnTransit = formatBackendDateTime(at(12), true);
    const fallbackDelivered = formatBackendDateTime(at(24), true);

    const finalInitiatedShort = initiatedDateShort || formatBackendDateTime(now, false);
    const finalDepartedShort = departedDateShort || formatBackendDateTime(at(4), false);
    const finalOnTransitShort = onTransitDateShort || formatBackendDateTime(at(12), false);
    const finalDeliveredShort = deliveredDateShort || formatBackendDateTime(at(24), false);

    let etaValue;
    if (status === 'Delivered') etaValue = 'Delivered successfully (' + finalDeliveredShort + ')';
    else if (status === 'Customs Exception') etaValue = 'Hold (Awaiting Customs)';
    else if (status === 'In Transit') etaValue = 'Scheduled Delivery: ' + finalDeliveredShort;
    else etaValue = 'ETA: ' + finalDeliveredShort;

    const timesArray = [
        finalInitiatedShort,
        step >= 2 ? finalDepartedShort : 'Pending Sorting',
        step >= 3 ? finalOnTransitShort : 'Pending Dispatch',
        step >= 4 ? finalDeliveredShort : 'Pending Delivery'
    ];

    // Timeline (newest first)
    const timeline = [];

    timeline.push({
        time: initiatedDate || fallbackInitiated,
        event: m1 || 'Manifest Initiated & Picked Up',
        loc: (shipper.split(',')[1] || '').trim() || 'Shipper Origin Facility Warehouse',
        icon: 'fa-truck-ramp-box',
        desc: 'Package collection completed. Waybill tags generated securely.'
    });

    if (step >= 2) {
        if (status === 'Customs Exception') {
            timeline.unshift({
                time: departedDate || fallbackDeparted,
                event: m2 || 'Customs Inspection Hold',
                loc: 'Port Customs Checkpoint Area',
                icon: 'fa-circle-exclamation',
                desc: 'Random customs check initiated. Import duty declaration under inspection. Agent broker has been notified.'
            });
        } else {
            timeline.unshift({
                time: departedDate || fallbackDeparted,
                event: m2 || 'Freight Sorted & Consolidated',
                loc: 'Carrier Dispatch Center',
                icon: 'fa-warehouse',
                desc: 'Cargo consolidated on linehaul truck loading ramps.'
            });
        }
    }

    if (step >= 3) {
        timeline.unshift({
            time: onTransitDate || fallbackOnTransit,
            event: m3 || 'Departed facility node on route transit',
            loc: 'Gateway Sorting Node',
            icon: 'fa-truck-fast',
            desc: 'Container manifest dispatched toward target delivery terminal.'
        });
    }

    if (step >= 4) {
        timeline.unshift({
            time: deliveredDate || fallbackDelivered,
            event: m4 || 'Cargo Delivered & Completed',
            loc: (receiver.split(',')[0] || '').trim() || 'Destination Receiver Dock',
            icon: 'fa-circle-check',
            desc: 'Cargo offloaded. Checked out cleanly. Received and signed by local consignee.'
        });
    }

    const newPackage = {
        waybill: 'WB-' + crypto.randomInt(100000, 900000) + '-' + generatedID,
        eta: etaValue,
        location: status === 'Delivered'
            ? (receiver.split(',')[0] || receiver)
            : (status === 'In Transit' ? 'En Route Gateway Center' : 'Sorting Hub Depot'),
        status: status,
        badgeClass: meta.badge,
        step: step,
        shipper: shipper,
        receiver: receiver,
        service: service,
        weight: weight || '15.0 kg',
        dimensions: dimensions || '40x40x40 cm',
        barcode: '||| ||| | || ' + randomNumber + ' ||',
        tempSensor: temp || '18.5°C',
        times: timesArray,
        timeline: timeline
    };

    await storage.set(generatedID, newPackage);
    res.status(201).json({ success: true, trackingID: generatedID, shipment: newPackage });
}));

// Update Status of package (staff only)
app.put('/api/shipments/:id/status', requireAuth, asyncHandler(async (req, res) => {
    const cargoId = cleanId(req.params.id);
    const b = req.body || {};
    const status = b.status;

    if (!STATUSES.includes(status)) {
        return res.status(400).json({ error: 'Invalid status value.' });
    }

    const cargo = cargoId ? await storage.get(cargoId) : null;
    if (!cargo) {
        return res.status(404).json({ error: 'Target package not found.' });
    }

    const location = str(b.location, 120);
    const details = str(b.details, 500);

    const meta = statusMeta(status);
    const step = meta.step;

    cargo.status = status;
    cargo.location = location || cargo.location;
    cargo.badgeClass = meta.badge;
    cargo.step = step;

    if (status === 'In Transit') cargo.eta = 'In Transit (Scheduled)';
    else if (status === 'Delivered') cargo.eta = 'Delivered successfully';
    else if (status === 'Customs Exception') cargo.eta = 'Hold (Awaiting Customs)';
    else cargo.eta = 'Processing in Depot';

    const now = new Date();
    const formattedTime = formatBackendDateTime(now, true);
    const formattedTimeShort = formatBackendDateTime(now, false);

    if (!Array.isArray(cargo.times)) cargo.times = [formattedTimeShort, 'Pending Sorting', 'Pending Dispatch', 'Pending Delivery'];
    if (!Array.isArray(cargo.timeline)) cargo.timeline = [];

    if (step >= 2 && cargo.times[1] === 'Pending Sorting') cargo.times[1] = formattedTimeShort;
    if (step >= 3 && cargo.times[2] === 'Pending Dispatch') cargo.times[2] = formattedTimeShort;
    if (step >= 4 && cargo.times[3] === 'Pending Delivery') cargo.times[3] = formattedTimeShort;

    cargo.timeline.unshift({
        time: formattedTime,
        event: 'Status updated to: ' + status,
        loc: cargo.location,
        icon: meta.icon,
        desc: details || ('Package status altered to ' + status + ' at ' + cargo.location + '. Operational logs updated.')
    });

    await storage.set(cargoId, cargo);
    res.status(200).json({ success: true, shipment: cargo });
}));

// Purge Shipment from database (staff only)
app.delete('/api/shipments/:id', requireAuth, asyncHandler(async (req, res) => {
    const cargoId = cleanId(req.params.id);

    if (cargoId && await storage.del(cargoId)) {
        res.status(200).json({ success: true, message: 'Waybill ' + cargoId + ' permanently removed.' });
    } else {
        res.status(404).json({ error: 'Package record not found.' });
    }
}));

// ==========================================
// QUOTE REQUESTS & NEWSLETTER (stored in the database, viewed in /admin)
// ==========================================
function makeCollection(name) {
    if (redis) {
        const key = 'cargotracker:' + name;
        return {
            async all() { return (await redis.hgetall(key)) || {}; },
            async get(id) { return (await redis.hget(key, id)) || null; },
            async set(id, rec) { await redis.hset(key, { [id]: rec }); },
            async del(id) { return (await redis.hdel(key, id)) > 0; },
            async count() { return await redis.hlen(key); }
        };
    }
    if (IS_VERCEL) {
        const fail = async () => { throw new Error('No database connected. Add Upstash Redis in Vercel > Storage and redeploy.'); };
        return { all: fail, get: fail, set: fail, del: fail, count: fail };
    }
    // Local development: JSON file (contains personal data - keep it out of Git)
    const file = path.join(__dirname, 'data-' + name + '.json');
    const load = () => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return {}; } };
    const save = (d) => fs.writeFileSync(file, JSON.stringify(d, null, 4), 'utf8');
    return {
        async all() { return load(); },
        async get(id) { return load()[id] || null; },
        async set(id, rec) { const d = load(); d[id] = rec; save(d); },
        async del(id) { const d = load(); if (!(id in d)) return false; delete d[id]; save(d); return true; },
        async count() { return Object.keys(load()).length; }
    };
}

const quotes = makeCollection('quotes');
const subscribers = makeCollection('subscribers');

const QUOTE_SERVICES = ['Air Freight', 'Ocean Freight', 'Road Freight', 'Train Freight', 'Warehouse Solutions'];
const QUOTE_STATUSES = ['new', 'read', 'replied'];
const MAX_STORED = 5000; // stops the database filling up if someone floods the forms
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Like str() but keeps line breaks (for the quote message)
function longText(v, max) {
    if (typeof v !== 'string') return '';
    return v.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, max);
}

const newestFirst = (a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || ''));

// PUBLIC: submit a quote request (5 per hour per IP)
app.post('/api/quotes', limitRequests('quote', 5, 3600), asyncHandler(async (req, res) => {
    const b = req.body || {};

    // Honeypot: real visitors never fill this hidden field, bots do. Pretend it worked.
    if (str(b.website, 100)) return res.status(201).json({ success: true });

    const name = str(b.name, 100);
    const email = str(b.email, 150).toLowerCase();
    const phone = str(b.phone, 40);
    const service = b.service;
    const message = longText(b.message, 2000);

    if (!name) return res.status(400).json({ error: 'Please enter your name.' });
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Please enter a valid email address.' });
    if (!QUOTE_SERVICES.includes(service)) return res.status(400).json({ error: 'Please select a service.' });

    if ((await quotes.count()) >= MAX_STORED) {
        return res.status(503).json({ error: 'We cannot accept new requests right now. Please call us instead.' });
    }

    const id = 'Q-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    await quotes.set(id, { id, name, email, phone, service, message, status: 'new', createdAt: new Date().toISOString() });
    res.status(201).json({ success: true });
}));

// PUBLIC: newsletter signup (10 per hour per IP). Duplicates are ignored silently.
app.post('/api/newsletter', limitRequests('newsletter', 10, 3600), asyncHandler(async (req, res) => {
    const email = str((req.body || {}).email, 150).toLowerCase();
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Please enter a valid email address.' });

    const id = crypto.createHash('sha256').update(email).digest('hex').slice(0, 24).toUpperCase();
    if (!(await subscribers.get(id))) {
        if ((await subscribers.count()) >= MAX_STORED) {
            return res.status(503).json({ error: 'Signups are temporarily unavailable.' });
        }
        await subscribers.set(id, { id, email, createdAt: new Date().toISOString() });
    }
    res.status(201).json({ success: true });
}));

// STAFF: list quote requests (newest first)
app.get('/api/quotes', requireAuth, asyncHandler(async (req, res) => {
    res.status(200).json(Object.values(await quotes.all()).sort(newestFirst));
}));

// STAFF: change a quote's status (new / read / replied)
app.put('/api/quotes/:id/status', requireAuth, asyncHandler(async (req, res) => {
    const id = cleanId(req.params.id);
    const status = (req.body || {}).status;
    if (!QUOTE_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status value.' });
    const rec = id ? await quotes.get(id) : null;
    if (!rec) return res.status(404).json({ error: 'Quote request not found.' });
    rec.status = status;
    await quotes.set(id, rec);
    res.status(200).json({ success: true, quote: rec });
}));

// STAFF: delete a quote request
app.delete('/api/quotes/:id', requireAuth, asyncHandler(async (req, res) => {
    const id = cleanId(req.params.id);
    if (id && await quotes.del(id)) return res.status(200).json({ success: true });
    res.status(404).json({ error: 'Quote request not found.' });
}));

// STAFF: list newsletter subscribers
app.get('/api/subscribers', requireAuth, asyncHandler(async (req, res) => {
    res.status(200).json(Object.values(await subscribers.all()).sort(newestFirst));
}));

// STAFF: remove a subscriber
app.delete('/api/subscribers/:id', requireAuth, asyncHandler(async (req, res) => {
    const id = cleanId(req.params.id);
    if (id && await subscribers.del(id)) return res.status(200).json({ success: true });
    res.status(404).json({ error: 'Subscriber not found.' });
}));

// ==========================================
// EMBEDDED STAFF PORTAL FRONTEND PAGE
// (client script avoids template literals and escapes all dynamic values)
// ==========================================
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Control Panel Portal | Shipment Logistics</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script>
        tailwind.config = { theme: { extend: { colors: { primary: '#FF3E41', secondary: '#0F172A', accent: '#06B6D4' } } } }
    </script>
    <style>
        .custom-toast { animation: slideIn 0.3s ease-out forwards; }
        @keyframes slideIn { from { transform: translateY(-1rem); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    </style>
</head>
<body class="bg-[#FAFAFA] text-slate-800 font-sans antialiased">
    <div id="toast-container" class="fixed top-5 right-5 z-50 flex flex-col gap-3 max-w-sm w-full pointer-events-none"></div>

    <div id="custom-confirm" class="hidden fixed inset-0 bg-slate-900/60 backdrop-blur-sm items-center justify-center z-50 p-4">
        <div class="bg-white rounded-2xl max-w-sm w-full p-6 shadow-2xl border border-slate-100">
            <div class="text-center">
                <span class="w-12 h-12 bg-rose-50 text-rose-500 flex items-center justify-center text-xl mx-auto rounded-full mb-3">
                    <i class="fa-solid fa-triangle-exclamation"></i>
                </span>
                <h3 class="font-bold text-slate-900 text-lg" id="confirm-title">Are you sure?</h3>
                <p class="text-slate-500 text-xs mt-2 leading-relaxed" id="confirm-message"></p>
            </div>
            <div class="mt-6 flex gap-3">
                <button id="confirm-cancel-btn" class="flex-1 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold rounded-xl text-xs uppercase tracking-wider transition-colors">Cancel</button>
                <button id="confirm-accept-btn" class="flex-1 py-2.5 bg-primary hover:bg-rose-600 text-white font-bold rounded-xl text-xs uppercase tracking-wider transition-colors">Delete</button>
            </div>
        </div>
    </div>

    <div id="login-screen" class="min-h-screen flex items-center justify-center bg-slate-950 px-4">
        <div class="max-w-md w-full bg-slate-900 border border-slate-800 p-8 rounded-3xl shadow-2xl">
            <div class="text-center mb-6">
                <span class="w-14 h-14 bg-primary/10 text-primary flex items-center justify-center text-2xl mx-auto rounded-full mb-3">
                    <i class="fa-solid fa-lock-open"></i>
                </span>
                <h2 class="text-white text-2xl font-bold">Staff Control Gateway</h2>
                <p class="text-slate-400 text-xs mt-1">Unlock central logistics servers securely</p>
            </div>
            <form id="loginForm" class="space-y-4">
                <div>
                    <label class="block text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Staff Username</label>
                    <input type="text" id="username" required autocomplete="username" class="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm text-white focus:outline-none focus:border-primary">
                </div>
                <div>
                    <label class="block text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Passkey Code</label>
                    <input type="password" id="password" required autocomplete="current-password" class="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm text-white focus:outline-none focus:border-primary">
                </div>
                <div id="loginError" class="hidden text-xs text-rose-500 font-bold bg-rose-500/10 p-2.5 rounded border border-rose-500/20"></div>
                <button type="submit" class="w-full py-3 bg-primary hover:bg-rose-600 text-white font-bold rounded-lg text-xs uppercase tracking-wider transition-colors">Authenticate Terminal</button>
            </form>
        </div>
    </div>

    <div id="dashboard-screen" class="hidden min-h-screen flex flex-col">
        <header class="bg-slate-950 text-white py-4 px-6 border-b border-slate-800 flex justify-between items-center">
            <div class="flex items-center gap-3">
                <div class="bg-primary text-white p-2.5 rounded-xl text-lg"><i class="fa-solid fa-satellite-dish animate-pulse"></i></div>
                <div>
                    <h1 class="font-bold text-lg">CargoTracker Central</h1>
                    <p class="text-[9px] text-slate-400 tracking-widest uppercase font-semibold">Live System Terminal</p>
                </div>
            </div>
            <button id="logoutBtn" class="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-xs font-bold rounded border border-slate-800 uppercase tracking-wider transition">Logout</button>
        </header>

        <div class="bg-white border-b border-slate-200 px-6">
            <div class="max-w-7xl mx-auto flex gap-2">
                <button id="tabbtn-shipments" data-tab="shipments" class="px-4 py-3 text-xs font-bold uppercase tracking-wider border-b-2 transition border-primary text-primary">Shipments</button>
                <button id="tabbtn-quotes" data-tab="quotes" class="px-4 py-3 text-xs font-bold uppercase tracking-wider border-b-2 transition border-transparent text-slate-500 hover:text-slate-800">Quote Requests <span id="quoteCountBadge" class="ml-1 px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 text-[10px]">0</span></button>
                <button id="tabbtn-subs" data-tab="subs" class="px-4 py-3 text-xs font-bold uppercase tracking-wider border-b-2 transition border-transparent text-slate-500 hover:text-slate-800">Subscribers <span id="subCountBadge" class="ml-1 px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 text-[10px]">0</span></button>
            </div>
        </div>

        <main id="tab-shipments" class="flex-grow p-6 max-w-7xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div class="lg:col-span-5 bg-white border border-slate-200 p-6 sm:p-8 rounded-2xl shadow-sm">
                <h3 class="font-bold text-lg text-slate-900 mb-6 border-b border-slate-100 pb-3">
                    <i class="fa-solid fa-boxes-packing text-primary mr-1"></i> New Cargo Entry
                </h3>
                <form id="createForm" class="space-y-4 text-xs">
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block font-bold text-slate-500 uppercase tracking-wider mb-1">Shipper Origin</label>
                            <input type="text" id="shipper" required maxlength="120" placeholder="Lux Logistics, Paris" class="w-full bg-slate-50 border border-slate-200 rounded p-2.5 outline-none focus:border-primary">
                        </div>
                        <div>
                            <label class="block font-bold text-slate-500 uppercase tracking-wider mb-1">Consignee Destination</label>
                            <input type="text" id="receiver" required maxlength="120" placeholder="TechCorp, New York" class="w-full bg-slate-50 border border-slate-200 rounded p-2.5 outline-none focus:border-primary">
                        </div>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block font-bold text-slate-500 uppercase tracking-wider mb-1">Service Level</label>
                            <select id="service" class="w-full bg-slate-50 border border-slate-200 rounded p-2.5 outline-none focus:border-primary">
                                <option>Express Air Freight Priority</option>
                                <option>Overland Road Freight Cold-Chain</option>
                                <option>Ocean Carrier Vessel Consignee</option>
                            </select>
                        </div>
                        <div>
                            <label class="block font-bold text-slate-500 uppercase tracking-wider mb-1">Current Status</label>
                            <select id="status" class="w-full bg-slate-50 border border-slate-200 rounded p-2.5 outline-none focus:border-primary">
                                <option>Sorting Depot</option>
                                <option>Customs Exception</option>
                                <option>In Transit</option>
                                <option>Delivered</option>
                            </select>
                        </div>
                    </div>
                    <div class="grid grid-cols-3 gap-3">
                        <div>
                            <label class="block font-bold text-slate-500 uppercase tracking-wider mb-1">Weight</label>
                            <input type="text" id="weight" maxlength="30" placeholder="12.5 kg" class="w-full bg-slate-50 border border-slate-200 rounded p-2 outline-none">
                        </div>
                        <div>
                            <label class="block font-bold text-slate-500 uppercase tracking-wider mb-1">Volume</label>
                            <input type="text" id="dimensions" maxlength="40" placeholder="40x40x40 cm" class="w-full bg-slate-50 border border-slate-200 rounded p-2 outline-none">
                        </div>
                        <div>
                            <label class="block font-bold text-slate-500 uppercase tracking-wider mb-1">Temp</label>
                            <input type="text" id="temp" maxlength="20" placeholder="18.5°C" class="w-full bg-slate-50 border border-slate-200 rounded p-2 outline-none">
                        </div>
                    </div>
                    <div class="border-t border-slate-100 pt-3">
                        <span class="block text-[10px] font-extrabold text-slate-400 uppercase tracking-wider mb-3">Custom Timeline Schedules</span>
                        <div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
                            <div>
                                <label class="block font-bold text-slate-400 uppercase tracking-[0.05em] mb-1 text-[9px]">Picked Up Date</label>
                                <input type="datetime-local" id="initiatedDate" class="w-full bg-slate-50 border border-slate-200 rounded p-2 outline-none focus:border-primary text-[10px]">
                            </div>
                            <div>
                                <label class="block font-bold text-slate-400 uppercase tracking-[0.05em] mb-1 text-[9px]">Sorted Date</label>
                                <input type="datetime-local" id="departedDate" class="w-full bg-slate-50 border border-slate-200 rounded p-2 outline-none focus:border-primary text-[10px]">
                            </div>
                            <div>
                                <label class="block font-bold text-slate-400 uppercase tracking-[0.05em] mb-1 text-[9px]">On Transit Date</label>
                                <input type="datetime-local" id="onTransitDate" class="w-full bg-slate-50 border border-slate-200 rounded p-2 outline-none focus:border-primary text-[10px]">
                            </div>
                            <div>
                                <label class="block font-bold text-slate-400 uppercase tracking-[0.05em] mb-1 text-[9px]">Delivered Date</label>
                                <input type="datetime-local" id="deliveredDate" class="w-full bg-slate-50 border border-slate-200 rounded p-2 outline-none focus:border-primary text-[10px]">
                            </div>
                        </div>
                    </div>
                    <button type="submit" class="w-full py-3 bg-primary hover:bg-rose-600 text-white font-bold rounded-xl tracking-wider uppercase shadow transition-all flex items-center justify-center gap-1.5 mt-4">
                        <i class="fa-solid fa-plus"></i> Inject Into Database
                    </button>
                </form>
            </div>

            <div class="lg:col-span-7 bg-white border border-slate-200 p-6 sm:p-8 rounded-2xl shadow-sm">
                <div class="flex justify-between items-center border-b border-slate-100 pb-3 mb-6">
                    <h3 class="font-bold text-lg text-slate-900"><i class="fa-solid fa-boxes-stacked text-primary mr-1"></i> Package Index</h3>
                    <span id="packageCount" class="text-xs font-bold text-slate-400 uppercase tracking-wider">-</span>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs border-collapse">
                        <thead>
                            <tr class="text-slate-400 font-bold border-b border-slate-100 uppercase tracking-wider">
                                <th class="py-3 px-2">ID</th>
                                <th class="py-3 px-2">Route Details</th>
                                <th class="py-3 px-2">Current State</th>
                                <th class="py-3 px-2 text-right">Modifier Ops</th>
                            </tr>
                        </thead>
                        <tbody id="shipment-rows" class="divide-y divide-slate-100"></tbody>
                    </table>
                </div>
            </div>
        </main>

        <section id="tab-quotes" class="hidden flex-grow p-6 max-w-7xl mx-auto w-full">
            <div class="bg-white border border-slate-200 p-6 sm:p-8 rounded-2xl shadow-sm">
                <div class="flex justify-between items-center border-b border-slate-100 pb-3 mb-6">
                    <h3 class="font-bold text-lg text-slate-900"><i class="fa-solid fa-inbox text-primary mr-1"></i> Quote Requests</h3>
                    <button id="refreshQuotes" class="text-xs font-bold text-slate-500 hover:text-primary uppercase tracking-wider"><i class="fa-solid fa-rotate mr-1"></i> Refresh</button>
                </div>
                <div id="quote-list" class="space-y-4"></div>
            </div>
        </section>

        <section id="tab-subs" class="hidden flex-grow p-6 max-w-7xl mx-auto w-full">
            <div class="bg-white border border-slate-200 p-6 sm:p-8 rounded-2xl shadow-sm">
                <div class="flex justify-between items-center border-b border-slate-100 pb-3 mb-6">
                    <h3 class="font-bold text-lg text-slate-900"><i class="fa-solid fa-envelope-open-text text-primary mr-1"></i> Newsletter Subscribers</h3>
                    <button id="copyEmails" class="text-xs font-bold text-slate-500 hover:text-primary uppercase tracking-wider"><i class="fa-solid fa-copy mr-1"></i> Copy all emails</button>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs border-collapse">
                        <thead>
                            <tr class="text-slate-400 font-bold border-b border-slate-100 uppercase tracking-wider">
                                <th class="py-3 px-2">Email</th>
                                <th class="py-3 px-2">Signed Up</th>
                                <th class="py-3 px-2 text-right">Remove</th>
                            </tr>
                        </thead>
                        <tbody id="sub-rows" class="divide-y divide-slate-100"></tbody>
                    </table>
                </div>
            </div>
        </section>
    </div>

    <script>
        var API_BASE = window.location.origin;
        var STATUSES = ['Sorting Depot', 'Customs Exception', 'In Transit', 'Delivered'];

        function esc(s) {
            return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
                return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
            });
        }

        function authHeaders(json) {
            var h = { 'Authorization': 'Bearer ' + sessionStorage.getItem('staffToken') };
            if (json) h['Content-Type'] = 'application/json';
            return h;
        }

        function showNotification(msg, type) {
            type = type || 'success';
            var container = document.getElementById('toast-container');
            var toast = document.createElement('div');
            toast.className = 'custom-toast pointer-events-auto flex items-center gap-3 p-4 rounded-xl shadow-lg border text-xs font-semibold bg-white transition-all ' +
                (type === 'success' ? 'border-emerald-500/20 text-emerald-800' : 'border-rose-500/20 text-rose-800');

            var icon = document.createElement('i');
            icon.className = 'fa-solid text-lg ' + (type === 'success' ? 'fa-circle-check text-emerald-500' : 'fa-circle-exclamation text-rose-500');
            var span = document.createElement('span');
            span.className = 'flex-grow';
            span.textContent = msg;

            toast.appendChild(icon);
            toast.appendChild(span);
            container.appendChild(toast);

            setTimeout(function () {
                toast.classList.add('opacity-0');
                setTimeout(function () { toast.remove(); }, 300);
            }, 3500);
        }

        function triggerConfirm(title, message, onAccept) {
            var modal = document.getElementById('custom-confirm');
            document.getElementById('confirm-title').textContent = title;
            document.getElementById('confirm-message').textContent = message;
            var cancelBtn = document.getElementById('confirm-cancel-btn');
            var acceptBtn = document.getElementById('confirm-accept-btn');

            modal.classList.remove('hidden');
            modal.classList.add('flex');

            function cleanUp() {
                modal.classList.add('hidden');
                modal.classList.remove('flex');
                cancelBtn.onclick = null;
                acceptBtn.onclick = null;
            }
            cancelBtn.onclick = cleanUp;
            acceptBtn.onclick = function () { onAccept(); cleanUp(); };
        }

        function formatDateTime(val, longFormat) {
            if (!val) return null;
            var d = new Date(val);
            if (isNaN(d.getTime())) return null;
            var month = d.toLocaleDateString('en-US', { month: 'short' });
            var day = d.toLocaleDateString('en-US', { day: '2-digit' });
            var year = d.getFullYear();
            var hours = d.getHours();
            var minutes = String(d.getMinutes()).padStart(2, '0');
            var ampm = hours >= 12 ? 'PM' : 'AM';
            hours = hours % 12;
            hours = hours ? hours : 12;
            var t = String(hours).padStart(2, '0') + ':' + minutes + ' ' + ampm;
            return longFormat ? (month + ' ' + day + ', ' + year + ' - ' + t) : (month + ' ' + day + ', ' + t);
        }

        function logout() {
            sessionStorage.removeItem('staffToken');
            location.reload();
        }

        function showDashboard() {
            document.getElementById('login-screen').classList.add('hidden');
            document.getElementById('dashboard-screen').classList.remove('hidden');
            fetchShipments();
            fetchQuotes();
            fetchSubs();
        }

        // ---------- Tabs ----------
        function tabClass(active) {
            return 'px-4 py-3 text-xs font-bold uppercase tracking-wider border-b-2 transition ' +
                (active ? 'border-primary text-primary' : 'border-transparent text-slate-500 hover:text-slate-800');
        }
        function showTab(name) {
            ['shipments', 'quotes', 'subs'].forEach(function (t) {
                document.getElementById('tab-' + t).classList.toggle('hidden', t !== name);
                document.getElementById('tabbtn-' + t).className = tabClass(t === name);
            });
            if (name === 'quotes') fetchQuotes();
            if (name === 'subs') fetchSubs();
        }
        document.querySelectorAll('[data-tab]').forEach(function (b) {
            b.addEventListener('click', function () { showTab(b.dataset.tab); });
        });

        function fmtDate(iso) {
            var d = new Date(iso);
            return isNaN(d.getTime()) ? '' : d.toLocaleString();
        }

        // ---------- Quote requests ----------
        var QUOTE_STATUS_LABELS = { 'new': 'New', 'read': 'Read', 'replied': 'Replied' };

        async function fetchQuotes() {
            var list = document.getElementById('quote-list');
            try {
                var res = await fetch(API_BASE + '/api/quotes', { headers: authHeaders() });
                if (res.status === 401) { logout(); return; }
                var data = await res.json();
                var unread = data.filter(function (q) { return q.status === 'new'; }).length;
                document.getElementById('quoteCountBadge').textContent = unread ? unread + ' new' : String(data.length);
                list.innerHTML = '';
                if (!data.length) {
                    list.innerHTML = '<p class="text-center text-slate-400 text-sm py-8">No quote requests yet.</p>';
                    return;
                }
                data.forEach(function (q) {
                    var opts = ['new', 'read', 'replied'].map(function (s) {
                        return '<option value="' + s + '"' + (q.status === s ? ' selected' : '') + '>' + QUOTE_STATUS_LABELS[s] + '</option>';
                    }).join('');
                    var card = document.createElement('div');
                    card.className = 'border rounded-xl p-5 ' + (q.status === 'new' ? 'border-rose-200 bg-rose-50/40' : 'border-slate-200 bg-white');
                    card.innerHTML =
                        '<div class="flex flex-wrap justify-between items-start gap-3">' +
                            '<div>' +
                                '<p class="font-bold text-slate-900 text-sm">' + esc(q.name) + '</p>' +
                                '<p class="text-xs text-slate-500 mt-0.5"><a class="text-primary hover:underline" href="mailto:' + esc(q.email) + '">' + esc(q.email) + '</a>' +
                                (q.phone ? ' &middot; ' + esc(q.phone) : '') + '</p>' +
                            '</div>' +
                            '<div class="text-right">' +
                                '<span class="px-2 py-0.5 rounded text-[10px] uppercase font-extrabold text-slate-700 bg-slate-100 border border-slate-200">' + esc(q.service) + '</span>' +
                                '<p class="text-[10px] text-slate-400 mt-1">' + esc(fmtDate(q.createdAt)) + '</p>' +
                            '</div>' +
                        '</div>' +
                        (q.message ? '<p class="mt-3 text-xs text-slate-700 whitespace-pre-wrap break-words">' + esc(q.message) + '</p>' : '') +
                        '<div class="mt-4 flex items-center gap-2">' +
                            '<select data-action="qstatus" data-id="' + esc(q.id) + '" class="bg-slate-50 border border-slate-200 rounded px-2.5 py-1.5 text-[11px] font-semibold text-slate-700 outline-none focus:border-primary cursor-pointer">' + opts + '</select>' +
                            '<button data-action="qdelete" data-id="' + esc(q.id) + '" class="h-8 w-8 flex items-center justify-center bg-rose-500 hover:bg-rose-600 text-white rounded-lg transition" title="Delete"><i class="fa-solid fa-trash text-[11px]"></i></button>' +
                        '</div>';
                    list.appendChild(card);
                });
            } catch (err) {
                list.innerHTML = '<p class="text-center text-red-500 text-sm py-8">Could not load quote requests.</p>';
            }
        }

        async function updateQuoteStatus(id, status) {
            try {
                var res = await fetch(API_BASE + '/api/quotes/' + encodeURIComponent(id) + '/status', {
                    method: 'PUT', headers: authHeaders(true), body: JSON.stringify({ status: status })
                });
                if (res.status === 401) { logout(); return; }
                if (!res.ok) showNotification('Could not update the request.', 'error');
                fetchQuotes();
            } catch (err) {
                showNotification('Error communicating with servers.', 'error');
            }
        }

        function deleteQuote(id) {
            triggerConfirm('Delete request?', 'This quote request will be permanently removed.', async function () {
                try {
                    var res = await fetch(API_BASE + '/api/quotes/' + encodeURIComponent(id), { method: 'DELETE', headers: authHeaders() });
                    if (res.status === 401) { logout(); return; }
                    showNotification(res.ok ? 'Request deleted.' : 'Could not delete the request.', res.ok ? 'success' : 'error');
                    fetchQuotes();
                } catch (err) {
                    showNotification('Error communicating with servers.', 'error');
                }
            });
        }

        document.getElementById('quote-list').addEventListener('change', function (e) {
            var t = e.target;
            if (t && t.dataset && t.dataset.action === 'qstatus') updateQuoteStatus(t.dataset.id, t.value);
        });
        document.getElementById('quote-list').addEventListener('click', function (e) {
            var btn = e.target.closest ? e.target.closest('[data-action="qdelete"]') : null;
            if (btn) deleteQuote(btn.dataset.id);
        });
        document.getElementById('refreshQuotes').addEventListener('click', fetchQuotes);

        // ---------- Newsletter subscribers ----------
        var subscriberEmails = [];

        async function fetchSubs() {
            var body = document.getElementById('sub-rows');
            try {
                var res = await fetch(API_BASE + '/api/subscribers', { headers: authHeaders() });
                if (res.status === 401) { logout(); return; }
                var data = await res.json();
                subscriberEmails = data.map(function (s) { return s.email; });
                document.getElementById('subCountBadge').textContent = String(data.length);
                body.innerHTML = '';
                if (!data.length) {
                    body.innerHTML = '<tr><td colspan="3" class="py-6 text-center text-slate-400">No subscribers yet.</td></tr>';
                    return;
                }
                data.forEach(function (s) {
                    var tr = document.createElement('tr');
                    tr.className = 'hover:bg-slate-50 transition-colors';
                    tr.innerHTML =
                        '<td class="py-3 px-2 font-semibold text-slate-800">' + esc(s.email) + '</td>' +
                        '<td class="py-3 px-2 text-slate-500">' + esc(fmtDate(s.createdAt)) + '</td>' +
                        '<td class="py-3 px-2 text-right"><button data-action="sdelete" data-id="' + esc(s.id) + '" class="h-8 w-8 inline-flex items-center justify-center bg-rose-500 hover:bg-rose-600 text-white rounded-lg transition" title="Remove"><i class="fa-solid fa-trash text-[11px]"></i></button></td>';
                    body.appendChild(tr);
                });
            } catch (err) {
                body.innerHTML = '<tr><td colspan="3" class="py-6 text-center text-red-500">Could not load subscribers.</td></tr>';
            }
        }

        document.getElementById('sub-rows').addEventListener('click', function (e) {
            var btn = e.target.closest ? e.target.closest('[data-action="sdelete"]') : null;
            if (!btn) return;
            var id = btn.dataset.id;
            triggerConfirm('Remove subscriber?', 'This email will be removed from the list.', async function () {
                try {
                    var res = await fetch(API_BASE + '/api/subscribers/' + encodeURIComponent(id), { method: 'DELETE', headers: authHeaders() });
                    if (res.status === 401) { logout(); return; }
                    showNotification(res.ok ? 'Subscriber removed.' : 'Could not remove subscriber.', res.ok ? 'success' : 'error');
                    fetchSubs();
                } catch (err) {
                    showNotification('Error communicating with servers.', 'error');
                }
            });
        });

        document.getElementById('copyEmails').addEventListener('click', function () {
            if (!subscriberEmails.length) { showNotification('No subscribers to copy.', 'error'); return; }
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(subscriberEmails.join(', ')).then(
                    function () { showNotification(subscriberEmails.length + ' emails copied.', 'success'); },
                    function () { showNotification('Copy failed. Your browser blocked clipboard access.', 'error'); }
                );
            } else {
                showNotification('Copy is not supported in this browser.', 'error');
            }
        });

        document.getElementById('logoutBtn').addEventListener('click', logout);

        if (sessionStorage.getItem('staffToken')) showDashboard();

        document.getElementById('loginForm').addEventListener('submit', async function (e) {
            e.preventDefault();
            var errBox = document.getElementById('loginError');
            errBox.classList.add('hidden');
            try {
                var res = await fetch(API_BASE + '/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: document.getElementById('username').value,
                        password: document.getElementById('password').value
                    })
                });
                var data = await res.json();
                if (data.success) {
                    sessionStorage.setItem('staffToken', data.token);
                    document.getElementById('password').value = '';
                    showDashboard();
                } else {
                    errBox.textContent = data.error || 'Invalid password or username.';
                    errBox.classList.remove('hidden');
                }
            } catch (err) {
                showNotification('Unable to connect to the server.', 'error');
            }
        });

        async function fetchShipments() {
            var list = document.getElementById('shipment-rows');
            list.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-slate-400">Loading database records...</td></tr>';
            try {
                var res = await fetch(API_BASE + '/api/shipments', { headers: authHeaders() });
                if (res.status === 401) { logout(); return; }
                var data = await res.json();
                var keys = Object.keys(data);

                document.getElementById('packageCount').textContent = keys.length + ' Items';
                list.innerHTML = '';

                keys.forEach(function (key) {
                    var pack = data[key];
                    var opts = STATUSES.map(function (s) {
                        return '<option value="' + esc(s) + '"' + (pack.status === s ? ' selected' : '') + '>' + esc(s) + '</option>';
                    }).join('');

                    var tr = document.createElement('tr');
                    tr.className = 'hover:bg-slate-50 transition-colors border-b border-slate-100';
                    tr.innerHTML =
                        '<td class="py-4 px-2 font-mono font-bold text-primary">' + esc(key) + '</td>' +
                        '<td class="py-4 px-2">' +
                            '<span class="block font-semibold text-slate-800 text-xs truncate max-w-[200px]">' + esc(pack.shipper) + '</span>' +
                            '<span class="block text-slate-400 text-[10px] truncate max-w-[200px]">' + esc(pack.receiver) + '</span>' +
                        '</td>' +
                        '<td class="py-4 px-2"><span class="px-2 py-0.5 rounded text-[10px] uppercase font-extrabold text-slate-700 bg-slate-100 border border-slate-200">' + esc(pack.status) + '</span></td>' +
                        '<td class="py-4 px-2 text-right"><div class="inline-flex items-center gap-2">' +
                            '<select data-action="status" data-id="' + esc(key) + '" class="bg-slate-50 border border-slate-200 hover:border-slate-300 rounded px-2.5 py-1.5 text-[11px] font-semibold text-slate-700 outline-none focus:border-primary transition cursor-pointer">' + opts + '</select>' +
                            '<button data-action="delete" data-id="' + esc(key) + '" class="h-8 w-8 flex items-center justify-center bg-rose-500 hover:bg-rose-600 text-white rounded-lg transition" title="Purge Record"><i class="fa-solid fa-trash text-[11px]"></i></button>' +
                        '</div></td>';
                    list.appendChild(tr);
                });
            } catch (err) {
                list.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-red-500">Database communication failed.</td></tr>';
            }
        }

        // Event delegation (no inline handlers, no IDs injected into code)
        var rows = document.getElementById('shipment-rows');
        rows.addEventListener('change', function (e) {
            var t = e.target;
            if (t && t.dataset && t.dataset.action === 'status') quickUpdateStatus(t.dataset.id, t.value);
        });
        rows.addEventListener('click', function (e) {
            var btn = e.target.closest ? e.target.closest('[data-action="delete"]') : null;
            if (btn) deleteShipment(btn.dataset.id);
        });

        document.getElementById('createForm').addEventListener('submit', async function (e) {
            e.preventDefault();
            var v = function (id) { return document.getElementById(id).value; };
            var initiatedRaw = v('initiatedDate'), departedRaw = v('departedDate'),
                onTransitRaw = v('onTransitDate'), deliveredRaw = v('deliveredDate');

            var payload = {
                shipper: v('shipper'), receiver: v('receiver'), service: v('service'), status: v('status'),
                weight: v('weight'), dimensions: v('dimensions'), temp: v('temp'),
                initiatedDate: formatDateTime(initiatedRaw, true), initiatedDateShort: formatDateTime(initiatedRaw, false),
                departedDate: formatDateTime(departedRaw, true), departedDateShort: formatDateTime(departedRaw, false),
                onTransitDate: formatDateTime(onTransitRaw, true), onTransitDateShort: formatDateTime(onTransitRaw, false),
                deliveredDate: formatDateTime(deliveredRaw, true), deliveredDateShort: formatDateTime(deliveredRaw, false)
            };

            try {
                var res = await fetch(API_BASE + '/api/shipments/create', {
                    method: 'POST', headers: authHeaders(true), body: JSON.stringify(payload)
                });
                if (res.status === 401) { logout(); return; }
                var data = await res.json();
                if (data.success) {
                    showNotification('Waybill generated successfully! ID: ' + data.trackingID, 'success');
                    document.getElementById('createForm').reset();
                    fetchShipments();
                } else {
                    showNotification(data.error || 'Failed to create waybill.', 'error');
                }
            } catch (err) {
                showNotification('Failed to write new waybill to database.', 'error');
            }
        });

        async function quickUpdateStatus(id, newStatus) {
            var location = 'Local Delivery Terminal';
            var details = 'Status manually updated through Staff Operations Console.';

            if (newStatus === 'Sorting Depot') {
                location = 'Hub Carrier / Sorting Yard Depot';
                details = 'Package registered and processed through sorting lines. Prepped for linehaul vehicle consolidation.';
            } else if (newStatus === 'Customs Exception') {
                location = 'Port Customs Checkpoint Area';
                details = 'Held temporarily for standard import clearance procedures and paperwork checking.';
            } else if (newStatus === 'In Transit') {
                location = 'En Route Gateway Hub';
                details = 'Cleared processing facilities and is actively forwarding across the transportation network node.';
            } else if (newStatus === 'Delivered') {
                location = 'Destination Receiver Dock';
                details = 'Shipment completed. Handover checked, completed, and signed for successfully by local consignee.';
            }

            try {
                var res = await fetch(API_BASE + '/api/shipments/' + encodeURIComponent(id) + '/status', {
                    method: 'PUT', headers: authHeaders(true),
                    body: JSON.stringify({ status: newStatus, location: location, details: details })
                });
                if (res.status === 401) { logout(); return; }
                if (res.ok) {
                    showNotification('Shipment ' + id + ' updated to "' + newStatus + '"', 'success');
                } else {
                    showNotification('Unable to save status updates. Try again.', 'error');
                }
                fetchShipments();
            } catch (err) {
                showNotification('Error communicating with servers.', 'error');
            }
        }

        function deleteShipment(id) {
            triggerConfirm(
                'Purge Waybill?',
                'Are you absolutely sure you want to permanently clear shipment ' + id + ' from tracking databases?',
                async function () {
                    try {
                        var res = await fetch(API_BASE + '/api/shipments/' + encodeURIComponent(id), { method: 'DELETE', headers: authHeaders() });
                        if (res.status === 401) { logout(); return; }
                        if (res.ok) {
                            showNotification('Waybill cleared successfully.', 'success');
                            fetchShipments();
                        } else {
                            showNotification('Failed to purge requested package.', 'error');
                        }
                    } catch (err) {
                        showNotification('System write permissions error.', 'error');
                    }
                }
            );
        }
    </script>
</body>
</html>`;

app.get('/admin', (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(ADMIN_HTML);
});

// ==========================================
// ERROR HANDLING
// ==========================================
app.use('/api', (req, res) => {
    res.status(404).json({ error: 'Not found.' });
});

app.use((err, req, res, next) => {
    const status = err.status && err.status >= 400 && err.status < 500 ? err.status : 500;
    if (status === 500) console.error('Server error:', err); // details stay in server logs only
    const msg = status === 413 ? 'Request too large.'
        : status === 400 ? 'Malformed request.'
        : status === 500 ? 'Internal server error.'
        : 'Request failed.';
    res.status(status).json({ error: msg });
});

// Local: start a listener. Vercel: just export the app.
if (require.main === module) {
    app.listen(PORT, () => {
        console.log('CargoTracker running on http://localhost:' + PORT + '  (storage: ' + storage.name + ')');
        console.log('Admin console: http://localhost:' + PORT + '/admin');
    });
}

module.exports = app;
