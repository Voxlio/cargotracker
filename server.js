/**
 * CargoTracker - Logistics & Tracking Backend (Vercel-ready)
 *
 * Storage:
 *  - On Vercel: Upstash Redis (add it from Vercel > Storage / Marketplace).
 *  - Locally (no Redis env vars): falls back to database.json on disk.
 *
 * Run locally:  npm install && npm start  ->  http://localhost:3000  and /admin
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.json');

// Middleware
app.use(cors()); // Permits any frontend website to access tracking data securely
app.use(express.json()); // Parses incoming JSON data payloads

// 🛠️ Paste this new line right here:
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// PERSISTENT STORAGE (Upstash Redis on Vercel, JSON file locally)
// ==========================================
// NOTE: Vercel's filesystem is read-only, so writing to database.json there
// silently fails. That is why new waybills were never found. Redis fixes that.

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

let storage;

if (REDIS_URL && REDIS_TOKEN) {
    const { Redis } = require('@upstash/redis');
    const redis = new Redis({ url: REDIS_URL, token: REDIS_TOKEN });
    let seedChecked = false;

    // Copy the records from database.json into Redis once, on first use
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
} else if (process.env.VERCEL) {
    // Refuse to run silently without a database on Vercel
    const fail = async () => { throw new Error('No database connected. Add Upstash Redis in Vercel > Storage and redeploy.'); };
    storage = { name: 'none', all: fail, get: fail, exists: fail, set: fail, del: fail };
} else {
    // Local development: JSON file
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
// STAFF AUTH (signed, expiring token - no server memory needed)
// ==========================================
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password';
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'dev-only-secret-change-me';

function signToken() {
    const exp = Date.now() + 12 * 60 * 60 * 1000; // 12 hours
    const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(String(exp)).digest('hex');
    return exp + '.' + sig;
}

function verifyToken(token) {
    if (!token) return false;
    const [exp, sig] = token.split('.');
    if (!exp || !sig || Number(exp) < Date.now()) return false;
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(exp).digest('hex');
    const a = Buffer.from(sig), b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requireAuth(req, res, next) {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!verifyToken(token)) return res.status(401).json({ error: 'Staff login required.' });
    next();
}

// Utility to format server-side dates when custom UI dates are not provided
function formatBackendDateTime(dateObj, longFormat = true) {
    if (!dateObj) return null;
    const d = new Date(dateObj);
    if (isNaN(d.getTime())) return null;
    
    const month = d.toLocaleDateString('en-US', { month: 'short' });
    const day = d.toLocaleDateString('en-US', { day: '2-digit' });
    const year = d.getFullYear();
    
    let hours = d.getHours();
    const minutes = String(d.getMinutes()).padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12; 
    const timeStr = `${String(hours).padStart(2, '0')}:${minutes} ${ampm}`;
    
    if (longFormat) {
        return `${month} ${day}, ${year} - ${timeStr}`;
    } else {
        return `${month} ${day}, ${timeStr}`;
    }
}


// ==========================================
// REST API ROUTING ENDPOINTS
// ==========================================

// Authenticate Admin Staff Credentials
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USER && password === ADMIN_PASS) {
        res.status(200).json({ 
            success: true, 
            token: signToken(),
            user: "Operations Admin"
        });
    } else {
        res.status(401).json({ success: false, error: "Invalid staff credentials" });
    }
});

// Fetch all registered cargo containers
app.get('/api/shipments', requireAuth, async (req, res) => {
    res.status(200).json(await storage.all());
});

// Search for single parcel tracking ID (GET /api/shipments/SH-99210)
app.get('/api/shipments/:id', async (req, res) => {
    const cargoId = req.params.id.trim().toUpperCase();
    const record = await storage.get(cargoId);

    if (record) {
        res.status(200).json(record);
    } else {
        res.status(404).json({ error: "Tracking identifier not recognized in active database manifests." });
    }
});

// Register and Generate brand new waybill
app.post('/api/shipments/create', requireAuth, async (req, res) => {
    const { 
        shipper, receiver, service, status, weight, dimensions, temp, m1, m2, m3, m4,
        initiatedDate, initiatedDateShort,
        departedDate, departedDateShort,
        onTransitDate, onTransitDateShort,
        deliveredDate, deliveredDateShort 
    } = req.body;

    if (!shipper || !receiver) {
        return res.status(400).json({ error: "Origin shipper and destination receiver details are mandatory." });
    }

    // 1. Math formula generating a cryptographically independent 5-digit index
    // Keep generating until we get an ID that is not already used
    let randomNumber, generatedID;
    do {
        randomNumber = Math.floor(Math.random() * 90000) + 10000;
        generatedID = "SH-" + randomNumber;
    } while (await storage.exists(generatedID));

    // 2. Select appropriate badge design styles matching cargo states
    let badgeClass = "bg-sky-500/10 text-sky-500 border border-sky-500/30";
    let step = 1;

    if (status === 'In Transit') {
        badgeClass = "bg-amber-500/10 text-amber-500 border border-amber-500/30";
        step = 3;
    } else if (status === 'Delivered') {
        badgeClass = "bg-emerald-500/10 text-[#22C55E] border border-emerald-500/30";
        step = 4;
    } else if (status === 'Customs Exception') {
        badgeClass = "bg-rose-500/10 text-rose-500 border border-rose-500/30";
        step = 2;
    }

    // Generate chronological fallbacks in case custom form values are empty
    const now = new Date();
    const fallbackInitiated = formatBackendDateTime(now, true);
    const fallbackInitiatedShort = formatBackendDateTime(now, false);

    const sortedTime = new Date(now.getTime() + 4 * 60 * 60 * 1000); // + 4 hours
    const fallbackDeparted = formatBackendDateTime(sortedTime, true);
    const fallbackDepartedShort = formatBackendDateTime(sortedTime, false);

    const transitTime = new Date(now.getTime() + 12 * 60 * 60 * 1000); // + 12 hours
    const fallbackOnTransit = formatBackendDateTime(transitTime, true);
    const fallbackOnTransitShort = formatBackendDateTime(transitTime, false);

    const deliveryTime = new Date(now.getTime() + 24 * 60 * 60 * 1000); // + 24 hours
    const fallbackDelivered = formatBackendDateTime(deliveryTime, true);
    const fallbackDeliveredShort = formatBackendDateTime(deliveryTime, false);

    const finalInitiatedShort = initiatedDateShort || fallbackInitiatedShort;
    const finalDepartedShort = departedDateShort || fallbackDepartedShort;
    const finalOnTransitShort = onTransitDateShort || fallbackOnTransitShort;
    const finalDeliveredShort = deliveredDateShort || fallbackDeliveredShort;

    // 3. Formulate ETA directly matching the custom delivery date
    let etaValue = "Awaiting Processing";
    if (status === 'Delivered') {
        etaValue = `Delivered successfully (${finalDeliveredShort})`;
    } else if (status === 'Customs Exception') {
        etaValue = "Hold (Awaiting Customs)";
    } else if (status === 'In Transit') {
        etaValue = `Scheduled Delivery: ${finalDeliveredShort}`;
    } else {
        etaValue = `ETA: ${finalDeliveredShort}`;
    }

    const timesArray = [
        finalInitiatedShort,
        step >= 2 ? finalDepartedShort : "Pending Sorting",
        step >= 3 ? finalOnTransitShort : "Pending Dispatch",
        step >= 4 ? finalDeliveredShort : "Pending Delivery"
    ];

    // 4. Construct sequential timeline logs according to chosen custom dates
    const timeline = [];

    // Step 1: Initiated Log
    timeline.push({
        time: initiatedDate || fallbackInitiated,
        event: m1 || "Manifest Initiated & Picked Up",
        loc: shipper.split(',')[1]?.trim() || "Shipper Origin Facility Warehouse",
        icon: "fa-truck-ramp-box",
        desc: "Package collection completed. Waybill tags generated securely."
    });

    // Step 2: Sorted or Customs Log
    if (step >= 2) {
        if (status === 'Customs Exception') {
            timeline.unshift({
                time: departedDate || fallbackDeparted,
                event: m2 || "Customs Inspection Hold",
                loc: "Port Customs Checkpoint Area",
                icon: "fa-circle-exclamation",
                desc: "Random customs check initiated. Import duty declaration under inspection. Agent broker has been notified."
            });
        } else {
            timeline.unshift({
                time: departedDate || fallbackDeparted,
                event: m2 || "Freight Sorted & Consolidated",
                loc: "Carrier Dispatch Center",
                icon: "fa-warehouse",
                desc: "Cargo consolidated on linehaul truck loading ramps."
            });
        }
    }

    // Step 3: Transit Log
    if (step >= 3) {
        timeline.unshift({
            time: onTransitDate || fallbackOnTransit,
            event: m3 || "Departed facility node on route transit",
            loc: "Gateway Sorting Node",
            icon: "fa-truck-fast",
            desc: "Container manifest dispatched toward target delivery terminal."
        });
    }

    // Step 4: Delivered Log
    if (step >= 4) {
        timeline.unshift({
            time: deliveredDate || fallbackDelivered,
            event: m4 || "Cargo Delivered & Completed",
            loc: receiver.split(',')[0]?.trim() || "Destination Receiver Dock",
            icon: "fa-circle-check",
            desc: "Cargo offloaded. Checked out cleanly. Received and signed by local consignee."
        });
    }

    const newPackage = {
        waybill: `WB-${Math.floor(Math.random() * 800000) + 100000}-${generatedID}`,
        eta: etaValue,
        location: status === 'Delivered' ? (receiver.split(',')[0] || receiver) : (status === 'In Transit' ? "En Route Gateway Center" : "Sorting Hub Depot"),
        status: status,
        badgeClass: badgeClass,
        step: step,
        shipper: shipper,
        receiver: receiver,
        service: service,
        weight: weight || "15.0 kg",
        dimensions: dimensions || "40x40x40 cm",
        barcode: `||| ||| | || ${randomNumber} ||`,
        tempSensor: temp || "18.5°C",
        times: timesArray,
        timeline: timeline
    };

    // 5. Save to database
    await storage.set(generatedID, newPackage);

    res.status(201).json({ success: true, trackingID: generatedID, shipment: newPackage });
});

// Update Status of package
app.put('/api/shipments/:id/status', requireAuth, async (req, res) => {
    const cargoId = req.params.id.trim().toUpperCase();
    const { status, location, details } = req.body;

    const cargo = await storage.get(cargoId);

    if (!cargo) {
        return res.status(404).json({ error: "Target package not found." });
    }

    // Modify payload
    cargo.status = status;
    cargo.location = location || cargo.location;
    
    let badgeClass = "bg-sky-500/10 text-sky-500 border border-sky-500/30";
    let step = 1;

    if (status === 'In Transit') {
        badgeClass = "bg-amber-500/10 text-amber-500 border border-amber-500/30";
        step = 3;
        cargo.eta = "In Transit (Scheduled)";
    } else if (status === 'Delivered') {
        badgeClass = "bg-emerald-500/10 text-[#22C55E] border border-emerald-500/30";
        step = 4;
        cargo.eta = "Delivered successfully";
    } else if (status === 'Customs Exception') {
        badgeClass = "bg-rose-500/10 text-rose-500 border border-rose-500/30";
        step = 2;
        cargo.eta = "Hold (Awaiting Customs)";
    } else {
        badgeClass = "bg-sky-500/10 text-sky-500 border border-sky-500/30";
        step = 1;
        cargo.eta = "Processing in Depot";
    }

    cargo.badgeClass = badgeClass;
    cargo.step = step;

    // Append update event to timeline logs
    const now = new Date();
    const formattedTime = now.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' }) + " - " + now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    const formattedTimeShort = now.toLocaleDateString('en-US', { month: 'short', day: '2-digit' }) + ", " + now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    
    // Choose icon based on status
    let eventIcon = 'fa-clock';
    if (status === 'Delivered') eventIcon = 'fa-circle-check';
    else if (status === 'In Transit') eventIcon = 'fa-truck-fast';
    else if (status === 'Customs Exception') eventIcon = 'fa-circle-exclamation';
    else if (status === 'Sorting Depot') eventIcon = 'fa-warehouse';

    // Update steps chronologically if needed
    if (step >= 1) cargo.times[0] = cargo.times[0] === "Pending Sorting" ? formattedTimeShort : cargo.times[0];
    if (step >= 2) cargo.times[1] = cargo.times[1] === "Pending Sorting" ? formattedTimeShort : cargo.times[1];
    if (step >= 3) cargo.times[2] = cargo.times[2] === "Pending Dispatch" ? formattedTimeShort : cargo.times[2];
    if (step >= 4) cargo.times[3] = cargo.times[3] === "Pending Delivery" ? formattedTimeShort : cargo.times[3];

    cargo.timeline.unshift({
        time: formattedTime,
        event: `Status updated to: ${status}`,
        loc: cargo.location,
        icon: eventIcon,
        desc: details || `Package status altered to ${status} at ${cargo.location}. Operational logs updated.`
    });

    await storage.set(cargoId, cargo);
    res.status(200).json({ success: true, shipment: cargo });
});

// Purge Shipment from database
app.delete('/api/shipments/:id', requireAuth, async (req, res) => {
    const cargoId = req.params.id.trim().toUpperCase();

    if (await storage.del(cargoId)) {
        res.status(200).json({ success: true, message: `Waybill ${cargoId} permanently removed.` });
    } else {
        res.status(404).json({ error: "Package record not found." });
    }
});

// ==========================================
// EMBEDDED STAFF PORTAL FRONTEND PAGE
// ==========================================

app.get('/admin', (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Control Panel Portal | Shipment Logistics</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <script>
            tailwind.config = {
                theme: {
                    extend: {
                        colors: {
                            primary: '#FF3E41',
                            secondary: '#0F172A',
                            accent: '#06B6D4'
                        }
                    }
                }
            }
        </script>
        <style>
            .custom-toast {
                animation: slideIn 0.3s ease-out forwards;
            }
            @keyframes slideIn {
                from { transform: translateY(-1rem); opacity: 0; }
                to { transform: translateY(0); opacity: 1; }
            }
        </style>
    </head>
    <body class="bg-[#FAFAFA] text-slate-800 font-sans antialiased">
        <!-- NOTIFICATION CONTAINER (Custom Toast system avoiding alerts) -->
        <div id="toast-container" class="fixed top-5 right-5 z-50 flex flex-col gap-3 max-w-sm w-full pointer-events-none"></div>

        <!-- CUSTOM CONFIRM MODAL CONTAINER -->
        <div id="custom-confirm" class="hidden fixed inset-0 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div class="bg-white rounded-2xl max-w-sm w-full p-6 shadow-2xl border border-slate-100 transform scale-95 transition-transform duration-200">
                <div class="text-center">
                    <span class="w-12 h-12 bg-rose-50 text-rose-500 flex items-center justify-center text-xl mx-auto rounded-full mb-3">
                        <i class="fa-solid fa-triangle-exclamation"></i>
                    </span>
                    <h3 class="font-bold text-slate-900 text-lg" id="confirm-title">Are you sure?</h3>
                    <p class="text-slate-500 text-xs mt-2 leading-relaxed" id="confirm-message">This action is permanent and will completely clear the tracking index from our servers.</p>
                </div>
                <div class="mt-6 flex gap-3">
                    <button id="confirm-cancel-btn" class="flex-1 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold rounded-xl text-xs uppercase tracking-wider transition-colors">
                        Cancel
                    </button>
                    <button id="confirm-accept-btn" class="flex-1 py-2.5 bg-primary hover:bg-rose-600 text-white font-bold rounded-xl text-xs uppercase tracking-wider transition-colors">
                        Delete
                    </button>
                </div>
            </div>
        </div>

        <!-- LOGGED OUT INTERFACE -->
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
                        <input type="text" id="username" required placeholder="admin" class="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm text-white focus:outline-none focus:border-primary">
                    </div>
                    <div>
                        <label class="block text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Passkey Code</label>
                        <input type="password" id="password" required placeholder="password" class="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm text-white focus:outline-none focus:border-primary">
                    </div>
                    <div id="loginError" class="hidden text-xs text-rose-500 font-bold bg-rose-500/10 p-2.5 rounded border border-rose-500/20">
                        Invalid password or username index.
                    </div>
                    <button type="submit" class="w-full py-3 bg-primary hover:bg-rose-600 text-white font-bold rounded-lg text-xs uppercase tracking-wider transition-colors">
                        Authenticate Terminal
                    </button>
                </form>
            </div>
        </div>

        <!-- LOGGED IN ADMINISTRATIVE DASHBOARD -->
        <div id="dashboard-screen" class="hidden min-h-screen flex flex-col">
            <!-- Header bar -->
            <header class="bg-slate-950 text-white py-4 px-6 border-b border-slate-850 flex justify-between items-center">
                <div class="flex items-center gap-3">
                    <div class="bg-primary text-white p-2.5 rounded-xl text-lg">
                        <i class="fa-solid fa-satellite-dish animate-pulse"></i>
                    </div>
                    <div>
                        <h1 class="font-bold text-lg">CargoTracker Central</h1>
                        <p class="text-[9px] text-slate-400 tracking-widest uppercase font-semibold">Live System Terminal</p>
                    </div>
                </div>
                <button onclick="logout()" class="px-4 py-2 bg-slate-900 hover:bg-slate-850 text-xs font-bold rounded border border-slate-800 uppercase tracking-wider transition">
                    Logout
                </button>
            </header>

            <!-- Main Panels -->
            <main class="flex-grow p-6 max-w-7xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
                
                <!-- Left panel: Package Creator Form -->
                <div class="lg:col-span-5 bg-white border border-slate-200 p-6 sm:p-8 rounded-2xl shadow-sm">
                    <h3 class="font-bold text-lg text-slate-900 mb-6 border-b border-slate-100 pb-3">
                        <i class="fa-solid fa-boxes-packing text-primary mr-1"></i> New Cargo Entry
                    </h3>

                    <form id="createForm" class="space-y-4 text-xs">
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="block font-bold text-slate-500 uppercase tracking-wider mb-1">Shipper Origin</label>
                                <input type="text" id="shipper" required placeholder="Lux Logistics, Paris" class="w-full bg-slate-50 border border-slate-200 rounded p-2.5 outline-none focus:border-primary">
                            </div>
                            <div>
                                <label class="block font-bold text-slate-500 uppercase tracking-wider mb-1">Consignee Destination</label>
                                <input type="text" id="receiver" required placeholder="TechCorp, New York" class="w-full bg-slate-50 border border-slate-200 rounded p-2.5 outline-none focus:border-primary">
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
                                <input type="text" id="weight" placeholder="12.5 kg" class="w-full bg-slate-50 border border-slate-200 rounded p-2 outline-none">
                            </div>
                            <div>
                                <label class="block font-bold text-slate-500 uppercase tracking-wider mb-1">Volume</label>
                                <input type="text" id="dimensions" placeholder="40x40x40 cm" class="w-full bg-slate-50 border border-slate-200 rounded p-2 outline-none">
                            </div>
                            <div>
                                <label class="block font-bold text-slate-500 uppercase tracking-wider mb-1">Temp</label>
                                <input type="text" id="temp" placeholder="18.5°C" class="w-full bg-slate-50 border border-slate-200 rounded p-2 outline-none">
                            </div>
                        </div>

                        <!-- CUSTOM TIMESTAMPS FOR THE NEW CARGO ENTRY -->
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

                <!-- Right panel: Packages Table List -->
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
                            <tbody id="shipment-rows" class="divide-y divide-slate-100">
                                <!-- Populated by JS -->
                            </tbody>
                        </table>
                    </div>
                </div>

            </main>
        </div>

        <script>
            const API_BASE = window.location.origin;

            function authHeaders(json) {
                const h = { 'Authorization': 'Bearer ' + sessionStorage.getItem("staffToken") };
                if (json) h['Content-Type'] = 'application/json';
                return h;
            }

            // Custom UI Notification Banner (Toast)
            function showNotification(msg, type = 'success') {
                const container = document.getElementById('toast-container');
                const toast = document.createElement('div');
                toast.className = \`custom-toast pointer-events-auto flex items-center gap-3 p-4 rounded-xl shadow-lg border text-xs font-semibold bg-white transition-all \${
                    type === 'success' 
                    ? 'border-emerald-500/20 text-emerald-800 shadow-emerald-500/5' 
                    : 'border-rose-500/20 text-rose-800 shadow-rose-500/5'
                }\`;

                const icon = type === 'success' ? 'fa-circle-check text-emerald-500' : 'fa-circle-exclamation text-rose-500';
                
                toast.innerHTML = \`
                    <i class="fa-solid \${icon} text-lg"></i>
                    <span class="flex-grow">\${msg}</span>
                \`;

                container.appendChild(toast);

                // Auto destroy after 3.5 seconds
                setTimeout(() => {
                    toast.classList.add('opacity-0', 'scale-95');
                    setTimeout(() => { toast.remove(); }, 300);
                }, 3500);
            }

            // Custom non-blocking Confirm Dialog
            function triggerConfirm(title, message, onAccept) {
                const modal = document.getElementById('custom-confirm');
                const titleEl = document.getElementById('confirm-title');
                const msgEl = document.getElementById('confirm-message');
                const cancelBtn = document.getElementById('confirm-cancel-btn');
                const acceptBtn = document.getElementById('confirm-accept-btn');

                titleEl.textContent = title;
                msgEl.textContent = message;
                modal.classList.remove('hidden');

                const cleanUp = () => {
                    modal.classList.add('hidden');
                    cancelBtn.onclick = null;
                    acceptBtn.onclick = null;
                };

                cancelBtn.onclick = () => {
                    cleanUp();
                };

                acceptBtn.onclick = () => {
                    onAccept();
                    cleanUp();
                };
            }

            // Custom Formatter to convert input date-time values into the tracking UI style
            function formatDateTime(val, longFormat = true) {
                if (!val) return null;
                const d = new Date(val);
                if (isNaN(d.getTime())) return null;
                
                const month = d.toLocaleDateString('en-US', { month: 'short' });
                const day = d.toLocaleDateString('en-US', { day: '2-digit' });
                const year = d.getFullYear();
                
                let hours = d.getHours();
                const minutes = String(d.getMinutes()).padStart(2, '0');
                const ampm = hours >= 12 ? 'PM' : 'AM';
                hours = hours % 12;
                hours = hours ? hours : 12; 
                const finalTimeStr = \`\${String(hours).padStart(2, '0')}:\${minutes} \${ampm}\`;
                
                if (longFormat) {
                    return \`\${month} \${day}, \${year} - \${finalTimeStr}\`;
                } else {
                    return \`\${month} \${day}, \${finalTimeStr}\`;
                }
            }

            // Check if user is already authenticated
            if (sessionStorage.getItem("staffToken")) {
                showDashboard();
            }

            // Login Logic
            document.getElementById('loginForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const errBox = document.getElementById('loginError');

                try {
                    const res = await fetch(API_BASE + '/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        sessionStorage.setItem("staffToken", data.token);
                        showDashboard();
                    } else {
                        errBox.classList.remove('hidden');
                    }
                } catch (err) {
                    showNotification("Unable to connect to Node backend database servers.", "error");
                }
            });

            function showDashboard() {
                document.getElementById('login-screen').classList.add('hidden');
                document.getElementById('dashboard-screen').classList.remove('hidden');
                fetchShipments();
            }

            function logout() {
                sessionStorage.removeItem("staffToken");
                location.reload();
            }

            // Fetch list
            async function fetchShipments() {
                const list = document.getElementById('shipment-rows');
                list.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-slate-400">Loading database records...</td></tr>';
                
                try {
                    const res = await fetch(API_BASE + '/api/shipments', { headers: authHeaders() });
                    if (res.status === 401) { logout(); return; }
                    const data = await res.json();
                    const keys = Object.keys(data);
                    
                    document.getElementById('packageCount').innerText = keys.length + " Items";
                    list.innerHTML = '';

                    keys.forEach(key => {
                        const pack = data[key];
                        const tr = document.createElement('tr');
                        tr.className = "hover:bg-slate-50 transition-colors border-b border-slate-100";
                        tr.innerHTML = \`
                            <td class="py-4 px-2 font-mono font-bold text-primary">\${key}</td>
                            <td class="py-4 px-2">
                                <span class="block font-semibold text-slate-800 text-xs truncate max-w-[200px]">\${pack.shipper}</span>
                                <span class="block text-slate-400 text-[10px] truncate max-w-[200px]">\${pack.receiver}</span>
                            </td>
                            <td class="py-4 px-2">
                                <span class="px-2 py-0.5 rounded text-[10px] uppercase font-extrabold text-slate-700 bg-slate-100 border border-slate-200">
                                    \${pack.status}
                                </span>
                            </td>
                            <td class="py-4 px-2 text-right">
                                <div class="inline-flex items-center gap-2">
                                    <!-- Dynamic Select Dropdown modifying live package states -->
                                    <select onchange="quickUpdateStatus('\${key}', this.value)" class="bg-slate-50 border border-slate-200 hover:border-slate-300 rounded px-2.5 py-1.5 text-[11px] font-semibold text-slate-700 outline-none focus:border-primary transition cursor-pointer">
                                        <option value="Sorting Depot" \${pack.status === 'Sorting Depot' ? 'selected' : ''}>Sorting Depot</option>
                                        <option value="Customs Exception" \${pack.status === 'Customs Exception' ? 'selected' : ''}>Customs Exception</option>
                                        <option value="In Transit" \${pack.status === 'In Transit' ? 'selected' : ''}>In Transit</option>
                                        <option value="Delivered" \${pack.status === 'Delivered' ? 'selected' : ''}>Delivered</option>
                                    </select>
                                    
                                    <button onclick="deleteShipment('\${key}')" class="h-8 w-8 flex items-center justify-center bg-rose-500 hover:bg-rose-600 text-white rounded-lg transition" title="Purge Record">
                                        <i class="fa-solid fa-trash text-[11px]"></i>
                                    </button>
                                </div>
                            </td>
                        \`;
                        list.appendChild(tr);
                    });
                } catch (err) {
                    list.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-red-500">Database communication failed.</td></tr>';
                }
            }

            // Create submission
            document.getElementById('createForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const initiatedRaw = document.getElementById('initiatedDate').value;
                const departedRaw = document.getElementById('departedDate').value;
                const onTransitRaw = document.getElementById('onTransitDate').value;
                const deliveredRaw = document.getElementById('deliveredDate').value;

                const payload = {
                    shipper: document.getElementById('shipper').value,
                    receiver: document.getElementById('receiver').value,
                    service: document.getElementById('service').value,
                    status: document.getElementById('status').value,
                    weight: document.getElementById('weight').value,
                    dimensions: document.getElementById('dimensions').value,
                    temp: document.getElementById('temp').value,
                    // Format dates into long and short strings to match default schema layouts
                    initiatedDate: formatDateTime(initiatedRaw, true),
                    initiatedDateShort: formatDateTime(initiatedRaw, false),
                    departedDate: formatDateTime(departedRaw, true),
                    departedDateShort: formatDateTime(departedRaw, false),
                    onTransitDate: formatDateTime(onTransitRaw, true),
                    onTransitDateShort: formatDateTime(onTransitRaw, false),
                    deliveredDate: formatDateTime(deliveredRaw, true),
                    deliveredDateShort: formatDateTime(deliveredRaw, false)
                };

                try {
                    const res = await fetch(API_BASE + '/api/shipments/create', {
                        method: 'POST',
                        headers: authHeaders(true),
                        body: JSON.stringify(payload)
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        showNotification("Waybill generated successfully! ID: " + data.trackingID, "success");
                        document.getElementById('createForm').reset();
                        fetchShipments();
                    } else {
                        showNotification(data.error || "Failed to create waybill.", "error");
                    }
                } catch (err) {
                    showNotification("Failed to write new waybill to database.", "error");
                }
            });

            // Quick Status transition with smart logistics description and physical hub matching
            async function quickUpdateStatus(id, newStatus) {
                let location = "Local Delivery Terminal";
                let details = "Status manually updated through Staff Operations Console.";

                if (newStatus === 'Sorting Depot') {
                    location = "Hub Carrier / Sorting Yard Depot";
                    details = "Package registered and processed through sorting lines. Prepped for linehaul vehicle consolidation.";
                } else if (newStatus === 'Customs Exception') {
                    location = "Port Customs Checkpoint Area";
                    details = "Held temporarily for standard import clearance procedures and paperwork checking.";
                } else if (newStatus === 'In Transit') {
                    location = "En Route Gateway Hub";
                    details = "Cleared processing facilities and is actively forwarding across the transportation network node.";
                } else if (newStatus === 'Delivered') {
                    location = "Destination Receiver Dock";
                    details = "Shipment completed. Handover checked, completed, and signed for successfully by local consignee.";
                }

                try {
                    const res = await fetch(API_BASE + '/api/shipments/' + id + '/status', {
                        method: 'PUT',
                        headers: authHeaders(true),
                        body: JSON.stringify({ 
                            status: newStatus, 
                            location: location, 
                            details: details 
                        })
                    });
                    if (res.ok) {
                        showNotification(\`Shipment \${id} updated to "\${newStatus}"\`, "success");
                        fetchShipments();
                    } else {
                        showNotification("Unable to save status updates. Try again.", "error");
                    }
                } catch (err) {
                    showNotification("Error communicating with servers.", "error");
                }
            }

            // Purge Shipment
            function deleteShipment(id) {
                triggerConfirm(
                    "Purge Waybill?", 
                    "Are you absolutely sure you want to permanently clear shipment " + id + " from tracking databases?", 
                    async () => {
                        try {
                            const res = await fetch(API_BASE + '/api/shipments/' + id, { method: 'DELETE', headers: authHeaders() });
                            if (res.ok) {
                                showNotification("Waybill cleared successfully.", "success");
                                fetchShipments();
                            } else {
                                showNotification("Failed to purge requested package.", "error");
                            }
                        } catch (err) {
                            showNotification("System write permissions error.", "error");
                        }
                    }
                );
            }
        </script>
    </body>
    </html>
    `);
});

// Local: start a listener. Vercel: just export the app.
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`CargoTracker running on http://localhost:${PORT}  (storage: ${storage.name})`);
        console.log(`Admin console: http://localhost:${PORT}/admin`);
    });
}

module.exports = app;
