const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());
const webDir = fs.existsSync(path.join(__dirname, '..', 'web'))
    ? path.join(__dirname, '..', 'web')
    : path.join(__dirname, 'web');
app.use(express.static(webDir));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// ============================================================
// KEY SYSTEM
// ============================================================
const KEYS_FILE = path.join(__dirname, 'keys.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASS || 'remoteandroid2026';

function loadKeys() {
    try {
        if (fs.existsSync(KEYS_FILE)) {
            return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
        }
    } catch (e) {}
    return {};
}

function saveKeys(keys) {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

let keys = loadKeys();

function generateKey(prefix, duration, hwid) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let keyBody = '';
    for (let i = 0; i < 16; i++) {
        if (i > 0 && i % 4 === 0) keyBody += '-';
        keyBody += chars[crypto.randomInt(chars.length)];
    }
    const key = prefix + '-' + keyBody;

    const durations = {
        '1h': 3600000,
        '6h': 21600000,
        '12h': 43200000,
        '1d': 86400000,
        '3d': 259200000,
        '7d': 604800000,
        '15d': 1296000000,
        '30d': 2592000000,
        'lifetime': 0
    };

    const durationMs = durations[duration] || 86400000;

    keys[key] = {
        key,
        prefix,
        duration,
        durationMs,
        hwid: hwid || null,
        createdAt: Date.now(),
        activatedAt: null,
        expiresAt: null,
        usedBy: null,
        status: 'unused' // unused, active, expired, banned
    };

    saveKeys(keys);
    return keys[key];
}

function validateKey(key, hwid) {
    const entry = keys[key];
    if (!entry) return { valid: false, error: 'Key não encontrada' };

    if (entry.status === 'banned') return { valid: false, error: 'Key banida' };

    if (entry.status === 'expired') return { valid: false, error: 'Key expirada' };

    // First use — activate
    if (entry.status === 'unused') {
        entry.status = 'active';
        entry.activatedAt = Date.now();
        entry.usedBy = hwid;
        if (entry.durationMs > 0) {
            entry.expiresAt = Date.now() + entry.durationMs;
        } else {
            entry.expiresAt = null; // lifetime
        }
        entry.hwid = hwid;
        saveKeys(keys);
        return {
            valid: true,
            key: entry.key,
            expiresAt: entry.expiresAt,
            duration: entry.duration,
            remaining: entry.expiresAt ? entry.expiresAt - Date.now() : null
        };
    }

    // Already active — check HWID lock
    if (entry.hwid && entry.hwid !== hwid) {
        return { valid: false, error: 'Key vinculada a outro dispositivo' };
    }

    // Check expiration
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
        entry.status = 'expired';
        saveKeys(keys);
        return { valid: false, error: 'Key expirada' };
    }

    return {
        valid: true,
        key: entry.key,
        expiresAt: entry.expiresAt,
        duration: entry.duration,
        remaining: entry.expiresAt ? entry.expiresAt - Date.now() : null
    };
}

function formatRemaining(ms) {
    if (!ms) return 'Lifetime';
    const h = Math.floor(ms / 3600000);
    const m = Math.floor((ms % 3600000) / 60000);
    if (h >= 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
    return `${h}h ${m}m`;
}

// ============================================================
// ADMIN API — Key Generator
// ============================================================

function adminAuth(req, res, next) {
    const pass = req.headers['x-admin-password'] || req.query.password;
    if (pass !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: 'Senha admin inválida' });
    }
    next();
}

app.post('/api/admin/generate', adminAuth, (req, res) => {
    const { prefix, duration, count, hwid } = req.body;
    if (!prefix || !duration) {
        return res.status(400).json({ error: 'Prefix e duration obrigatórios' });
    }

    const qty = Math.min(count || 1, 100);
    const generated = [];
    for (let i = 0; i < qty; i++) {
        generated.push(generateKey(prefix, duration, hwid || null));
    }

    console.log(`[ADMIN] Generated ${qty} keys: prefix=${prefix} duration=${duration}`);
    res.json({ keys: generated });
});

app.get('/api/admin/keys', adminAuth, (req, res) => {
    const filter = req.query.status;
    let result = Object.values(keys);
    if (filter) {
        result = result.filter(k => k.status === filter);
    }
    // Check and update expired keys
    const now = Date.now();
    result.forEach(k => {
        if (k.status === 'active' && k.expiresAt && now > k.expiresAt) {
            k.status = 'expired';
            keys[k.key].status = 'expired';
        }
    });
    saveKeys(keys);

    res.json({
        total: result.length,
        unused: result.filter(k => k.status === 'unused').length,
        active: result.filter(k => k.status === 'active').length,
        expired: result.filter(k => k.status === 'expired').length,
        banned: result.filter(k => k.status === 'banned').length,
        keys: result.sort((a, b) => b.createdAt - a.createdAt)
    });
});

app.post('/api/admin/ban', adminAuth, (req, res) => {
    const { key } = req.body;
    if (keys[key]) {
        keys[key].status = 'banned';
        saveKeys(keys);
        res.json({ ok: true });
    } else {
        res.status(404).json({ error: 'Key não encontrada' });
    }
});

app.post('/api/admin/unban', adminAuth, (req, res) => {
    const { key } = req.body;
    if (keys[key]) {
        keys[key].status = keys[key].activatedAt ? 'active' : 'unused';
        saveKeys(keys);
        res.json({ ok: true });
    } else {
        res.status(404).json({ error: 'Key não encontrada' });
    }
});

app.post('/api/admin/delete', adminAuth, (req, res) => {
    const { key } = req.body;
    if (keys[key]) {
        delete keys[key];
        saveKeys(keys);
        res.json({ ok: true });
    } else {
        res.status(404).json({ error: 'Key não encontrada' });
    }
});

app.post('/api/admin/reset-hwid', adminAuth, (req, res) => {
    const { key } = req.body;
    if (keys[key]) {
        keys[key].hwid = null;
        keys[key].usedBy = null;
        saveKeys(keys);
        res.json({ ok: true });
    } else {
        res.status(404).json({ error: 'Key não encontrada' });
    }
});

// ============================================================
// PUBLIC API — Key Validation
// ============================================================

app.post('/api/validate', (req, res) => {
    const { key, hwid } = req.body;
    if (!key) return res.status(400).json({ error: 'Key obrigatória' });
    const result = validateKey(key, hwid || 'web-' + uuidv4().slice(0, 8));
    res.json(result);
});

// ============================================================
// WEBSOCKET — Device & Panel relay
// ============================================================

const devices = new Map();
const panels = new Map();
const pairings = new Map();
const authenticatedPanels = new Set();

function broadcast(deviceId, msg) {
    const json = JSON.stringify(msg);
    for (const [id, panel] of panels) {
        if (panel.deviceId === deviceId && panel.ws.readyState === 1) {
            panel.ws.send(json);
        }
    }
}

function sendToDevice(deviceId, msg) {
    const dev = devices.get(deviceId);
    if (dev && dev.ws.readyState === 1) {
        dev.ws.send(JSON.stringify(msg));
        return true;
    }
    return false;
}

wss.on('connection', (ws, req) => {
    const connId = uuidv4();
    let role = null;
    let deviceId = null;
    let authenticated = false;

    ws.on('message', (raw) => {
        let msg;
        try { msg = JSON.parse(raw); } catch { return; }

        switch (msg.type) {
            case 'auth_key': {
                const hwid = msg.hwid || 'ws-' + connId.slice(0, 8);
                const result = validateKey(msg.key, hwid);
                ws.send(JSON.stringify({ type: 'auth_result', ...result }));
                if (result.valid) {
                    authenticated = true;
                    authenticatedPanels.add(connId);
                }
                break;
            }

            case 'register_device': {
                role = 'device';
                deviceId = msg.hwid || uuidv4();
                const pairCode = String(100000 + Math.floor(Math.random() * 900000));
                devices.set(deviceId, {
                    ws, connId, deviceId, pairCode,
                    model: msg.model || 'Unknown',
                    game: msg.game || 'Free Fire',
                    status: 'online',
                    lastSeen: Date.now()
                });
                pairings.set(pairCode, deviceId);
                ws.send(JSON.stringify({
                    type: 'registered',
                    deviceId,
                    pairCode,
                    serverTime: Date.now()
                }));
                console.log(`[DEVICE] ${deviceId} registered, pair: ${pairCode}`);
                break;
            }

            case 'register_panel': {
                if (!authenticated) {
                    ws.send(JSON.stringify({ type: 'auth_required' }));
                    break;
                }
                role = 'panel';
                panels.set(connId, { ws, connId, deviceId: null });
                ws.send(JSON.stringify({ type: 'panel_ready', connId }));
                break;
            }

            case 'pair': {
                if (!authenticated) {
                    ws.send(JSON.stringify({ type: 'auth_required' }));
                    break;
                }
                const targetDevice = pairings.get(msg.code);
                if (!targetDevice) {
                    ws.send(JSON.stringify({ type: 'pair_error', error: 'Código inválido' }));
                    break;
                }
                const panel = panels.get(connId);
                if (panel) {
                    panel.deviceId = targetDevice;
                    deviceId = targetDevice;
                    const dev = devices.get(targetDevice);
                    ws.send(JSON.stringify({
                        type: 'paired',
                        deviceId: targetDevice,
                        model: dev?.model,
                        game: dev?.game,
                        status: dev?.status
                    }));
                    sendToDevice(targetDevice, { type: 'panel_connected' });
                    console.log(`[PAIR] Panel ${connId} -> Device ${targetDevice}`);
                }
                break;
            }

            case 'apply_controls': {
                if (role === 'panel' && deviceId && authenticated) {
                    const sent = sendToDevice(deviceId, {
                        type: 'controls_update',
                        controls: msg.controls,
                        timestamp: Date.now()
                    });
                    ws.send(JSON.stringify({
                        type: 'controls_ack',
                        applied: sent,
                        timestamp: Date.now()
                    }));
                }
                break;
            }

            case 'device_status': {
                if (role === 'device' && deviceId) {
                    const dev = devices.get(deviceId);
                    if (dev) {
                        dev.status = msg.status;
                        dev.lastSeen = Date.now();
                        dev.gameState = msg.gameState;
                    }
                    broadcast(deviceId, {
                        type: 'device_status',
                        status: msg.status,
                        gameState: msg.gameState,
                        ping: msg.ping,
                        fps: msg.fps
                    });
                }
                break;
            }

            case 'inject_command': {
                if (role === 'panel' && deviceId && authenticated) {
                    sendToDevice(deviceId, {
                        type: 'inject',
                        action: msg.action,
                        payload: msg.payload
                    });
                }
                break;
            }

            case 'heartbeat': {
                ws.send(JSON.stringify({ type: 'heartbeat_ack', t: Date.now() }));
                if (role === 'device' && deviceId) {
                    const dev = devices.get(deviceId);
                    if (dev) dev.lastSeen = Date.now();
                }
                break;
            }
        }
    });

    ws.on('close', () => {
        authenticatedPanels.delete(connId);
        if (role === 'device' && deviceId) {
            const dev = devices.get(deviceId);
            if (dev) {
                pairings.delete(dev.pairCode);
                devices.delete(deviceId);
            }
            broadcast(deviceId, { type: 'device_disconnected' });
            console.log(`[DEVICE] ${deviceId} disconnected`);
        }
        if (role === 'panel') {
            panels.delete(connId);
            if (deviceId) {
                sendToDevice(deviceId, { type: 'panel_disconnected' });
            }
        }
    });
});

app.get('/api/status', (req, res) => {
    res.json({
        devices: devices.size,
        panels: panels.size,
        uptime: process.uptime()
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`[REMOTE ANDROID] Server running on port ${PORT}`);
    console.log(`[REMOTE ANDROID] Web panel: http://localhost:${PORT}`);
    console.log(`[REMOTE ANDROID] Admin panel: http://localhost:${PORT}/admin.html`);
    console.log(`[REMOTE ANDROID] Admin password: ${ADMIN_PASSWORD}`);
});
