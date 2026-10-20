'use strict';
/*
 * Love Alarm — servidor de emparejamiento y alarma privada.
 *
 * Sin dependencias externas: solo la librería estándar de Node (>=18).
 * Dos cuentas por pareja, dispositivos autorizados, emparejamiento por
 * invitación con doble confirmación, alarma push por "long-poll" y
 * confirmación de entrega/lectura.
 *
 * Ejecutar:  node server.js
 * Variables: PORT (8787), DATA_FILE (./data.json), HOST (0.0.0.0)
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT || '8787', 10);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');

// Almacenamiento externo opcional (Upstash Redis REST). Si está configurado,
// los datos sobreviven a reinicios y despliegues de Render.
const UPSTASH_URL = (process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/+$/, '');
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const USE_REDIS = !!(UPSTASH_URL && UPSTASH_TOKEN);
const DB_KEY = process.env.DB_KEY || 'love_alarm_db';

const INVITE_TTL_MS = 10 * 60 * 1000;   // la invitación caduca en 10 min
const ONLINE_MS = 90 * 1000;            // "en línea" si latió en el último 1:30
const POLL_MAX_MS = 30 * 1000;          // duración máxima de un long-poll
const ALARM_COOLDOWN_MS = 4 * 1000;     // anti-spam entre alarmas
const MAX_EVENTS = 800;
const SEND_COOLDOWN = {};

// ---------------------------------------------------------------------------
// Estado persistente
// ---------------------------------------------------------------------------

let db = {
  seq: 0,
  users: {},       // id -> { id, username, displayName, salt, hash, createdAt }
  tokens: {},      // token -> { userId, deviceId, createdAt, lastSeen }
  devices: {},     // id -> { id, userId, name, platform, createdAt, lastSeen }
  couples: {},     // id -> { id, members:[a,b], since, createdAt }
  userCouple: {},  // userId -> coupleId
  invites: {},     // code -> { code, fromId, createdAt, expiresAt, used }
  pending: {},     // id -> { id, fromId, toId, deviceId, status, createdAt }
  events: [],      // { id, coupleId, fromId, type, text, signature, ts, delivered, seen }
  shares: [],      // { shareType, fromId, coupleId, enabled, value, updatedAt }
};

async function upstash(command) {
  const res = await fetch(UPSTASH_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${UPSTASH_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(command),
  });
  if (!res.ok) throw new Error(`Upstash HTTP ${res.status}`);
  return res.json();
}

async function load() {
  if (USE_REDIS) {
    try {
      const r = await upstash(['GET', DB_KEY]);
      if (r && r.result) {
        db = Object.assign(db, JSON.parse(r.result));
        console.log('[love-alarm] datos cargados desde Upstash');
      } else {
        console.log('[love-alarm] Upstash vacío: base nueva');
      }
    } catch (e) {
      console.error('[love-alarm] no se pudo leer Upstash:', e.message);
    }
    return;
  }

  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      db = Object.assign(db, raw);
    }
  } catch (e) {
    console.error('[love-alarm] no se pudo leer data.json:', e.message);
  }
}

let saveTimer = null;
function save() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;

    if (USE_REDIS) {
      upstash(['SET', DB_KEY, JSON.stringify(db)]).catch((e) =>
        console.error('[love-alarm] no se pudo guardar en Upstash:', e.message)
      );
      return;
    }

    try {
      const tmp = DATA_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(db));
      fs.renameSync(tmp, DATA_FILE);
    } catch (e) {
      console.error('[love-alarm] no se pudo guardar data.json:', e.message);
    }
  }, 250);
}

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

const uid = () => crypto.randomBytes(12).toString('hex');
const token = () => crypto.randomBytes(32).toString('hex');
const now = () => Date.now();

function hashPassword(password, salt) {
  const s = salt || crypto.randomBytes(16).toString('hex');
  const h = crypto.scryptSync(String(password), s, 64).toString('hex');
  return { salt: s, hash: h };
}

function verifyPassword(password, salt, hash) {
  const candidate = crypto.scryptSync(String(password), salt, 64);
  const expected = Buffer.from(hash, 'hex');
  if (candidate.length !== expected.length) return false;
  return crypto.timingSafeEqual(candidate, expected);
}

function newCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function publicUser(u) {
  return u ? { id: u.id, username: u.username, displayName: u.displayName } : null;
}

function online(lastSeen) {
  return !!lastSeen && now() - lastSeen < ONLINE_MS;
}

function deviceView(d, currentDeviceId) {
  return {
    id: d.id,
    userId: d.userId,
    name: d.name,
    platform: d.platform || 'android',
    createdAt: d.createdAt,
    lastSeen: d.lastSeen,
    online: online(d.lastSeen),
    current: d.id === currentDeviceId,
  };
}

function coupleView(coupleId, forUserId) {
  if (!coupleId) return null;
  const c = db.couples[coupleId];
  if (!c) return null;
  const partnerId = c.members.find((m) => m !== forUserId);
  const p = partnerId ? db.users[partnerId] : null;
  const pTokenSeen = partnerId
    ? Math.max(0, ...Object.values(db.tokens).filter((t) => t.userId === partnerId).map((t) => t.lastSeen || 0))
    : 0;
  return {
    id: c.id,
    since: c.since,
    partner: p
      ? {
          id: p.id,
          username: p.username,
          displayName: p.displayName,
          online: online(pTokenSeen),
          lastSeen: pTokenSeen || null,
        }
      : null,
  };
}

function addEvent(coupleId, fromId, type, text, signature) {
  const ev = {
    id: ++db.seq,
    coupleId,
    fromId,
    type,
    text: text || null,
    signature: signature || null,
    ts: now(),
    delivered: false,
    seen: false,
  };
  db.events.push(ev);
  if (db.events.length > MAX_EVENTS) db.events = db.events.slice(-MAX_EVENTS);
  save();
  return ev;
}

// ---------------------------------------------------------------------------
// Long-poll: esperas activas por pareja
// ---------------------------------------------------------------------------

const waiters = new Map(); // coupleId -> Set<{ res, userId, since, timer }>

function waitersFor(coupleId) {
  if (!waiters.has(coupleId)) waiters.set(coupleId, new Set());
  return waiters.get(coupleId);
}

function wakeCouple(coupleId) {
  const set = waitersFor(coupleId);
  for (const w of Array.from(set)) {
    try {
      respondPoll(w);
    } catch (_) {
      /* la conexión ya no sirve; se limpia en close */
    }
  }
}

function cleanupWaiter(w) {
  const set = waiters.get(w.coupleId);
  if (set) {
    set.delete(w);
    if (set.size === 0) waiters.delete(w.coupleId);
  }
  if (w.timer) clearTimeout(w.timer);
}

function eventsSince(coupleId, since, forUserId) {
  return db.events.filter(
    (e) => e.coupleId === coupleId && e.id > since && e.fromId !== forUserId
  );
}

function statusesFor(coupleId, forUserId) {
  return db.events
    .filter((e) => e.coupleId === coupleId && e.fromId === forUserId)
    .slice(-40)
    .map((e) => ({ id: e.id, delivered: !!e.delivered, seen: !!e.seen }));
}

function maxEventId(coupleId) {
  let m = 0;
  for (const e of db.events) if (e.coupleId === coupleId && e.id > m) m = e.id;
  return m;
}

function respondPoll(w) {
  const { res, userId, coupleId } = w;
  const effectiveSince = Math.max(w.since, w.lastSentId || 0);
  const events = eventsSince(coupleId, effectiveSince, userId);
  const statuses = statusesFor(coupleId, userId);
  if (events.length === 0 && !statuses.some((s) => s.changed)) {
    // nada nuevo realmente: si es una reactivación por status, devolvemos igual.
  }
  let dirty = false;
  for (const e of events) {
    if (!e.delivered) { e.delivered = true; dirty = true; }
  }
  if (dirty) save();

  cleanupWaiter(w);
  const cursor = Math.max(effectiveSince, maxEventId(coupleId));
  json(res, 200, {
    events,
    statuses,
    cursor,
    couple: coupleView(coupleId, userId),
    serverTime: now(),
  });
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function json(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 8 * 1024 * 1024) { reject(new Error('payload_too_large')); req.destroy(); return; }
      data += chunk;
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch (e) { reject(new Error('bad_json')); }
    });
    req.on('error', reject);
  });
}

function authUser(req) {
  const h = req.headers['authorization'] || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const t = db.tokens[m[1]];
  if (!t) return null;
  const user = db.users[t.userId];
  if (!user) return null;
  if (!db.devices[t.deviceId]) return null; // dispositivo revocado
  t.lastSeen = now();
  const dev = db.devices[t.deviceId];
  if (dev) dev.lastSeen = now();
  return { token: m[1], user, device: dev, coupleId: db.userCouple[user.id] || null };
}

function cleanText(s, max = 400) {
  if (s == null) return null;
  const t = String(s).replace(/[\u0000-\u001F\u007F]/g, ' ').trim();
  return t.length ? t.slice(0, max) : null;
}

const USERNAME_RE = /^[a-z0-9_.]{3,32}$/;

// ---------------------------------------------------------------------------
// Rutas
// ---------------------------------------------------------------------------

async function register(req, res) {
  const b = await readBody(req);
  const username = String(b.username || '').toLowerCase().trim();
  const password = String(b.password || '');
  const displayName = cleanText(b.displayName, 40) || username;
  if (!USERNAME_RE.test(username)) return json(res, 400, { error: 'usuario_invalido' });
  if (password.length < 6) return json(res, 400, { error: 'clave_corta' });
  if (Object.values(db.users).some((u) => u.username === username))
    return json(res, 409, { error: 'usuario_ocupado' });

  const { salt, hash } = hashPassword(password);
  const id = uid();
  const user = { id, username, displayName, salt, hash, createdAt: now() };
  db.users[id] = user;
  const sess = issueSession(user, b.deviceId, b.deviceName, b.platform);
  save();
  json(res, 200, { token: sess.token, user: publicUser(user), couple: null, cursor: 0 });
}

function issueSession(user, deviceId, deviceName, platform) {
  let devId = deviceId && db.devices[deviceId] && db.devices[deviceId].userId === user.id ? deviceId : null;
  if (!devId) {
    devId = uid();
    db.devices[devId] = {
      id: devId,
      userId: user.id,
      name: cleanText(deviceName, 60) || 'Teléfono',
      platform: platform || 'android',
      createdAt: now(),
      lastSeen: now(),
    };
  } else {
    db.devices[devId].lastSeen = now();
    if (deviceName) db.devices[devId].name = cleanText(deviceName, 60) || db.devices[devId].name;
  }
  const tk = token();
  db.tokens[tk] = { userId: user.id, deviceId: devId, createdAt: now(), lastSeen: now() };
  return { token: tk, deviceId: devId };
}

async function login(req, res) {
  const b = await readBody(req);
  const username = String(b.username || '').toLowerCase().trim();
  const password = String(b.password || '');
  const user = Object.values(db.users).find((u) => u.username === username);
  if (!user || !verifyPassword(password, user.salt, user.hash))
    return json(res, 401, { error: 'credenciales_invalidas' });
  const sess = issueSession(user, b.deviceId, b.deviceName, b.platform);
  save();
  json(res, 200, {
    token: sess.token,
    user: publicUser(user),
    couple: coupleView(db.userCouple[user.id], user.id),
    cursor: db.userCouple[user.id] ? maxEventId(db.userCouple[user.id]) : 0,
  });
}

function logout(req, res, auth) {
  delete db.tokens[auth.token];
  save();
  json(res, 200, { ok: true });
}

async function pairCreate(req, res, auth) {
  if (auth.coupleId) return json(res, 409, { error: 'ya_emparejado' });
  const code = newCode();
  db.invites[code] = { code, fromId: auth.user.id, createdAt: now(), expiresAt: now() + INVITE_TTL_MS, used: false };
  save();
  json(res, 200, { code, expiresAt: db.invites[code].expiresAt });
}

async function pairJoin(req, res, auth) {
  const b = await readBody(req);
  const code = String(b.code || '').trim();
  const inv = db.invites[code];
  if (!inv || inv.used || inv.expiresAt < now()) return json(res, 404, { error: 'invitacion_invalida' });
  if (auth.coupleId) return json(res, 409, { error: 'ya_emparejado' });
  if (inv.fromId === auth.user.id) return json(res, 400, { error: 'no_puedes_contigo' });
  const host = db.users[inv.fromId];
  if (!host) return json(res, 404, { error: 'invitacion_invalida' });
  if (db.userCouple[host.id]) return json(res, 409, { error: 'host_ya_emparejado' });

  const requestId = uid();
  db.pending[requestId] = {
    id: requestId,
    code,
    fromId: host.id,
    toId: auth.user.id,
    deviceId: auth.device.id,
    status: 'pending',
    createdAt: now(),
  };
  // Aviso al host: queda pendiente de aprobación en su panel.
  addEvent(db.userCouple[host.id] || '__pair__' + host.id, auth.user.id, 'system',
    auth.user.displayName + ' quiere emparejarse contigo. Revisa el panel de seguridad.', null);
  save();
  json(res, 200, { pending: true, requestId });
}

async function pairApprove(req, res, auth) {
  const b = await readBody(req);
  const reqId = String(b.requestId || '');
  const approve = b.approve !== false;
  const p = db.pending[reqId];
  if (!p || p.fromId !== auth.user.id || p.status !== 'pending')
    return json(res, 404, { error: 'solicitud_invalida' });
  if (!approve) {
    p.status = 'rejected';
    addEvent('__pair__' + p.toId, auth.user.id, 'system', 'La invitación fue rechazada.', null);
    save();
    return json(res, 200, { ok: true, approved: false });
  }
  if (auth.coupleId) return json(res, 409, { error: 'ya_emparejado' });
  const other = db.users[p.toId];
  if (!other) return json(res, 404, { error: 'usuario_no_existe' });
  if (db.userCouple[other.id]) return json(res, 409, { error: 'la_otra_persona_ya_emparejada' });

  const coupleId = uid();
  db.couples[coupleId] = { id: coupleId, members: [auth.user.id, other.id], since: now(), createdAt: now() };
  db.userCouple[auth.user.id] = coupleId;
  db.userCouple[other.id] = coupleId;
  db.invites[p.code].used = true;
  p.status = 'approved';

  // Recupera eventos de emparejamiento guardados bajo la clave __pair__ y muévelos a la pareja.
  for (const e of db.events) {
    if (e.coupleId === '__pair__' + auth.user.id || e.coupleId === '__pair__' + other.id) {
      e.coupleId = coupleId;
    }
  }

  addEvent(coupleId, auth.user.id, 'system',
    '¡Vinculados! ' + auth.user.displayName + ' y ' + other.displayName + ' están conectados. 💞', null);
  save();
  wakeCouple(coupleId);
  json(res, 200, { ok: true, approved: true, couple: coupleView(coupleId, auth.user.id) });
}

async function pairCancel(req, res, auth) {
  for (const p of Object.values(db.pending)) {
    if (p.toId === auth.user.id && p.status === 'pending') p.status = 'cancelled';
  }
  save();
  json(res, 200, { ok: true });
}

function state(req, res, auth) {
  const coupleId = auth.coupleId;
  const devices = coupleId
    ? Object.values(db.devices)
        .filter((d) => db.couples[coupleId].members.includes(d.userId))
        .map((d) => deviceView(d, auth.device.id))
    : Object.values(db.devices)
        .filter((d) => d.userId === auth.user.id)
        .map((d) => deviceView(d, auth.device.id));

  const pendingForMe = Object.values(db.pending)
    .filter((p) => p.fromId === auth.user.id && p.status === 'pending')
    .map((p) => ({ id: p.id, fromName: (db.users[p.toId] || {}).displayName || 'Alguien', createdAt: p.createdAt }));

  json(res, 200, {
    user: publicUser(auth.user),
    couple: coupleView(coupleId, auth.user.id),
    devices,
    shares: sharesFor(auth),
    pendingRequests: pendingForMe,
    cursor: coupleId ? maxEventId(coupleId) : 0,
    serverTime: now(),
  });
}

function sharesFor(auth) {
  if (!auth.coupleId) return [];
  return db.shares
    .filter((s) => s.coupleId === auth.coupleId)
    .map((s) => ({
      shareType: s.shareType,
      fromId: s.fromId,
      enabled: s.enabled,
      value: s.value,
      updatedAt: s.updatedAt,
    }));
}

async function sendEvent(req, res, auth) {
  if (!auth.coupleId) return json(res, 403, { error: 'sin_pareja' });
  const b = await readBody(req);
  const type = String(b.type || '');
  const allowed = ['alarm', 'imissyou', 'message', 'heartbeat_love'];
  if (!allowed.includes(type)) return json(res, 400, { error: 'tipo_invalido' });

  const key = auth.coupleId;
  if ((type === 'alarm' || type === 'imissyou') && SEND_COOLDOWN[key] && now() - SEND_COOLDOWN[key] < ALARM_COOLDOWN_MS) {
    return json(res, 429, { error: 'espera_un_momento', retryInMs: ALARM_COOLDOWN_MS - (now() - SEND_COOLDOWN[key]) });
  }
  SEND_COOLDOWN[key] = now();

  const text = cleanText(b.text, 300);
  const signature = cleanText(b.signature, 40);
  const ev = addEvent(auth.coupleId, auth.user.id, type, text, signature);
  wakeCouple(auth.coupleId);
  json(res, 200, { ok: true, event: ev });
}

async function ack(req, res, auth) {
  if (!auth.coupleId) return json(res, 403, { error: 'sin_pareja' });
  const b = await readBody(req);
  const id = parseInt(b.eventId, 10);
  const kind = b.kind === 'seen' ? 'seen' : 'delivered';
  const ev = db.events.find((e) => e.id === id && e.coupleId === auth.coupleId);
  if (!ev) return json(res, 404, { error: 'evento_no_existe' });
  if (ev.fromId === auth.user.id) return json(res, 400, { error: 'no_puedes_confirmar_tu_evento' });
  if (kind === 'seen') { ev.seen = true; ev.delivered = true; }
  else ev.delivered = true;
  save();
  wakeCouple(auth.coupleId);
  json(res, 200, { ok: true });
}

function history(req, res, auth, query) {
  if (!auth.coupleId) return json(res, 200, { events: [] });
  const limit = Math.min(200, parseInt(query.limit || '60', 10) || 60);
  const events = db.events.filter((e) => e.coupleId === auth.coupleId).slice(-limit).reverse();
  json(res, 200, { events });
}

async function shareSet(req, res, auth) {
  if (!auth.coupleId) return json(res, 403, { error: 'sin_pareja' });
  const b = await readBody(req);
  const shareType = cleanText(b.shareType, 40);
  const allowed = ['location_manual', 'accounts_links', 'mood', 'note', 'screen_shot'];
  if (!allowed.includes(shareType)) return json(res, 400, { error: 'tipo_invalido' });
  const enabled = !!b.enabled;
  const value = b.value == null ? null : String(b.value).slice(0, 700000); // una captura en base64 cabe aquí
  let item = db.shares.find((s) => s.coupleId === auth.coupleId && s.shareType === shareType && s.fromId === auth.user.id);
  if (!item) {
    item = { shareType, fromId: auth.user.id, coupleId: auth.coupleId, enabled, value: null, updatedAt: now() };
    db.shares.push(item);
  }
  item.enabled = enabled;
  item.value = enabled ? value : null;
  item.updatedAt = now();
  addEvent(auth.coupleId, auth.user.id, 'system',
    auth.user.displayName + (enabled ? ' activó' : ' desactivó') + ' compartir: ' + shareType, null);
  save();
  wakeCouple(auth.coupleId);
  json(res, 200, { ok: true, shares: sharesFor(auth) });
}

async function deviceRevoke(req, res, auth) {
  const b = await readBody(req);
  const id = String(b.deviceId || '');
  const dev = db.devices[id];
  if (!dev) return json(res, 404, { error: 'dispositivo_no_existe' });
  const sameCouple = auth.coupleId && db.couples[auth.coupleId] && db.couples[auth.coupleId].members.includes(dev.userId);
  if (dev.userId !== auth.user.id && !sameCouple) return json(res, 403, { error: 'no_autorizado' });
  for (const [tk, t] of Object.entries(db.tokens)) if (t.deviceId === id) delete db.tokens[tk];
  delete db.devices[id];
  if (auth.coupleId) {
    addEvent(auth.coupleId, auth.user.id, 'system',
      auth.user.displayName + ' revocó un dispositivo: ' + dev.name, null);
  }
  save();
  if (auth.coupleId) wakeCouple(auth.coupleId);
  json(res, 200, { ok: true });
}

async function unpair(req, res, auth) {
  if (!auth.coupleId) return json(res, 409, { error: 'sin_pareja' });
  const c = db.couples[auth.coupleId];
  addEvent(auth.coupleId, auth.user.id, 'system', auth.user.displayName + ' deshizo el emparejamiento.', null);
  wakeCouple(auth.coupleId);
  delete db.couples[auth.coupleId];
  for (const m of c.members) delete db.userCouple[m];
  db.shares = db.shares.filter((s) => s.coupleId !== auth.coupleId);
  save();
  json(res, 200, { ok: true });
}

// ---------------------------------------------------------------------------
// Enrutador
// ---------------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return json(res, 204, {});
  const parsed = new URL(req.url, 'http://localhost');
  const p = parsed.pathname;
  const query = Object.fromEntries(parsed.searchParams.entries());

  try {
    if (p === '/health') return json(res, 200, { ok: true, time: now() });

    // Rutas públicas
    if (p === '/api/register' && req.method === 'POST') return await register(req, res);
    if (p === '/api/login' && req.method === 'POST') return await login(req, res);

    // A partir de aquí se requiere token
    const auth = authUser(req);
    if (!auth) return json(res, 401, { error: 'no_autenticado' });

    if (p === '/api/logout' && req.method === 'POST') return logout(req, res, auth);
    if (p === '/api/state' && req.method === 'GET') return state(req, res, auth);
    if (p === '/api/history' && req.method === 'GET') return history(req, res, auth, query);
    if (p === '/api/pair/create' && req.method === 'POST') return await pairCreate(req, res, auth);
    if (p === '/api/pair/join' && req.method === 'POST') return await pairJoin(req, res, auth);
    if (p === '/api/pair/approve' && req.method === 'POST') return await pairApprove(req, res, auth);
    if (p === '/api/pair/cancel' && req.method === 'POST') return await pairCancel(req, res, auth);
    if (p === '/api/send' && req.method === 'POST') return await sendEvent(req, res, auth);
    if (p === '/api/ack' && req.method === 'POST') return await ack(req, res, auth);
    if (p === '/api/share/set' && req.method === 'POST') return await shareSet(req, res, auth);
    if (p === '/api/device/revoke' && req.method === 'POST') return await deviceRevoke(req, res, auth);
    if (p === '/api/unpair' && req.method === 'POST') return await unpair(req, res, auth);

    if (p === '/api/poll' && req.method === 'GET') {
      if (!auth.coupleId) return json(res, 409, { error: 'sin_pareja' });
      const since = parseInt(query.since || '0', 10) || 0;
      const timeout = Math.min(POLL_MAX_MS, Math.max(1000, parseInt(query.timeout || '25000', 10) || 25000));
      const coupleId = auth.coupleId;
      const w = { res, userId: auth.user.id, coupleId, since, lastSentId: 0, timer: null };

      const pending = eventsSince(coupleId, since, auth.user.id);
      if (pending.length > 0) return respondPoll(w);

      const set = waitersFor(coupleId);
      set.add(w);
      w.timer = setTimeout(() => {
        try { respondPoll(w); } catch (_) { cleanupWaiter(w); }
      }, timeout);
      req.on('close', () => cleanupWaiter(w));
      return;
    }

    json(res, 404, { error: 'no_encontrado' });
  } catch (e) {
    if (e && (e.message === 'bad_json' || e.message === 'payload_too_large'))
      return json(res, 400, { error: e.message });
    console.error('[love-alarm] error:', e);
    json(res, 500, { error: 'error_interno' });
  }
});

// ---------------------------------------------------------------------------
// Arranque
// ---------------------------------------------------------------------------

// Limpieza periódica de invitaciones caducadas.
setInterval(() => {
  const t = now();
  for (const [k, v] of Object.entries(db.invites)) if (v.expiresAt < t) delete db.invites[k];
  for (const [k, v] of Object.entries(db.pending)) if (t - v.createdAt > 24 * 3600 * 1000) delete db.pending[k];
}, 60 * 1000).unref();

load().finally(() => {
  server.listen(PORT, HOST, () => {
    console.log(`[love-alarm] escuchando en http://${HOST}:${PORT}`);
    console.log(
      `[love-alarm] almacenamiento: ${USE_REDIS ? `Upstash Redis (${DB_KEY})` : DATA_FILE}`
    );
  });
});
