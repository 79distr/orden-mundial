// ORDEN MUNDIAL · API de cuentas y partidas guardadas
// Cloudflare Pages Functions + KV (binding: OM_KV)
//
// Rutas:
//   GET  /api/me        -> estado de la sesión
//   POST /api/register  -> crea una cuenta (por defecto solo la primera; ver README)
//   POST /api/login     -> inicia sesión
//   POST /api/logout    -> cierra sesión
//   GET  /api/save      -> descarga la partida (?which=backup para el respaldo)
//   PUT  /api/save      -> sube la partida (con control de conflictos)
//
// Variables opcionales (Settings > Variables and Secrets):
//   REGISTER_CODE   código de invitación obligatorio para crear cuentas
//   ALLOW_REGISTER  "true" para permitir más de una cuenta

const ENC = new TextEncoder();
const PBKDF2_ITERATIONS = 100000; // máximo que admite Workers
const SESSION_TTL = 60 * 60 * 24 * 30; // 30 días
const MAX_SAVE_CHARS = 8000000;
const BACKUP_MIN_AGE_MS = 10 * 60 * 1000;
const COOKIE = 'om_session';
const MAX_FAILS = 8;
const FAIL_WINDOW = 900; // 15 minutos
const DUMMY_SALT = new Uint8Array(16);

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...headers,
    },
  });
}

function b64u(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64u(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}

async function sha256(text) {
  return b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', ENC.encode(text))));
}

async function derive(password, salt) {
  const key = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
    key,
    256
  );
  return new Uint8Array(bits);
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function cookieHeader(value, maxAge, secure) {
  return `${COOKIE}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}`;
}

function normUser(raw) {
  const u = String(raw || '').trim().toLowerCase();
  return /^[a-z0-9_.-]{3,32}$/.test(u) ? u : null;
}

async function readJson(request, limit) {
  const text = await request.text();
  if (text.length > limit) return null;
  try {
    return JSON.parse(text);
  } catch (e) {
    return null;
  }
}

async function getSessionUser(request, env) {
  const token = getCookie(request, COOKIE);
  if (!token || token.length < 20 || token.length > 100) return null;
  const rec = await env.OM_KV.get('s:' + (await sha256(token)), 'json');
  return rec && rec.u ? rec.u : null;
}

async function createSession(env, username, secure) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = b64u(raw);
  await env.OM_KV.put('s:' + (await sha256(token)), JSON.stringify({ u: username, t: Date.now() }), {
    expirationTtl: SESSION_TTL,
  });
  return cookieHeader(token, SESSION_TTL, secure);
}

async function failures(env, ip) {
  return parseInt(await env.OM_KV.get('rl:' + ip), 10) || 0;
}

async function addFailure(env, ip, current) {
  await env.OM_KV.put('rl:' + ip, String(current + 1), { expirationTtl: FAIL_WINDOW });
}

const tooMany = () =>
  json({ error: 'rate_limit', message: 'Demasiados intentos fallidos. Esperá unos 15 minutos e intentá de nuevo.' }, 429);

async function registrationOpen(env) {
  if (env.ALLOW_REGISTER === 'true') return true;
  return !(await env.OM_KV.get('meta:users'));
}

async function handleMe(request, env) {
  const user = await getSessionUser(request, env);
  if (user) return json({ authenticated: true, username: user });
  return json({
    authenticated: false,
    canRegister: await registrationOpen(env),
    needsCode: !!env.REGISTER_CODE,
  });
}

async function handleRegister(request, env, secure, ip) {
  const fails = await failures(env, ip);
  if (fails >= MAX_FAILS) return tooMany();
  const body = await readJson(request, 10000);
  if (!body) return json({ error: 'bad_request', message: 'Solicitud inválida.' }, 400);
  if (!(await registrationOpen(env))) {
    return json({ error: 'closed', message: 'El registro de cuentas está cerrado.' }, 403);
  }
  if (env.REGISTER_CODE) {
    const given = ENC.encode(String(body.code || ''));
    const wanted = ENC.encode(String(env.REGISTER_CODE));
    if (!safeEqual(given, wanted)) {
      await addFailure(env, ip, fails);
      return json({ error: 'code', message: 'Código de invitación incorrecto.' }, 403);
    }
  }
  const username = normUser(body.username);
  const password = String(body.password || '');
  if (!username) {
    return json(
      { error: 'username', message: 'El usuario debe tener de 3 a 32 caracteres: letras, números, punto, guion o guion bajo.' },
      400
    );
  }
  if (password.length < 8 || password.length > 200) {
    return json({ error: 'password', message: 'La contraseña debe tener al menos 8 caracteres.' }, 400);
  }
  if (await env.OM_KV.get('u:' + username)) {
    return json({ error: 'exists', message: 'Ese usuario ya existe.' }, 409);
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(password, salt);
  await env.OM_KV.put(
    'u:' + username,
    JSON.stringify({ salt: b64u(salt), hash: b64u(hash), iter: PBKDF2_ITERATIONS, created: Date.now() })
  );
  await env.OM_KV.put('meta:users', '1');
  const cookie = await createSession(env, username, secure);
  return json({ ok: true, username }, 200, { 'Set-Cookie': cookie });
}

async function handleLogin(request, env, secure, ip) {
  const fails = await failures(env, ip);
  if (fails >= MAX_FAILS) return tooMany();
  const body = await readJson(request, 10000);
  if (!body) return json({ error: 'bad_request', message: 'Solicitud inválida.' }, 400);
  const username = normUser(body.username);
  const password = String(body.password || '').slice(0, 200);
  const rec = username ? await env.OM_KV.get('u:' + username, 'json') : null;
  // Se calcula el hash siempre para no revelar si el usuario existe por el tiempo de respuesta.
  const hash = await derive(password, rec ? unb64u(rec.salt) : DUMMY_SALT);
  if (!rec || !safeEqual(hash, unb64u(rec.hash))) {
    await addFailure(env, ip, fails);
    return json({ error: 'credentials', message: 'Usuario o contraseña incorrectos.' }, 401);
  }
  if (fails > 0) await env.OM_KV.delete('rl:' + ip);
  const cookie = await createSession(env, username, secure);
  return json({ ok: true, username }, 200, { 'Set-Cookie': cookie });
}

async function handleLogout(request, env, secure) {
  const token = getCookie(request, COOKIE);
  if (token && token.length >= 20 && token.length <= 100) {
    await env.OM_KV.delete('s:' + (await sha256(token)));
  }
  return json({ ok: true }, 200, { 'Set-Cookie': cookieHeader('', 0, secure) });
}

async function handleSaveGet(url, env, user) {
  const which = url.searchParams.get('which') === 'backup' ? 'bak:' : 'save:';
  const rec = await env.OM_KV.get(which + user, 'json');
  if (!rec) return json({ exists: false });
  return json({ exists: true, updatedAt: rec.updatedAt, data: rec.data });
}

async function handleSavePut(request, env, user) {
  const body = await readJson(request, MAX_SAVE_CHARS + 2000);
  if (!body || !body.data || typeof body.data !== 'object' || body.data.version !== 1) {
    return json({ error: 'invalid', message: 'La partida enviada no es válida o es demasiado grande.' }, 400);
  }
  const key = 'save:' + user;
  const current = await env.OM_KV.get(key, 'json');
  if (current && Number(body.baseVersion) !== current.updatedAt) {
    return json(
      { error: 'conflict', message: 'La partida en la nube cambió desde otro dispositivo.', updatedAt: current.updatedAt },
      409
    );
  }
  if (current && Date.now() - current.updatedAt > BACKUP_MIN_AGE_MS) {
    await env.OM_KV.put('bak:' + user, JSON.stringify(current));
  }
  const updatedAt = Math.max(Date.now(), (current ? current.updatedAt : 0) + 1);
  await env.OM_KV.put(key, JSON.stringify({ updatedAt, data: body.data }));
  return json({ ok: true, updatedAt });
}


// --- Salas multijugador (fase 1: creación, invitación y barrera de turnos) ---
const ROOM_TTL = 60 * 60 * 24 * 30;
function roomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  return Array.from(bytes, b => chars[b % chars.length]).join('');
}
async function roomMember(request, env, code) {
  const user = await getSessionUser(request, env);
  if (!user) return { error: json({ error: 'auth', message: 'Iniciá sesión.' }, 401) };
  const room = await env.OM_KV.get('room:' + code, 'json');
  if (!room) return { error: json({ error: 'room_not_found', message: 'La sala no existe o venció.' }, 404) };
  if (!room.players || !room.players[user]) return { error: json({ error: 'not_member', message: 'No pertenecés a esta sala.' }, 403) };
  return { user, room };
}
async function handleRoomCreate(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: 'auth', message: 'Iniciá sesión.' }, 401);
  const body = await readJson(request, 5000);
  const country = String(body?.country || '').trim().slice(0, 80);
  if (!country) return json({ error: 'country', message: 'Elegí un país.' }, 400);
  let code, key;
  for (let i = 0; i < 5; i++) { code = roomCode(); key = 'room:' + code; if (!(await env.OM_KV.get(key))) break; code = null; }
  if (!code) return json({ error: 'room_code', message: 'No se pudo generar un código. Intentá otra vez.' }, 500);
  const room = { code, owner: user, status: 'waiting', turn: 0, started: false, world: null, worldVersion: 0, turnReady: {}, createdAt: Date.now(), players: { [user]: { country, ready: false, joinedAt: Date.now() } } };
  await env.OM_KV.put(key, JSON.stringify(room), { expirationTtl: ROOM_TTL });
  return json({ ok: true, room });
}
async function handleRoomJoin(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: 'auth', message: 'Iniciá sesión.' }, 401);
  const body = await readJson(request, 5000);
  const code = String(body?.code || '').trim().toUpperCase();
  const country = String(body?.country || '').trim().slice(0, 80);
  if (!/^[A-HJ-NP-Z2-9]{6}$/.test(code) || !country) return json({ error: 'input', message: 'Revisá el código y el país elegido.' }, 400);
  const key = 'room:' + code, room = await env.OM_KV.get(key, 'json');
  if (!room) return json({ error: 'room_not_found', message: 'No encontramos esa sala.' }, 404);
  if (room.players?.[user]) return json({ ok: true, room });
  if (room.status !== 'waiting' || Object.keys(room.players || {}).length >= 2) return json({ error: 'room_full', message: 'La sala ya está completa.' }, 409);
  if (Object.values(room.players).some(p => p.country.toLowerCase() === country.toLowerCase())) return json({ error: 'country_taken', message: 'Ese país ya está elegido.' }, 409);
  room.players[user] = { country, ready: false, joinedAt: Date.now() };
  room.status = 'ready_check';
  await env.OM_KV.put(key, JSON.stringify(room), { expirationTtl: ROOM_TTL });
  return json({ ok: true, room });
}
async function handleRoomState(request, env, code) {
  const found = await roomMember(request, env, code);
  if (found.error) return found.error;
  return json({ ok: true, room: found.room, me: found.user });
}
async function handleRoomReady(request, env, code) {
  const found = await roomMember(request, env, code);
  if (found.error) return found.error;
  const room = found.room, body = await readJson(request, 2000);
  const ready = body?.ready !== false;
  room.players[found.user].ready = ready;
  const players = Object.values(room.players);
  if (players.length === 2 && players.every(p => p.ready)) room.status = 'both_ready';
  else room.status = players.length === 2 ? 'ready_check' : 'waiting';
  await env.OM_KV.put('room:' + code, JSON.stringify(room), { expirationTtl: ROOM_TTL });
  return json({ ok: true, room });
}
async function handleRoomStart(request, env, code) {
  const found = await roomMember(request, env, code);
  if (found.error) return found.error;
  const room = found.room;
  if (found.user !== room.owner) return json({ error: 'host_only', message: 'Solo quien creó la sala puede iniciar el mundo.' }, 403);
  if (Object.keys(room.players || {}).length !== 2 || !Object.values(room.players).every(p => p.ready)) return json({ error: 'not_ready', message: 'Los dos jugadores deben confirmar que están listos.' }, 409);
  const body = await readJson(request, MAX_SAVE_CHARS + 2000);
  if (!body?.data || body.data.version !== 1) return json({ error: 'invalid_world', message: 'No se recibió un estado de mundo válido.' }, 400);
  room.world = body.data;
  room.worldVersion = 1;
  room.turn = Number(body.data.turn) || 0;
  room.started = true;
  room.status = 'in_game';
  room.turnReady = {};
  await env.OM_KV.put('room:' + code, JSON.stringify(room), { expirationTtl: ROOM_TTL });
  return json({ ok: true, room });
}
async function handleRoomWorldGet(request, env, code) {
  const found = await roomMember(request, env, code);
  if (found.error) return found.error;
  const r = found.room;
  return json({ ok: true, started: !!r.started, world: r.world || null, worldVersion: r.worldVersion || 0, turn: r.turn || 0, turnReady: r.turnReady || {}, owner: r.owner, me: found.user, players: r.players });
}
async function handleRoomWorldPut(request, env, code) {
  const found = await roomMember(request, env, code);
  if (found.error) return found.error;
  const room = found.room;
  if (!room.started) return json({ error: 'not_started', message: 'La partida todavía no comenzó.' }, 409);
  const body = await readJson(request, MAX_SAVE_CHARS + 2000);
  if (!body?.data || body.data.version !== 1) return json({ error: 'invalid_world', message: 'Estado de mundo inválido.' }, 400);
  if (Number(body.baseVersion) !== Number(room.worldVersion || 0)) return json({ error: 'world_conflict', message: 'El mundo compartido cambió. Se actualizará tu pantalla.', worldVersion: room.worldVersion }, 409);
  // Los cambios de gestión se comparten con control de versión para evitar sobrescrituras silenciosas.
  room.world = body.data;
  room.worldVersion = (Number(room.worldVersion) || 0) + 1;
  room.lastWorldWriter = found.user;
  room.worldUpdatedAt = Date.now();
  await env.OM_KV.put('room:' + code, JSON.stringify(room), { expirationTtl: ROOM_TTL });
  return json({ ok: true, worldVersion: room.worldVersion });
}
async function handleRoomTurnReady(request, env, code) {
  const found = await roomMember(request, env, code);
  if (found.error) return found.error;
  const room = found.room;
  if (!room.started) return json({ error: 'not_started', message: 'La partida todavía no comenzó.' }, 409);
  room.turnReady = room.turnReady || {};
  room.turnReady[found.user] = true;
  await env.OM_KV.put('room:' + code, JSON.stringify(room), { expirationTtl: ROOM_TTL });
  return json({ ok: true, turnReady: room.turnReady, allReady: Object.keys(room.players).length === 2 && Object.keys(room.players).every(u => room.turnReady[u]) });
}
async function handleRoomAdvance(request, env, code) {
  const found = await roomMember(request, env, code);
  if (found.error) return found.error;
  const room = found.room;
  if (!room.started) return json({ error: 'not_started', message: 'La partida todavía no comenzó.' }, 409);
  if (found.user !== room.owner) return json({ error: 'host_only', message: 'El creador de la sala es quien ejecuta el avance mensual.' }, 403);
  if (Object.keys(room.players).length !== 2 || !Object.keys(room.players).every(u => room.turnReady?.[u])) return json({ error: 'not_ready', message: 'Falta la confirmación del otro jugador.' }, 409);
  const body = await readJson(request, MAX_SAVE_CHARS + 2000);
  if (!body?.data || body.data.version !== 1) return json({ error: 'invalid_world', message: 'Estado de mundo inválido.' }, 400);
  if (Number(body.baseVersion) !== Number(room.worldVersion || 0)) return json({ error: 'world_conflict', message: 'El mundo cambió antes de avanzar. Actualizá y volvé a intentarlo.' }, 409);
  room.world = body.data;
  room.worldVersion = (Number(room.worldVersion) || 0) + 1;
  room.turn = Number(body.data.turn) || (Number(room.turn) + 1);
  room.turnReady = {};
  room.lastWorldWriter = found.user;
  room.worldUpdatedAt = Date.now();
  await env.OM_KV.put('room:' + code, JSON.stringify(room), { expirationTtl: ROOM_TTL });
  return json({ ok: true, room, worldVersion: room.worldVersion });
}
async function handleRoomLeave(request, env, code) {
  const found = await roomMember(request, env, code);
  if (found.error) return found.error;
  const room = found.room;
  delete room.players[found.user];
  if (!Object.keys(room.players).length) await env.OM_KV.delete('room:' + code);
  else { room.status = 'waiting'; for (const p of Object.values(room.players)) p.ready = false; await env.OM_KV.put('room:' + code, JSON.stringify(room), { expirationTtl: ROOM_TTL }); }
  return json({ ok: true });
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const route = url.pathname.replace(/^\/api\/?/, '').replace(/\/+$/, '');
  const method = request.method;

  if (!env.OM_KV) {
    return json(
      { error: 'kv_not_configured', message: 'El servidor todavía no está configurado: falta vincular el KV namespace con el nombre OM_KV.' },
      503
    );
  }

  try {
    if (method !== 'GET' && method !== 'HEAD') {
      // Defensa contra CSRF: solo se aceptan escrituras originadas en este mismo sitio.
      if (request.headers.get('Origin') !== url.origin) {
        return json({ error: 'origin', message: 'Origen no permitido.' }, 403);
      }
    }
    const secure = url.protocol === 'https:';
    const ip = request.headers.get('CF-Connecting-IP') || 'local';

    if (route === 'me' && method === 'GET') return await handleMe(request, env);
    if (route === 'register' && method === 'POST') return await handleRegister(request, env, secure, ip);
    if (route === 'login' && method === 'POST') return await handleLogin(request, env, secure, ip);
    if (route === 'logout' && method === 'POST') return await handleLogout(request, env, secure);

    if (route === 'rooms' && method === 'POST') return await handleRoomCreate(request, env);
    if (route === 'rooms/join' && method === 'POST') return await handleRoomJoin(request, env);
    const roomWorldRoute = route.match(/^rooms\/([A-HJ-NP-Z2-9]{6})\/(start|world|turn-ready|advance)$/);
    if (roomWorldRoute && roomWorldRoute[2] === 'start' && method === 'POST') return await handleRoomStart(request, env, roomWorldRoute[1]);
    if (roomWorldRoute && roomWorldRoute[2] === 'world' && method === 'GET') return await handleRoomWorldGet(request, env, roomWorldRoute[1]);
    if (roomWorldRoute && roomWorldRoute[2] === 'world' && (method === 'PUT' || method === 'POST')) return await handleRoomWorldPut(request, env, roomWorldRoute[1]);
    if (roomWorldRoute && roomWorldRoute[2] === 'turn-ready' && method === 'POST') return await handleRoomTurnReady(request, env, roomWorldRoute[1]);
    if (roomWorldRoute && roomWorldRoute[2] === 'advance' && method === 'POST') return await handleRoomAdvance(request, env, roomWorldRoute[1]);
    const roomRoute = route.match(/^rooms\/([A-HJ-NP-Z2-9]{6})(?:\/(ready|leave))?$/);
    if (roomRoute && method === 'GET' && !roomRoute[2]) return await handleRoomState(request, env, roomRoute[1]);
    if (roomRoute && method === 'POST' && roomRoute[2] === 'ready') return await handleRoomReady(request, env, roomRoute[1]);
    if (roomRoute && method === 'POST' && roomRoute[2] === 'leave') return await handleRoomLeave(request, env, roomRoute[1]);

    if (route === 'save') {
      const user = await getSessionUser(request, env);
      if (!user) return json({ error: 'auth', message: 'Sesión no iniciada o vencida.' }, 401);
      if (method === 'GET') return await handleSaveGet(url, env, user);
      if (method === 'PUT' || method === 'POST') return await handleSavePut(request, env, user);
    }
    return json({ error: 'not_found', message: 'Ruta no encontrada.' }, 404);
  } catch (e) {
    return json({ error: 'server', message: 'Error interno del servidor.' }, 500);
  }
}
