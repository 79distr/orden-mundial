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
