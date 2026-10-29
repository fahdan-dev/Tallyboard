const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000, DB = path.join(__dirname, 'data.json');
const SECURE = process.env.NODE_ENV === 'production';
const ALLOW_REGISTRATION = process.env.ALLOW_REGISTRATION !== 'false';
const SESSION_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

let db = fs.existsSync(DB) ? JSON.parse(fs.readFileSync(DB)) : { users: [], tasks: [], seq: 1 };

const save = async () => {
  const tmp = DB + '.tmp';
  await fs.promises.writeFile(tmp, JSON.stringify(db, null, 2));
  await fs.promises.rename(tmp, DB);
};
const saveSync = () => fs.writeFileSync(DB, JSON.stringify(db, null, 2));

const hash = (pw, salt = crypto.randomBytes(16).toString('hex')) => salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
const DUMMY_HASH = hash('dummy-password-that-never-matches');
const check = (pw, h) => { const [s] = h.split(':'); const a = Buffer.from(hash(pw, s)), b = Buffer.from(h); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const addUser = (username, password, role = 'user') => { const u = { id: db.seq++, username, hash: hash(password), role, active: true, created: Date.now() }; db.users.push(u); return u; };

if (!db.users.length) {
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(12).toString('base64url');
  addUser('admin', pw, 'superadmin'); saveSync();
  if (process.env.ADMIN_PASSWORD) {
    console.log('Created superadmin: admin (password from ADMIN_PASSWORD env var). Change it after first login.');
  } else {
    console.log(`Created superadmin: admin / ${pw}`);
    console.log('Change this password immediately, or restart with ADMIN_PASSWORD=<your-password> set.');
  }
}
if (!db.users.some(u => u.role === 'superadmin')) { const first = db.users.find(u => u.role === 'admin'); if (first) { first.role = 'superadmin'; saveSync(); console.log('Promoted "' + first.username + '" to superadmin.'); } }
const isAdmin = u => u.role === 'admin' || u.role === 'superadmin', isSuper = u => u.role === 'superadmin';
const pub = u => ({ id: u.id, username: u.username, role: u.role, active: u.active, created: u.created });

const sessions = new Map(), attempts = new Map();
const createSession = (userId) => { const id = crypto.randomBytes(24).toString('hex'); sessions.set(id, { userId, created: Date.now() }); return id; };
const getSessionUser = (sid) => {
  const s = sessions.get(sid);
  if (!s) return null;
  if (Date.now() - s.created > SESSION_MAX_AGE) { sessions.delete(sid); return null; }
  return db.users.find(u => u.id === s.userId) || null;
};
const invalidateUserSessions = (userId) => { for (const [k, v] of sessions) if (v.userId === userId) sessions.delete(k); };

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of sessions) if (now - v.created > SESSION_MAX_AGE) sessions.delete(k);
  for (const [k, v] of attempts) if (now - v.t > 6e5) attempts.delete(k);
}, 10 * 60 * 1000).unref();

const cookieHeader = (req, id) => {
  const isHttps = req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
  return `sid=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${(SECURE && isHttps) ? '; Secure' : ''}`;
};
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
  ...(SECURE ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } : {}),
};

const send = (res, code, data, headers = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...SECURITY_HEADERS, ...headers }); res.end(JSON.stringify(data)); };
const body = req => new Promise(r => { let s = ''; req.on('data', c => { s += c; if (s.length > 1e5) req.destroy(); }); req.on('end', () => { try { r(JSON.parse(s || '{}')); } catch { r({}); } }); });
const cookie = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(c => c[0]));
const valid = (u, p) => /^[a-zA-Z0-9_]{3,20}$/.test(u || '') && typeof p === 'string' && p.length >= 8;
const getIp = req => req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
const log = (event, detail) => console.log(`[${new Date().toISOString()}] ${event}`, JSON.stringify(detail));

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

const handler = async (req, res) => {
  const url = new URL(req.url, 'http://x'), p = url.pathname, m = req.method;

  if (!p.startsWith('/api/')) {
    const f = path.join(__dirname, 'public', p === '/' ? 'index.html' : p);
    if (!f.startsWith(path.join(__dirname, 'public'))) { res.writeHead(404, SECURITY_HEADERS); return res.end('Not found'); }
    try {
      const content = await fs.promises.readFile(f);
      res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'text/plain', 'Cache-Control': 'no-store', ...SECURITY_HEADERS });
      return res.end(content);
    } catch { res.writeHead(404, SECURITY_HEADERS); return res.end('Not found'); }
  }

  if (['POST', 'PATCH'].includes(m) && !(req.headers['content-type'] || '').includes('application/json')) {
    return send(res, 400, { error: 'Invalid content type.' });
  }

  const b = ['POST', 'PATCH'].includes(m) ? await body(req) : {};
  const sid = cookie(req).sid, user = getSessionUser(sid);

  if (p === '/api/login' && m === 'POST') {
    const ip = getIp(req), n = attempts.get(ip) || { c: 0, t: Date.now() };
    if (Date.now() - n.t > 6e5) { n.c = 0; n.t = Date.now(); }
    if (n.c >= 5) { log('RATE_LIMIT', { ip }); return send(res, 429, { error: 'Too many attempts. Try again in a few minutes.' }); }
    const u = db.users.find(x => x.username.toLowerCase() === String(b.username).toLowerCase());
    const passwordOk = check(String(b.password), u ? u.hash : DUMMY_HASH);
    if (!u || !passwordOk) { n.c++; attempts.set(ip, n); log('LOGIN_FAIL', { username: b.username, ip }); return send(res, 401, { error: 'Wrong username or password.' }); }
    if (!u.active) { log('LOGIN_DISABLED', { username: u.username, ip }); return send(res, 403, { error: 'This account is disabled. Contact an admin.' }); }
    const id = createSession(u.id);
    log('LOGIN_OK', { username: u.username, ip });
    return send(res, 200, pub(u), { 'Set-Cookie': cookieHeader(req, id) });
  }

  if (p === '/api/register' && m === 'POST') {
    if (!ALLOW_REGISTRATION) return send(res, 403, { error: 'Registration is disabled. Contact an admin.' });
    const ip = getIp(req), n = attempts.get('reg:' + ip) || { c: 0, t: Date.now() };
    if (Date.now() - n.t > 6e5) { n.c = 0; n.t = Date.now(); }
    if (n.c >= 3) return send(res, 429, { error: 'Too many registrations. Try again later.' });
    if (!valid(b.username, b.password)) return send(res, 400, { error: 'Username: 3-20 letters/numbers/_. Password: 8+ characters.' });
    if (db.users.some(u => u.username.toLowerCase() === b.username.toLowerCase())) return send(res, 409, { error: 'That username is taken.' });
    n.c++; attempts.set('reg:' + ip, n);
    const u = addUser(b.username, b.password); await save();
    const id = createSession(u.id);
    log('REGISTER', { username: u.username, ip });
    return send(res, 200, pub(u), { 'Set-Cookie': cookieHeader(req, id) });
  }

  if (p === '/api/logout') { sessions.delete(sid); return send(res, 200, {}, { 'Set-Cookie': 'sid=; Max-Age=0; Path=/' }); }
  if (!user || !user.active) return send(res, 401, { error: 'Not signed in.' });
  if (p === '/api/me') return send(res, 200, pub(user));

  if (p === '/api/password' && m === 'POST') {
    if (!check(String(b.current), user.hash)) return send(res, 400, { error: 'Current password is wrong.' });
    if (!valid(user.username, b.next)) return send(res, 400, { error: 'New password needs 8+ characters.' });
    user.hash = hash(b.next);
    invalidateUserSessions(user.id);
    const id = createSession(user.id);
    await save();
    log('PASSWORD_CHANGE', { username: user.username });
    return send(res, 200, {}, { 'Set-Cookie': cookieHeader(req, id) });
  }

  if (p === '/api/username' && m === 'POST') {
    const nu = String(b.username || '');
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(nu)) return send(res, 400, { error: 'Username: 3-20 letters/numbers/_.' });
    if (db.users.some(u => u.id !== user.id && u.username.toLowerCase() === nu.toLowerCase())) return send(res, 409, { error: 'That username is taken.' });
    user.username = nu; await save(); return send(res, 200, pub(user));
  }

  if (p === '/api/tasks' && m === 'GET') return send(res, 200, db.tasks.filter(t => t.userId === user.id));
  if (p === '/api/tasks' && m === 'POST') {
    if (!String(b.title || '').trim()) return send(res, 400, { error: 'Task needs a title.' });
    const t = { id: db.seq++, userId: user.id, title: b.title.trim().slice(0, 140), done: false, created: Date.now() }; db.tasks.push(t); await save(); return send(res, 200, t);
  }
  const tm = p.match(/^\/api\/tasks\/(\d+)$/);
  if (tm) {
    const taskId = Number(tm[1]);
    const t = db.tasks.find(x => x.id === taskId && x.userId === user.id); if (!t) return send(res, 404, { error: 'Task not found.' });
    if (m === 'PATCH') { t.done = !!b.done; await save(); return send(res, 200, t); }
    if (m === 'DELETE') { db.tasks = db.tasks.filter(x => x !== t); await save(); return send(res, 200, {}); }
  }

  if (p.startsWith('/api/admin')) {
    if (!isAdmin(user)) return send(res, 403, { error: 'Admins only.' });
    if (p === '/api/admin/stats') return send(res, 200, { users: db.users.length, admins: db.users.filter(isAdmin).length, disabled: db.users.filter(u => !u.active).length, tasks: db.tasks.length, done: db.tasks.filter(t => t.done).length });
    if (p === '/api/admin/users' && m === 'GET') return send(res, 200, db.users.map(u => ({ ...pub(u), tasks: db.tasks.filter(t => t.userId === u.id).length })));
    if (p === '/api/admin/users' && m === 'POST') {
      if (!valid(b.username, b.password)) return send(res, 400, { error: 'Username: 3-20 letters/numbers/_. Password: 8+ characters.' });
      if (b.role === 'admin' && !isSuper(user)) return send(res, 403, { error: 'Only the superadmin can create admin accounts.' });
      if (db.users.some(u => u.username.toLowerCase() === b.username.toLowerCase())) return send(res, 409, { error: 'That username is taken.' });
      const u = addUser(b.username, b.password, b.role === 'admin' ? 'admin' : 'user'); await save();
      log('ADMIN_CREATE_USER', { admin: user.username, target: u.username, role: u.role });
      return send(res, 200, pub(u));
    }
    const um = p.match(/^\/api\/admin\/users\/(\d+)$/), userId = um ? Number(um[1]) : null, t = um && db.users.find(u => u.id === userId);
    if (um) {
      if (!t) return send(res, 404, { error: 'User not found.' });
      if (t.id === user.id) return send(res, 400, { error: "You can't change your own account here." });
      if (t.role === 'superadmin' || (t.role === 'admin' && !isSuper(user))) return send(res, 403, { error: 'Only the superadmin can manage admin accounts.' });
      if (m === 'PATCH') {
        if (b.role && !isSuper(user)) return send(res, 403, { error: 'Only the superadmin can change roles.' });
        if (b.role) t.role = b.role === 'admin' ? 'admin' : 'user';
        if (typeof b.active === 'boolean') { t.active = b.active; if (!b.active) invalidateUserSessions(t.id); }
        if (b.password) { if (b.password.length < 8) return send(res, 400, { error: 'Password needs 8+ characters.' }); t.hash = hash(b.password); invalidateUserSessions(t.id); }
        await save();
        log('ADMIN_UPDATE_USER', { admin: user.username, target: t.username, changes: Object.keys(b) });
        return send(res, 200, pub(t));
      }
      if (m === 'DELETE') {
        invalidateUserSessions(t.id);
        db.users = db.users.filter(u => u !== t); db.tasks = db.tasks.filter(x => x.userId !== t.id); await save();
        log('ADMIN_DELETE_USER', { admin: user.username, target: t.username });
        return send(res, 200, {});
      }
    }
  }
  send(res, 404, { error: 'Not found.' });
};
const server = http.createServer((req, res) => handler(req, res).catch(e => {
  console.error(e); if (!res.headersSent) send(res, 500, { error: 'Server error. Check the terminal for details.' }); else res.end();
}));
server.listen(PORT, () => console.log(`Running at http://localhost:${PORT}${SECURE ? ' (production — Secure cookies + HSTS enabled)' : ''}`));
