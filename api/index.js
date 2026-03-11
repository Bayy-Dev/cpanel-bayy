// api/index.js — PteroBot Panel API (Vercel Serverless + MongoDB + JWT)
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const fetch   = require('node-fetch');
const { connectDB, User, Log } = require('../lib/db');

// ── CONSTANTS ──────────────────────────────────────────────────────────
const ROLE_LEVEL = { ceo:0, owner:1, pt:2, reseller:3, admin:4, user:5 };
const CAN_CREATE = {
  ceo:      ['owner','pt','reseller','admin','user'],
  owner:    ['pt','reseller','admin','user'],
  pt:       ['reseller','admin','user'],
  reseller: ['admin','user'],
  admin:    ['user'],
  user:     [],
};
const JWT_SECRET  = process.env.JWT_SECRET;
const PTERO_URL   = process.env.PTERO_URL;
const PTERO_KEY   = process.env.PTERO_KEY;
const TTL         = 60 * 60 * 24 * 7; // 7 hari

// ── HELPERS ──────────────────────────────────────────────────────────
function safe(user) {
  const u = user.toObject ? user.toObject() : { ...user };
  delete u.password;
  return u;
}

function signToken(userId) {
  return jwt.sign({ id: userId.toString() }, JWT_SECRET, { expiresIn: TTL });
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

function getToken(req) {
  const auth = req.headers['authorization'];
  if (auth?.startsWith('Bearer ')) return auth.slice(7);
  const cookie = req.headers['cookie'] || '';
  const m = cookie.match(/auth_token=([^;]+)/);
  return m ? m[1] : null;
}

async function getMe(req) {
  const token = getToken(req);
  if (!token) return null;
  const payload = verifyToken(token);
  if (!payload) return null;
  const user = await User.findById(payload.id);
  if (!user || user.status === 'suspended') return null;
  return user;
}

async function logActivity(userId, action, targetId = null, detail = '') {
  try { await Log.create({ userId, action, targetId, detail }); } catch {}
}

async function ptero(method, endpoint, body = null) {
  const url  = PTERO_URL + '/api/application' + endpoint;
  const opts = {
    method,
    headers: {
      'Authorization': 'Bearer ' + PTERO_KEY,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
  };
  if (body) opts.body = JSON.stringify(body);
  try {
    const r    = await fetch(url, opts);
    const text = await r.text();
    return { code: r.status, body: text ? JSON.parse(text) : {} };
  } catch (e) {
    return { code: 500, body: { error: e.message } };
  }
}

// ── CORS + RESPONSE UTILS ──────────────────────────────────────────────
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
}

function ok(res, data, code = 200)  { cors(res); res.status(code).json(data); }
function err(res, msg, code = 400)  { cors(res); res.status(code).json({ error: msg }); }
function unauth(res)                { return err(res, 'Unauthorized', 401); }
function forbidden(res)             { return err(res, 'Akses ditolak', 403); }

// ── MAIN HANDLER ──────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  await connectDB();

  const url    = req.url.replace(/\?.*$/, '');
  const method = req.method;

  // ── PUBLIC: LOGIN ──────────────────────────────────────────────────
  if (url === '/api/login' && method === 'POST') {
    const { username, password } = req.body || {};
    if (!username || !password) return err(res, 'Username dan password wajib');

    const user = await User.findOne({
      $or: [{ username }, { email: username }],
      status: 'active',
    });
    if (!user) return err(res, 'Username atau password salah', 401);

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return err(res, 'Username atau password salah', 401);

    const token = signToken(user._id);
    res.setHeader('Set-Cookie', `auth_token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${TTL}`);
    await logActivity(user._id, 'login', null, 'Login berhasil');
    return ok(res, { success: true, token, user: safe(user) });
  }

  // ── PUBLIC: LOGOUT ──────────────────────────────────────────────────
  if (url === '/api/logout' && method === 'POST') {
    res.setHeader('Set-Cookie', 'auth_token=; Path=/; Max-Age=0');
    return ok(res, { success: true });
  }

  // ── ALL BELOW: AUTH REQUIRED ────────────────────────────────────────
  const me = await getMe(req);
  if (!me) return unauth(res);

  // ME
  if (url === '/api/me' && method === 'GET') {
    return ok(res, { user: safe(me) });
  }

  // STATS
  if (url === '/api/stats' && method === 'GET') {
    let totalUsers, suspended, byRole = {}, ptServers = 0;

    const filter = me.role === 'ceo' ? { role: { $ne: 'ceo' } } : { parentId: me._id };
    totalUsers = await User.countDocuments(filter);
    suspended  = await User.countDocuments({ ...filter, status: 'suspended' });

    for (const r of Object.keys(CAN_CREATE)) {
      byRole[r] = await User.countDocuments({ ...filter, role: r });
    }

    if (['ceo','owner','pt'].includes(me.role)) {
      const svR = await ptero('GET', '/servers?per_page=1');
      ptServers = svR.body?.meta?.pagination?.total || 0;
    }

    return ok(res, { totalUsers, suspended, byRole, ptServers });
  }

  // USERS LIST
  if (url === '/api/users' && method === 'GET') {
    const filter = me.role === 'ceo' ? {} : { parentId: me._id };
    const users  = await User.find(filter).select('-password').lean();
    // Inject parentUsername
    const parentIds = [...new Set(users.map(u => u.parentId?.toString()).filter(Boolean))];
    const parents   = await User.find({ _id: { $in: parentIds } }).select('username').lean();
    const pmap      = Object.fromEntries(parents.map(p => [p._id.toString(), p.username]));
    const out = users.map(u => ({ ...u, parentUsername: pmap[u.parentId?.toString()] || 'system' }));
    return ok(res, { data: out });
  }

  // CREATE USER
  if (url === '/api/users' && method === 'POST') {
    const { username, email, password, role, firstName, lastName, storageLimit, maxAccounts, notes } = req.body || {};
    if (!username || !email || !password || !role) return err(res, 'Field username, email, password, role wajib');
    if (!CAN_CREATE[me.role]?.includes(role)) return forbidden(res);
    if (me.maxAccounts !== null && me.accountsUsed >= me.maxAccounts) return err(res, 'Limit pembuatan akun tercapai');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err(res, 'Format email tidak valid');
    if (password.length < 6) return err(res, 'Password minimal 6 karakter');

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return err(res, exists.username === username ? 'Username sudah dipakai' : 'Email sudah dipakai');

    const hash    = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      username, email, password: hash, role,
      parentId: me._id,
      firstName: firstName || username,
      lastName:  lastName  || '',
      storageLimit: storageLimit ? parseInt(storageLimit) : null,
      maxAccounts:  maxAccounts  ? parseInt(maxAccounts)  : null,
      notes: notes || '',
    });

    // Update parent accountsUsed
    await User.findByIdAndUpdate(me._id, { $inc: { accountsUsed: 1 } });

    // Buat juga di Pterodactyl
    let pteroUserId = null;
    const ptRes = await ptero('POST', '/users', {
      username, email,
      first_name: firstName || username,
      last_name:  lastName  || '',
      password,
    });
    if (ptRes.code === 201) {
      pteroUserId = ptRes.body?.attributes?.id || null;
      if (pteroUserId) await User.findByIdAndUpdate(newUser._id, { pteroUserId });
    }

    await logActivity(me._id, 'create_user', newUser._id, `Buat ${username} (${role})`);
    return ok(res, { success: true, user: safe(newUser), pteroUserId }, 201);
  }

  // SUSPEND
  const suspendMatch = url.match(/^\/api\/users\/([^/]+)\/suspend$/);
  if (suspendMatch && method === 'POST') {
    const target = await User.findById(suspendMatch[1]);
    if (!target) return err(res, 'User tidak ditemukan', 404);
    if (ROLE_LEVEL[me.role] >= ROLE_LEVEL[target.role]) return forbidden(res);
    target.status = 'suspended';
    await target.save();
    await logActivity(me._id, 'suspend_user', target._id, `Suspend @${target.username}`);
    return ok(res, { success: true });
  }

  // UNSUSPEND
  const unsuspendMatch = url.match(/^\/api\/users\/([^/]+)\/unsuspend$/);
  if (unsuspendMatch && method === 'POST') {
    const target = await User.findById(unsuspendMatch[1]);
    if (!target) return err(res, 'User tidak ditemukan', 404);
    target.status = 'active';
    await target.save();
    await logActivity(me._id, 'unsuspend_user', target._id, `Aktifkan @${target.username}`);
    return ok(res, { success: true });
  }

  // DELETE USER
  const deleteUserMatch = url.match(/^\/api\/users\/([^/]+)$/);
  if (deleteUserMatch && method === 'DELETE') {
    const target = await User.findById(deleteUserMatch[1]);
    if (!target) return err(res, 'User tidak ditemukan', 404);
    if (ROLE_LEVEL[me.role] >= ROLE_LEVEL[target.role]) return forbidden(res);
    await User.findByIdAndDelete(target._id);
    await User.findByIdAndUpdate(target.parentId, { $inc: { accountsUsed: -1 } });
    await logActivity(me._id, 'delete_user', target._id, `Hapus @${target.username}`);
    return ok(res, { success: true });
  }

  // RESET PASSWORD
  const resetMatch = url.match(/^\/api\/users\/([^/]+)\/reset-password$/);
  if (resetMatch && method === 'POST') {
    const { password } = req.body || {};
    if (!password || password.length < 6) return err(res, 'Password minimal 6 karakter');
    const target = await User.findById(resetMatch[1]);
    if (!target) return err(res, 'User tidak ditemukan', 404);
    target.password = await bcrypt.hash(password, 10);
    await target.save();
    await logActivity(me._id, 'reset_password', target._id, `Reset pw @${target.username}`);
    return ok(res, { success: true });
  }

  // LOGS
  if (url === '/api/logs' && method === 'GET') {
    const logs = await Log.find({ $or: [{ userId: me._id }, { targetId: me._id }] })
      .sort({ createdAt: -1 }).limit(30).lean();
    return ok(res, { data: logs });
  }

  // ── PTERODACTYL PROXY ──────────────────────────────────────────────
  const ptGuard = () => {
    if (!['ceo','owner','pt'].includes(me.role)) { forbidden(res); return false; }
    return true;
  };

  if (url === '/api/ptero/servers' && method === 'GET') {
    if (!ptGuard()) return;
    const r = await ptero('GET', '/servers?include=user&per_page=50');
    return ok(res, r.body);
  }
  if (url === '/api/ptero/servers' && method === 'POST') {
    if (!ptGuard()) return;
    const r = await ptero('POST', '/servers', req.body);
    return res.status(r.code).json(r.body);
  }

  const svDelMatch    = url.match(/^\/api\/ptero\/servers\/(\d+)$/);
  const svSuspMatch   = url.match(/^\/api\/ptero\/servers\/(\d+)\/suspend$/);
  const svUnsuspMatch = url.match(/^\/api\/ptero\/servers\/(\d+)\/unsuspend$/);
  const svReinMatch   = url.match(/^\/api\/ptero\/servers\/(\d+)\/reinstall$/);

  if (svDelMatch    && method === 'DELETE') { if (!ptGuard()) return; const r = await ptero('DELETE', `/servers/${svDelMatch[1]}/force`);        return ok(res, { success: r.code === 204 }); }
  if (svSuspMatch   && method === 'POST')   { if (!ptGuard()) return; const r = await ptero('POST',   `/servers/${svSuspMatch[1]}/suspend`);      return ok(res, { success: r.code === 204 }); }
  if (svUnsuspMatch && method === 'POST')   { if (!ptGuard()) return; const r = await ptero('POST',   `/servers/${svUnsuspMatch[1]}/unsuspend`);  return ok(res, { success: r.code === 204 }); }
  if (svReinMatch   && method === 'POST')   { if (!ptGuard()) return; const r = await ptero('POST',   `/servers/${svReinMatch[1]}/reinstall`);    return ok(res, { success: r.code === 204 }); }

  if (url === '/api/ptero/nodes'     && method === 'GET') { if (!ptGuard()) return; const r = await ptero('GET', '/nodes');                                       return ok(res, r.body); }
  if (url === '/api/ptero/nests'     && method === 'GET') { const r = await ptero('GET', '/nests');                                                               return ok(res, r.body); }
  if (url === '/api/ptero/locations' && method === 'GET') { const r = await ptero('GET', '/locations');                                                           return ok(res, r.body); }
  if (url.startsWith('/api/ptero/eggs') && method === 'GET') {
    const nestId = req.url.match(/nest_id=(\d+)/)?.[1];
    if (!nestId) return err(res, 'nest_id wajib');
    const r = await ptero('GET', `/nests/${nestId}/eggs`);
    return ok(res, r.body);
  }

  // 404
  return err(res, 'Endpoint tidak ditemukan', 404);
};
