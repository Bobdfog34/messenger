const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const compression = require('compression');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' },
  maxHttpBufferSize: 50 * 1024 * 1024
});

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, 'data.json');
const UPLOAD_DIR = process.env.UPLOAD_DIR ? path.join(process.env.UPLOAD_DIR) : path.join(DATA_DIR, 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---- HTTP-сжатие (gzip) только для сжимаемых ассетов ----
const COMPRESSIBLE_RE = /\.(html?|js|mjs|css|json|map|svg|txt|wasm|xml|webmanifest)$/;
app.use(compression({
  threshold: 1024,
  level: 6,
  filter: (req, res) => {
    if (res.getHeader('Content-Encoding')) return false;
    return COMPRESSIBLE_RE.test(req.path);
  }
}));

app.use('/legacy', express.static('public'));
app.use('/uploads', express.static(UPLOAD_DIR));

const TG_DIR = path.join(__dirname, 'tg');
app.use('/tg', express.static(TG_DIR, {
  setHeaders: (res) => res.setHeader('Cache-Control', 'public, max-age=31536000, immutable')
}));
app.use(express.json());

const FLUTTER_BUILD = path.join(__dirname, 'public');
app.use(express.static(FLUTTER_BUILD, {
  setHeaders: (res, filePath) => {
    if (/\.(html?|js|json|wasm)$/.test(filePath)) {
      res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    }
  }
}));

// ---- Админ-панель ----
const ADMIN_DIR = path.join(__dirname, 'admin');
app.use('/admin', express.static(ADMIN_DIR, { index: 'index.html' }));

const adminPasswordFile = path.join(__dirname, 'admin', '.adminpass');
const adminTokens = new Set();

function getAdminPassword() {
  if (process.env.ADMIN_PASSWORD) return process.env.ADMIN_PASSWORD;
  try { return fs.readFileSync(adminPasswordFile, 'utf8').trim(); }
  catch (e) { return null; }
}

function createAdminPassword() {
  const pw = crypto.randomBytes(6).toString('hex');
  try {
    fs.mkdirSync(path.dirname(adminPasswordFile), { recursive: true });
    fs.writeFileSync(adminPasswordFile, pw, 'utf8');
  } catch (e) {}
  return pw;
}

function saveAdminPassword(pw) {
  try {
    fs.mkdirSync(path.dirname(adminPasswordFile), { recursive: true });
    fs.writeFileSync(adminPasswordFile, pw, 'utf8');
  } catch (e) {}
}

const auditLog = [];
function audit(action, detail) {
  const e = { time: Date.now(), action, detail: detail || '' };
  auditLog.push(e);
  if (auditLog.length > 200) auditLog.shift();
  try {
    fs.appendFileSync(path.join(__dirname, 'admin', 'audit.log'),
      new Date(e.time).toISOString() + ' | ' + action + ' | ' + (detail || '') + '\n', 'utf8');
  } catch (err) {}
}

function secureEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function adminAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token || !adminTokens.has(token)) return res.status(401).json({ error: 'Не авторизован' });
  next();
}

function adminUserView(id) {
  const u = state.users[id];
  if (!u) return null;
  let messageCount = 0;
  Object.values(state.privateMessages).forEach(arr => {
    arr.forEach(m => { if ((m.from === id || m.to === id) && !m.deleted) messageCount++; });
  });
  const p = getPublicUser(id);
  return {
    ...p,
    verified: !!u.verified,
    banned: !!u.banned,
    blocked: u.blocked || [],
    createdAt: u.createdAt || u.lastSeen || 0,
    messageCount,
    sysadmin: !!u.sysadmin
  };
}

function disconnectUser(id) {
  const set = userSockets.get(id);
  if (set) set.forEach(sk => { try { sk.emit('banned'); sk.disconnect(true); } catch (e) {} });
}

app.post('/api/admin/login', (req, res) => {
  const pw = getAdminPassword() || createAdminPassword();
  const input = (req.body.password || '');
  if (!secureEqual(input, pw)) return res.status(401).json({ error: 'Неверный пароль' });
  const token = crypto.randomBytes(24).toString('hex');
  adminTokens.add(token);
  audit('admin.login', 'успешный вход');
  res.json({ token });
});

app.post('/api/admin/password', adminAuth, (req, res) => {
  const pw = getAdminPassword() || createAdminPassword();
  if (!secureEqual(String(req.body.current || ''), pw)) {
    return res.status(401).json({ error: 'Текущий пароль неверный' });
  }
  const next = String(req.body.password || '');
  if (next.length < 6) return res.status(400).json({ error: 'Новый пароль минимум 6 символов' });
  saveAdminPassword(next);
  audit('admin.password', 'смена пароля');
  res.json({ ok: true });
});

app.get('/api/admin/audit', adminAuth, (req, res) => {
  res.json(auditLog.slice().reverse());
});

app.get('/api/admin/backup', adminAuth, (req, res) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="messenger-backup-' + Date.now() + '.json"');
  res.send(JSON.stringify(state, null, 2));
});

app.post('/api/admin/announcement', adminAuth, (req, res) => {
  const text = String(req.body.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Пустое объявление' });
  ensureSystemUser();
  const time = Date.now();
  const clean = text.slice(0, 500);
  const targets = Object.keys(state.users).filter(u => u !== SYSTEM_ID && !state.users[u].banned);
  for (const uid of targets) {
    const msg = saveMessage(SYSTEM_ID, uid, clean);
    io.to(`user:${uid}`).emit('newMessage', { msg, fromUser: getPublicUser(SYSTEM_ID) });
    io.to(`user:${uid}`).emit('unreadUpdate', { from: SYSTEM_ID, count: unreadCount(uid, SYSTEM_ID) });
  }
  saveData();
  io.emit('announcement', { text: clean, time });
  io.emit('chatListRefresh');
  audit('admin.announcement', 'рассылка ' + targets.length + ' пользователям: ' + clean.slice(0, 120));
  res.json({ ok: true, sent: targets.length });
});

app.post('/api/admin/chat/clear', adminAuth, (req, res) => {
  const a = String(req.body.a || '');
  const b = String(req.body.b || '');
  if (!a || !b || !state.users[a] || !state.users[b]) {
    return res.status(400).json({ error: 'Укажите двух пользователей' });
  }
  const key = [a, b].sort().join('|');
  if (state.privateMessages[key]) state.privateMessages[key] = [];
  saveData();
  io.to(`user:${a}`).emit('chatCleared', { friendId: b });
  io.to(`user:${b}`).emit('chatCleared', { friendId: a });
  io.emit('chatListRefresh');
  audit('admin.chat.clear', 'очищен чат ' + a + ' <-> ' + b);
  res.json({ ok: true });
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
  let messagesTotal = 0;
  Object.values(state.privateMessages).forEach(arr => {
    messagesTotal += arr.filter(m => !m.deleted).length;
  });
  res.json({
    users: Object.keys(state.users).length,
    online: Object.values(state.users).filter(u => u.online).length,
    verified: Object.values(state.users).filter(u => u.verified).length,
    banned: Object.values(state.users).filter(u => u.banned).length,
    messagesTotal,
    chatsTotal: Object.keys(state.directChats).length
  });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  const list = Object.keys(state.users)
    .map(adminUserView)
    .filter(Boolean)
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  res.json(list);
});

app.post('/api/admin/user', adminAuth, (req, res) => {
  const name = (req.body.name || '').trim();
  const username = normalizeUsername(req.body.username);
  const password = (req.body.password || '');
  if (!name || !username || password.length < 4) {
    return res.status(400).json({ error: 'Нужны: имя, ник и пароль (мин. 4 символа)' });
  }
  if (Object.values(state.users).some(u => u.username === username)) {
    return res.status(409).json({ error: 'Этот никнейм уже занят' });
  }
  const colors = ['#5470a8', '#8a4b7e', '#3a9b6a', '#a8573f', '#4b7ea8', '#a8763f', '#5b6ea8', '#a84b6e', '#2b6ea8', '#a84b8a'];
  const salt = uuidv4();
  const id = uuidv4();
  state.users[id] = {
    id,
    name,
    username,
    avatarColor: colors[Math.floor(Math.random() * colors.length)],
    online: false,
    lastSeen: Date.now(),
    blocked: [],
    bio: '',
    phone: '',
    avatar: '',
    muted: [],
    pinnedChats: [],
    salt,
    passwordHash: hashPassword(password, salt),
    verified: !!req.body.verified,
    banned: false,
    createdAt: Date.now()
  };
  saveData();
  audit('admin.user.create', 'создан @' + username + ' (' + name + ')');
  res.json(adminUserView(id));
});

app.patch('/api/admin/user/:id', adminAuth, (req, res) => {
  const u = state.users[req.params.id];
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  const d = req.body || {};
  if (d.name !== undefined) {
    const n = String(d.name).trim().slice(0, 30);
    if (n) u.name = n;
  }
  if (d.username !== undefined) {
    const un = normalizeUsername(d.username);
    if (un && !Object.values(state.users).some(x => x.username === un && x.id !== u.id)) u.username = un;
  }
  if (d.bio !== undefined) u.bio = String(d.bio).slice(0, 200);
  if (d.verified !== undefined) u.verified = !!d.verified;
  if (d.avatarColor !== undefined && /^#[0-9a-fA-F]{6}$/.test(d.avatarColor)) u.avatarColor = d.avatarColor;
  saveData();
  io.emit('chatListRefresh');
  broadcastPresence();
  audit('admin.user.edit', 'изменён @' + u.username);
  res.json(adminUserView(u.id));
});

app.post('/api/admin/user/:id/verify', adminAuth, (req, res) => {
  const u = state.users[req.params.id];
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  u.verified = !!req.body.verified;
  saveData();
  io.emit('chatListRefresh');
  broadcastPresence();
  audit('admin.user.verify', (u.verified ? 'выдана галочка' : 'снята галочка') + ' @' + u.username);
  res.json(adminUserView(u.id));
});

app.post('/api/admin/user/:id/ban', adminAuth, (req, res) => {
  const u = state.users[req.params.id];
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  if (u.sysadmin) return res.status(400).json({ error: 'Системного пользователя нельзя забанить' });
  u.banned = !!req.body.banned;
  saveData();
  if (u.banned) disconnectUser(u.id);
  io.emit('chatListRefresh');
  broadcastPresence();
  audit('admin.user.ban', (u.banned ? 'забанен' : 'разбанен') + ' @' + u.username);
  res.json(adminUserView(u.id));
});

app.post('/api/admin/user/:id/premium', adminAuth, (req, res) => {
  const u = state.users[req.params.id];
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  u.premium = !!req.body.premium;
  if (!u.premium) u.statusEmoji = '';
  saveData();
  io.emit('chatListRefresh');
  broadcastPresence();
  io.to(`user:${u.id}`).emit('premiumUpdated', { premium: !!u.premium, statusEmoji: u.statusEmoji || '' });
  audit('admin.user.premium', (u.premium ? 'выдан Премиум' : 'отозван Премиум') + ' @' + u.username);
  res.json(adminUserView(u.id));
});

app.post('/api/admin/user/:id/delete', adminAuth, (req, res) => {
  const id = req.params.id;
  if (!state.users[id]) return res.status(404).json({ error: 'Пользователь не найден' });
  if (state.users[id].sysadmin) return res.status(400).json({ error: 'Системного пользователя нельзя удалить' });
  disconnectUser(id);
  delete state.users[id];
  Object.keys(state.privateMessages).forEach(k => {
    const parts = k.split('|');
    if (parts[0] === id || parts[1] === id) delete state.privateMessages[k];
  });
  Object.keys(state.directChats).forEach(k => {
    state.directChats[k] = (state.directChats[k] || []).filter(x => x !== id);
    if (!state.directChats[k].length) delete state.directChats[k];
  });
  saveData();
  io.emit('chatListRefresh');
  broadcastPresence();
  audit('admin.user.delete', 'удалён пользователь ' + id);
  res.json({ ok: true });
});

app.post('/api/admin/user/:id/password', adminAuth, (req, res) => {
  const u = state.users[req.params.id];
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  const pw = (req.body.password || '');
  if (pw.length < 4) return res.status(400).json({ error: 'Пароль минимум 4 символа' });
  u.salt = uuidv4();
  u.passwordHash = hashPassword(pw, u.salt);
  saveData();
  audit('admin.user.password', 'сброшен пароль @' + u.username);
  res.json({ ok: true });
});

app.get('/api/admin/messages', adminAuth, (req, res) => {
  const userId = req.query.user;
  if (userId) {
    const rows = [];
    Object.entries(state.privateMessages).forEach(([k, arr]) => {
      const parts = k.split('|');
      if (parts[0] !== userId && parts[1] !== userId) return;
      const other = parts[0] === userId ? parts[1] : parts[0];
      const gu = state.users[other];
      arr.filter(m => !m.deleted).forEach(m => rows.push({
        ...m,
        other,
        otherName: gu ? gu.name : other,
        otherUsername: gu ? gu.username : ''
      }));
    });
    rows.sort((x, y) => x.time - y.time);
    return res.json(rows);
  }
  const all = [];
  Object.entries(state.privateMessages).forEach(([k, arr]) => {
    arr.filter(m => !m.deleted).forEach(m => all.push({
      ...m,
      fromName: (state.users[m.from] && state.users[m.from].name) || m.from,
      toName: (state.users[m.to] && state.users[m.to].name) || m.to
    }));
  });
  all.sort((x, y) => y.time - x.time);
  res.json(all.slice(0, 500));
});

app.post('/api/admin/message/delete', adminAuth, (req, res) => {
  const messageId = (req.body || {}).messageId;
  if (!messageId) return res.status(400).json({ error: 'Нет id сообщения' });
  for (const arr of Object.values(state.privateMessages)) {
    const m = arr.find(x => x.id === messageId);
    if (m) {
      m.deleted = true;
      saveData();
      io.to(`user:${m.from}`).emit('messageDeleted', { id: m.id, by: 'admin' });
      io.to(`user:${m.to}`).emit('messageDeleted', { id: m.id, by: 'admin' });
      io.emit('chatListRefresh');
      audit('admin.message.delete', 'удалено сообщение ' + m.id);
      return res.json({ ok: true });
    }
  }
  res.status(404).json({ error: 'Сообщение не найдено' });
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/legacy') || req.path.startsWith('/uploads') || req.path.startsWith('/emoji') || req.path.startsWith('/tg')) return next();
  res.sendFile(path.join(FLUTTER_BUILD, 'index.html'));
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '';
    cb(null, uuidv4() + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ---- Хранилище данных ----
let state = {
  users: {},
  privateMessages: {},
  directChats: {},
  pins: {},
  chatTimers: {},
  groups: {},
  groupMessages: {}
};

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      state = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('Ошибка загрузки данных:', e);
  }
  if (!state || typeof state !== 'object') state = {};
  state.users = state.users || {};
  state.privateMessages = state.privateMessages || {};
  state.directChats = state.directChats || {};
  state.pins = state.pins || {};
  state.chatTimers = state.chatTimers || {};
  state.groups = state.groups || {};
  state.groupMessages = state.groupMessages || {};
}

function saveData() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(state, null, 2));
  } catch (e) {
    console.error('Ошибка сохранения данных:', e);
  }
}

loadData();

// ---- Системный пользователь для рассылок ----
const SYSTEM_ID = 'afmvp';
function ensureSystemUser() {
  if (state.users[SYSTEM_ID]) return;
  state.users[SYSTEM_ID] = {
    id: SYSTEM_ID,
    name: 'AFVMP',
    username: 'afmvp',
    avatarColor: '#3390ec',
    online: true,
    lastSeen: Date.now(),
    blocked: [],
    bio: 'Официальные уведомления мессенджера',
    salt: uuidv4(),
    passwordHash: '',
    verified: true,
    banned: false,
    sysadmin: true,
    createdAt: 1
  };
  saveData();
}
ensureSystemUser();

// ---- Вспомогательные функции ----
function chatKey(a, b) {
  return [a, b].sort().join('|');
}

function getUser(userId) {
  return state.users[userId] || null;
}

function getPublicUser(userId) {
  const u = state.users[userId];
  if (!u) return null;
  ensureUserDefaults(u);
  return {
    id: u.id,
    username: u.username,
    name: u.name,
    avatarColor: u.avatarColor,
    avatar: u.avatar || '',
    phone: u.phone || '',
    online: !!u.online,
    lastSeen: u.lastSeen,
    bio: u.bio || '',
    verified: !!u.verified,
    createdAt: u.createdAt || 0,
    premium: !!u.premium,
    statusEmoji: u.statusEmoji || ''
  };
}

function saveMessage(fromId, toId, text, type = 'text', attachment = null, opts = {}) {
  const key = chatKey(fromId, toId);
  if (!state.privateMessages[key]) state.privateMessages[key] = [];
  const msg = {
    id: uuidv4(),
    from: fromId,
    to: toId,
    text,
    type,
    attachment,
    time: Date.now(),
    read: false,
    edited: false,
    deleted: false,
    reactions: {},
    hiddenFor: [],
    reply: opts.reply || null,
    fwd: opts.fwd || null
  };
  state.privateMessages[key].push(msg);

  if (!state.directChats[toId]) state.directChats[toId] = [];
  if (!state.directChats[toId].includes(fromId)) state.directChats[toId].push(fromId);
  if (!state.directChats[fromId]) state.directChats[fromId] = [];
  if (!state.directChats[fromId].includes(toId)) state.directChats[fromId].push(toId);

  saveData();

  if (opts.timer && opts.timer > 0) {
    scheduleMessageDelete(msg.id, key, opts.timer);
  }
  return msg;
}

const _deleteTimers = new Map();
function scheduleMessageDelete(msgId, key, seconds) {
  if (_deleteTimers.has(msgId)) clearTimeout(_deleteTimers.get(msgId));
  const t = setTimeout(() => {
    _deleteTimers.delete(msgId);
    const arr = state.privateMessages[key] || [];
    const msg = arr.find(m => m.id === msgId);
    if (!msg) return;
    msg.deleted = true;
    if (state.pins[key] === msgId) {
      delete state.pins[key];
      emitPinChange(msg.from, msg.to, null);
    }
    saveData();
    io.to(`user:${msg.to}`).emit('messageDeleted', { id: msgId, by: 'timer' });
    io.to(`user:${msg.from}`).emit('messageDeleted', { id: msgId, by: 'timer' });
    io.emit('chatListRefresh');
  }, seconds * 1000);
  t.unref && t.unref();
  _deleteTimers.set(msgId, t);
}

function deleteMessageSoft(msgId, byUserId, meOnly) {
  for (const [key, arr] of Object.entries(state.privateMessages)) {
    const idx = arr.findIndex(m => m.id === msgId);
    if (idx === -1) continue;
    const m = arr[idx];
    if (meOnly) {
      if (!m.hiddenFor) m.hiddenFor = [];
      if (!m.hiddenFor.includes(byUserId)) m.hiddenFor.push(byUserId);
      saveData();
      io.to(`user:${byUserId}`).emit('messageDeleted', { id: msgId, by: byUserId, meOnly: true });
      return { meOnly: true, m };
    }
    m.deleted = true;
    if (state.pins[key] === msgId) {
      delete state.pins[key];
    }
    saveData();
    io.to(`user:${m.to}`).emit('messageDeleted', { id: msgId, by: byUserId });
    io.to(`user:${m.from}`).emit('messageDeleted', { id: msgId, by: byUserId });
    emitPinChange(m.from, m.to, null);
    return { meOnly: false, m };
  }
  return null;
}

function emitPinChange(a, b, pinPayload) {
  io.to(`user:${a}`).emit('messagePinned', { to: b, pin: pinPayload });
  io.to(`user:${b}`).emit('messagePinned', { to: a, pin: pinPayload });
  io.emit('chatListRefresh');
}

function findOwnedMessage(userId, msgId) {
  for (const [key, arr] of Object.entries(state.privateMessages)) {
    const parts = key.split('|');
    if (parts[0] !== userId && parts[1] !== userId) continue;
    const m = arr.find(x => x.id === msgId && !x.deleted && !(x.hiddenFor || []).includes(userId));
    if (m) return m;
  }
  return null;
}

function sanitizeReply(r) {
  if (!r || typeof r !== 'object') return null;
  return {
    id: String(r.id || ''),
    from: String(r.from || ''),
    text: String(r.text || '').slice(0, 200),
    type: String(r.type || 'text'),
    fromName: String(r.fromName || ''),
    attachment: r.attachment || null
  };
}

// ---- Группы и каналы ----
function createGroup(userId, name, kind) {
  const id = uuidv4();
  const colors = ['#5470a8', '#8a4b7e', '#3a9b6a', '#a8573f', '#4b7ea8', '#a8763f', '#5b6ea8', '#a84b6e', '#2b6ea8', '#a84b8a'];
  const g = {
    id,
    kind: kind === 'channel' ? 'channel' : 'group',
    name: String(name || '').trim().slice(0, 40),
    avatarColor: colors[Math.floor(Math.random() * colors.length)],
    avatar: '',
    username: '',
    creator: userId,
    admins: [userId],
    members: [userId],
    verified: false,
    createdAt: Date.now(),
    pin: null
  };
  state.groups[id] = g;
  state.groupMessages[id] = [];
  saveData();
  return g;
}

function getPublicGroup(gid, viewerId) {
  const g = state.groups[gid];
  if (!g) return null;
  const last = (state.groupMessages[gid] || []).filter(m => !m.deleted);
  const lm = last.length ? last[last.length - 1] : null;
  const meUser = state.users[viewerId] || {};
  return {
    id: g.id,
    kind: g.kind,
    name: g.name,
    username: g.username || '',
    avatarColor: g.avatarColor,
    avatar: g.avatar || '',
    verified: g.verified,
    createdAt: g.createdAt,
    online: false,
    lastSeen: g.lastActivity || g.createdAt || 0,
    bio: '',
    phone: '',
    creator: g.creator,
    admins: g.admins,
    memberCount: g.members.length,
    isMember: g.members.includes(viewerId),
    admin: (g.admins || []).includes(viewerId),
    lastMessage: lm,
    unread: groupUnread(viewerId, gid),
    blocked: false,
    muted: (meUser.muted || []).includes(gid),
    pinned: (meUser.pinnedChats || []).includes(gid)
  };
}

function findGroupMessage(gid, msgId) {
  const arr = state.groupMessages[gid] || [];
  return arr.find(m => m.id === msgId);
}

function saveGroupMessage(gid, fromId, text, type = 'text', attachment = null, opts = {}) {
  if (!state.groupMessages[gid]) state.groupMessages[gid] = [];
  const g = state.groups[gid];
  const msg = {
    id: uuidv4(),
    from: fromId,
    text,
    type,
    attachment,
    time: Date.now(),
    read: false,
    edited: false,
    deleted: false,
    reactions: {},
    hiddenFor: [],
    readBy: [fromId],
    reply: opts.reply || null,
    fwd: opts.fwd || null
  };
  state.groupMessages[gid].push(msg);
  if (g) g.lastActivity = Date.now();
  saveData();
  return msg;
}

function groupUnread(userId, gid) {
  const arr = state.groupMessages[gid] || [];
  return arr.filter(m => !m.deleted && !(m.readBy || []).includes(userId) && m.from !== userId).length;
}

function joinGroupRooms(socket, userId) {
  Object.values(state.groups).forEach(g => {
    if (g.members.includes(userId)) socket.join('group:' + g.id);
  });
}

function emitGroupMessage(gid, msg, fromUser) {
  io.to('group:' + gid).emit('gNewMessage', { gid, msg, fromUser });
  io.emit('chatListRefresh');
}

function broadcastGroup(gid, event, payload) {
  io.to('group:' + gid).emit(event, payload);
  io.emit('chatListRefresh');
}

function findGroupByMember(gid, userId) {
  const g = state.groups[gid];
  return g && g.members.includes(userId) ? g : null;
}

function ensureUserDefaults(u) {
  if (!u.muted) u.muted = [];
  if (!u.pinnedChats) u.pinnedChats = [];
  if (u.premium === undefined) u.premium = false;
  if (!u.statusEmoji) u.statusEmoji = '';
}

function unreadCount(userId, fromId) {
  const key = chatKey(userId, fromId);
  const msgs = state.privateMessages[key] || [];
  return msgs.filter(m => m.to === userId && !m.read && !m.deleted && !(m.hiddenFor || []).includes(userId)).length;
}

function isBlocked(blockerId, blockedId) {
  const u = getUser(blockerId);
  return u && u.blocked && u.blocked.includes(blockedId);
}

// ---- REST ----
function normalizeUsername(raw) {
  return (raw || '').trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
}

function hashPassword(password, salt) {
  return crypto.createHash('sha256').update(salt + password).digest('hex');
}

function sanitizePublic(userId) {
  const p = getPublicUser(userId);
  return p;
}

app.post('/api/register', (req, res) => {
  const name = (req.body.name || '').trim();
  const username = normalizeUsername(req.body.username);
  const password = (req.body.password || '');
  if (!name) return res.status(400).json({ error: 'Укажите имя' });
  if (name.length > 30) return res.status(400).json({ error: 'Имя слишком длинное' });
  if (!username) return res.status(400).json({ error: 'Никнейм только латиницей (a-z, 0-9, _)' });
  if (password.length < 4) return res.status(400).json({ error: 'Пароль минимум 4 символа' });
  const existing = Object.values(state.users).find(u => u.username === username);
  if (existing) return res.status(409).json({ error: 'Этот никнейм уже занят. Выберите другой.' });

  const id = uuidv4();
  const colors = ['#5470a8', '#8a4b7e', '#3a9b6a', '#a8573f', '#4b7ea8', '#a8763f', '#5b6ea8', '#a84b6e', '#2b6ea8', '#a84b8a'];
  const salt = uuidv4();
  state.users[id] = {
    id,
    name,
    username,
    avatarColor: colors[Math.floor(Math.random() * colors.length)],
    online: false,
    lastSeen: Date.now(),
    blocked: [],
    bio: '',
    phone: '',
    avatar: '',
    muted: [],
    pinnedChats: [],
    salt,
    passwordHash: hashPassword(password, salt),
    verified: false,
    banned: false,
    createdAt: Date.now()
  };
  saveData();
  res.json({ user: getPublicUser(id) });
});

app.post('/api/login', (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = (req.body.password || '');
  if (!username || !password) return res.status(400).json({ error: 'Укажите никнейм и пароль' });
  const user = Object.values(state.users).find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  if (user.banned) return res.status(403).json({ error: 'Аккаунт заблокирован администратором' });
  if (user.passwordHash !== hashPassword(password, user.salt)) {
    return res.status(403).json({ error: 'Неверный пароль' });
  }
  res.json({ user: getPublicUser(user.id) });
});

app.get('/api/validate', (req, res) => {
  const id = req.query.id;
  const u = getUser(id);
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  if (u.banned) return res.status(403).json({ error: 'Аккаунт заблокирован администратором' });
  res.json({ user: getPublicUser(id) });
});

app.get('/api/users', (req, res) => {
  const me = req.query.me;
  const list = Object.values(state.users)
    .filter(u => u.id !== me && !isBlocked(u.id, me) && !isBlocked(me, u.id))
    .map(u => {
      const p = getPublicUser(u.id);
      p.unread = unreadCount(me, u.id);
      p.blocked = (state.users[me]?.blocked || []).includes(u.id);
      return p;
    })
    .sort((a, b) => {
      if (a.online !== b.online) return a.online ? -1 : 1;
      return (b.lastSeen || 0) - (a.lastSeen || 0);
    });
  res.json(list);
});

app.get('/api/search', (req, res) => {
  const me = req.query.me;
  const q = (req.query.q || '').trim().toLowerCase();
  if (!q) return res.json([]);
  const list = Object.values(state.users)
    .filter(u => u.id !== me && !isBlocked(u.id, me) && !isBlocked(me, u.id))
    .filter(u =>
      u.username.includes(q) ||
      u.name.toLowerCase().includes(q)
    )
    .slice(0, 30)
    .map(u => {
      const p = getPublicUser(u.id);
      p.unread = unreadCount(me, u.id);
      p.blocked = (state.users[me]?.blocked || []).includes(u.id);
      return p;
    })
    .sort((a, b) => {
      if (a.online !== b.online) return a.online ? -1 : 1;
      return (b.lastSeen || 0) - (a.lastSeen || 0);
    });
  res.json(list);
});

app.get('/api/messages', (req, res) => {
  const a = req.query.a;
  const b = req.query.b;
  if (!a || !b) return res.json({ messages: [], pin: null, timer: 0 });
  const key = chatKey(a, b);
  const msgs = (state.privateMessages[key] || [])
    .map(m => ({ ...m }))
    .filter(m => !m.deleted && !(m.hiddenFor || []).includes(a));
  state.privateMessages[key] = (state.privateMessages[key] || []).map(m =>
    m.to === a ? { ...m, read: true } : m
  );
  const pinId = state.pins[key];
  let pinMsg = null;
  if (pinId) {
    const pm = (state.privateMessages[key] || []).find(m => m.id === pinId && !m.deleted);
    if (pm) pinMsg = pm;
    else delete state.pins[key];
  }
  saveData();
  res.json({ messages: msgs, pin: pinMsg, timer: state.chatTimers[key] || 0 });
});

app.get('/api/search/messages', (req, res) => {
  const me = req.query.me;
  const q = (req.query.q || '').trim().toLowerCase();
  if (!me || !q) return res.json([]);
  const out = [];
  Object.entries(state.privateMessages).forEach(([k, arr]) => {
    const parts = k.split('|');
    if (parts[0] !== me && parts[1] !== me) return;
    const other = parts[0] === me ? parts[1] : parts[0];
    arr.forEach(m => {
      if (m.deleted || (m.hiddenFor || []).includes(me)) return;
      if ((m.text || '').toLowerCase().includes(q)) {
        const o = state.users[other];
        out.push({
          ...m,
          chatId: other,
          chatName: o ? o.name : other,
          chatUsername: o ? o.username : '',
          mine: m.from === me
        });
      }
    });
  });
  out.sort((a, b) => b.time - a.time);
  res.json(out.slice(0, 60));
});

app.get('/api/common', (req, res) => {
  const a = req.query.a;
  const b = req.query.b;
  if (!a || !b) return res.json({ medias: [], count: 0 });
  const key = chatKey(a, b);
  const msgs = (state.privateMessages[key] || []).filter(m => !m.deleted);
  res.json({
    count: msgs.length,
    medias: msgs
      .filter(m => m.type === 'image' || m.type === 'file' || m.type === 'video' || m.type === 'gif' || m.type === 'voice' || m.type === 'circle')
      .slice(-50)
      .reverse()
  });
});

app.get('/api/groups', (req, res) => {
  const me = req.query.me;
  const q = (req.query.q || '').trim().toLowerCase();
  if (!me) return res.json([]);
  let list = Object.values(state.groups).filter(g => g.members.includes(me));
  if (q) list = list.filter(g => g.name.toLowerCase().includes(q));
  res.json(list.map(g => getPublicGroup(g.id, me)).filter(Boolean));
});

app.get('/api/group/messages', (req, res) => {
  const me = req.query.me;
  const gid = req.query.g;
  const g = state.groups[gid];
  if (!g || !g.members.includes(me)) return res.status(403).json({ error: 'Доступ запрещён' });
  const arr = (state.groupMessages[gid] || []).map(m => ({ ...m })).filter(m => !m.deleted && !(m.hiddenFor || []).includes(me));
  const pin = g.pin ? (state.groupMessages[gid] || []).find(m => m.id === g.pin && !m.deleted) || null : null;
  state.groupMessages[gid] = (state.groupMessages[gid] || []).map(m => {
    if (m.from !== me && !(m.readBy || []).includes(me)) {
      return { ...m, readBy: [...(m.readBy || []), me] };
    }
    return m;
  });
  saveData();
  res.json({ messages: arr, pin, group: getPublicGroup(gid, me) });
});

app.get('/api/group/info', (req, res) => {
  const me = req.query.me;
  const gid = req.query.g;
  const g = state.groups[gid];
  if (!g) return res.status(404).json({ error: 'Группа не найдена' });
  const members = g.members.map(uid => {
    const u = state.users[uid];
    return u ? { ...getPublicUser(uid), isAdmin: (g.admins || []).includes(uid) } : null;
  }).filter(Boolean);
  res.json({ group: getPublicGroup(gid, me), members });
});

app.get('/api/blocked', (req, res) => {
  const me = req.query.me;
  const u = getUser(me);
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  const list = (u.blocked || [])
    .map(id => getUser(id))
    .filter(Boolean)
    .map(u2 => getPublicUser(u2.id));
  res.json(list);
});

// Прокси анимированных эмодзи с кэшем на диск
const EMOJI_DIR = path.join(__dirname, 'emoji_cache');
app.get('/emoji/:seq.gif', async (req, res) => {
  const seq = String(req.params.seq || '');
  if (!/^[0-9a-f_]+$/.test(seq)) return res.status(400).end();
  const p = path.join(EMOJI_DIR, seq + '.gif');
  if (fs.existsSync(p)) {
    res.setHeader('Content-Type', 'image/gif');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    return res.sendFile(p);
  }
  try {
    const r = await fetch('https://fonts.gstatic.com/s/e/notoemoji/latest/' + seq + '/512.gif');
    if (!r.ok) return res.status(502).end();
    const buf = Buffer.from(await r.arrayBuffer());
    if (!fs.existsSync(EMOJI_DIR)) fs.mkdirSync(EMOJI_DIR, { recursive: true });
    fs.writeFileSync(p, buf);
    res.setHeader('Content-Type', 'image/gif');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.end(buf);
  } catch (e) {
    res.status(502).end();
  }
});

// Загрузка файлов
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
  const isImage = req.file.mimetype.startsWith('image/');
  res.json({
    filename: req.file.filename,
    url: '/uploads/' + req.file.filename,
    originalname: req.file.originalname,
    mimetype: req.file.mimetype,
    size: req.file.size,
    type: isImage ? 'image' : 'file'
  });
});

// ---- Socket.IO ----
const userSockets = new Map();

io.on('connection', (socket) => {
  let userId = null;

  socket.on('login', (data) => {
    const user = getUser(data.userId);
    if (!user) { socket.emit('error', { error: 'Пользователь не найден' }); return; }
    if (user.banned) { socket.emit('error', { error: 'Аккаунт заблокирован администратором' }); return; }
    userId = user.id;
    socket.join(`user:${userId}`);
    joinGroupRooms(socket, userId);
    if (!userSockets.has(userId)) userSockets.set(userId, new Set());
    userSockets.get(userId).add(socket);
    user.online = true;
    user.lastSeen = Date.now();
    saveData();
    socket.emit('loggedIn', { user: getPublicUser(userId) });
    broadcastPresence();
    sendChatList(socket, userId);
  });

  socket.on('sendMessage', (data) => {
    if (!userId) return;
    const { to, text, type = 'text', attachment = null, reply = null } = data;
    if (!to || !getUser(to)) return;
    // проверка блокировки
    if (isBlocked(to, userId) || isBlocked(userId, to)) {
      return socket.emit('error', { error: 'Невозможно отправить сообщение' });
    }
    if (type === 'text' && (!text || !text.trim())) return;
    const key = chatKey(userId, to);
    const timer = state.chatTimers[key] || 0;
    const replyObj = sanitizeReply(reply);
    const msg = saveMessage(userId, to, (text || '').trim(), type, attachment, { reply: replyObj, timer });

    const fromUser = getPublicUser(userId);
    io.to(`user:${to}`).emit('newMessage', { msg, fromUser });
    io.to(`user:${userId}`).emit('newMessage', { msg, fromUser });
    io.to(`user:${to}`).emit('unreadUpdate', { from: userId, count: unreadCount(to, userId) });
    socket.emit('unreadUpdate', { from: to, count: unreadCount(userId, to) });
  });

  socket.on('forwardMessage', (data) => {
    if (!userId) return;
    const ids = Array.isArray(data.ids) ? data.ids : [];
    const to = data.to;
    if (!to || !getUser(to) || ids.length === 0) return;
    if (isBlocked(to, userId) || isBlocked(userId, to)) return;
    const keyTo = chatKey(userId, to);
    const timer = state.chatTimers[keyTo] || 0;
    const forwarded = [];
    for (const id of ids) {
      const src = findOwnedMessage(userId, id);
      if (!src) continue;
      const fwdFrom = state.users[src.from];
      const msg = saveMessage(userId, to, src.text || '', src.type || 'text', src.attachment || null, {
        fwd: {
          from: src.from,
          fromName: fwdFrom ? fwdFrom.name : 'Пользователь',
          time: src.time,
          text: (src.text || '').slice(0, 80),
          type: src.type || 'text'
        },
        timer
      });
      forwarded.push(msg);
    }
    if (forwarded.length === 0) return;
    const fromUser = getPublicUser(userId);
    for (const msg of forwarded) {
      io.to(`user:${to}`).emit('newMessage', { msg, fromUser });
      io.to(`user:${userId}`).emit('newMessage', { msg, fromUser });
    }
    io.to(`user:${to}`).emit('unreadUpdate', { from: userId, count: unreadCount(to, userId) });
    socket.emit('unreadUpdate', { from: to, count: unreadCount(userId, to) });
  });

  socket.on('pinMessage', (data) => {
    if (!userId) return;
    const { id, to } = data || {};
    if (!to || !getUser(to) || !id) return;
    const key = chatKey(userId, to);
    const arr = state.privateMessages[key] || [];
    const msg = arr.find(m => m.id === id && !m.deleted);
    if (!msg) return;
    if (state.pins[key] === id) {
      delete state.pins[key];
    } else {
      state.pins[key] = id;
    }
    saveData();
    const pinMsg = state.pins[key] ? { id: msg.id, text: msg.text, type: msg.type, from: msg.from, time: msg.time, attachment: msg.attachment } : null;
    emitPinChange(userId, to, pinMsg);
  });

  socket.on('setChatTimer', (data) => {
    if (!userId) return;
    const { to, seconds } = data || {};
    if (!to || !getUser(to)) return;
    const key = chatKey(userId, to);
    if (typeof seconds !== 'number' || seconds <= 0) {
      delete state.chatTimers[key];
    } else {
      state.chatTimers[key] = seconds;
    }
    saveData();
    socket.emit('chatTimerUpdated', { friendId: to, seconds: state.chatTimers[key] || 0 });
  });

  socket.on('setMuted', (data) => {
    if (!userId) return;
    const { chatId } = data || {};
    if (!chatId) return;
    const me = getUser(userId);
    if (!me.muted) me.muted = [];
    if (me.muted.includes(chatId)) me.muted = me.muted.filter(x => x !== chatId);
    else me.muted.push(chatId);
    saveData();
    socket.emit('mutedUpdated', { chatId, muted: me.muted.includes(chatId) });
  });

  socket.on('pinChat', (data) => {
    if (!userId) return;
    const { chatId } = data || {};
    if (!chatId || !(getUser(chatId) || state.groups[chatId])) return;
    const me = getUser(userId);
    if (!me.pinnedChats) me.pinnedChats = [];
    if (me.pinnedChats.includes(chatId)) me.pinnedChats = me.pinnedChats.filter(x => x !== chatId);
    else me.pinnedChats.push(chatId);
    saveData();
    socket.emit('chatListRefresh');
  });

  // ---- Группы и каналы ----
  socket.on('createGroup', (data) => {
    if (!userId) return;
    const g = createGroup(userId, (data || {}).name || 'Новая группа', (data || {}).kind || 'group');
    socket.join('group:' + g.id);
    saveData();
    socket.emit('groupCreated', { group: getPublicGroup(g.id, userId) });
    io.emit('chatListRefresh');
  });

  socket.on('groupMessage', (data) => {
    if (!userId) return;
    const { gid, text, type = 'text', attachment = null, reply = null } = data || {};
    const g = findGroupByMember(gid, userId);
    if (!g) return;
    if (g.kind === 'channel' && !(g.admins || []).includes(userId)) {
      return socket.emit('error', { error: 'Только администраторы могут публиковать в канал' });
    }
    if (type === 'text' && (!text || !text.trim())) return;
    const msg = saveGroupMessage(g.id, userId, (text || '').trim(), type, attachment, { reply: sanitizeReply(reply) });
    emitGroupMessage(g.id, msg, getPublicUser(userId));
  });

  socket.on('editGroupMessage', (data) => {
    if (!userId) return;
    const { gid, id, text } = data || {};
    const g = findGroupByMember(gid, userId);
    if (!g) return;
    const msg = findGroupMessage(gid, id);
    if (!msg || msg.from !== userId || msg.type !== 'text') return;
    msg.text = (text || '').trim();
    msg.edited = true;
    saveData();
    broadcastGroup(gid, 'gMessageEdited', { gid, id, text: msg.text });
  });

  socket.on('deleteGroupMessage', (data) => {
    if (!userId) return;
    const { gid, id, meOnly } = data || {};
    const g = findGroupByMember(gid, userId);
    if (!g) return;
    const msg = findGroupMessage(gid, id);
    if (!msg) return;
    if (meOnly) {
      if (!msg.hiddenFor) msg.hiddenFor = [];
      if (!msg.hiddenFor.includes(userId)) msg.hiddenFor.push(userId);
      saveData();
      socket.emit('gMessageDeleted', { gid, id });
      io.emit('chatListRefresh');
      return;
    }
    if (msg.from !== userId && !(g.admins || []).includes(userId)) return;
    msg.deleted = true;
    if (g.pin === id) { g.pin = null; broadcastGroup(gid, 'gPin', { gid, pin: null }); }
    saveData();
    broadcastGroup(gid, 'gMessageDeleted', { gid, id });
  });

  socket.on('reactGroupMessage', (data) => {
    if (!userId) return;
    const { gid, id, reaction } = data || {};
    const g = findGroupByMember(gid, userId);
    if (!g || !reaction) return;
    const msg = findGroupMessage(gid, id);
    if (!msg) return;
    if (!msg.reactions || typeof msg.reactions !== 'object') msg.reactions = {};
    if (!msg.reactions[reaction]) msg.reactions[reaction] = [];
    const list = msg.reactions[reaction];
    const idx = list.indexOf(userId);
    if (idx >= 0) list.splice(idx, 1); else list.push(userId);
    if (list.length === 0) delete msg.reactions[reaction];
    saveData();
    broadcastGroup(gid, 'gMessageReacted', { gid, id, reactions: msg.reactions || {} });
  });

  socket.on('pinGroupMessage', (data) => {
    if (!userId) return;
    const { gid, id } = data || {};
    const g = findGroupByMember(gid, userId);
    if (!g || !(g.admins || []).includes(userId)) return;
    const msg = findGroupMessage(gid, id);
    if (!msg || msg.deleted) return;
    if (g.pin === id) g.pin = null;
    else g.pin = id;
    saveData();
    const pin = g.pin ? { id: msg.id, text: msg.text, type: msg.type, from: msg.from, time: msg.time } : null;
    broadcastGroup(gid, 'gPin', { gid, pin });
  });

  socket.on('addGroupMembers', (data) => {
    if (!userId) return;
    const { gid, members } = data || {};
    const g = findGroupByMember(gid, userId);
    if (!g || !(g.admins || []).includes(userId)) return;
    const uids = Array.isArray(members) ? members.filter(u => getUser(u)) : [];
    uids.forEach(uid => {
      if (!g.members.includes(uid)) {
        g.members.push(uid);
        const set = userSockets.get(uid);
        if (set) set.forEach(sk => sk.join('group:' + gid));
      }
    });
    saveData();
    broadcastGroup(gid, 'gMembers', { gid });
  });

  socket.on('removeGroupMember', (data) => {
    if (!userId) return;
    const { gid, uid } = data || {};
    const g = findGroupByMember(gid, userId);
    if (!g || !(g.admins || []).includes(userId)) return;
    if (userId === uid) return;
    g.members = g.members.filter(x => x !== uid);
    g.admins = (g.admins || []).filter(x => x !== uid);
    const set = userSockets.get(uid);
    if (set) set.forEach(sk => { try { sk.leave('group:' + gid); } catch (e) {} });
    saveData();
    broadcastGroup(gid, 'gMembers', { gid });
    io.to(`user:${uid}`).emit('removedFromGroup', { gid });
  });

  socket.on('promoteAdmin', (data) => {
    if (!userId) return;
    const { gid, uid } = data || {};
    const g = findGroupByMember(gid, userId);
    if (!g || !(g.admins || []).includes(userId)) return;
    if (!g.members.includes(uid)) return;
    if (!g.admins) g.admins = [];
    if (g.admins.includes(uid)) g.admins = g.admins.filter(x => x !== uid);
    else g.admins.push(uid);
    saveData();
    broadcastGroup(gid, 'gMembers', { gid });
  });

  socket.on('setGroupInfo', (data) => {
    if (!userId) return;
    const { gid, name, avatarColor, avatar } = data || {};
    const g = findGroupByMember(gid, userId);
    if (!g || !(g.admins || []).includes(userId)) return;
    if (name !== undefined && String(name).trim()) g.name = String(name).trim().slice(0, 40);
    if (avatarColor !== undefined && /^#[0-9a-fA-F]{6}$/.test(avatarColor)) g.avatarColor = avatarColor;
    if (avatar !== undefined) g.avatar = avatar ? String(avatar) : '';
    saveData();
    broadcastGroup(gid, 'gInfo', { gid, group: getPublicGroup(gid, userId) });
  });

  socket.on('leaveGroup', (data) => {
    if (!userId) return;
    const { gid } = data || {};
    const g = state.groups[gid];
    if (!g || !g.members.includes(userId)) return;
    g.members = g.members.filter(x => x !== userId);
    g.admins = (g.admins || []).filter(x => x !== userId);
    if (g.members.length === 0) {
      delete state.groups[gid];
      delete state.groupMessages[gid];
    }
    saveData();
    try { socket.leave('group:' + gid); } catch (e) {}
    io.emit('chatListRefresh');
  });

  socket.on('deleteGroup', (data) => {
    if (!userId) return;
    const { gid } = data || {};
    const g = state.groups[gid];
    if (!g || g.creator !== userId) return;
    broadcastGroup(gid, 'gDeleted', { gid });
    delete state.groups[gid];
    delete state.groupMessages[gid];
    saveData();
  });

  socket.on('markGroupRead', (data) => {
    if (!userId) return;
    const { gid } = data || {};
    const g = findGroupByMember(gid, userId);
    if (!g) return;
    state.groupMessages[gid] = (state.groupMessages[gid] || []).map(m => {
      if (m.from !== userId && !(m.readBy || []).includes(userId)) {
        return { ...m, readBy: [...(m.readBy || []), userId] };
      }
      return m;
    });
    saveData();
    socket.emit('chatListRefresh');
  });

  socket.on('editMessage', (data) => {
    if (!userId) return;
    const { id, text, to } = data;
    const key = chatKey(userId, to);
    const arr = state.privateMessages[key] || [];
    const msg = arr.find(m => m.id === id && m.from === userId);
    if (!msg) return;
    if (msg.type === 'text') {
      msg.text = (text || '').trim();
      msg.edited = true;
      saveData();
      const fromUser = getPublicUser(userId);
      io.to(`user:${to}`).emit('messageEdited', { id, text: msg.text, to, from: userId });
      io.to(`user:${userId}`).emit('messageEdited', { id, text: msg.text, to, from: userId });
      io.to(`user:${to}`).emit('chatListRefresh');
      io.to(`user:${userId}`).emit('chatListRefresh');
    }
  });

  socket.on('deleteMessage', (data) => {
    if (!userId) return;
    const { id, meOnly } = data;
    deleteMessageSoft(id, userId, !!meOnly);
    if (meOnly) {
      socket.emit('chatListRefresh');
    } else {
      io.emit('chatListRefresh');
    }
  });

  socket.on('reactToMessage', (data) => {
    if (!userId) return;
    const { id, to, reaction } = data || {};
    if (!to || !getUser(to) || !reaction) return;
    if (isBlocked(to, userId) || isBlocked(userId, to)) return;
    const key = chatKey(userId, to);
    const arr = state.privateMessages[key] || [];
    const msg = arr.find(m => m.id === id);
    if (!msg) return;
    if (!msg.reactions || typeof msg.reactions !== 'object') msg.reactions = {};
    if (!msg.reactions[reaction]) msg.reactions[reaction] = [];
    const list = msg.reactions[reaction];
    const idx = list.indexOf(userId);
    if (idx >= 0) list.splice(idx, 1); else list.push(userId);
    if (list.length === 0) delete msg.reactions[reaction];
    saveData();
    const payload = { id, from: msg.from, to: msg.to, reactions: msg.reactions || {} };
    io.to(`user:${to}`).emit('messageReacted', payload);
    io.to(`user:${userId}`).emit('messageReacted', payload);
  });

  socket.on('clearChat', (data) => {
    if (!userId) return;
    const { friendId } = data;
    const key = chatKey(userId, friendId);
    if (state.privateMessages[key]) {
      state.privateMessages[key].forEach(m => { m.deleted = true; });
      saveData();
    }
    io.to(`user:${friendId}`).emit('chatCleared', { by: userId });
    socket.emit('chatCleared', { by: userId });
  });

  socket.on('markRead', (data) => {
    if (!userId) return;
    const { friendId } = data;
    const key = chatKey(userId, friendId);
    state.privateMessages[key] = (state.privateMessages[key] || []).map(m =>
      m.to === userId && m.from === friendId ? { ...m, read: true } : m
    );
    saveData();
    io.to(`user:${friendId}`).emit('readReceipt', { by: userId, friendId });
  });

  socket.on('typing', (data) => {
    if (!userId) return;
    const { to } = data;
    io.to(`user:${to}`).emit('typing', { from: userId });
  });

  socket.on('blockUser', (data) => {
    if (!userId) return;
    const { targetId } = data;
    const me = getUser(userId);
    if (!me) return;
    if (!me.blocked) me.blocked = [];
    if (!me.blocked.includes(targetId)) {
      me.blocked.push(targetId);
      saveData();
    }
    // Уведомить собеседника о новом статусе
    io.to(`user:${targetId}`).emit('userBlocked', { by: userId });
    broadcastPresence();
  });

  socket.on('unblockUser', (data) => {
    if (!userId) return;
    const { targetId } = data;
    const me = getUser(userId);
    if (!me || !me.blocked) return;
    me.blocked = me.blocked.filter(id => id !== targetId);
    saveData();
    io.to(`user:${targetId}`).emit('userUnblocked', { by: userId });
    broadcastPresence();
  });

  socket.on('updateBio', (data) => {
    if (!userId) return;
    const me = getUser(userId);
    if (!me) return;
    me.bio = (data.bio || '').slice(0, 200);
    saveData();
    socket.emit('bioUpdated', { bio: me.bio });
    broadcastPresence();
  });

  socket.on('updateProfile', (data) => {
    if (!userId) return;
    const me = getUser(userId);
    if (!me || !data) return;

    if (data.name !== undefined) {
      const name = (data.name || '').trim().slice(0, 30);
      if (name) me.name = name;
    }
    if (data.username !== undefined) {
      const username = normalizeUsername(data.username);
      if (username && username !== me.username) {
        const taken = Object.values(state.users).some(u => u.username === username && u.id !== userId);
        if (taken) {
          return socket.emit('profileUpdateError', { error: 'Этот никнейм уже занят' });
        }
        me.username = username;
      }
    }
    if (data.bio !== undefined) {
      me.bio = (data.bio || '').trim().slice(0, 200);
    }
    if (data.phone !== undefined) {
      me.phone = (data.phone || '').trim().slice(0, 30);
    }
    if (data.avatar !== undefined) {
      me.avatar = data.avatar ? String(data.avatar) : '';
    }

    saveData();
    socket.emit('profileUpdated', { user: getPublicUser(userId) });
    io.emit('chatListRefresh');
    broadcastPresence();
  });

  socket.on('setStatusEmoji', (data) => {
    if (!userId) return;
    const me = getUser(userId);
    if (!me) return;
    ensureUserDefaults(me);
    if (!me.premium) {
      return socket.emit('profileUpdateError', { error: 'Эмодзи-статус доступен только с Премиум' });
    }
    const emoji = (data && data.emoji ? String(data.emoji).trim() : '').slice(0, 16);
    me.statusEmoji = emoji;
    saveData();
    socket.emit('profileUpdated', { user: getPublicUser(userId) });
    io.emit('chatListRefresh');
    broadcastPresence();
  });

  socket.on('disconnect', () => {
    if (userId) {
      const set = userSockets.get(userId);
      if (set) {
        set.delete(socket);
        if (set.size === 0) userSockets.delete(userId);
      }
      const user = getUser(userId);
      if (user) {
        user.online = false;
        user.lastSeen = Date.now();
        saveData();
      }
      broadcastPresence();
    }
  });
});

function broadcastPresence() {
  const list = Object.values(state.users).map(u => ({
    id: u.id,
    online: !!u.online,
    lastSeen: u.lastSeen,
    blocked: u.blocked || [],
    verified: !!u.verified
  }));
  io.emit('presence', { users: list });
}

function sendChatList(socket, userId) {
  const meUser = state.users[userId] || {};
  const muted = meUser.muted || [];
  const pinned = meUser.pinnedChats || [];
  const contacts = (state.directChats[userId] || [])
    .filter(id => id !== userId)
    .map(id => {
      const u = getUser(id);
      if (!u) return null;
      if (isBlocked(u.id, userId) || isBlocked(userId, u.id)) return null;
      const p = getPublicUser(id);
      const key = chatKey(userId, id);
      const msgs = state.privateMessages[key] || [];
      const visibleMsgs = msgs.filter(m => !m.deleted && !(m.hiddenFor || []).includes(userId));
      p.lastMessage = visibleMsgs.length ? visibleMsgs[visibleMsgs.length - 1] : null;
      p.unread = unreadCount(userId, id);
      p.blocked = (state.users[userId]?.blocked || []).includes(id);
      p.muted = muted.includes(id);
      p.pinned = pinned.includes(id);
      return p;
    }).filter(Boolean);
  const groups = Object.values(state.groups)
    .filter(g => g.members.includes(userId))
    .map(g => getPublicGroup(g.id, userId))
    .filter(Boolean);
  const all = [...contacts, ...groups].sort((a, b) => {
    if (!!a.pinned !== !!b.pinned) return a.pinned ? -1 : 1;
    const ta = a.lastMessage ? a.lastMessage.time : (a.pinned ? 0 : 0);
    const tb = b.lastMessage ? b.lastMessage.time : (b.pinned ? 0 : 0);
    return tb - ta;
  });
  socket.emit('chatList', { contacts: all });
}

server.listen(PORT, () => {
  console.log(`Мессенджер запущен: http://localhost:${PORT}`);
});