const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const JWT_SECRET = 'whatsapp_clone_super_secret_2024';
const PORT = process.env.PORT || 3000;

const db = new Database('./chat.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, phone TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL,
    avatar TEXT DEFAULT NULL, about TEXT DEFAULT 'Hey there! I am using WhatsApp.',
    last_seen TEXT DEFAULT NULL, is_online INTEGER DEFAULT 0, lock_pin TEXT DEFAULT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, contact_id TEXT NOT NULL,
    nickname TEXT DEFAULT NULL, blocked INTEGER DEFAULT 0, is_favorite INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS groups_table (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '',
    avatar TEXT DEFAULT NULL, created_by TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS group_members (
    id TEXT PRIMARY KEY, group_id TEXT NOT NULL, user_id TEXT NOT NULL,
    role TEXT DEFAULT 'member', joined_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS communities (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '',
    avatar TEXT DEFAULT NULL, created_by TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS community_members (
    id TEXT PRIMARY KEY, community_id TEXT NOT NULL, user_id TEXT NOT NULL,
    role TEXT DEFAULT 'member', joined_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS channels (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '',
    avatar TEXT DEFAULT NULL, created_by TEXT DEFAULT 'system',
    followers_count INTEGER DEFAULT 0, verified INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS channel_followers (
    id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, user_id TEXT NOT NULL,
    followed_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY, sender_id TEXT NOT NULL, receiver_id TEXT, group_id TEXT,
    content TEXT, type TEXT DEFAULT 'text', media_url TEXT DEFAULT NULL,
    reply_to TEXT DEFAULT NULL, forwarded INTEGER DEFAULT 0,
    deleted_for_everyone INTEGER DEFAULT 0, starred INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS message_status (
    id TEXT PRIMARY KEY, message_id TEXT NOT NULL, user_id TEXT NOT NULL,
    status TEXT DEFAULT 'sent', updated_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS message_reactions (
    id TEXT PRIMARY KEY, message_id TEXT NOT NULL, user_id TEXT NOT NULL,
    emoji TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS status_updates (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, content TEXT, type TEXT DEFAULT 'text',
    media_url TEXT DEFAULT NULL, bg_color TEXT DEFAULT '#00a884',
    font_style TEXT DEFAULT 'normal', expires_at TEXT NOT NULL,
    views TEXT DEFAULT '[]', created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS locked_chats (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, chat_id TEXT NOT NULL,
    chat_type TEXT DEFAULT 'user', created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS calls (
    id TEXT PRIMARY KEY, caller_id TEXT NOT NULL, receiver_id TEXT NOT NULL,
    type TEXT DEFAULT 'voice', status TEXT DEFAULT 'missed',
    duration INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now'))
  );
`);

app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

const storage = multer.diskStorage({
  destination: (req, file, cb) => { const d = './uploads'; if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); cb(null, d); },
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 64 * 1024 * 1024 } });

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); } catch { res.status(401).json({ error: 'Invalid token' }); }
};

const onlineUsers = new Map();

app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, name, password } = req.body;
    if (!phone || !name || !password) return res.status(400).json({ error: 'All fields required' });
    if (db.prepare('SELECT id FROM users WHERE phone = ?').get(phone)) return res.status(400).json({ error: 'Phone already registered' });
    const id = uuidv4();
    db.prepare('INSERT INTO users (id, phone, name, password) VALUES (?, ?, ?, ?)').run(id, phone, name, await bcrypt.hash(password, 10));
    const token = jwt.sign({ id, phone, name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id, phone, name, avatar: null, about: 'Hey there! I am using WhatsApp.' } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
    if (!user || !await bcrypt.compare(password, user.password)) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, phone: user.phone, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, phone: user.phone, name: user.name, avatar: user.avatar, about: user.about, has_pin: !!user.lock_pin } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/me', auth, (req, res) => {
  const u = db.prepare('SELECT id, phone, name, avatar, about, last_seen, lock_pin FROM users WHERE id = ?').get(req.user.id);
  res.json({ ...u, has_pin: !!u.lock_pin, lock_pin: undefined });
});
app.put('/api/users/me', auth, (req, res) => {
  db.prepare('UPDATE users SET name = ?, about = ? WHERE id = ?').run(req.body.name, req.body.about, req.user.id);
  res.json({ success: true });
});
app.post('/api/users/avatar', auth, upload.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const url = `/uploads/${req.file.filename}`;
  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(url, req.user.id);
  res.json({ avatar: url });
});
app.post('/api/users/set-pin', auth, async (req, res) => {
  const { pin } = req.body;
  db.prepare('UPDATE users SET lock_pin = ? WHERE id = ?').run(pin ? await bcrypt.hash(pin, 10) : null, req.user.id);
  res.json({ success: true });
});
app.post('/api/users/verify-pin', auth, async (req, res) => {
  const u = db.prepare('SELECT lock_pin FROM users WHERE id = ?').get(req.user.id);
  res.json({ valid: u.lock_pin ? await bcrypt.compare(req.body.pin, u.lock_pin) : false });
});
app.get('/api/users/search', auth, (req, res) => {
  res.json(db.prepare('SELECT id, phone, name, avatar, about FROM users WHERE (phone LIKE ? OR name LIKE ?) AND id != ?').all(`%${req.query.q}%`, `%${req.query.q}%`, req.user.id));
});
app.get('/api/users/:id', auth, (req, res) => {
  const u = db.prepare('SELECT id, phone, name, avatar, about, last_seen, is_online FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json(u);
});

app.get('/api/contacts', auth, (req, res) => res.json(db.prepare(`SELECT c.id as cid, c.nickname, c.blocked, c.is_favorite, u.id, u.phone, u.name, u.avatar, u.about, u.last_seen, u.is_online FROM contacts c JOIN users u ON c.contact_id = u.id WHERE c.user_id = ?`).all(req.user.id)));
app.post('/api/contacts', auth, (req, res) => {
  const { contact_id, nickname } = req.body;
  if (db.prepare('SELECT id FROM contacts WHERE user_id = ? AND contact_id = ?').get(req.user.id, contact_id)) return res.status(400).json({ error: 'Already added' });
  const id = uuidv4();
  db.prepare('INSERT INTO contacts (id, user_id, contact_id, nickname) VALUES (?, ?, ?, ?)').run(id, req.user.id, contact_id, nickname || null);
  res.json({ success: true, id });
});
app.put('/api/contacts/:id/favorite', auth, (req, res) => {
  const c = db.prepare('SELECT * FROM contacts WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!c) return res.status(404).json({ error: 'Not found' });
  db.prepare('UPDATE contacts SET is_favorite = ? WHERE id = ?').run(c.is_favorite ? 0 : 1, req.params.id);
  res.json({ success: true });
});

app.get('/api/locked-chats', auth, (req, res) => res.json(db.prepare('SELECT * FROM locked_chats WHERE user_id = ?').all(req.user.id)));
app.post('/api/locked-chats', auth, (req, res) => {
  const { chat_id, chat_type } = req.body;
  if (!db.prepare('SELECT id FROM locked_chats WHERE user_id = ? AND chat_id = ?').get(req.user.id, chat_id))
    db.prepare('INSERT INTO locked_chats (id, user_id, chat_id, chat_type) VALUES (?, ?, ?, ?)').run(uuidv4(), req.user.id, chat_id, chat_type || 'user');
  res.json({ success: true });
});
app.delete('/api/locked-chats/:chatId', auth, (req, res) => {
  db.prepare('DELETE FROM locked_chats WHERE user_id = ? AND chat_id = ?').run(req.user.id, req.params.chatId);
  res.json({ success: true });
});

app.get('/api/chats', auth, (req, res) => {
  const lockedIds = db.prepare('SELECT chat_id FROM locked_chats WHERE user_id = ?').all(req.user.id).map(r => r.chat_id);
  const chats = db.prepare(`
    SELECT DISTINCT CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END as other_user_id,
    MAX(m.created_at) as last_message_time, m.content as last_content, m.type as last_type, m.sender_id as last_sender_id,
    u.name, u.avatar, u.is_online, u.last_seen,
    (SELECT COUNT(*) FROM messages WHERE sender_id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END AND receiver_id = ? AND deleted_for_everyone = 0 AND id NOT IN (SELECT message_id FROM message_status WHERE user_id = ? AND status = 'read')) as unread_count
    FROM messages m JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
    WHERE (m.sender_id = ? OR m.receiver_id = ?) AND m.receiver_id IS NOT NULL AND m.deleted_for_everyone = 0
    GROUP BY other_user_id ORDER BY last_message_time DESC
  `).all(req.user.id, req.user.id, req.user.id, req.user.id, req.user.id, req.user.id, req.user.id);
  res.json(chats.map(c => ({ ...c, is_locked: lockedIds.includes(c.other_user_id) })));
});

app.get('/api/messages/:userId', auth, (req, res) => {
  const msgs = db.prepare(`SELECT m.*, u.name as sender_name, u.avatar as sender_avatar, rm.content as reply_content, rm.type as reply_type, ru.name as reply_sender_name FROM messages m JOIN users u ON m.sender_id = u.id LEFT JOIN messages rm ON m.reply_to = rm.id LEFT JOIN users ru ON rm.sender_id = ru.id WHERE ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)) AND m.deleted_for_everyone = 0 ORDER BY m.created_at ASC LIMIT 200`).all(req.user.id, req.params.userId, req.params.userId, req.user.id);
  const ids = msgs.map(m => m.id);
  let reactions = ids.length ? db.prepare(`SELECT mr.*, u.name as user_name FROM message_reactions mr JOIN users u ON mr.user_id = u.id WHERE mr.message_id IN (${ids.map(() => '?').join(',')})`).all(...ids) : [];
  const rm = {}; reactions.forEach(r => { if (!rm[r.message_id]) rm[r.message_id] = []; rm[r.message_id].push(r); });
  res.json(msgs.map(m => ({ ...m, reactions: rm[m.id] || [] })));
});
app.get('/api/messages/group/:groupId', auth, (req, res) => {
  res.json(db.prepare(`SELECT m.*, u.name as sender_name, u.avatar as sender_avatar FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.group_id = ? AND m.deleted_for_everyone = 0 ORDER BY m.created_at ASC LIMIT 200`).all(req.params.groupId));
});
app.post('/api/messages', auth, upload.single('media'), (req, res) => {
  const { receiver_id, group_id, content, type, reply_to, forwarded } = req.body;
  const id = uuidv4();
  const media_url = req.file ? `/uploads/${req.file.filename}` : null;
  db.prepare('INSERT INTO messages (id, sender_id, receiver_id, group_id, content, type, media_url, reply_to, forwarded) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(id, req.user.id, receiver_id || null, group_id || null, content || null, type || 'text', media_url, reply_to || null, forwarded ? 1 : 0);
  const msg = { ...db.prepare(`SELECT m.*, u.name as sender_name, u.avatar as sender_avatar FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = ?`).get(id), reactions: [] };
  if (receiver_id) { const rs = onlineUsers.get(receiver_id); if (rs) io.to(rs).emit('new_message', msg); const ss = onlineUsers.get(req.user.id); if (ss) io.to(ss).emit('message_sent', msg); }
  if (group_id) io.to(`group_${group_id}`).emit('new_group_message', msg);
  res.json(msg);
});
app.delete('/api/messages/:id', auth, (req, res) => {
  if (req.body.for_everyone) { db.prepare('UPDATE messages SET deleted_for_everyone = 1, content = null, media_url = null WHERE id = ? AND sender_id = ?').run(req.params.id, req.user.id); io.emit('message_deleted', { id: req.params.id }); }
  res.json({ success: true });
});
app.post('/api/messages/:id/reaction', auth, (req, res) => {
  const { emoji } = req.body;
  const ex = db.prepare('SELECT id FROM message_reactions WHERE message_id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (ex) { emoji ? db.prepare('UPDATE message_reactions SET emoji = ? WHERE id = ?').run(emoji, ex.id) : db.prepare('DELETE FROM message_reactions WHERE id = ?').run(ex.id); }
  else if (emoji) db.prepare('INSERT INTO message_reactions (id, message_id, user_id, emoji) VALUES (?, ?, ?, ?)').run(uuidv4(), req.params.id, req.user.id, emoji);
  io.emit('reaction_updated', { message_id: req.params.id });
  res.json({ success: true });
});
app.post('/api/messages/:id/star', auth, (req, res) => {
  const m = db.prepare('SELECT starred FROM messages WHERE id = ?').get(req.params.id);
  db.prepare('UPDATE messages SET starred = ? WHERE id = ?').run(m.starred ? 0 : 1, req.params.id);
  res.json({ starred: !m.starred });
});

app.get('/api/groups', auth, (req, res) => res.json(db.prepare(`SELECT g.* FROM groups_table g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = ?`).all(req.user.id)));
app.post('/api/groups', auth, upload.single('avatar'), (req, res) => {
  const { name, description, members } = req.body;
  const id = uuidv4(); const avatar = req.file ? `/uploads/${req.file.filename}` : null;
  db.prepare('INSERT INTO groups_table (id, name, description, avatar, created_by) VALUES (?, ?, ?, ?, ?)').run(id, name, description || '', avatar, req.user.id);
  db.prepare('INSERT INTO group_members (id, group_id, user_id, role) VALUES (?, ?, ?, ?)').run(uuidv4(), id, req.user.id, 'admin');
  JSON.parse(members || '[]').forEach(uid => db.prepare('INSERT INTO group_members (id, group_id, user_id) VALUES (?, ?, ?)').run(uuidv4(), id, uid));
  res.json({ id, name, description, avatar });
});
app.get('/api/groups/:id/members', auth, (req, res) => res.json(db.prepare(`SELECT gm.role, gm.joined_at, u.id, u.name, u.avatar, u.phone, u.is_online FROM group_members gm JOIN users u ON gm.user_id = u.id WHERE gm.group_id = ?`).all(req.params.id)));

app.get('/api/communities', auth, (req, res) => res.json(db.prepare(`SELECT c.* FROM communities c JOIN community_members cm ON c.id = cm.community_id WHERE cm.user_id = ?`).all(req.user.id)));
app.post('/api/communities', auth, upload.single('avatar'), (req, res) => {
  const { name, description } = req.body; const id = uuidv4(); const avatar = req.file ? `/uploads/${req.file.filename}` : null;
  db.prepare('INSERT INTO communities (id, name, description, avatar, created_by) VALUES (?, ?, ?, ?, ?)').run(id, name, description || '', avatar, req.user.id);
  db.prepare('INSERT INTO community_members (id, community_id, user_id, role) VALUES (?, ?, ?, ?)').run(uuidv4(), id, req.user.id, 'admin');
  res.json({ id, name, description, avatar });
});

app.get('/api/channels', auth, (req, res) => {
  res.json({ following: db.prepare(`SELECT ch.* FROM channels ch JOIN channel_followers cf ON ch.id = cf.channel_id WHERE cf.user_id = ?`).all(req.user.id), suggested: db.prepare(`SELECT * FROM channels WHERE id NOT IN (SELECT channel_id FROM channel_followers WHERE user_id = ?) LIMIT 10`).all(req.user.id) });
});
app.post('/api/channels/:id/follow', auth, (req, res) => {
  if (!db.prepare('SELECT id FROM channel_followers WHERE channel_id = ? AND user_id = ?').get(req.params.id, req.user.id)) {
    db.prepare('INSERT INTO channel_followers (id, channel_id, user_id) VALUES (?, ?, ?)').run(uuidv4(), req.params.id, req.user.id);
    db.prepare('UPDATE channels SET followers_count = followers_count + 1 WHERE id = ?').run(req.params.id);
  }
  res.json({ success: true });
});

app.get('/api/status', auth, (req, res) => {
  res.json(db.prepare(`SELECT s.*, u.name, u.avatar FROM status_updates s JOIN users u ON s.user_id = u.id WHERE s.expires_at > ? AND (s.user_id = ? OR s.user_id IN (SELECT contact_id FROM contacts WHERE user_id = ?)) ORDER BY s.created_at DESC`).all(new Date().toISOString(), req.user.id, req.user.id));
});
app.post('/api/status', auth, upload.single('media'), (req, res) => {
  const { content, type, bg_color, font_style } = req.body; const id = uuidv4();
  db.prepare('INSERT INTO status_updates (id, user_id, content, type, media_url, bg_color, font_style, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id, req.user.id, content || null, type || 'text', req.file ? `/uploads/${req.file.filename}` : null, bg_color || '#00a884', font_style || 'normal', new Date(Date.now() + 86400000).toISOString());
  res.json({ success: true, id });
});
app.post('/api/status/:id/view', auth, (req, res) => {
  const s = db.prepare('SELECT views FROM status_updates WHERE id = ?').get(req.params.id);
  if (s) { const v = JSON.parse(s.views || '[]'); if (!v.includes(req.user.id)) { v.push(req.user.id); db.prepare('UPDATE status_updates SET views = ? WHERE id = ?').run(JSON.stringify(v), req.params.id); } }
  res.json({ success: true });
});
app.delete('/api/status/:id', auth, (req, res) => { db.prepare('DELETE FROM status_updates WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id); res.json({ success: true }); });

app.get('/api/calls', auth, (req, res) => res.json(db.prepare(`SELECT c.*, u.name as other_name, u.avatar as other_avatar FROM calls c JOIN users u ON u.id = CASE WHEN c.caller_id = ? THEN c.receiver_id ELSE c.caller_id END WHERE c.caller_id = ? OR c.receiver_id = ? ORDER BY c.created_at DESC LIMIT 50`).all(req.user.id, req.user.id, req.user.id)));
app.post('/api/calls', auth, (req, res) => {
  db.prepare('INSERT INTO calls (id, caller_id, receiver_id, type, status, duration) VALUES (?, ?, ?, ?, ?, ?)').run(uuidv4(), req.user.id, req.body.receiver_id, req.body.type || 'voice', req.body.status || 'missed', req.body.duration || 0);
  res.json({ success: true });
});

app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: `/uploads/${req.file.filename}` });
});

// Seed channels
const seedChannels = () => {
  if (db.prepare('SELECT COUNT(*) as c FROM channels').get().c === 0) {
    [{ name: 'WhatsApp', desc: 'Official WhatsApp channel', v: 1, f: 500000000 }, { name: 'Tech Daily', desc: 'Latest technology updates', v: 1, f: 2500000 }, { name: 'Sports Hub', desc: 'Sports scores & highlights', v: 0, f: 1200000 }, { name: 'News Today', desc: 'Breaking news 24/7', v: 1, f: 5000000 }]
      .forEach(ch => db.prepare('INSERT INTO channels (id, name, description, verified, followers_count) VALUES (?, ?, ?, ?, ?)').run(uuidv4(), ch.name, ch.desc, ch.v, ch.f));
  }
};
seedChannels();

io.use((socket, next) => { try { socket.user = jwt.verify(socket.handshake.auth.token, JWT_SECRET); next(); } catch { next(new Error('Invalid token')); } });

io.on('connection', (socket) => {
  const uid = socket.user.id;
  onlineUsers.set(uid, socket.id);
  db.prepare("UPDATE users SET is_online = 1, last_seen = datetime('now') WHERE id = ?").run(uid);
  io.emit('user_status', { userId: uid, is_online: true });
  db.prepare('SELECT group_id FROM group_members WHERE user_id = ?').all(uid).forEach(g => socket.join(`group_${g.group_id}`));

  socket.on('typing', ({ to, isGroup }) => { if (isGroup) socket.to(`group_${to}`).emit('user_typing', { userId: uid, chatId: to }); else { const s = onlineUsers.get(to); if (s) io.to(s).emit('user_typing', { userId: uid, chatId: uid }); } });
  socket.on('stop_typing', ({ to, isGroup }) => { if (isGroup) socket.to(`group_${to}`).emit('user_stop_typing', { userId: uid }); else { const s = onlineUsers.get(to); if (s) io.to(s).emit('user_stop_typing', { userId: uid }); } });
  socket.on('messages_read', ({ senderId }) => { const s = onlineUsers.get(senderId); if (s) io.to(s).emit('messages_read', { by: uid }); });
  socket.on('call_offer', ({ to, offer, type }) => { const s = onlineUsers.get(to); if (s) io.to(s).emit('call_offer', { from: uid, offer, type }); });
  socket.on('call_answer', ({ to, answer }) => { const s = onlineUsers.get(to); if (s) io.to(s).emit('call_answer', { from: uid, answer }); });
  socket.on('call_ice', ({ to, candidate }) => { const s = onlineUsers.get(to); if (s) io.to(s).emit('call_ice', { from: uid, candidate }); });
  socket.on('call_end', ({ to }) => { const s = onlineUsers.get(to); if (s) io.to(s).emit('call_ended', { from: uid }); });
  socket.on('call_reject', ({ to }) => { const s = onlineUsers.get(to); if (s) io.to(s).emit('call_rejected', { from: uid }); });
  socket.on('disconnect', () => { onlineUsers.delete(uid); const ls = new Date().toISOString(); db.prepare('UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?').run(ls, uid); io.emit('user_status', { userId: uid, is_online: false, last_seen: ls }); });
});

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
