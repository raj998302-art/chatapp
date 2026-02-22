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

const JWT_SECRET = 'whatsapp_clone_super_secret_key_2024';
const PORT = process.env.PORT || 3000;

// Database setup
const db = new Database('./chat.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    phone TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    avatar TEXT DEFAULT NULL,
    about TEXT DEFAULT 'Hey there! I am using WhatsApp Clone.',
    last_seen TEXT DEFAULT NULL,
    is_online INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    contact_id TEXT NOT NULL,
    nickname TEXT DEFAULT NULL,
    blocked INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (contact_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    avatar TEXT DEFAULT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS group_members (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    joined_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (group_id) REFERENCES groups(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    sender_id TEXT NOT NULL,
    receiver_id TEXT,
    group_id TEXT,
    content TEXT,
    type TEXT DEFAULT 'text',
    media_url TEXT DEFAULT NULL,
    reply_to TEXT DEFAULT NULL,
    forwarded INTEGER DEFAULT 0,
    deleted_for_everyone INTEGER DEFAULT 0,
    starred INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (sender_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS message_status (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    status TEXT DEFAULT 'sent',
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (message_id) REFERENCES messages(id)
  );

  CREATE TABLE IF NOT EXISTS message_reactions (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    emoji TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (message_id) REFERENCES messages(id)
  );

  CREATE TABLE IF NOT EXISTS status_updates (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    content TEXT,
    type TEXT DEFAULT 'text',
    media_url TEXT DEFAULT NULL,
    bg_color TEXT DEFAULT '#128C7E',
    expires_at TEXT NOT NULL,
    views TEXT DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS calls (
    id TEXT PRIMARY KEY,
    caller_id TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    type TEXT DEFAULT 'voice',
    status TEXT DEFAULT 'missed',
    duration INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = './uploads';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, uuidv4() + path.extname(file.originalname));
  }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// Auth middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Socket user map
const onlineUsers = new Map(); // userId -> socketId

// ==================== AUTH ROUTES ====================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, name, password } = req.body;
    if (!phone || !name || !password) return res.status(400).json({ error: 'All fields required' });
    const existing = db.prepare('SELECT id FROM users WHERE phone = ?').get(phone);
    if (existing) return res.status(400).json({ error: 'Phone already registered' });
    const hashed = await bcrypt.hash(password, 10);
    const id = uuidv4();
    db.prepare('INSERT INTO users (id, phone, name, password) VALUES (?, ?, ?, ?)').run(id, phone, name, hashed);
    const token = jwt.sign({ id, phone, name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id, phone, name, avatar: null, about: 'Hey there! I am using WhatsApp Clone.' } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
    if (!user) return res.status(400).json({ error: 'User not found' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid password' });
    const token = jwt.sign({ id: user.id, phone: user.phone, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, phone: user.phone, name: user.name, avatar: user.avatar, about: user.about } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== USER ROUTES ====================

app.get('/api/users/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, phone, name, avatar, about, last_seen FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

app.put('/api/users/me', auth, (req, res) => {
  const { name, about } = req.body;
  db.prepare('UPDATE users SET name = ?, about = ? WHERE id = ?').run(name, about, req.user.id);
  res.json({ success: true });
});

app.post('/api/users/avatar', auth, upload.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const url = `/uploads/${req.file.filename}`;
  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(url, req.user.id);
  res.json({ avatar: url });
});

app.get('/api/users/search', auth, (req, res) => {
  const { q } = req.query;
  const users = db.prepare('SELECT id, phone, name, avatar, about FROM users WHERE (phone LIKE ? OR name LIKE ?) AND id != ?').all(`%${q}%`, `%${q}%`, req.user.id);
  res.json(users);
});

app.get('/api/users/:id', auth, (req, res) => {
  const user = db.prepare('SELECT id, phone, name, avatar, about, last_seen, is_online FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json(user);
});

// ==================== CONTACTS ROUTES ====================

app.get('/api/contacts', auth, (req, res) => {
  const contacts = db.prepare(`
    SELECT c.id as contact_entry_id, c.nickname, c.blocked, c.created_at,
           u.id, u.phone, u.name, u.avatar, u.about, u.last_seen, u.is_online
    FROM contacts c
    JOIN users u ON c.contact_id = u.id
    WHERE c.user_id = ?
  `).all(req.user.id);
  res.json(contacts);
});

app.post('/api/contacts', auth, (req, res) => {
  const { contact_id, nickname } = req.body;
  const existing = db.prepare('SELECT id FROM contacts WHERE user_id = ? AND contact_id = ?').get(req.user.id, contact_id);
  if (existing) return res.status(400).json({ error: 'Contact already added' });
  const id = uuidv4();
  db.prepare('INSERT INTO contacts (id, user_id, contact_id, nickname) VALUES (?, ?, ?, ?)').run(id, req.user.id, contact_id, nickname || null);
  res.json({ success: true, id });
});

app.delete('/api/contacts/:id', auth, (req, res) => {
  db.prepare('DELETE FROM contacts WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ success: true });
});

// ==================== MESSAGES ROUTES ====================

app.get('/api/messages/:userId', auth, (req, res) => {
  const messages = db.prepare(`
    SELECT m.*, 
           u.name as sender_name, u.avatar as sender_avatar,
           rm.content as reply_content, rm.type as reply_type,
           ru.name as reply_sender_name
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    LEFT JOIN messages rm ON m.reply_to = rm.id
    LEFT JOIN users ru ON rm.sender_id = ru.id
    WHERE ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
    AND m.deleted_for_everyone = 0
    ORDER BY m.created_at ASC
    LIMIT 100
  `).all(req.user.id, req.params.userId, req.params.userId, req.user.id);
  
  // Mark as read
  db.prepare(`
    UPDATE message_status SET status = 'read', updated_at = datetime('now')
    WHERE message_id IN (
      SELECT id FROM messages WHERE sender_id = ? AND receiver_id = ?
    ) AND user_id = ? AND status != 'read'
  `).run(req.params.userId, req.user.id, req.user.id);
  
  // Fetch reactions
  const msgIds = messages.map(m => m.id);
  let reactions = [];
  if (msgIds.length > 0) {
    const placeholders = msgIds.map(() => '?').join(',');
    reactions = db.prepare(`SELECT mr.*, u.name as user_name FROM message_reactions mr JOIN users u ON mr.user_id = u.id WHERE mr.message_id IN (${placeholders})`).all(...msgIds);
  }
  
  const reactionsMap = {};
  reactions.forEach(r => {
    if (!reactionsMap[r.message_id]) reactionsMap[r.message_id] = [];
    reactionsMap[r.message_id].push(r);
  });
  
  const result = messages.map(m => ({ ...m, reactions: reactionsMap[m.id] || [] }));
  res.json(result);
});

app.get('/api/messages/group/:groupId', auth, (req, res) => {
  const messages = db.prepare(`
    SELECT m.*, u.name as sender_name, u.avatar as sender_avatar
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    WHERE m.group_id = ? AND m.deleted_for_everyone = 0
    ORDER BY m.created_at ASC
    LIMIT 100
  `).all(req.params.groupId);
  res.json(messages);
});

app.post('/api/messages', auth, upload.single('media'), (req, res) => {
  const { receiver_id, group_id, content, type, reply_to, forwarded } = req.body;
  const id = uuidv4();
  const media_url = req.file ? `/uploads/${req.file.filename}` : null;
  db.prepare('INSERT INTO messages (id, sender_id, receiver_id, group_id, content, type, media_url, reply_to, forwarded) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
    id, req.user.id, receiver_id || null, group_id || null, content || null, type || 'text', media_url, reply_to || null, forwarded ? 1 : 0
  );
  
  const message = db.prepare(`
    SELECT m.*, u.name as sender_name, u.avatar as sender_avatar
    FROM messages m JOIN users u ON m.sender_id = u.id
    WHERE m.id = ?
  `).get(id);
  
  // Emit via socket
  if (receiver_id) {
    const receiverSocket = onlineUsers.get(receiver_id);
    if (receiverSocket) {
      io.to(receiverSocket).emit('new_message', { ...message, reactions: [] });
      // Update status to delivered
      db.prepare('INSERT OR REPLACE INTO message_status (id, message_id, user_id, status) VALUES (?, ?, ?, ?)').run(uuidv4(), id, receiver_id, 'delivered');
    }
    // Notify sender too
    const senderSocket = onlineUsers.get(req.user.id);
    if (senderSocket) {
      io.to(senderSocket).emit('message_sent', { ...message, reactions: [] });
    }
  }
  
  if (group_id) {
    io.to(`group_${group_id}`).emit('new_group_message', { ...message, reactions: [] });
  }
  
  res.json({ ...message, reactions: [] });
});

app.delete('/api/messages/:id', auth, (req, res) => {
  const { for_everyone } = req.body;
  if (for_everyone) {
    db.prepare('UPDATE messages SET deleted_for_everyone = 1, content = null, media_url = null WHERE id = ? AND sender_id = ?').run(req.params.id, req.user.id);
    io.emit('message_deleted', { id: req.params.id, for_everyone: true });
  }
  res.json({ success: true });
});

app.post('/api/messages/:id/reaction', auth, (req, res) => {
  const { emoji } = req.body;
  const existing = db.prepare('SELECT id FROM message_reactions WHERE message_id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (existing) {
    if (emoji) {
      db.prepare('UPDATE message_reactions SET emoji = ? WHERE id = ?').run(emoji, existing.id);
    } else {
      db.prepare('DELETE FROM message_reactions WHERE id = ?').run(existing.id);
    }
  } else if (emoji) {
    db.prepare('INSERT INTO message_reactions (id, message_id, user_id, emoji) VALUES (?, ?, ?, ?)').run(uuidv4(), req.params.id, req.user.id, emoji);
  }
  io.emit('reaction_updated', { message_id: req.params.id, user_id: req.user.id, emoji });
  res.json({ success: true });
});

app.post('/api/messages/:id/star', auth, (req, res) => {
  const msg = db.prepare('SELECT starred FROM messages WHERE id = ?').get(req.params.id);
  db.prepare('UPDATE messages SET starred = ? WHERE id = ?').run(msg.starred ? 0 : 1, req.params.id);
  res.json({ starred: !msg.starred });
});

app.get('/api/messages/starred', auth, (req, res) => {
  const msgs = db.prepare(`
    SELECT m.*, u.name as sender_name FROM messages m JOIN users u ON m.sender_id = u.id
    WHERE m.starred = 1 AND (m.sender_id = ? OR m.receiver_id = ?)
  `).all(req.user.id, req.user.id);
  res.json(msgs);
});

// ==================== CHATS (conversations list) ====================

app.get('/api/chats', auth, (req, res) => {
  const chats = db.prepare(`
    SELECT DISTINCT
      CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END as other_user_id,
      MAX(m.created_at) as last_message_time,
      m.content as last_content, m.type as last_type,
      u.name, u.avatar, u.is_online, u.last_seen,
      (SELECT COUNT(*) FROM messages WHERE sender_id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END AND receiver_id = ? AND deleted_for_everyone = 0 AND id NOT IN (SELECT message_id FROM message_status WHERE user_id = ? AND status = 'read')) as unread_count
    FROM messages m
    JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
    WHERE (m.sender_id = ? OR m.receiver_id = ?) AND m.receiver_id IS NOT NULL AND m.deleted_for_everyone = 0
    GROUP BY other_user_id
    ORDER BY last_message_time DESC
  `).all(req.user.id, req.user.id, req.user.id, req.user.id, req.user.id, req.user.id, req.user.id);
  res.json(chats);
});

// ==================== GROUPS ROUTES ====================

app.get('/api/groups', auth, (req, res) => {
  const groups = db.prepare(`
    SELECT g.* FROM groups g
    JOIN group_members gm ON g.id = gm.group_id
    WHERE gm.user_id = ?
  `).all(req.user.id);
  res.json(groups);
});

app.post('/api/groups', auth, upload.single('avatar'), (req, res) => {
  const { name, description, members } = req.body;
  const id = uuidv4();
  const avatar = req.file ? `/uploads/${req.file.filename}` : null;
  db.prepare('INSERT INTO groups (id, name, description, avatar, created_by) VALUES (?, ?, ?, ?, ?)').run(id, name, description || '', avatar, req.user.id);
  
  // Add creator
  db.prepare('INSERT INTO group_members (id, group_id, user_id, role) VALUES (?, ?, ?, ?)').run(uuidv4(), id, req.user.id, 'admin');
  
  // Add members
  const memberList = JSON.parse(members || '[]');
  memberList.forEach(uid => {
    db.prepare('INSERT INTO group_members (id, group_id, user_id) VALUES (?, ?, ?)').run(uuidv4(), id, uid);
  });
  
  res.json({ id, name, description, avatar });
});

app.get('/api/groups/:id/members', auth, (req, res) => {
  const members = db.prepare(`
    SELECT gm.role, gm.joined_at, u.id, u.name, u.avatar, u.phone, u.is_online
    FROM group_members gm JOIN users u ON gm.user_id = u.id
    WHERE gm.group_id = ?
  `).all(req.params.id);
  res.json(members);
});

app.post('/api/groups/:id/members', auth, (req, res) => {
  const { user_id } = req.body;
  db.prepare('INSERT INTO group_members (id, group_id, user_id) VALUES (?, ?, ?)').run(uuidv4(), req.params.id, user_id);
  res.json({ success: true });
});

app.delete('/api/groups/:id/members/:userId', auth, (req, res) => {
  db.prepare('DELETE FROM group_members WHERE group_id = ? AND user_id = ?').run(req.params.id, req.params.userId);
  res.json({ success: true });
});

// ==================== STATUS ROUTES ====================

app.get('/api/status', auth, (req, res) => {
  const now = new Date().toISOString();
  const statuses = db.prepare(`
    SELECT s.*, u.name, u.avatar, u.phone FROM status_updates s
    JOIN users u ON s.user_id = u.id
    WHERE s.expires_at > ? AND (
      s.user_id = ? OR
      s.user_id IN (SELECT contact_id FROM contacts WHERE user_id = ?)
    )
    ORDER BY s.created_at DESC
  `).all(now, req.user.id, req.user.id);
  res.json(statuses);
});

app.post('/api/status', auth, upload.single('media'), (req, res) => {
  const { content, type, bg_color } = req.body;
  const id = uuidv4();
  const media_url = req.file ? `/uploads/${req.file.filename}` : null;
  const expires_at = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO status_updates (id, user_id, content, type, media_url, bg_color, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    id, req.user.id, content || null, type || 'text', media_url, bg_color || '#128C7E', expires_at
  );
  res.json({ success: true, id });
});

app.post('/api/status/:id/view', auth, (req, res) => {
  const status = db.prepare('SELECT views FROM status_updates WHERE id = ?').get(req.params.id);
  if (status) {
    const views = JSON.parse(status.views || '[]');
    if (!views.includes(req.user.id)) {
      views.push(req.user.id);
      db.prepare('UPDATE status_updates SET views = ? WHERE id = ?').run(JSON.stringify(views), req.params.id);
    }
  }
  res.json({ success: true });
});

// ==================== CALLS ====================

app.get('/api/calls', auth, (req, res) => {
  const calls = db.prepare(`
    SELECT c.*, u.name as other_name, u.avatar as other_avatar
    FROM calls c
    JOIN users u ON u.id = CASE WHEN c.caller_id = ? THEN c.receiver_id ELSE c.caller_id END
    WHERE c.caller_id = ? OR c.receiver_id = ?
    ORDER BY c.created_at DESC LIMIT 50
  `).all(req.user.id, req.user.id, req.user.id);
  res.json(calls);
});

// Upload endpoint for media
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: `/uploads/${req.file.filename}`, filename: req.file.originalname });
});

// ==================== SOCKET.IO ====================

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  const userId = socket.user.id;
  onlineUsers.set(userId, socket.id);
  
  // Update online status
  db.prepare('UPDATE users SET is_online = 1, last_seen = datetime(\'now\') WHERE id = ?').run(userId);
  io.emit('user_status', { userId, is_online: true });
  
  // Join group rooms
  const groups = db.prepare('SELECT group_id FROM group_members WHERE user_id = ?').all(userId);
  groups.forEach(g => socket.join(`group_${g.group_id}`));
  
  // Typing indicators
  socket.on('typing', ({ to, isGroup }) => {
    if (isGroup) {
      socket.to(`group_${to}`).emit('user_typing', { userId, chatId: to });
    } else {
      const receiverSocket = onlineUsers.get(to);
      if (receiverSocket) io.to(receiverSocket).emit('user_typing', { userId, chatId: userId });
    }
  });
  
  socket.on('stop_typing', ({ to, isGroup }) => {
    if (isGroup) {
      socket.to(`group_${to}`).emit('user_stop_typing', { userId, chatId: to });
    } else {
      const receiverSocket = onlineUsers.get(to);
      if (receiverSocket) io.to(receiverSocket).emit('user_stop_typing', { userId, chatId: userId });
    }
  });
  
  // Read receipts
  socket.on('messages_read', ({ senderId }) => {
    const senderSocket = onlineUsers.get(senderId);
    if (senderSocket) io.to(senderSocket).emit('messages_read', { by: userId });
  });
  
  // Call signaling
  socket.on('call_offer', ({ to, offer, type }) => {
    const receiverSocket = onlineUsers.get(to);
    if (receiverSocket) io.to(receiverSocket).emit('call_offer', { from: userId, offer, type });
  });
  
  socket.on('call_answer', ({ to, answer }) => {
    const receiverSocket = onlineUsers.get(to);
    if (receiverSocket) io.to(receiverSocket).emit('call_answer', { from: userId, answer });
  });
  
  socket.on('call_ice', ({ to, candidate }) => {
    const receiverSocket = onlineUsers.get(to);
    if (receiverSocket) io.to(receiverSocket).emit('call_ice', { from: userId, candidate });
  });
  
  socket.on('call_end', ({ to }) => {
    const receiverSocket = onlineUsers.get(to);
    if (receiverSocket) io.to(receiverSocket).emit('call_ended', { from: userId });
  });
  
  socket.on('call_reject', ({ to }) => {
    const receiverSocket = onlineUsers.get(to);
    if (receiverSocket) io.to(receiverSocket).emit('call_rejected', { from: userId });
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(userId);
    const last_seen = new Date().toISOString();
    db.prepare('UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?').run(last_seen, userId);
    io.emit('user_status', { userId, is_online: false, last_seen });
  });
});

server.listen(PORT, () => {
  console.log(`🚀 WhatsApp Clone running on port ${PORT}`);
});
