const express = require('express');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'yagiztagram-secret-change-me-in-production';
const DB_FILE = path.join(__dirname, 'database.sqlite');

app.use(cors({ credentials: true, origin: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

fs.mkdirSync('uploads', { recursive: true });

let db;
let dbReady = false;

function saveDb() {
  try {
    if (db) {
      const data = db.export();
      fs.writeFileSync(DB_FILE, Buffer.from(data));
    }
  } catch (e) {}
}

function run(sql, params = []) {
  if (!dbReady) throw new Error('Veritabanı henüz hazır değil.');
  const stmt = db.prepare(sql);
  stmt.run(params);
  const info = { lastInsertRowid: stmt.lastInsertRowid, changes: stmt.changes };
  stmt.free();
  saveDb();
  return info;
}
function get(sql, params = []) {
  if (!dbReady) throw new Error('Veritabanı henüz hazır değil.');
  const stmt = db.prepare(sql);
  stmt.bind(params);
  let row = null;
  if (stmt.step()) {
    row = stmt.getAsObject();
  }
  stmt.free();
  return row;
}
function all(sql, params = []) {
  if (!dbReady) throw new Error('Veritabanı henüz hazır değil.');
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}

const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Sadece resim yükleyebilirsiniz.'));
  },
});

function authenticateToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Giriş yapmalısınız.' });
  const token = auth.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Geçersiz token.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token süresi doldu.' });
    req.user = user;
    next();
  });
}

// ---------- Kimlik ----------
app.post('/api/register', (req, res) => {
  try {
    const { username, password, full_name } = req.body;
    if (!username || !password || !full_name) {
      return res.status(400).json({ error: 'Tüm alanları doldurun.' });
    }
    const existing = get('SELECT id FROM users WHERE username = ?', [username]);
    if (existing && existing.id) return res.status(409).json({ error: 'Bu kullanıcı adı zaten var.' });

    const hash = bcrypt.hashSync(password, 10);
    run('INSERT INTO users (username, password, full_name) VALUES (?, ?, ?)', [
      username, hash, full_name,
    ]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body;
    const user = get('SELECT * FROM users WHERE username = ?', [username]);
    if (!user || !user.id) return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });
    const match = bcrypt.compareSync(password, user.password);
    if (!match) return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: user.id, username: user.username, full_name: user.full_name, bio: user.bio, avatar: user.avatar },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Kullanıcılar ----------
app.get('/api/me', authenticateToken, (req, res) => {
  const user = get('SELECT id, username, full_name, bio, avatar FROM users WHERE id = ?', [req.user.id]);
  if (!user || !user.id) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
  res.json({ user });
});

app.get('/api/users', authenticateToken, (req, res) => {
  const q = req.query.q || '';
  const users = all(
    'SELECT id, username, full_name, avatar FROM users WHERE username LIKE ? OR full_name LIKE ? LIMIT 20',
    [`%${q}%`, `%${q}%`]
  );
  res.json({ users });
});

app.get('/api/profile/:username', authenticateToken, (req, res) => {
  try {
    const profileUser = get('SELECT id, username, full_name, bio, avatar, created_at FROM users WHERE username = ?', [req.params.username]);
    if (!profileUser || !profileUser.id) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

    const isOwn = profileUser.id === req.user.id;
    const isFollowing = get('SELECT id FROM followers WHERE follower_id = ? AND following_id = ?', [req.user.id, profileUser.id]);

    const posts = all(
      `SELECT p.*, u.username, u.full_name, u.avatar,
             (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id) AS like_count,
             (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
             EXISTS(SELECT 1 FROM post_likes pl2 WHERE pl2.post_id = p.id AND pl2.user_id = ?) AS liked
       FROM posts p JOIN users u ON u.id = p.user_id
       WHERE p.user_id = ?
       ORDER BY p.created_at DESC`,
      [req.user.id, profileUser.id]
    );

    const followerCount = get('SELECT COUNT(*) AS c FROM followers WHERE following_id = ?', [profileUser.id]);
    const followingCount = get('SELECT COUNT(*) AS c FROM followers WHERE follower_id = ?', [profileUser.id]);

    res.json({
      user: { ...profileUser, isOwn, isFollowing: !!isFollowing },
      posts,
      stats: {
        posts: posts.length,
        followers: followerCount.c,
        following: followingCount.c,
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Akış ----------
app.get('/api/feed', authenticateToken, (req, res) => {
  try {
    const posts = all(
      `SELECT p.*, u.username, u.full_name, u.avatar,
             (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id) AS like_count,
             (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
             EXISTS(SELECT 1 FROM post_likes pl2 WHERE pl2.post_id = p.id AND pl2.user_id = ?) AS liked
       FROM posts p
       JOIN users u ON u.id = p.user_id
       WHERE p.user_id = ?
          OR p.user_id IN (SELECT following_id FROM followers WHERE follower_id = ?)
       ORDER BY p.created_at DESC
       LIMIT 50`,
      [req.user.id, req.user.id]
    );
    res.json({ posts });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Gönderiler ----------
app.post('/api/posts', authenticateToken, upload.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Resim seçmelisiniz.' });
    const { caption } = req.body;
    const imageUrl = `/uploads/${req.file.filename}`;
    run('INSERT INTO posts (user_id, image_url, caption) VALUES (?, ?, ?)', [
      req.user.id, imageUrl, caption || '',
    ]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/posts/:id/like', authenticateToken, (req, res) => {
  try {
    const postId = req.params.id;
    const existing = get('SELECT id FROM post_likes WHERE post_id = ? AND user_id = ?', [postId, req.user.id]);
    if (existing && existing.id) {
      run('DELETE FROM post_likes WHERE id = ?', [existing.id]);
      res.json({ liked: false });
    } else {
      run('INSERT INTO post_likes (post_id, user_id) VALUES (?, ?)', [postId, req.user.id]);
      res.json({ liked: true });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/posts/:id/comment', authenticateToken, (req, res) => {
  try {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: 'Yorum boş olamaz.' });
    run('INSERT INTO comments (post_id, user_id, text) VALUES (?, ?, ?)', [
      req.params.id, req.user.id, text,
    ]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/posts/:id/comments', authenticateToken, (req, res) => {
  try {
    const comments = all(
      `SELECT c.*, u.username, u.full_name, u.avatar
       FROM comments c JOIN users u ON u.id = c.user_id
       WHERE c.post_id = ?
       ORDER BY c.created_at ASC`,
      [req.params.id]
    );
    res.json({ comments });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Takip ----------
app.post('/api/follow/:userId', authenticateToken, (req, res) => {
  try {
    const targetId = parseInt(req.params.userId);
    if (targetId === req.user.id) return res.status(400).json({ error: 'Kendinizi takip edemezsiniz.' });
    const existing = get('SELECT id FROM followers WHERE follower_id = ? AND following_id = ?', [req.user.id, targetId]);
    if (existing && existing.id) {
      run('DELETE FROM followers WHERE id = ?', [existing.id]);
      res.json({ following: false });
    } else {
      run('INSERT INTO followers (follower_id, following_id) VALUES (?, ?)', [req.user.id, targetId]);
      res.json({ following: true });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Mesajlar ----------
app.get('/api/messages/:userId', authenticateToken, (req, res) => {
  try {
    const otherId = parseInt(req.params.userId);
    const messages = all(
      `SELECT m.*, u.username AS sender_name
       FROM messages m JOIN users u ON u.id = m.sender_id
       WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
       ORDER BY m.created_at ASC`,
      [req.user.id, otherId, otherId, req.user.id]
    );
    res.json({ messages });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/messages', authenticateToken, (req, res) => {
  try {
    const { receiver_id, text } = req.body;
    if (!receiver_id || !text) return res.status(400).json({ error: 'Eksik bilgi.' });
    run('INSERT INTO messages (sender_id, receiver_id, text) VALUES (?, ?, ?)', [
      req.user.id, receiver_id, text,
    ]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/conversations', authenticateToken, (req, res) => {
  try {
    const rows = all(
      `SELECT u.id, u.username, u.full_name, u.avatar,
              m.text AS last_message, m.created_at AS last_time
       FROM users u
       JOIN messages m ON m.sender_id = u.id OR m.receiver_id = u.id
       WHERE (m.sender_id = ? OR m.receiver_id = ?) AND u.id != ?
       GROUP BY u.id
       ORDER BY m.created_at DESC`,
      [req.user.id, req.user.id, req.user.id]
    );
    res.json({ conversations: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Hikayeler ----------
app.get('/api/stories', authenticateToken, (req, res) => {
  try {
    const stories = all(
      `SELECT s.*, u.username, u.full_name, u.avatar
       FROM stories s JOIN users u ON u.id = s.user_id
       WHERE s.expires_at > datetime('now')
       ORDER BY s.created_at DESC
       LIMIT 30`,
      []
    );
    res.json({ stories });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/stories', authenticateToken, upload.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Resim seçmelisiniz.' });
    const imageUrl = `/uploads/${req.file.filename}`;
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    run('INSERT INTO stories (user_id, image_url, expires_at) VALUES (?, ?, ?)', [
      req.user.id, imageUrl, expires,
    ]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Sağlık kontrolü ----------
app.get('/api/health', (req, res) => {
  res.json({ ok: true, dbReady });
});

// ---------- Veritabanını başlat ----------
function initTables() {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    full_name TEXT NOT NULL,
    bio TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    image_url TEXT NOT NULL,
    caption TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS post_likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(post_id, user_id),
    FOREIGN KEY (post_id) REFERENCES posts(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS followers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    follower_id INTEGER NOT NULL,
    following_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(follower_id, following_id),
    FOREIGN KEY (follower_id) REFERENCES users(id),
    FOREIGN KEY (following_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    read_at DATETIME,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS stories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    image_url TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  saveDb();
}

initSqlJs().then(SQL => {
  if (fs.existsSync(DB_FILE)) {
    const buf = fs.readFileSync(DB_FILE);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }
  initTables();
  dbReady = true;

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Yağıztagram sunucusu çalışıyor: http://0.0.0.0:${PORT}`);
  });
}).catch(err => {
  console.error('Veritabanı başlatılamadı:', err);
  process.exit(1);
});
