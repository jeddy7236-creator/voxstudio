'use strict';

const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const fs         = require('fs');
const path       = require('path');
const { v4: uuidv4 } = require('uuid');
const Database   = require('better-sqlite3');
const ffmpeg     = require('fluent-ffmpeg');
const ffmpegPath = require('ffmpeg-static');

const PORT       = process.env.PORT       || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'voxstudio_secret_CHANGE_IN_PROD';

if (process.env.NODE_ENV === 'production' && JWT_SECRET.includes('CHANGE')) {
    console.error('FATAL: Set JWT_SECRET in production!');
    process.exit(1);
}

ffmpeg.setFfmpegPath(ffmpegPath);

[
    'uploads/images', 'uploads/videos', 'uploads/audio',
    'uploads/thumbnails', 'public'
].forEach(d => fs.mkdirSync(d, { recursive: true }));

const app = express();
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'] }));
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

const db = new Database('./voxstudio.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    username     TEXT UNIQUE NOT NULL,
    email        TEXT UNIQUE NOT NULL,
    password     TEXT NOT NULL,
    display_name TEXT,
    avatar_url   TEXT,
    bio          TEXT,
    role         TEXT NOT NULL DEFAULT 'user',
    plan         TEXT NOT NULL DEFAULT 'free',
    is_active    INTEGER NOT NULL DEFAULT 1,
    total_views  INTEGER NOT NULL DEFAULT 0,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login   DATETIME
  );
  CREATE TABLE IF NOT EXISTS videos (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    title       TEXT,
    description TEXT,
    filename    TEXT NOT NULL,
    url         TEXT NOT NULL,
    thumbnail   TEXT,
    duration    REAL,
    file_size   INTEGER,
    mime_type   TEXT,
    category    TEXT DEFAULT 'general',
    tags        TEXT DEFAULT '[]',
    status      TEXT NOT NULL DEFAULT 'ready',
    views       INTEGER NOT NULL DEFAULT 0,
    likes       INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS images (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    title       TEXT,
    filename    TEXT NOT NULL,
    url         TEXT NOT NULL,
    file_size   INTEGER,
    mime_type   TEXT,
    tags        TEXT DEFAULT '[]',
    views       INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS scripts (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    title       TEXT,
    topic       TEXT NOT NULL,
    platform    TEXT DEFAULT 'tiktok',
    tone        TEXT DEFAULT 'motivation',
    content     TEXT NOT NULL,
    hooks       TEXT DEFAULT '[]',
    cta         TEXT,
    word_count  INTEGER DEFAULT 0,
    char_count  INTEGER DEFAULT 0,
    is_favorite INTEGER NOT NULL DEFAULT 0,
    copies      INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS audio (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    title      TEXT,
    filename   TEXT NOT NULL,
    url        TEXT NOT NULL,
    duration   REAL,
    file_size  INTEGER,
    mime_type  TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS hashtag_sets (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    name       TEXT NOT NULL,
    platform   TEXT NOT NULL,
    tags       TEXT NOT NULL,
    uses       INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS activity_log (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    action     TEXT NOT NULL,
    details    TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_videos_user   ON videos(user_id);
  CREATE INDEX IF NOT EXISTS idx_images_user   ON images(user_id);
  CREATE INDEX IF NOT EXISTS idx_scripts_user  ON scripts(user_id);
  CREATE INDEX IF NOT EXISTS idx_audio_user    ON audio(user_id);
  CREATE INDEX IF NOT EXISTS idx_users_email   ON users(email);
`);

const ok       = (res, data, code = 200) => res.status(code).json({ success: true,  ...data });
const fail     = (res, msg,  code = 400) => res.status(code).json({ success: false, error: msg });
const sanitize = s => String(s || '').trim().slice(0, 2000);
const isEmail  = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const safeJson = (s, fb = []) => { try { return JSON.parse(s); } catch { return fb; } };

const logActivity = (userId, action, details = '') => {
    try { db.prepare('INSERT INTO activity_log (id,user_id,action,details) VALUES (?,?,?,?)').run(uuidv4(), userId, action, details); } catch {}
};

const auth = (req, res, next) => {
    const h = req.headers.authorization || '';
    if (!h.startsWith('Bearer ')) return fail(res, 'Unauthorized', 401);
    try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
    catch (e) { fail(res, e.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token', 401); }
};

const makeUpload = (folder, types, sizeMB) => multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, `uploads/${folder}/`),
        filename:    (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname).toLowerCase()}`)
    }),
    limits: { fileSize: sizeMB * 1024 * 1024 },
    fileFilter: (req, file, cb) => types.includes(file.mimetype) ? cb(null, true) : cb(new Error(`Invalid type`))
});

const imgUpload   = makeUpload('images',    ['image/jpeg','image/png','image/webp','image/gif'], 50);
const vidUpload   = makeUpload('videos',    ['video/mp4','video/quicktime','video/x-msvideo','video/webm'], 500);
const audioUpload = makeUpload('audio',     ['audio/mpeg','audio/wav','audio/ogg','audio/mp4','audio/aac'], 100);

const getDuration = fp => new Promise(r => ffmpeg.ffprobe(fp, (e, m) => r(e ? null : m?.format?.duration || null)));
const makeThumbnail = (fp, name) => new Promise(r =>
    ffmpeg(fp).screenshots({ timestamps: ['10%'], filename: name, folder: 'uploads/thumbnails', size: '640x?' })
        .on('end', () => r(`/uploads/thumbnails/${name}`))
        .on('error', e => { console.warn('Thumb failed:', e.message); r(null); }));

const TEMPLATES = {
    motivation: t => `🔥 ${t.toUpperCase()} — THE TRUTH NOBODY TELLS YOU\n\nMost people fail at ${t} not because they lack talent.\nThey fail because they quit 3 feet from gold.\n\nHere's what actually changes everything:\n\n1️⃣ Start before you feel ready\n2️⃣ Show up daily — even when it's ugly\n3️⃣ Protect your energy like it's money\n\nThe gap between where you are and where you want to be?\nIt's not talent. It's not luck. It's CONSISTENCY.\n\nSave this. Watch it when you want to quit.\nDrop a 🔥 if this hits different.\n\n#${t.replace(/\s+/g,'')} #motivation #mindset #success #grind`,
    business: t => `💼 How to build a business around ${t} from scratch\n\nStep 1 → Find the pain inside ${t}\nStep 2 → Create content that solves it\nStep 3 → Build an audience that trusts you\nStep 4 → Offer the shortcut (your paid product)\n\nRevenue doesn't come from going viral.\nIt comes from being TRUSTED.\n\n1,000 true fans × $100/year = $100K business\n\nStart TODAY. Not Monday. Today.\n\n#business #${t.replace(/\s+/g,'')} #entrepreneur #money #startup`,
    educational: t => `📚 What nobody explains about ${t}\n\n❌ What most think: too complicated\n✅ Reality: just misunderstood\n\nWhat to actually do:\n✔ One concept at a time\n✔ Apply it immediately\n✔ Review every 2 weeks\n\nKnowledge without action = trivia\nAction without knowledge = guessing\nCombine them = RESULTS\n\n#${t.replace(/\s+/g,'')} #learnontiktok #education #tips`,
    funny: t => `😂 POV: You decide to get into ${t}\n\nWeek 1: "This is gonna be SO easy"\nWeek 2: [entire personality becomes ${t}]\nWeek 3: "Why did no one warn me"\nWeek 4: Can't stop. Won't stop.\nMonth 3: Lowkey actually getting good\nMonth 6: Teaching others like you didn't google everything 💀\n\nComment your week 👇\n\n#funny #relatable #${t.replace(/\s+/g,'')} #fyp`,
    storytelling: t => `🎬 The day ${t} changed everything\n\nI was stuck. Nothing was working.\nI had no idea what to do next.\n\nThen someone mentioned ${t}.\nI almost ignored it.\n\n30 days later — everything shifted.\n\nNot because I got lucky.\nBecause I stopped waiting for the perfect moment.\n\nThis is your sign.\n\n#${t.replace(/\s+/g,'')} #story #transformation #reallife`,
    viral: t => `⚡ This ${t} hack breaks the algorithm\n\nEveryone is sleeping on this.\n\n→ Hook in the first 2 seconds\n→ Deliver value before the ask\n→ End with a pattern interrupt\n\nThe result? 10x the reach.\nSame amount of effort.\n\nScreenshot this. Use it today.\n\n#${t.replace(/\s+/g,'')} #viral #growthhack #contentcreator`,
};

const HOOKS = t => [
    `🎯 Stop scrolling — this ${t} tip changes everything`,
    `🔥 99% of people get ${t} completely wrong`,
    `💎 The ${t} secret top creators don't share`,
    `⚡ I wish someone told me this about ${t} sooner`,
    `🚨 Don't try ${t} until you see this`,
];

const CTAS = [
    '💾 Save this — you will need it.',
    '🔁 Share with someone who needs this.',
    '👇 Comment your thoughts below.',
    '➕ Follow for daily creator tips.',
];

const HASHTAGS = {
    tiktok:    t => `#${t.replace(/\s+/g,'')} #fyp #foryou #viral #trending #tiktok #creator`,
    instagram: t => `#${t.replace(/\s+/g,'')} #reels #instagram #explore #instagood #content #creator`,
    youtube:   t => `#${t.replace(/\s+/g,'')} #youtube #shorts #youtuber #subscribe #viral`,
    twitter:   t => `#${t.replace(/\s+/g,'')} #twitter #trending #viral`,
    linkedin:  t => `#${t.replace(/\s+/g,'')} #linkedin #professional #business #growth`,
};

app.get('/health', (req, res) => res.json({ status: 'ok', app: 'VoxStudio', version: '3.0.0', time: new Date().toISOString() }));

app.post('/api/auth/signup', async (req, res) => {
    try {
        const username = sanitize(req.body.username);
        const email    = sanitize(req.body.email).toLowerCase();
        const password = req.body.password || '';
        const display  = sanitize(req.body.display_name) || username;
        if (!username || !email || !password) return fail(res, 'All fields required');
        if (username.length < 3 || username.length > 30) return fail(res, 'Username must be 3-30 chars');
        if (!/^[a-zA-Z0-9_]+$/.test(username)) return fail(res, 'Username: letters, numbers, _ only');
        if (!isEmail(email)) return fail(res, 'Invalid email');
        if (password.length < 8) return fail(res, 'Password min 8 characters');
        const exists = db.prepare('SELECT id FROM users WHERE email=? OR username=?').get(email, username);
        if (exists) return fail(res, 'Email or username already taken', 409);
        const hashed = await bcrypt.hash(password, 12);
        const id = uuidv4();
        db.prepare('INSERT INTO users (id,username,email,password,display_name) VALUES (?,?,?,?,?)').run(id, username, email, hashed, display);
        logActivity(id, 'signup', `New user: ${username}`);
        const token = jwt.sign({ id, username, role: 'user' }, JWT_SECRET, { expiresIn: '30d' });
        ok(res, { token, user: { id, username, email, display_name: display, role: 'user', plan: 'free' } }, 201);
    } catch (e) { console.error('Signup:', e); fail(res, 'Server error', 500); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const email    = sanitize(req.body.email).toLowerCase();
        const password = req.body.password || '';
        if (!email || !password) return fail(res, 'Email and password required');
        const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
        const dummy = '$2a$12$dummyhashfortimingsafety000000000000000000000000000000';
        const valid = user ? await bcrypt.compare(password, user.password) : await bcrypt.compare(password, dummy) && false;
        if (!user || !valid || !user.is_active) return fail(res, 'Invalid credentials', 401);
        db.prepare('UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?').run(user.id);
        logActivity(user.id, 'login');
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
        ok(res, { token, user: { id: user.id, username: user.username, email: user.email, display_name: user.display_name, role: user.role, plan: user.plan } });
    } catch (e) { console.error('Login:', e); fail(res, 'Server error', 500); }
});

app.get('/api/user/profile', auth, (req, res) => {
    const user = db.prepare('SELECT id,username,email,display_name,avatar_url,bio,role,plan,created_at,last_login FROM users WHERE id=?').get(req.user.id);
    if (!user) return fail(res, 'Not found', 404);
    const stats = {
        videos : db.prepare('SELECT COUNT(*) AS c FROM videos  WHERE user_id=?').get(req.user.id)?.c || 0,
        images : db.prepare('SELECT COUNT(*) AS c FROM images  WHERE user_id=?').get(req.user.id)?.c || 0,
        scripts: db.prepare('SELECT COUNT(*) AS c FROM scripts WHERE user_id=?').get(req.user.id)?.c || 0,
        audio  : db.prepare('SELECT COUNT(*) AS c FROM audio   WHERE user_id=?').get(req.user.id)?.c || 0,
        total_views: db.prepare('SELECT SUM(views) AS v FROM videos WHERE user_id=?').get(req.user.id)?.v || 0,
    };
    ok(res, { user: { ...user, stats } });
});

app.patch('/api/user/profile', auth, (req, res) => {
    db.prepare('UPDATE users SET display_name=?,bio=?,updated_at=CURRENT_TIMESTAMP WHERE id=?')
      .run(sanitize(req.body.display_name) || null, sanitize(req.body.bio).slice(0,300) || null, req.user.id);
    ok(res, { message: 'Profile updated' });
});

app.post('/api/user/change-password', auth, async (req, res) => {
    try {
        const { current_password, new_password } = req.body;
        if (!current_password || !new_password) return fail(res, 'Both passwords required');
        if (new_password.length < 8) return fail(res, 'Min 8 characters');
        const user = db.prepare('SELECT password FROM users WHERE id=?').get(req.user.id);
        const valid = await bcrypt.compare(current_password, user.password);
        if (!valid) return fail(res, 'Wrong current password', 401);
        const hashed = await bcrypt.hash(new_password, 12);
        db.prepare('UPDATE users SET password=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(hashed, req.user.id);
        ok(res, { message: 'Password changed' });
    } catch (e) { fail(res, 'Server error', 500); }
});

app.post('/api/videos/upload', auth, (req, res) => {
    vidUpload.single('video')(req, res, async err => {
        if (err) return fail(res, err.message);
        if (!req.file) return fail(res, 'Video file required');
        const id = uuidv4();
        const url = `/uploads/videos/${req.file.filename}`;
        const title = sanitize(req.body.title) || req.file.originalname;
        try {
            const [duration, thumbnail] = await Promise.all([getDuration(req.file.path), makeThumbnail(req.file.path, `${id}.jpg`)]);
            db.prepare('INSERT INTO videos (id,user_id,title,filename,url,thumbnail,duration,mime_type,file_size) VALUES (?,?,?,?,?,?,?,?,?)').run(id, req.user.id, title, req.file.filename, url, thumbnail, duration, req.file.mimetype, req.file.size);
            logActivity(req.user.id, 'upload_video', title);
            ok(res, { id, url, thumbnail, duration, title });
        } catch (e) { fs.unlink(req.file.path, () => {}); fail(res, 'Failed to process', 500); }
    });
});

app.get('/api/videos', auth, (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;
    const search = `%${sanitize(req.query.search)}%`;
    const videos = db.prepare('SELECT * FROM videos WHERE user_id=? AND title LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(req.user.id, search, limit, offset);
    const total  = db.prepare('SELECT COUNT(*) AS c FROM videos WHERE user_id=? AND title LIKE ?').get(req.user.id, search)?.c || 0;
    ok(res, { videos: videos.map(v => ({ ...v, tags: safeJson(v.tags) })), total, page, limit });
});

app.get('/api/videos/:id', auth, (req, res) => {
    const v = db.prepare('SELECT * FROM videos WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
    if (!v) return fail(res, 'Not found', 404);
    db.prepare('UPDATE videos SET views=views+1 WHERE id=?').run(req.params.id);
    ok(res, { video: { ...v, views: v.views + 1 } });
});

app.delete('/api/videos/:id', auth, (req, res) => {
    const v = db.prepare('SELECT * FROM videos WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
    if (!v) return fail(res, 'Not found', 404);
    db.prepare('DELETE FROM videos WHERE id=?').run(req.params.id);
    [`uploads/videos/${v.filename}`, `uploads/thumbnails/${req.params.id}.jpg`].forEach(f => fs.existsSync(f) && fs.unlink(f, () => {}));
    ok(res, { message: 'Deleted' });
});

app.post('/api/images/upload', auth, (req, res) => {
    imgUpload.single('image')(req, res, async err => {
        if (err) return fail(res, err.message);
        if (!req.file) return fail(res, 'Image required');
        const id = uuidv4();
        const url = `/uploads/images/${req.file.filename}`;
        const title = sanitize(req.body.title) || req.file.originalname;
        try {
            db.prepare('INSERT INTO images (id,user_id,title,filename,url,mime_type,file_size) VALUES (?,?,?,?,?,?,?)').run(id, req.user.id, title, req.file.filename, url, req.file.mimetype, req.file.size);
            logActivity(req.user.id, 'upload_image', title);
            ok(res, { id, url, title });
        } catch (e) { fs.unlink(req.file.path, () => {}); fail(res, 'Failed to save', 500); }
    });
});

app.get('/api/images', auth, (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;
    const images = db.prepare('SELECT * FROM images WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(req.user.id, limit, offset);
    const total  = db.prepare('SELECT COUNT(*) AS c FROM images WHERE user_id=?').get(req.user.id)?.c || 0;
    ok(res, { images, total, page, limit });
});

app.delete('/api/images/:id', auth, (req, res) => {
    const img = db.prepare('SELECT * FROM images WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
    if (!img) return fail(res, 'Not found', 404);
    db.prepare('DELETE FROM images WHERE id=?').run(req.params.id);
    const fp = `uploads/images/${img.filename}`;
    if (fs.existsSync(fp)) fs.unlink(fp, () => {});
    ok(res, { message: 'Deleted' });
});

app.post('/api/audio/upload', auth, (req, res) => {
    audioUpload.single('audio')(req, res, async err => {
        if (err) return fail(res, err.message);
        if (!req.file) return fail(res, 'Audio required');
        const id = uuidv4();
        const url = `/uploads/audio/${req.file.filename}`;
        const title = sanitize(req.body.title) || req.file.originalname;
        const duration = await getDuration(req.file.path);
        try {
            db.prepare('INSERT INTO audio (id,user_id,title,filename,url,duration,mime_type,file_size) VALUES (?,?,?,?,?,?,?,?)').run(id, req.user.id, title, req.file.filename, url, duration, req.file.mimetype, req.file.size);
            ok(res, { id, url, duration, title });
        } catch (e) { fs.unlink(req.file.path, () => {}); fail(res, 'Failed to save', 500); }
    });
});

app.get('/api/audio', auth, (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;
    const files = db.prepare('SELECT * FROM audio WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(req.user.id, limit, offset);
    const total = db.prepare('SELECT COUNT(*) AS c FROM audio WHERE user_id=?').get(req.user.id)?.c || 0;
    ok(res, { audio: files, total, page, limit });
});

app.delete('/api/audio/:id', auth, (req, res) => {
    const f = db.prepare('SELECT * FROM audio WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
    if (!f) return fail(res, 'Not found', 404);
    db.prepare('DELETE FROM audio WHERE id=?').run(req.params.id);
    const fp = `uploads/audio/${f.filename}`;
    if (fs.existsSync(fp)) fs.unlink(fp, () => {});
    ok(res, { message: 'Deleted' });
});

app.post('/api/scripts/generate', auth, (req, res) => {
    try {
        const topic    = sanitize(req.body.topic);
        const platform = sanitize(req.body.platform) || 'tiktok';
        const tone     = sanitize(req.body.tone)     || 'motivation';
        const title    = sanitize(req.body.title)    || `${topic} — ${tone}`;
        if (!topic || topic.length < 2) return fail(res, 'Topic required');
        const gen      = TEMPLATES[tone] || TEMPLATES.motivation;
        const content  = gen(topic);
        const hooks    = HOOKS(topic);
        const cta      = CTAS[Math.floor(Math.random() * CTAS.length)];
        const hashtags = (HASHTAGS[platform] || HASHTAGS.tiktok)(topic);
        const wc       = content.trim().split(/\s+/).length;
        const id = uuidv4();
        db.prepare('INSERT INTO scripts (id,user_id,title,topic,platform,tone,content,hooks,cta,word_count,char_count) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(id, req.user.id, title, topic, platform, tone, content, JSON.stringify(hooks), cta, wc, content.length);
        logActivity(req.user.id, 'generate_script', topic);
        ok(res, { id, title, content, hooks, cta, hashtags, word_count: wc, platform, tone });
    } catch (e) { console.error('Script:', e); fail(res, 'Failed', 500); }
});

app.get('/api/scripts', auth, (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;
    const tone = sanitize(req.query.tone);
    const platform = sanitize(req.query.platform);
    const fav = req.query.favorites === 'true';
    let where = 'user_id=?';
    const params = [req.user.id];
    if (tone)     { where += ' AND tone=?';     params.push(tone); }
    if (platform) { where += ' AND platform=?'; params.push(platform); }
    if (fav)      { where += ' AND is_favorite=1'; }
    const scripts = db.prepare(`SELECT * FROM scripts WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
    const total   = db.prepare(`SELECT COUNT(*) AS c FROM scripts WHERE ${where}`).get(...params)?.c || 0;
    ok(res, { scripts: scripts.map(s => ({ ...s, hooks: safeJson(s.hooks) })), total, page, limit });
});

app.patch('/api/scripts/:id/favorite', auth, (req, res) => {
    const s = db.prepare('SELECT is_favorite FROM scripts WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
    if (!s) return fail(res, 'Not found', 404);
    const nv = s.is_favorite ? 0 : 1;
    db.prepare('UPDATE scripts SET is_favorite=? WHERE id=?').run(nv, req.params.id);
    ok(res, { is_favorite: !!nv });
});

app.patch('/api/scripts/:id/copy', auth, (req, res) => {
    db.prepare('UPDATE scripts SET copies=copies+1 WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
    ok(res, { message: 'Recorded' });
});

app.delete('/api/scripts/:id', auth, (req, res) => {
    const s = db.prepare('SELECT id FROM scripts WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
    if (!s) return fail(res, 'Not found', 404);
    db.prepare('DELETE FROM scripts WHERE id=?').run(req.params.id);
    ok(res, { message: 'Deleted' });
});

app.post('/api/hashtags/generate', auth, (req, res) => {
    const topic = sanitize(req.body.topic);
    const platform = sanitize(req.body.platform) || 'tiktok';
    if (!topic) return fail(res, 'Topic required');
    const gen = HASHTAGS[platform] || HASHTAGS.tiktok;
    const tags = gen(topic);
    const id = uuidv4();
    db.prepare('INSERT INTO hashtag_sets (id,user_id,name,platform,tags) VALUES (?,?,?,?,?)').run(id, req.user.id, topic, platform, tags);
    ok(res, { id, tags, platform });
});

app.get('/api/hashtags', auth, (req, res) => {
    const sets = db.prepare('SELECT * FROM hashtag_sets WHERE user_id=? ORDER BY created_at DESC LIMIT 50').all(req.user.id);
    ok(res, { hashtags: sets });
});

app.get('/api/dashboard', auth, (req, res) => {
    const uid = req.user.id;
    const stats = {
        total_videos  : db.prepare('SELECT COUNT(*) AS c FROM videos  WHERE user_id=?').get(uid)?.c || 0,
        total_images  : db.prepare('SELECT COUNT(*) AS c FROM images  WHERE user_id=?').get(uid)?.c || 0,
        total_scripts : db.prepare('SELECT COUNT(*) AS c FROM scripts WHERE user_id=?').get(uid)?.c || 0,
        total_audio   : db.prepare('SELECT COUNT(*) AS c FROM audio   WHERE user_id=?').get(uid)?.c || 0,
        total_views   : db.prepare('SELECT SUM(views) AS v FROM videos WHERE user_id=?').get(uid)?.v || 0,
        fav_scripts   : db.prepare('SELECT COUNT(*) AS c FROM scripts WHERE user_id=? AND is_favorite=1').get(uid)?.c || 0,
        storage_mb    : Math.round(((db.prepare('SELECT SUM(file_size) AS s FROM videos WHERE user_id=?').get(uid)?.s || 0) + (db.prepare('SELECT SUM(file_size) AS s FROM images WHERE user_id=?').get(uid)?.s || 0) + (db.prepare('SELECT SUM(file_size) AS s FROM audio WHERE user_id=?').get(uid)?.s || 0)) / 1024 / 1024),
    };
    const recent_videos  = db.prepare('SELECT id,title,url,thumbnail,views,created_at FROM videos  WHERE user_id=? ORDER BY created_at DESC LIMIT 6').all(uid);
    const recent_images  = db.prepare('SELECT id,title,url,created_at FROM images WHERE user_id=? ORDER BY created_at DESC LIMIT 6').all(uid);
    const recent_scripts = db.prepare('SELECT id,title,topic,tone,platform,created_at FROM scripts WHERE user_id=? ORDER BY created_at DESC LIMIT 6').all(uid);
    const activity       = db.prepare('SELECT action,details,created_at FROM activity_log WHERE user_id=? ORDER BY created_at DESC LIMIT 10').all(uid);
    ok(res, { stats, recent_videos, recent_images, recent_scripts, activity });
});

app.use((req, res) => fail(res, `${req.method} ${req.path} not found`, 404));
app.use((err, req, res, next) => { console.error(err); fail(res, 'Server error', 500); });

const server = app.listen(PORT, () => {
    console.log(`\n🎙️  VOXSTUDIO v3.0 → http://localhost:${PORT}`);
    console.log(`📦  Mode: ${process.env.NODE_ENV || 'development'}\n`);
});

const shutdown = sig => {
    console.log(`\n${sig} — shutting down...`);
    server.close(() => { db.close(); process.exit(0); });
    setTimeout(() => process.exit(1), 10000);
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('uncaughtException',  e => { console.error('Uncaught:', e);  shutdown('error'); });
process.on('unhandledRejection', e => { console.error('Rejection:', e); shutdown('error'); });
