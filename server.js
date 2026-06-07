require('dotenv').config();
const express    = require('express');
const mysql2     = require('mysql2/promise');
const session    = require('express-session');
const { exec }   = require('child_process');
const fs         = require('fs');
const path       = require('path');
const http       = require('http');
const { Server } = require('socket.io');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server);

// ─── Middleware setup ────────────────────────────────────────────────────────

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret:            process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave:            false,
    saveUninitialized: true,
    cookie:            { maxAge: 24 * 60 * 60 * 1000 }
}));

// WAF middleware — Fase 2. Dipasang SEBELUM semua route.
// Terpisah dari kode endpoint rentan: endpoint tidak dimodifikasi sama sekali.
app.use(require('./lib/waf')(io));

// ─── Database ────────────────────────────────────────────────────────────────

let db;

async function connectDB() {
    const cfg = {
        host:     process.env.DB_HOST     || 'localhost',
        user:     process.env.DB_USER     || 'demo',
        password: process.env.DB_PASS     || 'demo',
        database: process.env.DB_NAME     || 'demoids',
        // multipleStatements: false (default) — UNION SELECT tetap bisa; yang tidak bisa: stacked queries (';')
    };

    for (let i = 1; i <= 20; i++) {
        try {
            db = await mysql2.createConnection(cfg);
            await db.query('SELECT 1');
            console.log('[DB] Connected to MySQL');
            return;
        } catch (err) {
            console.log(`[DB] Attempt ${i}/20 failed: ${err.message} — retry in 3s`);
            await new Promise(r => setTimeout(r, 3000));
        }
    }
    console.error('[DB] Could not connect after 20 attempts. Exiting.');
    process.exit(1);
}

// Helper: ambil IP client (support X-Forwarded-For dari reverse proxy)
function clientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
        || req.socket.remoteAddress
        || 'unknown';
}

// ─── Socket.io ───────────────────────────────────────────────────────────────

io.on('connection', (socket) => {
    // Client yang join sebagai monitor mendapat stream event
    socket.on('join-monitor', () => socket.join('monitor-room'));
});

// Fungsi ini akan dipakai oleh WAF (Fase 2) dan Honeypot (Fase 4) untuk emit event
// Dideklarasikan global supaya bisa diakses dari modul lain
global.emitEvent = async (event) => {
    try {
        // Simpan ke DB
        await db.query(
            `INSERT INTO events (layer, attack_type, nickname, src_ip, route, method, payload, severity)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [event.layer, event.attack_type, event.nickname, event.src_ip,
             event.route, event.method, event.payload?.substring(0, 200), event.severity || 'medium']
        );
        // Broadcast ke semua monitor yang connect
        io.to('monitor-room').emit('new-event', { ...event, ts: new Date().toISOString() });
    } catch (err) {
        console.error('[EVENT]', err.message);
    }
};

// ─── robots.txt — bait honeypot ──────────────────────────────────────────────

// Mendaftarkan path honeypot supaya "ditemukan" oleh yang membaca robots.txt
app.get('/robots.txt', (req, res) => {
    res.type('text/plain');
    res.send([
        'User-agent: *',
        'Disallow: /admin-backup',
        'Disallow: /secret-login',
        'Disallow: /api/internal',
        'Disallow: /backup/',
    ].join('\n'));
});

// ─── Landing & nickname ───────────────────────────────────────────────────────

app.get('/', (req, res) => {
    // <!-- TODO: hapus login lama di /secret-login --> (komentar bait di HTML output)
    res.render('index', { session: req.session });
});

app.post('/set-nickname', (req, res) => {
    const nick = (req.body.nickname || '').trim().substring(0, 30) || 'anonymous';
    req.session.nickname = nick;
    res.redirect('/');
});

// ─── /login — VULNERABLE: SQL Injection ──────────────────────────────────────
// JANGAN PERBAIKI: kerentanan ini disengaja untuk demo

app.get('/login', (req, res) => {
    res.render('login', { session: req.session, error: null, user: null, rawQuery: null });
});

app.post('/login', async (req, res) => {
    const username = req.body.username || '';
    const password = req.body.password || '';

    // Interpolasi string langsung — SENGAJA rentan SQL injection
    // Payload bypass: username = ' OR '1'='1' --
    const rawQuery = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

    try {
        const [rows] = await db.query(rawQuery);
        const user = rows.length > 0 ? rows[0] : null;
        res.render('login', {
            session:  req.session,
            error:    user ? null : 'Login gagal. Username atau password salah.',
            user,
            rawQuery, // ditampilkan di halaman untuk edukasi
        });
    } catch (err) {
        // Error MySQL juga ditampilkan — berguna untuk error-based SQLi
        res.render('login', {
            session:  req.session,
            error:    `MySQL Error: ${err.message}`,
            user:     null,
            rawQuery,
        });
    }
});

// ─── /comments — VULNERABLE: Stored XSS ─────────────────────────────────────
// JANGAN PERBAIKI: gunakan <%- %> di EJS (bukan <%=>) supaya XSS bisa berjalan

app.get('/comments', async (req, res) => {
    const [comments] = await db.query('SELECT * FROM comments ORDER BY created_at DESC');
    res.render('comments', { session: req.session, comments, posted: false });
});

app.post('/comments', async (req, res) => {
    const body     = req.body.body || '';
    const nickname = req.session.nickname || 'anonymous';

    // Simpan raw tanpa sanitasi — <script>alert('XSS')</script> tersimpan apa adanya
    await db.query('INSERT INTO comments (nickname, body) VALUES (?, ?)', [nickname, body]);

    const [comments] = await db.query('SELECT * FROM comments ORDER BY created_at DESC');
    res.render('comments', { session: req.session, comments, posted: true });
});

// ─── /search — VULNERABLE: Reflected XSS + SQLi UNION ───────────────────────
// JANGAN PERBAIKI: q direfleksikan tanpa escaping ke halaman

app.get('/search', async (req, res) => {
    const q = req.query.q || '';
    let results  = [];
    let dbError  = null;
    let rawQuery = null;

    if (q) {
        // Interpolasi string langsung — rentan UNION-based SQLi
        // Payload: ' UNION SELECT 1,username,secret_flag,4 FROM users--
        rawQuery = `SELECT * FROM comments WHERE body LIKE '%${q}%'`;
        try {
            const [rows] = await db.query(rawQuery);
            results = rows;
        } catch (err) {
            dbError = err.message;
        }
    }

    // q dikirim ke view dengan <%- %> — rentan Reflected XSS
    res.render('search', { session: req.session, q, results, dbError, rawQuery });
});

// ─── /tools — VULNERABLE: Command Injection ──────────────────────────────────
// JANGAN PERBAIKI: exec() berjalan di shell — ; | && semuanya aktif

app.get('/tools', (req, res) => {
    res.render('tools', { session: req.session, output: null, host: '', cmd: null });
});

app.post('/tools/ping', (req, res) => {
    const host = req.body.host || '127.0.0.1';

    // PERINGATAN: endpoint ini hanya aman di container terisolasi
    // Payload: 127.0.0.1; id    atau    127.0.0.1 | cat /etc/passwd
    const cmd = `ping -c 2 ${host}`;

    exec(cmd, { timeout: 8000 }, (error, stdout, stderr) => {
        const output = [stdout, stderr].filter(Boolean).join('\n')
            || (error ? error.message : '(no output)');
        res.render('tools', { session: req.session, output, host, cmd });
    });
});

// ─── /view — VULNERABLE: Path Traversal ──────────────────────────────────────
// JANGAN PERBAIKI: path.join dengan input user bisa keluar dari folder target

app.get('/view', (req, res) => {
    const file     = req.query.file || 'public/docs/readme.txt';

    // path.join merespek .. — file=../../etc/passwd bisa baca /etc/passwd
    // Dari /app: path.join('/app', '../../etc/passwd') = '/etc/passwd'
    const filePath = path.join(__dirname, file);

    try {
        const content = fs.readFileSync(filePath, 'utf8');
        res.render('view', { session: req.session, content, file, filePath, error: null });
    } catch (err) {
        res.render('view', {
            session: req.session, content: null, file, filePath,
            error: err.message,
        });
    }
});

// ─── Placeholder routes untuk fase berikutnya ────────────────────────────────

// ─── /monitor — live dashboard (Fase 3) ──────────────────────────────────────

app.get('/monitor', async (req, res) => {
    const token = req.query.token || '';
    if (!process.env.MONITOR_TOKEN || token !== process.env.MONITOR_TOKEN) {
        return res.status(401).send(`<!DOCTYPE html>
<html><head><style>body{background:#0a0a0a;color:#fff;font-family:monospace;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}</style></head>
<body><div><h1 style="font-size:3rem;color:#ef4444">401</h1>
<p>Token diperlukan untuk mengakses monitor.</p>
<p style="color:#6b7280">Buka: /monitor?token=TOKEN_KAMU</p></div></body></html>`);
    }

    try {
        // Event terbaru (60), dikirim ke client dalam urutan DESC (terbaru di atas)
        const [events] = await db.query(
            'SELECT * FROM events ORDER BY ts DESC LIMIT 60'
        );

        // Leaderboard: ranking berdasar total serangan per nickname
        const [leaderboard] = await db.query(`
            SELECT nickname,
                COUNT(*) AS total,
                SUM(attack_type='sqli')              AS sqli,
                SUM(attack_type='xss')               AS xss,
                SUM(attack_type='path_traversal')    AS path_traversal,
                SUM(attack_type='command_injection') AS command_injection,
                SUM(attack_type='honeypot_access')   AS honeypot
            FROM events
            GROUP BY nickname
            ORDER BY total DESC
            LIMIT 15
        `);

        // Statistik global
        const [[stats]] = await db.query(`
            SELECT
                COUNT(*)                             AS total,
                COUNT(DISTINCT nickname)             AS unique_users,
                SUM(attack_type='sqli')              AS sqli,
                SUM(attack_type='xss')               AS xss,
                SUM(attack_type='path_traversal')    AS path_traversal,
                SUM(attack_type='command_injection') AS command_injection,
                SUM(layer='honeypot')                AS honeypot,
                SUM(layer='network-suricata')        AS suricata
            FROM events
        `);

        const emptyStats = { total:0, unique_users:0, sqli:0, xss:0,
            path_traversal:0, command_injection:0, honeypot:0, suricata:0 };

        // Escape < > & supaya payload XSS (mis. </script>) tidak memutus script block di HTML
        // < / > adalah Unicode escape yang valid di JS tapi tidak dikenali HTML parser
        const safeJson = (o) => JSON.stringify(o)
            .replace(/</g, '\\u003c')
            .replace(/>/g, '\\u003e')
            .replace(/&/g, '\\u0026');

        res.render('monitor', {
            token,
            events,                              // hanya untuk cek .length di EJS
            stats:           stats || emptyStats,
            eventsJson:      safeJson(events),
            leaderboardJson: safeJson(leaderboard),
            statsJson:       safeJson(stats || emptyStats),
        });
    } catch (err) {
        res.status(500).send('DB Error: ' + err.message);
    }
});

// ─── /play — daftar tantangan peserta (Fase 6) ───────────────────────────────
app.get('/play', (req, res) => {
    res.render('play', { session: req.session });
});

// ─── /admin-backup & /secret-login — Honeypot (Fase 4) ──────────────────────
// Endpoint ini TIDAK punya fungsi sah — SEMUA akses adalah anomali.
// 0 false positive: tidak ada pengguna legitimate yang punya alasan ke sini.
// Bait terpasang di: robots.txt, komentar HTML index, link tersembunyi di /comments.

async function honeypotHandler(req, res) {
    const username = (req.body?.username || '').substring(0, 60);
    const password = (req.body?.password || '').substring(0, 60);
    const isPost   = req.method === 'POST';

    const event = {
        layer:       'honeypot',
        attack_type: 'honeypot_access',
        nickname:    req.session?.nickname || 'anonymous',
        src_ip:      clientIP(req),
        route:       req.path,
        method:      req.method,
        // Catat kredensial yang diketik — ditampilkan di monitor untuk edukasi
        payload: isPost
            ? `username="${username}" password="${password}"`
            : `[GET] ${req.path}`,
        severity: 'high',
    };

    if (typeof global.emitEvent === 'function') {
        try { await global.emitEvent(event); } catch (_) {}
    }

    // Selalu tampilkan halaman login — tidak pernah benar-benar login
    // Pesan "gagal" membuat attacker terus mencoba → lebih banyak event di monitor
    res.render('honeypot', {
        session:     req.session,
        route:       req.path,
        loginFailed: isPost,
        username,   // pre-fill username supaya terasa realistis
    });
}

app.get( ['/admin-backup', '/secret-login'], honeypotHandler);
app.post(['/admin-backup', '/secret-login'], honeypotHandler);

// ─── /api/reset — hapus semua events + komentar (hanya monitor token) ────────
// Proteksi: token yang sama dengan /monitor — peserta biasa tidak punya token ini.
// Setelah reset, emit socket 'reset' agar SEMUA klien monitor ikut bersih serentak.

app.post('/api/reset', async (req, res) => {
    const token = req.query.token || '';
    if (!process.env.MONITOR_TOKEN || token !== process.env.MONITOR_TOKEN) {
        return res.status(401).json({ error: 'Token diperlukan' });
    }
    try {
        await db.query('DELETE FROM events');
        await db.query('DELETE FROM comments');
        // Kembalikan satu komentar awal supaya halaman /comments tidak kosong total
        await db.query(
            "INSERT INTO comments (nickname, body) VALUES ('system', 'Selamat datang di PT. Baroque-ah! Silakan tinggalkan komentar atau pertanyaan di sini.')"
        );
        // Broadcast reset ke semua tab monitor yang sedang buka
        io.to('monitor-room').emit('reset');
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── /api/test-suricata — inject event Suricata dummy (Fase 5 debug) ─────────
// Berguna karena volume suricata-logs di-mount :ro di container app,
// sehingga test-eve.js tidak bisa nulis file langsung dari sini.
// Endpoint ini bypass file — panggil global.emitEvent langsung.

const TEST_SIGS = [
    { sig: 'DEMO SQLi - UNION SELECT detected', sid: 1000001, sev: 2, url: '/search' },
    { sig: 'DEMO SQLi - OR-based login bypass', sid: 1000002, sev: 2, url: '/login' },
    { sig: 'DEMO XSS - script tag detected',    sid: 1000004, sev: 2, url: '/comments' },
    { sig: 'DEMO Path Traversal',               sid: 1000006, sev: 2, url: '/view' },
    { sig: 'DEMO Command Injection',            sid: 1000008, sev: 1, url: '/tools/ping' },
    { sig: 'DEMO Honeypot - admin-backup',      sid: 1000009, sev: 3, url: '/admin-backup' },
];
const TEST_IPS = ['192.168.1.10','192.168.1.42','10.0.0.55','172.16.0.23','192.168.0.101'];

app.get('/api/test-suricata', async (req, res) => {
    const token = req.query.token || '';
    if (!process.env.MONITOR_TOKEN || token !== process.env.MONITOR_TOKEN) {
        return res.status(401).json({ error: 'Token diperlukan: ?token=MONITOR_TOKEN' });
    }

    const count = Math.min(parseInt(req.query.count) || 1, 10);
    const injected = [];

    for (let i = 0; i < count; i++) {
        const pick = TEST_SIGS[Math.floor(Math.random() * TEST_SIGS.length)];
        const sev  = pick.sev <= 1 ? 'critical' : pick.sev === 2 ? 'high' : 'medium';
        const event = {
            layer:       'network-suricata',
            attack_type: pick.sig,
            nickname:    'suricata',
            src_ip:      TEST_IPS[Math.floor(Math.random() * TEST_IPS.length)],
            route:       pick.url,
            method:      'GET',
            payload:     `${pick.sig} [sid:${pick.sid} sev:${pick.sev} action:allowed]`,
            severity:    sev,
        };
        if (typeof global.emitEvent === 'function') {
            try { await global.emitEvent(event); } catch (_) {}
        }
        injected.push(pick.sig);
    }

    res.json({ ok: true, count: injected.length, injected });
});

// ─── 404 ──────────────────────────────────────────────────────────────────────

app.use((req, res) => {
    res.status(404).render('404', { session: req.session });
});

// ─── Start ────────────────────────────────────────────────────────────────────

connectDB().then(() => {
    // Fase 5: mulai tailer Suricata eve.json setelah DB siap
    // global.emitEvent sudah terdefinisi, jadi alert langsung masuk ke DB + monitor
    require('./lib/eve-tailer')();

    const PORT = process.env.PORT || 3000;
    server.listen(PORT, '0.0.0.0', () => {
        console.log(`[APP] PT. Baroque-ah Demo running on http://0.0.0.0:${PORT}`);
        console.log(`[APP] WAF mode: ${process.env.WAF_MODE || 'detect'}`);
        console.log(`[APP] Eve log: ${process.env.EVE_JSON_PATH || '/var/log/suricata/eve.json'}`);
    });
});
