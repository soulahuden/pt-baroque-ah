// lib/waf.js — WAF middleware (lapisan deteksi aplikasi)
// Dipasang SEBELUM route rentan, tapi TERPISAH dari kode endpoint
// sehingga endpoint tetap sengaja rentan tanpa modifikasi apapun.
//
// Konsep dua mode (bahan ajar utama):
//   detect  → catat + alert, request dilanjutkan → serangan tetap berhasil di UI
//   block   → catat + balas halaman KETAHUAN, request DIHENTIKAN (demo IPS)

// ─── Pattern deteksi ─────────────────────────────────────────────────────────
// Urutan pemeriksaan menentukan label yang muncul di monitor.
// Satu request hanya dilaporkan sekali (match pertama).

const PATTERNS = [
    {
        type:  'sqli',
        label: 'SQL Injection',
        sev:   'high',
        // UNION SELECT, OR/AND bypass, komentar SQL, stacked query
        re:    /(\b(union|select|insert|update|delete|drop|alter|exec)\b[\s\S]{0,60}\b(from|into|table|where|values)\b|'[\s]*(or|and)[\s]*'[\s]*[='1]|(--|\s#)\s*$|'[\s]*;)/i,
    },
    {
        type:  'xss',
        label: 'Cross-Site Scripting (XSS)',
        sev:   'medium',
        // <script>, javascript:, event handler inline, onerror/onload
        re:    /(<script[\s>\/]|<\/script|javascript\s*:|on(error|load|click|mouse\w+|focus|blur|key\w+)\s*=\s*["'`]?|<img[^>]{0,100}onerror\s*=)/i,
    },
    {
        type:  'path_traversal',
        label: 'Path Traversal',
        sev:   'high',
        // ../ \..\, URL-encoded, /etc/passwd
        re:    /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|%252e%252e|\/etc\/(passwd|shadow|hostname)|\/proc\/(version|self))/i,
    },
    {
        type:  'command_injection',
        label: 'Command Injection',
        sev:   'critical',
        // ; | ` & $() setelah karakter lain, atau &&/||
        re:    /[a-z0-9.]\s*([;|`]|\|\||&&)\s*\w|\$\(|`[^`]+`/i,
    },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function clientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
        || req.socket?.remoteAddress
        || 'unknown';
}

// Flatten semua nilai string dari object (support nested array dari form)
function flattenValues(obj) {
    const out = [];
    for (const val of Object.values(obj || {})) {
        if (typeof val === 'string')       out.push(val);
        else if (Array.isArray(val))       val.forEach(v => typeof v === 'string' && out.push(v));
    }
    return out;
}

// Scan semua input — kembalikan match pertama atau null
function detectAttack(req) {
    // Kumpulkan semua input: query string, body, route params
    const allValues = [
        ...flattenValues(req.query),
        ...flattenValues(req.body),
        ...flattenValues(req.params),
    ];

    for (const value of allValues) {
        if (!value || value.length < 3) continue;
        for (const p of PATTERNS) {
            if (p.re.test(value)) {
                return { pattern: p, payload: value };
            }
        }
    }
    return null;
}

// ─── Middleware factory ───────────────────────────────────────────────────────

module.exports = function createWAF(io) {
    const wafMode = (process.env.WAF_MODE || 'detect').toLowerCase();
    console.log(`[WAF] Initialized — mode: ${wafMode.toUpperCase()}`);

    return async function waf(req, res, next) {
        // Abaikan static files dan monitor
        if (req.path.startsWith('/monitor') || req.path.match(/\.(css|js|png|ico|jpg|woff)$/)) {
            return next();
        }

        const match = detectAttack(req);
        if (!match) return next(); // bersih, lanjut

        const { pattern, payload } = match;
        const event = {
            layer:       'app-waf',
            attack_type: pattern.type,
            nickname:    req.session?.nickname || 'anonymous',
            src_ip:      clientIP(req),
            route:       req.path,
            method:      req.method,
            payload:     payload.substring(0, 200),
            severity:    pattern.sev,
        };

        // Simpan ke DB + broadcast ke semua klien monitor via Socket.io
        if (typeof global.emitEvent === 'function') {
            try { await global.emitEvent(event); } catch (_) {}
        }

        if (wafMode === 'block') {
            // Mode IPS — hentikan request, tampilkan halaman KETAHUAN
            return res.status(403).render('blocked', {
                session: req.session,
                event,
                label: pattern.label,
            });
        }

        // Mode IDS (detect) — catat & teruskan, serangan tetap berhasil di endpoint
        next();
    };
};
