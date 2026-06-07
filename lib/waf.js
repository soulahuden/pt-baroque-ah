const PATTERNS = [
    {
        type:  'sqli',
        label: 'SQL Injection',
        sev:   'high',
        re:    /(\b(union|select|insert|update|delete|drop|alter|exec)\b[\s\S]{0,60}\b(from|into|table|where|values)\b|'[\s]*(or|and)[\s]*'[\s]*[='1]|(--|\s#)\s*$|'[\s]*;)/i,
    },
    {
        type:  'xss',
        label: 'Cross-Site Scripting (XSS)',
        sev:   'medium',
        re:    /(<script[\s>\/]|<\/script|javascript\s*:|on(error|load|click|mouse\w+|focus|blur|key\w+)\s*=\s*["'`]?|<img[^>]{0,100}onerror\s*=)/i,
    },
    {
        type:  'path_traversal',
        label: 'Path Traversal',
        sev:   'high',
        re:    /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|%252e%252e|\/etc\/(passwd|shadow|hostname)|\/proc\/(version|self))/i,
    },
    {
        type:  'command_injection',
        label: 'Command Injection',
        sev:   'critical',
        re:    /[a-z0-9.]\s*([;|`]|\|\||&&)\s*\w|\$\(|`[^`]+`/i,
    },
];

function clientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
        || req.socket?.remoteAddress
        || 'unknown';
}

function flattenValues(obj) {
    const out = [];
    for (const val of Object.values(obj || {})) {
        if (typeof val === 'string')       out.push(val);
        else if (Array.isArray(val))       val.forEach(v => typeof v === 'string' && out.push(v));
    }
    return out;
}

function detectAttack(req) {
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

module.exports = function createWAF(io) {
    const wafMode = (process.env.WAF_MODE || 'detect').toLowerCase();
    console.log(`[WAF] Initialized — mode: ${wafMode.toUpperCase()}`);

    return async function waf(req, res, next) {
        if (req.path.startsWith('/monitor') || req.path.match(/\.(css|js|png|ico|jpg|woff)$/)) {
            return next();
        }

        const match = detectAttack(req);
        if (!match) return next();

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

        if (typeof global.emitEvent === 'function') {
            try { await global.emitEvent(event); } catch (_) {}
        }

        if (wafMode === 'block') {
            return res.status(403).render('blocked', {
                session: req.session,
                event,
                label: pattern.label,
            });
        }

        next();
    };
};
