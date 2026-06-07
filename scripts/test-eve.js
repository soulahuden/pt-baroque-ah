#!/usr/bin/env node
// scripts/test-eve.js — Inject alert Suricata dummy ke eve.json
//
// Kegunaan:
//   1. Verifikasi tailer bekerja tanpa perlu Suricata beneran
//   2. Demonstrasi di kelas saat Suricata belum menghasilkan alert
//
// Cara pakai (di dalam container app):
//   node scripts/test-eve.js
//   node scripts/test-eve.js /tmp/eve-test.json   ← path custom
//   COUNT=5 node scripts/test-eve.js              ← inject 5 alert sekaligus

const fs   = require('fs');
const path = require('path');

const evePath = process.argv[2] || process.env.EVE_JSON_PATH || '/var/log/suricata/eve.json';
const count   = parseInt(process.env.COUNT) || 1;

// Contoh alert yang cocok dengan custom.rules kita
const SIGNATURES = [
    { sig: 'DEMO SQLi - UNION SELECT detected', sid: 1000001, sev: 2, url: '/search?q=%27+UNION+SELECT' },
    { sig: 'DEMO SQLi - OR-based login bypass', sid: 1000002, sev: 2, url: '/login' },
    { sig: 'DEMO XSS - script tag detected',    sid: 1000004, sev: 2, url: '/comments' },
    { sig: 'DEMO XSS - event handler detected', sid: 1000005, sev: 2, url: '/search' },
    { sig: 'DEMO Path Traversal',               sid: 1000006, sev: 2, url: '/view?file=../../etc/passwd' },
    { sig: 'DEMO Command Injection',            sid: 1000008, sev: 1, url: '/tools/ping' },
    { sig: 'DEMO Honeypot - admin-backup',      sid: 1000009, sev: 3, url: '/admin-backup' },
];

const FAKE_IPS = [
    '192.168.1.10','192.168.1.42','10.0.0.55','172.16.0.23','192.168.0.101',
];

function randomItem(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function buildAlert(pick) {
    return {
        timestamp: new Date().toISOString().replace('Z', '+0000'),
        flow_id:   Math.floor(Math.random() * 9e15),
        in_iface:  'eth0',
        event_type: 'alert',
        src_ip:    randomItem(FAKE_IPS),
        src_port:  40000 + Math.floor(Math.random() * 20000),
        dest_ip:   '10.0.0.1',
        dest_port: 80,
        proto:     'TCP',
        alert: {
            action:       'allowed',    // IDS mode — hanya deteksi, tidak blokir
            gid:          1,
            signature_id: pick.sid,
            rev:          1,
            signature:    pick.sig,
            category:     'Web Application Attack',
            severity:     pick.sev,
        },
        http: {
            hostname:    'baroque-ah.demo',
            url:         pick.url,
            http_method: pick.url.includes('login') || pick.url.includes('comment') ? 'POST' : 'GET',
            protocol:    'HTTP/1.1',
            status:      200,
        },
        app_proto: 'http',
    };
}

// Pastikan folder ada
try {
    fs.mkdirSync(path.dirname(evePath), { recursive: true });
} catch (_) {}

// Inject
let injected = 0;
for (let i = 0; i < count; i++) {
    const pick  = randomItem(SIGNATURES);
    const alert = buildAlert(pick);
    try {
        fs.appendFileSync(evePath, JSON.stringify(alert) + '\n', 'utf8');
        console.log(`[TEST] #${i + 1} injected → "${pick.sig}" (sid:${pick.sid})`);
        injected++;
    } catch (err) {
        console.error(`[TEST] Write error: ${err.message}`);
        process.exit(1);
    }
}

console.log(`\n[TEST] ${injected} alert(s) appended to ${evePath}`);
console.log('[TEST] Tailer akan mendeteksinya dalam ~1 detik.');
console.log('[TEST] Buka monitor untuk melihat event layer network-suricata (cyan).');
