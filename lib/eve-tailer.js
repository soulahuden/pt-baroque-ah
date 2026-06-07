// lib/eve-tailer.js — Jembatan Suricata → monitor
//
// Cara kerja:
//   1. Cek apakah EVE_JSON_PATH ada — kalau belum, retry setiap 5s (Suricata mungkin belum start)
//   2. Catat byte-offset terakhir dibaca sehingga hanya baris BARU yang diproses
//   3. Poll setiap 1 detik via setInterval — lebih reliable dari fs.watch di Docker volume mounts
//   4. Parse setiap baris JSON, filter hanya event_type:"alert"
//   5. Map ke format event kita, panggil global.emitEvent → tampil di monitor berdampingan
//      dengan event WAF (app-waf) dan honeypot

const fs = require('fs');

// Suricata severity: integer 1 (paling parah) → 4 (informational)
function mapSeverity(sev) {
    const n = parseInt(sev) || 3;
    if (n <= 1) return 'critical';
    if (n === 2) return 'high';
    if (n === 3) return 'medium';
    return 'low';
}

module.exports = function startEveTailer() {
    const evePath = process.env.EVE_JSON_PATH || '/var/log/suricata/eve.json';
    let filePos   = 0;    // byte offset terakhir yang sudah diproses
    let ready     = false; // sudah berhasil menemukan file pertama kali

    // ── Baca baris-baris baru sejak posisi terakhir ──────────────────────────

    function readNewLines() {
        let fd;
        try {
            fd = fs.openSync(evePath, 'r');
            const { size } = fs.fstatSync(fd);

            // Deteksi file rotation / truncation (Suricata bisa rotate eve.json)
            if (size < filePos) {
                console.log('[EVE] File truncated or rotated — reset to byte 0');
                filePos = 0;
            }
            if (size === filePos) return; // tidak ada konten baru

            const buf = Buffer.alloc(size - filePos);
            fs.readSync(fd, buf, 0, buf.length, filePos);
            filePos = size;

            // Split per baris; baris terakhir mungkin parsial (tulis belum selesai)
            const lines = buf.toString('utf8').split('\n');
            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                try {
                    const evt = JSON.parse(trimmed);
                    if (evt.event_type === 'alert') processAlert(evt);
                } catch (_) {
                    // JSON parsial — tulis Suricata belum selesai, abaikan
                }
            }
        } catch (err) {
            if (err.code !== 'ENOENT') {
                console.error('[EVE] Read error:', err.message);
            }
        } finally {
            if (fd !== undefined) {
                try { fs.closeSync(fd); } catch (_) {}
            }
        }
    }

    // ── Proses satu alert dari eve.json ──────────────────────────────────────

    function processAlert(evtJson) {
        const alert = evtJson.alert || {};
        const http  = evtJson.http  || {};

        // Suricata tidak tahu session/nickname — gunakan 'suricata' sebagai label layer
        // src_ip akan ditampilkan di monitor sebagai sumber serangan
        const event = {
            layer:       'network-suricata',
            attack_type: alert.signature || 'Suricata Alert',
            nickname:    'suricata',
            src_ip:      evtJson.src_ip   || 'unknown',
            route:       http.url          || '/',
            method:      http.http_method  || '?',
            payload: [
                alert.signature  || '',
                `[sid:${alert.signature_id || '?'}`,
                `sev:${alert.severity || '?'}`,
                `action:${alert.action || '?'}]`,
            ].join(' ').substring(0, 200),
            severity: mapSeverity(alert.severity),
        };

        if (typeof global.emitEvent === 'function') {
            global.emitEvent(event).catch(err => {
                console.error('[EVE] emitEvent failed:', err.message);
            });
        }
    }

    // ── Start: tunggu file ada dulu, lalu mulai polling ───────────────────────

    function tryStart() {
        if (!fs.existsSync(evePath)) {
            if (!ready) {
                console.log(`[EVE] Waiting for ${evePath} — Suricata belum start? Retry in 5s`);
            }
            setTimeout(tryStart, 5000);
            return;
        }

        if (!ready) {
            // Mulai dari AKHIR file saat ini — jangan replay alert lama saat app restart
            try {
                filePos = fs.statSync(evePath).size;
            } catch (_) {
                filePos = 0;
            }
            console.log(`[EVE] Tailing ${evePath} — start at byte ${filePos}`);
            ready = true;

            // Mulai polling 1 detik sekali
            // Polling lebih reliable dari fs.watch untuk Docker named volumes
            setInterval(readNewLines, 1000);
        }
    }

    tryStart();
    return { getPath: () => evePath }; // expose untuk logging/test
};
