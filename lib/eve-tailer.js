const fs = require('fs');

function mapSeverity(sev) {
    const n = parseInt(sev) || 3;
    if (n <= 1) return 'critical';
    if (n === 2) return 'high';
    if (n === 3) return 'medium';
    return 'low';
}

module.exports = function startEveTailer() {
    const evePath = process.env.EVE_JSON_PATH || '/var/log/suricata/eve.json';
    let filePos   = 0;
    let ready     = false;

    function readNewLines() {
        let fd;
        try {
            fd = fs.openSync(evePath, 'r');
            const { size } = fs.fstatSync(fd);

            if (size < filePos) {
                console.log('[EVE] File rotated — reset to byte 0');
                filePos = 0;
            }
            if (size === filePos) return;

            const buf = Buffer.alloc(size - filePos);
            fs.readSync(fd, buf, 0, buf.length, filePos);
            filePos = size;

            const lines = buf.toString('utf8').split('\n');
            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                try {
                    const evt = JSON.parse(trimmed);
                    if (evt.event_type === 'alert') processAlert(evt);
                } catch (_) {}
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

    function processAlert(evtJson) {
        const alert = evtJson.alert || {};
        const http  = evtJson.http  || {};

        const event = {
            layer:       'network-suricata',
            attack_type: alert.signature || 'Suricata Alert',
            nickname:    'suricata',
            src_ip:      evtJson.src_ip  || 'unknown',
            route:       http.url         || '/',
            method:      http.http_method || '?',
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

    function tryStart() {
        if (!fs.existsSync(evePath)) {
            if (!ready) {
                console.log(`[EVE] Waiting for ${evePath} — retry in 5s`);
            }
            setTimeout(tryStart, 5000);
            return;
        }

        if (!ready) {
            try {
                filePos = fs.statSync(evePath).size;
            } catch (_) {
                filePos = 0;
            }
            console.log(`[EVE] Tailing ${evePath} — start at byte ${filePos}`);
            ready = true;
            setInterval(readNewLines, 1000);
        }
    }

    tryStart();
    return { getPath: () => evePath };
};
