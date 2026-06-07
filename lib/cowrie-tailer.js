const fs = require('fs');

const EVENT_MAP = {
    'cowrie.login.failed':         { attack_type: 'ssh_brute_force',  severity: 'medium' },
    'cowrie.login.success':        { attack_type: 'ssh_login_success', severity: 'critical' },
    'cowrie.command.input':        { attack_type: 'ssh_command',       severity: 'high' },
    'cowrie.session.file_download':{ attack_type: 'malware_download',  severity: 'critical' },
    'cowrie.session.file_upload':  { attack_type: 'file_upload',       severity: 'high' },
    'cowrie.session.connect':      { attack_type: 'ssh_connect',       severity: 'low' },
};

module.exports = function startCowrieTailer() {
    const cowriePath = process.env.COWRIE_JSON_PATH || '/var/log/cowrie/cowrie.json';
    let filePos      = 0;
    let ready        = false;

    function readNewLines() {
        let fd;
        try {
            fd = fs.openSync(cowriePath, 'r');
            const { size } = fs.fstatSync(fd);

            if (size < filePos) {
                console.log('[COWRIE] File rotated — reset to byte 0');
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
                    processEvent(evt);
                } catch (_) {}
            }
        } catch (err) {
            if (err.code !== 'ENOENT') {
                console.error('[COWRIE] Read error:', err.message);
            }
        } finally {
            if (fd !== undefined) try { fs.closeSync(fd); } catch (_) {}
        }
    }

    function processEvent(evt) {
        const mapped = EVENT_MAP[evt.eventid];
        if (!mapped) return;

        let payload = '';
        if (evt.username) payload += `user="${evt.username}" `;
        if (evt.password) payload += `pass="${evt.password}" `;
        if (evt.input)    payload += `cmd="${evt.input}" `;
        if (evt.url)      payload += `url="${evt.url}" `;
        if (evt.outfile)  payload += `file="${evt.outfile}"`;
        payload = payload.trim().substring(0, 200) || evt.eventid;

        const event = {
            layer:       'network-cowrie',
            attack_type: mapped.attack_type,
            nickname:    'cowrie',
            src_ip:      evt.src_ip || 'unknown',
            route:       'SSH :22',
            method:      'SSH',
            payload,
            severity:    mapped.severity,
        };

        if (typeof global.emitEvent === 'function') {
            global.emitEvent(event).catch(err => {
                console.error('[COWRIE] emitEvent failed:', err.message);
            });
        }
    }

    function tryStart() {
        if (!fs.existsSync(cowriePath)) {
            if (!ready) {
                console.log(`[COWRIE] Waiting for ${cowriePath} — retry in 5s`);
            }
            setTimeout(tryStart, 5000);
            return;
        }

        if (!ready) {
            try { filePos = fs.statSync(cowriePath).size; } catch (_) { filePos = 0; }
            console.log(`[COWRIE] Tailing ${cowriePath} — start at byte ${filePos}`);
            ready = true;
            setInterval(readNewLines, 1000);
        }
    }

    tryStart();
};
