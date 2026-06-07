# PT. Baroque-ah — Demo Lab IDS/IPS & Honeypot

Aplikasi web **sengaja rentan** untuk demo edukasi keamanan di kelas.
Mendemonstrasikan cara kerja IDS/IPS dan honeypot secara realtime.

---

## Stack

| Service | Image | Peran |
|---|---|---|
| `app` | Build lokal (Node 20) | Web target rentan + WAF middleware + monitor + honeypot |
| `mysql` | mysql:8 | Database |
| `suricata` | jasonish/suricata | IDS — sniff trafik, generate `eve.json` |
| `evebox` | jasonish/evebox | Dashboard Suricata (backup, akses via SSH tunnel) |

---

## Deploy di VPS

### Prasyarat
- VPS Ubuntu 22/24, minimal RAM 2 GB
- Docker & Docker Compose v2 terinstall
- Akses SSH

### Langkah deploy

**1. Clone repo dan masuk ke folder:**
```bash
git clone <repo-url> && cd <nama-folder>
```

**2. Buat file konfigurasi:**
```bash
cp .env.example .env
nano .env
```

Isi wajib diganti (jangan pakai nilai default):
```
DB_PASS=password_kuat_db
DB_ROOT_PASS=password_kuat_root
SESSION_SECRET=string_acak_panjang_min_32_karakter
MONITOR_TOKEN=token_rahasia_untuk_akses_monitor
```

**3. (Opsional) Sesuaikan interface Suricata:**
```bash
# Cek nama interface utama VPS
ip addr
# Kalau bukan eth0, update di .env:
SURICATA_INTERFACE=ens3   # atau enp0s1, dll
```

**4. Build dan jalankan:**
```bash
docker compose up -d --build
```

**5. Verifikasi semua service jalan:**
```bash
docker compose ps
docker compose logs app --tail 40
```

Output normal di log `app`:
```
[DB] Connected to MySQL
[WAF] Initialized — mode: DETECT
[EVE] Waiting for /var/log/suricata/eve.json — retry in 5s
[APP] PT. Baroque-ah Demo running on http://0.0.0.0:3000
```
Baris `[EVE] Waiting...` normal — hilang setelah Suricata selesai start (~30 detik).

**6. WAJIB — Kunci cloud firewall:**

Di panel VPS (DigitalOcean / Vultr / Linode / AWS):
```
Allow TCP 80    → HANYA dari IP publik ruangan (cek di whatismyip.com saat di lokasi)
Allow TCP 22    → HANYA dari IP laptop kamu
Drop semua sisanya
```
Tanpa firewall, VPS akan diserang beneran dalam menit.

**7. Akses EveBox (opsional — dashboard Suricata detail):**
```bash
# Dari laptop kamu, buat SSH tunnel:
ssh -L 5636:127.0.0.1:5636 user@IP-VPS

# Lalu buka di browser:
http://localhost:5636
```

**8. WAJIB — Snapshot VPS sebelum demo:**

Buat snapshot di panel VPS untuk rollback instan kalau ada masalah saat demo.

---

## Saat Demo

### Setup presenter
```bash
# Buka monitor di laptop (tampilkan ke proyektor):
http://IP-VPS/monitor?token=TOKEN_KAMU

# Buka daftar tantangan di tab lain:
http://IP-VPS/play
```

### Setup peserta
1. Minta peserta konek ke jaringan yang IP-nya sudah di-whitelist di firewall
2. Buka di browser HP/laptop: `http://IP-VPS`
3. Masukkan nickname → klik **Mulai Serang**
4. Buka `/play` untuk daftar tantangan

### Ganti mode WAF untuk demo IPS
```bash
# Di .env, ubah WAF_MODE lalu restart app saja (tanpa rebuild):
WAF_MODE=block docker compose up -d app

# Atau edit .env lalu:
docker compose up -d app
```

| Mode | Efek |
|---|---|
| `detect` | Serangan **berhasil** + tercatat di monitor (demo IDS) |
| `block` | Serangan **diblokir**, muncul halaman merah KETAHUAN (demo IPS) |

### Test Suricata tanpa serangan nyata
```bash
# Inject 1 alert dummy (dari browser/curl):
curl "http://IP-VPS/api/test-suricata?token=TOKEN_KAMU"

# Inject 5 sekaligus:
curl "http://IP-VPS/api/test-suricata?token=TOKEN_KAMU&count=5"
```
Event akan muncul di monitor sebagai card **cyan** berlabel `SURICATA`.

---

## Endpoint lengkap

| Route | Jenis | Kerentanan |
|---|---|---|
| `GET /` | Landing | Nickname gateway |
| `GET/POST /login` | Target | SQL Injection |
| `GET/POST /comments` | Target | Stored XSS |
| `GET /search?q=` | Target | Reflected XSS + SQLi UNION |
| `GET/POST /tools/ping` | Target | Command Injection |
| `GET /view?file=` | Target | Path Traversal |
| `GET /admin-backup` | Honeypot | Jebakan admin palsu |
| `GET /secret-login` | Honeypot | Jebakan login palsu |
| `GET /robots.txt` | Bait | Mendaftarkan path honeypot |
| `GET /play` | Info | Daftar tantangan peserta |
| `GET /monitor?token=` | Monitor | Dashboard realtime |
| `GET /api/test-suricata?token=` | Debug | Inject dummy Suricata alert |

---

## Payload demo (untuk presenter)

### 1. SQLi — Login bypass
```
URL:      /login
Username: ' OR '1'='1' --
Password: (kosong)
Efek:     Masuk sebagai admin, FLAG muncul
```

### 2. Stored XSS
```
URL:     /comments
Payload: <script>alert('Hacked by '+document.title)</script>
Efek:    Script jalan di browser SEMUA orang yang buka /comments
```

### 3. SQLi UNION — extract database
```
URL:     /search?q=
Payload: ' UNION SELECT 1,username,secret_flag,4 FROM users--
Efek:    Menampilkan username + FLAG semua user dari tabel users
```

### 4. Command Injection
```
URL:     /tools
Input:   127.0.0.1; id
Efek:    Output: uid=0(root) — jalan sebagai root di container
```

### 5. Path Traversal
```
URL:  /view?file=../../etc/passwd
Efek: Membaca /etc/passwd dari container
```

### 6. Honeypot (jangan kasih tahu peserta dulu!)
```
Bait: robots.txt → /admin-backup
Bait: View Source → komentar HTML /secret-login
Bait: Inspect Element footer /comments → link tersembunyi
Efek: Akses honeypot → event merah HIGH di monitor
```

---

## Reset antar sesi
```bash
# Hapus semua data (events, komentar, user session) + rebuild
docker compose down -v
docker compose up -d --build
```

---

## Troubleshooting

**Suricata tidak menghasilkan alert:**
```bash
docker compose logs suricata --tail 50
# Cek nama interface — mungkin bukan eth0
ip addr
# Update SURICATA_INTERFACE di .env lalu restart:
docker compose up -d suricata
```

**App tidak bisa connect ke DB:**
```bash
docker compose logs mysql --tail 20
# Tunggu ~30 detik setelah pertama kali up — MySQL perlu inisialisasi
```

**Monitor tidak update realtime:**
```bash
# Pastikan Socket.io bisa tersambung — tidak ada proxy yang memblokir WebSocket
# Atau minta peserta refresh sekali
```

**Reset total kalau ada yang rusak:**
```bash
docker compose down -v && docker compose up -d --build
```
