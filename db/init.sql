-- Skema database PT. Baroque-ah Demo Lab
-- File ini di-mount ke MySQL container dan dijalankan otomatis saat pertama kali start

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50),
  password VARCHAR(50),
  role VARCHAR(20) DEFAULT 'user',
  secret_flag VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS comments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nickname VARCHAR(50),
  body TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabel events: diisi oleh WAF middleware (Fase 2) dan honeypot (Fase 4)
CREATE TABLE IF NOT EXISTS events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  layer VARCHAR(30),
  attack_type VARCHAR(50),
  nickname VARCHAR(50),
  src_ip VARCHAR(45),
  route VARCHAR(100),
  method VARCHAR(10),
  payload TEXT,
  severity VARCHAR(10) DEFAULT 'medium'
);

-- Seed: akun demo (password plaintext untuk keperluan demo SQLi)
INSERT INTO users (username, password, role, secret_flag) VALUES
  ('admin', 'sup3rs3cret', 'admin', 'FLAG{sql_injection_berhasil_kamu_hebat}'),
  ('user1', 'password123', 'user', NULL),
  ('guest', 'guest', 'user', NULL);

-- Seed: satu komentar awal biar halaman tidak kosong
INSERT INTO comments (nickname, body) VALUES
  ('system', 'Selamat datang di PT. Baroque-ah! Silakan tinggalkan komentar atau pertanyaan di sini.');
