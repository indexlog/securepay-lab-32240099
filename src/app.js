const express = require('express');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const config = require('./config');
const { createDb, verifyPassword, allBound } = require('./db');

// Ganti karakter khusus HTML menjadi entity supaya tidak dieksekusi browser
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function createApp() {
  const app = express();
  const db = await createDb();
  let settings = _.cloneDeep(config.defaultSettings);

  app.use(express.json());

  // Middleware autentikasi JWT
  function requireAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.replace('Bearer ', '');
    try {
      req.user = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
      next();
    } catch (err) {
      res.status(401).json({ error: 'Token tidak valid' });
    }
  }

  // Health check
  app.get('/health', (req, res) => res.json({ status: 'ok' }));

  // Halaman sambutan
  app.get('/welcome', (req, res) => {
    const name = req.query.name || 'Tamu';
    res.send(`<h1>Selamat datang di SecurePay, ${escapeHtml(name)}!</h1>`);
  });

  // Login -> mengembalikan JWT
  app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    // 1) ambil user berdasarkan username saja, 2) verifikasi password-nya
    const user = allBound(db, 'SELECT id, username, role, password_hash FROM users WHERE username = ?', [
      String(username),
    ])[0];
    if (!user || !verifyPassword(String(password), user.password_hash)) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, config.jwtSecret, {
      expiresIn: '1h',
    });
    res.json({ token });
  });

  // Cari pengguna berdasarkan nama
  app.get('/api/users/search', (req, res) => {
    const q = req.query.q || '';
    // Parameterized query: input dikirim sebagai DATA, bukan bagian dari perintah SQL
    const rows = allBound(db, 'SELECT id, username, full_name FROM users WHERE full_name LIKE ?', [`%${q}%`]);
    res.json(rows);
  });

  // Detail pengguna berdasarkan id
  app.get('/api/users/:id', (req, res) => {
    // Validasi: id harus berupa angka bulat positif
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ error: 'ID tidak valid' });
    const rows = allBound(db, 'SELECT id, username, full_name, role FROM users WHERE id = ?', [Number(req.params.id)]);
    if (rows.length === 0) return res.status(404).json({ error: 'Pengguna tidak ditemukan' });
    res.json(rows[0]);
  });

  // Transfer uang antar pengguna
  app.post('/api/transfer', requireAuth, (req, res) => {
    const { from, to, amount } = req.body;
    const sender = allBound(db, 'SELECT * FROM users WHERE username = ?', [from])[0];
    const receiver = allBound(db, 'SELECT * FROM users WHERE username = ?', [to])[0];
    if (!sender || !receiver) return res.status(404).json({ error: 'Akun tidak ditemukan' });
    if (sender.balance < amount) return res.status(400).json({ error: 'Saldo tidak cukup' });

    db.run('UPDATE users SET balance = balance - ? WHERE username = ?', [amount, from]);
    db.run('UPDATE users SET balance = balance + ? WHERE username = ?', [amount, to]);
    res.json({ message: 'Transfer berhasil', from, to, amount });
  });

  // Lihat saldo
  app.get('/api/balance/:username', requireAuth, (req, res) => {
    const rows = allBound(db, 'SELECT username, balance FROM users WHERE username = ?', [req.params.username]);
    if (rows.length === 0) return res.status(404).json({ error: 'Akun tidak ditemukan' });
    res.json(rows[0]);
  });

  // Ubah pengaturan aplikasi (digabung dengan pengaturan yang ada)
  app.post('/api/settings', requireAuth, (req, res) => {
    settings = _.merge(settings, req.body);
    res.json(settings);
  });

  // Penanganan error
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err); // detail lengkap hanya di log server
    res.status(500).json({ error: 'Terjadi kesalahan pada server' }); // pesan generik ke klien
  });

  return app;
}

module.exports = { createApp };
