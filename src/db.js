const crypto = require('crypto');
const initSqlJs = require('sql.js');

// Hash password memakai scrypt (algoritma khusus password) + salt acak per user.
// Format yang disimpan di database: "salt:hash" (keduanya hex).
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

// Verifikasi password: hitung ulang hash dengan salt yang tersimpan, bandingkan dengan timingSafeEqual
function verifyPassword(password, stored) {
  const [salt, hashHex] = String(stored || '').split(':');
  if (!salt || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(password, salt, expected.length);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

// Membuat database SQLite in-memory berisi data contoh
async function createDb() {
  const SQL = await initSqlJs();
  const db = new SQL.Database();

  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    full_name TEXT,
    role TEXT,
    balance INTEGER
  )`);

  const seed = [
    ['admin', 'Admin#2024', 'Administrator SecurePay', 'admin', 0],
    ['budi', 'budi123', 'Budi Santoso', 'customer', 5000000],
    ['sari', 'sari123', 'Sari Wulandari', 'customer', 7500000],
    ['andi', 'andi123', 'Andi Pratama', 'customer', 2500000],
  ];
  const stmt = db.prepare(
    'INSERT INTO users (username, password_hash, full_name, role, balance) VALUES (?, ?, ?, ?, ?)'
  );
  for (const [u, p, name, role, bal] of seed) {
    stmt.run([u, hashPassword(p), name, role, bal]);
  }
  stmt.free();

  return db;
}

// Helper: jalankan query SELECT dan kembalikan array of object
function all(db, sql) {
  const result = db.exec(sql);
  if (result.length === 0) return [];
  const { columns, values } = result[0];
  return values.map((row) => Object.fromEntries(row.map((v, i) => [columns[i], v])));
}

// Helper: SELECT dengan parameter (prepared statement)
function allBound(db, sql, params) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

module.exports = { createDb, hashPassword, verifyPassword, all, allBound };
