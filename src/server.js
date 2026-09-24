const minimist = require('minimist');
const config = require('./config');
const { createApp } = require('./app');

// Contoh: node src/server.js --port 8080
// Secret wajib diisi lewat environment variable, lihat .env.example
if (!process.env.JWT_SECRET) {
  console.error('ERROR: environment variable JWT_SECRET belum diisi.');
  process.exit(1);
}

const args = minimist(process.argv.slice(2));
const port = args.port || config.port;

createApp().then((app) => {
  app.listen(port, () => console.log(`SecurePay berjalan di http://localhost:${port}`));
});
