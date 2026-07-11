require('dotenv').config();
const path = require('path');
const { createApp } = require('./app');

const PORT = Number(process.env.PORT) || 5346;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'certwatch.db');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const CHECK_INTERVAL_MS = Number(process.env.CHECK_INTERVAL_MS) || 6 * 3600 * 1000;

const app = createApp({ dbPath: DB_PATH, adminPassword: ADMIN_PASSWORD, checkIntervalMs: CHECK_INTERVAL_MS });

app.listen(PORT, () => {
  console.log(`Certwatch listening on http://localhost:${PORT}`);
  if (ADMIN_PASSWORD === 'admin') {
    console.log('⚠ Using default admin password — set ADMIN_PASSWORD in .env for production.');
  }
});
