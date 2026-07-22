const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const db = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

app.use('/api/auth', require('./routes/auth'));
app.use('/api/jenkins', require('./routes/jenkins'));
app.use('/api/scans', require('./routes/scans'));
app.use('/api/settings', require('./routes/settings'));
app.use('/api/github', require('./routes/github'));

app.get('/api/health', (_, res) => res.json({ ok: true }));

async function waitForDb(retries = 20, delayMs = 2000) {
  const schema = fs.readFileSync(path.join(__dirname, 'db/schema.sql'), 'utf8');
  for (let i = 1; i <= retries; i++) {
    try {
      await db.query(schema);
      console.log('DB schema applied');
      return;
    } catch (err) {
      console.log(`DB not ready (attempt ${i}/${retries}): ${err.message}`);
      if (i === retries) throw err;
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
}

const PORT = process.env.PORT || 4500;
waitForDb()
  .then(() => app.listen(PORT, () => console.log(`DevSecurityHub backend on :${PORT}`)))
  .catch(err => { console.error('Startup failed', err.message); process.exit(1); });
