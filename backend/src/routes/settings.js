const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const db = require('../db');
const { detectProvider } = require('../services/ai.service');

router.get('/', auth, async (req, res) => {
  const row = await db.query('SELECT ai_api_key FROM users WHERE id = $1', [req.user.id]);
  const key = row.rows[0]?.ai_api_key || '';
  res.json({
    aiKeySet: !!key,
    aiProvider: detectProvider(key),
  });
});

router.post('/ai-key', auth, async (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey) return res.status(400).json({ error: 'apiKey required' });
  const provider = detectProvider(apiKey);
  if (!provider) return res.status(400).json({ error: 'Unknown key format. Must start with gsk_, AIza, sk-ant-, or sk-' });
  await db.query('UPDATE users SET ai_api_key = $1 WHERE id = $2', [apiKey, req.user.id]);
  res.json({ ok: true, provider });
});

router.delete('/ai-key', auth, async (req, res) => {
  await db.query("UPDATE users SET ai_api_key = '' WHERE id = $1", [req.user.id]);
  res.json({ ok: true });
});

module.exports = router;
