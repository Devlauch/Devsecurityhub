const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const db = require('../db');
const jenkins = require('../services/jenkins.service');

router.post('/connect', auth, async (req, res) => {
  const { url, username, token } = req.body;
  if (!url || !username || !token) return res.status(400).json({ error: 'url, username and token required' });
  try {
    await jenkins.testConnection(url, username, token);
    await db.query(
      `INSERT INTO jenkins_connections (user_id, url, username, token)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id) DO UPDATE SET url=$2, username=$3, token=$4`,
      [req.user.id, url.replace(/\/$/, ''), username, token]
    );
    res.json({ ok: true, url });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/status', auth, async (req, res) => {
  const row = await db.query('SELECT url, username FROM jenkins_connections WHERE user_id = $1', [req.user.id]);
  if (!row.rows[0]) return res.json({ connected: false });
  res.json({ connected: true, url: row.rows[0].url, username: row.rows[0].username });
});

router.delete('/disconnect', auth, async (req, res) => {
  await db.query('DELETE FROM jenkins_connections WHERE user_id = $1', [req.user.id]);
  res.json({ ok: true });
});

router.post('/sonar', auth, async (req, res) => {
  const { sonarUrl, sonarToken } = req.body;
  if (!sonarUrl || !sonarToken) return res.status(400).json({ error: 'sonarUrl and sonarToken required' });

  let j;
  try { j = await jenkins.getJenkinsForUser(req.user.id); }
  catch { return res.status(400).json({ error: 'Jenkins not connected' }); }

  const escapedUrl = sonarUrl.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const escapedToken = sonarToken.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const script = `
import hudson.slaves.EnvironmentVariablesNodeProperty
import jenkins.model.Jenkins
def inst = Jenkins.instance
def gnp = inst.globalNodeProperties
def existing = gnp.getAll(EnvironmentVariablesNodeProperty.class)
def prop
if (existing.isEmpty()) {
  prop = new EnvironmentVariablesNodeProperty()
  gnp.add(prop)
} else {
  prop = existing[0]
}
prop.envVars.put('SONAR_HOST_URL', '${escapedUrl}')
prop.envVars.put('SONAR_TOKEN', '${escapedToken}')
inst.save()
println 'SONAR_PUSH_OK'
`.trim();

  try {
    const crumb = await jenkins.getCrumb(j.url, j.username, j.token);
    const axios = require('axios');
    const params = new URLSearchParams({ script });
    const response = await axios.post(`${j.url}/scriptText`, params.toString(), {
      auth: { username: j.username, password: j.token },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...crumb },
      timeout: 15000,
    });
    const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    if (!body.includes('SONAR_PUSH_OK')) {
      return res.status(500).json({ error: `Jenkins script error: ${body.slice(0, 300)}` });
    }
    await db.query(
      `INSERT INTO sonar_connections (user_id, url, token)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE SET url=$2, token=$3`,
      [req.user.id, sonarUrl.replace(/\/$/, ''), sonarToken]
    );
    res.json({ ok: true });
  } catch (err) {
    const msg = err.response?.data || err.message;
    res.status(500).json({ error: `Failed to push to Jenkins: ${msg}` });
  }
});

module.exports = router;
