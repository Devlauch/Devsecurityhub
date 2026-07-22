const express = require('express');
const router = express.Router();
const axios = require('axios');
const auth = require('../middleware/auth');
const db = require('../db');

const GH_API = 'https://api.github.com';

function ghClient(token) {
  return axios.create({
    baseURL: GH_API,
    headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'DevSecurityHub' },
  });
}

router.post('/connect', auth, async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'token required' });
  try {
    const { data } = await ghClient(token).get('/user');
    await db.query(
      `INSERT INTO github_connections (user_id, token, login)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE SET token = $2, login = $3`,
      [req.user.id, token, data.login]
    );
    res.json({ ok: true, login: data.login });
  } catch (e) {
    const status = e.response?.status;
    if (status === 401) return res.status(401).json({ error: 'Invalid token — check your PAT' });
    res.status(500).json({ error: 'GitHub API error: ' + (e.message || 'unknown') });
  }
});

router.get('/status', auth, async (req, res) => {
  const row = await db.query('SELECT login FROM github_connections WHERE user_id = $1', [req.user.id]);
  if (!row.rows.length) return res.json({ connected: false });
  res.json({ connected: true, login: row.rows[0].login });
});

router.delete('/disconnect', auth, async (req, res) => {
  await db.query('DELETE FROM github_connections WHERE user_id = $1', [req.user.id]);
  res.json({ ok: true });
});

router.get('/repos', auth, async (req, res) => {
  const row = await db.query('SELECT token FROM github_connections WHERE user_id = $1', [req.user.id]);
  if (!row.rows.length) return res.status(400).json({ error: 'GitHub not connected' });
  try {
    const { data } = await ghClient(row.rows[0].token).get('/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator');
    res.json(data.map(r => ({
      id: r.id,
      name: r.name,
      fullName: r.full_name,
      private: r.private,
      defaultBranch: r.default_branch,
      cloneUrl: r.clone_url,
      language: r.language,
    })));
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch repos: ' + (e.message || 'unknown') });
  }
});

router.get('/repos/:owner/:repo/detect', auth, async (req, res) => {
  const row = await db.query('SELECT token FROM github_connections WHERE user_id = $1', [req.user.id]);
  if (!row.rows.length) return res.status(400).json({ error: 'GitHub not connected' });

  const { owner, repo } = req.params;
  const client = ghClient(row.rows[0].token);

  try {
    const { data: contents } = await client.get(`/repos/${owner}/${repo}/contents/`);
    const files = contents.map(f => f.name);

    const hasDockerfile = files.some(f => f.toLowerCase() === 'dockerfile');

    let language = 'unknown';
    let frameworks = [];
    const depFiles = [];

    if (files.includes('package.json')) {
      language = 'node';
      depFiles.push('package.json');
      try {
        const { data: pkgFile } = await client.get(`/repos/${owner}/${repo}/contents/package.json`);
        const pkg = JSON.parse(Buffer.from(pkgFile.content, 'base64').toString());
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };
        if (deps['express'])  frameworks.push('express');
        if (deps['react'])    frameworks.push('react');
        if (deps['vue'])      frameworks.push('vue');
        if (deps['next'])     frameworks.push('next.js');
        if (deps['fastify'])  frameworks.push('fastify');
        if (deps['nestjs'] || deps['@nestjs/core']) frameworks.push('nestjs');
      } catch {}
    } else if (files.some(f => ['requirements.txt', 'pyproject.toml', 'setup.py', 'Pipfile'].includes(f))) {
      language = 'python';
      depFiles.push(...files.filter(f => ['requirements.txt', 'pyproject.toml', 'setup.py'].includes(f)));
    } else if (files.some(f => ['pom.xml', 'build.gradle', 'build.gradle.kts'].includes(f))) {
      language = 'java';
      depFiles.push(...files.filter(f => ['pom.xml', 'build.gradle'].includes(f)));
    } else if (files.includes('go.mod')) {
      language = 'go';
      depFiles.push('go.mod');
    } else if (files.includes('Gemfile')) {
      language = 'ruby';
      depFiles.push('Gemfile');
    } else if (files.includes('composer.json')) {
      language = 'php';
      depFiles.push('composer.json');
    } else if (files.includes('Cargo.toml')) {
      language = 'rust';
      depFiles.push('Cargo.toml');
    }

    const keyFiles = files.filter(f =>
      ['package.json', 'requirements.txt', 'pom.xml', 'build.gradle', 'go.mod', 'Gemfile',
       'composer.json', 'Cargo.toml', 'Dockerfile', '.env', '.env.example',
       'docker-compose.yml', '.github', 'Makefile'].includes(f)
    );

    const hasSecurityJenkinsfile = files.includes('Jenkinsfile.security');

    const activeScanners = ['gitleaks', 'semgrep', 'owasp'];
    if (hasDockerfile) activeScanners.push('trivy');

    res.json({ hasDockerfile, hasSecurityJenkinsfile, language, frameworks, keyFiles, depFiles, activeScanners });
  } catch (e) {
    res.status(500).json({ error: 'Failed to detect repo: ' + (e.response?.data?.message || e.message) });
  }
});

router.post('/repos/:owner/:repo/analyze', auth, async (req, res) => {
  const row = await db.query('SELECT token FROM github_connections WHERE user_id = $1', [req.user.id]);
  if (!row.rows.length) return res.status(400).json({ error: 'GitHub not connected' });

  const userRow = await db.query('SELECT ai_api_key FROM users WHERE id = $1', [req.user.id]);
  const aiKey = userRow.rows[0]?.ai_api_key || '';
  if (!aiKey) return res.json({ analysis: null, reason: 'no_ai_key' });

  const { language, frameworks, keyFiles, hasDockerfile } = req.body;
  const { analyzeRepo } = require('../services/ai.service');

  try {
    const analysis = await analyzeRepo({ language, frameworks, keyFiles, hasDockerfile }, aiKey);
    res.json({ analysis });
  } catch (e) {
    res.json({ analysis: null, reason: e.message });
  }
});

router.get('/repos/:owner/:repo/branches', auth, async (req, res) => {
  const row = await db.query('SELECT token FROM github_connections WHERE user_id = $1', [req.user.id]);
  if (!row.rows.length) return res.status(400).json({ error: 'GitHub not connected' });
  try {
    const { owner, repo } = req.params;
    const { data } = await ghClient(row.rows[0].token).get(`/repos/${owner}/${repo}/branches?per_page=100`);
    res.json(data.map(b => ({ name: b.name, sha: b.commit.sha })));
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch branches: ' + (e.message || 'unknown') });
  }
});

module.exports = router;
