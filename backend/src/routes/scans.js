const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const db = require('../db');
const jenkins = require('../services/jenkins.service');
const { generateSecurityJenkinsfile, buildJobXml } = require('../services/jenkinsfile');
const { summarizeFindings } = require('../services/ai.service');
const { checkAndPushJenkinsfile } = require('../services/github.service');

async function getJenkins(userId) {
  return jenkins.getJenkinsForUser(userId);
}

router.post('/', auth, async (req, res) => {
  const {
    repoUrl, branch = 'main', jobName,
    detectedLang = '', hasDockerfile = false, preAnalysis = '',
    ghOwner, ghRepo,
  } = req.body;
  if (!repoUrl) return res.status(400).json({ error: 'repoUrl required' });

  let j;
  try {
    j = await getJenkins(req.user.id);
  } catch {
    return res.status(400).json({ error: 'Jenkins not connected. Go to Settings to connect.' });
  }

  const baseName = jobName || ('securjenkins-' + repoUrl.replace(/\.git$/, '').split('/').pop().replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 35));
  const safeJob = baseName.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 60) + '-' + Date.now().toString().slice(-6);

  const jf = generateSecurityJenkinsfile(repoUrl, branch, safeJob);

  // Push Jenkinsfile.security to the repo if GitHub is connected
  let jenkinsfilePushed = false;
  if (ghOwner && ghRepo) {
    const ghRow = await db.query('SELECT token FROM github_connections WHERE user_id = $1', [req.user.id]);
    if (ghRow.rows.length) {
      try {
        await checkAndPushJenkinsfile(ghRow.rows[0].token, ghOwner, ghRepo, jf);
        jenkinsfilePushed = true;
      } catch (e) {
        console.warn(`Could not push Jenkinsfile.security to ${ghOwner}/${ghRepo}: ${e.message}`);
      }
    }
  }

  try {
    const xml = buildJobXml(jf);
    await jenkins.createJob(j.url, j.username, j.token, safeJob, xml);
    await jenkins.triggerBuild(j.url, j.username, j.token, safeJob);

    const result = await db.query(
      `INSERT INTO scans
         (user_id, repo_url, branch, job_name, status, detected_lang, has_dockerfile, pre_analysis, jenkinsfile_pushed)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.user.id, repoUrl, branch, safeJob, 'running', detectedLang, hasDockerfile, preAnalysis, jenkinsfilePushed]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/', auth, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM scans WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('[GET /scans] DB error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.get('/:id', auth, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Scan not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('[GET /scans/:id] DB error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.post('/:id/rerun', auth, async (req, res) => {
  let scanRow;
  try { scanRow = await db.query('SELECT * FROM scans WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]); }
  catch (err) { return res.status(500).json({ error: err.message }); }
  if (!scanRow.rows[0]) return res.status(404).json({ error: 'Scan not found' });
  const scan = scanRow.rows[0];

  let j;
  try {
    j = await getJenkins(req.user.id);
  } catch {
    return res.status(400).json({ error: 'Jenkins not connected.' });
  }

  try {
    await db.query('DELETE FROM scan_reports WHERE scan_id = $1', [scan.id]);
    const jf = generateSecurityJenkinsfile(scan.repo_url, scan.branch, scan.job_name);
    const xml = buildJobXml(jf);
    try { await jenkins.deleteJob(j.url, j.username, j.token, scan.job_name); } catch {}
    await jenkins.createJobIfMissing(j.url, j.username, j.token, scan.job_name, xml);
    await jenkins.triggerBuild(j.url, j.username, j.token, scan.job_name);
    await db.query("UPDATE scans SET status='running', last_build=NULL WHERE id=$1", [scan.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[rerun] error:', err.message, err.response?.status, err.response?.data);
    res.status(500).json({ error: err.message });
  }
});

router.post('/:id/stop', auth, async (req, res) => {
  let scanRow;
  try { scanRow = await db.query('SELECT * FROM scans WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]); }
  catch (err) { return res.status(500).json({ error: err.message }); }
  if (!scanRow.rows[0]) return res.status(404).json({ error: 'Scan not found' });
  const scan = scanRow.rows[0];

  let j;
  try {
    j = await getJenkins(req.user.id);
  } catch {
    return res.status(400).json({ error: 'Jenkins not connected.' });
  }

  try {
    await jenkins.stopBuild(j.url, j.username, j.token, scan.job_name);
    await db.query("UPDATE scans SET status='failed' WHERE id=$1", [scan.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/:id', auth, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Scan not found' });
    const scan = result.rows[0];
    try {
      const j = await getJenkins(req.user.id);
      await jenkins.deleteJob(j.url, j.username, j.token, scan.job_name);
    } catch {}
    await db.query('DELETE FROM scans WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/:id/status/poll', auth, async (req, res) => {
  let scanRow;
  try { scanRow = await db.query('SELECT * FROM scans WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]); }
  catch (err) { return res.status(500).json({ error: err.message }); }
  if (!scanRow.rows[0]) return res.status(404).json({ error: 'Scan not found' });
  const scan = scanRow.rows[0];

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  let j;
  try {
    j = await getJenkins(req.user.id);
  } catch {
    send({ status: 'error', error: 'Jenkins not connected' });
    return res.end();
  }

  let attempts = 0;
  const MAX_ATTEMPTS = 360; // 30 minutes at 5s intervals

  const markFailed = async (reason) => {
    await db.query("UPDATE scans SET status='failed' WHERE id=$1", [scan.id]);
    send({ status: 'failed', error: reason });
  };

  const poll = async () => {
    attempts++;
    if (attempts > MAX_ATTEMPTS) {
      await markFailed('Scan timed out after 30 minutes.');
      return true;
    }
    try {
      const build = await jenkins.getBuildStatus(j.url, j.username, j.token, scan.job_name);
      if (build.building) {
        send({ status: 'running', build: build.number });
        await db.query('UPDATE scans SET status=$1, last_build=$2 WHERE id=$3', ['running', build.number, scan.id]);
        return false;
      }
      const done = build.result === 'SUCCESS' || build.result === 'UNSTABLE' || build.result === 'FAILURE';
      if (done) {
        await db.query('UPDATE scans SET status=$1, last_build=$2 WHERE id=$3', ['done', build.number, scan.id]);
        await fetchAndStoreReports(j, scan, build.number);
        send({ status: 'done', build: build.number });
        return true;
      }
      send({ status: 'running' });
      return false;
    } catch (err) {
      if (err.code === 'JOB_NOT_FOUND') {
        // Build may still be queued â€” lastBuild returns 404 until the build starts.
        // Give Jenkins up to 60 seconds (12 attempts) before declaring failure.
        if (attempts <= 12) {
          send({ status: 'running', note: 'Build queued in Jenkins...' });
          return false;
        }
        await markFailed(err.message);
        return true;
      }
      // Transient error (network hiccup, Jenkins restart) â€” keep polling
      send({ status: 'running', note: 'Waiting for Jenkins...' });
      return false;
    }
  };

  const interval = setInterval(async () => {
    const done = await poll();
    if (done) {
      clearInterval(interval);
      res.end();
    }
  }, 5000);

  await poll();

  req.on('close', () => clearInterval(interval));
});

async function fetchAndStoreReports(j, scan, buildNumber) {
  const artifacts = [
    { type: 'gitleaks', file: 'gitleaks-report.json' },
    { type: 'semgrep', file: 'sonarqube-report.json' },
    { type: 'owasp', file: 'trivy-fs-report.json' },
    { type: 'trivy', file: 'trivy-report.txt' },
    { type: 'checkov', file: 'checkov-report.json' },
  ];

  for (const a of artifacts) {
    try {
      const content = await jenkins.getArtifact(j.url, j.username, j.token, scan.job_name, buildNumber, a.file);
      await db.query(
        `INSERT INTO scan_reports (scan_id, type, content)
         VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING`,
        [scan.id, a.type, content]
      );
    } catch {}
  }

  await enrichSonarReport(scan);
}

async function enrichSonarReport(scan) {
  try {
    const reportRow = await db.query("SELECT content FROM scan_reports WHERE scan_id = $1 AND type = 'semgrep'", [scan.id]);
    if (!reportRow.rows[0]) return;
    const report = JSON.parse(reportRow.rows[0].content);
    if (report.status !== 'OK' || !report.projectKey) return;

    const sonarRow = await db.query('SELECT url, token FROM sonar_connections WHERE user_id = $1', [scan.user_id]);
    if (!sonarRow.rows[0]) return;
    const { url, token } = sonarRow.rows[0];

    const axios = require('axios');
    const auth = { username: token, password: '' };

    const [measuresRes, issuesRes] = await Promise.allSettled([
      axios.get(`${url}/api/measures/component`, {
        params: { component: report.projectKey, metricKeys: 'bugs,vulnerabilities,code_smells,security_hotspots,ncloc,reliability_rating,security_rating,sqale_rating' },
        auth, timeout: 15000,
      }),
      axios.get(`${url}/api/issues/search`, {
        params: { componentKeys: report.projectKey, resolved: false, ps: 20, types: 'VULNERABILITY,BUG', severities: 'BLOCKER,CRITICAL,MAJOR' },
        auth, timeout: 15000,
      }),
    ]);

    const enriched = {
      ...report,
      measures: measuresRes.status === 'fulfilled' ? measuresRes.value.data : null,
      issues: issuesRes.status === 'fulfilled' ? issuesRes.value.data : null,
    };

    await db.query(
      "UPDATE scan_reports SET content = $1 WHERE scan_id = $2 AND type = 'semgrep'",
      [JSON.stringify(enriched), scan.id]
    );
  } catch (e) {
    console.warn('[enrichSonarReport] failed:', e.message);
  }
}

router.get('/:id/reports/ai', auth, async (req, res) => {
  try {
    const scanRow = await db.query('SELECT * FROM scans WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (!scanRow.rows[0]) return res.status(404).json({ error: 'Scan not found' });

    const existing = await db.query("SELECT content FROM scan_reports WHERE scan_id = $1 AND type = 'ai_summary'", [req.params.id]);
    if (existing.rows[0]) return res.json({ summary: existing.rows[0].content });

    const reports = await db.query("SELECT type, content FROM scan_reports WHERE scan_id = $1 AND type != 'ai_summary'", [req.params.id]);
    const byType = {};
    reports.rows.forEach(r => { byType[r.type] = r.content; });

    const userRow = await db.query('SELECT ai_api_key FROM users WHERE id = $1', [req.user.id]);
    const aiKey = userRow.rows[0]?.ai_api_key || '';

    const summary = await summarizeFindings(byType.gitleaks, byType.semgrep, byType.owasp, byType.trivy, aiKey);

    if (aiKey) {
      await db.query('INSERT INTO scan_reports (scan_id, type, content) VALUES ($1, $2, $3)', [req.params.id, 'ai_summary', summary]);
    }

    res.json({ summary });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/:id/reports/:type', auth, async (req, res) => {
  try {
    const { id, type } = req.params;
    const validTypes = ['gitleaks', 'semgrep', 'owasp', 'trivy', 'checkov'];
    if (!validTypes.includes(type)) return res.status(400).json({ error: 'Invalid report type' });

    const scanRow = await db.query('SELECT * FROM scans WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    if (!scanRow.rows[0]) return res.status(404).json({ error: 'Scan not found' });

    const report = await db.query('SELECT content FROM scan_reports WHERE scan_id = $1 AND type = $2', [id, type]);
    if (!report.rows[0]) {
      if (scanRow.rows[0].status !== 'done') return res.json({ content: null, pending: true });
      return res.json({ content: null, pending: false });
    }
    res.json({ content: report.rows[0].content });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
