const axios = require('axios');
const db = require('../db');

function getClient(url, username, token) {
  return axios.create({
    baseURL: url,
    auth: { username, password: token },
    headers: { 'Content-Type': 'application/xml' },
    timeout: 30000,
  });
}

async function testConnection(url, username, token) {
  const client = getClient(url, username, token);
  try {
    await client.get('/api/json');
  } catch (err) {
    const code = err.code;
    const status = err.response?.status;
    if (code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'ETIMEDOUT')
      throw new Error(`Cannot reach Jenkins at ${url}. If Jenkins is on your host machine, use http://host.docker.internal:8080`);
    if (status === 401 || status === 403)
      throw new Error('Jenkins rejected credentials. Check your username and API token.');
    throw new Error(err.response?.data || err.message);
  }
}

async function getJenkinsForUser(userId) {
  const row = await db.query('SELECT url, username, token FROM jenkins_connections WHERE user_id = $1', [userId]);
  if (!row.rows[0]) throw new Error('Jenkins not connected');
  return row.rows[0];
}

async function createJob(url, username, token, jobName, jobXml) {
  const client = getClient(url, username, token);
  const safe = encodeURIComponent(jobName);
  try {
    await client.post(`/createItem?name=${safe}`, jobXml);
  } catch (err) {
    if (err.response?.status === 400) {
      // Job already exists — update its pipeline script, crumb required for CSRF
      const crumb = await getCrumb(url, username, token);
      await client.post(`/job/${safe}/config.xml`, jobXml, { headers: crumb });
    } else {
      const msg = err.response?.data || err.message;
      throw new Error(`Jenkins createJob failed (${err.response?.status || err.code}): ${msg}`);
    }
  }
}

// Creates the job only if it doesn't exist — ignores 400 (already exists) without
// attempting a config.xml update (which requires a CSRF crumb).
async function createJobIfMissing(url, username, token, jobName, jobXml) {
  const client = getClient(url, username, token);
  const safe = encodeURIComponent(jobName);
  try {
    await client.post(`/createItem?name=${safe}`, jobXml);
  } catch (err) {
    if (err.response?.status === 400) return; // already exists, nothing to do
    const msg = err.response?.data || err.message;
    throw new Error(`Jenkins createJob failed (${err.response?.status || err.code}): ${msg}`);
  }
}

async function triggerBuild(url, username, token, jobName) {
  const client = getClient(url, username, token);
  const safe = encodeURIComponent(jobName);
  try {
    await client.post(`/job/${safe}/build`);
  } catch (err) {
    const msg = err.response?.data || err.message;
    throw new Error(`Jenkins triggerBuild failed (${err.response?.status || err.code}): ${msg}`);
  }
}

async function getBuildStatus(url, username, token, jobName, buildNumber = 'lastBuild') {
  const client = getClient(url, username, token);
  const safe = encodeURIComponent(jobName);
  try {
    const res = await client.get(`/job/${safe}/${buildNumber}/api/json`, {
      headers: { 'Content-Type': 'application/json' },
    });
    return {
      number: res.data.number,
      result: res.data.result,
      building: res.data.building,
      duration: res.data.duration,
    };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404) {
      const e = new Error(`Jenkins job "${jobName}" not found (404). It may have been deleted from Jenkins.`);
      e.code = 'JOB_NOT_FOUND';
      throw e;
    }
    throw err;
  }
}

async function getArtifact(url, username, token, jobName, buildNumber, artifactName) {
  const client = getClient(url, username, token);
  const safe = encodeURIComponent(jobName);
  const res = await client.get(`/job/${safe}/${buildNumber}/artifact/${artifactName}`, {
    headers: { Accept: 'text/plain' },
  });
  return typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
}

async function stopBuild(url, username, token, jobName) {
  const client = getClient(url, username, token);
  const safe = encodeURIComponent(jobName);
  await client.post(`/job/${safe}/lastBuild/stop`);
}

async function getCrumb(url, username, token) {
  try {
    const client = getClient(url, username, token);
    const res = await client.get('/crumbIssuer/api/json', { headers: { 'Content-Type': 'application/json' } });
    return { [res.data.crumbRequestField]: res.data.crumb };
  } catch {
    return {};
  }
}

async function deleteJob(url, username, token, jobName) {
  const client = getClient(url, username, token);
  const safe = encodeURIComponent(jobName);
  const crumb = await getCrumb(url, username, token);
  try {
    await client.post(`/job/${safe}/doDelete`, null, { headers: crumb });
  } catch (err) {
    console.warn(`[deleteJob] ${jobName}: ${err.response?.status || err.message}`);
  }
}

module.exports = { testConnection, getJenkinsForUser, createJob, createJobIfMissing, triggerBuild, stopBuild, getBuildStatus, getArtifact, deleteJob, getCrumb };
