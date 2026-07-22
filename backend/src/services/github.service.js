const axios = require('axios');

function ghClient(token) {
  return axios.create({
    baseURL: 'https://api.github.com',
    headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'DevSecurityHub' },
    timeout: 15000,
  });
}

async function getJenkinsfileStatus(token, owner, repo) {
  try {
    const { data } = await ghClient(token).get(`/repos/${owner}/${repo}/contents/Jenkinsfile.security`);
    return { exists: true, sha: data.sha };
  } catch (e) {
    if (e.response?.status === 404) return { exists: false, sha: null };
    throw e;
  }
}

async function checkAndPushJenkinsfile(token, owner, repo, content) {
  const status = await getJenkinsfileStatus(token, owner, repo);
  const body = {
    message: status.exists
      ? 'chore: update Jenkinsfile.security [DevSecurityHub]'
      : 'chore: add Jenkinsfile.security for security scanning [DevSecurityHub]',
    content: Buffer.from(content).toString('base64'),
  };
  if (status.sha) body.sha = status.sha;
  await ghClient(token).put(`/repos/${owner}/${repo}/contents/Jenkinsfile.security`, body);
  return { wasExisting: status.exists };
}

module.exports = { getJenkinsfileStatus, checkAndPushJenkinsfile };
