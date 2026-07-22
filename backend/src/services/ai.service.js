const axios = require('axios');

function detectProvider(key = '') {
  if (!key) return null;
  if (key.startsWith('gsk_'))    return 'groq';
  if (key.startsWith('AIza'))    return 'gemini';
  if (key.startsWith('sk-ant-')) return 'claude';
  if (key.startsWith('sk-'))     return 'openai';
  return null;
}

async function callAI(prompt, apiKey) {
  const provider = detectProvider(apiKey);
  if (!provider) throw new Error('Unknown API key format. Groq=gsk_, Gemini=AIza, Claude=sk-ant-, OpenAI=sk-');

  if (provider === 'claude') {
    const res = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1024,
      messages: [{ role: 'user', content: prompt }],
    }, { headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' }, timeout: 60000 });
    return res.data.content[0].text;
  }

  if (provider === 'openai') {
    const res = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: 'gpt-4o-mini', max_tokens: 1024,
      messages: [{ role: 'user', content: prompt }],
    }, { headers: { Authorization: `Bearer ${apiKey}` }, timeout: 60000 });
    return res.data.choices[0].message.content;
  }

  if (provider === 'groq') {
    const res = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
      model: 'llama-3.3-70b-versatile', max_tokens: 1024,
      messages: [{ role: 'user', content: prompt }],
    }, { headers: { Authorization: `Bearer ${apiKey}` }, timeout: 60000 });
    return res.data.choices[0].message.content;
  }

  if (provider === 'gemini') {
    const res = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
      { contents: [{ parts: [{ text: prompt }] }], generationConfig: { maxOutputTokens: 1024 } },
      { timeout: 60000 }
    );
    return res.data.candidates[0].content.parts[0].text;
  }
}

async function summarizeFindings(gitleaks, semgrep, owasp, trivy, apiKey) {
  if (!apiKey) return 'No AI key configured — add one in Settings to get an AI summary.';

  const gitleaksSummary = (() => {
    try {
      const parsed = JSON.parse(gitleaks || '[]');
      return Array.isArray(parsed) ? `${parsed.length} secrets found` : 'unavailable';
    } catch { return gitleaks ? 'report available' : 'not run'; }
  })();

  const semgrepSummary = (() => {
    try {
      const parsed = JSON.parse(semgrep || '{"results":[]}');
      return `${(parsed.results || []).length} issues found`;
    } catch { return semgrep ? 'report available' : 'not run'; }
  })();

  const owaspSummary = (() => {
    try {
      const parsed = JSON.parse(owasp || '{"dependencies":[]}');
      const vulnCount = (parsed.dependencies || []).filter(d => d.vulnerabilities?.length).length;
      return `${vulnCount} vulnerable dependencies`;
    } catch { return owasp ? 'report available' : 'not run'; }
  })();

  const trivySummary = trivy
    ? trivy.includes('CRITICAL') || trivy.includes('HIGH')
      ? 'critical/high CVEs found in container'
      : 'no high/critical CVEs in container'
    : 'not run (no Dockerfile)';

  const prompt = `You are a security analyst. Summarize these security scan results in 4-6 bullet points. Be concise and actionable.

Gitleaks (secrets): ${gitleaksSummary}
Semgrep (SAST): ${semgrepSummary}
OWASP Dependency Check: ${owaspSummary}
Trivy (container): ${trivySummary}

Provide:
- Overall risk level (Critical/High/Medium/Low)
- Key findings per scanner
- Top 2-3 immediate actions to take`;

  try {
    return await callAI(prompt, apiKey);
  } catch (err) {
    return `AI summary failed: ${err.message}`;
  }
}

async function analyzeRepo({ language, frameworks, keyFiles, hasDockerfile }, apiKey) {
  if (!apiKey) return null;

  const stackDesc = [
    `Language: ${language}`,
    frameworks.length ? `Frameworks: ${frameworks.join(', ')}` : null,
    `Dockerfile present: ${hasDockerfile ? 'Yes' : 'No'}`,
    keyFiles.length ? `Key files found: ${keyFiles.join(', ')}` : null,
  ].filter(Boolean).join('\n');

  const prompt = `You are a security engineer reviewing a repository before running automated security scans.

Repository details:
${stackDesc}

In 4-5 short bullet points, describe:
- The top security risks for this specific tech stack
- What secrets or credentials to watch for (specific to ${language})
- Common vulnerable dependency patterns for this stack
- Any specific OWASP vulnerabilities common to ${language}/${frameworks[0] || 'this type of'} apps
- What the Trivy scan will ${hasDockerfile ? 'focus on in the container image' : 'skip (no Dockerfile detected)'}

Be specific, concise, and actionable. No generic advice.`;

  try {
    return await callAI(prompt, apiKey);
  } catch {
    return null;
  }
}

module.exports = { detectProvider, callAI, summarizeFindings, analyzeRepo };
