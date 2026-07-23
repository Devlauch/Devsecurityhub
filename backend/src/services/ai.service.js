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

async function summarizeFindings(gitleaks, semgrep, owasp, trivy, apiKey, correlated) {
  if (!apiKey) return JSON.stringify({ error: 'No AI key configured — add one in Settings to get an AI summary.' });

  const secretCount = (() => { try { const p = JSON.parse(gitleaks || '[]'); return Array.isArray(p) ? p.length : 0; } catch { return 0; } })();
  const sonarIssues = (() => { try { const p = JSON.parse(semgrep || '{}'); return (p.issues?.issues || []).length; } catch { return 0; } })();
  const trivyResults = (() => { try { const p = JSON.parse(owasp || '{}'); return (p.Results || []).reduce((s, r) => s + (r.Vulnerabilities?.length || 0), 0); } catch { return 0; } })();
  const trivyCritical = trivy ? (trivy.match(/CRITICAL/g) || []).length : 0;

  const correlatedSummary = correlated ? `
Cross-tool correlation found ${correlated.multiToolHits} files flagged by multiple scanners (highest risk).
Top correlated findings:
${(correlated.items || []).slice(0, 5).map(i =>
  `  - ${i.file || 'unknown file'} → tools: [${i.tools.join(', ')}] → severity: ${i.severity}`
).join('\n')}` : '';

  const prompt = `You are a senior application security engineer. Analyze these automated security scan results and respond ONLY with valid JSON (no markdown, no explanation outside JSON).

SCAN RESULTS:
- Gitleaks secrets scanner: ${secretCount} secrets/credentials exposed
- SonarQube SAST: ${sonarIssues} code issues found
- Trivy filesystem: ${trivyResults} vulnerable dependencies
- Trivy container: ${trivyCritical > 0 ? `${trivyCritical} CRITICAL CVEs in container image` : trivy ? 'no critical CVEs' : 'not run (no Dockerfile)'}
${correlatedSummary}

Respond with this exact JSON structure:
{
  "riskLevel": "CRITICAL|HIGH|MEDIUM|LOW",
  "riskScore": <number 0-100>,
  "headline": "<one sentence overall assessment>",
  "topFindings": [
    { "severity": "CRITICAL|HIGH|MEDIUM", "tool": "<tool name>", "issue": "<specific finding>", "fix": "<concrete fix action>" }
  ],
  "immediateActions": ["<action 1>", "<action 2>", "<action 3>"],
  "byTool": {
    "secrets": "<1-sentence assessment>",
    "sast": "<1-sentence assessment>",
    "dependencies": "<1-sentence assessment>",
    "container": "<1-sentence assessment>"
  }
}

topFindings should have 3-5 items. immediateActions should have exactly 3 items. Be specific, not generic.`;

  try {
    const raw = await callAI(prompt, apiKey);
    // Validate it's parseable JSON, return raw string for frontend to parse
    JSON.parse(raw);
    return raw;
  } catch (err) {
    // If JSON parse fails, wrap the text response
    try {
      const text = await callAI(prompt, apiKey);
      return JSON.stringify({ error: null, rawText: text });
    } catch (e) {
      return JSON.stringify({ error: `AI summary failed: ${e.message}` });
    }
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
