import React, { useState, useEffect, useCallback } from 'react';
import api from '../api/client';

const S = {
  page: { padding: 32, maxWidth: 680 },
  h1: { fontSize: 22, fontWeight: 700, color: '#e6edf3', marginBottom: 4 },
  sub: { color: '#8b949e', fontSize: 13, marginBottom: 32 },
  card: { background: '#161b22', border: '1px solid #30363d', borderRadius: 8, padding: 24, marginBottom: 20 },
  cardTitle: { fontSize: 15, fontWeight: 600, color: '#e6edf3', marginBottom: 4 },
  cardSub: { fontSize: 12, color: '#8b949e', marginBottom: 20 },
  label: { display: 'block', fontSize: 12, color: '#8b949e', marginBottom: 6, marginTop: 14 },
  input: { width: '100%', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: '9px 12px', color: '#e6edf3', fontSize: 14, outline: 'none', boxSizing: 'border-box' },
  inputDisabled: { width: '100%', background: '#0d1117', border: '1px solid #21262d', borderRadius: 6, padding: '9px 12px', color: '#484f58', fontSize: 14, outline: 'none', boxSizing: 'border-box', cursor: 'not-allowed' },
  row: { display: 'flex', gap: 10, marginTop: 16, alignItems: 'center' },
  btn: { padding: '8px 18px', background: '#238636', border: 'none', borderRadius: 6, color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer' },
  btnDisabled: { padding: '8px 18px', background: '#21262d', border: 'none', borderRadius: 6, color: '#484f58', fontSize: 13, fontWeight: 600, cursor: 'not-allowed' },
  btnDanger: { padding: '8px 18px', background: '#21262d', border: '1px solid #f85149', borderRadius: 6, color: '#f85149', fontSize: 13, cursor: 'pointer' },
  btnGhost: { padding: '6px 14px', background: 'transparent', border: '1px solid #30363d', borderRadius: 6, color: '#8b949e', fontSize: 12, cursor: 'pointer' },
  badge: { display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 12px', borderRadius: 20, fontSize: 12, fontWeight: 600, marginBottom: 12 },
  ok: { background: 'rgba(63,185,80,0.15)', color: '#3fb950' },
  no: { background: 'rgba(248,81,73,0.15)', color: '#f85149' },
  loading: { background: 'rgba(139,148,158,0.15)', color: '#8b949e' },
  msg: { marginTop: 10, fontSize: 13 },
  msgOk: { marginTop: 10, fontSize: 13, color: '#3fb950' },
  msgErr: { marginTop: 10, fontSize: 13, color: '#f85149' },
  warn: { background: 'rgba(210,153,34,0.12)', border: '1px solid rgba(210,153,34,0.3)', borderRadius: 6, padding: '10px 14px', fontSize: 12, color: '#d2993a', marginBottom: 16 },
};

async function fetchAllStatuses() {
  const [j, s, g] = await Promise.all([
    api.get('/jenkins/status'),
    api.get('/settings'),
    api.get('/github/status'),
  ]);
  return { jenkins: j.data, settings: s.data, github: g.data };
}

async function retryFetch(maxAttempts = 8, delayMs = 2000) {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      return await fetchAllStatuses();
    } catch {
      if (i < maxAttempts - 1) await new Promise(r => setTimeout(r, delayMs));
    }
  }
  return null;
}

export default function SettingsPage() {
  const [loading, setLoading] = useState(true);
  const [jenkinsStatus, setJenkinsStatus] = useState(null);
  const [aiStatus, setAiStatus] = useState(null);
  const [ghStatus, setGhStatus] = useState(null);

  const [jenkinsForm, setJenkinsForm] = useState({ url: '', username: '', token: '' });
  const [jenkinsMsg, setJenkinsMsg] = useState('');

  const [aiKey, setAiKey] = useState('');
  const [aiMsg, setAiMsg] = useState('');

  const [ghToken, setGhToken] = useState('');
  const [ghMsg, setGhMsg] = useState('');

  const [sonarForm, setSonarForm] = useState({ sonarUrl: '', sonarToken: '' });
  const [sonarMsg, setSonarMsg] = useState('');
  const [sonarLoading, setSonarLoading] = useState(false);

  const loadStatuses = useCallback(async () => {
    setLoading(true);
    const result = await retryFetch();
    if (result) {
      setJenkinsStatus(result.jenkins);
      setAiStatus(result.settings);
      setGhStatus(result.github);
    }
    setLoading(false);
  }, []);

  useEffect(() => { loadStatuses(); }, [loadStatuses]);

  const connectJenkins = async e => {
    e.preventDefault();
    setJenkinsMsg('');
    try {
      await api.post('/jenkins/connect', jenkinsForm);
      setJenkinsStatus({ connected: true, url: jenkinsForm.url });
      setSonarMsg(''); // clear any stale sonar error now that Jenkins is connected
      setJenkinsMsg('Connected successfully.');
    } catch (err) {
      setJenkinsMsg(err.response?.data?.error || 'Connection failed');
    }
  };

  const disconnectJenkins = async () => {
    await api.delete('/jenkins/disconnect').catch(() => {});
    setJenkinsStatus({ connected: false });
    setSonarMsg('');
  };

  const saveAiKey = async e => {
    e.preventDefault();
    setAiMsg('');
    try {
      const { data } = await api.post('/settings/ai-key', { apiKey: aiKey });
      setAiStatus({ aiKeySet: true, aiProvider: data.provider });
      setAiMsg(`Saved. Provider: ${data.provider}`);
      setAiKey('');
    } catch (err) {
      setAiMsg(err.response?.data?.error || 'Failed to save key');
    }
  };

  const removeAiKey = async () => {
    await api.delete('/settings/ai-key').catch(() => {});
    setAiStatus({ aiKeySet: false, aiProvider: null });
    setAiMsg('Key removed.');
  };

  const connectGitHub = async e => {
    e.preventDefault();
    setGhMsg('');
    try {
      const { data } = await api.post('/github/connect', { token: ghToken });
      setGhStatus({ connected: true, login: data.login });
      setGhMsg(`Connected as @${data.login}`);
      setGhToken('');
    } catch (err) {
      setGhMsg(err.response?.data?.error || 'Connection failed');
    }
  };

  const disconnectGitHub = async () => {
    await api.delete('/github/disconnect').catch(() => {});
    setGhStatus({ connected: false });
    setGhMsg('Disconnected.');
  };

  const pushSonarToJenkins = async e => {
    e.preventDefault();
    setSonarMsg('');
    setSonarLoading(true);
    try {
      await api.post('/jenkins/sonar', sonarForm);
      setSonarMsg('Pushed to Jenkins successfully. SONAR_HOST_URL and SONAR_TOKEN are now set as global env vars.');
      setSonarForm({ sonarUrl: '', sonarToken: '' });
    } catch (err) {
      setSonarMsg(err.response?.data?.error || 'Failed to push to Jenkins');
    } finally {
      setSonarLoading(false);
    }
  };

  const jenkinsConnected = jenkinsStatus?.connected;

  return (
    <div style={S.page}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
        <div style={S.h1}>Settings</div>
        <button
          style={S.btnGhost}
          onClick={loadStatuses}
          disabled={loading}
          title="Refresh all connection statuses"
        >
          {loading ? 'Checking...' : '↻ Refresh'}
        </button>
      </div>
      <div style={S.sub}>Configure Jenkins and AI provider for security scans.</div>

      {/* Jenkins */}
      <div style={S.card}>
        <div style={S.cardTitle}>Jenkins Connection</div>
        <div style={S.cardSub}>Connect to your Jenkins instance to create and run security scan jobs.</div>
        {loading
          ? <div style={{ ...S.badge, ...S.loading }}>⏳ Checking...</div>
          : jenkinsStatus && (
            <div style={{ ...S.badge, ...(jenkinsConnected ? S.ok : S.no) }}>
              {jenkinsConnected ? `✓ Connected — ${jenkinsStatus.url}` : '✗ Not connected'}
            </div>
          )}
        <form onSubmit={connectJenkins}>
          <label style={S.label}>Jenkins URL</label>
          <input style={S.input} value={jenkinsForm.url} onChange={e => setJenkinsForm(f => ({ ...f, url: e.target.value }))} placeholder="http://host.docker.internal:8080" required />
          <label style={S.label}>Username</label>
          <input style={S.input} value={jenkinsForm.username} onChange={e => setJenkinsForm(f => ({ ...f, username: e.target.value }))} placeholder="admin" required />
          <label style={S.label}>API Token</label>
          <input style={S.input} type="password" value={jenkinsForm.token} onChange={e => setJenkinsForm(f => ({ ...f, token: e.target.value }))} placeholder="11abc..." required />
          <div style={S.row}>
            <button style={S.btn} type="submit">Connect</button>
            {jenkinsConnected && <button style={S.btnDanger} type="button" onClick={disconnectJenkins}>Disconnect</button>}
          </div>
        </form>
        {jenkinsMsg && <div style={{ ...S.msg, color: jenkinsMsg.startsWith('Connected') ? '#3fb950' : '#f85149' }}>{jenkinsMsg}</div>}
      </div>

      {/* SonarQube */}
      <div style={S.card}>
        <div style={S.cardTitle}>SonarQube</div>
        <div style={S.cardSub}>
          Automatically injects <code>SONAR_HOST_URL</code> and <code>SONAR_TOKEN</code> into Jenkins as global environment variables.
          Once pushed, every new scan will use SonarQube for SAST analysis.
        </div>
        {!loading && !jenkinsConnected && (
          <div style={S.warn}>⚠ Connect Jenkins first before pushing SonarQube settings.</div>
        )}
        <form onSubmit={pushSonarToJenkins}>
          <label style={S.label}>SonarQube Server URL</label>
          <input
            style={jenkinsConnected ? S.input : S.inputDisabled}
            disabled={!jenkinsConnected}
            value={sonarForm.sonarUrl}
            onChange={e => setSonarForm(f => ({ ...f, sonarUrl: e.target.value }))}
            placeholder="http://host.docker.internal:9000"
            required
          />
          <label style={S.label}>SonarQube Token</label>
          <input
            style={jenkinsConnected ? S.input : S.inputDisabled}
            disabled={!jenkinsConnected}
            type="password"
            value={sonarForm.sonarToken}
            onChange={e => setSonarForm(f => ({ ...f, sonarToken: e.target.value }))}
            placeholder="sqp_..."
            required
          />
          <div style={{ fontSize: 11, color: '#8b949e', marginTop: 6 }}>
            Generate at SonarQube → My Account → Security → Generate Token
          </div>
          <div style={S.row}>
            <button
              style={jenkinsConnected && !sonarLoading ? S.btn : S.btnDisabled}
              type="submit"
              disabled={!jenkinsConnected || sonarLoading}
            >
              {sonarLoading ? 'Pushing...' : 'Push to Jenkins'}
            </button>
          </div>
        </form>
        {sonarMsg && (
          <div style={sonarMsg.startsWith('Pushed') ? S.msgOk : S.msgErr}>{sonarMsg}</div>
        )}
      </div>

      {/* GitHub */}
      <div style={S.card}>
        <div style={S.cardTitle}>GitHub Connection</div>
        <div style={S.cardSub}>Connect with a Personal Access Token (PAT) to browse your repos when creating a scan. Requires <code>repo</code> scope.</div>
        {loading
          ? <div style={{ ...S.badge, ...S.loading }}>⏳ Checking...</div>
          : ghStatus && (
            <div style={{ ...S.badge, ...(ghStatus.connected ? S.ok : S.no) }}>
              {ghStatus.connected ? `✓ Connected — @${ghStatus.login}` : '✗ Not connected'}
            </div>
          )}
        <form onSubmit={connectGitHub}>
          <label style={S.label}>Personal Access Token</label>
          <input style={S.input} type="password" value={ghToken} onChange={e => setGhToken(e.target.value)} placeholder="ghp_..." />
          <div style={{ fontSize: 11, color: '#8b949e', marginTop: 4 }}>
            Generate at github.com → Settings → Developer settings → Personal access tokens → Fine-grained or Classic (repo scope).
          </div>
          <div style={S.row}>
            <button style={S.btn} type="submit">Connect</button>
            {ghStatus?.connected && <button style={S.btnDanger} type="button" onClick={disconnectGitHub}>Disconnect</button>}
          </div>
        </form>
        {ghMsg && <div style={{ ...S.msg, color: ghMsg.startsWith('Connected') ? '#3fb950' : '#f85149' }}>{ghMsg}</div>}
      </div>

      {/* AI Key */}
      <div style={S.card}>
        <div style={S.cardTitle}>AI Summary Key</div>
        <div style={S.cardSub}>Used to generate plain-English summaries of scan results. Supports Groq (gsk_), Gemini (AIza), Claude (sk-ant-), OpenAI (sk-).</div>
        {loading
          ? <div style={{ ...S.badge, ...S.loading }}>⏳ Checking...</div>
          : aiStatus && (
            <div style={{ ...S.badge, ...(aiStatus.aiKeySet ? S.ok : S.no) }}>
              {aiStatus.aiKeySet ? `✓ Set — ${aiStatus.aiProvider}` : '✗ Not configured'}
            </div>
          )}
        <form onSubmit={saveAiKey}>
          <label style={S.label}>API Key</label>
          <input style={S.input} value={aiKey} onChange={e => setAiKey(e.target.value)} placeholder="sk-... or gsk_... or AIza... or sk-ant-..." />
          <div style={S.row}>
            <button style={S.btn} type="submit">Save Key</button>
            {aiStatus?.aiKeySet && <button style={S.btnDanger} type="button" onClick={removeAiKey}>Remove</button>}
          </div>
        </form>
        {aiMsg && <div style={S.msg}>{aiMsg}</div>}
      </div>
    </div>
  );
}
