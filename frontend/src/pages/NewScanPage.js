import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';

const S = {
  page: { padding: 32, maxWidth: 660 },
  h1: { fontSize: 22, fontWeight: 700, color: '#e6edf3', marginBottom: 4 },
  sub: { color: '#8b949e', fontSize: 13, marginBottom: 28 },
  card: { background: '#161b22', border: '1px solid #30363d', borderRadius: 8, padding: 28, marginBottom: 18 },
  label: { display: 'block', fontSize: 12, color: '#8b949e', marginBottom: 6, marginTop: 18 },
  input: { width: '100%', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: '9px 12px', color: '#e6edf3', fontSize: 14, outline: 'none', boxSizing: 'border-box' },
  select: { width: '100%', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: '9px 12px', color: '#e6edf3', fontSize: 14, outline: 'none', boxSizing: 'border-box' },
  hint: { fontSize: 11, color: '#8b949e', marginTop: 4 },
  row: { display: 'flex', gap: 10, marginTop: 20 },
  btn: { padding: '10px 24px', background: '#238636', border: 'none', borderRadius: 6, color: '#fff', fontSize: 14, fontWeight: 600, cursor: 'pointer' },
  btnLoading: { padding: '10px 24px', background: '#1a6626', border: 'none', borderRadius: 6, color: '#8b949e', fontSize: 14, fontWeight: 600, cursor: 'not-allowed', opacity: 0.7 },
  btnCancel: { padding: '10px 18px', background: '#21262d', border: '1px solid #30363d', borderRadius: 6, color: '#8b949e', fontSize: 14, cursor: 'pointer' },
  err: { marginTop: 14, color: '#f85149', fontSize: 13, padding: '10px 14px', background: 'rgba(248,81,73,0.1)', borderRadius: 6, border: '1px solid rgba(248,81,73,0.3)' },
  badge: { display: 'inline-block', padding: '3px 10px', borderRadius: 12, fontSize: 11, fontWeight: 600, marginRight: 6, marginBottom: 4 },
  scanBadge: { background: 'rgba(88,166,255,0.12)', border: '1px solid rgba(88,166,255,0.3)', color: '#58a6ff' },
  skipBadge: { background: 'rgba(139,148,158,0.12)', border: '1px solid #30363d', color: '#8b949e' },
  okBadge: { background: 'rgba(63,185,80,0.15)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)' },
  detCard: { background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: 16, marginTop: 16 },
  detTitle: { fontSize: 12, color: '#8b949e', marginBottom: 10, fontWeight: 600 },
  aiBox: { background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: 14, fontSize: 13, color: '#e6edf3', lineHeight: 1.7, whiteSpace: 'pre-wrap', marginTop: 16 },
  aiTitle: { fontSize: 12, color: '#8b949e', fontWeight: 600, marginBottom: 8 },
  langIcon: { fontSize: 20, marginRight: 8 },
};

const LANG_ICONS = { node: '🟢', python: '🐍', java: '☕', go: '🐹', ruby: '💎', php: '🐘', rust: '🦀', unknown: '📁' };

export default function NewScanPage() {
  const nav = useNavigate();

  // GitHub state
  const [ghConnected, setGhConnected] = useState(false);
  const [repos, setRepos] = useState([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [selectedRepo, setSelectedRepo] = useState('');
  const [branches, setBranches] = useState([]);
  const [branchesLoading, setBranchesLoading] = useState(false);

  // Detection state
  const [detecting, setDetecting] = useState(false);
  const [detection, setDetection] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState('');

  // Form state
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');
  const [manualErr, setManualErr] = useState('');

  useEffect(() => {
    api.get('/github/status').then(r => {
      if (r.data.connected) {
        setGhConnected(true);
        loadRepos();
      }
    }).catch(() => {});
  }, []);

  const loadRepos = async () => {
    setReposLoading(true);
    try {
      const { data } = await api.get('/github/repos');
      setRepos(data);
    } catch {
      setErr('Failed to load GitHub repos. Check your token in Settings.');
    } finally {
      setReposLoading(false);
    }
  };

  const selectRepo = async fullName => {
    setSelectedRepo(fullName);
    setDetection(null);
    setAiAnalysis('');
    setErr('');
    const repo = repos.find(r => r.fullName === fullName);
    if (!repo) return;

    setRepoUrl(repo.cloneUrl);
    setBranch(repo.defaultBranch || 'main');
    setBranches([]);

    // Load branches
    setBranchesLoading(true);
    const [owner, repoName] = fullName.split('/');
    try {
      const { data } = await api.get(`/github/repos/${owner}/${repoName}/branches`);
      setBranches(data.map(b => b.name));
    } catch {
      setBranches([repo.defaultBranch || 'main']);
    } finally {
      setBranchesLoading(false);
    }

    // Auto-detect
    setDetecting(true);
    try {
      const { data: det } = await api.get(`/github/repos/${owner}/${repoName}/detect`);
      setDetection(det);

      // AI pre-analysis
      setAnalyzing(true);
      try {
        const { data: ai } = await api.post(`/github/repos/${owner}/${repoName}/analyze`, det);
        if (ai.analysis) setAiAnalysis(ai.analysis);
      } catch {}
      setAnalyzing(false);
    } catch (e) {
      setErr(e.response?.data?.error || 'Detection failed');
    } finally {
      setDetecting(false);
    }
  };

  const submit = async e => {
    e.preventDefault();
    setErr('');
    setLoading(true);
    try {
      const [owner, repoName] = selectedRepo.split('/');
      const { data } = await api.post('/scans', {
        repoUrl,
        branch,
        detectedLang: detection?.language || '',
        hasDockerfile: detection?.hasDockerfile || false,
        preAnalysis: aiAnalysis || '',
        ghOwner: owner,
        ghRepo: repoName,
      });
      nav(`/scans/${data.id}`);
    } catch (e) {
      setErr(e.response?.data?.error || e.message || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  const manualSubmit = async e => {
    e.preventDefault();
    setManualErr('');
    setLoading(true);
    try {
      const { data } = await api.post('/scans', { repoUrl, branch });
      nav(`/scans/${data.id}`);
    } catch (e) {
      setManualErr(e.response?.data?.error || e.message || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={S.page}>
      <div style={S.h1}>New Security Scan</div>
      <div style={S.sub}>AI analyzes your repo, then Jenkins runs all 4 security scanners automatically.</div>

      {ghConnected ? (
        <div style={S.card}>
          <div style={{ fontSize: 13, color: '#8b949e', marginBottom: 12 }}>Select a repository from your GitHub account:</div>

          {reposLoading ? (
            <div style={{ color: '#8b949e', fontSize: 13 }}>Loading repos...</div>
          ) : (
            <select style={S.select} value={selectedRepo} onChange={e => selectRepo(e.target.value)}>
              <option value="">-- choose a repo --</option>
              {repos.map(r => (
                <option key={r.id} value={r.fullName}>
                  {r.fullName}{r.private ? ' 🔒' : ''}
                </option>
              ))}
            </select>
          )}

          {detecting && (
            <div style={{ color: '#8b949e', fontSize: 13, marginTop: 14 }}>🔍 Analyzing repository...</div>
          )}

          {detection && !detecting && (
            <div style={S.detCard}>
              <div style={S.detTitle}>
                <span style={S.langIcon}>{LANG_ICONS[detection.language] || '📁'}</span>
                Detected: {detection.language.charAt(0).toUpperCase() + detection.language.slice(1)}
                {detection.frameworks.length > 0 && ` · ${detection.frameworks.join(', ')}`}
              </div>

              <div style={{ marginBottom: 10 }}>
                {detection.hasDockerfile
                  ? <span style={{ ...S.badge, ...S.okBadge }}>✓ Dockerfile found</span>
                  : <span style={{ ...S.badge, ...S.skipBadge }}>✗ No Dockerfile — Trivy skipped</span>
                }
                {detection.hasSecurityJenkinsfile
                  ? <span style={{ ...S.badge, ...S.okBadge }}>✓ Jenkinsfile.security exists</span>
                  : <span style={{ ...S.badge, background: 'rgba(210,153,34,0.15)', border: '1px solid rgba(210,153,34,0.4)', color: '#d29922' }}>✎ Jenkinsfile.security will be created</span>
                }
              </div>

              <div style={{ fontSize: 11, color: '#8b949e', marginBottom: 6 }}>Scanners that will run:</div>
              <div>
                {detection.activeScanners.map(s => (
                  <span key={s} style={{ ...S.badge, ...S.scanBadge }}>{s}</span>
                ))}
                {!detection.hasDockerfile && (
                  <span style={{ ...S.badge, ...S.skipBadge }}>trivy (skipped)</span>
                )}
              </div>

              {detection.keyFiles.length > 0 && (
                <div style={{ marginTop: 10, fontSize: 11, color: '#8b949e' }}>
                  Found: {detection.keyFiles.join(', ')}
                </div>
              )}
            </div>
          )}

          {analyzing && (
            <div style={{ color: '#8b949e', fontSize: 13, marginTop: 14 }}>✨ AI analyzing security risks...</div>
          )}

          {aiAnalysis && !analyzing && (
            <div style={S.aiBox}>
              <div style={S.aiTitle}>✨ AI Pre-Scan Analysis</div>
              {aiAnalysis}
            </div>
          )}

          {selectedRepo && !detecting && (
            <form onSubmit={submit}>
              {branches.length > 0 && !branchesLoading && (
                <>
                  <label style={S.label}>Branch</label>
                  <select style={S.select} value={branch} onChange={e => setBranch(e.target.value)}>
                    {branches.map(b => <option key={b} value={b}>{b}</option>)}
                  </select>
                </>
              )}

              {err && <div style={S.err}>{err}</div>}

              <div style={S.row}>
                <button style={loading ? S.btnLoading : S.btn} type="submit" disabled={loading}>
                  {loading ? 'Starting scan...' : '▶ Run Security Scan'}
                </button>
                <button style={S.btnCancel} type="button" onClick={() => nav('/dashboard')}>Cancel</button>
              </div>
            </form>
          )}
        </div>
      ) : (
        <div style={{ ...S.card, marginBottom: 18 }}>
          <div style={{ fontSize: 13, color: '#8b949e', marginBottom: 10 }}>
            Connect GitHub in <span style={{ color: '#58a6ff', cursor: 'pointer' }} onClick={() => nav('/settings')}>Settings</span> to browse repos and get AI pre-scan analysis.
          </div>
        </div>
      )}

      <div style={{ ...S.card, marginTop: 0 }}>
        <div style={{ fontSize: 13, color: '#8b949e', marginBottom: 4, fontWeight: 600 }}>
          {ghConnected ? 'Or scan any public URL manually:' : 'Scan any repository:'}
        </div>
        <form onSubmit={manualSubmit}>
          <label style={S.label}>Repository URL</label>
          <input
            style={S.input}
            value={repoUrl}
            onChange={e => setRepoUrl(e.target.value)}
            placeholder="https://github.com/org/repo.git"
            required
          />
          <div style={S.hint}>Public repos or repos your Jenkins has access to.</div>

          <label style={S.label}>Branch</label>
          <input
            style={S.input}
            value={branch}
            onChange={e => setBranch(e.target.value)}
            placeholder="main"
          />

          {manualErr && <div style={S.err}>{manualErr}</div>}

          <div style={S.row}>
            <button style={loading ? S.btnLoading : S.btn} type="submit" disabled={loading}>
              {loading ? 'Starting scan...' : '▶ Run Scan'}
            </button>
            {!ghConnected && (
              <button style={S.btnCancel} type="button" onClick={() => nav('/dashboard')}>Cancel</button>
            )}
          </div>
        </form>
      </div>
    </div>
  );
}
