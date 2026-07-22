import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../api/client';

const TABS = [
  { id: 'gitleaks', label: '🔑 Secrets (Gitleaks)' },
  { id: 'semgrep', label: '🔍 SAST (SonarQube)' },
  { id: 'owasp', label: '📦 Dependencies (Trivy FS)' },
  { id: 'trivy', label: '🐳 Container (Trivy)' },
  { id: 'checkov', label: '🏗️ IaC (Checkov)' },
  { id: 'ai', label: '✨ AI Summary' },
];

const S = {
  page: { padding: 32 },
  header: { marginBottom: 28 },
  back: { color: '#8b949e', fontSize: 13, cursor: 'pointer', marginBottom: 12, background: 'none', border: 'none', padding: 0 },
  h1: { fontSize: 20, fontWeight: 700, color: '#e6edf3', marginBottom: 6 },
  meta: { display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' },
  branch: { background: '#21262d', border: '1px solid #30363d', borderRadius: 4, padding: '2px 8px', fontSize: 12, color: '#8b949e' },
  status: { display: 'inline-block', padding: '3px 12px', borderRadius: 12, fontSize: 12, fontWeight: 600 },
  running: { background: 'rgba(56,139,253,0.2)', color: '#388bfd' },
  done: { background: 'rgba(63,185,80,0.2)', color: '#3fb950' },
  failed: { background: 'rgba(248,81,73,0.2)', color: '#f85149' },
  pending: { background: 'rgba(139,148,158,0.2)', color: '#8b949e' },
  tabs: { display: 'flex', borderBottom: '1px solid #30363d', marginBottom: 24, gap: 0, overflowX: 'auto' },
  tab: { padding: '10px 18px', cursor: 'pointer', fontSize: 13, color: '#8b949e', background: 'none', border: 'none', borderBottom: '2px solid transparent', whiteSpace: 'nowrap' },
  tabActive: { color: '#58a6ff', borderBottomColor: '#58a6ff' },
  pre: { background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: 20, fontSize: 12, color: '#e6edf3', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 600, overflow: 'auto', fontFamily: 'monospace', lineHeight: 1.6 },
  empty: { color: '#8b949e', fontSize: 13, padding: 20 },
  loading: { color: '#8b949e', fontSize: 13, padding: 20 },
  aiBox: { background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: 20, fontSize: 14, color: '#e6edf3', lineHeight: 1.8, whiteSpace: 'pre-wrap' },
  deleteBtn: { marginLeft: 'auto', padding: '6px 14px', background: '#21262d', border: '1px solid #f85149', borderRadius: 6, color: '#f85149', fontSize: 12, cursor: 'pointer' },
  scannerStat: { display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' },
  statCard: { background: '#161b22', border: '1px solid #30363d', borderRadius: 6, padding: '12px 18px', minWidth: 120 },
  statNum: { fontSize: 24, fontWeight: 700, color: '#f85149' },
  statLabel: { fontSize: 11, color: '#8b949e', marginTop: 2 },
};

function statusStyle(s) {
  if (s === 'running') return S.running;
  if (s === 'done') return S.done;
  if (s === 'failed') return S.failed;
  return S.pending;
}

function parseGitleaks(content) {
  try { return JSON.parse(content); } catch { return null; }
}
function parseJson(content) {
  try { return JSON.parse(content); } catch { return null; }
}

function GitleaksReport({ content }) {
  if (!content) return <div style={S.empty}>No secrets report available yet.</div>;
  const findings = parseGitleaks(content);
  if (!findings || !Array.isArray(findings)) return <pre style={S.pre}>{content}</pre>;
  if (findings.length === 0) return <div style={{ ...S.empty, color: '#3fb950' }}>✓ No secrets found.</div>;
  return (
    <div>
      <div style={S.scannerStat}>
        <div style={S.statCard}>
          <div style={{ ...S.statNum, color: '#f85149' }}>{findings.length}</div>
          <div style={S.statLabel}>Secrets Found</div>
        </div>
      </div>
      {findings.map((f, i) => (
        <div key={i} style={{ ...S.pre, marginBottom: 10, padding: 16 }}>
          <div style={{ color: '#f85149', fontWeight: 700, marginBottom: 6 }}>{f.RuleID || f.ruleId || 'Secret'}</div>
          <div><span style={{ color: '#8b949e' }}>File:</span> {f.File || f.file || 'unknown'}</div>
          {f.StartLine && <div><span style={{ color: '#8b949e' }}>Line:</span> {f.StartLine}</div>}
          {f.Secret && <div><span style={{ color: '#8b949e' }}>Match:</span> {f.Secret.slice(0, 40)}...</div>}
          {f.Description && <div style={{ marginTop: 4, color: '#d29922' }}>{f.Description}</div>}
        </div>
      ))}
    </div>
  );
}

function SonarQubeReport({ content }) {
  if (!content) return <div style={S.empty}>No SonarQube report available yet.</div>;
  const data = parseJson(content);
  if (!data) return <pre style={S.pre}>{content}</pre>;

  if (data.status === 'NOT_CONFIGURED') {
    return (
      <div style={{ ...S.pre, color: '#8b949e' }}>
        <div style={{ fontWeight: 600, marginBottom: 8, color: '#d29922' }}>⚠ SonarQube Not Configured</div>
        <div>{data.message}</div>
        <div style={{ marginTop: 12, fontSize: 11, lineHeight: 1.8 }}>
          Go to Settings → SonarQube → enter your SonarQube URL and token → Push to Jenkins.
        </div>
      </div>
    );
  }

  if (data.status === 'OK') {
    const measures = {};
    (data.measures?.component?.measures || []).forEach(m => { measures[m.metric] = m.value; });
    const bugs = parseInt(measures.bugs || '0');
    const vulns = parseInt(measures.vulnerabilities || '0');
    const codeSmells = parseInt(measures.code_smells || '0');
    const hotspots = parseInt(measures.security_hotspots || '0');
    const ncloc = parseInt(measures.ncloc || '0');
    const issues = data.issues?.issues || [];
    const hasMetrics = data.measures != null;

    const ratingLabel = v => ({ '1': 'A', '2': 'B', '3': 'C', '4': 'D', '5': 'E' }[String(Math.round(v))] || v);
    const ratingColor = v => ({ '1': '#3fb950', '2': '#3fb950', '3': '#d29922', '4': '#f85149', '5': '#f85149' }[String(Math.round(v))] || '#8b949e');
    const sevColor = s => (s === 'BLOCKER' || s === 'CRITICAL') ? '#f85149' : '#d29922';

    return (
      <div>
        <div style={{ color: '#3fb950', fontWeight: 600, marginBottom: 16, fontSize: 13 }}>✓ SonarQube Analysis Complete — {data.projectKey}</div>
        {hasMetrics ? (
          <>
            <div style={S.scannerStat}>
              <div style={S.statCard}>
                <div style={{ ...S.statNum, color: bugs > 0 ? '#f85149' : '#3fb950' }}>{bugs}</div>
                <div style={S.statLabel}>Bugs</div>
              </div>
              <div style={S.statCard}>
                <div style={{ ...S.statNum, color: vulns > 0 ? '#f85149' : '#3fb950' }}>{vulns}</div>
                <div style={S.statLabel}>Vulnerabilities</div>
              </div>
              <div style={S.statCard}>
                <div style={{ ...S.statNum, color: codeSmells > 0 ? '#d29922' : '#3fb950' }}>{codeSmells}</div>
                <div style={S.statLabel}>Code Smells</div>
              </div>
              <div style={S.statCard}>
                <div style={{ ...S.statNum, color: hotspots > 0 ? '#d29922' : '#3fb950' }}>{hotspots}</div>
                <div style={S.statLabel}>Hotspots</div>
              </div>
              {ncloc > 0 && (
                <div style={S.statCard}>
                  <div style={{ ...S.statNum, color: '#e6edf3', fontSize: 18 }}>{ncloc.toLocaleString()}</div>
                  <div style={S.statLabel}>Lines of Code</div>
                </div>
              )}
              {measures.reliability_rating && (
                <div style={S.statCard}>
                  <div style={{ ...S.statNum, color: ratingColor(measures.reliability_rating), fontSize: 22 }}>{ratingLabel(measures.reliability_rating)}</div>
                  <div style={S.statLabel}>Reliability</div>
                </div>
              )}
              {measures.security_rating && (
                <div style={S.statCard}>
                  <div style={{ ...S.statNum, color: ratingColor(measures.security_rating), fontSize: 22 }}>{ratingLabel(measures.security_rating)}</div>
                  <div style={S.statLabel}>Security</div>
                </div>
              )}
            </div>

            {issues.length > 0 && (
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#e6edf3', marginBottom: 12 }}>
                  Top Issues ({data.issues?.total} total)
                </div>
                {issues.map((issue, i) => (
                  <div key={i} style={{ ...S.pre, marginBottom: 8, padding: 14 }}>
                    <div style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
                      <span style={{ color: sevColor(issue.severity), fontWeight: 700, fontSize: 11 }}>{issue.severity}</span>
                      <span style={{ color: '#484f58', fontSize: 11 }}>{issue.type}</span>
                    </div>
                    <div style={{ color: '#e6edf3', fontSize: 13 }}>{issue.message}</div>
                    {issue.component && (
                      <div style={{ color: '#8b949e', fontSize: 11, marginTop: 4 }}>
                        {issue.component.split(':').pop()}{issue.line ? `:${issue.line}` : ''}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {issues.length === 0 && bugs === 0 && vulns === 0 && (
              <div style={{ ...S.empty, color: '#3fb950' }}>✓ No bugs or vulnerabilities found.</div>
            )}
          </>
        ) : (
          <div style={{ color: '#8b949e', fontSize: 13 }}>
            Analysis recorded. Metrics could not be fetched — ensure SonarQube URL and token are set in Settings.
          </div>
        )}
      </div>
    );
  }

  return <pre style={S.pre}>{content}</pre>;
}

function TrivyFsReport({ content }) {
  if (!content) return <div style={S.empty}>No dependency scan report available yet.</div>;
  const data = parseJson(content);
  if (!data) return <pre style={S.pre}>{content}</pre>;
  const results = (data.Results || []).filter(r => r.Vulnerabilities?.length > 0);
  if (results.length === 0) return <div style={{ ...S.empty, color: '#3fb950' }}>✓ No vulnerable dependencies found.</div>;
  const totalVulns = results.reduce((sum, r) => sum + r.Vulnerabilities.length, 0);
  const critical = results.reduce((sum, r) => sum + r.Vulnerabilities.filter(v => v.Severity === 'CRITICAL').length, 0);
  const high = results.reduce((sum, r) => sum + r.Vulnerabilities.filter(v => v.Severity === 'HIGH').length, 0);
  return (
    <div>
      <div style={S.scannerStat}>
        {critical > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#f85149' }}>{critical}</div><div style={S.statLabel}>CRITICAL</div></div>}
        {high > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#d29922' }}>{high}</div><div style={S.statLabel}>HIGH</div></div>}
        <div style={S.statCard}><div style={S.statNum}>{totalVulns}</div><div style={S.statLabel}>Total CVEs</div></div>
      </div>
      {results.map((r, i) => (
        <div key={i} style={{ ...S.pre, marginBottom: 10, padding: 16 }}>
          <div style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
            {r.Target} <span style={{ fontSize: 11, color: '#8b949e' }}>({r.Type})</span>
          </div>
          {r.Vulnerabilities.map((v, j) => (
            <div key={j} style={{ marginBottom: 8, paddingBottom: 8, borderBottom: j < r.Vulnerabilities.length - 1 ? '1px solid #21262d' : 'none' }}>
              <span style={{ color: v.Severity === 'CRITICAL' ? '#f85149' : '#d29922', fontWeight: 600 }}>{v.VulnerabilityID}</span>
              <span style={{ color: '#8b949e', fontSize: 11, marginLeft: 8 }}>{v.Severity}</span>
              <span style={{ color: '#8b949e', fontSize: 11, marginLeft: 8 }}>{v.PkgName} {v.InstalledVersion}</span>
              {v.Title && <div style={{ color: '#8b949e', fontSize: 12, marginTop: 4 }}>{v.Title}</div>}
              {v.FixedVersion && <div style={{ color: '#3fb950', fontSize: 11, marginTop: 2 }}>Fix: {v.FixedVersion}</div>}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

function TrivyReport({ content }) {
  if (!content) return <div style={S.empty}>No Trivy report available. (Runs only if Dockerfile is present)</div>;
  const lines = content.split('\n');
  return (
    <pre style={S.pre}>
      {lines.map((line, i) => {
        const color = line.includes('CRITICAL') ? '#f85149' : line.includes('HIGH') ? '#d29922' : line.includes('MEDIUM') ? '#388bfd' : '#e6edf3';
        return <span key={i} style={{ color }}>{line}{'\n'}</span>;
      })}
    </pre>
  );
}

function CheckovReport({ content }) {
  if (!content) return <div style={S.empty}>No IaC scan report available. (Runs if Dockerfile or docker-compose.yml is present)</div>;
  const raw = parseJson(content);
  if (!raw) return <pre style={S.pre}>{content}</pre>;

  // Checkov outputs an array when scanning multiple files (monorepo), or a single object
  const reports = Array.isArray(raw) ? raw : [raw];
  const failed = reports.flatMap(r => r.results?.failed_checks || []);
  const passed = reports.reduce((s, r) => s + (r.summary?.passed || 0), 0);
  const failedCount = reports.reduce((s, r) => s + (r.summary?.failed || 0), 0) || failed.length;

  if (failedCount === 0) {
    return <div style={{ ...S.empty, color: '#3fb950' }}>✓ No IaC misconfigurations found. {passed} checks passed.</div>;
  }

  const sevColor = s => (s === 'HIGH' || s === 'CRITICAL') ? '#f85149' : s === 'MEDIUM' ? '#d29922' : '#8b949e';
  const high = failed.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length;
  const medium = failed.filter(f => f.severity === 'MEDIUM').length;
  const low = failedCount - high - medium;

  return (
    <div>
      <div style={S.scannerStat}>
        {high > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#f85149' }}>{high}</div><div style={S.statLabel}>HIGH</div></div>}
        {medium > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#d29922' }}>{medium}</div><div style={S.statLabel}>MEDIUM</div></div>}
        {low > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#8b949e' }}>{low}</div><div style={S.statLabel}>LOW</div></div>}
        <div style={S.statCard}><div style={S.statNum}>{failedCount}</div><div style={S.statLabel}>Failures</div></div>
        <div style={S.statCard}><div style={{ ...S.statNum, color: '#3fb950' }}>{passed}</div><div style={S.statLabel}>Passed</div></div>
      </div>
      {failed.map((f, i) => (
        <div key={i} style={{ ...S.pre, marginBottom: 8, padding: 14 }}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 4, alignItems: 'center' }}>
            <span style={{ color: sevColor(f.severity), fontWeight: 700, fontSize: 11 }}>{f.severity || 'INFO'}</span>
            <span style={{ color: '#58a6ff', fontSize: 11, fontFamily: 'monospace' }}>{f.check_id}</span>
          </div>
          <div style={{ color: '#e6edf3', fontSize: 13, marginBottom: 4 }}>{f.check?.name || f.check_id}</div>
          <div style={{ color: '#8b949e', fontSize: 11 }}>
            {f.repo_file_path || f.file_path}
            {f.file_line_range && ` (lines ${f.file_line_range[0]}-${f.file_line_range[1]})`}
          </div>
        </div>
      ))}
    </div>
  );
}

function AiSummary({ scanId, ready }) {
  const [summary, setSummary] = useState('');
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');

  const load = async () => {
    setLoading(true);
    setErr('');
    try {
      const { data } = await api.get(`/scans/${scanId}/reports/ai`);
      setSummary(data.summary || 'No summary available.');
    } catch (e) {
      setErr(e.response?.data?.error || 'Failed to load summary');
    } finally {
      setLoading(false);
    }
  };

  if (!ready) return <div style={S.empty}>Summary will be available once the scan completes.</div>;
  if (!summary && !loading && !err) {
    return (
      <div>
        <div style={{ color: '#8b949e', fontSize: 13, marginBottom: 16 }}>Click to generate an AI-powered summary of all scan findings.</div>
        <button onClick={load} style={{ padding: '9px 20px', background: '#238636', border: 'none', borderRadius: 6, color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
          ✨ Generate AI Summary
        </button>
      </div>
    );
  }
  if (loading) return <div style={S.loading}>Generating summary...</div>;
  if (err) return <div style={{ ...S.empty, color: '#f85149' }}>{err}</div>;
  return <div style={S.aiBox}>{summary}</div>;
}

export default function ScanDetailPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const [scan, setScan] = useState(null);
  const [tab, setTab] = useState('gitleaks');
  const [reports, setReports] = useState({});
  const [loading, setLoading] = useState(true);
  const [pollError, setPollError] = useState('');
  const [actioning, setActioning] = useState(null);
  const eventSourceRef = useRef(null);

  useEffect(() => {
    api.get(`/scans/${id}`).then(r => {
      setScan(r.data);
      setLoading(false);
      if (r.data.status === 'running' || r.data.status === 'pending') {
        startPolling();
      } else if (r.data.status === 'done') {
        loadAllReports();
      }
    }).catch(() => setLoading(false));
    return () => eventSourceRef.current?.close();
  }, [id]);

  const startPolling = () => {
    eventSourceRef.current?.close();
    setPollError('');
    const token = localStorage.getItem('sechub_token');
    const es = new EventSource(`/api/scans/${id}/status/poll?token=${token}`);
    eventSourceRef.current = es;
    es.onmessage = e => {
      try {
        const data = JSON.parse(e.data);
        setScan(prev => ({ ...prev, status: data.status, last_build: data.build || prev?.last_build }));
        if (data.status === 'done') {
          es.close();
          loadAllReports();
        } else if (data.status === 'failed') {
          setPollError(data.error || 'Scan failed.');
          es.close();
        }
      } catch {}
    };
    es.onerror = () => es.close();
  };

  const loadAllReports = async () => {
    const types = ['gitleaks', 'semgrep', 'owasp', 'trivy', 'checkov'];
    const results = await Promise.allSettled(types.map(t => api.get(`/scans/${id}/reports/${t}`)));
    const newReports = {};
    results.forEach((r, i) => {
      if (r.status === 'fulfilled') newReports[types[i]] = r.value.data.content;
    });
    setReports(newReports);
  };

  const rerun = async () => {
    setActioning('rerun');
    try {
      await api.post(`/scans/${id}/rerun`);
      setScan(prev => ({ ...prev, status: 'running', last_build: null }));
      setReports({});
      setPollError('');
      startPolling();
    } catch (err) {
      alert(err.response?.data?.error || 'Rerun failed');
    } finally {
      setActioning(null);
    }
  };

  const stop = async () => {
    setActioning('stop');
    try {
      await api.post(`/scans/${id}/stop`);
      eventSourceRef.current?.close();
      setScan(prev => ({ ...prev, status: 'failed' }));
    } catch (err) {
      alert(err.response?.data?.error || 'Stop failed');
    } finally {
      setActioning(null);
    }
  };

  const deleteScan = async () => {
    if (!window.confirm('Delete this scan?')) return;
    await api.delete(`/scans/${id}`).catch(() => {});
    nav('/dashboard');
  };

  if (loading) return <div style={{ padding: 32, color: '#8b949e' }}>Loading...</div>;
  if (!scan) return <div style={{ padding: 32, color: '#f85149' }}>Scan not found.</div>;

  const done = scan.status === 'done';
  const running = scan.status === 'running' || scan.status === 'pending';

  return (
    <div style={S.page}>
      <div style={S.header}>
        <button style={S.back} onClick={() => nav('/dashboard')}>← Back to Dashboard</button>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div>
            <div style={S.h1}>{scan.repo_url.replace(/\.git$/, '').split('/').slice(-2).join('/')}</div>
            <div style={S.meta}>
              <span style={S.branch}>{scan.branch}</span>
              <span style={{ ...S.status, ...statusStyle(scan.status) }}>
                {scan.status === 'running' ? '⟳ Running' : scan.status === 'done' ? '✓ Done' : scan.status === 'failed' ? '✗ Failed' : '⏳ Pending'}
              </span>
              {scan.last_build && <span style={{ color: '#8b949e', fontSize: 12 }}>Build #{scan.last_build}</span>}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {running && (
              <button
                disabled={actioning === 'stop'}
                onClick={stop}
                style={{
                  padding: '6px 14px', borderRadius: 6, fontSize: 12,
                  background: actioning === 'stop' ? '#21262d' : '#21262d',
                  border: `1px solid ${actioning === 'stop' ? '#484f58' : '#d29922'}`,
                  color: actioning === 'stop' ? '#484f58' : '#d29922',
                  cursor: actioning === 'stop' ? 'not-allowed' : 'pointer',
                  opacity: actioning === 'stop' ? 0.6 : 1,
                }}
              >
                {actioning === 'stop' ? 'Stopping...' : '■ Stop'}
              </button>
            )}
            {!running && (
              <button
                disabled={actioning === 'rerun'}
                onClick={rerun}
                style={{
                  padding: '6px 14px', borderRadius: 6, fontSize: 12,
                  background: '#21262d',
                  border: `1px solid ${actioning === 'rerun' ? '#484f58' : '#388bfd'}`,
                  color: actioning === 'rerun' ? '#484f58' : '#388bfd',
                  cursor: actioning === 'rerun' ? 'not-allowed' : 'pointer',
                  opacity: actioning === 'rerun' ? 0.6 : 1,
                }}
              >
                {actioning === 'rerun' ? 'Rerunning...' : '↺ Rerun'}
              </button>
            )}
            <button style={S.deleteBtn} onClick={deleteScan}>Delete</button>
          </div>
        </div>
      </div>

      {pollError && (
        <div style={{ marginBottom: 20, padding: '12px 16px', background: 'rgba(248,81,73,0.1)', border: '1px solid rgba(248,81,73,0.3)', borderRadius: 6, color: '#f85149', fontSize: 13 }}>
          ✗ {pollError}
        </div>
      )}

      {scan.detected_lang && (
        <div style={{ marginBottom: 16, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: '#8b949e' }}>Detected:</span>
          <span style={{ background: '#21262d', border: '1px solid #30363d', borderRadius: 4, padding: '2px 8px', fontSize: 12, color: '#e6edf3' }}>
            {scan.detected_lang}
          </span>
          {scan.has_dockerfile
            ? <span style={{ background: 'rgba(63,185,80,0.15)', border: '1px solid rgba(63,185,80,0.3)', borderRadius: 4, padding: '2px 8px', fontSize: 11, color: '#3fb950' }}>✓ Dockerfile</span>
            : <span style={{ background: 'rgba(139,148,158,0.1)', border: '1px solid #30363d', borderRadius: 4, padding: '2px 8px', fontSize: 11, color: '#8b949e' }}>✗ No Dockerfile — Trivy skipped</span>
          }
          {scan.jenkinsfile_pushed && (
            <span style={{ background: 'rgba(88,166,255,0.12)', border: '1px solid rgba(88,166,255,0.3)', borderRadius: 4, padding: '2px 8px', fontSize: 11, color: '#58a6ff' }}>
              ✓ Jenkinsfile.security pushed to repo
            </span>
          )}
        </div>
      )}

      {scan.pre_analysis && (
        <div style={{ marginBottom: 20, background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: 16 }}>
          <div style={{ fontSize: 12, color: '#8b949e', fontWeight: 600, marginBottom: 8 }}>✨ AI Pre-Scan Analysis</div>
          <div style={{ fontSize: 13, color: '#e6edf3', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>{scan.pre_analysis}</div>
        </div>
      )}

      <div style={S.tabs}>
        {TABS.map(t => (
          <button key={t.id} style={{ ...S.tab, ...(tab === t.id ? S.tabActive : {}) }} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'gitleaks' && <GitleaksReport content={reports.gitleaks} />}
      {tab === 'semgrep' && <SonarQubeReport content={reports.semgrep} />}
      {tab === 'owasp' && <TrivyFsReport content={reports.owasp} />}
      {tab === 'trivy' && <TrivyReport content={reports.trivy} />}
      {tab === 'checkov' && <CheckovReport content={reports.checkov} />}
      {tab === 'ai' && <AiSummary scanId={id} ready={done} />}
    </div>
  );
}
