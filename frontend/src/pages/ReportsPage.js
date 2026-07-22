import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';

function repoName(url) {
  try { return url.replace(/\.git$/, '').split('/').slice(-2).join('/'); } catch { return url; }
}

function parseJson(content) {
  try { return JSON.parse(content); } catch { return null; }
}

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const SEV_COLOR = {
  CRITICAL: '#f85149', HIGH: '#d29922', MEDIUM: '#388bfd', LOW: '#3fb950',
  BLOCKER: '#f85149', MAJOR: '#d29922', MINOR: '#8b949e',
};

function SevBadge({ sev }) {
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 4,
      fontSize: 10, fontWeight: 700,
      color: SEV_COLOR[sev] || '#8b949e',
      background: `${SEV_COLOR[sev] || '#8b949e'}18`,
      border: `1px solid ${SEV_COLOR[sev] || '#8b949e'}40`,
    }}>
      {sev}
    </span>
  );
}

const TOOL_TABS = [
  { id: 'overview',  label: '📊 Overview'      },
  { id: 'gitleaks',  label: '🔑 Secrets'        },
  { id: 'sonar',     label: '🔍 SAST'           },
  { id: 'trivy',     label: '📦 Dependencies'   },
  { id: 'checkov',   label: '🏗️ IaC'            },
];

export default function ReportsPage() {
  const nav = useNavigate();
  const [scans, setScans] = useState([]);
  const [reports, setReports] = useState({}); // { [scanId]: { gitleaks, semgrep, owasp, checkov } }
  const [loading, setLoading] = useState(true);
  const [loadingReports, setLoadingReports] = useState(false);
  const [tab, setTab] = useState('overview');
  const [selectedScan, setSelectedScan] = useState('all');

  useEffect(() => {
    api.get('/scans').then(async r => {
      const all = r.data;
      setScans(all);
      setLoading(false);
      const done = all.filter(s => s.status === 'done').slice(0, 10);
      if (done.length > 0) {
        setLoadingReports(true);
        const fetched = {};
        await Promise.allSettled(done.map(async scan => {
          const types = ['gitleaks', 'semgrep', 'owasp', 'checkov'];
          const results = await Promise.allSettled(types.map(t => api.get(`/scans/${scan.id}/reports/${t}`)));
          fetched[scan.id] = {};
          results.forEach((res, i) => {
            if (res.status === 'fulfilled') fetched[scan.id][types[i]] = res.value.data.content;
          });
        }));
        setReports(fetched);
        setLoadingReports(false);
      }
    }).catch(() => setLoading(false));
  }, []);

  // ── Aggregation helpers ──────────────────────────────────────────────────────
  const targetScans = selectedScan === 'all'
    ? scans.filter(s => s.status === 'done').slice(0, 10)
    : scans.filter(s => s.id === selectedScan);

  function getAllSecrets() {
    const out = [];
    for (const scan of targetScans) {
      const raw = reports[scan.id]?.gitleaks;
      if (!raw) continue;
      const data = parseJson(raw);
      if (!Array.isArray(data)) continue;
      data.forEach(f => out.push({ ...f, _scan: scan }));
    }
    return out;
  }

  function getAllSonarIssues() {
    const out = [];
    for (const scan of targetScans) {
      const raw = reports[scan.id]?.semgrep;
      if (!raw) continue;
      const data = parseJson(raw);
      if (!data || data.status !== 'OK') continue;
      (data.issues?.issues || []).forEach(issue => out.push({ ...issue, _scan: scan }));
    }
    return out;
  }

  function getAllCves() {
    const out = [];
    for (const scan of targetScans) {
      const raw = reports[scan.id]?.owasp;
      if (!raw) continue;
      const data = parseJson(raw);
      if (!data) continue;
      (data.Results || []).forEach(r => {
        (r.Vulnerabilities || []).forEach(v => out.push({ ...v, _target: r.Target, _scan: scan }));
      });
    }
    return out.sort((a, b) => (SEV_ORDER[a.Severity] ?? 9) - (SEV_ORDER[b.Severity] ?? 9));
  }

  function getAllIacFailures() {
    const out = [];
    for (const scan of targetScans) {
      const raw = reports[scan.id]?.checkov;
      if (!raw) continue;
      const data = parseJson(raw);
      if (!data) continue;
      const reports_ = Array.isArray(data) ? data : [data];
      reports_.flatMap(r => r.results?.failed_checks || []).forEach(f => out.push({ ...f, _scan: scan }));
    }
    return out;
  }

  // ── Overview stats ───────────────────────────────────────────────────────────
  const secrets = getAllSecrets();
  const sonarIssues = getAllSonarIssues();
  const cves = getAllCves();
  const iacFails = getAllIacFailures();
  const critCves = cves.filter(v => v.Severity === 'CRITICAL').length;
  const highCves = cves.filter(v => v.Severity === 'HIGH').length;
  const doneScanCount = scans.filter(s => s.status === 'done').length;

  const S = {
    page: { padding: 32, animation: 'fadeIn 0.25s ease' },
    h1: { fontSize: 22, fontWeight: 700, color: '#e6edf3', marginBottom: 4 },
    sub: { color: '#8b949e', fontSize: 13, marginBottom: 28 },
    tabs: { display: 'flex', borderBottom: '1px solid #30363d', marginBottom: 24, gap: 0, overflowX: 'auto' },
    tab: { padding: '10px 18px', cursor: 'pointer', fontSize: 13, color: '#8b949e', background: 'none', border: 'none', borderBottom: '2px solid transparent', whiteSpace: 'nowrap' },
    tabActive: { color: '#58a6ff', borderBottomColor: '#58a6ff' },
    card: { background: '#161b22', border: '1px solid #30363d', borderRadius: 10, padding: '16px 20px' },
    row: { display: 'flex', flexWrap: 'wrap', gap: 12, marginBottom: 24 },
    statCard: { flex: '1 1 120px', background: '#161b22', border: '1px solid #30363d', borderRadius: 10, padding: '16px 20px' },
    statNum: { fontSize: 32, fontWeight: 700, lineHeight: 1, marginBottom: 6 },
    statLabel: { fontSize: 11, color: '#8b949e', fontWeight: 600, letterSpacing: '0.06em' },
    finding: { background: '#161b22', border: '1px solid #30363d', borderRadius: 8, padding: 14, marginBottom: 8 },
    findingHdr: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6, flexWrap: 'wrap' },
    empty: { color: '#8b949e', fontSize: 13, padding: '24px 0', textAlign: 'center' },
    scanLink: { color: '#58a6ff', fontSize: 11, cursor: 'pointer', textDecoration: 'none', marginLeft: 'auto' },
  };

  if (loading) {
    return (
      <div style={S.page}>
        <div style={{ height: 28, width: 200, background: '#161b22', borderRadius: 6, marginBottom: 24, animation: 'pulse 1.5s ease-in-out infinite' }} />
        <div style={{ display: 'flex', gap: 12 }}>
          {[1,2,3,4].map(i => <div key={i} style={{ height: 90, flex: 1, background: '#161b22', borderRadius: 10, animation: 'pulse 1.5s ease-in-out infinite' }} />)}
        </div>
      </div>
    );
  }

  return (
    <div style={S.page}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 28 }}>
        <div>
          <div style={S.h1}>Reports Dashboard</div>
          <div style={S.sub}>
            Aggregated findings from {doneScanCount} completed scan{doneScanCount !== 1 ? 's' : ''}
            {loadingReports && <span style={{ marginLeft: 8, color: '#388bfd', animation: 'pulse 1s ease-in-out infinite' }}>· loading reports...</span>}
          </div>
        </div>
        {/* Scan filter */}
        {scans.filter(s => s.status === 'done').length > 0 && (
          <select
            value={selectedScan}
            onChange={e => setSelectedScan(e.target.value)}
            style={{
              background: '#161b22', border: '1px solid #30363d', borderRadius: 6,
              padding: '8px 12px', color: '#e6edf3', fontSize: 13, outline: 'none',
              maxWidth: 240,
            }}
          >
            <option value="all">All scans (latest 10)</option>
            {scans.filter(s => s.status === 'done').map(s => (
              <option key={s.id} value={s.id}>{repoName(s.repo_url)} · {s.branch}</option>
            ))}
          </select>
        )}
      </div>

      {doneScanCount === 0 && (
        <div style={{ ...S.card, textAlign: 'center', padding: '60px 0', color: '#8b949e' }}>
          <div style={{ fontSize: 36, marginBottom: 14 }}>📭</div>
          <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 8, color: '#e6edf3' }}>No completed scans yet</div>
          <div style={{ fontSize: 13, marginBottom: 24 }}>Run a security scan to see reports here.</div>
          <button onClick={() => nav('/scans/new')} style={{ padding: '9px 20px', background: '#238636', border: 'none', borderRadius: 6, color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
            + New Scan
          </button>
        </div>
      )}

      {doneScanCount > 0 && (
        <>
          {/* Tabs */}
          <div style={S.tabs}>
            {TOOL_TABS.map(t => (
              <button key={t.id} style={{ ...S.tab, ...(tab === t.id ? S.tabActive : {}) }} onClick={() => setTab(t.id)}>
                {t.label}
              </button>
            ))}
          </div>

          {/* ── Overview ── */}
          {tab === 'overview' && (
            <div style={{ animation: 'fadeIn 0.2s ease' }}>
              <div style={S.row}>
                <div style={S.statCard}>
                  <div style={{ ...S.statNum, color: secrets.length > 0 ? '#f85149' : '#3fb950' }}>{secrets.length}</div>
                  <div style={S.statLabel}>🔑 SECRETS FOUND</div>
                </div>
                <div style={S.statCard}>
                  <div style={{ ...S.statNum, color: sonarIssues.length > 0 ? '#d29922' : '#3fb950' }}>{sonarIssues.length}</div>
                  <div style={S.statLabel}>🔍 SAST ISSUES</div>
                </div>
                <div style={S.statCard}>
                  <div style={{ ...S.statNum, color: critCves > 0 ? '#f85149' : highCves > 0 ? '#d29922' : '#3fb950' }}>{cves.length}</div>
                  <div style={S.statLabel}>📦 CVEs</div>
                  {critCves > 0 && <div style={{ fontSize: 11, color: '#f85149', marginTop: 4 }}>{critCves} CRITICAL</div>}
                </div>
                <div style={S.statCard}>
                  <div style={{ ...S.statNum, color: iacFails.length > 0 ? '#d29922' : '#3fb950' }}>{iacFails.length}</div>
                  <div style={S.statLabel}>🏗️ IaC FAILURES</div>
                </div>
              </div>

              {/* Scan summary table */}
              <div style={{ ...S.card, padding: 0, overflow: 'hidden' }}>
                <div style={{ padding: '14px 20px', borderBottom: '1px solid #30363d' }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: '#8b949e', letterSpacing: '0.06em' }}>SCAN SUMMARY</div>
                </div>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ background: '#0d1117' }}>
                      {['Repository', 'Branch', '🔑 Secrets', '🔍 SAST', '📦 CVEs', '🏗️ IaC', ''].map((h, i) => (
                        <th key={i} style={{ textAlign: 'left', padding: '10px 16px', fontSize: 11, color: '#8b949e', fontWeight: 700, letterSpacing: '0.05em', borderBottom: '1px solid #30363d' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {targetScans.map((scan, idx) => {
                      const rep = reports[scan.id] || {};
                      const secs = (() => { const d = parseJson(rep.gitleaks); return Array.isArray(d) ? d.length : '–'; })();
                      const sast = (() => { const d = parseJson(rep.semgrep); return d?.status === 'OK' ? (d.issues?.total || 0) : '–'; })();
                      const cvesCount = (() => { const d = parseJson(rep.owasp); return d ? (d.Results || []).reduce((s, r) => s + (r.Vulnerabilities?.length || 0), 0) : '–'; })();
                      const iacCount = (() => { const d = parseJson(rep.checkov); if (!d) return '–'; const r = Array.isArray(d) ? d : [d]; return r.reduce((s, x) => s + (x.summary?.failed || 0), 0); })();
                      const hasFindings = (typeof secs === 'number' && secs > 0) || (typeof cvesCount === 'number' && cvesCount > 0);
                      return (
                        <tr key={scan.id} style={{ borderBottom: idx < targetScans.length - 1 ? '1px solid #21262d' : 'none' }}>
                          <td style={{ padding: '12px 16px', fontSize: 13 }}>
                            <span style={{ color: '#58a6ff', fontWeight: 500 }}>{repoName(scan.repo_url)}</span>
                            {hasFindings && <span style={{ marginLeft: 8, width: 6, height: 6, borderRadius: '50%', background: '#f85149', display: 'inline-block', verticalAlign: 'middle' }} />}
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <span style={{ background: '#21262d', border: '1px solid #30363d', borderRadius: 3, padding: '1px 6px', fontSize: 11, color: '#8b949e' }}>{scan.branch}</span>
                          </td>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: typeof secs === 'number' && secs > 0 ? '#f85149' : typeof secs === 'number' ? '#3fb950' : '#484f58' }}>{secs}</td>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: typeof sast === 'number' && sast > 0 ? '#d29922' : typeof sast === 'number' ? '#3fb950' : '#484f58' }}>{sast}</td>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: typeof cvesCount === 'number' && cvesCount > 0 ? '#d29922' : typeof cvesCount === 'number' ? '#3fb950' : '#484f58' }}>{cvesCount}</td>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: typeof iacCount === 'number' && iacCount > 0 ? '#d29922' : typeof iacCount === 'number' ? '#3fb950' : '#484f58' }}>{iacCount}</td>
                          <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                            <button onClick={() => nav(`/scans/${scan.id}`)} style={{ padding: '4px 12px', background: '#21262d', border: '1px solid #30363d', borderRadius: 6, color: '#8b949e', fontSize: 12, cursor: 'pointer' }}>
                              View →
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Secrets (Gitleaks) ── */}
          {tab === 'gitleaks' && (
            <div style={{ animation: 'fadeIn 0.2s ease' }}>
              <div style={{ fontSize: 13, color: '#8b949e', marginBottom: 16 }}>
                {secrets.length === 0 ? '✓ No secrets found across scanned repositories.' : `${secrets.length} secret${secrets.length !== 1 ? 's' : ''} found`}
              </div>
              {secrets.length === 0 && <div style={{ ...S.empty, fontSize: 40 }}>🔐</div>}
              {secrets.map((f, i) => (
                <div key={i} style={S.finding}>
                  <div style={S.findingHdr}>
                    <SevBadge sev="HIGH" />
                    <span style={{ color: '#f85149', fontWeight: 700, fontSize: 13 }}>{f.RuleID || f.ruleId || 'Secret'}</span>
                    <span
                      style={S.scanLink}
                      onClick={() => nav(`/scans/${f._scan.id}`)}
                    >
                      {repoName(f._scan.repo_url)} →
                    </span>
                  </div>
                  <div style={{ fontSize: 12, color: '#8b949e' }}>
                    File: <span style={{ color: '#e6edf3' }}>{f.File || f.file || 'unknown'}</span>
                    {f.StartLine && <span> · Line {f.StartLine}</span>}
                  </div>
                  {f.Secret && <div style={{ fontSize: 11, color: '#8b949e', marginTop: 4, fontFamily: 'monospace' }}>Match: {f.Secret.slice(0, 50)}...</div>}
                  {f.Description && <div style={{ fontSize: 12, color: '#d29922', marginTop: 4 }}>{f.Description}</div>}
                </div>
              ))}
            </div>
          )}

          {/* ── SAST (SonarQube) ── */}
          {tab === 'sonar' && (
            <div style={{ animation: 'fadeIn 0.2s ease' }}>
              <div style={{ fontSize: 13, color: '#8b949e', marginBottom: 16 }}>
                {sonarIssues.length === 0 ? '✓ No SAST issues found.' : `${sonarIssues.length} issue${sonarIssues.length !== 1 ? 's' : ''} found`}
              </div>
              {sonarIssues.length === 0 && <div style={S.empty}><span style={{ fontSize: 40 }}>✅</span></div>}
              {sonarIssues.map((issue, i) => (
                <div key={i} style={S.finding}>
                  <div style={S.findingHdr}>
                    <SevBadge sev={issue.severity} />
                    <span style={{ color: '#484f58', fontSize: 11 }}>{issue.type}</span>
                    <span style={S.scanLink} onClick={() => nav(`/scans/${issue._scan.id}`)}>
                      {repoName(issue._scan.repo_url)} →
                    </span>
                  </div>
                  <div style={{ fontSize: 13, color: '#e6edf3', marginBottom: 4 }}>{issue.message}</div>
                  {issue.component && (
                    <div style={{ fontSize: 11, color: '#8b949e' }}>
                      {issue.component.split(':').pop()}{issue.line ? `:${issue.line}` : ''}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* ── Dependencies (Trivy FS) ── */}
          {tab === 'trivy' && (
            <div style={{ animation: 'fadeIn 0.2s ease' }}>
              <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
                {critCves > 0 && (
                  <div style={S.statCard}>
                    <div style={{ ...S.statNum, fontSize: 26, color: '#f85149' }}>{critCves}</div>
                    <div style={S.statLabel}>CRITICAL CVEs</div>
                  </div>
                )}
                {highCves > 0 && (
                  <div style={S.statCard}>
                    <div style={{ ...S.statNum, fontSize: 26, color: '#d29922' }}>{highCves}</div>
                    <div style={S.statLabel}>HIGH CVEs</div>
                  </div>
                )}
                <div style={S.statCard}>
                  <div style={{ ...S.statNum, fontSize: 26, color: cves.length > 0 ? '#e6edf3' : '#3fb950' }}>{cves.length}</div>
                  <div style={S.statLabel}>TOTAL CVEs</div>
                </div>
              </div>
              {cves.length === 0 && <div style={{ ...S.empty, fontSize: 13 }}>✓ No vulnerable dependencies found.</div>}
              {cves.map((v, i) => (
                <div key={i} style={S.finding}>
                  <div style={S.findingHdr}>
                    <SevBadge sev={v.Severity} />
                    <span style={{ color: SEV_COLOR[v.Severity] || '#e6edf3', fontWeight: 700, fontFamily: 'monospace', fontSize: 12 }}>{v.VulnerabilityID}</span>
                    <span style={{ color: '#8b949e', fontSize: 12 }}>{v.PkgName} {v.InstalledVersion}</span>
                    <span style={S.scanLink} onClick={() => nav(`/scans/${v._scan.id}`)}>
                      {repoName(v._scan.repo_url)} →
                    </span>
                  </div>
                  {v.Title && <div style={{ fontSize: 12, color: '#8b949e', marginBottom: 4 }}>{v.Title}</div>}
                  <div style={{ fontSize: 11, color: '#484f58' }}>{v._target}</div>
                  {v.FixedVersion && <div style={{ fontSize: 11, color: '#3fb950', marginTop: 4 }}>Fix available: {v.FixedVersion}</div>}
                </div>
              ))}
            </div>
          )}

          {/* ── IaC (Checkov) ── */}
          {tab === 'checkov' && (
            <div style={{ animation: 'fadeIn 0.2s ease' }}>
              <div style={{ fontSize: 13, color: '#8b949e', marginBottom: 16 }}>
                {iacFails.length === 0 ? '✓ No IaC misconfigurations found.' : `${iacFails.length} failure${iacFails.length !== 1 ? 's' : ''} found`}
              </div>
              {iacFails.length === 0 && <div style={S.empty}><span style={{ fontSize: 40 }}>✅</span></div>}
              {iacFails.map((f, i) => (
                <div key={i} style={S.finding}>
                  <div style={S.findingHdr}>
                    <SevBadge sev={f.severity || 'INFO'} />
                    <span style={{ color: '#58a6ff', fontSize: 11, fontFamily: 'monospace' }}>{f.check_id}</span>
                    <span style={S.scanLink} onClick={() => nav(`/scans/${f._scan.id}`)}>
                      {repoName(f._scan.repo_url)} →
                    </span>
                  </div>
                  <div style={{ fontSize: 13, color: '#e6edf3', marginBottom: 4 }}>{f.check?.name || f.check_id}</div>
                  <div style={{ fontSize: 11, color: '#8b949e' }}>
                    {f.repo_file_path || f.file_path}
                    {f.file_line_range && ` (lines ${f.file_line_range[0]}-${f.file_line_range[1]})`}
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
