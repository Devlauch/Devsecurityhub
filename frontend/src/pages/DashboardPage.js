import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';

const SEVERITY_COLORS = { CRITICAL: '#f85149', HIGH: '#d29922', MEDIUM: '#388bfd', LOW: '#3fb950' };

const S = {
  page: { padding: 32 },
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 },
  h1: { fontSize: 22, fontWeight: 700, color: '#e6edf3' },
  newBtn: { padding: '9px 18px', background: '#238636', border: 'none', borderRadius: 6, color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer' },
  empty: { textAlign: 'center', padding: '60px 0', color: '#8b949e', fontSize: 14 },
  table: { width: '100%', borderCollapse: 'collapse' },
  th: { textAlign: 'left', padding: '10px 14px', fontSize: 12, color: '#8b949e', borderBottom: '1px solid #30363d', fontWeight: 600 },
  td: { padding: '12px 14px', fontSize: 13, color: '#e6edf3', borderBottom: '1px solid #21262d', cursor: 'pointer' },
  trHover: { background: 'rgba(88,166,255,0.04)' },
  status: { display: 'inline-block', padding: '2px 10px', borderRadius: 12, fontSize: 11, fontWeight: 600 },
  running: { background: 'rgba(56,139,253,0.2)', color: '#388bfd' },
  done: { background: 'rgba(63,185,80,0.2)', color: '#3fb950' },
  failed: { background: 'rgba(248,81,73,0.2)', color: '#f85149' },
  pending: { background: 'rgba(139,148,158,0.2)', color: '#8b949e' },
  repoText: { color: '#58a6ff', fontWeight: 500 },
  branchPill: { background: '#21262d', border: '1px solid #30363d', borderRadius: 4, padding: '1px 7px', fontSize: 11, color: '#8b949e', marginLeft: 8 },
};

function statusStyle(s) {
  if (s === 'running') return S.running;
  if (s === 'done') return S.done;
  if (s === 'failed') return S.failed;
  return S.pending;
}

function repoName(url) {
  try { return url.replace(/\.git$/, '').split('/').slice(-2).join('/'); } catch { return url; }
}

export default function DashboardPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [hover, setHover] = useState(null);
  const [rerunning, setRerunning] = useState(null);
  const nav = useNavigate();

  useEffect(() => {
    api.get('/scans').then(r => setScans(r.data)).catch(() => {}).finally(() => setLoading(false));
    const interval = setInterval(() => {
      api.get('/scans').then(r => setScans(r.data)).catch(() => {});
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const rerun = async (e, scanId) => {
    e.stopPropagation();
    setRerunning(scanId);
    try {
      await api.post(`/scans/${scanId}/rerun`);
      setScans(prev => prev.map(s => s.id === scanId ? { ...s, status: 'running', last_build: null } : s));
      nav(`/scans/${scanId}`);
    } catch (err) {
      alert(err.response?.data?.error || 'Rerun failed');
    } finally {
      setRerunning(null);
    }
  };

  const counts = scans.reduce((acc, s) => { acc[s.status] = (acc[s.status] || 0) + 1; return acc; }, {});

  return (
    <div style={S.page}>
      <div style={S.header}>
        <div>
          <div style={S.h1}>Security Scans</div>
          <div style={{ color: '#8b949e', fontSize: 13, marginTop: 4 }}>
            {scans.length} scans &nbsp;·&nbsp;
            {counts.done || 0} completed &nbsp;·&nbsp;
            {counts.running || 0} running &nbsp;·&nbsp;
            {counts.failed || 0} failed
          </div>
        </div>
        <button style={S.newBtn} onClick={() => nav('/scans/new')}>+ New Scan</button>
      </div>

      {loading && <div style={S.empty}>Loading...</div>}
      {!loading && scans.length === 0 && (
        <div style={S.empty}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>🔒</div>
          <div style={{ marginBottom: 8 }}>No scans yet.</div>
          <div>Click <strong>+ New Scan</strong> to scan a repository.</div>
        </div>
      )}

      {scans.length > 0 && (
        <table style={S.table}>
          <thead>
            <tr>
              <th style={S.th}>Repository</th>
              <th style={S.th}>Branch</th>
              <th style={S.th}>Status</th>
              <th style={S.th}>Jenkins Job</th>
              <th style={S.th}>Started</th>
              <th style={S.th}></th>
            </tr>
          </thead>
          <tbody>
            {scans.map(scan => (
              <tr
                key={scan.id}
                onClick={() => nav(`/scans/${scan.id}`)}
                style={{ ...(hover === scan.id ? S.trHover : {}) }}
                onMouseEnter={() => setHover(scan.id)}
                onMouseLeave={() => setHover(null)}
              >
                <td style={S.td}><span style={S.repoText}>{repoName(scan.repo_url)}</span></td>
                <td style={S.td}><span style={S.branchPill}>{scan.branch}</span></td>
                <td style={S.td}>
                  <span style={{ ...S.status, ...statusStyle(scan.status) }}>
                    {scan.status === 'running' ? '⟳ Running' : scan.status === 'done' ? '✓ Done' : scan.status === 'failed' ? '✗ Failed' : '⏳ Pending'}
                  </span>
                </td>
                <td style={{ ...S.td, color: '#8b949e', fontSize: 12 }}>{scan.job_name}</td>
                <td style={{ ...S.td, color: '#8b949e' }}>{new Date(scan.created_at).toLocaleString()}</td>
                <td style={{ ...S.td, textAlign: 'right' }} onClick={e => e.stopPropagation()}>
                  <button
                    disabled={rerunning === scan.id || scan.status === 'running'}
                    onClick={e => rerun(e, scan.id)}
                    style={{ padding: '4px 12px', background: '#21262d', border: '1px solid #30363d', borderRadius: 6, color: rerunning === scan.id ? '#8b949e' : '#e6edf3', fontSize: 12, cursor: 'pointer' }}
                  >
                    {rerunning === scan.id ? '...' : '↺ Rerun'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
