import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';

function repoName(url) {
  try { return url.replace(/\.git$/, '').split('/').slice(-2).join('/'); } catch { return url; }
}

function timeAgo(dateStr) {
  const diff = (Date.now() - new Date(dateStr)) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const STATUS_CONFIG = {
  running: { color: '#388bfd', bg: 'rgba(56,139,253,0.12)', border: 'rgba(56,139,253,0.35)', label: 'Running', dot: true },
  done:    { color: '#3fb950', bg: 'rgba(63,185,80,0.12)',   border: 'rgba(63,185,80,0.35)',   label: 'Done',    dot: false },
  failed:  { color: '#f85149', bg: 'rgba(248,81,73,0.12)',   border: 'rgba(248,81,73,0.35)',   label: 'Failed',  dot: false },
  pending: { color: '#8b949e', bg: 'rgba(139,148,158,0.1)',  border: '#30363d',                label: 'Pending', dot: true },
};

function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.pending;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '3px 10px', borderRadius: 12,
      fontSize: 11, fontWeight: 600,
      color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}`,
    }}>
      {cfg.dot && (
        <span style={{
          width: 6, height: 6, borderRadius: '50%',
          background: cfg.color,
          animation: status === 'running' ? 'runDot 1.4s ease-in-out infinite' : 'pulse 2s ease-in-out infinite',
          flexShrink: 0,
        }} />
      )}
      {cfg.label}
    </span>
  );
}

function StatCard({ value, label, color, icon }) {
  return (
    <div style={{
      background: '#161b22', border: '1px solid #30363d', borderRadius: 10,
      padding: '18px 22px', flex: '1 1 120px', minWidth: 110,
      animation: 'slideUp 0.3s ease',
    }}>
      <div style={{ fontSize: 11, color: '#8b949e', fontWeight: 600, letterSpacing: '0.06em', marginBottom: 8 }}>
        {icon} {label}
      </div>
      <div style={{ fontSize: 28, fontWeight: 700, color: color || '#e6edf3', lineHeight: 1 }}>
        {value}
      </div>
    </div>
  );
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
  const runningScans = scans.filter(s => s.status === 'running' || s.status === 'pending');
  const doneScans = scans.filter(s => s.status !== 'running' && s.status !== 'pending');

  if (loading) {
    return (
      <div style={{ padding: 32 }}>
        <div style={{ height: 28, width: 160, background: '#161b22', borderRadius: 6, marginBottom: 24, animation: 'pulse 1.5s ease-in-out infinite' }} />
        <div style={{ display: 'flex', gap: 12, marginBottom: 28 }}>
          {[1, 2, 3, 4].map(i => <div key={i} style={{ height: 80, flex: 1, background: '#161b22', borderRadius: 10, animation: 'pulse 1.5s ease-in-out infinite' }} />)}
        </div>
        <div style={{ height: 200, background: '#161b22', borderRadius: 10, animation: 'pulse 1.5s ease-in-out infinite' }} />
      </div>
    );
  }

  return (
    <div style={{ padding: 32, animation: 'fadeIn 0.25s ease' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e6edf3' }}>Security Scans</div>
          <div style={{ color: '#8b949e', fontSize: 13, marginTop: 3 }}>
            Jenkins-powered security pipeline · auto-refreshes every 10s
          </div>
        </div>
        <button
          style={{ padding: '9px 18px', background: '#238636', border: 'none', borderRadius: 6, color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}
          onClick={() => nav('/scans/new')}
        >
          + New Scan
        </button>
      </div>

      {/* Stat cards */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 28, flexWrap: 'wrap' }}>
        <StatCard value={scans.length} label="TOTAL SCANS" icon="📊" />
        <StatCard value={counts.running || 0} label="RUNNING" color="#388bfd" icon="⟳" />
        <StatCard value={counts.done || 0} label="COMPLETED" color="#3fb950" icon="✓" />
        <StatCard value={counts.failed || 0} label="FAILED" color={(counts.failed || 0) > 0 ? '#f85149' : '#8b949e'} icon="✗" />
        <StatCard value={counts.pending || 0} label="PENDING" color="#d29922" icon="⏳" />
      </div>

      {scans.length === 0 && (
        <div style={{ textAlign: 'center', padding: '80px 0', color: '#8b949e' }}>
          <div style={{ fontSize: 40, marginBottom: 16 }}>🔒</div>
          <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8, color: '#e6edf3' }}>No scans yet</div>
          <div style={{ fontSize: 13, marginBottom: 24 }}>Start by scanning a repository for security vulnerabilities.</div>
          <button
            style={{ padding: '10px 24px', background: '#238636', border: 'none', borderRadius: 6, color: '#fff', fontSize: 14, fontWeight: 600, cursor: 'pointer' }}
            onClick={() => nav('/scans/new')}
          >
            + New Scan
          </button>
        </div>
      )}

      {/* Active pipelines */}
      {runningScans.length > 0 && (
        <div style={{ marginBottom: 28 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#388bfd', letterSpacing: '0.07em', marginBottom: 12 }}>
            ⟳ ACTIVE PIPELINES
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {runningScans.map(scan => (
              <div
                key={scan.id}
                onClick={() => nav(`/scans/${scan.id}`)}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  background: '#161b22',
                  border: '1px solid rgba(56,139,253,0.35)',
                  borderRadius: 8, padding: '14px 18px', cursor: 'pointer',
                  animation: 'glow 3s ease-in-out infinite',
                  transition: 'border-color 0.2s',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                  <div>
                    <div style={{ color: '#58a6ff', fontWeight: 600, fontSize: 14 }}>{repoName(scan.repo_url)}</div>
                    <div style={{ color: '#8b949e', fontSize: 12, marginTop: 2 }}>
                      <span style={{ background: '#21262d', border: '1px solid #30363d', borderRadius: 3, padding: '1px 6px', marginRight: 8 }}>{scan.branch}</span>
                      {scan.job_name}
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <StatusBadge status={scan.status} />
                  <span style={{ color: '#8b949e', fontSize: 12 }}>{timeAgo(scan.created_at)}</span>
                  <span style={{ color: '#8b949e', fontSize: 12 }}>→</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All scans table */}
      {doneScans.length > 0 && (
        <div>
          {runningScans.length > 0 && (
            <div style={{ fontSize: 12, fontWeight: 700, color: '#8b949e', letterSpacing: '0.07em', marginBottom: 12 }}>
              RECENT SCANS
            </div>
          )}
          <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 10, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: '#0d1117' }}>
                  <th style={{ textAlign: 'left', padding: '10px 16px', fontSize: 11, color: '#8b949e', fontWeight: 700, letterSpacing: '0.06em', borderBottom: '1px solid #30363d' }}>REPOSITORY</th>
                  <th style={{ textAlign: 'left', padding: '10px 16px', fontSize: 11, color: '#8b949e', fontWeight: 700, letterSpacing: '0.06em', borderBottom: '1px solid #30363d' }}>BRANCH</th>
                  <th style={{ textAlign: 'left', padding: '10px 16px', fontSize: 11, color: '#8b949e', fontWeight: 700, letterSpacing: '0.06em', borderBottom: '1px solid #30363d' }}>STATUS</th>
                  <th style={{ textAlign: 'left', padding: '10px 16px', fontSize: 11, color: '#8b949e', fontWeight: 700, letterSpacing: '0.06em', borderBottom: '1px solid #30363d' }}>JENKINS JOB</th>
                  <th style={{ textAlign: 'left', padding: '10px 16px', fontSize: 11, color: '#8b949e', fontWeight: 700, letterSpacing: '0.06em', borderBottom: '1px solid #30363d' }}>STARTED</th>
                  <th style={{ padding: '10px 16px', borderBottom: '1px solid #30363d' }}></th>
                </tr>
              </thead>
              <tbody>
                {doneScans.map((scan, idx) => (
                  <tr
                    key={scan.id}
                    onClick={() => nav(`/scans/${scan.id}`)}
                    style={{
                      background: hover === scan.id ? 'rgba(88,166,255,0.04)' : 'transparent',
                      cursor: 'pointer',
                      transition: 'background 0.15s',
                      borderBottom: idx < doneScans.length - 1 ? '1px solid #21262d' : 'none',
                    }}
                    onMouseEnter={() => setHover(scan.id)}
                    onMouseLeave={() => setHover(null)}
                  >
                    <td style={{ padding: '13px 16px', fontSize: 13 }}>
                      <span style={{ color: '#58a6ff', fontWeight: 500 }}>{repoName(scan.repo_url)}</span>
                    </td>
                    <td style={{ padding: '13px 16px' }}>
                      <span style={{ background: '#21262d', border: '1px solid #30363d', borderRadius: 3, padding: '2px 7px', fontSize: 11, color: '#8b949e' }}>{scan.branch}</span>
                    </td>
                    <td style={{ padding: '13px 16px' }}>
                      <StatusBadge status={scan.status} />
                    </td>
                    <td style={{ padding: '13px 16px', fontSize: 12, color: '#8b949e' }}>{scan.job_name}</td>
                    <td style={{ padding: '13px 16px', fontSize: 12, color: '#8b949e' }}>{timeAgo(scan.created_at)}</td>
                    <td style={{ padding: '13px 16px', textAlign: 'right' }} onClick={e => e.stopPropagation()}>
                      <button
                        disabled={rerunning === scan.id || scan.status === 'running'}
                        onClick={e => rerun(e, scan.id)}
                        style={{
                          padding: '4px 12px', background: '#21262d', border: '1px solid #30363d',
                          borderRadius: 6, color: rerunning === scan.id ? '#8b949e' : '#e6edf3',
                          fontSize: 12, cursor: 'pointer',
                        }}
                      >
                        {rerunning === scan.id ? '...' : '↺ Rerun'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
