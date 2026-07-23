import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../api/client';

const TABS = [
  { id: 'correlated', label: '🔗 Correlated' },
  { id: 'gitleaks', label: '🔑 Secrets' },
  { id: 'semgrep', label: '🔍 SAST' },
  { id: 'owasp', label: '📦 Dependencies' },
  { id: 'trivy', label: '🐳 Container' },
  { id: 'checkov', label: '🏗️ IaC' },
  { id: 'ai', label: '✨ AI Summary' },
];

const PIPELINE_STAGES = [
  { id: 'checkout',    label: 'Checkout',    icon: '📥', endSec: 15 },
  { id: 'setup',       label: 'Setup Tools', icon: '🔧', endSec: 70 },
  { id: 'gitleaks',    label: 'Gitleaks',    icon: '🔑', endSec: 120 },
  { id: 'trufflehog',  label: 'TruffleHog',  icon: '🔒', endSec: 170 },
  { id: 'sonarqube',   label: 'SonarQube',   icon: '🔍', endSec: 270 },
  { id: 'semgrep',     label: 'Semgrep',     icon: '🧪', endSec: 360 },
  { id: 'trivy-fs',    label: 'Trivy FS',    icon: '📦', endSec: 420 },
  { id: 'owasp-dc',    label: 'OWASP DC',    icon: '🛡️', endSec: 560 },
  { id: 'checkov',     label: 'Checkov',     icon: '🏗️', endSec: 630 },
  { id: 'container',   label: 'Container',   icon: '🐳', endSec: 760, dockerOnly: true },
];

const S = {
  page: { padding: 32 },
  header: { marginBottom: 24 },
  back: { color: '#8b949e', fontSize: 13, cursor: 'pointer', marginBottom: 14, background: 'none', border: 'none', padding: 0, display: 'flex', alignItems: 'center', gap: 4 },
  h1: { fontSize: 20, fontWeight: 700, color: '#e6edf3', marginBottom: 6 },
  meta: { display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' },
  branch: { background: '#21262d', border: '1px solid #30363d', borderRadius: 4, padding: '2px 10px', fontSize: 12, color: '#8b949e' },
  status: { display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 12px', borderRadius: 12, fontSize: 12, fontWeight: 600 },
  running: { background: 'rgba(56,139,253,0.15)', color: '#388bfd', border: '1px solid rgba(56,139,253,0.3)' },
  done: { background: 'rgba(63,185,80,0.15)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)' },
  failed: { background: 'rgba(248,81,73,0.15)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' },
  pending: { background: 'rgba(139,148,158,0.15)', color: '#8b949e', border: '1px solid #30363d' },
  tabs: { display: 'flex', borderBottom: '1px solid #30363d', marginBottom: 24, gap: 0, overflowX: 'auto' },
  tab: { padding: '10px 18px', cursor: 'pointer', fontSize: 13, color: '#8b949e', background: 'none', border: 'none', borderBottom: '2px solid transparent', whiteSpace: 'nowrap' },
  tabActive: { color: '#58a6ff', borderBottomColor: '#58a6ff' },
  pre: { background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: 20, fontSize: 12, color: '#e6edf3', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 600, overflow: 'auto', fontFamily: 'monospace', lineHeight: 1.6 },
  empty: { color: '#8b949e', fontSize: 13, padding: 20 },
  loading: { color: '#8b949e', fontSize: 13, padding: 20 },
  aiBox: { background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: 20, fontSize: 14, color: '#e6edf3', lineHeight: 1.8, whiteSpace: 'pre-wrap' },
  scannerStat: { display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' },
  statCard: { background: '#161b22', border: '1px solid #30363d', borderRadius: 6, padding: '12px 18px', minWidth: 110 },
  statNum: { fontSize: 24, fontWeight: 700, color: '#f85149' },
  statLabel: { fontSize: 11, color: '#8b949e', marginTop: 2 },
};

function statusStyle(s) {
  if (s === 'running') return S.running;
  if (s === 'done') return S.done;
  if (s === 'failed') return S.failed;
  return S.pending;
}

function parseJson(content) {
  try { return JSON.parse(content); } catch { return null; }
}

// ── Pipeline Tracker ──────────────────────────────────────────────────────────
function PipelineTracker({ scan }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const startTime = new Date(scan.created_at).getTime();
    const tick = () => setElapsed(Math.floor((Date.now() - startTime) / 1000));
    tick();
    if (scan.status === 'running' || scan.status === 'pending') {
      const iv = setInterval(tick, 1000);
      return () => clearInterval(iv);
    }
  }, [scan.status, scan.created_at]);

  const stages = PIPELINE_STAGES.filter(s => !s.dockerOnly || scan.has_dockerfile);

  function stageStatus(stage, idx) {
    if (scan.status === 'done') return 'done';
    if (scan.status === 'pending') return idx === 0 ? 'running' : 'pending';
    if (scan.status === 'failed') {
      if (elapsed > stage.endSec) return 'done';
      const prevEnd = stages[idx - 1]?.endSec ?? 0;
      if (elapsed >= prevEnd) return 'failed';
      return 'pending';
    }
    // running
    if (elapsed >= stage.endSec) return 'done';
    const prevEnd = stages[idx - 1]?.endSec ?? 0;
    if (elapsed >= prevEnd) return 'running';
    return 'pending';
  }

  const mins = Math.floor(elapsed / 60);
  const secs = elapsed % 60;
  const isActive = scan.status === 'running' || scan.status === 'pending';

  return (
    <div style={{
      background: '#161b22',
      border: '1px solid #30363d',
      borderRadius: 10,
      padding: '18px 20px',
      marginBottom: 24,
      animation: 'fadeIn 0.3s ease',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', color: '#8b949e' }}>
          PIPELINE STAGES
        </div>
        <div style={{ display: 'flex', gap: 16, alignItems: 'center', fontSize: 12, color: '#8b949e' }}>
          {scan.last_build && (
            <span style={{ background: '#21262d', border: '1px solid #30363d', borderRadius: 4, padding: '2px 8px', fontSize: 11 }}>
              Build #{scan.last_build}
            </span>
          )}
          {isActive && (
            <span style={{ fontVariantNumeric: 'tabular-nums' }}>
              {mins}m {String(secs).padStart(2, '0')}s
            </span>
          )}
        </div>
      </div>

      {/* Stage pills */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 0, overflowX: 'auto', paddingBottom: 2 }}>
        {stages.map((stage, i) => {
          const st = stageStatus(stage, i);
          const borderColor = st === 'running' ? 'rgba(56,139,253,0.7)'
            : st === 'done' ? 'rgba(63,185,80,0.5)'
            : st === 'failed' ? 'rgba(248,81,73,0.5)'
            : '#21262d';
          const bg = st === 'running' ? 'rgba(56,139,253,0.1)'
            : st === 'done' ? 'rgba(63,185,80,0.08)'
            : st === 'failed' ? 'rgba(248,81,73,0.08)'
            : 'transparent';
          const labelColor = st === 'running' ? '#58a6ff'
            : st === 'done' ? '#3fb950'
            : st === 'failed' ? '#f85149'
            : '#484f58';

          return (
            <React.Fragment key={stage.id}>
              <div style={{
                display: 'flex', flexDirection: 'column', alignItems: 'center',
                minWidth: 74, padding: '8px 6px', borderRadius: 8,
                border: `1px solid ${borderColor}`,
                background: bg,
                animation: st === 'running' ? 'stagePulse 2s ease-in-out infinite' : 'none',
                transition: 'all 0.4s ease',
                flexShrink: 0,
              }}>
                <div style={{ fontSize: 17, marginBottom: 5, lineHeight: 1 }}>
                  {st === 'done'
                    ? <span style={{ color: '#3fb950' }}>✓</span>
                    : st === 'failed'
                    ? <span style={{ color: '#f85149' }}>✗</span>
                    : st === 'running'
                    ? <span style={{ display: 'inline-block', animation: 'spin 1.2s linear infinite', color: '#388bfd' }}>⟳</span>
                    : <span style={{ opacity: 0.35 }}>{stage.icon}</span>
                  }
                </div>
                <div style={{ fontSize: 10, color: labelColor, fontWeight: st === 'running' ? 700 : 400, textAlign: 'center', whiteSpace: 'nowrap' }}>
                  {stage.label}
                </div>
              </div>
              {i < stages.length - 1 && (
                <div style={{
                  width: 24, height: 1, flexShrink: 0,
                  background: st === 'done' ? 'rgba(63,185,80,0.5)' : '#21262d',
                  transition: 'background 0.4s ease',
                  margin: '0 1px',
                }} />
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Progress bar */}
      {isActive && (
        <div style={{ marginTop: 14, height: 3, background: '#21262d', borderRadius: 2, overflow: 'hidden' }}>
          <div style={{
            height: '100%',
            background: 'linear-gradient(90deg, #1f6feb, #388bfd, #58a6ff)',
            animation: 'progressSlide 300s linear forwards',
            borderRadius: 2,
          }} />
        </div>
      )}
    </div>
  );
}

// ── Report Components ─────────────────────────────────────────────────────────
const ALL_SOURCE_BADGES = {
  gitleaks:   { label: 'Gitleaks',   bg: 'rgba(248,81,73,0.12)',  border: 'rgba(248,81,73,0.35)',  color: '#f85149' },
  trufflehog: { label: 'TruffleHog', bg: 'rgba(210,153,34,0.12)', border: 'rgba(210,153,34,0.35)', color: '#d29922' },
  sonarqube:  { label: 'SonarQube',  bg: 'rgba(56,139,253,0.12)', border: 'rgba(56,139,253,0.35)', color: '#388bfd' },
  semgrep:    { label: 'Semgrep',    bg: 'rgba(63,185,80,0.12)',  border: 'rgba(63,185,80,0.35)',  color: '#3fb950' },
  trivy:      { label: 'Trivy',      bg: 'rgba(210,153,34,0.12)', border: 'rgba(210,153,34,0.35)', color: '#d29922' },
  grype:      { label: 'Grype',      bg: 'rgba(88,166,255,0.12)', border: 'rgba(88,166,255,0.35)', color: '#58a6ff' },
};
const SEV_COLOR_ALL = { CRITICAL: '#f85149', HIGH: '#d29922', MEDIUM: '#388bfd', LOW: '#8b949e', INFO: '#484f58', UNKNOWN: '#484f58' };

function SourceBadge({ src }) {
  const b = ALL_SOURCE_BADGES[src] || { label: src, bg: '#21262d', border: '#30363d', color: '#8b949e' };
  return <span style={{ background: b.bg, border: `1px solid ${b.border}`, borderRadius: 3, padding: '1px 7px', fontSize: 10, color: b.color, fontWeight: 600 }}>{b.label}</span>;
}

function ConfirmedBadge() {
  return <span style={{ background: 'rgba(63,185,80,0.12)', border: '1px solid rgba(63,185,80,0.3)', borderRadius: 3, padding: '1px 7px', fontSize: 10, color: '#3fb950', fontWeight: 700 }}>✓ CONFIRMED</span>;
}

function MergedBanner({ left, right, leftCount, rightCount, bothCount, extra }) {
  return (
    <div style={{ marginBottom: 14, padding: '8px 14px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
      <span style={{ fontSize: 12, color: '#8b949e' }}>Scanners:</span>
      <span style={{ fontSize: 12, color: ALL_SOURCE_BADGES[left]?.color || '#8b949e', fontWeight: 600 }}>{(ALL_SOURCE_BADGES[left]?.label || left)} — {leftCount} findings</span>
      <span style={{ fontSize: 12, color: ALL_SOURCE_BADGES[right]?.color || '#8b949e', fontWeight: 600 }}>{(ALL_SOURCE_BADGES[right]?.label || right)} — {rightCount} findings</span>
      {bothCount > 0 && <span style={{ fontSize: 12, color: '#3fb950', fontWeight: 600 }}>✦ {bothCount} confirmed by both</span>}
      {extra && <span style={{ fontSize: 11, color: '#58a6ff', marginLeft: 'auto' }}>{extra}</span>}
    </div>
  );
}

function SecretsReport({ scanId, done }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!done) return;
    setLoading(true);
    api.get(`/scans/${scanId}/reports/secrets`)
      .then(r => setData(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [scanId, done]);

  if (!done) return <div style={S.empty}>Secrets report available once scan completes.</div>;
  if (loading) return <div style={S.loading}>Merging Gitleaks + TruffleHog results...</div>;
  if (!data) return <div style={S.empty}>No secrets scan data yet.</div>;
  if (data.totalFindings === 0) return <div style={{ ...S.empty, color: '#3fb950' }}>✓ No secrets found across both scanners.</div>;

  return (
    <div>
      <MergedBanner left="gitleaks" right="trufflehog" leftCount={data.gitleaksCount} rightCount={data.trufflehogCount} bothCount={data.bothCount} extra={data.verifiedCount > 0 ? `⚠ ${data.verifiedCount} verified active` : null} />
      <div style={S.scannerStat}>
        <div style={S.statCard}><div style={{ ...S.statNum, color: '#f85149' }}>{data.totalFindings}</div><div style={S.statLabel}>Unique Secrets</div></div>
        {data.bothCount > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#3fb950' }}>{data.bothCount}</div><div style={S.statLabel}>Confirmed</div></div>}
        {data.verifiedCount > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#f85149' }}>{data.verifiedCount}</div><div style={S.statLabel}>Verified Active</div></div>}
      </div>
      {data.items.map((item, i) => (
        <div key={i} style={{ background: '#0d1117', border: `1px solid ${item.sources.length > 1 ? 'rgba(63,185,80,0.3)' : item.verified ? 'rgba(248,81,73,0.4)' : '#21262d'}`, borderRadius: 6, padding: 14, marginBottom: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ color: '#f85149', fontWeight: 700, fontSize: 13 }}>{item.detectorType}</span>
            {item.verified && <span style={{ background: 'rgba(248,81,73,0.15)', border: '1px solid rgba(248,81,73,0.4)', borderRadius: 3, padding: '1px 7px', fontSize: 10, color: '#f85149', fontWeight: 700 }}>⚠ VERIFIED ACTIVE</span>}
            {item.sources.map(src => <SourceBadge key={src} src={src} />)}
            {item.sources.length > 1 && <ConfirmedBadge />}
          </div>
          {item.file && <div style={{ color: '#8b949e', fontSize: 11, marginTop: 5 }}>File: {item.file}{item.line ? ` · Line ${item.line}` : ''}</div>}
          {item.match && <div style={{ color: '#484f58', fontSize: 11, marginTop: 3, fontFamily: 'monospace' }}>Match: {item.match}</div>}
        </div>
      ))}
    </div>
  );
}

function SastReport({ scanId, done, sonarContent }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!done) return;
    setLoading(true);
    api.get(`/scans/${scanId}/reports/sast`)
      .then(r => setData(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [scanId, done]);

  // Show SonarQube summary metrics separately (from existing enriched report)
  const sonarData = parseJson(sonarContent);
  const sonarMetrics = sonarData?.status === 'OK' ? (() => {
    const measures = {};
    (sonarData.measures?.component?.measures || []).forEach(m => { measures[m.metric] = m.value; });
    return measures;
  })() : null;

  const ratingLabel = v => ({ '1': 'A', '2': 'B', '3': 'C', '4': 'D', '5': 'E' }[String(Math.round(v))] || v);
  const ratingColor = v => ({ '1': '#3fb950', '2': '#3fb950', '3': '#d29922', '4': '#f85149', '5': '#f85149' }[String(Math.round(v))] || '#8b949e');

  return (
    <div>
      {sonarData?.status === 'NOT_CONFIGURED' && (
        <div style={{ marginBottom: 12, padding: '8px 14px', background: 'rgba(210,153,34,0.08)', border: '1px solid rgba(210,153,34,0.3)', borderRadius: 6, fontSize: 12, color: '#d29922' }}>
          ⚠ SonarQube not configured — showing Semgrep results only. Go to Settings → SonarQube to enable.
        </div>
      )}
      {sonarMetrics && (
        <div style={{ marginBottom: 14, padding: '8px 14px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: 12, color: '#8b949e' }}>SonarQube:</span>
          {['bugs','vulnerabilities','code_smells'].map(k => (
            <span key={k} style={{ fontSize: 12, color: parseInt(sonarMetrics[k] || '0') > 0 ? '#f85149' : '#3fb950', fontWeight: 600 }}>{parseInt(sonarMetrics[k] || '0')} {k.replace('_', ' ')}</span>
          ))}
          {sonarMetrics.security_rating && <span style={{ fontSize: 12, color: ratingColor(sonarMetrics.security_rating), fontWeight: 700 }}>Security: {ratingLabel(sonarMetrics.security_rating)}</span>}
          {sonarMetrics.reliability_rating && <span style={{ fontSize: 12, color: ratingColor(sonarMetrics.reliability_rating), fontWeight: 700 }}>Reliability: {ratingLabel(sonarMetrics.reliability_rating)}</span>}
        </div>
      )}
      {!done ? (
        <div style={S.empty}>SAST report available once scan completes.</div>
      ) : loading ? (
        <div style={S.loading}>Merging SonarQube + Semgrep results...</div>
      ) : !data ? (
        <div style={S.empty}>No SAST data available yet.</div>
      ) : data.totalFindings === 0 ? (
        <div style={{ ...S.empty, color: '#3fb950' }}>✓ No SAST issues found across both scanners.</div>
      ) : (
        <>
          <MergedBanner left="sonarqube" right="semgrep" leftCount={data.sonarCount} rightCount={data.semgrepCount} bothCount={data.bothCount} />
          <div style={S.scannerStat}>
            {data.critical > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#f85149' }}>{data.critical}</div><div style={S.statLabel}>CRITICAL</div></div>}
            {data.high > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#d29922' }}>{data.high}</div><div style={S.statLabel}>HIGH</div></div>}
            <div style={S.statCard}><div style={S.statNum}>{data.totalFindings}</div><div style={S.statLabel}>Total Issues</div></div>
            {data.bothCount > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#3fb950' }}>{data.bothCount}</div><div style={S.statLabel}>Confirmed</div></div>}
          </div>
          {data.items.map((item, i) => (
            <div key={i} style={{ background: '#0d1117', border: `1px solid ${item.sources.length > 1 ? 'rgba(63,185,80,0.3)' : '#21262d'}`, borderRadius: 6, padding: 14, marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span style={{ background: 'rgba(139,148,158,0.1)', border: '1px solid #30363d', borderRadius: 3, padding: '1px 7px', fontSize: 10, color: SEV_COLOR_ALL[item.severity] || '#8b949e', fontWeight: 700 }}>{item.severity}</span>
                {item.sources.map(src => <SourceBadge key={src} src={src} />)}
                {item.sources.length > 1 && <ConfirmedBadge />}
                {item.ruleId && <span style={{ fontSize: 10, color: '#484f58', fontFamily: 'monospace' }}>{item.ruleId}</span>}
              </div>
              <div style={{ color: '#e6edf3', fontSize: 13, marginTop: 6, lineHeight: 1.5 }}>{item.message}</div>
              {item.file && <div style={{ color: '#8b949e', fontSize: 11, marginTop: 4 }}>{item.file}{item.line ? `:${item.line}` : ''}</div>}
            </div>
          ))}
        </>
      )}
    </div>
  );
}

const SOURCE_BADGE = {
  trivy:     { label: 'Trivy',    bg: 'rgba(210,153,34,0.15)',  border: 'rgba(210,153,34,0.4)',  color: '#d29922' },
  'owasp-dc': { label: 'OWASP DC', bg: 'rgba(248,81,73,0.12)',   border: 'rgba(248,81,73,0.35)',  color: '#f85149' },
};
const SEV_DEP_COLOR = { CRITICAL: '#f85149', HIGH: '#d29922', MEDIUM: '#388bfd', LOW: '#8b949e', UNKNOWN: '#484f58' };

function DependenciesReport({ scanId, done }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!done) return;
    setLoading(true);
    api.get(`/scans/${scanId}/reports/dependencies`)
      .then(r => setData(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [scanId, done]);

  if (!done) return <div style={S.empty}>Dependency report available once scan completes.</div>;
  if (loading) return <div style={S.loading}>Merging Trivy + OWASP Dependency-Check results...</div>;
  if (!data) return <div style={S.empty}>No dependency scan data available yet.</div>;
  if (data.totalFindings === 0) return <div style={{ ...S.empty, color: '#3fb950' }}>✓ No vulnerable dependencies found across both scanners.</div>;

  const critical = data.items.filter(i => i.severity === 'CRITICAL').length;
  const high = data.items.filter(i => i.severity === 'HIGH').length;

  return (
    <div>
      {/* Tool coverage banner */}
      <div style={{ marginBottom: 14, padding: '8px 14px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        <span style={{ fontSize: 12, color: '#8b949e' }}>Scanners:</span>
        <span style={{ fontSize: 12, color: '#d29922', fontWeight: 600 }}>📦 Trivy FS — {data.trivyCount} CVEs</span>
        <span style={{ fontSize: 12, color: '#f85149', fontWeight: 600 }}>🔒 OWASP DC — {data.owaspDcCount} CVEs</span>
        {data.bothCount > 0 && <span style={{ fontSize: 12, color: '#3fb950', fontWeight: 600 }}>✦ {data.bothCount} confirmed by both</span>}
        <span style={{ fontSize: 11, color: '#58b945e8', marginLeft: 'auto' }}>✦ Enriched with OSV.dev</span>
      </div>

      {/* Stat cards */}
      <div style={S.scannerStat}>
        {critical > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#f85149' }}>{critical}</div><div style={S.statLabel}>CRITICAL</div></div>}
        {high > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#d29922' }}>{high}</div><div style={S.statLabel}>HIGH</div></div>}
        <div style={S.statCard}><div style={S.statNum}>{data.totalFindings}</div><div style={S.statLabel}>Unique CVEs</div></div>
        {data.bothCount > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#3fb950' }}>{data.bothCount}</div><div style={S.statLabel}>Confirmed</div></div>}
      </div>

      {/* CVE list */}
      {data.items.map((item, i) => (
        <div key={i} style={{ background: '#0d1117', border: `1px solid ${item.sources.length > 1 ? 'rgba(63,185,80,0.3)' : '#21262d'}`, borderRadius: 6, padding: 14, marginBottom: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ color: SEV_DEP_COLOR[item.severity] || '#8b949e', fontWeight: 700, fontSize: 13 }}>{item.cveId}</span>
            <span style={{ background: 'rgba(139,148,158,0.1)', border: '1px solid #30363d', borderRadius: 3, padding: '1px 7px', fontSize: 10, color: SEV_DEP_COLOR[item.severity] || '#8b949e', fontWeight: 600 }}>{item.severity}</span>
            {item.cvssScore && <span style={{ background: '#21262d', border: '1px solid #30363d', borderRadius: 3, padding: '1px 6px', fontSize: 10, color: '#d29922' }}>CVSS {item.cvssScore}</span>}
            {item.sources.map(src => {
              const b = SOURCE_BADGE[src] || { label: src, bg: '#21262d', border: '#30363d', color: '#8b949e' };
              return <span key={src} style={{ background: b.bg, border: `1px solid ${b.border}`, borderRadius: 3, padding: '1px 7px', fontSize: 10, color: b.color, fontWeight: 600 }}>{b.label}</span>;
            })}
            {item.sources.length > 1 && <span style={{ background: 'rgba(63,185,80,0.12)', border: '1px solid rgba(63,185,80,0.3)', borderRadius: 3, padding: '1px 7px', fontSize: 10, color: '#3fb950', fontWeight: 700 }}>✓ CONFIRMED</span>}
          </div>
          {item.pkg && <div style={{ color: '#8b949e', fontSize: 11, marginTop: 4 }}>{item.pkg} {item.installedVersion && `v${item.installedVersion}`} {item.target && `· ${item.target}`}</div>}
          {item.title && item.title !== item.cveId && <div style={{ color: '#c9d1d9', fontSize: 12, marginTop: 4, lineHeight: 1.5 }}>{item.title}</div>}
          <div style={{ display: 'flex', gap: 10, marginTop: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            {item.fixedVersion && <span style={{ color: '#3fb950', fontSize: 11 }}>✓ Fix: {item.fixedVersion}</span>}
            {item.references?.slice(0, 2).map((ref, ri) => (
              <a key={ri} href={ref} target="_blank" rel="noreferrer" style={{ color: '#58a6ff', fontSize: 11 }}>Advisory ↗</a>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function ContainerReport({ scanId, done, hasDockerfile }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!done || !hasDockerfile) return;
    setLoading(true);
    api.get(`/scans/${scanId}/reports/container`)
      .then(r => setData(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [scanId, done, hasDockerfile]);

  if (!hasDockerfile) return <div style={S.empty}>Container scan skipped — no Dockerfile detected.</div>;
  if (!done) return <div style={S.empty}>Container report available once scan completes.</div>;
  if (loading) return <div style={S.loading}>Merging Trivy image + Grype results...</div>;
  if (!data) return <div style={S.empty}>No container scan data. Docker may not be available in Jenkins.</div>;
  if (data.totalFindings === 0) return <div style={{ ...S.empty, color: '#3fb950' }}>✓ No container CVEs found across both scanners.</div>;

  return (
    <div>
      <MergedBanner left="trivy" right="grype" leftCount={data.trivyCount} rightCount={data.grypeCount} bothCount={data.bothCount} />
      <div style={S.scannerStat}>
        {data.critical > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#f85149' }}>{data.critical}</div><div style={S.statLabel}>CRITICAL</div></div>}
        {data.high > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#d29922' }}>{data.high}</div><div style={S.statLabel}>HIGH</div></div>}
        <div style={S.statCard}><div style={S.statNum}>{data.totalFindings}</div><div style={S.statLabel}>Unique CVEs</div></div>
        {data.bothCount > 0 && <div style={S.statCard}><div style={{ ...S.statNum, color: '#3fb950' }}>{data.bothCount}</div><div style={S.statLabel}>Confirmed</div></div>}
      </div>
      {data.items.map((item, i) => (
        <div key={i} style={{ background: '#0d1117', border: `1px solid ${item.sources.length > 1 ? 'rgba(63,185,80,0.3)' : '#21262d'}`, borderRadius: 6, padding: 14, marginBottom: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ color: SEV_COLOR_ALL[item.severity] || '#8b949e', fontWeight: 700, fontSize: 13 }}>{item.cveId}</span>
            <span style={{ background: 'rgba(139,148,158,0.1)', border: '1px solid #30363d', borderRadius: 3, padding: '1px 7px', fontSize: 10, color: SEV_COLOR_ALL[item.severity] || '#8b949e', fontWeight: 600 }}>{item.severity}</span>
            {item.sources.map(src => <SourceBadge key={src} src={src} />)}
            {item.sources.length > 1 && <ConfirmedBadge />}
          </div>
          {(item.pkg || item.target) && <div style={{ color: '#8b949e', fontSize: 11, marginTop: 4 }}>{item.pkg} {item.installedVersion && `v${item.installedVersion}`}{item.target && ` · ${item.target}`}</div>}
          {item.title && item.title !== item.cveId && <div style={{ color: '#c9d1d9', fontSize: 12, marginTop: 4, lineHeight: 1.5 }}>{item.title}</div>}
          {item.fixedVersion && <div style={{ color: '#3fb950', fontSize: 11, marginTop: 5 }}>✓ Fix: {item.fixedVersion}</div>}
        </div>
      ))}
    </div>
  );
}

function CheckovReport({ content }) {
  if (!content) return <div style={S.empty}>No IaC scan report. (Runs if Dockerfile or docker-compose.yml is present)</div>;
  const raw = parseJson(content);
  if (!raw) return <pre style={S.pre}>{content}</pre>;
  const reports = Array.isArray(raw) ? raw : [raw];
  const failed = reports.flatMap(r => r.results?.failed_checks || []);
  const passed = reports.reduce((s, r) => s + (r.summary?.passed || 0), 0);
  const failedCount = reports.reduce((s, r) => s + (r.summary?.failed || 0), 0) || failed.length;
  if (failedCount === 0) return <div style={{ ...S.empty, color: '#3fb950' }}>✓ No IaC misconfigurations found. {passed} checks passed.</div>;
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
          <div style={{ color: '#8b949e', fontSize: 11 }}>{f.repo_file_path || f.file_path}{f.file_line_range && ` (lines ${f.file_line_range[0]}-${f.file_line_range[1]})`}</div>
        </div>
      ))}
    </div>
  );
}

// ── Correlated Report ─────────────────────────────────────────────────────────
const SEV_COLOR = { CRITICAL: '#f85149', HIGH: '#d29922', MEDIUM: '#388bfd', LOW: '#8b949e', UNKNOWN: '#484f58' };
const TOOL_CHIP = { gitleaks: { label: '🔑 Secrets', color: '#f85149' }, sonarqube: { label: '🔍 SAST', color: '#388bfd' }, 'trivy-fs': { label: '📦 Deps', color: '#d29922' }, checkov: { label: '🏗️ IaC', color: '#3fb950' } };

function CorrelatedReport({ scanId, done }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!done) return;
    setLoading(true);
    api.get(`/scans/${scanId}/reports/correlated`)
      .then(r => setData(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [scanId, done]);

  if (!done) return <div style={S.empty}>Correlated view available once scan completes.</div>;
  if (loading) return <div style={S.loading}>Building correlation map...</div>;
  if (!data) return <div style={S.empty}>No findings to correlate yet.</div>;

  const { totalFindings, uniqueFiles, multiToolHits, criticalCount, highCount, toolBreakdown, items } = data;

  if (totalFindings === 0) return <div style={{ ...S.empty, color: '#3fb950' }}>✓ No findings across all tools.</div>;

  return (
    <div>
      {/* Summary cards */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
        <div style={S.statCard}><div style={{ ...S.statNum, fontSize: 22 }}>{totalFindings}</div><div style={S.statLabel}>Total Findings</div></div>
        <div style={S.statCard}><div style={{ ...S.statNum, fontSize: 22, color: '#f85149' }}>{criticalCount}</div><div style={S.statLabel}>Critical Files</div></div>
        <div style={S.statCard}><div style={{ ...S.statNum, fontSize: 22, color: '#d29922' }}>{highCount}</div><div style={S.statLabel}>High Files</div></div>
        <div style={S.statCard}><div style={{ ...S.statNum, fontSize: 22, color: '#58a6ff' }}>{multiToolHits}</div><div style={S.statLabel}>Multi-Tool Hits</div></div>
      </div>

      {/* Tool breakdown */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
        {Object.entries(toolBreakdown).map(([tool, count]) => count > 0 && (
          <span key={tool} style={{ background: '#21262d', border: '1px solid #30363d', borderRadius: 20, padding: '4px 12px', fontSize: 11, color: '#8b949e' }}>
            {tool}: <strong style={{ color: '#e6edf3' }}>{count}</strong>
          </span>
        ))}
      </div>

      {multiToolHits > 0 && (
        <div style={{ marginBottom: 12, padding: '8px 14px', background: 'rgba(248,81,73,0.07)', border: '1px solid rgba(248,81,73,0.25)', borderRadius: 6, fontSize: 12, color: '#f85149' }}>
          ⚠ {multiToolHits} file{multiToolHits > 1 ? 's' : ''} flagged by multiple scanners — highest priority to fix
        </div>
      )}

      {/* Findings list */}
      {items.map((item, i) => (
        <div key={i} style={{
          ...S.pre, marginBottom: 8, padding: 14,
          border: item.multiTool ? `1px solid ${SEV_COLOR[item.severity] || '#30363d'}` : '1px solid #21262d',
          background: item.multiTool ? 'rgba(248,81,73,0.04)' : '#0d1117',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
            <span style={{ color: SEV_COLOR[item.severity] || '#8b949e', fontWeight: 700, fontSize: 11 }}>{item.severity}</span>
            {item.multiTool && <span style={{ background: 'rgba(248,81,73,0.15)', border: '1px solid rgba(248,81,73,0.3)', borderRadius: 10, padding: '1px 8px', fontSize: 10, color: '#f85149', fontWeight: 700 }}>MULTI-TOOL</span>}
            {item.tools.map(t => {
              const cfg = TOOL_CHIP[t] || { label: t, color: '#8b949e' };
              return <span key={t} style={{ background: '#21262d', border: `1px solid ${cfg.color}33`, borderRadius: 10, padding: '1px 8px', fontSize: 10, color: cfg.color }}>{cfg.label}</span>;
            })}
          </div>
          <div style={{ color: '#e6edf3', fontSize: 12, fontFamily: 'monospace', marginBottom: 8 }}>{item.file || '(no file)'}</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {item.findings.map((f, fi) => (
              <div key={fi} style={{ fontSize: 11, color: '#8b949e', paddingLeft: 10, borderLeft: `2px solid ${SEV_COLOR[f.severity] || '#30363d'}` }}>
                <span style={{ color: SEV_COLOR[f.severity] || '#8b949e', fontWeight: 600 }}>{f.severity}</span> · {f.title}
                {f.line && <span style={{ color: '#484f58' }}> (line {f.line})</span>}
                {f.fix && <span style={{ color: '#3fb950' }}> → fix: {f.fix}</span>}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── AI Pre-Scan Analysis Card ─────────────────────────────────────────────────
const SECTION_ICONS = {
  'Top Security Risks': '🛡️',
  'Secrets or Credentials': '🔑',
  'Common Vulnerable Dependency': '📦',
  'OWASP': '⚠️',
  'Focus Areas': '🔍',
};

function renderInline(text) {
  const parts = text.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((p, i) =>
    p.startsWith('**') && p.endsWith('**')
      ? <strong key={i} style={{ color: '#e6edf3', fontWeight: 600 }}>{p.slice(2, -2)}</strong>
      : <span key={i}>{p}</span>
  );
}

function PreAnalysisCard({ text }) {
  const sections = [];
  let current = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('### ')) {
      if (current) sections.push(current);
      const title = line.replace(/^###\s*/, '');
      const icon = Object.entries(SECTION_ICONS).find(([k]) => title.includes(k))?.[1] || '📋';
      current = { title, icon, items: [] };
    } else if (line.startsWith('- ') && current) {
      current.items.push(line.slice(2));
    } else if (current) {
      current.items.push(line);
    }
  }
  if (current) sections.push(current);

  return (
    <div style={{ marginBottom: 20, background: '#161b22', border: '1px solid rgba(88,166,255,0.2)', borderRadius: 10, overflow: 'hidden', animation: 'fadeIn 0.3s ease' }}>
      {/* Header bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 18px', background: 'rgba(88,166,255,0.06)', borderBottom: '1px solid rgba(88,166,255,0.15)' }}>
        <span style={{ fontSize: 16 }}>✨</span>
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#58a6ff', letterSpacing: '0.06em' }}>AI PRE-SCAN ANALYSIS</div>
          <div style={{ fontSize: 11, color: '#484f58', marginTop: 1 }}>Generated before pipeline run — highlights expected risk areas</div>
        </div>
      </div>

      {/* Sections grid */}
      <div style={{ padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: 14 }}>
        {sections.length === 0 ? (
          <div style={{ fontSize: 13, color: '#e6edf3', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>{text}</div>
        ) : sections.map((sec, si) => (
          <div key={si} style={{ background: '#0d1117', border: '1px solid #21262d', borderRadius: 8, padding: '12px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <span style={{ fontSize: 15 }}>{sec.icon}</span>
              <span style={{ fontSize: 12, fontWeight: 700, color: '#d29922', letterSpacing: '0.04em' }}>{sec.title}</span>
            </div>
            <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 7 }}>
              {sec.items.map((item, ii) => (
                <li key={ii} style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                  <span style={{ color: '#388bfd', flexShrink: 0, marginTop: 2, fontSize: 11 }}>▸</span>
                  <span style={{ fontSize: 12, color: '#8b949e', lineHeight: 1.6 }}>{renderInline(item)}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

const RISK_COLOR = { CRITICAL: '#f85149', HIGH: '#d29922', MEDIUM: '#388bfd', LOW: '#3fb950' };

function AiSummary({ scanId, ready }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');

  const load = async () => {
    setLoading(true);
    setErr('');
    try {
      const { data } = await api.get(`/scans/${scanId}/reports/ai`);
      const raw = data.summary || '';
      try {
        setResult(JSON.parse(raw));
      } catch {
        setResult({ rawText: raw });
      }
    } catch (e) {
      setErr(e.response?.data?.error || 'Failed to load summary');
    } finally {
      setLoading(false);
    }
  };

  if (!ready) return <div style={S.empty}>Summary will be available once the scan completes.</div>;
  if (!result && !loading && !err) {
    return (
      <div>
        <div style={{ color: '#8b949e', fontSize: 13, marginBottom: 16 }}>Click to generate an AI-powered summary of all scan findings.</div>
        <button onClick={load} style={{ padding: '9px 20px', background: '#238636', border: 'none', borderRadius: 6, color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
          ✨ Generate AI Summary
        </button>
      </div>
    );
  }
  if (loading) return <div style={S.loading}>Generating AI correlation analysis...</div>;
  if (err) return <div style={{ ...S.empty, color: '#f85149' }}>{err}</div>;
  if (!result) return null;

  // Fallback: raw text
  if (result.error) return <div style={{ ...S.empty, color: '#f85149' }}>{result.error}</div>;
  if (result.rawText) return <div style={S.aiBox}>{result.rawText}</div>;

  const riskColor = RISK_COLOR[result.riskLevel] || '#8b949e';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Risk header */}
      <div style={{ background: '#161b22', border: `1px solid ${riskColor}44`, borderRadius: 10, padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 18 }}>
        <div style={{ textAlign: 'center', flexShrink: 0 }}>
          <div style={{ fontSize: 32, fontWeight: 800, color: riskColor, lineHeight: 1 }}>{result.riskLevel}</div>
          <div style={{ fontSize: 11, color: '#8b949e', marginTop: 3 }}>RISK LEVEL</div>
          {result.riskScore != null && (
            <div style={{ marginTop: 6, height: 4, width: 80, background: '#21262d', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${result.riskScore}%`, background: riskColor, borderRadius: 2 }} />
            </div>
          )}
        </div>
        <div style={{ flex: 1, fontSize: 13, color: '#e6edf3', lineHeight: 1.6 }}>{result.headline}</div>
      </div>

      {/* Top findings */}
      {result.topFindings?.length > 0 && (
        <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 10, padding: '14px 18px' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#8b949e', letterSpacing: '0.07em', marginBottom: 12 }}>TOP FINDINGS</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {result.topFindings.map((f, i) => (
              <div key={i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                <span style={{ color: RISK_COLOR[f.severity] || '#8b949e', fontWeight: 700, fontSize: 11, flexShrink: 0, minWidth: 60 }}>{f.severity}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12, color: '#e6edf3' }}>{f.issue}</div>
                  {f.fix && <div style={{ fontSize: 11, color: '#3fb950', marginTop: 3 }}>→ {f.fix}</div>}
                  <div style={{ fontSize: 10, color: '#484f58', marginTop: 2 }}>{f.tool}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Immediate actions */}
      {result.immediateActions?.length > 0 && (
        <div style={{ background: 'rgba(35,134,54,0.08)', border: '1px solid rgba(63,185,80,0.25)', borderRadius: 10, padding: '14px 18px' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#3fb950', letterSpacing: '0.07em', marginBottom: 10 }}>IMMEDIATE ACTIONS</div>
          <ol style={{ paddingLeft: 18, margin: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
            {result.immediateActions.map((a, i) => (
              <li key={i} style={{ fontSize: 12, color: '#e6edf3', lineHeight: 1.6 }}>{a}</li>
            ))}
          </ol>
        </div>
      )}

      {/* By tool */}
      {result.byTool && (
        <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 10, padding: '14px 18px' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#8b949e', letterSpacing: '0.07em', marginBottom: 12 }}>BY SCANNER</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
            {[['🔑 Secrets', result.byTool.secrets], ['🔍 SAST', result.byTool.sast], ['📦 Dependencies', result.byTool.dependencies], ['🐳 Container', result.byTool.container]].map(([label, text]) => text && (
              <div key={label} style={{ background: '#0d1117', border: '1px solid #21262d', borderRadius: 6, padding: '10px 12px' }}>
                <div style={{ fontSize: 11, color: '#58a6ff', fontWeight: 600, marginBottom: 5 }}>{label}</div>
                <div style={{ fontSize: 11, color: '#8b949e', lineHeight: 1.5 }}>{text}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────
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
        if (data.status === 'done') { es.close(); loadAllReports(); }
        else if (data.status === 'failed') { setPollError(data.error || 'Scan failed.'); es.close(); }
      } catch {}
    };
    es.onerror = () => es.close();
  };

  const loadAllReports = async () => {
    const types = ['gitleaks', 'semgrep', 'owasp', 'trivy', 'checkov'];
    const results = await Promise.allSettled(types.map(t => api.get(`/scans/${id}/reports/${t}`)));
    const newReports = {};
    results.forEach((r, i) => { if (r.status === 'fulfilled') newReports[types[i]] = r.value.data.content; });
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
    } finally { setActioning(null); }
  };

  const stop = async () => {
    setActioning('stop');
    try {
      await api.post(`/scans/${id}/stop`);
      eventSourceRef.current?.close();
      setScan(prev => ({ ...prev, status: 'failed' }));
    } catch (err) {
      alert(err.response?.data?.error || 'Stop failed');
    } finally { setActioning(null); }
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
      {/* Header */}
      <div style={S.header}>
        <button style={S.back} onClick={() => nav('/dashboard')}>
          <span>←</span> Back to Dashboard
        </button>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
          <div>
            <div style={S.h1}>{scan.repo_url.replace(/\.git$/, '').split('/').slice(-2).join('/')}</div>
            <div style={S.meta}>
              <span style={S.branch}>{scan.branch}</span>
              <span style={{ ...S.status, ...statusStyle(scan.status) }}>
                {scan.status === 'running'
                  ? <><span style={{ display: 'inline-block', animation: 'spin 1.2s linear infinite' }}>⟳</span> Running</>
                  : scan.status === 'done' ? '✓ Done'
                  : scan.status === 'failed' ? '✗ Failed'
                  : '⏳ Pending'}
              </span>
              {scan.last_build && <span style={{ color: '#8b949e', fontSize: 12 }}>Build #{scan.last_build}</span>}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>
            {running && (
              <button disabled={actioning === 'stop'} onClick={stop} style={{
                padding: '6px 14px', borderRadius: 6, fontSize: 12, background: '#21262d',
                border: `1px solid ${actioning === 'stop' ? '#484f58' : '#d29922'}`,
                color: actioning === 'stop' ? '#484f58' : '#d29922',
                cursor: actioning === 'stop' ? 'not-allowed' : 'pointer',
                opacity: actioning === 'stop' ? 0.6 : 1,
              }}>
                {actioning === 'stop' ? 'Stopping...' : '■ Stop'}
              </button>
            )}
            {!running && (
              <button disabled={actioning === 'rerun'} onClick={rerun} style={{
                padding: '6px 14px', borderRadius: 6, fontSize: 12, background: '#21262d',
                border: `1px solid ${actioning === 'rerun' ? '#484f58' : '#388bfd'}`,
                color: actioning === 'rerun' ? '#484f58' : '#388bfd',
                cursor: actioning === 'rerun' ? 'not-allowed' : 'pointer',
                opacity: actioning === 'rerun' ? 0.6 : 1,
              }}>
                {actioning === 'rerun' ? 'Rerunning...' : '↺ Rerun'}
              </button>
            )}
            <button style={{ padding: '6px 14px', background: '#21262d', border: '1px solid #f85149', borderRadius: 6, color: '#f85149', fontSize: 12, cursor: 'pointer' }} onClick={deleteScan}>
              Delete
            </button>
          </div>
        </div>
      </div>

      {/* Pipeline Tracker */}
      <PipelineTracker scan={scan} />

      {pollError && (
        <div style={{ marginBottom: 20, padding: '12px 16px', background: 'rgba(248,81,73,0.1)', border: '1px solid rgba(248,81,73,0.3)', borderRadius: 6, color: '#f85149', fontSize: 13 }}>
          ✗ {pollError}
        </div>
      )}

      {/* Metadata badges */}
      {scan.detected_lang && (
        <div style={{ marginBottom: 16, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: '#8b949e' }}>Detected:</span>
          <span style={{ background: '#21262d', border: '1px solid #30363d', borderRadius: 4, padding: '2px 8px', fontSize: 12, color: '#e6edf3' }}>{scan.detected_lang}</span>
          {scan.has_dockerfile
            ? <span style={{ background: 'rgba(63,185,80,0.12)', border: '1px solid rgba(63,185,80,0.3)', borderRadius: 4, padding: '2px 8px', fontSize: 11, color: '#3fb950' }}>✓ Dockerfile</span>
            : <span style={{ background: 'rgba(139,148,158,0.08)', border: '1px solid #30363d', borderRadius: 4, padding: '2px 8px', fontSize: 11, color: '#8b949e' }}>✗ No Dockerfile — Trivy skipped</span>
          }
          {scan.jenkinsfile_pushed && (
            <span style={{ background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.3)', borderRadius: 4, padding: '2px 8px', fontSize: 11, color: '#58a6ff' }}>✓ Jenkinsfile.security pushed</span>
          )}
        </div>
      )}

      {scan.pre_analysis && <PreAnalysisCard text={scan.pre_analysis} />}

      {/* Tabs */}
      <div style={S.tabs}>
        {TABS.map(t => (
          <button key={t.id} style={{ ...S.tab, ...(tab === t.id ? S.tabActive : {}) }} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      <div style={{ animation: 'fadeIn 0.2s ease' }}>
        {tab === 'correlated' && <CorrelatedReport scanId={id} done={done} />}
        {tab === 'gitleaks' && <SecretsReport scanId={id} done={done} />}
        {tab === 'semgrep' && <SastReport scanId={id} done={done} sonarContent={reports.semgrep} />}
        {tab === 'owasp' && <DependenciesReport scanId={id} done={done} />}
        {tab === 'trivy' && <ContainerReport scanId={id} done={done} hasDockerfile={scan?.has_dockerfile} />}
        {tab === 'checkov' && <CheckovReport content={reports.checkov} />}
        {tab === 'ai' && <AiSummary scanId={id} ready={done} />}
      </div>
    </div>
  );
}
