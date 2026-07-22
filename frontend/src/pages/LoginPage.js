import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';
import { useAuth } from '../App';

const S = {
  wrap: { minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#0d1117' },
  card: { background: '#161b22', border: '1px solid #30363d', borderRadius: 8, padding: 40, width: 380 },
  title: { fontSize: 24, fontWeight: 700, color: '#58a6ff', marginBottom: 4 },
  sub: { color: '#8b949e', fontSize: 13, marginBottom: 28 },
  tabs: { display: 'flex', gap: 0, marginBottom: 24, borderBottom: '1px solid #30363d' },
  tab: { flex: 1, padding: '8px 0', textAlign: 'center', cursor: 'pointer', fontSize: 14, color: '#8b949e', background: 'none', border: 'none', borderBottom: '2px solid transparent' },
  tabActive: { color: '#58a6ff', borderBottomColor: '#58a6ff' },
  label: { display: 'block', fontSize: 12, color: '#8b949e', marginBottom: 6, marginTop: 14 },
  input: { width: '100%', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: '9px 12px', color: '#e6edf3', fontSize: 14, outline: 'none' },
  btn: { width: '100%', marginTop: 22, padding: '10px 0', background: '#238636', border: 'none', borderRadius: 6, color: '#fff', fontSize: 14, fontWeight: 600, cursor: 'pointer' },
  btnLoading: { width: '100%', marginTop: 22, padding: '10px 0', background: '#1a6626', border: 'none', borderRadius: 6, color: '#8b949e', fontSize: 14, fontWeight: 600, cursor: 'not-allowed', opacity: 0.7 },
  err: { marginTop: 14, color: '#f85149', fontSize: 13 },
};

export default function LoginPage() {
  const [tab, setTab] = useState('login');
  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const nav = useNavigate();

  const set = k => e => setForm(f => ({ ...f, [k]: e.target.value }));

  const submit = async e => {
    e.preventDefault();
    setErr('');
    setLoading(true);
    try {
      const path = tab === 'login' ? '/auth/login' : '/auth/register';
      const { data } = await api.post(path, form);
      login(data.token, data.user);
      nav('/dashboard');
    } catch (err) {
      setErr(err.response?.data?.error || 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={S.wrap}>
      <div style={S.card}>
        <div style={S.title}>DevSecurityHub</div>
        <div style={S.sub}>Jenkins-powered security scanning</div>
        <div style={S.tabs}>
          {['login', 'register'].map(t => (
            <button key={t} style={{ ...S.tab, ...(tab === t ? S.tabActive : {}) }} onClick={() => setTab(t)}>
              {t === 'login' ? 'Sign In' : 'Register'}
            </button>
          ))}
        </div>
        <form onSubmit={submit}>
          {tab === 'register' && (
            <>
              <label style={S.label}>Name</label>
              <input style={S.input} value={form.name} onChange={set('name')} placeholder="Your name" required />
            </>
          )}
          <label style={S.label}>Email</label>
          <input style={S.input} type="email" value={form.email} onChange={set('email')} placeholder="you@example.com" required />
          <label style={S.label}>Password</label>
          <input style={S.input} type="password" value={form.password} onChange={set('password')} placeholder="••••••••" required />
          {err && <div style={S.err}>{err}</div>}
          <button style={loading ? S.btnLoading : S.btn} type="submit" disabled={loading}>
            {loading ? (tab === 'login' ? 'Signing in...' : 'Creating account...') : tab === 'login' ? 'Sign In' : 'Create Account'}
          </button>
        </form>
      </div>
    </div>
  );
}
