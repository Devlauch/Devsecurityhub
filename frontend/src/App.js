import React, { createContext, useContext, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import NewScanPage from './pages/NewScanPage';
import ScanDetailPage from './pages/ScanDetailPage';
import SettingsPage from './pages/SettingsPage';

export const AuthContext = createContext(null);

export function useAuth() {
  return useContext(AuthContext);
}

function PrivateRoute({ children }) {
  const { user } = useAuth();
  return user ? children : <Navigate to="/login" replace />;
}

const S = {
  layout: { display: 'flex', minHeight: '100vh', background: '#0d1117' },
  sidebar: { width: 220, background: '#161b22', borderRight: '1px solid #30363d', padding: '24px 0', display: 'flex', flexDirection: 'column' },
  logo: { padding: '0 20px 24px', fontSize: 18, fontWeight: 700, color: '#58a6ff', borderBottom: '1px solid #30363d', marginBottom: 16 },
  logoSub: { fontSize: 11, color: '#8b949e', fontWeight: 400, marginTop: 2 },
  navLink: { display: 'block', padding: '10px 20px', color: '#8b949e', textDecoration: 'none', fontSize: 14, borderLeft: '3px solid transparent', transition: 'all 0.15s' },
  navLinkActive: { color: '#58a6ff', borderLeftColor: '#58a6ff', background: 'rgba(88,166,255,0.06)' },
  main: { flex: 1, overflow: 'auto' },
  logoutBtn: { marginTop: 'auto', padding: '10px 20px', color: '#f85149', fontSize: 14, background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left' },
};

function Nav() {
  const { logout } = useAuth();
  const loc = useLocation();
  const link = (to, label) => (
    <Link to={to} style={{ ...S.navLink, ...(loc.pathname === to || loc.pathname.startsWith(to + '/') ? S.navLinkActive : {}) }}>{label}</Link>
  );
  return (
    <div style={S.sidebar}>
      <div style={S.logo}>
        DevSecurityHub
        <div style={S.logoSub}>Jenkins Security Scans</div>
      </div>
      {link('/dashboard', '▦ Dashboard')}
      {link('/scans/new', '+ New Scan')}
      {link('/settings', '⚙ Settings')}
      <button style={S.logoutBtn} onClick={logout}>Logout</button>
    </div>
  );
}

function Layout({ children }) {
  return (
    <div style={S.layout}>
      <Nav />
      <div style={S.main}>{children}</div>
    </div>
  );
}

export default function App() {
  const stored = localStorage.getItem('sechub_user');
  const [user, setUser] = useState(stored ? JSON.parse(stored) : null);

  const login = (token, userData) => {
    localStorage.setItem('sechub_token', token);
    localStorage.setItem('sechub_user', JSON.stringify(userData));
    setUser(userData);
  };

  const logout = () => {
    localStorage.removeItem('sechub_token');
    localStorage.removeItem('sechub_user');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/dashboard" element={<PrivateRoute><Layout><DashboardPage /></Layout></PrivateRoute>} />
          <Route path="/scans/new" element={<PrivateRoute><Layout><NewScanPage /></Layout></PrivateRoute>} />
          <Route path="/scans/:id" element={<PrivateRoute><Layout><ScanDetailPage /></Layout></PrivateRoute>} />
          <Route path="/settings" element={<PrivateRoute><Layout><SettingsPage /></Layout></PrivateRoute>} />
          <Route path="*" element={<Navigate to={user ? '/dashboard' : '/login'} replace />} />
        </Routes>
      </BrowserRouter>
    </AuthContext.Provider>
  );
}
