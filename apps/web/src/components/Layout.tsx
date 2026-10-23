import { Outlet, NavLink, Link } from 'react-router-dom';
import {
  Search, LayoutDashboard, History, Settings,
  Sun, Moon, Shield, BookOpen, Compass
} from 'lucide-react';
import { useState, useEffect } from 'react';

// SVG Logo
function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="32" cy="32" r="27" stroke="#609966" strokeWidth="4" />
      <circle cx="32" cy="15" r="15" stroke="#9DC08B" strokeWidth="2.5" />
      <circle cx="32" cy="14" r="3.5" fill="#609966" />
      <circle cx="32" cy="50" r="3.5" fill="#609966" />
      <circle cx="14" cy="32" r="3.5" fill="#609966" />
      <circle cx="50" cy="32" r="3.5" fill="#609966" />
      <circle cx="32" cy="32" r="5" fill="#40513B" />
      <line x1="32" y1="18" x2="32" y2="26" stroke="#9DC08B" strokeWidth="1.5" strokeLinecap="round" />
      <line x1="32" y1="38" x2="32" y2="46" stroke="#9DC08B" strokeWidth="1.5" strokeLinecap="round" />
      <line x1="18" y1="32" x2="26" y2="32" stroke="#9DC08B" strokeWidth="1.5" strokeLinecap="round" />
      <line x1="38" y1="32" x2="46" y2="32" stroke="#9DC08B" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

interface LayoutProps {
  minimal?: boolean;
  showSidebar?: boolean;
}

export default function Layout({ minimal, showSidebar }: LayoutProps) {
  const [theme, setTheme] = useState<'light' | 'dark'>(() =>
    (localStorage.getItem('os_theme') as 'light' | 'dark') ?? 'light'
  );

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('os_theme', theme);
  }, [theme]);

  const toggleTheme = () => setTheme(t => t === 'light' ? 'dark' : 'light');

  const sidebarNav = [
    { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { to: '/investigate', icon: Search, label: 'Investigate' },
    { to: '/framework', icon: Compass, label: 'OSINT Framework' },
    { to: '/history', icon: History, label: 'History' },
    { to: '/settings', icon: Settings, label: 'Settings' },
  ];

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Navigation */}
      <nav className="nav">
        <div className="nav-inner">
          <Link to="/" className="nav-logo">
            <Logo />
            Open<span>Spective</span>
          </Link>

          {!minimal && (
            <>
              <div className="nav-links" style={{ flex: 1, justifyContent: 'center' }}>
                {!showSidebar && (
                  <>
                    <NavLink to="/framework" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>OSINT Framework</NavLink>
                    <NavLink to="/docs" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>Docs</NavLink>
                    <NavLink to="/privacy" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>Privacy</NavLink>
                  </>
                )}
              </div>

              <div className="flex items-center gap-3">
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={toggleTheme}
                  aria-label="Toggle theme"
                  style={{ padding: '8px' }}
                >
                  {theme === 'light' ? <Moon size={16} /> : <Sun size={16} />}
                </button>

                <NavLink to="/investigate" className="btn btn-primary btn-sm">
                  <Search size={14} /> New Investigation
                </NavLink>
              </div>
            </>
          )}
        </div>
      </nav>

      {/* Main Content */}
      {showSidebar ? (
        <div className="layout-with-sidebar" style={{ flex: 1 }}>
          {/* Sidebar */}
          <aside className="sidebar">
            <nav style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {sidebarNav.map(({ to, icon: Icon, label }) => (
                <NavLink
                  key={to}
                  to={to}
                  className={({ isActive }) =>
                    `flex items-center gap-3 nav-link${isActive ? ' active' : ''}`
                  }
                  style={{ borderRadius: 'var(--radius)', fontWeight: 500 }}
                >
                  <Icon size={18} />
                  {label}
                </NavLink>
              ))}
            </nav>

            <div style={{ borderTop: '1px solid var(--color-border)', marginTop: 'auto', paddingTop: 'var(--space-4)' }}>
              <div style={{ padding: 'var(--space-3)', background: 'var(--color-bg-secondary)', borderRadius: 'var(--radius)', marginBottom: 'var(--space-3)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: 'var(--text-xs)', color: 'var(--color-accent)', fontWeight: 600 }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--color-accent)', display: 'inline-block' }} />
                  Free & Open Edition
                </div>
                <div style={{ fontSize: '11px', color: 'var(--color-text-secondary)', marginTop: '3px' }}>
                  No sign-in required
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <NavLink to="/docs" className={({ isActive }) => `flex items-center gap-3 nav-link${isActive ? ' active' : ''}`} style={{ fontSize: 'var(--text-sm)' }}>
                  <BookOpen size={15} /> Docs
                </NavLink>
                <NavLink to="/privacy" className={({ isActive }) => `flex items-center gap-3 nav-link${isActive ? ' active' : ''}`} style={{ fontSize: 'var(--text-sm)' }}>
                  <Shield size={15} /> Privacy
                </NavLink>
              </div>
            </div>
          </aside>

          <main className="main-content">
            <Outlet />
          </main>
        </div>
      ) : (
        <main style={{ flex: 1 }}>
          <Outlet />
        </main>
      )}

      {/* Footer (only on non-sidebar pages) */}
      {!showSidebar && !minimal && (
        <footer style={{
          borderTop: '1px solid var(--color-border)',
          padding: 'var(--space-8) var(--space-6)',
          background: 'var(--color-surface)',
          marginTop: 'auto',
        }}>
          <div className="container">
            <div className="flex items-center justify-between flex-wrap gap-4">
              <div className="flex items-center gap-3">
                <Logo size={22} />
                <span style={{ fontWeight: 700, color: 'var(--color-dark)' }}>OpenSpective</span>
                <span style={{ color: 'var(--color-text-muted)', fontSize: 'var(--text-sm)' }}>v0.1.0</span>
              </div>
              <div className="flex items-center gap-6" style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>
                <Link to="/docs" style={{ color: 'inherit' }}>Docs</Link>
                <Link to="/privacy" style={{ color: 'inherit' }}>Privacy</Link>
                <Link to="/terms" style={{ color: 'inherit' }}>Terms</Link>
                <span>For authorized research only</span>
              </div>
            </div>
          </div>
        </footer>
      )}
    </div>
  );
}
