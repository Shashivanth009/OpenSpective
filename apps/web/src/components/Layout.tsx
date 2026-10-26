import { Outlet, NavLink, Link, useLocation } from 'react-router-dom';
import {
  Search, LayoutDashboard, History, Settings,
  Sun, Moon, Shield, BookOpen, Compass, Menu, X
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
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const location = useLocation();

  // Close mobile menu on page navigation
  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location.pathname]);

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
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--color-bg)' }}>
      {/* Navigation Top Bar */}
      <nav className="nav glass-nav">
        <div className="nav-inner" style={{ height: '64px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 var(--space-5)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            {showSidebar && (
              <button
                className="mobile-menu-btn btn btn-ghost btn-sm"
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                aria-label="Toggle navigation menu"
                style={{ padding: '6px', display: 'none' }}
              >
                {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
              </button>
            )}

            <Link to="/" className="nav-logo" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Logo size={32} />
              <div style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.1 }}>
                <span style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.02em', color: 'var(--color-dark)' }}>
                  Open<span style={{ color: 'var(--color-accent)' }}>Spective</span>
                </span>
                <span style={{ fontSize: '9px', fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  Passive Reconnaissance
                </span>
              </div>
            </Link>
          </div>

          {!minimal && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              {!showSidebar && (
                <div className="nav-links" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)' }}>
                  <NavLink to="/framework" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>OSINT Framework</NavLink>
                  <NavLink to="/docs" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>Docs</NavLink>
                  <NavLink to="/privacy" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>Privacy</NavLink>
                </div>
              )}

              <button
                className="btn btn-ghost btn-sm"
                onClick={toggleTheme}
                aria-label="Toggle theme"
                style={{ padding: '8px 10px', borderRadius: 'var(--radius)', border: '1px solid var(--glass-border-subtle)' }}
                title={theme === 'light' ? 'Switch to Dark Mode' : 'Switch to Light Mode'}
              >
                {theme === 'light' ? <Moon size={16} /> : <Sun size={16} />}
              </button>

              <NavLink to="/investigate" className="btn btn-primary btn-sm" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', boxShadow: '0 2px 10px rgba(96,153,102,0.3)' }}>
                <Search size={14} /> <span className="hide-on-mobile">New Investigation</span>
              </NavLink>
            </div>
          )}
        </div>
      </nav>

      {/* Main Content Area */}
      {showSidebar ? (
        <div className="layout-with-sidebar" style={{ flex: 1, display: 'flex', position: 'relative' }}>
          {/* Mobile Backdrop Overlay */}
          {mobileMenuOpen && (
            <div
              className="sidebar-backdrop"
              onClick={() => setMobileMenuOpen(false)}
              style={{
                position: 'fixed',
                inset: 0,
                background: 'rgba(0, 0, 0, 0.45)',
                backdropFilter: 'blur(4px)',
                zIndex: 40,
              }}
            />
          )}

          {/* Frosted Glass Sidebar */}
          <aside className={`sidebar glass-sidebar ${mobileMenuOpen ? 'mobile-open' : ''}`}>
            <nav style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
              {sidebarNav.map(({ to, icon: Icon, label }) => {
                const isCurrent = to === '/investigate'
                  ? location.pathname === '/investigate' || location.pathname.startsWith('/investigations/')
                  : location.pathname === to;
                return (
                  <NavLink
                    key={to}
                    to={to}
                    className={() =>
                      `sidebar-link flex items-center gap-2${isCurrent ? ' active glow-border-accent' : ''}`
                    }
                  >
                    <Icon size={16} />
                    <span>{label}</span>
                  </NavLink>
                );
              })}
            </nav>

            <div style={{ borderTop: '1px solid var(--glass-border-subtle)', marginTop: 'auto', paddingTop: '12px' }}>
              <div
                className="glass-panel-subtle"
                style={{
                  padding: '8px 10px',
                  borderRadius: '10px',
                  marginBottom: '10px',
                  border: '1px solid var(--glass-border)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--color-accent)', fontWeight: 700 }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--color-accent)', display: 'inline-block', boxShadow: '0 0 8px var(--color-accent)' }} />
                  Free & Open Edition
                </div>
                <div style={{ fontSize: '10px', color: 'var(--color-text-secondary)', marginTop: '2px' }}>
                  Passive OSINT Suite
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                <NavLink to="/docs" className={({ isActive }) => `sidebar-link-subtle flex items-center gap-2${isActive ? ' active' : ''}`}>
                  <BookOpen size={13} /> Documentation
                </NavLink>
                <NavLink to="/privacy" className={({ isActive }) => `sidebar-link-subtle flex items-center gap-2${isActive ? ' active' : ''}`}>
                  <Shield size={13} /> Security & Privacy
                </NavLink>
              </div>
            </div>
          </aside>

          <main className="main-content" style={{ flex: 1, minWidth: 0, overflowX: 'hidden' }}>
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
