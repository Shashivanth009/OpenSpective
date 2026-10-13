import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Search, Shield, Activity, Globe, CheckCircle2, Clock,
  ArrowUpRight, Server, RefreshCw, PlusCircle, ShieldAlert
} from 'lucide-react';
import { useAuth } from '../AuthContext.tsx';
import * as api from '../api.ts';

export default function DashboardPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [investigations, setInvestigations] = useState<api.Investigation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [quickTarget, setQuickTarget] = useState('');
  const [health, setHealth] = useState<any>(null);

  const fetchDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [invList, healthData] = await Promise.allSettled([
        api.listInvestigations(1, 10),
        api.getHealth(),
      ]);

      if (invList.status === 'fulfilled') {
        setInvestigations(invList.value.data);
      }
      if (healthData.status === 'fulfilled') {
        setHealth(healthData.value);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to load dashboard data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const handleQuickLaunch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickTarget.trim()) return;
    navigate(`/investigate?q=${encodeURIComponent(quickTarget.trim())}`);
  };

  const completedCount = investigations.filter(i => i.status === 'completed').length;
  const runningCount = investigations.filter(i => i.status === 'running' || i.status === 'queued').length;
  const totalCount = investigations.length;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <span className="badge badge-success">Completed</span>;
      case 'running':
        return <span className="badge badge-info"><span className="spinner" style={{ width: 10, height: 10 }} /> Running</span>;
      case 'queued':
        return <span className="badge badge-warning">Queued</span>;
      case 'partial':
        return <span className="badge badge-warning">Partial</span>;
      case 'failed':
        return <span className="badge badge-error">Failed</span>;
      default:
        return <span className="badge badge-neutral">{status}</span>;
    }
  };

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto', padding: 'var(--space-6) var(--space-8)' }}>
      {/* Top Banner / Welcome */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-8)', flexWrap: 'wrap', gap: 'var(--space-4)' }}>
        <div>
          <h1 style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, letterSpacing: '-0.03em', color: 'var(--color-dark)' }}>
            Intelligence Command
          </h1>
          <p style={{ color: 'var(--color-text-secondary)', marginTop: 'var(--space-1)', fontSize: 'var(--text-base)' }}>
            Welcome back, <strong>{user?.displayName || user?.email || 'Investigator'}</strong>. Passive OSINT posture is operational.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
          <button onClick={fetchDashboardData} className="btn btn-ghost btn-sm" title="Refresh metrics">
            <RefreshCw size={15} /> Refresh
          </button>
          <Link to="/investigate" className="btn btn-primary btn-sm">
            <PlusCircle size={15} /> New Investigation
          </Link>
        </div>
      </div>

      {error && (
        <div className="alert alert-error" style={{ marginBottom: 'var(--space-6)' }}>
          {error}
        </div>
      )}

      {/* Quick Launch Bar */}
      <div className="card" style={{ marginBottom: 'var(--space-8)', padding: 'var(--space-5)', background: 'var(--color-surface-elevated)' }}>
        <form onSubmit={handleQuickLaunch} style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: 1, minWidth: '280px' }}>
            <Search
              size={18}
              style={{
                position: 'absolute',
                left: '14px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--color-text-muted)'
              }}
            />
            <input
              type="text"
              className="input"
              style={{ paddingLeft: '44px', width: '100%' }}
              placeholder="Enter target (domain, IPv4/IPv6, email, GitHub user, organization, URL)..."
              value={quickTarget}
              onChange={(e) => setQuickTarget(e.target.value)}
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={!quickTarget.trim()}>
            Start Scan
          </button>
        </form>
      </div>

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 'var(--space-5)', marginBottom: 'var(--space-8)' }}>
        <div className="card" style={{ padding: 'var(--space-5)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, textTransform: 'uppercase', color: 'var(--color-text-muted)', letterSpacing: '0.05em' }}>
                Total Investigations
              </div>
              <div style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, marginTop: 'var(--space-2)', color: 'var(--color-dark)' }}>
                {totalCount}
              </div>
            </div>
            <div style={{ width: 40, height: 40, borderRadius: 'var(--radius)', background: 'var(--color-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-accent)' }}>
              <Activity size={22} />
            </div>
          </div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginTop: 'var(--space-3)' }}>
            Tracked across all target domains & IPs
          </div>
        </div>

        <div className="card" style={{ padding: 'var(--space-5)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, textTransform: 'uppercase', color: 'var(--color-text-muted)', letterSpacing: '0.05em' }}>
                Completed Scans
              </div>
              <div style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, marginTop: 'var(--space-2)', color: 'var(--color-success)' }}>
                {completedCount}
              </div>
            </div>
            <div style={{ width: 40, height: 40, borderRadius: 'var(--radius)', background: 'var(--color-success-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-success)' }}>
              <CheckCircle2 size={22} />
            </div>
          </div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginTop: 'var(--space-3)' }}>
            Artifacts and findings synthesized
          </div>
        </div>

        <div className="card" style={{ padding: 'var(--space-5)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, textTransform: 'uppercase', color: 'var(--color-text-muted)', letterSpacing: '0.05em' }}>
                In Flight / Active
              </div>
              <div style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, marginTop: 'var(--space-2)', color: runningCount > 0 ? 'var(--color-info)' : 'var(--color-text-muted)' }}>
                {runningCount}
              </div>
            </div>
            <div style={{ width: 40, height: 40, borderRadius: 'var(--radius)', background: 'var(--color-info-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-info)' }}>
              <Clock size={22} />
            </div>
          </div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginTop: 'var(--space-3)' }}>
            {runningCount > 0 ? 'Collectors currently executing' : 'Ready for next target'}
          </div>
        </div>

        <div className="card" style={{ padding: 'var(--space-5)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, textTransform: 'uppercase', color: 'var(--color-text-muted)', letterSpacing: '0.05em' }}>
                Module Health
              </div>
              <div style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, marginTop: 'var(--space-2)', color: 'var(--color-accent-dark)' }}>
                {health?.status === 'ok' ? '100%' : 'Online'}
              </div>
            </div>
            <div style={{ width: 40, height: 40, borderRadius: 'var(--radius)', background: 'var(--color-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-accent)' }}>
              <Shield size={22} />
            </div>
          </div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginTop: 'var(--space-3)' }}>
            Edge worker & passive collectors ready
          </div>
        </div>
      </div>

      {/* Main Grid: Recent Investigations + Collectors Status */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 'var(--space-8)', alignItems: 'start' }}>
        {/* Recent Investigations */}
        <div className="card">
          <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, margin: 0 }}>
              Recent Investigations
            </h2>
            <Link to="/history" style={{ fontSize: 'var(--text-sm)', color: 'var(--color-accent)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
              View all <ArrowUpRight size={14} />
            </Link>
          </div>

          <div className="card-body" style={{ padding: 0 }}>
            {loading ? (
              <div style={{ padding: 'var(--space-12)', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                <span className="spinner" style={{ marginRight: 'var(--space-2)' }} /> Loading investigations...
              </div>
            ) : investigations.length === 0 ? (
              <div style={{ padding: 'var(--space-12)', textAlign: 'center' }}>
                <Globe size={40} style={{ margin: '0 auto var(--space-4)', color: 'var(--color-accent-soft)' }} />
                <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-dark)' }}>No investigations yet</h3>
                <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--text-sm)', maxWidth: '400px', margin: 'var(--space-2) auto var(--space-6)' }}>
                  Launch your first reconnaissance to uncover DNS records, certificate transparency logs, subdomains, and threat indicators.
                </p>
                <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'center' }}>
                  <button onClick={() => navigate('/investigate?q=github.com')} className="btn btn-secondary btn-sm">Try github.com</button>
                  <button onClick={() => navigate('/investigate?q=1.1.1.1')} className="btn btn-secondary btn-sm">Try 1.1.1.1</button>
                </div>
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="table" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th>Target</th>
                      <th>Type</th>
                      <th>Status</th>
                      <th>Started</th>
                      <th style={{ textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {investigations.map((inv) => (
                      <tr key={inv.id}>
                        <td>
                          <div style={{ fontWeight: 600, color: 'var(--color-dark)' }}>
                            <Link to={`/investigations/${inv.id}`} style={{ textDecoration: 'none', color: 'inherit' }}>
                              {inv.target}
                            </Link>
                          </div>
                          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
                            ID: {inv.id.substring(0, 12)}...
                          </div>
                        </td>
                        <td>
                          <span className="badge badge-neutral" style={{ textTransform: 'capitalize' }}>
                            {inv.target_type}
                          </span>
                        </td>
                        <td>{getStatusBadge(inv.status)}</td>
                        <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)' }}>
                          {new Date(inv.started_at).toLocaleString()}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <Link to={`/investigations/${inv.id}`} className="btn btn-ghost btn-sm" style={{ padding: '6px 10px' }}>
                            View Report
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Intelligence Feeds & Engine Status */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
          <div className="card">
            <div className="card-header">
              <h2 style={{ fontSize: 'var(--text-base)', fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <Server size={18} style={{ color: 'var(--color-accent)' }} /> Collector Engines
              </h2>
            </div>
            <div className="card-body" style={{ padding: 'var(--space-4)' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {[
                  { name: 'Cloudflare DNS (1.1.1.1)', desc: 'A, AAAA, MX, TXT, CAA DoH', status: 'Active' },
                  { name: 'RDAP Registry Protocol', desc: 'ICANN / RIR Registration queries', status: 'Active' },
                  { name: 'Certificate Transparency', desc: 'crt.sh log monitor & subdomains', status: 'Active' },
                  { name: 'IPInfo Geolocation', desc: 'ASN, Country, City, Carrier info', status: 'Active' },
                  { name: 'VirusTotal Intelligence', desc: 'Multi-engine vendor reputation', status: health?.services?.virustotal === 'ok' ? 'Configured' : 'Optional' },
                  { name: 'Workers AI Synthesizer', desc: 'LLM evidence analysis & summary', status: health?.services?.ai === 'ok' ? 'Available' : 'Standby' },
                ].map((col, idx) => (
                  <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--space-2) 0', borderBottom: idx < 5 ? '1px solid var(--color-border)' : 'none' }}>
                    <div>
                      <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-dark)' }}>{col.name}</div>
                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>{col.desc}</div>
                    </div>
                    <span className="badge badge-success" style={{ fontSize: '10px' }}>{col.status}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="card" style={{ background: 'var(--color-surface-elevated)' }}>
            <div className="card-body" style={{ padding: 'var(--space-5)' }}>
              <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-start' }}>
                <ShieldAlert size={22} style={{ color: 'var(--color-accent)', flexShrink: 0, marginTop: 2 }} />
                <div>
                  <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-dark)' }}>
                    Ethical Reconnaissance Policy
                  </h3>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginTop: 'var(--space-1)', lineHeight: 1.5 }}>
                    OpenSpective only initiates passive public inquiries (DNS over HTTPS, Certificate Transparency, publicly published registry data). No port scans, no crawling, no intrusive exploitation.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
