import { useState, useEffect } from 'react';
import { User, Key, Shield, Moon, Sun } from 'lucide-react';
import * as api from '../api.ts';

export default function SettingsPage() {
  const [usage, setUsage] = useState<any>(null);
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [theme, setTheme] = useState<'light' | 'dark'>(() =>
    (localStorage.getItem('os_theme') as 'light' | 'dark') ?? 'light'
  );

  const toggleTheme = (newTheme: 'light' | 'dark') => {
    setTheme(newTheme);
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('os_theme', newTheme);
  };

  useEffect(() => {
    async function loadData() {
      try {
        const [usageData, healthData] = await Promise.allSettled([
          api.getUsage(),
          api.getHealth(),
        ]);
        if (usageData.status === 'fulfilled') setUsage(usageData.value);
        if (healthData.status === 'fulfilled') setHealth(healthData.value);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  if (loading) {
    return (
      <div style={{ maxWidth: '980px', margin: '0 auto', padding: 'var(--space-12)', textAlign: 'center' }}>
        <div className="spinner" style={{ margin: '0 auto var(--space-4)' }} />
        <p style={{ color: 'var(--color-text-secondary)' }}>Loading configuration & telemetry...</p>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '980px', margin: '0 auto', padding: 'var(--space-6) var(--space-8)' }}>
      <div style={{ marginBottom: 'var(--space-8)' }}>
        <h1 style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, color: 'var(--color-dark)', letterSpacing: '-0.03em' }}>
          Platform Settings
        </h1>
        <p style={{ color: 'var(--color-text-secondary)', marginTop: 'var(--space-1)', fontSize: 'var(--text-base)' }}>
          Manage your account profile, intelligence provider credentials, and preferences.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
        {/* Profile Card */}
        <div className="card" style={{ padding: 'var(--space-6)' }}>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginBottom: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <User size={20} style={{ color: 'var(--color-accent)' }} /> Access & Profile
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 'var(--space-4)' }}>
            <div>
              <label className="input-label">Access Mode</label>
              <input type="text" className="input" disabled value="100% Free & Open Access" />
            </div>

            <div>
              <label className="input-label">Authentication Status</label>
              <input type="text" className="input" disabled value="Public Access (No Sign-in Required)" />
            </div>

            <div>
              <label className="input-label">Platform Edition</label>
              <input type="text" className="input" disabled value="Community Open Edition" style={{ fontFamily: 'var(--font-mono)' }} />
            </div>
          </div>
        </div>

        {/* Rate Limits & Usage */}
        <div className="card" style={{ padding: 'var(--space-6)' }}>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginBottom: 'var(--space-2)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Shield size={20} style={{ color: 'var(--color-accent)' }} /> Operational Rate Limits
          </h2>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginBottom: 'var(--space-4)' }}>
            Rate limits ensure compliance with public DNS, RDAP, and CT provider terms of service.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 'var(--space-4)' }}>
            <div style={{ padding: 'var(--space-4)', borderRadius: 'var(--radius)', background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)' }}>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Investigations / Hour</div>
              <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: 'var(--color-dark)', marginTop: 'var(--space-1)' }}>
                {usage?.count !== undefined ? `${usage.count} / ${usage.limit ?? 60} req` : '60 req/hr'}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-success)', marginTop: 'var(--space-1)' }}>
                {usage?.remaining !== undefined ? `${usage.remaining} remaining` : 'Standard Tier'}
              </div>
            </div>

            <div style={{ padding: 'var(--space-4)', borderRadius: 'var(--radius)', background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)' }}>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Cloudflare 1.1.1.1 DoH</div>
              <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: 'var(--color-dark)', marginTop: 'var(--space-1)' }}>
                Unlimited
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-success)', marginTop: 'var(--space-1)' }}>Public Anycast</div>
            </div>

            <div style={{ padding: 'var(--space-4)', borderRadius: 'var(--radius)', background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)' }}>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>crt.sh CT Logs</div>
              <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: 'var(--color-dark)', marginTop: 'var(--space-1)' }}>
                Bounded (4 req/m)
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-info)', marginTop: 'var(--space-1)' }}>Polite queue</div>
            </div>
          </div>
        </div>

        {/* API Credentials Configuration */}
        <div className="card" style={{ padding: 'var(--space-6)' }}>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginBottom: 'var(--space-2)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Key size={20} style={{ color: 'var(--color-accent)' }} /> External Intelligence Providers
          </h2>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginBottom: 'var(--space-4)' }}>
            Cloudflare Worker secrets can be bound securely using Wrangler environment variables.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {[
              { key: 'VIRUSTOTAL_API_KEY', name: 'VirusTotal Threat Intelligence', configured: health?.services?.virustotal === 'ok', desc: 'Provides vendor reputation and malicious verdict aggregation.' },
              { key: 'IPINFO_TOKEN', name: 'IPInfo Geolocation Token', configured: health?.services?.ipinfo === 'ok', desc: 'Increases monthly geolocation and ASN quota from 50k to paid tiers.' },
              { key: 'GITHUB_TOKEN', name: 'GitHub Personal Access Token', configured: health?.services?.github === 'ok', desc: 'Elevates public repository and account search from 60 req/hr to 5,000 req/hr.' },
              { key: 'HAVE_I_BEEN_PWNED_API_KEY', name: 'HaveIBeenPwned API Key', configured: health?.services?.haveibeenpwned === 'ok', desc: 'Permits non-intrusive breach notification lookups for domain/email targets.' },
            ].map(item => (
              <div key={item.key} style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: 'var(--space-3) var(--space-4)',
                borderRadius: 'var(--radius)',
                border: '1px solid var(--color-border)',
                background: 'var(--color-surface)',
              }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--color-dark)' }}>{item.name}</strong>
                    <code>{item.key}</code>
                  </div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginTop: 2 }}>{item.desc}</div>
                </div>
                <span className={`badge ${item.configured ? 'badge-success' : 'badge-neutral'}`}>
                  {item.configured ? 'Active' : 'Unset'}
                </span>
              </div>
            ))}
          </div>

          <div style={{ marginTop: 'var(--space-4)', padding: 'var(--space-4)', background: 'var(--color-bg)', borderRadius: 'var(--radius)', fontSize: 'var(--text-xs)', color: 'var(--color-dark)' }}>
            💡 To configure secrets in production, run:
            <pre style={{ margin: 'var(--space-2) 0 0', padding: 'var(--space-2)', background: 'var(--color-surface)', borderRadius: 'var(--radius)', fontFamily: 'var(--font-mono)' }}>
              npx wrangler secret put VIRUSTOTAL_API_KEY
            </pre>
          </div>
        </div>

        {/* Appearance & Interface */}
        <div className="card" style={{ padding: 'var(--space-6)' }}>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginBottom: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Sun size={20} style={{ color: 'var(--color-accent)' }} /> Appearance
          </h2>
          <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
            <button
              onClick={() => toggleTheme('light')}
              className={`btn ${theme === 'light' ? 'btn-primary' : 'btn-secondary'}`}
            >
              <Sun size={16} /> Nature Light
            </button>
            <button
              onClick={() => toggleTheme('dark')}
              className={`btn ${theme === 'dark' ? 'btn-primary' : 'btn-secondary'}`}
            >
              <Moon size={16} /> Cyber Dark
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
