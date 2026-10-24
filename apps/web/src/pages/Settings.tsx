import { useState, useEffect } from 'react';
import {
  User, Key, Shield, Moon, Sun, Check, Eye, EyeOff, Save,
  Sliders, Database, Trash2, Sparkles, ExternalLink
} from 'lucide-react';
import * as api from '../api.ts';

export default function SettingsPage() {
  const [usage, setUsage] = useState<any>(null);
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Appearance
  const [theme, setTheme] = useState<'light' | 'dark'>(() =>
    (localStorage.getItem('os_theme') as 'light' | 'dark') ?? 'light'
  );

  // Custom API Keys
  const [apiKeys, setApiKeys] = useState<api.CustomApiKeys>(() => api.getCustomApiKeys());
  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({});

  // Engine Preferences
  const [defaultTargetType, setDefaultTargetType] = useState<string>(() =>
    localStorage.getItem('os_pref_target_type') || 'auto'
  );
  const [autoAiSynthesis, setAutoAiSynthesis] = useState<boolean>(() =>
    localStorage.getItem('os_pref_ai_auto') === 'true'
  );
  const [defaultGraphLayout, setDefaultGraphLayout] = useState<string>(() =>
    localStorage.getItem('os_pref_graph_layout') || 'clustered'
  );

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const toggleTheme = (newTheme: 'light' | 'dark') => {
    setTheme(newTheme);
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('os_theme', newTheme);
    showToast(`Interface switched to ${newTheme === 'dark' ? 'Cyber Dark' : 'Nature Light'} mode.`);
  };

  const toggleShowKey = (id: string) => {
    setShowKeys(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleKeyChange = (keyName: keyof api.CustomApiKeys, value: string) => {
    setApiKeys(prev => ({ ...prev, [keyName]: value.trim() }));
  };

  const handleSaveKeys = (e: React.FormEvent) => {
    e.preventDefault();
    api.saveCustomApiKeys(apiKeys);
    showToast('✓ Custom API credentials successfully updated & saved locally!');
  };

  const handleSavePreferences = () => {
    localStorage.setItem('os_pref_target_type', defaultTargetType);
    localStorage.setItem('os_pref_ai_auto', String(autoAiSynthesis));
    localStorage.setItem('os_pref_graph_layout', defaultGraphLayout);
    showToast('✓ Reconnaissance engine defaults updated.');
  };

  const handleClearCache = () => {
    if (window.confirm('Clear all locally cached investigation settings, preferences, and keys?')) {
      localStorage.removeItem('os_api_keys');
      localStorage.removeItem('os_pref_target_type');
      localStorage.removeItem('os_pref_ai_auto');
      localStorage.removeItem('os_pref_graph_layout');
      setApiKeys({});
      setDefaultTargetType('auto');
      setAutoAiSynthesis(false);
      setDefaultGraphLayout('clustered');
      showToast('Local application cache and credentials cleared.');
    }
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
      <div style={{ maxWidth: '1000px', margin: '0 auto', padding: 'var(--space-12)', textAlign: 'center' }}>
        <div className="spinner" style={{ margin: '0 auto var(--space-4)' }} />
        <p style={{ color: 'var(--color-text-secondary)' }}>Loading platform configuration and service health...</p>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '1040px', margin: '0 auto', padding: 'var(--space-6) var(--space-8)' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 'var(--space-8)', flexWrap: 'wrap', gap: 'var(--space-4)' }}>
        <div>
          <h1 style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, color: 'var(--color-dark)', letterSpacing: '-0.03em' }}>
            Platform Settings & Control Center
          </h1>
          <p style={{ color: 'var(--color-text-secondary)', marginTop: 'var(--space-1)', fontSize: 'var(--text-base)' }}>
            Configure your external intelligence API keys, automated synthesis parameters, and system aesthetics.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <span className="badge badge-success" style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 12px' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981' }} />
            System Operational
          </span>
        </div>
      </div>

      {/* Floating Toast */}
      {toastMessage && (
        <div style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          background: 'rgba(16, 185, 129, 0.95)',
          color: '#ffffff',
          padding: '12px 20px',
          borderRadius: 'var(--radius-lg)',
          boxShadow: '0 8px 30px rgba(0,0,0,0.3)',
          zIndex: 9999,
          fontSize: '13px',
          fontWeight: 600,
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          backdropFilter: 'blur(8px)',
        }}>
          <Check size={18} /> {toastMessage}
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
        {/* Profile & Node Status */}
        <div className="card" style={{ padding: 'var(--space-6)' }}>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginBottom: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <User size={20} style={{ color: 'var(--color-accent)' }} /> Access Mode & Node Telemetry
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 'var(--space-4)' }}>
            <div style={{ padding: 'var(--space-4)', borderRadius: 'var(--radius)', background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)' }}>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Operational Mode</div>
              <div style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-dark)', marginTop: 4 }}>
                100% Free & Open Access
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-success)', marginTop: 2 }}>Public Community Node (No Paywall)</div>
            </div>

            <div style={{ padding: 'var(--space-4)', borderRadius: 'var(--radius)', background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)' }}>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Worker Engine Version</div>
              <div style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-dark)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
                {health?.version ?? 'v0.1.0-alpha'}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-info)', marginTop: 2 }}>High-Concurrency Microservices</div>
            </div>

            <div style={{ padding: 'var(--space-4)', borderRadius: 'var(--radius)', background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)' }}>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Integrated OSINT Engines</div>
              <div style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-accent)', marginTop: 4 }}>
                173+ Active Collectors
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-text-secondary)', marginTop: 2 }}>DNS, RDAP, CT, Shodan, Social, Crypto, Dorks</div>
            </div>
          </div>
        </div>

        {/* API Credentials Configuration */}
        <div className="card" style={{ padding: 'var(--space-6)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
            <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <Key size={20} style={{ color: 'var(--color-accent)' }} /> External Intelligence Providers & API Keys
            </h2>
          </div>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginBottom: 'var(--space-5)' }}>
            Enter your custom API tokens below to automatically unlock premium quotas and direct queries for VirusTotal, Shodan, IPInfo, GitHub, and HaveIBeenPwned. Keys are stored locally in your browser and seamlessly attached to background scans.
          </p>

          <form onSubmit={handleSaveKeys}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              {[
                {
                  id: 'virustotal',
                  envName: 'VIRUSTOTAL_API_KEY',
                  label: 'VirusTotal Threat Intelligence',
                  placeholder: 'e.g. 8f4a1b2c3d...',
                  desc: 'Unlocks malware scanning, AV verdicts, and threat reputation feeds.',
                  docUrl: 'https://www.virustotal.com/gui/user/username/apikey',
                },
                {
                  id: 'shodan',
                  envName: 'SHODAN_API_KEY',
                  label: 'Shodan Internet Intelligence',
                  placeholder: 'e.g. 21B8eF4... (Free or Member key)',
                  desc: 'Queries open ports, banners, vulnerabilities (CVEs), and exposed industrial IoT.',
                  docUrl: 'https://account.shodan.io',
                },
                {
                  id: 'ipinfo',
                  envName: 'IPINFO_TOKEN',
                  label: 'IPInfo Geolocation Token',
                  placeholder: 'e.g. 1a2b3c4d5e6f7g',
                  desc: 'Expands monthly IP geolocation, ASN routing, and ISP carrier attribution limit.',
                  docUrl: 'https://ipinfo.io/account/token',
                },
                {
                  id: 'github',
                  envName: 'GITHUB_TOKEN',
                  label: 'GitHub Personal Access Token (PAT)',
                  placeholder: 'ghp_...',
                  desc: 'Elevates public account, commit email, repository, and SSH key searches to 5,000 req/hr.',
                  docUrl: 'https://github.com/settings/tokens',
                },
                {
                  id: 'haveibeenpwned',
                  envName: 'HAVE_I_BEEN_PWNED_API_KEY',
                  label: 'HaveIBeenPwned API Key',
                  placeholder: 'e.g. 3a9c7b...',
                  desc: 'Enables breach database lookups and compromised credential monitoring.',
                  docUrl: 'https://haveibeenpwned.com/API/Key',
                },
              ].map((provider) => {
                const val = (apiKeys as any)[provider.id] || '';
                const isEnvActive = health?.services?.[provider.id] === 'ok';
                const isCustomActive = !!val;
                const isVisible = !!showKeys[provider.id];

                return (
                  <div
                    key={provider.id}
                    style={{
                      padding: 'var(--space-4)',
                      borderRadius: 'var(--radius)',
                      border: '1px solid var(--color-border)',
                      background: 'var(--color-surface)',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
                      <div>
                        <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--color-dark)' }}>{provider.label}</strong>
                        <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginLeft: 'var(--space-2)', fontFamily: 'var(--font-mono)' }}>
                          ({provider.envName})
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                        {isCustomActive ? (
                          <span className="badge badge-success" style={{ fontSize: '11px' }}>Custom Key Saved</span>
                        ) : isEnvActive ? (
                          <span className="badge badge-info" style={{ fontSize: '11px' }}>Active (Backend Env)</span>
                        ) : (
                          <span className="badge badge-neutral" style={{ fontSize: '11px' }}>Unset (Optional)</span>
                        )}
                        <a
                          href={provider.docUrl}
                          target="_blank"
                          rel="noreferrer"
                          style={{ color: 'var(--color-text-muted)', display: 'flex', alignItems: 'center' }}
                          title="Get API Key"
                        >
                          <ExternalLink size={13} />
                        </a>
                      </div>
                    </div>

                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginBottom: 'var(--space-3)' }}>
                      {provider.desc}
                    </div>

                    <div style={{ display: 'flex', gap: 'var(--space-2)', position: 'relative' }}>
                      <input
                        type={isVisible ? 'text' : 'password'}
                        className="input input-sm"
                        placeholder={provider.placeholder}
                        value={val}
                        onChange={(e) => handleKeyChange(provider.id as any, e.target.value)}
                        style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', flex: 1 }}
                      />
                      <button
                        type="button"
                        onClick={() => toggleShowKey(provider.id)}
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '4px 10px' }}
                        title={isVisible ? 'Hide token' : 'Show token'}
                      >
                        {isVisible ? <EyeOff size={15} /> : <Eye size={15} />}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>

            <div style={{ marginTop: 'var(--space-5)', display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-3)' }}>
              <button type="submit" className="btn btn-primary">
                <Save size={16} /> Save API Credentials
              </button>
            </div>
          </form>
        </div>

        {/* Engine Defaults & Automation */}
        <div className="card" style={{ padding: 'var(--space-6)' }}>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginBottom: 'var(--space-2)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Sliders size={20} style={{ color: 'var(--color-accent)' }} /> Reconnaissance Defaults & Automation
          </h2>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginBottom: 'var(--space-4)' }}>
            Customize how new targets are handled upon clicking "Launch Deep Investigation".
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 'var(--space-4)', marginBottom: 'var(--space-4)' }}>
            <div>
              <label className="input-label">Default Target Classification</label>
              <select
                className="input input-sm"
                value={defaultTargetType}
                onChange={(e) => setDefaultTargetType(e.target.value)}
              >
                <option value="auto">Auto-Detect (Smart Heuristics)</option>
                <option value="domain">Domain / Hostname</option>
                <option value="ip">IPv4 / IPv6 Address</option>
                <option value="username">Username / Social Handle</option>
                <option value="email">Email Address</option>
                <option value="person">Full Name / Person</option>
                <option value="phone">Phone Number (E.164)</option>
              </select>
            </div>

            <div>
              <label className="input-label">Default Knowledge Graph Layout</label>
              <select
                className="input input-sm"
                value={defaultGraphLayout}
                onChange={(e) => setDefaultGraphLayout(e.target.value)}
              >
                <option value="clustered">Clustered by Entity Type</option>
                <option value="radial">Radial Hub-and-Spoke</option>
                <option value="hierarchy">Topological Hierarchy</option>
                <option value="grid">Structured Matrix Grid</option>
              </select>
            </div>
          </div>

          <div style={{ padding: 'var(--space-3) var(--space-4)', background: 'var(--color-surface-elevated)', borderRadius: 'var(--radius)', border: '1px solid var(--color-border)', marginBottom: 'var(--space-4)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--color-dark)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Sparkles size={15} style={{ color: 'var(--color-accent)' }} /> Automated AI Synthesis
              </strong>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginTop: 2 }}>
                Automatically synthesize intelligence report and risk verdict as soon as collectors finish.
              </div>
            </div>
            <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={autoAiSynthesis}
                onChange={(e) => setAutoAiSynthesis(e.target.checked)}
                style={{ width: 18, height: 18, cursor: 'pointer', accentColor: 'var(--color-accent)' }}
              />
            </label>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button type="button" onClick={handleSavePreferences} className="btn btn-secondary btn-sm">
              <Save size={14} /> Update Defaults
            </button>
          </div>
        </div>

        {/* Appearance & Themes */}
        <div className="card" style={{ padding: 'var(--space-6)' }}>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginBottom: 'var(--space-2)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Sun size={20} style={{ color: 'var(--color-accent)' }} /> Appearance & Interface
          </h2>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginBottom: 'var(--space-4)' }}>
            Choose between the signature Nature Emerald light palette and high-contrast Cyber Dark mode.
          </p>
          <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
            <button
              onClick={() => toggleTheme('light')}
              className={`btn ${theme === 'light' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '10px 18px', display: 'flex', alignItems: 'center', gap: '8px' }}
            >
              <Sun size={17} /> Nature Light Mode
            </button>
            <button
              onClick={() => toggleTheme('dark')}
              className={`btn ${theme === 'dark' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '10px 18px', display: 'flex', alignItems: 'center', gap: '8px' }}
            >
              <Moon size={17} /> Cyber Dark Mode
            </button>
          </div>
        </div>

        {/* Operational Rate Limits */}
        <div className="card" style={{ padding: 'var(--space-6)' }}>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginBottom: 'var(--space-2)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Shield size={20} style={{ color: 'var(--color-accent)' }} /> Infrastructure Quotas & Rate Limits
          </h2>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginBottom: 'var(--space-4)' }}>
            Rate limits ensure compliance with public DNS, RDAP, and CT provider terms of service.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 'var(--space-4)' }}>
            <div style={{ padding: 'var(--space-4)', borderRadius: 'var(--radius)', background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)' }}>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Investigations / Hour</div>
              <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: 'var(--color-dark)', marginTop: 'var(--space-1)' }}>
                {usage?.limits?.investigations ? `${usage.used?.investigations ?? 0} / ${usage.limits.investigations}` : '60 req/hr'}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-success)', marginTop: 'var(--space-1)' }}>
                {usage?.remaining?.investigations !== undefined ? `${usage.remaining.investigations} remaining this hour` : 'Community Tier'}
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
                Adaptive
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-info)', marginTop: 'var(--space-1)' }}>Polite Concurrency Queue</div>
            </div>
          </div>
        </div>

        {/* Cache & Local Data Maintenance */}
        <div className="card" style={{ padding: 'var(--space-6)', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginBottom: 'var(--space-2)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)', color: 'var(--color-dark)' }}>
            <Database size={20} style={{ color: '#ef4444' }} /> Local Storage & Data Maintenance
          </h2>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginBottom: 'var(--space-4)' }}>
            Reset stored API keys, layout preferences, and UI session state.
          </p>

          <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
            <button
              onClick={handleClearCache}
              className="btn btn-ghost btn-sm"
              style={{ color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.3)' }}
            >
              <Trash2 size={15} /> Reset Local Preferences & Stored Keys
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
