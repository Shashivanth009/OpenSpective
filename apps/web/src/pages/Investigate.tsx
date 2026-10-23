import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Search, Shield, CheckCircle2, AlertCircle, Sparkles,
  Globe, Mail, User, Network, Building, Link2, ArrowRight, Phone, Coins
} from 'lucide-react';
import * as api from '../api.ts';

const MODULES_CONFIG = [
  { id: 'dns', name: 'DNS Intelligence', desc: 'A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records via 1.1.1.1 DoH', types: ['domain', 'email', 'url', 'organization'] },
  { id: 'rdap', name: 'RDAP / WHOIS', desc: 'Domain registrar, dates, RIR IP allocation data', types: ['domain', 'ip', 'email', 'url'] },
  { id: 'certificate_transparency', name: 'Certificate Transparency', desc: 'Historical & active SSL certificates, SAN subdomains from crt.sh', types: ['domain', 'email', 'url', 'organization'] },
  { id: 'ipinfo', name: 'IP Geolocation & ASN', desc: 'Country, city, ASN number, organization route mapping', types: ['ip', 'domain'] },
  { id: 'virustotal', name: 'VirusTotal Threat Intel', desc: 'Reputation analysis across 70+ threat intelligence engines (requires key)', types: ['domain', 'ip', 'url', 'email'] },
  { id: 'github', name: 'GitHub Public Intelligence', desc: 'Public repositories, contributors, code associations', types: ['organization', 'username', 'email', 'domain'] },
  { id: 'person_search', name: 'Public Person & Entity Search', desc: 'GitHub full name matches, Wikipedia articles, Wikidata knowledge graph, HackerNews mentions', types: ['person'] },
  { id: 'username_presence', name: 'Cross-Platform Username Footprint', desc: 'Verifies presence across GitHub, GitLab, HackerNews, PyPI, NPM, Keybase, DEV, and Hashnode', types: ['username', 'person'] },
  { id: 'email_identity', name: 'Email & Developer Attribution', desc: 'Discovers verified git commits, real author names, linked GitHub profiles, Gravatar accounts, and handle footprints', types: ['email'] },
  { id: 'url_metadata', name: 'URL Metadata & Headers', desc: 'HTTP response status, title, redirects, headers (single bounded request)', types: ['url'] },
  { id: 'web_archive', name: 'Wayback Machine Archive', desc: 'Internet Archive CDX snapshots, historical discovery dates, and archived endpoints', types: ['domain', 'url', 'organization'] },
  { id: 'tech_stack', name: 'Security Headers & Tech Stack', desc: 'Evaluates HSTS, CSP, X-Frame-Options, server headers, and CDN/WAF defenses', types: ['domain', 'url', 'organization'] },
  { id: 'crypto', name: 'Blockchain & Crypto Forensics', desc: 'Analyzes Bitcoin, Ethereum, Solana, and TRON wallet balances, activity, and transactions', types: ['crypto_wallet', 'person', 'username'] },
  { id: 'breach', name: 'Breach & Credential Exposure', desc: 'Checks targets against documented public breach datasets and credential exposure archives', types: ['email', 'domain', 'username'] },
  { id: 'location', name: 'Geolocation & Places Intelligence', desc: 'Geocodes physical locations, profiles, and commit timezone signatures into coordinates with OpenStreetMap and Google Maps links', types: ['person', 'email', 'username', 'organization', 'ip'] },
];

export default function InvestigatePage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialQuery = searchParams.get('q') || '';

  const [target, setTarget] = useState(initialQuery);
  const [targetType, setTargetType] = useState<string>('auto');
  const [selectedModules, setSelectedModules] = useState<string[]>([
    'dns', 'rdap', 'certificate_transparency', 'ipinfo', 'github', 'person_search', 'username_presence', 'email_identity', 'url_metadata', 'web_archive', 'tech_stack', 'crypto', 'breach', 'location'
  ]);
  const [enableAi, setEnableAi] = useState(true);
  const [loading, setLoading] = useState(false);
  const [classifying, setClassifying] = useState(false);
  const [classification, setClassification] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // Auto classify target on change
  useEffect(() => {
    if (!target.trim() || target.trim().length < 3) {
      setClassification(null);
      return;
    }

    const timer = setTimeout(async () => {
      setClassifying(true);
      try {
        const res = await api.classifyTarget(target.trim());
        setClassification(res);
        if (targetType === 'auto') {
          // Keep auto selection
        }
      } catch {
        // Silently fail classification
      } finally {
        setClassifying(false);
      }
    }, 400);

    return () => clearTimeout(timer);
  }, [target]);

  const activeTargetType = targetType === 'auto' ? (classification?.targetType || 'unknown') : targetType;

  const toggleModule = (modId: string) => {
    if (selectedModules.includes(modId)) {
      setSelectedModules(selectedModules.filter(m => m !== modId));
    } else {
      setSelectedModules([...selectedModules, modId]);
    }
  };

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setError(null);
    setLoading(true);

    try {
      const typeToSend = targetType === 'auto' ? undefined : targetType;
      const res = await api.createInvestigation(
        target.trim(),
        typeToSend,
        selectedModules,
        enableAi
      );
      navigate(`/investigations/${res.investigation.id}`);
    } catch (err: any) {
      setError(err?.message || 'Failed to start investigation. Please verify inputs.');
      setLoading(false);
    }
  };

  const getTargetIcon = (type: string) => {
    switch (type) {
      case 'domain': return <Globe size={16} />;
      case 'ip': return <Network size={16} />;
      case 'email': return <Mail size={16} />;
      case 'username': return <User size={16} />;
      case 'person': return <User size={16} />;
      case 'organization': return <Building size={16} />;
      case 'url': return <Link2 size={16} />;
      case 'phone': return <Phone size={16} />;
      case 'crypto_wallet': return <Coins size={16} />;
      default: return <Search size={16} />;
    }
  };

  return (
    <div style={{ maxWidth: '980px', margin: '0 auto', padding: 'var(--space-6) var(--space-8)' }}>
      <div style={{ marginBottom: 'var(--space-8)' }}>
        <h1 style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, color: 'var(--color-dark)', letterSpacing: '-0.03em' }}>
          New Passive Reconnaissance
        </h1>
        <p style={{ color: 'var(--color-text-secondary)', marginTop: 'var(--space-2)', fontSize: 'var(--text-base)' }}>
          Provide any digital identifier to run non-intrusive public intelligence correlation.
        </p>
      </div>

      {error && (
        <div className="alert alert-error" style={{ marginBottom: 'var(--space-6)' }}>
          <AlertCircle size={18} />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleLaunch}>
        {/* Step 1: Target Input */}
        <div className="card" style={{ marginBottom: 'var(--space-6)', padding: 'var(--space-6)' }}>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginBottom: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Search size={20} style={{ color: 'var(--color-accent)' }} /> 1. Reconnaissance Target
          </h2>

          <div className="input-wrapper" style={{ marginBottom: 'var(--space-4)' }}>
            <label htmlFor="targetInput" className="input-label">Target Identifier</label>
            <div style={{ position: 'relative' }}>
              <input
                id="targetInput"
                type="text"
                required
                className="input"
                style={{ paddingLeft: '44px', fontSize: 'var(--text-base)', height: '48px' }}
                placeholder="e.g. cloudflare.com, 1.1.1.1, user@proton.me, github-org, https://..."
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
              <div style={{ position: 'absolute', left: '16px', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }}>
                {classifying ? <span className="spinner" style={{ width: 16, height: 16 }} /> : getTargetIcon(activeTargetType)}
              </div>
            </div>
          </div>

          {/* Classification hint badge */}
          {classification && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-3)',
              padding: 'var(--space-3) var(--space-4)',
              background: 'var(--color-bg)',
              borderRadius: 'var(--radius)',
              fontSize: 'var(--text-sm)',
              color: 'var(--color-dark)',
              border: '1px solid var(--color-border)',
            }}>
              <CheckCircle2 size={16} style={{ color: 'var(--color-accent)' }} />
              <div>
                Detected as: <strong style={{ textTransform: 'capitalize' }}>{classification.targetType}</strong> ({classification.confidence} confidence)
                {classification.normalizedTarget && (
                  <span style={{ color: 'var(--color-text-secondary)', marginLeft: '8px' }}>
                    Normalized: <code>{classification.normalizedTarget}</code>
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Explicit Target Type Override */}
          <div style={{ marginTop: 'var(--space-5)' }}>
            <label className="input-label" style={{ marginBottom: 'var(--space-2)' }}>Override Target Type (optional)</label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
              {['auto', 'domain', 'ip', 'email', 'username', 'person', 'organization', 'url', 'phone', 'crypto_wallet'].map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTargetType(t)}
                  className={`btn btn-sm ${targetType === t ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ textTransform: 'capitalize' }}
                >
                  {t === 'auto' ? '✨ Auto-Detect' : t.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Step 2: Collector Selection */}
        <div className="card" style={{ marginBottom: 'var(--space-6)', padding: 'var(--space-6)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-4)' }}>
            <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <Shield size={20} style={{ color: 'var(--color-accent)' }} /> 2. Intelligence Collectors
            </h2>
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setSelectedModules(MODULES_CONFIG.map(m => m.id))}
              >
                Select All
              </button>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setSelectedModules([])}
              >
                Clear
              </button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 'var(--space-3)' }}>
            {MODULES_CONFIG.map((mod) => {
              const isSelected = selectedModules.includes(mod.id);
              const isApplicable = activeTargetType === 'unknown' || activeTargetType === 'auto' || mod.types.includes(activeTargetType);

              return (
                <div
                  key={mod.id}
                  onClick={() => toggleModule(mod.id)}
                  style={{
                    padding: 'var(--space-4)',
                    borderRadius: 'var(--radius)',
                    border: `1.5px solid ${isSelected ? 'var(--color-accent)' : 'var(--color-border)'}`,
                    background: isSelected ? 'var(--color-bg-secondary)' : 'var(--color-surface)',
                    cursor: 'pointer',
                    transition: 'all var(--transition-fast)',
                    opacity: isApplicable ? 1 : 0.6,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-1)' }}>
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => {}} // handled by parent div
                      style={{ accentColor: 'var(--color-accent)' }}
                    />
                    <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--color-dark)' }}>{mod.name}</strong>
                  </div>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', margin: 0, paddingLeft: '22px' }}>
                    {mod.desc}
                  </p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Step 3: AI Synthesis Option */}
        <div className="card" style={{ marginBottom: 'var(--space-8)', padding: 'var(--space-5)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center' }}>
              <Sparkles size={22} style={{ color: 'var(--color-accent)' }} />
              <div>
                <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--color-dark)' }}>
                  Cloudflare Workers AI Correlation & Synthesis
                </strong>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', margin: 0 }}>
                  Automatically analyze findings, detect anomalous DNS configurations, and summarize operational posture with strictly evidence-grounded insights.
                </p>
              </div>
            </div>
            <label style={{ position: 'relative', display: 'inline-flex', alignItems: 'center', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={enableAi}
                onChange={(e) => setEnableAi(e.target.checked)}
                style={{ width: '20px', height: '20px', accentColor: 'var(--color-accent)' }}
              />
            </label>
          </div>
        </div>

        {/* Submit Button */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-4)' }}>
          <button
            type="submit"
            className="btn btn-primary btn-lg"
            disabled={loading || !target.trim()}
            style={{ minWidth: '220px', justifyContent: 'center' }}
          >
            {loading ? (
              <>
                <span className="spinner" />
                Initializing Engines...
              </>
            ) : (
              <>
                <Search size={18} />
                Execute Investigation
                <ArrowRight size={18} />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
