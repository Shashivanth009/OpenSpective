import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Search, Shield, CheckCircle2, AlertCircle, Sparkles,
  Globe, Mail, User, Network, Building, Link2, ArrowRight, Phone, Coins
} from 'lucide-react';
import * as api from '../api.ts';

const MODULES_CONFIG = [
  { id: 'certificate_transparency', name: 'Subfinder & crt.sh (Subdomains)', desc: 'Discovers active subdomains, root domains, and historical SSL/TLS certificates via crt.sh CT log streams', types: ['domain', 'email', 'url', 'organization'] },
  { id: 'username_presence', name: 'Sherlock & WhatsMyName (Profiles)', desc: 'Performs zero-false-positive profile verification across GitHub, GitLab, DockerHub, NPM, Keybase, HackerNews, Mastodon, and 15+ registries', types: ['username', 'person'] },
  { id: 'email_identity', name: 'theHarvester & Hunter (Email Recon)', desc: 'Discovers verified git commits, real author names, linked GitHub profiles, Gravatar accounts, and handle footprints', types: ['email'] },
  { id: 'tech_stack', name: 'Wappalyzer & BuiltWith (Tech Stack)', desc: 'Audits HTTP security hygiene (HSTS, CSP, X-Frame-Options) and detects web servers & CDN/WAF defenses', types: ['domain', 'url', 'organization'] },
  { id: 'web_archive', name: 'Waybackurls & GAU (Historical Archives)', desc: 'Searches Internet Archive CDX index for historical snapshots, first-seen timestamps, and archived endpoints', types: ['domain', 'url', 'organization'] },
  { id: 'shodan', name: 'Shodan & Censys (Ports & CVEs)', desc: 'Passively maps open network ports, detected software CPEs, and known CVE vulnerabilities without active socket probing', types: ['ip', 'domain'] },
  { id: 'dns_security', name: 'SecurityHeaders & Defensive DNS Hygiene', desc: 'Audits SPF, DMARC, BIMI, MTA-STS, TLS-RPT, and DNSSEC defenses and grades domain spoofability', types: ['domain', 'email', 'organization'] },
  { id: 'threat_intel', name: 'Abuse.ch URLhaus & ThreatFox (Threat IOCs)', desc: 'Queries live abuse databases for malware distribution payloads, malicious host reputation, and botnet command & control indicators', types: ['domain', 'ip', 'url', 'organization'] },
  { id: 'cloud_storage', name: 'S3Scanner & CloudEnum (Cloud Buckets)', desc: 'Enumerates storage bucket naming permutations across Amazon Web Services S3, Google Cloud Storage, and Azure Blobs', types: ['domain', 'organization', 'url'] },
  { id: 'search_dorks', name: 'Google Dorks & Search Intelligence', desc: 'Compiles and checks targeted search queries across Google, GitHub Code, Shodan, Censys, FOFA, and Pastebin', types: ['domain', 'ip', 'email', 'username', 'url', 'organization', 'person', 'phone'] },
  { id: 'pgp_keys', name: 'Ubuntu PGP Public Keyserver', desc: 'Queries Ubuntu / SKS PGP keyservers for cryptographic public keys, email identities, and creation timestamps', types: ['email', 'person', 'username', 'organization', 'domain'] },
  { id: 'dns', name: 'Authoritative DNS (Cloudflare DoH)', desc: 'Retrieves authoritative DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA) using Cloudflare DNS over HTTPS', types: ['domain', 'email', 'url', 'organization'] },
  { id: 'rdap', name: 'RDAP & WHOIS (IANA / Verisign)', desc: 'Retrieves authoritative domain and IP registration data from ICANN RDAP and regional internet registries', types: ['domain', 'ip', 'email', 'url'] },
  { id: 'ipinfo', name: 'IPinfo Geolocation & ASN Mapping', desc: 'Retrieves public IP geolocation, autonomous system numbers (ASN), carrier, and organization route mapping', types: ['ip', 'domain'] },
  { id: 'github', name: 'GitHub Public Repos & Code Leaks', desc: 'Searches public GitHub repositories, code commits, contributors, and organizational structures', types: ['organization', 'username', 'email', 'domain'] },
  { id: 'breach', name: 'Have I Been Pwned & Breach Records', desc: 'Checks targets against documented public breach datasets and credential exposure archives', types: ['email', 'domain', 'username'] },
  { id: 'location', name: 'Bellingcat & OpenStreetMap (GEOINT)', desc: 'Geocodes physical locations, profiles, and commit timezone signatures into coordinates with OpenStreetMap and Google Maps links', types: ['person', 'email', 'username', 'organization', 'ip'] },
  { id: 'phone', name: 'PhoneInfoga & Telephony Intelligence', desc: 'Analyzes international ITU-T E.164 dialing plans, telecom region, line type (mobile/fixed/toll-free), and OSINT search pivots', types: ['phone'] },
  { id: 'crypto', name: 'Blockchain & Crypto Forensics', desc: 'Analyzes Bitcoin, Ethereum, Solana, and TRON wallet balances, activity, and transactions', types: ['crypto_wallet', 'person', 'username'] },
  { id: 'virustotal', name: 'VirusTotal Threat Intel', desc: 'Reputation analysis across 70+ threat intelligence engines (requires key)', types: ['domain', 'ip', 'url', 'email'] },
  { id: 'person_search', name: 'Public Person & Entity Search', desc: 'GitHub full name matches, Wikipedia articles, Wikidata knowledge graph, HackerNews mentions', types: ['person'] },
  { id: 'osint_framework', name: 'OSINT Framework 110+ Toolkit Suite', desc: 'Executes cross-engine public intelligence pivots, PGP keys, S3 cloud enumeration, Abuse.ch, and public records', types: ['domain', 'ip', 'email', 'username', 'url', 'organization', 'person', 'phone'] },
];

export default function InvestigatePage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialQuery = searchParams.get('q') || searchParams.get('target') || '';
  const initialType = searchParams.get('type') || 'auto';
  const initialModule = searchParams.get('module');

  const [target, setTarget] = useState(initialQuery);
  const [targetType, setTargetType] = useState<string>(initialType);
  const [selectedModules, setSelectedModules] = useState<string[]>(() => {
    const all = [
      'certificate_transparency', 'username_presence', 'email_identity', 'tech_stack',
      'web_archive', 'shodan', 'dns_security', 'threat_intel', 'cloud_storage',
      'search_dorks', 'pgp_keys', 'dns', 'rdap', 'ipinfo', 'github', 'breach', 'location', 'phone', 'crypto', 'person_search', 'osint_framework'
    ];
    if (initialModule && all.includes(initialModule)) {
      return all;
    }
    return all;
  });
  const [enableAi, setEnableAi] = useState(true);
  const [loading, setLoading] = useState(false);
  const [launchProgress, setLaunchProgress] = useState(0);
  const [launchStepText, setLaunchStepText] = useState('');
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
    setLaunchProgress(15);
    setLaunchStepText('Classifying target & assembling selected OSINT engines...');

    const interval = setInterval(() => {
      setLaunchProgress((prev) => {
        if (prev < 40) return prev + 12;
        if (prev < 80) return prev + 8;
        if (prev < 95) return prev + 3;
        return prev;
      });
    }, 200);

    try {
      const typeToSend = targetType === 'auto' ? undefined : targetType;
      setLaunchStepText(`Dispatching ${selectedModules.length} intelligence collectors across edge network...`);
      const res = await api.createInvestigation(
        target.trim(),
        typeToSend,
        selectedModules,
        enableAi
      );
      setLaunchProgress(100);
      setLaunchStepText('Investigation queued successfully! Transferring to live telemetry...');
      clearInterval(interval);
      setTimeout(() => {
        navigate(`/investigations/${res.investigation.id}`);
      }, 350);
    } catch (err: any) {
      clearInterval(interval);
      setError(err?.message || 'Failed to start investigation. Please verify inputs.');
      setLoading(false);
      setLaunchProgress(0);
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

        {/* Live OSINT Engine Deployment Status Block Element */}
        {loading && (
          <div className="card" style={{
            marginBottom: 'var(--space-6)',
            padding: 'var(--space-6)',
            border: '2px solid var(--color-accent)',
            background: 'linear-gradient(135deg, rgba(37, 99, 235, 0.08) 0%, rgba(16, 185, 129, 0.05) 100%)',
            boxShadow: '0 0 24px rgba(37, 99, 235, 0.16)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-3)', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                <span className="spinner" style={{ width: 22, height: 22 }} />
                <div>
                  <strong style={{ fontSize: 'var(--text-base)', color: 'var(--color-dark)' }}>
                    Deploying OSINT Reconnaissance Engines
                  </strong>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginTop: '2px' }}>
                    {launchStepText}
                  </div>
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <span style={{ fontSize: '1.75rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: 'var(--color-accent)', lineHeight: 1 }}>
                  {launchProgress}%
                </span>
                <div style={{ fontSize: '10px', color: 'var(--color-text-muted)', fontWeight: 600 }}>
                  Deployment Status
                </div>
              </div>
            </div>

            <div style={{ width: '100%', height: '8px', background: 'var(--color-border)', borderRadius: '999px', overflow: 'hidden', marginBottom: 'var(--space-3)' }}>
              <div style={{
                height: '100%',
                width: `${launchProgress}%`,
                background: 'linear-gradient(90deg, #2563eb 0%, #3b82f6 50%, #10b981 100%)',
                borderRadius: '999px',
                transition: 'width 0.2s ease',
                boxShadow: '0 0 10px rgba(37, 99, 235, 0.4)'
              }} />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
              <span>Target: <strong>{target}</strong> ({activeTargetType})</span>
              <span><strong>{selectedModules.length}</strong> OSINT Engines Initialized</span>
            </div>
          </div>
        )}

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
                Initializing Engines ({launchProgress}%)...
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
