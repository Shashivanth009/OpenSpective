import { Link, useNavigate } from 'react-router-dom';
import {
  Search, Shield, Globe, Mail, User, Building, Phone,
  Network, Cpu, Brain, FileDown, ArrowRight,
  CheckCircle, AlertTriangle, Lock, Zap, Eye, Database
} from 'lucide-react';
import { useState } from 'react';
import * as api from '../api.ts';

const TARGET_TYPE_EXAMPLES = [
  { label: 'Domain', example: 'example.com', icon: Globe },
  { label: 'Email', example: 'analyst@example.com', icon: Mail },
  { label: 'Username', example: '@researcher', icon: User },
  { label: 'IP Address', example: '8.8.8.8', icon: Network },
  { label: 'Organization', example: 'Acme Corp', icon: Building },
  { label: 'Phone', example: '+12025551234', icon: Phone },
];

const FEATURES = [
  {
    icon: Globe,
    title: 'Universal Target Input',
    desc: 'Investigate domains, emails, usernames, IPs, URLs, people, organizations, or phone numbers — all from one interface.',
  },
  {
    icon: Database,
    title: 'Passive Reconnaissance',
    desc: 'DNS records, RDAP data, certificate transparency, IP intelligence, and threat feeds. No unauthorized access.',
  },
  {
    icon: Brain,
    title: 'Evidence-Grounded AI',
    desc: 'AI analysis powered by Cloudflare Workers AI, grounded strictly in collected evidence. No invented findings.',
  },
  {
    icon: Eye,
    title: 'Relationship Graphs',
    desc: 'Interactive entity graphs showing verified relationships between discovered assets, with source attribution on every edge.',
  },
  {
    icon: FileDown,
    title: 'Structured Reports',
    desc: 'Export investigations as JSON, CSV, or printable HTML with methodology notes, source references, and limitations.',
  },
  {
    icon: Shield,
    title: 'Security First',
    desc: 'SSRF protection, ownership enforcement, rate limiting, and no fabricated results. Built for responsible use.',
  },
];

const PRINCIPLES = [
  'Evidence before AI',
  'Real findings before dashboards',
  'Passive reconnaissance by default',
  'Honest reporting of uncertainty',
  'Privacy and responsible use',
  'Free-tier-first infrastructure',
];

export default function LandingPage() {
  const navigate = useNavigate();
  const [input, setInput] = useState('');
  const [classifying, setClassifying] = useState(false);
  const [classification, setClassification] = useState<null | { targetType: string; normalizedTarget: string; confidence: string; isAmbiguous: boolean; validationMessage: string | null }>(null);

  const handleInputChange = async (value: string) => {
    setInput(value);
    if (value.trim().length < 3) {
      setClassification(null);
      return;
    }

    // Debounce: classify after 500ms
    setClassifying(true);
    try {
      const result = await api.classifyTarget(value);
      setClassification(result);
    } catch {
      setClassification(null);
    } finally {
      setClassifying(false);
    }
  };

  const handleInvestigate = () => {
    if (!input.trim()) return;
    navigate(`/investigate?q=${encodeURIComponent(input.trim())}`);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleInvestigate();
  };

  return (
    <div>
      {/* Hero */}
      <section className="hero">
        <div className="hero-bg" />
        <div className="container" style={{ position: 'relative' }}>
          <div className="animate-fade-in">
            <div className="badge badge-accent" style={{ margin: '0 auto var(--space-6)', display: 'inline-flex' }}>
              <Zap size={12} /> Open Intelligence Platform · v0.1.0 MVP
            </div>

            <h1 className="hero-title">
              Open Intelligence.<br />
              <span className="gradient-text">Clearer Insights.</span>
            </h1>

            <p className="hero-tagline">
              AI-assisted OSINT and passive reconnaissance for domains, emails, IPs,
              usernames, organizations, and more — powered by public data sources.
            </p>

            {/* Main input */}
            <div style={{ margin: 'var(--space-10) auto 0', maxWidth: '800px' }}>
              <div className="investigate-input-wrapper">
                <input
                  type="text"
                  className="investigate-input"
                  placeholder="Enter a name, email, username, domain, IP address, URL, or organization..."
                  value={input}
                  onChange={e => handleInputChange(e.target.value)}
                  onKeyDown={handleKeyDown}
                  id="hero-search"
                  aria-label="Investigation target"
                  autoComplete="off"
                />
                <button
                  className="btn btn-primary btn-lg investigate-btn"
                  onClick={handleInvestigate}
                  disabled={!input.trim() || classifying}
                  id="hero-investigate-btn"
                >
                  <Search size={18} />
                  Investigate
                </button>
              </div>

              {/* Classification display */}
              {classification && !classifying && input.trim().length >= 3 && (
                <div style={{ marginTop: 'var(--space-3)', display: 'flex', justifyContent: 'center' }}>
                  <div className="classification-display">
                    <Cpu size={14} />
                    Detected: <strong>{classification.targetType}</strong>
                    {classification.isAmbiguous && (
                      <span style={{ color: 'var(--color-warning)', marginLeft: '8px' }}>
                        <AlertTriangle size={12} /> Ambiguous
                      </span>
                    )}
                    {classification.validationMessage && (
                      <span style={{ color: 'var(--color-warning)', fontSize: 'var(--text-xs)' }}>
                        {' '}{classification.validationMessage}
                      </span>
                    )}
                  </div>
                </div>
              )}
              {classifying && (
                <div style={{ marginTop: 'var(--space-3)', display: 'flex', justifyContent: 'center' }}>
                  <div className="classification-display">
                    <div className="spinner spinner-sm" /> Classifying...
                  </div>
                </div>
              )}

              {/* Example targets */}
              <div style={{ marginTop: 'var(--space-6)', display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', justifyContent: 'center' }}>
                {TARGET_TYPE_EXAMPLES.map(({ label, example, icon: Icon }) => (
                  <button
                    key={label}
                    className="badge badge-default"
                    style={{ cursor: 'pointer', padding: '6px 12px', fontSize: 'var(--text-xs)', border: '1px solid var(--color-border)', background: 'var(--color-surface)' }}
                    onClick={() => handleInputChange(example)}
                  >
                    <Icon size={11} /> {label}
                  </button>
                ))}
              </div>
            </div>

            {/* CTA */}
            <div style={{ display: 'flex', gap: 'var(--space-3)', justifyContent: 'center', marginTop: 'var(--space-10)', flexWrap: 'wrap' }}>
              <Link to="/investigate" className="btn btn-primary btn-lg" id="hero-investigate-btn">
                Start Investigation <ArrowRight size={18} />
              </Link>
              <Link to="/dashboard" className="btn btn-secondary btn-lg">
                <LayoutDashboard size={18} /> Command Dashboard
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section style={{ padding: 'var(--space-20) 0', background: 'var(--color-bg-secondary)' }}>
        <div className="container">
          <div style={{ textAlign: 'center', marginBottom: 'var(--space-12)' }}>
            <h2 style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, letterSpacing: '-0.03em' }}>
              Built for real intelligence work
            </h2>
            <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--text-lg)', marginTop: 'var(--space-3)' }}>
              Every feature designed around evidence, accuracy, and responsible use.
            </p>
          </div>
          <div className="feature-grid">
            {FEATURES.map(({ icon: Icon, title, desc }) => (
              <div key={title} className="feature-card">
                <div className="feature-icon">
                  <Icon size={24} />
                </div>
                <h3 className="feature-title">{title}</h3>
                <p className="feature-desc">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Principles */}
      <section style={{ padding: 'var(--space-20) 0' }}>
        <div className="container">
          <div style={{ maxWidth: '760px', margin: '0 auto' }}>
            <h2 style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 'var(--space-8)' }}>
              Core principles
            </h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 'var(--space-3)' }}>
              {PRINCIPLES.map(p => (
                <div key={p} className="flex items-center gap-3" style={{ padding: 'var(--space-3)' }}>
                  <CheckCircle size={18} color="var(--color-accent)" style={{ flexShrink: 0 }} />
                  <span style={{ fontWeight: 500, color: 'var(--color-text-secondary)' }}>{p}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Responsible use notice */}
      <section style={{ padding: 'var(--space-12) 0', background: 'var(--color-bg-secondary)' }}>
        <div className="container">
          <div className="alert alert-muted" style={{ maxWidth: '760px', margin: '0 auto', borderRadius: 'var(--radius-lg)' }}>
            <Lock size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <div style={{ fontWeight: 600, marginBottom: '4px' }}>Responsible Use</div>
              <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
                OpenSpective is designed for lawful open-source intelligence research using publicly available data only.
                It must not be used for unauthorized surveillance, doxxing, harassment, or any illegal purpose.
                All investigation results include source attribution and represent data available at collection time.
                OpenSpective is 100% free and open for public reconnaissance and lawful security research.
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section style={{ padding: 'var(--space-20) 0', textAlign: 'center' }}>
        <div className="container">
          <h2 style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, letterSpacing: '-0.03em' }}>
            Start your first investigation
          </h2>
          <p style={{ color: 'var(--color-text-secondary)', marginTop: 'var(--space-3)', marginBottom: 'var(--space-8)', fontSize: 'var(--text-lg)' }}>
            100% free and open for everyone. No sign-in or account required.
          </p>
          <Link to="/investigate" className="btn btn-primary btn-xl">
            Launch Free Investigation <ArrowRight size={20} />
          </Link>
        </div>
      </section>
    </div>
  );
}

// Need to import for the logged-in CTA
import { LayoutDashboard } from 'lucide-react';
