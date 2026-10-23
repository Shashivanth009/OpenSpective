import { useState, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Compass, Search, ExternalLink, Copy, Check, Sparkles,
  Terminal, Shield, BookOpen, Layers, CheckCircle2
} from 'lucide-react';

import { type OsintTool, OSINT_CATEGORIES, OSINT_TOOLS_REGISTRY, STARTER_WORKFLOW_STEPS } from '@openspective/shared';
export default function OsintFrameworkPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const initialTarget = searchParams.get('target') || '';
  const [activeTarget, setActiveTarget] = useState(initialTarget);
  const [selectedCategory, setSelectedCategory] = useState<string>('All Tools');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showStarterGuide, setShowStarterGuide] = useState(false);

  // Helper to extract components from active target
  const { domain, username, email, ip, cleanTarget } = useMemo(() => {
    const raw = activeTarget.trim();
    if (!raw) {
      return { domain: 'example.com', username: 'targetuser', email: 'user@example.com', ip: '1.1.1.1', cleanTarget: 'example.com' };
    }

    let d = raw;
    let u = raw;
    let e = raw;
    let i = raw;

    // Email detection
    if (raw.includes('@')) {
      e = raw;
      const parts = raw.split('@');
      u = parts[0] || 'targetuser';
      d = parts[1] || 'example.com';
    } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(raw)) {
      // IP detection
      i = raw;
    } else if (raw.includes('.')) {
      // Domain / host
      d = raw.replace(/^https?:\/\//i, '').split('/')[0] || raw;
      u = d.split('.')[0] || raw;
    } else {
      // Username or keyword
      u = raw;
      d = `${raw}.com`;
      e = `${raw}@gmail.com`;
    }

    return {
      domain: d,
      username: u,
      email: e,
      ip: i,
      cleanTarget: raw,
    };
  }, [activeTarget]);

  // Compute live URLs and CLI commands with target interpolated
  const resolveToolActions = (tool: OsintTool) => {
    let resolvedUrl = tool.urlTemplate
      .replace(/\{target\}/g, encodeURIComponent(cleanTarget))
      .replace(/\{domain\}/g, encodeURIComponent(domain))
      .replace(/\{username\}/g, encodeURIComponent(username))
      .replace(/\{email\}/g, encodeURIComponent(email))
      .replace(/\{ip\}/g, encodeURIComponent(ip));

    let resolvedCli = tool.cliCommand
      ? tool.cliCommand
          .replace(/\{target\}/g, cleanTarget)
          .replace(/\{domain\}/g, domain)
          .replace(/\{username\}/g, username)
          .replace(/\{email\}/g, email)
          .replace(/\{ip\}/g, ip)
      : undefined;

    return { resolvedUrl, resolvedCli };
  };

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleLaunchInvestigation = () => {
    if (!activeTarget.trim()) return;
    navigate(`/investigate?q=${encodeURIComponent(activeTarget.trim())}`);
  };

  const mapToolToModule = (tool: OsintTool): string => {
    const t = tool.id.toLowerCase();
    const cat = tool.category.toLowerCase();
    if (t.includes('subfinder') || t.includes('crt') || t.includes('findomain') || t.includes('amass')) return 'certificate_transparency';
    if (t.includes('sherlock') || t.includes('whatsmyname') || t.includes('blackbird') || cat.includes('username')) return 'username_presence';
    if (t.includes('harvester') || t.includes('hunter') || cat.includes('email')) return 'email_identity';
    if (t.includes('wappalyzer') || t.includes('builtwith') || cat.includes('fingerprinting')) return 'tech_stack';
    if (t.includes('wayback') || t.includes('gau') || cat.includes('crawling')) return 'web_archive';
    if (t.includes('shodan') || t.includes('censys') || t.includes('fofa') || t.includes('zoomeye')) return 'shodan';
    if (t.includes('urlhaus') || t.includes('threatfox') || cat.includes('threat')) return 'threat_intel';
    if (t.includes('s3') || t.includes('cloud') || cat.includes('cloud')) return 'cloud_storage';
    if (t.includes('dork') || cat.includes('search engine')) return 'search_dorks';
    if (t.includes('pgp') || t.includes('key')) return 'pgp_keys';
    if (cat.includes('domain') || cat.includes('dns')) return 'dns';
    if (cat.includes('ip') || cat.includes('network')) return 'ipinfo';
    if (cat.includes('github') || cat.includes('code')) return 'github';
    if (cat.includes('breach')) return 'breach';
    if (cat.includes('geoint') || cat.includes('satellite')) return 'location';
    return 'dns';
  };

  const handleScanWithTool = (tool: OsintTool) => {
    const targetToUse = activeTarget.trim() || 'example.com';
    const mod = mapToolToModule(tool);
    navigate(`/investigate?q=${encodeURIComponent(targetToUse)}&module=${encodeURIComponent(mod)}`);
  };

  // Filtered tools
  const filteredTools = useMemo(() => {
    return OSINT_TOOLS_REGISTRY.filter(tool => {
      const matchesCategory = selectedCategory === 'All Tools' || tool.category === selectedCategory;
      const query = searchQuery.toLowerCase().trim();
      const matchesSearch = !query ||
        tool.name.toLowerCase().includes(query) ||
        tool.description.toLowerCase().includes(query) ||
        tool.subcategory.toLowerCase().includes(query) ||
        tool.category.toLowerCase().includes(query) ||
        tool.tags.some(t => t.toLowerCase().includes(query)) ||
        (tool.cliCommand && tool.cliCommand.toLowerCase().includes(query));

      return matchesCategory && matchesSearch;
    });
  }, [selectedCategory, searchQuery]);

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto', padding: 'var(--space-6) var(--space-6)' }}>
      {/* Header Banner */}
      <div style={{ marginBottom: 'var(--space-8)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 'var(--space-4)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <div style={{
              width: 44,
              height: 44,
              borderRadius: 'var(--radius)',
              background: 'var(--color-accent-soft)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--color-accent)'
            }}>
              <Compass size={28} />
            </div>
            <div>
              <h1 style={{ fontSize: 'var(--text-3xl)', fontWeight: 900, margin: 0, color: 'var(--color-dark)' }}>
                OSINT Framework & Intelligence Hub
              </h1>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', margin: 0, marginTop: '2px' }}>
                Unified directory of all 18 core OSINT framework domains, 110+ specialized reconnaissance tools, and live CLI command generator.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
            <button
              onClick={() => setShowStarterGuide(!showStarterGuide)}
              className={`btn btn-sm ${showStarterGuide ? 'btn-primary' : 'btn-secondary'}`}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}
            >
              <BookOpen size={15} /> {showStarterGuide ? 'Hide Starter Guide' : 'Starter Toolkit Workflow'}
            </button>
          </div>
        </div>
      </div>

      {/* Interactive Starter Toolkit Sequence (Collapsible) */}
      {showStarterGuide && (
        <div className="card" style={{
          marginBottom: 'var(--space-8)',
          padding: 'var(--space-6)',
          background: 'linear-gradient(135deg, rgba(37,99,235,0.04), rgba(16,185,129,0.04))',
          border: '1.5px solid var(--color-accent)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
            <Shield size={20} style={{ color: 'var(--color-accent)' }} />
            <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 800, margin: 0, color: 'var(--color-dark)' }}>
              Starter Toolkit for Cybersecurity OSINT — Practical Sequence
            </h2>
          </div>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginBottom: 'var(--space-5)' }}>
            For authorized lab targets, bug bounties, and defense teams. Follow this structured 7-step sequence instead of running 100 tools at once:
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 'var(--space-3)' }}>
            {STARTER_WORKFLOW_STEPS.map(step => (
              <div
                key={step.step}
                style={{
                  background: 'var(--color-surface)',
                  padding: 'var(--space-4)',
                  borderRadius: 'var(--radius)',
                  border: '1px solid var(--color-border)',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  gap: 'var(--space-2)'
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-1)' }}>
                    <span className="badge badge-primary" style={{ fontSize: '10px', fontWeight: 800 }}>
                      Step {step.step}
                    </span>
                    <strong style={{ fontSize: 'var(--text-xs)', color: 'var(--color-dark)' }}>
                      {step.title}
                    </strong>
                  </div>
                  <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-accent)', marginBottom: 'var(--space-1)' }}>
                    {step.tools}
                  </div>
                  <p style={{ fontSize: '11px', color: 'var(--color-text-secondary)', margin: 0, lineHeight: 1.4 }}>
                    {step.purpose}
                  </p>
                </div>

                <div style={{
                  background: 'var(--color-bg)',
                  padding: '4px 8px',
                  borderRadius: 'var(--radius-sm)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '10px',
                  color: 'var(--color-text-primary)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <code style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {step.cli.replace('{domain}', domain).replace('{target}', cleanTarget).replace('{ip}', ip).replace('{username}', username)}
                  </code>
                  <button
                    onClick={() => handleCopyText(step.cli.replace('{domain}', domain).replace('{target}', cleanTarget).replace('{ip}', ip).replace('{username}', username), `step-${step.step}`)}
                    className="btn btn-ghost btn-xs"
                    style={{ padding: '2px 4px', height: 'auto', marginLeft: '4px' }}
                    title="Copy command"
                  >
                    {copiedId === `step-${step.step}` ? <Check size={10} style={{ color: 'var(--color-success)' }} /> : <Copy size={10} />}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Active Target Pivot Engine */}
      <div className="card" style={{
        marginBottom: 'var(--space-6)',
        padding: 'var(--space-5)',
        background: 'var(--color-surface-elevated)',
        border: '1.5px solid var(--color-accent-soft)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
          <Sparkles size={18} style={{ color: 'var(--color-accent)' }} />
          <strong style={{ fontSize: 'var(--text-base)', color: 'var(--color-dark)' }}>
            Active Target Pivot Engine
          </strong>
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
            Enter any target to dynamically populate pre-configured live query links and CLI commands across all 110+ tools below
          </span>
        </div>

        <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 280 }}>
            <input
              type="text"
              className="input"
              placeholder="e.g. example.com, torvalds, analyst@target.org, 1.1.1.1, +14155552671"
              value={activeTarget}
              onChange={(e) => setActiveTarget(e.target.value)}
              style={{ width: '100%', fontSize: 'var(--text-sm)' }}
            />
          </div>

          <button
            onClick={handleLaunchInvestigation}
            disabled={!activeTarget.trim()}
            className="btn btn-primary"
            style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}
          >
            <Search size={16} /> Run Full OpenSpective Scan
          </button>
        </div>

        {activeTarget.trim() && (
          <div style={{ marginTop: 'var(--space-3)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap', fontSize: 'var(--text-xs)' }}>
            <span style={{ color: 'var(--color-text-secondary)', fontWeight: 600 }}>Active Target Variables:</span>
            <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)' }}>Domain: {domain}</span>
            <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)' }}>Username: {username}</span>
            <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)' }}>Email: {email}</span>
            <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)' }}>IP: {ip}</span>
            <span style={{ color: 'var(--color-text-muted)', marginLeft: 'auto' }}>
              All 110+ tools below dynamically updated!
            </span>
          </div>
        )}
      </div>

      {/* Filter Toolbar & Category Navigation */}
      <div style={{ marginBottom: 'var(--space-6)' }}>
        {/* Search bar & count */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Layers size={16} style={{ color: 'var(--color-accent)' }} />
            <span style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-dark)' }}>
              Showing {filteredTools.length} of {OSINT_TOOLS_REGISTRY.length} tools
            </span>
          </div>

          <div style={{ width: 320, maxWidth: '100%' }}>
            <input
              type="text"
              className="input input-sm"
              placeholder="Search tools, tags, or CLI commands..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: '100%' }}
            />
          </div>
        </div>

        {/* Category Pills (All 18 Categories) */}
        <div style={{
          display: 'flex',
          gap: 'var(--space-2)',
          flexWrap: 'wrap',
          background: 'var(--color-surface)',
          padding: 'var(--space-3)',
          borderRadius: 'var(--radius)',
          border: '1px solid var(--color-border)'
        }}>
          {OSINT_CATEGORIES.map(cat => {
            const count = cat === 'All Tools'
              ? OSINT_TOOLS_REGISTRY.length
              : OSINT_TOOLS_REGISTRY.filter(t => t.category === cat).length;

            return (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`btn btn-xs ${selectedCategory === cat ? 'btn-primary' : 'btn-ghost'}`}
                style={{
                  fontSize: '11px',
                  padding: '3px 10px',
                  borderRadius: 'var(--radius-sm)',
                  fontWeight: selectedCategory === cat ? 700 : 500
                }}
              >
                {cat} ({count})
              </button>
            );
          })}
        </div>
      </div>

      {/* Tools Grid (All 110+ Tools) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 'var(--space-4)' }}>
        {filteredTools.map(tool => {
          const { resolvedUrl, resolvedCli } = resolveToolActions(tool);

          return (
            <div
              key={tool.id}
              className="card"
              style={{
                padding: 'var(--space-5)',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                gap: 'var(--space-4)',
                border: '1px solid var(--color-border)',
                background: 'var(--color-surface)',
                transition: 'all 0.2s ease',
              }}
            >
              <div>
                {/* Header row */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
                  <div>
                    <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 800, margin: 0, color: 'var(--color-dark)' }}>
                      {tool.name}
                    </h3>
                    <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
                      {tool.subcategory} • <span style={{ color: 'var(--color-accent)' }}>{tool.category}</span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                    {tool.cliCommand && (
                      <span className="badge badge-neutral" style={{ fontSize: '9px', padding: '1px 5px', display: 'inline-flex', alignItems: 'center', gap: '2px' }}>
                        <Terminal size={9} /> CLI
                      </span>
                    )}
                    {tool.freeTier && (
                      <span className="badge badge-success" style={{ fontSize: '9px', padding: '1px 5px' }}>
                        Free
                      </span>
                    )}
                    {tool.requiresApiKey && (
                      <span className="badge badge-warning" style={{ fontSize: '9px', padding: '1px 5px' }}>
                        API Key
                      </span>
                    )}
                  </div>
                </div>

                {/* Description */}
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', lineHeight: 1.5, margin: 0, marginBottom: 'var(--space-3)' }}>
                  {tool.description}
                </p>

                {/* Best for highlight */}
                {tool.bestFor && (
                  <div style={{
                    fontSize: '11px',
                    color: '#059669',
                    background: '#ecfdf5',
                    padding: '4px 8px',
                    borderRadius: 'var(--radius-sm)',
                    marginBottom: 'var(--space-3)',
                    border: '1px solid #d1fae5',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px'
                  }}>
                    <CheckCircle2 size={12} style={{ flexShrink: 0 }} />
                    <span><strong>Best for:</strong> {tool.bestFor}</span>
                  </div>
                )}

                {/* CLI Command snippet (if available) */}
                {resolvedCli && (
                  <div style={{
                    background: 'var(--color-bg)',
                    border: '1px solid var(--color-border)',
                    borderRadius: 'var(--radius)',
                    padding: 'var(--space-2) var(--space-3)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: 'var(--space-2)'
                  }}>
                    <code style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--color-dark)' }}>
                      $ {resolvedCli}
                    </code>
                    <button
                      onClick={() => handleCopyText(resolvedCli, `cli-${tool.id}`)}
                      className="btn btn-ghost btn-xs"
                      style={{ padding: '2px 4px', height: 'auto', marginLeft: '6px' }}
                      title="Copy CLI command"
                    >
                      {copiedId === `cli-${tool.id}` ? <Check size={12} style={{ color: 'var(--color-success)' }} /> : <Copy size={12} />}
                    </button>
                  </div>
                )}
              </div>

              {/* Action buttons */}
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                paddingTop: 'var(--space-3)',
                borderTop: '1px solid var(--color-border-subtle)',
                flexWrap: 'wrap',
                gap: 'var(--space-2)'
              }}>
                <div style={{ display: 'flex', gap: 'var(--space-1)', alignItems: 'center', flexWrap: 'wrap' }}>
                  <button
                    onClick={() => handleCopyText(resolvedUrl, `url-${tool.id}`)}
                    className="btn btn-ghost btn-xs"
                    style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}
                  >
                    {copiedId === `url-${tool.id}` ? <Check size={12} /> : <Copy size={12} />}
                    {copiedId === `url-${tool.id}` ? 'Copied' : 'Copy Query'}
                  </button>

                  <button
                    onClick={() => handleScanWithTool(tool)}
                    className="btn btn-secondary btn-xs"
                    style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', fontWeight: 600 }}
                    title={`Scan active target in OpenSpective with ${tool.name}`}
                  >
                    <Shield size={11} style={{ color: 'var(--color-accent)' }} /> Scan In OpenSpective
                  </button>
                </div>

                <a
                  href={resolvedUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="btn btn-primary btn-xs"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}
                >
                  <ExternalLink size={12} /> Launch Web Tool
                </a>
              </div>
            </div>
          );
        })}
      </div>

      {filteredTools.length === 0 && (
        <div className="card" style={{ padding: 'var(--space-12)', textAlign: 'center', marginTop: 'var(--space-6)' }}>
          <Search size={36} style={{ color: 'var(--color-text-muted)', marginBottom: 'var(--space-3)' }} />
          <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
            No tools matched your search criteria
          </h3>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', marginBottom: 'var(--space-4)' }}>
            Try searching for a different keyword or select "All Tools" above.
          </p>
          <button onClick={() => { setSelectedCategory('All Tools'); setSearchQuery(''); }} className="btn btn-secondary btn-sm">
            Reset Filters
          </button>
        </div>
      )}
    </div>
  );
}
