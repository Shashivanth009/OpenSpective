import { useState, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Search, Shield, CheckCircle2, AlertCircle, Sparkles,
  Globe, Mail, User, Network, Building, Link2, ArrowRight, Phone, Coins
} from 'lucide-react';
import { OSINT_TOOLS_REGISTRY, OSINT_CATEGORIES, type OsintTool } from '@openspective/shared';
import * as api from '../api.ts';

export default function InvestigatePage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialQuery = searchParams.get('q') || searchParams.get('target') || '';
  const initialType = searchParams.get('type') || localStorage.getItem('os_pref_target_type') || 'auto';
  const initialModule = searchParams.get('module');

  const [target, setTarget] = useState(initialQuery);
  const [targetType, setTargetType] = useState<string>(initialType);
  const [selectedCategory, setSelectedCategory] = useState<string>('All Tools');
  const [toolSearch, setToolSearch] = useState('');

  // ALL 173 OSINT TOOLS PRE-SELECTED BY DEFAULT AT START
  const [selectedModules, setSelectedModules] = useState<string[]>(() => {
    return OSINT_TOOLS_REGISTRY.map(t => t.id);
  });

  useEffect(() => {
    if (initialModule && !selectedModules.includes(initialModule)) {
      setSelectedModules((prev) => [...prev, initialModule]);
    }
  }, [initialModule]);
  const [enableAi, setEnableAi] = useState<boolean>(() => {
    const pref = localStorage.getItem('os_pref_ai_auto');
    return pref !== null ? pref === 'true' : true;
  });
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

  const filteredTools = useMemo(() => {
    return OSINT_TOOLS_REGISTRY.filter((tool: OsintTool) => {
      const matchesCategory = selectedCategory === 'All Tools' || tool.category === selectedCategory;
      if (!matchesCategory) return false;
      if (!toolSearch.trim()) return true;
      const q = toolSearch.toLowerCase();
      return (
        tool.name.toLowerCase().includes(q) ||
        tool.description.toLowerCase().includes(q) ||
        tool.subcategory.toLowerCase().includes(q) ||
        tool.tags.some(t => t.toLowerCase().includes(q)) ||
        (tool.bestFor && tool.bestFor.toLowerCase().includes(q))
      );
    });
  }, [selectedCategory, toolSearch]);

  const selectAllTools = () => {
    setSelectedModules(OSINT_TOOLS_REGISTRY.map(t => t.id));
  };

  const selectFilteredTools = () => {
    const ids = new Set([...selectedModules, ...filteredTools.map(t => t.id)]);
    setSelectedModules(Array.from(ids));
  };

  const clearAllTools = () => {
    setSelectedModules([]);
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
        <div className="card glass-panel" style={{ marginBottom: 'var(--space-6)', padding: 'var(--space-6)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-4)', flexWrap: 'wrap', gap: 'var(--space-3)' }}>
            <div>
              <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <Shield size={20} style={{ color: 'var(--color-accent)' }} /> 2. OSINT Reconnaissance Framework Suite
              </h2>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', margin: '4px 0 0 0' }}>
                All 173 specialized OSINT intelligence engines and passive collectors are selected by default for maximum depth.
              </p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
              <span className="badge badge-accent" style={{ fontWeight: 800, padding: '6px 14px', fontSize: '13px', border: '1.5px solid rgba(16, 185, 129, 0.4)' }}>
                {selectedModules.length} / {OSINT_TOOLS_REGISTRY.length} Selected
              </span>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={selectAllTools}
                style={{ fontWeight: 700, padding: '6px 14px', gap: '6px' }}
              >
                <CheckCircle2 size={15} /> Select All 173 Engines
              </button>
              {toolSearch || selectedCategory !== 'All Tools' ? (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={selectFilteredTools}
                >
                  Select Filtered ({filteredTools.length})
                </button>
              ) : null}
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={clearAllTools}
                style={{ color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.25)' }}
              >
                Clear
              </button>
            </div>
          </div>

          {/* Search Input Bar */}
          <div style={{ marginBottom: 'var(--space-3)', position: 'relative' }}>
            <Search size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
            <input
              type="text"
              className="input"
              style={{ paddingLeft: '40px', height: '42px', fontSize: 'var(--text-sm)' }}
              placeholder="Filter 173 tools by name, category, CLI command, or tag..."
              value={toolSearch}
              onChange={(e) => setToolSearch(e.target.value)}
            />
            {toolSearch && (
              <button
                type="button"
                onClick={() => setToolSearch('')}
                style={{ position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer', fontSize: '14px' }}
              >
                ✕
              </button>
            )}
          </div>

          {/* Prominent High-Glass Category Pills with "All Tools" front and center */}
          <div style={{
            display: 'flex',
            gap: '8px',
            flexWrap: 'wrap',
            padding: '10px 12px',
            background: 'var(--glass-bg-subtle)',
            borderRadius: 'var(--radius)',
            border: '1.5px solid var(--glass-border)',
            marginBottom: 'var(--space-4)',
            backdropFilter: 'blur(16px)',
          }}>
            {OSINT_CATEGORIES.map((cat) => {
              const count = cat === 'All Tools'
                ? OSINT_TOOLS_REGISTRY.length
                : OSINT_TOOLS_REGISTRY.filter(t => t.category === cat).length;
              const isActive = selectedCategory === cat;

              return (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setSelectedCategory(cat)}
                  className={`glass-pill ${isActive ? 'glass-pill-active' : ''}`}
                  style={{
                    fontSize: '11px',
                    fontWeight: isActive ? 800 : 600,
                    cursor: 'pointer',
                    gap: '6px',
                  }}
                >
                  {cat === 'All Tools' && <Shield size={13} style={{ color: isActive ? 'var(--color-accent)' : 'inherit' }} />}
                  {cat}
                  <span style={{
                    fontSize: '10px',
                    padding: '2px 7px',
                    borderRadius: '10px',
                    background: isActive ? 'rgba(16, 185, 129, 0.35)' : 'var(--glass-bg-card)',
                    color: isActive ? 'var(--color-text-primary)' : 'var(--color-text-secondary)',
                    fontWeight: 700,
                    border: '1px solid var(--glass-border-subtle)',
                  }}>
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Tools Grid with Smooth Max Height */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
            gap: 'var(--space-3)',
            maxHeight: '440px',
            overflowY: 'auto',
            paddingRight: '6px',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius)',
            padding: 'var(--space-3)',
            background: 'var(--color-bg)'
          }}>
            {filteredTools.map((tool: OsintTool) => {
              const isSelected = selectedModules.includes(tool.id);

              return (
                <div
                  key={tool.id}
                  onClick={() => toggleModule(tool.id)}
                  className="glass-card"
                  style={{
                    padding: 'var(--space-3) var(--space-4)',
                    borderRadius: 'var(--radius)',
                    border: `1.5px solid ${isSelected ? 'var(--color-accent)' : 'var(--color-border)'}`,
                    background: isSelected ? 'rgba(37, 99, 235, 0.08)' : 'var(--color-surface)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', overflow: 'hidden' }}>
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => {}} // handled by card click
                        style={{ accentColor: 'var(--color-accent)', width: '15px', height: '15px', cursor: 'pointer' }}
                      />
                      <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--color-dark)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {tool.name}
                      </strong>
                    </div>
                    <span style={{ fontSize: '10px', color: 'var(--color-text-muted)', background: 'var(--color-bg)', padding: '2px 6px', borderRadius: '4px', border: '1px solid var(--color-border)', whiteSpace: 'nowrap' }}>
                      {tool.subcategory}
                    </span>
                  </div>

                  <p style={{
                    fontSize: '11px',
                    color: 'var(--color-text-secondary)',
                    margin: '2px 0 0 23px',
                    lineHeight: 1.35,
                    display: '-webkit-box',
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: 'vertical',
                    overflow: 'hidden'
                  }}>
                    {tool.description}
                  </p>

                  {tool.bestFor && (
                    <div style={{ paddingLeft: '23px', fontSize: '10px', color: 'var(--color-accent)', fontStyle: 'italic', marginTop: '2px' }}>
                      ★ {tool.bestFor}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 'var(--space-3)', fontSize: '12px', color: 'var(--color-text-muted)' }}>
            <span>Showing {filteredTools.length} of {OSINT_TOOLS_REGISTRY.length} tools ({selectedCategory})</span>
            <span><strong>{selectedModules.length}</strong> selected for target execution</span>
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
