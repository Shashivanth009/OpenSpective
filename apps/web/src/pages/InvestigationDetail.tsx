import { useState, useEffect, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  AlertTriangle, GitBranch, RefreshCw, Sparkles,
  FileText, ChevronDown, ChevronRight, Clock,
  ShieldCheck, BarChart3, CornerUpRight, ExternalLink,
  Copy, Check, Database, MapPin
} from 'lucide-react';
import * as api from '../api.ts';

export default function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [investigation, setInvestigation] = useState<api.Investigation | null>(null);
  const [executions, setExecutions] = useState<api.CollectorExecution[]>([]);
  const [findings, setFindings] = useState<api.Finding[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchFilter, setSearchFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [analyzingAi, setAnalyzingAi] = useState(false);
  const [aiReport, setAiReport] = useState<any>(null);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'findings' | 'timeline' | 'scorecard'>('findings');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    if (!id) return;
    try {
      const [invRes, findRes] = await Promise.all([
        api.getInvestigation(id),
        api.getFindings(id, undefined, 1, 300),
      ]);
      setInvestigation(invRes.investigation);
      setExecutions(invRes.executions);
      setFindings(findRes.data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load investigation details.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    // Auto-poll if running
    let timer: ReturnType<typeof setInterval> | undefined;
    if (investigation?.status === 'running' || investigation?.status === 'queued') {
      timer = setInterval(() => {
        fetchData();
      }, 3000);
    }
    return () => clearInterval(timer);
  }, [id, investigation?.status]);

  const handleRunAiAnalysis = async () => {
    if (!id) return;
    setAnalyzingAi(true);
    try {
      const report = await api.analyzeInvestigation(id);
      setAiReport(report);
      fetchData();
    } catch (err: any) {
      alert(err?.message || 'AI analysis failed.');
    } finally {
      setAnalyzingAi(false);
    }
  };

  const handleExport = async (format: 'json' | 'csv' | 'html') => {
    if (!id) return;
    try {
      const res = await api.generateReport(id, format);
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `openspective-report-${investigation?.target || id}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err: any) {
      alert(err?.message || 'Export failed.');
    }
  };

  // Client-side OASIS STIX 2.1 Threat Intel Bundle generator
  const handleExportStix = () => {
    if (!investigation) return;
    const now = new Date().toISOString();
    const bundleId = `bundle--${Math.random().toString(36).slice(2, 11)}-${Date.now()}`;
    const identityId = `identity--${Math.random().toString(36).slice(2, 11)}`;

    const stixObjects: any[] = [
      {
        type: 'identity',
        spec_version: '2.1',
        id: identityId,
        created: now,
        modified: now,
        name: 'OpenSpective Passive OSINT Platform',
        identity_class: 'system',
      },
      {
        type: 'observed-data',
        spec_version: '2.1',
        id: `observed-data--${Math.random().toString(36).slice(2, 11)}`,
        created_by_ref: identityId,
        created: now,
        modified: now,
        first_observed: investigation.started_at,
        last_observed: investigation.completed_at || now,
        number_observed: findings.length,
        objects: {
          '0': {
            type: investigation.target_type === 'ip' ? 'ipv4-addr' : investigation.target_type === 'email' ? 'email-addr' : 'domain-name',
            value: investigation.target,
          },
        },
      },
    ];

    findings.forEach((f) => {
      stixObjects.push({
        type: 'indicator',
        spec_version: '2.1',
        id: `indicator--${Math.random().toString(36).slice(2, 11)}`,
        created_by_ref: identityId,
        created: f.first_seen || now,
        modified: f.first_seen || now,
        name: `${f.category}: ${f.type}`,
        description: f.notes || f.value,
        indicator_types: [f.severity === 'critical' || f.severity === 'high' ? 'malicious-activity' : 'anomalous-activity'],
        pattern_type: 'stix',
        pattern: `[artifact:payload_bin = '${f.value}']`,
        valid_from: f.first_seen || now,
        confidence: f.confidence === 'high' ? 90 : f.confidence === 'medium' ? 60 : 30,
      });
    });

    const bundle = {
      type: 'bundle',
      id: bundleId,
      objects: stixObjects,
    };

    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `stix2.1-${investigation.target}-${investigation.id}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  const handleCopyRaw = (text: string, fid: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(fid);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Helper to extract a pivotable target from a finding
  const detectPivotTarget = (f: api.Finding): { target: string; type: string } | null => {
    if (f.type === 'git_author_email' && f.value.includes('@')) {
      return { target: f.value, type: 'email' };
    }
    if (f.type === 'account_presence') {
      const match = f.value.match(/^[^:]+:\s*([^\s]+)/);
      if (match && match[1]) return { target: match[1], type: 'username' };
    }
    if (f.type === 'git_commit') {
      const match = f.value.match(/^([^@]+)@/);
      if (match && match[1]) return { target: match[1], type: 'organization' };
    }
    if (f.type === 'dns_a' || f.type === 'dns_aaaa') {
      return { target: f.value, type: 'ip' };
    }
    if (f.type === 'dns_mx') {
      return { target: f.value, type: 'domain' };
    }
    if (f.type === 'github_profile') {
      return { target: f.value, type: 'username' };
    }
    return null;
  };

  // Timeline events extracted and sorted chronologically
  const timelineEvents = useMemo(() => {
    return findings
      .map(f => {
        let eventDate = f.first_seen;
        try {
          const raw = typeof f.raw_data === 'string' ? JSON.parse(f.raw_data) : f.raw_data;
          if (raw?.date) eventDate = raw.date;
          else if (raw?.firstActivity) eventDate = raw.firstActivity;
          else if (raw?.registeredAt) eventDate = raw.registeredAt;
          else if (raw?.breachDate) eventDate = raw.breachDate;
          else if (raw?.timestamp && raw.timestamp.length >= 8) {
            const y = raw.timestamp.slice(0, 4);
            const m = raw.timestamp.slice(4, 6);
            const d = raw.timestamp.slice(6, 8);
            eventDate = `${y}-${m}-${d}`;
          }
        } catch {
          // ignore parse error
        }

        return {
          id: f.id,
          finding: f,
          category: f.category,
          type: f.type,
          value: f.value,
          notes: f.notes,
          severity: f.severity,
          source: f.source_name,
          sourceUrl: f.source_url,
          timestamp: eventDate || f.first_seen,
        };
      })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [findings]);

  // Executive Intelligence Scorecard calculations
  const scorecard = useMemo(() => {
    const total = findings.length;
    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const highCount = findings.filter(f => f.severity === 'high').length;
    const mediumCount = findings.filter(f => f.severity === 'medium').length;

    // Attribute depth
    const emailsFound = findings.filter(f => f.category === 'identity_attribution' || f.type.includes('email')).length;
    const commitsFound = findings.filter(f => f.category === 'developer_activity' || f.type === 'git_commit').length;
    const profilesFound = findings.filter(f => f.category === 'social_profile' || f.category === 'public_profile').length;
    const infraFound = findings.filter(f => f.category === 'dns' || f.category === 'rdap' || f.category === 'certificate' || f.category === 'technology' || f.category === 'infrastructure').length;
    const breachesFound = findings.filter(f => f.category === 'threat_intelligence' && f.type === 'breach_record').length;
    const portsAndCvesFound = findings.filter(f => f.type === 'passive_open_ports' || f.type === 'known_cve' || f.type === 'known_cves_summary').length;
    const locationsFound = findings.filter(f => f.category === 'location_intelligence').length;
    const phoneFound = findings.filter(f => f.category === 'identity' && (f.type === 'phone_profile' || f.type === 'osint_search_dork')).length;
    const securityFinding = findings.find(f => f.type === 'dns_security_score' || f.type === 'security_hygiene_score');

    let exposureScore = Math.min(100, Math.round(
      (commitsFound * 12) +
      (emailsFound * 20) +
      (profilesFound * 8) +
      (breachesFound * 25) +
      (portsAndCvesFound * 15) +
      (infraFound * 5)
    ));
    if (exposureScore === 0 && total > 0) exposureScore = 25;

    let attributionLevel = 'Unverified Surface';
    if (emailsFound > 0 && commitsFound > 0) attributionLevel = 'Directly Attributed (Verified Code Author)';
    else if (phoneFound > 0) attributionLevel = 'Telephony & Carrier Allocated';
    else if (portsAndCvesFound > 0) attributionLevel = 'Network & Service Vulnerability Exposure';
    else if (emailsFound > 0 || profilesFound >= 3) attributionLevel = 'High Footprint Correlation';
    else if (infraFound > 0) attributionLevel = 'Infrastructure Mapping';

    return {
      total,
      criticalCount,
      highCount,
      mediumCount,
      exposureScore,
      attributionLevel,
      emailsFound,
      commitsFound,
      profilesFound,
      infraFound,
      breachesFound,
      portsAndCvesFound,
      locationsFound,
      phoneFound,
      securityScore: securityFinding?.value || null,
    };
  }, [findings]);

  const filteredFindings = findings.filter(f => {
    const matchesCat = selectedCategory === 'all' || f.category.toLowerCase() === selectedCategory.toLowerCase();
    const matchesSearch = !searchFilter ||
      f.value.toLowerCase().includes(searchFilter.toLowerCase()) ||
      f.type.toLowerCase().includes(searchFilter.toLowerCase()) ||
      (f.notes && f.notes.toLowerCase().includes(searchFilter.toLowerCase()));
    return matchesCat && matchesSearch;
  });

  const categories = ['all', ...Array.from(new Set(findings.map(f => f.category)))];

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed': return <span className="badge badge-success">Completed</span>;
      case 'running': return <span className="badge badge-info"><span className="spinner" style={{ width: 10, height: 10 }} /> Running</span>;
      case 'queued': return <span className="badge badge-warning">Queued</span>;
      case 'partial': return <span className="badge badge-warning">Partial</span>;
      case 'failed': return <span className="badge badge-error">Failed</span>;
      default: return <span className="badge badge-neutral">{status}</span>;
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'critical': return <span className="badge badge-error">Critical</span>;
      case 'high': return <span className="badge badge-error">High</span>;
      case 'medium': return <span className="badge badge-warning">Medium</span>;
      case 'low': return <span className="badge badge-success">Low</span>;
      default: return <span className="badge badge-neutral">Info</span>;
    }
  };

  if (loading && !investigation) {
    return (
      <div style={{ maxWidth: '1400px', margin: '0 auto', padding: 'var(--space-12)', textAlign: 'center' }}>
        <span className="spinner" style={{ width: 28, height: 28, marginBottom: 'var(--space-4)' }} />
        <p style={{ color: 'var(--color-text-secondary)' }}>Loading investigation telemetry...</p>
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div style={{ maxWidth: '800px', margin: 'var(--space-12) auto', padding: 'var(--space-6)' }}>
        <div className="alert alert-error">
          <AlertTriangle size={20} />
          <span>{error || 'Investigation not found.'}</span>
        </div>
        <Link to="/dashboard" className="btn btn-secondary" style={{ marginTop: 'var(--space-4)' }}>
          Back to Dashboard
        </Link>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto', padding: 'var(--space-6) var(--space-8)' }}>
      {/* Target Banner */}
      <div className="card" style={{ marginBottom: 'var(--space-6)', padding: 'var(--space-6)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 'var(--space-4)' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-2)' }}>
              <h1 style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, color: 'var(--color-dark)', margin: 0 }}>
                {investigation.target}
              </h1>
              <span className="badge badge-neutral" style={{ textTransform: 'capitalize' }}>
                {investigation.target_type.replace('_', ' ')}
              </span>
              {getStatusBadge(investigation.status)}
            </div>

            <div style={{ display: 'flex', gap: 'var(--space-4)', fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
              <span>ID: <code>{investigation.id}</code></span>
              <span>Started: {new Date(investigation.started_at).toLocaleTimeString()}</span>
              {investigation.completed_at && (
                <span>Completed: {new Date(investigation.completed_at).toLocaleTimeString()}</span>
              )}
            </div>
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
            <Link to={`/investigations/${investigation.id}/graph`} className="btn btn-secondary btn-sm">
              <GitBranch size={16} /> Interactive Graph
            </Link>

            <button
              onClick={handleRunAiAnalysis}
              disabled={analyzingAi}
              className="btn btn-secondary btn-sm"
              title="Synthesize findings with Workers AI"
            >
              <Sparkles size={16} style={{ color: 'var(--color-accent)' }} />
              {analyzingAi ? 'Synthesizing...' : 'AI Synthesis'}
            </button>

            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <button onClick={() => handleExport('json')} className="btn btn-ghost btn-sm" title="Export JSON">
                JSON
              </button>
              <button onClick={() => handleExport('csv')} className="btn btn-ghost btn-sm" title="Export CSV">
                CSV
              </button>
              <button onClick={handleExportStix} className="btn btn-ghost btn-sm" title="Export OASIS STIX 2.1 Threat Intel">
                <ShieldCheck size={14} style={{ color: 'var(--color-accent)' }} /> STIX 2.1
              </button>
              <button onClick={() => handleExport('html')} className="btn btn-ghost btn-sm" title="Download HTML Report">
                <FileText size={16} /> Report
              </button>
            </div>

            <button onClick={fetchData} className="btn btn-ghost btn-sm" title="Refresh">
              <RefreshCw size={16} />
            </button>
          </div>
        </div>
      </div>

      {/* Collector Executions Progress Row */}
      <div className="card" style={{ marginBottom: 'var(--space-6)', padding: 'var(--space-5)' }}>
        <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-3)' }}>
          Active Intelligence Telemetry
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 'var(--space-3)' }}>
          {executions.map(exec => (
            <div key={exec.id} style={{
              padding: 'var(--space-3)',
              borderRadius: 'var(--radius)',
              background: 'var(--color-bg)',
              border: '1px solid var(--color-border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}>
              <div>
                <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, textTransform: 'uppercase', color: 'var(--color-dark)' }}>
                  {exec.collector_name.replace('_', ' ')}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--color-text-secondary)', marginTop: 2 }}>
                  {exec.findings_count} findings
                </div>
              </div>
              {getStatusBadge(exec.status)}
            </div>
          ))}
        </div>
      </div>

      {/* AI Intelligence Synthesis Section (if generated) */}
      {(aiReport || investigation.ai_analysis_id) && (
        <div className="card" style={{
          marginBottom: 'var(--space-6)',
          padding: 'var(--space-6)',
          border: '1.5px solid var(--color-accent-soft)',
          background: 'var(--color-surface-elevated)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
            <Sparkles size={20} style={{ color: 'var(--color-accent)' }} />
            <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, margin: 0, color: 'var(--color-dark)' }}>
              AI Intelligence Synthesis
            </h2>
          </div>

          <div style={{
            fontSize: 'var(--text-sm)',
            lineHeight: 1.7,
            color: 'var(--color-text-primary)',
            background: 'var(--color-surface)',
            padding: 'var(--space-5)',
            borderRadius: 'var(--radius)',
            border: '1px solid var(--color-border)',
            whiteSpace: 'pre-wrap',
          }}>
            {aiReport?.summary || aiReport?.fullResponse || 'Intelligence analysis generated by Cloudflare Workers AI based on collected findings.'}
          </div>

          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginTop: 'var(--space-3)' }}>
            ⚠️ Evidence-grounded synthesis. No facts invented. Generated by {aiReport?.model || '@cf/meta/llama-3-8b-instruct'}.
          </div>
        </div>
      )}

      {/* View Switcher Tabs */}
      <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
        <button
          onClick={() => setActiveTab('findings')}
          className={`btn btn-sm ${activeTab === 'findings' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <Database size={15} /> Discovered Findings ({findings.length})
        </button>
        <button
          onClick={() => setActiveTab('timeline')}
          className={`btn btn-sm ${activeTab === 'timeline' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <Clock size={15} /> Chronological Timeline ({timelineEvents.length})
        </button>
        <button
          onClick={() => setActiveTab('scorecard')}
          className={`btn btn-sm ${activeTab === 'scorecard' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <BarChart3 size={15} /> Intelligence Scorecard
        </button>
      </div>

      {/* TAB 1: FINDINGS TABLE */}
      {activeTab === 'findings' && (
        <div className="card">
          <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-4)' }}>
            <div>
              <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, margin: 0 }}>
                Discovered Findings ({filteredFindings.length})
              </h2>
            </div>

            <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center', flexWrap: 'wrap' }}>
              {/* Filter by Category */}
              <div style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                {categories.map(cat => (
                  <button
                    key={cat}
                    onClick={() => setSelectedCategory(cat)}
                    className={`btn btn-xs ${selectedCategory === cat ? 'btn-primary' : 'btn-ghost'}`}
                    style={{ textTransform: 'capitalize' }}
                  >
                    {cat.replace('_', ' ')}
                  </button>
                ))}
              </div>

              {/* Search Input */}
              <input
                type="text"
                className="input input-sm"
                placeholder="Search findings..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                style={{ width: '180px' }}
              />
            </div>
          </div>

          <div className="card-body" style={{ padding: 0 }}>
            {filteredFindings.length === 0 ? (
              <div style={{ padding: 'var(--space-12)', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                No findings matched the selected criteria.
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="table" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th style={{ width: '120px' }}>Category</th>
                      <th style={{ width: '140px' }}>Type</th>
                      <th>Value</th>
                      <th style={{ width: '100px' }}>Severity</th>
                      <th style={{ width: '100px' }}>Confidence</th>
                      <th style={{ width: '160px' }}>Source</th>
                      <th style={{ width: '90px' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFindings.map(f => {
                      const isExpanded = expandedFinding === f.id;
                      const pivot = detectPivotTarget(f);
                      return (
                        <>
                          <tr key={f.id} style={{ cursor: 'pointer' }} onClick={() => setExpandedFinding(isExpanded ? null : f.id)}>
                            <td>
                              <span className="badge badge-neutral" style={{ textTransform: 'capitalize' }}>
                                {f.category.replace('_', ' ')}
                              </span>
                            </td>
                            <td style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)' }}>
                              {f.type}
                            </td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', wordBreak: 'break-all' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                                <span>{f.value}</span>
                                {f.source_url && (
                                  <a
                                    href={f.source_url}
                                    target="_blank"
                                    rel="noreferrer"
                                    onClick={(e) => e.stopPropagation()}
                                    title="Open source URL in new tab"
                                    style={{ color: 'var(--color-accent)', display: 'inline-flex' }}
                                  >
                                    <ExternalLink size={13} />
                                  </a>
                                )}
                              </div>
                              {f.notes && (
                                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', fontFamily: 'var(--font-sans)', marginTop: 2 }}>
                                  {f.notes}
                                </div>
                              )}
                              {f.category === 'location_intelligence' && (
                                <div style={{ marginTop: '6px', display: 'flex', gap: '8px', alignItems: 'center' }}>
                                  <a
                                    href={f.source_url || `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(f.value)}`}
                                    target="_blank"
                                    rel="noreferrer"
                                    onClick={(e) => e.stopPropagation()}
                                    className="btn btn-xs"
                                    style={{
                                      background: '#fff1f2',
                                      color: '#e11d48',
                                      border: '1px solid #fecdd3',
                                      fontWeight: 600,
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '4px',
                                      padding: '2px 8px'
                                    }}
                                  >
                                    <MapPin size={12} /> Open in Google Maps
                                  </a>
                                </div>
                              )}
                            </td>
                            <td>{getSeverityBadge(f.severity)}</td>
                            <td>
                              <span style={{ fontSize: 'var(--text-xs)', textTransform: 'capitalize' }}>
                                {f.confidence}
                              </span>
                            </td>
                            <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)' }}>
                              {f.source_name}
                            </td>
                            <td style={{ textAlign: 'center' }}>
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 'var(--space-2)' }}>
                                {pivot && (
                                  <Link
                                    to={`/investigate?q=${encodeURIComponent(pivot.target)}`}
                                    onClick={(e) => e.stopPropagation()}
                                    className="btn btn-xs btn-ghost"
                                    title={`Pivot to new investigation on ${pivot.target}`}
                                    style={{ color: 'var(--color-accent)' }}
                                  >
                                    <CornerUpRight size={14} />
                                  </Link>
                                )}
                                {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                              </div>
                            </td>
                          </tr>

                          {isExpanded && (
                            <tr key={`${f.id}-expanded`} style={{ background: 'var(--color-surface-elevated)' }}>
                              <td colSpan={7} style={{ padding: 'var(--space-4) var(--space-6)' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
                                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
                                    RAW ARTIFACT DATA (FIRST SEEN: {new Date(f.first_seen).toLocaleString()})
                                  </div>
                                  <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                                    {pivot && (
                                      <Link
                                        to={`/investigate?q=${encodeURIComponent(pivot.target)}`}
                                        className="btn btn-xs btn-primary"
                                        style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                      >
                                        <CornerUpRight size={12} /> Pivot to {pivot.target}
                                      </Link>
                                    )}
                                    <button
                                      onClick={() => handleCopyRaw(typeof f.raw_data === 'string' ? f.raw_data : JSON.stringify(f.raw_data, null, 2), f.id)}
                                      className="btn btn-xs btn-ghost"
                                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                    >
                                      {copiedId === f.id ? <Check size={12} /> : <Copy size={12} />}
                                      {copiedId === f.id ? 'Copied' : 'Copy JSON'}
                                    </button>
                                  </div>
                                </div>
                                <pre style={{
                                  margin: 0,
                                  padding: 'var(--space-3)',
                                  background: 'var(--color-surface)',
                                  borderRadius: 'var(--radius)',
                                  border: '1px solid var(--color-border)',
                                  fontSize: '11px',
                                  overflowX: 'auto',
                                }}>
                                  {(() => {
                                    try {
                                      return JSON.stringify(typeof f.raw_data === 'string' ? JSON.parse(f.raw_data) : f.raw_data, null, 2);
                                    } catch {
                                      return String(f.raw_data);
                                    }
                                  })()}
                                </pre>
                              </td>
                            </tr>
                          )}
                        </>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: CHRONOLOGICAL TIMELINE */}
      {activeTab === 'timeline' && (
        <div className="card" style={{ padding: 'var(--space-6)' }}>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginBottom: 'var(--space-6)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Clock size={20} style={{ color: 'var(--color-accent)' }} /> Chronological Intelligence Timeline
          </h2>

          <div style={{ position: 'relative', paddingLeft: 'var(--space-6)', borderLeft: '2px solid var(--color-border)' }}>
            {timelineEvents.map((evt) => (
              <div key={evt.id} style={{ position: 'relative', marginBottom: 'var(--space-6)' }}>
                {/* Timeline node dot */}
                <div style={{
                  position: 'absolute',
                  left: 'calc(-1 * var(--space-6) - 5px)',
                  top: '4px',
                  width: '10px',
                  height: '10px',
                  borderRadius: '50%',
                  background: evt.severity === 'critical' || evt.severity === 'high' ? 'var(--color-error)' : 'var(--color-accent)',
                  boxShadow: '0 0 0 3px var(--color-bg)',
                }} />

                <div style={{
                  background: 'var(--color-bg)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius)',
                  padding: 'var(--space-4)',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                      <span className="badge badge-neutral" style={{ textTransform: 'capitalize', fontSize: '11px' }}>
                        {evt.category.replace('_', ' ')}
                      </span>
                      <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--color-dark)' }}>
                        {evt.type}
                      </strong>
                    </div>
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {new Date(evt.timestamp).toLocaleDateString()} {new Date(evt.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', color: 'var(--color-text-primary)', wordBreak: 'break-all' }}>
                    {evt.value}
                  </div>

                  {evt.notes && (
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginTop: 'var(--space-2)' }}>
                      {evt.notes}
                    </div>
                  )}

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 'var(--space-3)', fontSize: '11px', color: 'var(--color-text-muted)' }}>
                    <span>Source: {evt.source}</span>
                    {evt.sourceUrl && (
                      <a href={evt.sourceUrl} target="_blank" rel="noreferrer" style={{ color: 'var(--color-accent)', display: 'inline-flex', alignItems: 'center', gap: '3px' }}>
                        Source artifact <ExternalLink size={11} />
                      </a>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: INTELLIGENCE SCORECARD */}
      {activeTab === 'scorecard' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 'var(--space-6)' }}>
          {/* Exposure Gauge Card */}
          <div className="card" style={{ padding: 'var(--space-6)', textAlign: 'center' }}>
            <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: 'var(--space-4)' }}>
              Public Exposure & Surface Score
            </h3>
            <div style={{
              fontSize: '48px',
              fontWeight: 900,
              color: scorecard.exposureScore >= 75 ? 'var(--color-accent)' : scorecard.exposureScore >= 40 ? 'var(--color-warning)' : 'var(--color-text-primary)',
              lineHeight: 1,
              marginBottom: 'var(--space-2)',
            }}>
              {scorecard.exposureScore}/100
            </div>
            <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-dark)', marginBottom: 'var(--space-4)' }}>
              {scorecard.attributionLevel}
            </div>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
              Calculated based on verified Git commits, cross-platform usernames, published public emails, historical archives, and public infrastructure exposure.
            </p>
          </div>

          {/* Footprint Breakdown */}
          <div className="card" style={{ padding: 'var(--space-6)' }}>
            <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: 'var(--space-4)' }}>
              Discovered Entity Breakdown
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Verified Developer Commits</span>
                <strong style={{ color: 'var(--color-dark)' }}>{scorecard.commitsFound}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Correlated Email Identifiers</span>
                <strong style={{ color: 'var(--color-dark)' }}>{scorecard.emailsFound}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Social & Registry Profiles</span>
                <strong style={{ color: 'var(--color-dark)' }}>{scorecard.profilesFound}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Infrastructure & DNS Records</span>
                <strong style={{ color: 'var(--color-dark)' }}>{scorecard.infraFound}</strong>
              </div>
              {scorecard.portsAndCvesFound > 0 && (
                <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Ports & Vulnerabilities (Shodan)</span>
                  <strong style={{ color: 'var(--color-error)' }}>{scorecard.portsAndCvesFound}</strong>
                </div>
              )}
              {scorecard.locationsFound > 0 && (
                <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Geocoded Places & Coordinates</span>
                  <strong style={{ color: 'var(--color-accent)' }}>{scorecard.locationsFound}</strong>
                </div>
              )}
              {scorecard.phoneFound > 0 && (
                <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>E.164 Telephony & OSINT Dorks</span>
                  <strong style={{ color: 'var(--color-accent)' }}>{scorecard.phoneFound}</strong>
                </div>
              )}
              {scorecard.securityScore && (
                <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Defensive Hygiene Posture</span>
                  <strong style={{ color: 'var(--color-dark)', fontSize: '12px' }}>{scorecard.securityScore}</strong>
                </div>
              )}
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Compromised Breach Records</span>
                <strong style={{ color: scorecard.breachesFound > 0 ? 'var(--color-error)' : 'var(--color-dark)' }}>{scorecard.breachesFound}</strong>
              </div>
            </div>
          </div>

          {/* Threat & Severity Distribution */}
          <div className="card" style={{ padding: 'var(--space-6)' }}>
            <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: 'var(--space-4)' }}>
              Severity & Risk Distribution
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
              <div style={{ padding: 'var(--space-3)', background: 'var(--color-bg)', borderRadius: 'var(--radius)', border: '1px solid var(--color-border)' }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Critical / High</div>
                <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: 'var(--color-error)' }}>
                  {scorecard.criticalCount + scorecard.highCount}
                </div>
              </div>
              <div style={{ padding: 'var(--space-3)', background: 'var(--color-bg)', borderRadius: 'var(--radius)', border: '1px solid var(--color-border)' }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Medium / Low</div>
                <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: 'var(--color-warning)' }}>
                  {scorecard.mediumCount}
                </div>
              </div>
              <div style={{ gridColumn: 'span 2', padding: 'var(--space-3)', background: 'var(--color-bg)', borderRadius: 'var(--radius)', border: '1px solid var(--color-border)' }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Total Intelligence Artifacts</div>
                <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: 'var(--color-accent)' }}>
                  {scorecard.total}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
