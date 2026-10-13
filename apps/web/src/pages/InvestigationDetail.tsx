import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  AlertTriangle, GitBranch, RefreshCw, Sparkles,
  FileText, ChevronDown, ChevronRight
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
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    if (!id) return;
    try {
      const [invRes, findRes] = await Promise.all([
        api.getInvestigation(id),
        api.getFindings(id, undefined, 1, 200),
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
                {investigation.target_type}
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
          Collector Execution Status
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 'var(--space-3)' }}>
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
                  {exec.collector_name}
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

      {/* Findings Section */}
      <div className="card">
        <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-4)' }}>
          <div>
            <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, margin: 0 }}>
              Discovered Findings ({findings.length})
            </h2>
          </div>

          <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center', flexWrap: 'wrap' }}>
            {/* Filter by Category */}
            <div style={{ display: 'flex', gap: 'var(--space-1)' }}>
              {categories.map(cat => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`btn btn-xs ${selectedCategory === cat ? 'btn-primary' : 'btn-ghost'}`}
                  style={{ textTransform: 'capitalize' }}
                >
                  {cat}
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
                    <th style={{ width: '60px' }}></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map(f => {
                    const isExpanded = expandedFinding === f.id;
                    return (
                      <>
                        <tr key={f.id} style={{ cursor: 'pointer' }} onClick={() => setExpandedFinding(isExpanded ? null : f.id)}>
                          <td>
                            <span className="badge badge-neutral" style={{ textTransform: 'capitalize' }}>
                              {f.category}
                            </span>
                          </td>
                          <td style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)' }}>
                            {f.type}
                          </td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', wordBreak: 'break-all' }}>
                            {f.value}
                            {f.notes && (
                              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', fontFamily: 'var(--font-sans)', marginTop: 2 }}>
                                {f.notes}
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
                            {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                          </td>
                        </tr>

                        {isExpanded && (
                          <tr key={`${f.id}-expanded`} style={{ background: 'var(--color-surface-elevated)' }}>
                            <td colSpan={7} style={{ padding: 'var(--space-4) var(--space-6)' }}>
                              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginBottom: 'var(--space-2)' }}>
                                RAW ARTIFACT DATA (FIRST SEEN: {new Date(f.first_seen).toLocaleString()})
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
                                    return JSON.stringify(JSON.parse(f.raw_data), null, 2);
                                  } catch {
                                    return f.raw_data;
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
    </div>
  );
}
