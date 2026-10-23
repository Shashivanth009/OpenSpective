import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  History, Search, RefreshCw, PlusCircle,
  ChevronLeft, ChevronRight, Trash2, AlertTriangle, Check
} from 'lucide-react';
import * as api from '../api.ts';

export default function HistoryPage() {
  const [investigations, setInvestigations] = useState<api.Investigation[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [searchFilter, setSearchFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [isClearingAll, setIsClearingAll] = useState(false);
  const [showClearModal, setShowClearModal] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const pageSize = 15;

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listInvestigations(page, pageSize);
      setInvestigations(res.data);
      setTotal(res.total);
      setHasMore(res.hasMore);
    } catch (err: any) {
      setError(err?.message || 'Failed to load investigation history.');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteSingle = async (id: string, targetName: string) => {
    if (!window.confirm(`Delete investigation for "${targetName}" (${id})? This will permanently remove all findings and records.`)) {
      return;
    }
    setDeletingId(id);
    try {
      await api.deleteInvestigation(id);
      setInvestigations(prev => prev.filter(inv => inv.id !== id));
      setTotal(prev => Math.max(0, prev - 1));
      showToast(`Investigation for "${targetName}" deleted.`);
    } catch (err: any) {
      setError(err?.message || 'Failed to delete investigation.');
    } finally {
      setDeletingId(null);
    }
  };

  const handleClearAll = async () => {
    setIsClearingAll(true);
    setError(null);
    try {
      const res = await api.clearAllInvestigations();
      setInvestigations([]);
      setTotal(0);
      setHasMore(false);
      setShowClearModal(false);
      showToast(res.message || 'All reconnaissance history has been permanently wiped.');
    } catch (err: any) {
      setError(err?.message || 'Failed to clear investigation history.');
    } finally {
      setIsClearingAll(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [page]);

  const filtered = investigations.filter(inv => {
    const matchesSearch = !searchFilter ||
      inv.target.toLowerCase().includes(searchFilter.toLowerCase()) ||
      inv.id.toLowerCase().includes(searchFilter.toLowerCase());
    const matchesStatus = statusFilter === 'all' || inv.status === statusFilter;
    const matchesType = typeFilter === 'all' || inv.target_type === typeFilter;
    return matchesSearch && matchesStatus && matchesType;
  });

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

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto', padding: 'var(--space-6) var(--space-8)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-8)', flexWrap: 'wrap', gap: 'var(--space-4)' }}>
        <div>
          <h1 style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, color: 'var(--color-dark)', letterSpacing: '-0.03em' }}>
            Reconnaissance History
          </h1>
          <p style={{ color: 'var(--color-text-secondary)', marginTop: 'var(--space-1)', fontSize: 'var(--text-base)' }}>
            Complete audit trail of passive OSINT inquiries and generated intelligence.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center' }}>
          <button onClick={fetchHistory} className="btn btn-ghost btn-sm">
            <RefreshCw size={15} /> Refresh
          </button>
          {investigations.length > 0 && (
            <button
              onClick={() => setShowClearModal(true)}
              className="btn btn-danger btn-sm"
              style={{ background: 'rgba(239, 68, 68, 0.12)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.3)' }}
              title="Delete all investigation history"
            >
              <Trash2 size={15} /> Clear All History
            </button>
          )}
          <Link to="/investigate" className="btn btn-primary btn-sm">
            <PlusCircle size={15} /> New Scan
          </Link>
        </div>
      </div>

      {/* Floating Feedback Toast */}
      {toastMessage && (
        <div style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          background: 'rgba(16, 185, 129, 0.95)',
          color: '#ffffff',
          padding: '10px 18px',
          borderRadius: 'var(--radius-lg)',
          boxShadow: '0 8px 30px rgba(0,0,0,0.3)',
          zIndex: 9999,
          fontSize: '13px',
          fontWeight: 600,
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
        }}>
          <Check size={16} /> {toastMessage}
        </div>
      )}

      {error && (
        <div className="alert alert-error" style={{ marginBottom: 'var(--space-6)' }}>
          {error}
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="card" style={{ marginBottom: 'var(--space-6)', padding: 'var(--space-4)' }}>
        <div style={{ display: 'flex', gap: 'var(--space-4)', alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: 1, minWidth: '240px' }}>
            <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
            <input
              type="text"
              className="input input-sm"
              placeholder="Search targets or investigation IDs..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              style={{ paddingLeft: '38px', width: '100%' }}
            />
          </div>

          <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Status:</span>
            <select
              className="input input-sm"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              style={{ width: '130px' }}
            >
              <option value="all">All Statuses</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="partial">Partial</option>
              <option value="failed">Failed</option>
            </select>
          </div>

          <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Type:</span>
            <select
              className="input input-sm"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              style={{ width: '140px' }}
            >
              <option value="all">All Types</option>
              <option value="domain">Domain</option>
              <option value="ip">IP Address</option>
              <option value="email">Email</option>
              <option value="url">URL</option>
              <option value="username">Username</option>
              <option value="organization">Organization</option>
            </select>
          </div>
        </div>
      </div>

      {/* History Table */}
      <div className="card">
        <div className="card-body" style={{ padding: 0 }}>
          {loading ? (
            <div style={{ padding: 'var(--space-12)', textAlign: 'center', color: 'var(--color-text-muted)' }}>
              <span className="spinner" style={{ marginRight: 'var(--space-2)' }} /> Loading past inquiries...
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: 'var(--space-12)', textAlign: 'center' }}>
              <History size={40} style={{ margin: '0 auto var(--space-4)', color: 'var(--color-accent-soft)' }} />
              <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-dark)' }}>No records match</h3>
              <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--text-sm)', maxWidth: '400px', margin: 'var(--space-2) auto' }}>
                Try adjusting your search query or launch a new investigation.
              </p>
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
                    <th>Completed</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(inv => (
                    <tr key={inv.id}>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--color-dark)' }}>
                          <Link to={`/investigations/${inv.id}`} style={{ textDecoration: 'none', color: 'inherit' }}>
                            {inv.target}
                          </Link>
                        </div>
                        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {inv.id}
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
                      <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)' }}>
                        {inv.completed_at ? new Date(inv.completed_at).toLocaleString() : '—'}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end', alignItems: 'center' }}>
                          <Link to={`/investigations/${inv.id}`} className="btn btn-secondary btn-sm" style={{ padding: '4px 10px' }}>
                            Details
                          </Link>
                          <Link to={`/investigations/${inv.id}/graph`} className="btn btn-ghost btn-sm" style={{ padding: '4px 10px' }}>
                            Graph
                          </Link>
                          <button
                            onClick={() => handleDeleteSingle(inv.id, inv.target)}
                            disabled={deletingId === inv.id}
                            className="btn btn-ghost btn-sm"
                            style={{ padding: '4px 8px', color: '#ef4444' }}
                            title="Permanently delete this investigation"
                          >
                            {deletingId === inv.id ? (
                              <span className="spinner" style={{ width: 13, height: 13 }} />
                            ) : (
                              <Trash2 size={14} />
                            )}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Pagination Bar */}
        <div style={{
          padding: 'var(--space-4) var(--space-6)',
          borderTop: '1px solid var(--color-border)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: 'var(--text-xs)',
          color: 'var(--color-text-secondary)',
        }}>
          <div>
            Showing page {page} {total > 0 && `(Total: ${total})`}
          </div>
          <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="btn btn-ghost btn-xs"
            >
              <ChevronLeft size={14} /> Previous
            </button>
            <button
              onClick={() => setPage(p => p + 1)}
              disabled={!hasMore}
              className="btn btn-ghost btn-xs"
            >
              Next <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Clear All Confirmation Modal */}
      {showClearModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 10000,
          padding: 'var(--space-4)',
        }}>
          <div className="card glass-panel" style={{ maxWidth: '480px', width: '100%', padding: 'var(--space-6)', border: '1px solid rgba(239, 68, 68, 0.4)', boxShadow: '0 20px 50px rgba(0,0,0,0.5)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-4)', color: '#ef4444' }}>
              <AlertTriangle size={28} />
              <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 800, margin: 0 }}>Permanently Wipe All History?</h2>
            </div>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: 'var(--space-6)' }}>
              This will permanently delete all {total} reconnaissance investigations, including all OSINT collector telemetry, discovered findings, STIX artifacts, and relationship graphs. This action cannot be reversed.
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-3)' }}>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setShowClearModal(false)}
                disabled={isClearingAll}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-danger btn-sm"
                onClick={handleClearAll}
                disabled={isClearingAll}
                style={{ background: '#ef4444', color: 'white' }}
              >
                {isClearingAll ? (
                  <>
                    <span className="spinner" style={{ width: 14, height: 14 }} /> Wiping Everything...
                  </>
                ) : (
                  <>
                    <Trash2 size={15} /> Yes, Delete All History
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
