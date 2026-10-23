import { useState, useEffect, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import ReactFlow, {
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  MarkerType,
  type Node,
  type Edge
} from 'reactflow';
import 'reactflow/dist/style.css';
import { GitBranch, ArrowLeft, RefreshCw, AlertCircle, MapPin, ExternalLink } from 'lucide-react';
import * as api from '../api.ts';

// Color map for node types
const NODE_TYPE_COLORS: Record<string, string> = {
  domain: '#609966',
  subdomain: '#9DC08B',
  ip: '#2563eb',
  certificate: '#c07a20',
  organization: '#7c3aed',
  repository: '#40513B',
  email: '#0891b2',
  location: '#e11d48',
  crypto_wallet: '#f59e0b',
  person: '#9333ea',
  username: '#0284c7',
  url: '#4b5563',
  unknown: '#9ca3af',
};

export default function GraphPage() {
  const { id } = useParams<{ id: string }>();
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [rawGraph, setRawGraph] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [filterType, setFilterType] = useState('all');

  const fetchGraphData = async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.getGraph(id);
      setRawGraph(data);

      // Layout nodes radially / grid
      const count = data.nodes.length;
      const angleStep = (2 * Math.PI) / (count || 1);
      const radius = Math.max(220, count * 35);

      const flowNodes: Node[] = data.nodes.map((n, idx) => {
        // Target or center node
        const isRoot = idx === 0;
        const x = isRoot ? 400 : 400 + Math.cos(idx * angleStep) * radius;
        const y = isRoot ? 300 : 300 + Math.sin(idx * angleStep) * radius;
        const color = NODE_TYPE_COLORS[n.type.toLowerCase()] || '#609966';

        const isLocation = n.type.toLowerCase() === 'location';

        return {
          id: n.id,
          type: 'default',
          position: { x, y },
          data: {
            label: (
              <div style={{ textAlign: 'center', padding: '4px' }}>
                <div style={{
                  fontSize: '10px',
                  textTransform: 'uppercase',
                  color: isLocation ? '#e11d48' : '#6b7280',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '4px'
                }}>
                  {isLocation && <MapPin size={11} />}
                  {n.type}
                </div>
                <div style={{ fontSize: '12px', fontWeight: 600, color: '#111827', wordBreak: 'break-all' }}>
                  {n.label || n.value}
                </div>
              </div>
            ),
            raw: n,
          },
          style: {
            background: '#ffffff',
            border: `2px solid ${color}`,
            borderRadius: '10px',
            boxShadow: '0 4px 12px rgba(0,0,0,0.08)',
            padding: '6px 12px',
            minWidth: '120px',
            cursor: 'pointer',
          },
        };
      });

      const flowEdges: Edge[] = data.edges.map(e => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label || e.type,
        type: 'smoothstep',
        markerEnd: { type: MarkerType.ArrowClosed, color: '#9ca3af' },
        style: { stroke: '#9ca3af', strokeWidth: 1.5 },
        labelStyle: { fill: '#4b5563', fontSize: 10, fontWeight: 500 },
        data: e,
      }));

      setNodes(flowNodes);
      setEdges(flowEdges);
    } catch (err: any) {
      setError(err?.message || 'Failed to load correlation graph.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraphData();
  }, [id]);

  const onNodeClick = (_: any, node: Node) => {
    setSelectedNode(node.data.raw);
  };

  const nodeTypes = useMemo(() => {
    if (!rawGraph?.nodes) return ['all'];
    return ['all', ...Array.from(new Set(rawGraph.nodes.map((n: any) => n.type)))];
  }, [rawGraph]);

  return (
    <div style={{ height: 'calc(100vh - 65px)', display: 'flex', flexDirection: 'column', background: 'var(--color-bg)' }}>
      {/* Top Bar */}
      <div style={{
        padding: 'var(--space-3) var(--space-6)',
        background: 'var(--color-surface)',
        borderBottom: '1px solid var(--color-border)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 'var(--space-3)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
          <Link to={`/investigations/${id}`} className="btn btn-ghost btn-sm">
            <ArrowLeft size={16} /> Investigation Details
          </Link>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <GitBranch size={18} style={{ color: 'var(--color-accent)' }} />
            <h1 style={{ fontSize: 'var(--text-base)', fontWeight: 700, margin: 0, color: 'var(--color-dark)' }}>
              Entity Correlation Graph
            </h1>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          {/* Node Type Filter */}
          <div style={{ display: 'flex', gap: 'var(--space-1)' }}>
            {nodeTypes.slice(0, 5).map((t: any) => (
              <button
                key={t}
                onClick={() => setFilterType(t)}
                className={`btn btn-xs ${filterType === t ? 'btn-primary' : 'btn-ghost'}`}
                style={{ textTransform: 'capitalize' }}
              >
                {t}
              </button>
            ))}
          </div>

          <button onClick={fetchGraphData} className="btn btn-ghost btn-sm" title="Re-center layout">
            <RefreshCw size={15} />
          </button>
        </div>
      </div>

      {/* Main Graph Area */}
      <div style={{ flex: 1, position: 'relative' }}>
        {loading ? (
          <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center' }}>
            <span className="spinner" style={{ width: 32, height: 32 }} />
          </div>
        ) : error ? (
          <div style={{ maxWidth: '600px', margin: 'var(--space-12) auto', padding: 'var(--space-6)' }}>
            <div className="alert alert-error">
              <AlertCircle size={18} />
              <span>{error}</span>
            </div>
          </div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            fitView
          >
            <MiniMap
              nodeColor={(n) => NODE_TYPE_COLORS[n.data?.raw?.type?.toLowerCase()] || '#609966'}
              style={{ background: '#f8faf4' }}
            />
            <Controls />
            <Background gap={16} size={1} color="#d6ddb7" />
          </ReactFlow>
        )}

        {/* Selected Node Drawer */}
        {selectedNode && (
          <div style={{
            position: 'absolute',
            top: '20px',
            right: '20px',
            width: '340px',
            background: 'var(--color-surface)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius)',
            boxShadow: 'var(--shadow-lg)',
            padding: 'var(--space-5)',
            zIndex: 10,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-3)' }}>
              <span
                className="badge"
                style={{
                  textTransform: 'capitalize',
                  backgroundColor: `${NODE_TYPE_COLORS[selectedNode.type?.toLowerCase()] || '#6b7280'}20`,
                  color: NODE_TYPE_COLORS[selectedNode.type?.toLowerCase()] || '#374151',
                  border: `1px solid ${NODE_TYPE_COLORS[selectedNode.type?.toLowerCase()] || '#d1d5db'}`,
                  fontWeight: 700,
                }}
              >
                {selectedNode.type}
              </span>
              <button
                onClick={() => setSelectedNode(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '18px', color: 'var(--color-text-muted)' }}
              >
                ×
              </button>
            </div>

            <div style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-dark)', wordBreak: 'break-all', marginBottom: 'var(--space-2)' }}>
              {selectedNode.value || selectedNode.label}
            </div>

            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginBottom: 'var(--space-4)' }}>
              Entity Identifier: <code>{selectedNode.id}</code>
            </div>

            {/* Location Specific Map Actions */}
            {selectedNode.type?.toLowerCase() === 'location' && (
              <div style={{
                background: '#fff1f2',
                border: '1px solid #fecdd3',
                borderRadius: 'var(--radius)',
                padding: 'var(--space-3)',
                marginBottom: 'var(--space-4)'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: 'var(--text-xs)', fontWeight: 700, color: '#be123c', marginBottom: 'var(--space-2)' }}>
                  <MapPin size={14} /> Physical Geolocation Clue
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <a
                    href={`https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(selectedNode.value || selectedNode.label)}`}
                    target="_blank"
                    rel="noreferrer"
                    className="btn btn-sm"
                    style={{ background: '#e11d48', color: '#ffffff', border: 'none', justifyContent: 'center' }}
                  >
                    <ExternalLink size={14} /> Open in Google Maps
                  </a>
                  <a
                    href={`https://www.openstreetmap.org/search?query=${encodeURIComponent(selectedNode.value || selectedNode.label)}`}
                    target="_blank"
                    rel="noreferrer"
                    className="btn btn-ghost btn-sm"
                    style={{ justifyContent: 'center', color: '#be123c' }}
                  >
                    Open in OpenStreetMap
                  </a>
                </div>
              </div>
            )}

            {/* URL specific actions */}
            {selectedNode.type?.toLowerCase() === 'url' && (
              <div style={{ marginBottom: 'var(--space-4)' }}>
                <a
                  href={selectedNode.value || selectedNode.label}
                  target="_blank"
                  rel="noreferrer"
                  className="btn btn-secondary btn-sm"
                  style={{ width: '100%', justifyContent: 'center' }}
                >
                  <ExternalLink size={14} /> Visit Discovered URL
                </a>
              </div>
            )}

            <div style={{ borderTop: '1px solid var(--color-border)', paddingTop: 'var(--space-3)' }}>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: 'var(--space-2)' }}>
                ATTRIBUTION & EDGES
              </div>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', margin: 0, lineHeight: 1.5 }}>
                Directly associated in the investigation corpus. Relationships are strictly grounded in public records and verified across open OSINT platforms.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
