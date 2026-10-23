import { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import ReactFlow, {
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  MarkerType,
  type Node,
  type Edge,
  useReactFlow,
  ReactFlowProvider,
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  GitBranch, ArrowLeft, RefreshCw, AlertCircle, MapPin, ExternalLink,
  Search, Filter, Layers, Download, X, Maximize2, Globe, Server, Mail,
  User, ShieldAlert, Key, Cpu, Database, Building2, Link2, Eye
} from 'lucide-react';
import * as api from '../api.ts';

// Curated harmonious color palette for entity node types
const NODE_TYPE_COLORS: Record<string, string> = {
  domain: '#10b981',
  subdomain: '#34d399',
  ip: '#3b82f6',
  certificate: '#f59e0b',
  organization: '#8b5cf6',
  repository: '#059669',
  email: '#06b6d4',
  location: '#f43f5e',
  crypto_wallet: '#eab308',
  person: '#a855f7',
  username: '#0284c7',
  url: '#64748b',
  asn: '#6366f1',
  threat_ioc: '#ef4444',
  cloud_bucket: '#38bdf8',
  unknown: '#94a3b8',
};

// Node icon helper for category banners
const getNodeIcon = (type: string) => {
  switch (type?.toLowerCase()) {
    case 'domain':
    case 'subdomain': return <Globe size={11} />;
    case 'ip': return <Server size={11} />;
    case 'email': return <Mail size={11} />;
    case 'username':
    case 'person': return <User size={11} />;
    case 'location': return <MapPin size={11} />;
    case 'organization': return <Building2 size={11} />;
    case 'threat_ioc': return <ShieldAlert size={11} />;
    case 'repository': return <Database size={11} />;
    case 'url': return <Link2 size={11} />;
    case 'crypto_wallet': return <Key size={11} />;
    default: return <Cpu size={11} />;
  }
};

type LayoutType = 'radial' | 'concentric' | 'hierarchy' | 'grid';

function GraphViewInner() {
  const { id } = useParams<{ id: string }>();
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [rawGraph, setRawGraph] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [hoveredNode, setHoveredNode] = useState<{ raw: any; x: number; y: number } | null>(null);
  const [filterType, setFilterType] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [layout, setLayout] = useState<LayoutType>('radial');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const reactFlowInstance = useReactFlow();

  const fetchGraphData = async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.getGraph(id);
      setRawGraph(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load correlation graph.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraphData();
  }, [id]);

  // Compute 1-hop connected neighbors of selectedNode
  const connectedNeighborIds = useMemo(() => {
    if (!selectedNode || !rawGraph?.edges) return new Set<string>();
    const set = new Set<string>();
    set.add(selectedNode.id);
    for (const e of rawGraph.edges) {
      if (e.source === selectedNode.id) set.add(e.target);
      if (e.target === selectedNode.id) set.add(e.source);
    }
    return set;
  }, [selectedNode, rawGraph]);

  // Compute degree connections for every node
  const nodeConnectionMap = useMemo(() => {
    const map = new Map<string, number>();
    if (!rawGraph?.edges) return map;
    for (const e of rawGraph.edges) {
      map.set(e.source, (map.get(e.source) || 0) + 1);
      map.set(e.target, (map.get(e.target) || 0) + 1);
    }
    return map;
  }, [rawGraph?.edges]);

  // Calculate distinct node types with counts
  const nodeTypeStats = useMemo(() => {
    if (!rawGraph?.nodes) return { all: 0 };
    const counts: Record<string, number> = { all: rawGraph.nodes.length };
    for (const n of rawGraph.nodes) {
      const t = n.type || 'unknown';
      counts[t] = (counts[t] || 0) + 1;
    }
    return counts;
  }, [rawGraph]);

  // Filter raw nodes by category and search query
  const filteredRawNodes = useMemo(() => {
    if (!rawGraph?.nodes) return [];
    return rawGraph.nodes.filter((n: any) => {
      const matchesType = filterType === 'all' || n.type?.toLowerCase() === filterType.toLowerCase();
      const matchesSearch = !searchQuery.trim() ||
        (n.label || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        (n.value || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        (n.type || '').toLowerCase().includes(searchQuery.toLowerCase());
      return matchesType && matchesSearch;
    });
  }, [rawGraph, filterType, searchQuery]);

  // Layout algorithm calculation
  const layoutedPositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    const count = filteredRawNodes.length;
    if (count === 0) return positions;

    if (layout === 'radial') {
      const angleStep = (2 * Math.PI) / (count > 1 ? count - 1 : 1);
      const radius = Math.max(240, count * 36);
      let nonRootIndex = 0;

      filteredRawNodes.forEach((n: any, idx: number) => {
        if (idx === 0) {
          positions[n.id] = { x: 500, y: 350 };
        } else {
          positions[n.id] = {
            x: 500 + Math.cos(nonRootIndex * angleStep) * radius,
            y: 350 + Math.sin(nonRootIndex * angleStep) * radius,
          };
          nonRootIndex++;
        }
      });
    } else if (layout === 'concentric') {
      // Group into inner ring (high priority / infrastructure) and outer ring
      const innerTypes = new Set(['domain', 'email', 'ip', 'person', 'username']);
      const innerNodes: any[] = [];
      const outerNodes: any[] = [];

      filteredRawNodes.forEach((n: any, idx: number) => {
        if (idx === 0) return;
        if (innerTypes.has(n.type?.toLowerCase())) innerNodes.push(n);
        else outerNodes.push(n);
      });

      if (filteredRawNodes[0]) {
        positions[filteredRawNodes[0].id] = { x: 500, y: 350 };
      }

      const innerRadius = 220;
      const innerStep = (2 * Math.PI) / (innerNodes.length || 1);
      innerNodes.forEach((n, idx) => {
        positions[n.id] = {
          x: 500 + Math.cos(idx * innerStep) * innerRadius,
          y: 350 + Math.sin(idx * innerStep) * innerRadius,
        };
      });

      const outerRadius = Math.max(420, innerRadius + outerNodes.length * 20);
      const outerStep = (2 * Math.PI) / (outerNodes.length || 1);
      outerNodes.forEach((n, idx) => {
        positions[n.id] = {
          x: 500 + Math.cos(idx * outerStep) * outerRadius,
          y: 350 + Math.sin(idx * outerStep) * outerRadius,
        };
      });
    } else if (layout === 'hierarchy') {
      // Hierarchical levels: Level 0: root, Level 1: domain/ip/user, Level 2: others
      const levels: Record<number, any[]> = { 0: [], 1: [], 2: [] };
      filteredRawNodes.forEach((n: any, idx: number) => {
        if (idx === 0) levels[0].push(n);
        else if (['domain', 'ip', 'email', 'organization', 'person'].includes(n.type?.toLowerCase())) levels[1].push(n);
        else levels[2].push(n);
      });

      const yOffset = 180;
      [0, 1, 2].forEach(lvl => {
        const row = levels[lvl] || [];
        const width = row.length * 220;
        const startX = 500 - width / 2;
        row.forEach((n, idx) => {
          positions[n.id] = {
            x: startX + idx * 220 + 110,
            y: 120 + lvl * yOffset,
          };
        });
      });
    } else {
      // Grid Layout
      const cols = Math.ceil(Math.sqrt(count * 1.5));
      const colWidth = 240;
      const rowHeight = 120;
      filteredRawNodes.forEach((n: any, idx: number) => {
        const col = idx % cols;
        const row = Math.floor(idx / cols);
        positions[n.id] = {
          x: 100 + col * colWidth,
          y: 100 + row * rowHeight,
        };
      });
    }

    return positions;
  }, [filteredRawNodes, layout]);

  // Construct Flow Nodes with modern color blocks
  const flowNodes: Node[] = useMemo(() => {
    return filteredRawNodes.map((n: any, idx: number) => {
      const isRoot = idx === 0 && filterType === 'all' && !searchQuery.trim();
      const pos = layoutedPositions[n.id] || { x: 400, y: 300 };
      const color = NODE_TYPE_COLORS[n.type?.toLowerCase()] || '#10b981';

      const isSelected = selectedNode?.id === n.id;
      const isHovered = hoveredNode?.raw?.id === n.id;
      const isNeighbor = connectedNeighborIds.has(n.id);
      const isDimmed = selectedNode && !isNeighbor;
      const connectionCount = nodeConnectionMap.get(n.id) || 0;

      return {
        id: n.id,
        type: 'default',
        position: pos,
        data: {
          label: (
            <div style={{
              borderRadius: '9px',
              overflow: 'hidden',
              minWidth: '150px',
              maxWidth: '220px',
              boxShadow: isSelected
                ? `0 0 22px ${color}80, 0 8px 24px rgba(0,0,0,0.18)`
                : isHovered
                ? `0 0 16px ${color}60, 0 6px 18px rgba(0,0,0,0.12)`
                : '0 4px 14px rgba(0,0,0,0.08)',
              border: isSelected
                ? `2px solid ${color}`
                : isHovered
                ? `2px solid ${color}`
                : '1px solid rgba(0,0,0,0.08)',
              background: '#ffffff',
            }}>
              {/* Category Color Block Header */}
              <div style={{
                background: color,
                padding: '4px 8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                color: '#ffffff',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  {getNodeIcon(n.type)}
                  <span style={{
                    fontSize: '9px',
                    fontWeight: 800,
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                  }}>
                    {n.type}
                  </span>
                </div>
                <span style={{
                  fontSize: '8px',
                  background: 'rgba(255, 255, 255, 0.28)',
                  padding: '1px 5px',
                  borderRadius: '4px',
                  fontWeight: 700,
                  whiteSpace: 'nowrap',
                }}>
                  {connectionCount} {connectionCount === 1 ? 'link' : 'links'}
                </span>
              </div>

              {/* Node Body Card */}
              <div style={{
                padding: '7px 10px',
                background: isSelected ? 'rgba(255, 255, 255, 0.98)' : '#ffffff',
                textAlign: 'left',
              }}>
                <div style={{
                  fontSize: isRoot ? '12.5px' : '11.5px',
                  fontWeight: 700,
                  color: '#0f172a',
                  wordBreak: 'break-all',
                  lineHeight: 1.3,
                }}>
                  {n.label || n.value}
                </div>
              </div>
            </div>
          ),
          raw: n,
        },
        style: {
          background: 'transparent',
          border: 'none',
          padding: 0,
          cursor: 'pointer',
          opacity: isDimmed ? 0.2 : 1,
          transition: 'all 0.25s cubic-bezier(0.16, 1, 0.3, 1)',
          transform: isSelected ? 'scale(1.08)' : isHovered ? 'scale(1.05)' : 'scale(1)',
          zIndex: isSelected ? 15 : isHovered ? 12 : isNeighbor ? 5 : 1,
        },
      };
    });
  }, [filteredRawNodes, layoutedPositions, selectedNode, hoveredNode, connectedNeighborIds, filterType, searchQuery, nodeConnectionMap]);

  // Construct Flow Edges with dynamic highlights and animated pulses
  const flowEdges: Edge[] = useMemo(() => {
    if (!rawGraph?.edges) return [];
    const visibleIds = new Set(filteredRawNodes.map((n: any) => n.id));

    return rawGraph.edges
      .filter((e: any) => visibleIds.has(e.source) && visibleIds.has(e.target))
      .map((e: any) => {
        const isConnectedToSelected = selectedNode && (e.source === selectedNode.id || e.target === selectedNode.id);
        const isConnectedToHovered = hoveredNode?.raw && (e.source === hoveredNode.raw.id || e.target === hoveredNode.raw.id);
        const isHighlighted = isConnectedToSelected || isConnectedToHovered;
        const isDimmed = selectedNode && !isConnectedToSelected;

        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label || e.type,
          type: 'smoothstep',
          animated: isHighlighted,
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isConnectedToHovered ? '#3b82f6' : isConnectedToSelected ? 'var(--color-accent)' : '#94a3b8',
          },
          style: {
            stroke: isConnectedToHovered ? '#3b82f6' : isConnectedToSelected ? 'var(--color-accent)' : '#94a3b8',
            strokeWidth: isHighlighted ? 2.5 : 1.5,
            opacity: isDimmed ? 0.12 : 1,
            transition: 'all 0.25s ease',
          },
          labelStyle: {
            fill: isConnectedToHovered ? '#1d4ed8' : isConnectedToSelected ? 'var(--color-accent-dark)' : '#64748b',
            fontSize: 10,
            fontWeight: isHighlighted ? 700 : 500,
            opacity: isDimmed ? 0.15 : 1,
          },
          data: e,
        };
      });
  }, [rawGraph?.edges, filteredRawNodes, selectedNode, hoveredNode]);

  // Sync to ReactFlow state
  useEffect(() => {
    setNodes(flowNodes);
    setEdges(flowEdges);
  }, [flowNodes, flowEdges, setNodes, setEdges]);

  const onNodeClick = (_: any, node: Node) => {
    if (selectedNode?.id === node.data.raw?.id) {
      setSelectedNode(null);
    } else {
      setSelectedNode(node.data.raw);
    }
  };

  const handleRecenter = useCallback(() => {
    reactFlowInstance.fitView({ padding: 0.2, duration: 450 });
  }, [reactFlowInstance]);

  const handleExportGraphJson = () => {
    if (!rawGraph) return;
    const exportData = {
      investigationId: id,
      exportedAt: new Date().toISOString(),
      nodes: filteredRawNodes,
      edges: flowEdges.map(e => e.data || e),
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `graph-${id}-${filterType}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setToastMessage('Exported graph JSON successfully!');
    setTimeout(() => setToastMessage(null), 3000);
  };

  return (
    <div style={{ height: 'calc(100vh - 65px)', display: 'flex', flexDirection: 'column', background: 'var(--color-bg)', position: 'relative' }}>
      {/* ======================================================== */}
      {/* TOP GLASS CONTROL BAR                                    */}
      {/* ======================================================== */}
      <div
        className="glass-panel"
        style={{
          margin: 'var(--space-3) var(--space-4)',
          padding: 'var(--space-3) var(--space-5)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 'var(--space-3)',
          zIndex: 10,
        }}
      >
        {/* Navigation & Title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <Link to={`/investigations/${id}`} className="btn btn-ghost btn-sm" title="Return to findings">
            <ArrowLeft size={16} /> Details
          </Link>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span style={{
              display: 'inline-flex',
              padding: '6px',
              borderRadius: '8px',
              background: 'rgba(96, 153, 102, 0.15)',
              color: 'var(--color-accent)'
            }}>
              <GitBranch size={17} />
            </span>
            <div>
              <h1 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, margin: 0, color: 'var(--color-dark)' }}>
                Correlation Graph
              </h1>
              <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                {filteredRawNodes.length} of {rawGraph?.nodes?.length || 0} entities visible
              </div>
            </div>
          </div>
        </div>

        {/* Search Bar */}
        <div style={{ position: 'relative', width: '240px' }}>
          <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
          <input
            type="text"
            className="glass-input"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search nodes (IP, handle)..."
            style={{ width: '100%', padding: '6px 28px 6px 30px', fontSize: 'var(--text-xs)' }}
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              style={{ position: 'absolute', right: '8px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-text-muted)' }}
            >
              <X size={13} />
            </button>
          )}
        </div>

        {/* Layout Mode Selector */}
        <div className="glass-panel-subtle" style={{ display: 'flex', alignItems: 'center', gap: '2px', padding: '3px 6px', borderRadius: 'var(--radius)' }}>
          <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginRight: '4px' }}>
            <Layers size={13} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '2px' }} /> Layout:
          </span>
          {(['radial', 'concentric', 'hierarchy', 'grid'] as LayoutType[]).map((mode) => (
            <button
              key={mode}
              onClick={() => setLayout(mode)}
              className={`btn btn-xs ${layout === mode ? 'btn-primary' : 'btn-ghost'}`}
              style={{ textTransform: 'capitalize', fontSize: '11px', fontWeight: 600 }}
            >
              {mode}
            </button>
          ))}
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <button onClick={handleExportGraphJson} className="btn btn-ghost btn-sm" title="Export graph as JSON">
            <Download size={14} /> JSON
          </button>
          <button onClick={handleRecenter} className="btn btn-ghost btn-sm" title="Fit & center view">
            <Maximize2 size={14} />
          </button>
          <button onClick={fetchGraphData} className="btn btn-ghost btn-sm" title="Refresh graph data">
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* ======================================================== */}
      {/* FILTER BUTTONS ROW (ALL DISCOVERED ENTITY CATEGORIES)   */}
      {/* ======================================================== */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--space-1)',
        padding: '0 var(--space-4) var(--space-2)',
        overflowX: 'auto',
        flexShrink: 0,
        zIndex: 5,
      }}>
        <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginRight: '6px', whiteSpace: 'nowrap' }}>
          <Filter size={12} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '2px' }} /> Filter:
        </span>
        {Object.entries(nodeTypeStats).map(([type, count]) => {
          const isActive = filterType.toLowerCase() === type.toLowerCase();
          const color = NODE_TYPE_COLORS[type.toLowerCase()] || '#609966';
          return (
            <button
              key={type}
              onClick={() => {
                setFilterType(type);
                setSelectedNode(null);
              }}
              className={`glass-pill ${isActive ? 'glow-border-accent' : ''}`}
              style={{
                cursor: 'pointer',
                border: isActive ? `1.5px solid ${color}` : '1px solid var(--glass-border)',
                background: isActive ? `${color}22` : 'var(--glass-bg-subtle)',
                color: isActive ? color : 'var(--color-text-secondary)',
                fontWeight: isActive ? 700 : 500,
                fontSize: '11px',
                padding: '3px 10px',
                whiteSpace: 'nowrap',
              }}
            >
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: type === 'all' ? 'var(--color-dark)' : color }} />
              <span style={{ textTransform: 'capitalize' }}>{type}</span>
              <span style={{ fontSize: '10px', opacity: 0.75 }}>({count})</span>
            </button>
          );
        })}

        {selectedNode && (
          <button
            onClick={() => setSelectedNode(null)}
            className="btn btn-ghost btn-xs"
            style={{ color: '#ef4444', fontWeight: 600, marginLeft: 'auto', whiteSpace: 'nowrap' }}
          >
            Clear Neighbor Highlight
          </button>
        )}
      </div>

      {/* ======================================================== */}
      {/* MAIN GRAPH CANVAS                                        */}
      {/* ======================================================== */}
      <div style={{ flex: 1, position: 'relative' }}>
        {loading ? (
          <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center' }}>
            <span className="spinner" style={{ width: 34, height: 34 }} />
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
            onNodeMouseEnter={(_event, node) => {
              setHoveredNode({ raw: node.data.raw, x: _event.clientX, y: _event.clientY });
            }}
            onNodeMouseLeave={() => setHoveredNode(null)}
            onPaneClick={() => {
              setSelectedNode(null);
              setHoveredNode(null);
            }}
            fitView
          >
            <MiniMap
              nodeColor={(n) => NODE_TYPE_COLORS[n.data?.raw?.type?.toLowerCase()] || '#10b981'}
              style={{
                background: 'var(--glass-bg-card)',
                backdropFilter: 'blur(10px)',
                borderRadius: '8px',
                border: '1px solid var(--color-border)',
              }}
            />
            <Controls style={{ borderRadius: '8px', overflow: 'hidden', boxShadow: 'var(--shadow-md)' }} />
            <Background gap={18} size={1} color="var(--color-border)" />
          </ReactFlow>
        )}

        {/* Floating On-Hover Intelligence Info Card */}
        {hoveredNode && !selectedNode && (
          <div
            className="graph-hover-card"
            style={{
              left: Math.min(window.innerWidth - 320, hoveredNode.x + 16),
              top: Math.min(window.innerHeight - 180, hoveredNode.y + 16),
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <span
                style={{
                  background: NODE_TYPE_COLORS[hoveredNode.raw.type?.toLowerCase()] || '#10b981',
                  color: '#ffffff',
                  fontSize: '9.5px',
                  fontWeight: 800,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  padding: '2px 8px',
                  borderRadius: '6px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                }}
              >
                {getNodeIcon(hoveredNode.raw.type)}
                {hoveredNode.raw.type}
              </span>
              <span style={{ fontSize: '10px', color: 'var(--color-text-muted)', fontWeight: 600 }}>
                {nodeConnectionMap.get(hoveredNode.raw.id) || 0} links
              </span>
            </div>

            <div style={{ fontSize: '13px', fontWeight: 700, color: '#0f172a', wordBreak: 'break-all', marginBottom: '6px' }}>
              {hoveredNode.raw.label || hoveredNode.raw.value}
            </div>

            <div style={{ fontSize: '10.5px', color: 'var(--color-text-secondary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Eye size={11} style={{ color: 'var(--color-accent)' }} />
              <span>Click node to pin details & multi-hop links</span>
            </div>
          </div>
        )}

        {/* Selected Node Frosted Glass Drawer */}
        {selectedNode && (
          <div
            className="glass-card"
            style={{
              position: 'absolute',
              top: '20px',
              right: '20px',
              width: '360px',
              padding: 'var(--space-5)',
              zIndex: 20,
              boxShadow: 'var(--shadow-xl)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-3)' }}>
              <span
                className="badge"
                style={{
                  textTransform: 'capitalize',
                  backgroundColor: `${NODE_TYPE_COLORS[selectedNode.type?.toLowerCase()] || '#6b7280'}20`,
                  color: NODE_TYPE_COLORS[selectedNode.type?.toLowerCase()] || '#374151',
                  border: `1.5px solid ${NODE_TYPE_COLORS[selectedNode.type?.toLowerCase()] || '#d1d5db'}`,
                  fontWeight: 700,
                  fontSize: '11px',
                  padding: '3px 10px',
                }}
              >
                {selectedNode.type}
              </span>
              <button
                onClick={() => setSelectedNode(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '18px', color: 'var(--color-text-muted)' }}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-dark)', wordBreak: 'break-all', marginBottom: 'var(--space-2)' }}>
              {selectedNode.value || selectedNode.label}
            </div>

            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginBottom: 'var(--space-4)' }}>
              Entity Identifier: <code>{selectedNode.id}</code>
            </div>

            {/* Connected Neighbors Count */}
            <div style={{
              background: 'var(--glass-bg-subtle)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius)',
              padding: 'var(--space-2) var(--space-3)',
              marginBottom: 'var(--space-4)',
              fontSize: '12px',
              color: 'var(--color-text-secondary)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <span>Direct OSINT Connections:</span>
              <strong style={{ color: 'var(--color-accent)' }}>{connectedNeighborIds.size - 1} adjacent</strong>
            </div>

            {/* Location Specific Map Actions */}
            {selectedNode.type?.toLowerCase() === 'location' && (
              <div style={{
                background: 'rgba(244, 63, 94, 0.08)',
                border: '1px solid rgba(244, 63, 94, 0.25)',
                borderRadius: 'var(--radius)',
                padding: 'var(--space-3)',
                marginBottom: 'var(--space-4)'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: 'var(--text-xs)', fontWeight: 700, color: '#e11d48', marginBottom: 'var(--space-2)' }}>
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
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: 'var(--space-1)' }}>
                ATTRIBUTION & EDGES
              </div>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', margin: 0, lineHeight: 1.5 }}>
                Directly associated in the investigation corpus. Relationships are strictly grounded in public records and verified across open OSINT platforms.
              </p>
            </div>
          </div>
        )}

        {/* Toast Feedback */}
        {toastMessage && (
          <div
            className="glass-pill"
            style={{
              position: 'fixed',
              bottom: '24px',
              left: '50%',
              transform: 'translateX(-50%)',
              background: 'rgba(16, 185, 129, 0.95)',
              color: 'white',
              padding: '10px 20px',
              borderRadius: 'var(--radius-lg)',
              boxShadow: 'var(--shadow-lg)',
              zIndex: 9999,
              fontSize: '13px',
              fontWeight: 600,
            }}
          >
            {toastMessage}
          </div>
        )}
      </div>
    </div>
  );
}

export default function GraphPage() {
  return (
    <ReactFlowProvider>
      <GraphViewInner />
    </ReactFlowProvider>
  );
}
