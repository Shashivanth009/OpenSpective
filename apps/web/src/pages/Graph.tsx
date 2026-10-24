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
  const [searchFocused, setSearchFocused] = useState<boolean>(false);
  const [drawerMinimized, setDrawerMinimized] = useState<boolean>(false);
  const [layout, setLayout] = useState<LayoutType>('concentric');
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

  // Live matching suggestions for search dropdown
  const searchSuggestions = useMemo(() => {
    if (!searchQuery.trim() || !rawGraph?.nodes) return [];
    const q = searchQuery.toLowerCase();
    return rawGraph.nodes
      .filter((n: any) =>
        (n.label || '').toLowerCase().includes(q) ||
        (n.value || '').toLowerCase().includes(q) ||
        (n.type || '').toLowerCase().includes(q)
      )
      .slice(0, 8);
  }, [searchQuery, rawGraph]);

  // Layout algorithm calculation
  const layoutedPositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    const count = filteredRawNodes.length;
    if (count === 0) return positions;

    if (layout === 'radial') {
      const angleStep = (2 * Math.PI) / (count > 1 ? count - 1 : 1);
      const radius = Math.min(380, Math.max(180, count * 16));
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
      // Group into Ring 1 (core infrastructure & identities) and outer rings
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

      const innerRadius = 200;
      const innerStep = (2 * Math.PI) / (innerNodes.length || 1);
      innerNodes.forEach((n, idx) => {
        positions[n.id] = {
          x: 500 + Math.cos(idx * innerStep) * innerRadius,
          y: 350 + Math.sin(idx * innerStep) * innerRadius,
        };
      });

      // Split outer nodes into 2 rings if there are more than 22 to avoid crowding
      if (outerNodes.length <= 22) {
        const outerRadius = 350;
        const outerStep = (2 * Math.PI) / (outerNodes.length || 1);
        outerNodes.forEach((n, idx) => {
          positions[n.id] = {
            x: 500 + Math.cos(idx * outerStep) * outerRadius,
            y: 350 + Math.sin(idx * outerStep) * outerRadius,
          };
        });
      } else {
        const ring2Nodes = outerNodes.slice(0, Math.ceil(outerNodes.length / 2));
        const ring3Nodes = outerNodes.slice(Math.ceil(outerNodes.length / 2));

        const r2Radius = 330;
        const r2Step = (2 * Math.PI) / (ring2Nodes.length || 1);
        ring2Nodes.forEach((n, idx) => {
          positions[n.id] = {
            x: 500 + Math.cos(idx * r2Step) * r2Radius,
            y: 350 + Math.sin(idx * r2Step) * r2Radius,
          };
        });

        const r3Radius = 450;
        const r3Step = (2 * Math.PI) / (ring3Nodes.length || 1);
        ring3Nodes.forEach((n, idx) => {
          positions[n.id] = {
            x: 500 + Math.cos(idx * r3Step) * r3Radius,
            y: 350 + Math.sin(idx * r3Step) * r3Radius,
          };
        });
      }
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

  // Construct Flow Nodes with clean minimalist cards
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
              borderRadius: '8px',
              overflow: 'hidden',
              width: '180px',
              boxShadow: isSelected
                ? `0 0 20px ${color}90, 0 8px 24px rgba(0,0,0,0.2)`
                : isHovered
                ? `0 0 14px ${color}60, 0 4px 16px rgba(0,0,0,0.12)`
                : '0 2px 10px rgba(0,0,0,0.06)',
              border: isSelected
                ? `2px solid ${color}`
                : isHovered
                ? `2px solid ${color}`
                : '1px solid rgba(0,0,0,0.08)',
              background: '#ffffff',
              borderLeft: `5px solid ${color}`,
            }}>
              {/* Category Color Sub-Header */}
              <div style={{
                padding: '4px 8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                background: `${color}14`,
                borderBottom: '1px solid rgba(0,0,0,0.04)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color }}>
                  {getNodeIcon(n.type)}
                  <span style={{
                    fontSize: '9px',
                    fontWeight: 800,
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                  }}>
                    {n.type}
                  </span>
                </div>
                {connectionCount > 0 && (
                  <span style={{
                    fontSize: '8.5px',
                    background: 'rgba(0, 0, 0, 0.08)',
                    color: '#334155',
                    padding: '1px 5px',
                    borderRadius: '4px',
                    fontWeight: 700,
                    whiteSpace: 'nowrap',
                  }}>
                    {connectionCount}
                  </span>
                )}
              </div>

              {/* Node Body Label */}
              <div style={{ padding: '6px 8px', textAlign: 'left' }}>
                <div style={{
                  fontSize: isRoot ? '12px' : '11px',
                  fontWeight: 700,
                  color: '#0f172a',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  maxWidth: '164px',
                }} title={n.label || n.value}>
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

  // Construct Flow Edges with smooth Bezier curves and animated pulses
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
          type: 'default', // Smooth cubic Bezier curves
          animated: isHighlighted,
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isConnectedToHovered ? '#3b82f6' : isConnectedToSelected ? '#10b981' : '#94a3b8',
            width: 14,
            height: 14,
          },
          style: {
            stroke: isConnectedToHovered ? '#3b82f6' : isConnectedToSelected ? '#10b981' : 'rgba(148, 163, 184, 0.45)',
            strokeWidth: isHighlighted ? 2.5 : 1.2,
            opacity: isDimmed ? 0.08 : 1,
            transition: 'all 0.25s ease',
          },
          labelStyle: {
            fill: isConnectedToHovered ? '#1d4ed8' : isConnectedToSelected ? '#059669' : '#475569',
            fontSize: 9.5,
            fontWeight: isHighlighted ? 700 : 600,
            opacity: isDimmed ? 0.12 : 1,
          },
          labelBgPadding: [4, 6] as [number, number],
          labelBgBorderRadius: 4,
          labelBgStyle: {
            fill: '#ffffff',
            fillOpacity: 0.95,
            stroke: isConnectedToHovered ? '#3b82f6' : isConnectedToSelected ? '#10b981' : '#cbd5e1',
            strokeWidth: 1,
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

  const handleSelectAndCenterNode = useCallback((targetNode: any) => {
    setSelectedNode(targetNode);
    setSearchQuery('');
    setSearchFocused(false);
    const pos = layoutedPositions[targetNode.id];
    if (pos) {
      reactFlowInstance.setCenter(pos.x + 90, pos.y + 30, { zoom: 1.35, duration: 550 });
    }
  }, [layoutedPositions, reactFlowInstance]);

  const handleLayoutChange = useCallback((newLayout: LayoutType) => {
    setLayout(newLayout);
    setTimeout(() => {
      reactFlowInstance.fitView({ padding: 0.22, duration: 400 });
    }, 60);
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

        {/* Search Bar with Autocomplete Dropdown */}
        <div style={{ position: 'relative', width: '250px' }}>
          <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
          <input
            type="text"
            className="glass-input"
            value={searchQuery}
            onFocus={() => setSearchFocused(true)}
            onBlur={() => setTimeout(() => setSearchFocused(false), 250)}
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

          {/* Autocomplete Dropdown */}
          {searchFocused && searchSuggestions.length > 0 && (
            <div
              className="glass-card"
              style={{
                position: 'absolute',
                top: 'calc(100% + 6px)',
                left: 0,
                right: 0,
                maxHeight: '260px',
                overflowY: 'auto',
                padding: '4px',
                zIndex: 50,
                boxShadow: 'var(--shadow-xl)',
                borderRadius: 'var(--radius)',
                background: 'var(--color-bg)',
              }}
            >
              <div style={{ fontSize: '10px', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', padding: '4px 8px' }}>
                Quick Jump To Node ({searchSuggestions.length})
              </div>
              {searchSuggestions.map((item: any) => {
                const itemColor = NODE_TYPE_COLORS[item.type?.toLowerCase()] || '#10b981';
                return (
                  <div
                    key={item.id}
                    onMouseDown={() => handleSelectAndCenterNode(item)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '6px 8px',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      gap: '8px',
                      transition: 'background 0.15s ease',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--glass-bg-subtle)')}
                    onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden' }}>
                      <span style={{ color: itemColor }}>{getNodeIcon(item.type)}</span>
                      <span style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--color-dark)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {item.label || item.value}
                      </span>
                    </div>
                    <span style={{
                      fontSize: '9px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      color: itemColor,
                      background: `${itemColor}15`,
                      padding: '1px 5px',
                      borderRadius: '3px',
                      whiteSpace: 'nowrap',
                    }}>
                      {item.type}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Layout Mode Selector */}
        <div className="glass-panel-subtle" style={{ display: 'flex', alignItems: 'center', gap: '2px', padding: '3px 6px', borderRadius: 'var(--radius)' }}>
          <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginRight: '4px' }}>
            <Layers size={13} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '2px' }} /> Layout:
          </span>
          {(['concentric', 'radial', 'hierarchy', 'grid'] as LayoutType[]).map((mode) => (
            <button
              key={mode}
              onClick={() => handleLayoutChange(mode)}
              className={`btn btn-xs ${layout === mode ? 'btn-primary' : 'btn-ghost'}`}
              style={{ textTransform: 'capitalize', fontSize: '11px', fontWeight: 600 }}
            >
              {mode === 'concentric' ? 'Clustered' : mode}
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
            panOnScroll={false}
            zoomOnPinch={true}
            panOnDrag={true}
            zoomOnScroll={true}
            minZoom={0.15}
            maxZoom={2.5}
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

        {/* Floating Quick Touch & Mouse Navigation Toolbar */}
        <div style={{
          position: 'absolute',
          bottom: '24px',
          left: '24px',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          background: 'var(--glass-bg)',
          backdropFilter: 'blur(16px)',
          border: '1px solid var(--glass-border)',
          borderRadius: 'var(--radius-lg)',
          padding: '6px 10px',
          boxShadow: 'var(--shadow-lg)',
          zIndex: 10,
        }}>
          <button
            onClick={() => reactFlowInstance.zoomIn({ duration: 300 })}
            className="btn btn-ghost btn-xs"
            title="Zoom In"
            style={{ fontWeight: 700, fontSize: '15px', width: '28px', height: '28px', padding: 0 }}
          >
            +
          </button>
          <button
            onClick={() => reactFlowInstance.zoomOut({ duration: 300 })}
            className="btn btn-ghost btn-xs"
            title="Zoom Out"
            style={{ fontWeight: 700, fontSize: '15px', width: '28px', height: '28px', padding: 0 }}
          >
            -
          </button>
          <button
            onClick={handleRecenter}
            className="btn btn-ghost btn-xs"
            title="Fit to screen & center graph"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', fontWeight: 600 }}
          >
            <Maximize2 size={12} /> Fit
          </button>
          <div style={{ width: '1px', height: '16px', background: 'var(--color-border)', margin: '0 2px' }} />
          <button
            onClick={() => setLayout('concentric')}
            className={`btn btn-xs ${layout === 'concentric' ? 'btn-primary' : 'btn-ghost'}`}
            style={{ fontSize: '11px', padding: '3px 8px' }}
          >
            Clustered
          </button>
          <button
            onClick={() => setLayout('radial')}
            className={`btn btn-xs ${layout === 'radial' ? 'btn-primary' : 'btn-ghost'}`}
            style={{ fontSize: '11px', padding: '3px 8px' }}
          >
            Radial
          </button>
        </div>

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
              width: 'min(360px, calc(100vw - 32px))',
              maxHeight: 'calc(100vh - 160px)',
              overflowY: 'auto',
              padding: 'var(--space-5)',
              zIndex: 20,
              boxShadow: 'var(--shadow-xl)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: drawerMinimized ? 0 : 'var(--space-3)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
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
                  type="button"
                  onClick={() => setDrawerMinimized(!drawerMinimized)}
                  className="btn btn-ghost btn-xs"
                  style={{ fontSize: '10px', padding: '1px 6px' }}
                >
                  {drawerMinimized ? 'Expand' : 'Minimize'}
                </button>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '18px', color: 'var(--color-text-muted)' }}
              >
                <X size={16} />
              </button>
            </div>

            {!drawerMinimized && (
              <>
                <div style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-dark)', wordBreak: 'break-all', marginBottom: 'var(--space-2)' }}>
                  {selectedNode.value || selectedNode.label}
                </div>

                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginBottom: 'var(--space-4)' }}>
                  Entity Identifier: <code>{selectedNode.id}</code>
                </div>

                {/* Connected Neighbors Count & Quick Actions */}
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

                {/* Clickable Adjacent Neighbor Entities Pills */}
                {connectedNeighborIds.size > 1 && (
                  <div style={{ marginBottom: 'var(--space-4)' }}>
                    <div style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                      Connected Entities ({connectedNeighborIds.size - 1})
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', maxHeight: '110px', overflowY: 'auto' }}>
                      {filteredRawNodes
                        .filter((n: any) => n.id !== selectedNode.id && connectedNeighborIds.has(n.id))
                        .map((n: any) => {
                          const nColor = NODE_TYPE_COLORS[n.type?.toLowerCase()] || '#10b981';
                          return (
                            <button
                              key={n.id}
                              onClick={() => handleSelectAndCenterNode(n)}
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                background: `${nColor}15`,
                                color: nColor,
                                border: `1px solid ${nColor}40`,
                                borderRadius: '4px',
                                padding: '2px 6px',
                                fontSize: '10.5px',
                                fontWeight: 600,
                                cursor: 'pointer',
                                maxWidth: '160px',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                              title={`Focus ${n.label || n.value}`}
                            >
                              {getNodeIcon(n.type)}
                              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{n.label || n.value}</span>
                            </button>
                          );
                        })}
                    </div>
                  </div>
                )}

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
                    href={`https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(
                      (selectedNode.value || selectedNode.label || '').match(/(-?\d+\.\d+),\s*(-?\d+\.\d+)/)
                        ? (selectedNode.value || selectedNode.label).match(/(-?\d+\.\d+),\s*(-?\d+\.\d+)/)![0]
                        : selectedNode.value || selectedNode.label
                    )}`}
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
            </>
          )}
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
