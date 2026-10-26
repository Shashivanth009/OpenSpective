import { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import ReactFlow, {
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  MarkerType,
  Handle,
  Position,
  type Node,
  type Edge,
  type NodeProps,
  useReactFlow,
  ReactFlowProvider,
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  GitBranch, ArrowLeft, RefreshCw, AlertCircle, MapPin, ExternalLink,
  Search, Layers, Download, X, Maximize2, Globe, Server, Mail,
  User, ShieldAlert, Key, Cpu, Database, Building2, Link2, Eye,
  Target, ArrowUpRight, ArrowDownLeft, ShieldCheck,
  Filter, Copy, Check
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
  technology: '#ec4899',
  unknown: '#94a3b8',
};

// Node icon helper for category banners
const getNodeIcon = (type: string, size = 12) => {
  switch (type?.toLowerCase()) {
    case 'domain':
    case 'subdomain': return <Globe size={size} />;
    case 'ip': return <Server size={size} />;
    case 'email': return <Mail size={size} />;
    case 'username':
    case 'person': return <User size={size} />;
    case 'location': return <MapPin size={size} />;
    case 'organization': return <Building2 size={size} />;
    case 'threat_ioc': return <ShieldAlert size={size} />;
    case 'repository': return <Database size={size} />;
    case 'url': return <Link2 size={size} />;
    case 'crypto_wallet': return <Key size={size} />;
    default: return <Cpu size={size} />;
  }
};

type LayoutType = 'clustered' | 'hierarchy' | 'radial' | 'grid';
type LabelMode = 'smart' | 'always' | 'hover';

// ========================================================
// CUSTOM ENTITY NODE COMPONENT (REACTFLOW)
// ========================================================
const EntityNodeComponent = ({ data, selected }: NodeProps) => {
  const { raw, isRoot, connectionCount, color, isHighlighted, isDimmed } = data;

  const typeName = (raw.type || 'unknown').toLowerCase();
  const nodeColor = color || NODE_TYPE_COLORS[typeName] || '#10b981';
  const labelText = raw.label || raw.value || 'Entity';

  // Subtitle / context of discovery
  const subtitle = useMemo(() => {
    if (isRoot) return 'Investigation Seed Target';
    if (raw.properties?.sampleNotes) {
      const clean = String(raw.properties.sampleNotes).replace(/^[•\s*-]+/, '').trim();
      return clean.length > 28 ? clean.slice(0, 26) + '...' : clean;
    }
    if (raw.properties?.sourceNames?.length) {
      return `Via ${raw.properties.sourceNames[0]}`;
    }
    if (raw.type === 'location') return 'Spatial Geo-Clue';
    if (raw.type === 'ip') return 'Network Host IP';
    if (raw.type === 'domain') return 'DNS Host Domain';
    if (raw.type === 'username') return 'Discovered Handle';
    if (raw.type === 'repository') return 'Public Repository';
    return `${connectionCount || 1} connected link${connectionCount === 1 ? '' : 's'}`;
  }, [raw, isRoot, connectionCount]);

  return (
    <div style={{ position: 'relative', width: isRoot ? '240px' : '220px' }}>
      {/* Handles on all four sides for clean edge routing */}
      <Handle
        type="target"
        position={Position.Top}
        id="top"
        style={{
          background: nodeColor,
          width: 7,
          height: 7,
          border: '1.5px solid #ffffff',
          borderRadius: '50%',
          top: -4,
          opacity: isHighlighted || selected ? 1 : 0.6,
        }}
      />
      <Handle
        type="source"
        position={Position.Bottom}
        id="bottom"
        style={{
          background: nodeColor,
          width: 7,
          height: 7,
          border: '1.5px solid #ffffff',
          borderRadius: '50%',
          bottom: -4,
          opacity: isHighlighted || selected ? 1 : 0.6,
        }}
      />
      <Handle
        type="target"
        position={Position.Left}
        id="left"
        style={{
          background: nodeColor,
          width: 7,
          height: 7,
          border: '1.5px solid #ffffff',
          borderRadius: '50%',
          left: -4,
          opacity: isHighlighted || selected ? 1 : 0.6,
        }}
      />
      <Handle
        type="source"
        position={Position.Right}
        id="right"
        style={{
          background: nodeColor,
          width: 7,
          height: 7,
          border: '1.5px solid #ffffff',
          borderRadius: '50%',
          right: -4,
          opacity: isHighlighted || selected ? 1 : 0.6,
        }}
      />

      {/* Main Glass Card Body */}
      <div
        style={{
          borderRadius: '10px',
          overflow: 'hidden',
          background: 'var(--glass-bg-card)',
          backdropFilter: 'blur(16px)',
          WebkitBackdropFilter: 'blur(16px)',
          border: selected
            ? `2px solid ${nodeColor}`
            : isRoot
            ? `2px solid ${nodeColor}`
            : isHighlighted
            ? `2px solid ${nodeColor}`
            : '1px solid var(--glass-border)',
          borderLeft: `5px solid ${nodeColor}`,
          boxShadow: isRoot
            ? `0 0 24px ${nodeColor}60, var(--glass-shadow)`
            : selected
            ? `0 0 20px ${nodeColor}70, var(--glass-shadow)`
            : isHighlighted
            ? `0 0 14px ${nodeColor}50, var(--glass-shadow)`
            : 'var(--glass-shadow)',
          transition: 'all 0.25s cubic-bezier(0.16, 1, 0.3, 1)',
          opacity: isDimmed ? 0.15 : 1,
          transform: selected ? 'scale(1.04)' : isHighlighted ? 'scale(1.02)' : 'scale(1)',
          cursor: 'pointer',
        }}
      >
        {/* Top Category Strip */}
        <div
          style={{
            padding: '5px 10px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: `${nodeColor}14`,
            borderBottom: '1px solid var(--color-border)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px', color: nodeColor }}>
            {isRoot ? <Target size={13} style={{ color: nodeColor }} /> : getNodeIcon(raw.type, 12)}
            <span
              style={{
                fontSize: '9.5px',
                fontWeight: 800,
                textTransform: 'uppercase',
                letterSpacing: '0.06em',
              }}
            >
              {isRoot ? 'TARGET SEED' : raw.type}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            {connectionCount > 0 && (
              <span
                style={{
                  fontSize: '9px',
                  background: 'var(--color-bg-secondary)',
                  color: 'var(--color-text-secondary)',
                  padding: '1px 6px',
                  borderRadius: '10px',
                  fontWeight: 700,
                  border: '1px solid var(--color-border)',
                }}
                title={`${connectionCount} direct OSINT links`}
              >
                {connectionCount} {connectionCount === 1 ? 'link' : 'links'}
              </span>
            )}
          </div>
        </div>

        {/* Primary Value & Context Label */}
        <div style={{ padding: '8px 10px', textAlign: 'left' }}>
          <div
            style={{
              fontSize: isRoot ? '12.5px' : '11.5px',
              fontWeight: 700,
              color: 'var(--color-dark)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              maxWidth: isRoot ? '210px' : '190px',
              lineHeight: 1.3,
            }}
            title={labelText}
          >
            {labelText}
          </div>

          {/* Subtitle / Telemetry Info */}
          <div
            style={{
              fontSize: '10px',
              color: 'var(--color-text-muted)',
              marginTop: '3px',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            <span
              style={{
                width: 5,
                height: 5,
                borderRadius: '50%',
                background: isRoot ? '#10b981' : nodeColor,
                flexShrink: 0,
              }}
            />
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {subtitle}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

// Register custom node types with ReactFlow
const customNodeTypes = {
  entityNode: EntityNodeComponent,
};

// ========================================================
// MAIN GRAPH COMPONENT INNER
// ========================================================
function GraphViewInner() {
  const { id } = useParams<{ id: string }>();
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [rawGraph, setRawGraph] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [hoveredNode, setHoveredNode] = useState<{ raw: any; x: number; y: number } | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<{ edge: any; x: number; y: number } | null>(null);
  const [filterType, setFilterType] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [searchFocused, setSearchFocused] = useState<boolean>(false);
  const [layout, setLayout] = useState<LayoutType>('clustered');
  const [labelMode, setLabelMode] = useState<LabelMode>('smart');
  const [isolatedNodeId, setIsolatedNodeId] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const reactFlowInstance = useReactFlow();

  // Fetch graph data from backend
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

  // Compute degree connections and neighbor maps
  const { nodeConnectionMap, neighborAdjacencyMap, edgeLookupMap } = useMemo(() => {
    const connMap = new Map<string, number>();
    const adjMap = new Map<string, Set<string>>();
    const edgeMap = new Map<string, any[]>();

    if (rawGraph?.edges) {
      for (const e of rawGraph.edges) {
        connMap.set(e.source, (connMap.get(e.source) || 0) + 1);
        connMap.set(e.target, (connMap.get(e.target) || 0) + 1);

        if (!adjMap.has(e.source)) adjMap.set(e.source, new Set());
        if (!adjMap.has(e.target)) adjMap.set(e.target, new Set());
        adjMap.get(e.source)!.add(e.target);
        adjMap.get(e.target)!.add(e.source);

        if (!edgeMap.has(e.source)) edgeMap.set(e.source, []);
        if (!edgeMap.has(e.target)) edgeMap.set(e.target, []);
        edgeMap.get(e.source)!.push(e);
        edgeMap.get(e.target)!.push(e);
      }
    }
    return { nodeConnectionMap: connMap, neighborAdjacencyMap: adjMap, edgeLookupMap: edgeMap };
  }, [rawGraph?.edges]);

  // Compute 1-hop connected neighbors of selectedNode
  const connectedNeighborIds = useMemo(() => {
    if (!selectedNode) return new Set<string>();
    const neighbors = neighborAdjacencyMap.get(selectedNode.id);
    const set = new Set<string>(neighbors ? Array.from(neighbors) : []);
    set.add(selectedNode.id);
    return set;
  }, [selectedNode, neighborAdjacencyMap]);

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

  // Root Target Node
  const rootNode = useMemo(() => {
    if (!rawGraph?.nodes?.length) return null;
    return rawGraph.nodes.find((n: any) => n.properties?.isRoot) || rawGraph.nodes[0];
  }, [rawGraph]);

  // Filter raw nodes by category, search query, and isolation
  const filteredRawNodes = useMemo(() => {
    if (!rawGraph?.nodes) return [];
    return rawGraph.nodes.filter((n: any) => {
      // Isolation filter
      if (isolatedNodeId) {
        const allowed = neighborAdjacencyMap.get(isolatedNodeId) || new Set();
        if (n.id !== isolatedNodeId && !allowed.has(n.id)) return false;
      }

      // Type filter
      const matchesType = filterType === 'all' || n.type?.toLowerCase() === filterType.toLowerCase();

      // Search filter
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch = !q ||
        (n.label || '').toLowerCase().includes(q) ||
        (n.value || '').toLowerCase().includes(q) ||
        (n.type || '').toLowerCase().includes(q);

      return matchesType && matchesSearch;
    });
  }, [rawGraph, filterType, searchQuery, isolatedNodeId, neighborAdjacencyMap]);

  // Live matching suggestions for search dropdown
  const searchSuggestions = useMemo(() => {
    if (!searchQuery.trim() || !rawGraph?.nodes) return [];
    const q = searchQuery.toLowerCase().trim();
    return rawGraph.nodes
      .filter((n: any) =>
        (n.label || '').toLowerCase().includes(q) ||
        (n.value || '').toLowerCase().includes(q) ||
        (n.type || '').toLowerCase().includes(q)
      )
      .slice(0, 8);
  }, [searchQuery, rawGraph]);

  // ========================================================
  // SMART LAYOUT ALGORITHM (NO OVERLAPPING HAIRBALLS)
  // ========================================================
  const layoutedPositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    const count = filteredRawNodes.length;
    if (count === 0) return positions;

    const root = rootNode || filteredRawNodes[0];
    const rootId = root?.id;

    if (layout === 'clustered') {
      // ----------------------------------------------------
      // CLUSTERED BRANCH RADIAL LAYOUT
      // ----------------------------------------------------
      const originX = 600;
      const originY = 450;

      // Place root at center
      if (rootId) {
        positions[rootId] = { x: originX, y: originY };
      }

      // Categorize other nodes into logical OSINT branches
      const branchIdentities: any[] = [];
      const branchNetwork: any[] = [];
      const branchLocations: any[] = [];
      const branchOther: any[] = [];

      filteredRawNodes.forEach((n: any) => {
        if (n.id === rootId) return;
        const t = (n.type || '').toLowerCase();
        if (['email', 'username', 'person', 'repository', 'url'].includes(t)) {
          branchIdentities.push(n);
        } else if (['domain', 'subdomain', 'ip', 'technology', 'asn', 'certificate'].includes(t)) {
          branchNetwork.push(n);
        } else if (['location'].includes(t)) {
          branchLocations.push(n);
        } else {
          branchOther.push(n);
        }
      });

      // Branch sector angles (in radians)
      // Sector 1: Identities (Top-Right / Right: -0.6 to 1.1)
      // Sector 2: Infrastructure (Left / Bottom-Left: 2.2 to 4.2)
      // Sector 3: Locations (Bottom / Bottom-Right: 1.2 to 2.1)
      // Sector 4: Other (Top / Top-Left: 4.3 to 5.6)
      const layoutBranch = (list: any[], startAngle: number, endAngle: number) => {
        if (list.length === 0) return;

        // Separate 1-hop from multi-hop
        const direct1Hop = list.filter(n => neighborAdjacencyMap.get(rootId)?.has(n.id));
        const multiHop = list.filter(n => !neighborAdjacencyMap.get(rootId)?.has(n.id));

        // Place 1-hop nodes in inner arc
        const innerRadius = Math.max(300, Math.min(480, direct1Hop.length * 55));
        const angleSpan = endAngle - startAngle;
        const step1 = direct1Hop.length > 1 ? angleSpan / (direct1Hop.length - 1) : 0;

        direct1Hop.forEach((n, idx) => {
          const angle = direct1Hop.length === 1 ? (startAngle + endAngle) / 2 : startAngle + idx * step1;
          positions[n.id] = {
            x: originX + Math.cos(angle) * innerRadius,
            y: originY + Math.sin(angle) * innerRadius,
          };
        });

        // Place multi-hop nodes in outer arc, clustered near their parent if possible
        const outerRadius = innerRadius + 280;
        const step2 = multiHop.length > 1 ? angleSpan / (multiHop.length - 1) : 0;

        multiHop.forEach((n, idx) => {
          // If node connects to a placed 1-hop node, bias toward that angle
          const connectedParents = Array.from(neighborAdjacencyMap.get(n.id) || []).filter(pId => positions[pId]);
          let angle: number;
          if (connectedParents.length > 0) {
            const parentPos = positions[connectedParents[0]];
            const parentAngle = Math.atan2(parentPos.y - originY, parentPos.x - originX);
            const offset = ((idx % 3) - 1) * 0.18;
            angle = parentAngle + offset;
          } else {
            angle = multiHop.length === 1 ? (startAngle + endAngle) / 2 : startAngle + idx * step2;
          }

          positions[n.id] = {
            x: originX + Math.cos(angle) * outerRadius,
            y: originY + Math.sin(angle) * outerRadius,
          };
        });
      };

      layoutBranch(branchIdentities, -0.6, 1.1); // Right / Identities
      layoutBranch(branchLocations, 1.2, 2.1);   // Bottom / Spatial
      layoutBranch(branchNetwork, 2.2, 4.2);     // Left / Network Infrastructure
      layoutBranch(branchOther, 4.3, 5.6);       // Top / Other

      // Collision avoidance & spring repulsion relaxation pass
      const nodeKeys = Object.keys(positions);
      const minDistanceX = 250;
      const minDistanceY = 110;

      for (let iter = 0; iter < 12; iter++) {
        for (let i = 0; i < nodeKeys.length; i++) {
          const idA = nodeKeys[i];
          if (idA === rootId) continue; // Keep root firmly centered
          const posA = positions[idA];

          for (let j = i + 1; j < nodeKeys.length; j++) {
            const idB = nodeKeys[j];
            const posB = positions[idB];

            const dx = posB.x - posA.x;
            const dy = posB.y - posA.y;

            if (Math.abs(dx) < minDistanceX && Math.abs(dy) < minDistanceY) {
              const pushX = (minDistanceX - Math.abs(dx)) * 0.45 * (dx >= 0 ? 1 : -1);
              const pushY = (minDistanceY - Math.abs(dy)) * 0.45 * (dy >= 0 ? 1 : -1);

              if (idA !== rootId) {
                posA.x -= pushX * 0.5;
                posA.y -= pushY * 0.5;
              }
              if (idB !== rootId) {
                posB.x += pushX * 0.5;
                posB.y += pushY * 0.5;
              }
            }
          }
        }
      }
    } else if (layout === 'hierarchy') {
      // ----------------------------------------------------
      // MALTEGO-STYLE DIRECTED INTELLIGENCE TREE
      // ----------------------------------------------------
      const levels: Record<number, any[]> = { 0: [], 1: [], 2: [], 3: [] };
      const visited = new Set<string>();

      // Level 0: Root
      if (rootId) {
        levels[0].push(root);
        visited.add(rootId);
      }

      // Level 1: Direct 1-hop children
      filteredRawNodes.forEach((n: any) => {
        if (!visited.has(n.id) && neighborAdjacencyMap.get(rootId)?.has(n.id)) {
          levels[1].push(n);
          visited.add(n.id);
        }
      });

      // Level 2: 2-hop grandchildren
      filteredRawNodes.forEach((n: any) => {
        if (!visited.has(n.id)) {
          const isL2 = levels[1].some(l1 => neighborAdjacencyMap.get(l1.id)?.has(n.id));
          if (isL2) {
            levels[2].push(n);
            visited.add(n.id);
          }
        }
      });

      // Level 3: Remainder / Deep terminals
      filteredRawNodes.forEach((n: any) => {
        if (!visited.has(n.id)) {
          levels[3].push(n);
        }
      });

      const levelY = [80, 320, 580, 840];
      const cardWidth = 260;

      [0, 1, 2, 3].forEach(lvl => {
        const row = levels[lvl] || [];
        const totalWidth = row.length * cardWidth;
        const startX = 600 - totalWidth / 2;

        row.forEach((n: any, idx: number) => {
          positions[n.id] = {
            x: startX + idx * cardWidth + 130,
            y: levelY[lvl],
          };
        });
      });
    } else if (layout === 'radial') {
      // ----------------------------------------------------
      // RADAR CONCENTRIC RINGS
      // ----------------------------------------------------
      const originX = 600;
      const originY = 450;

      if (rootId) positions[rootId] = { x: originX, y: originY };

      const nonRoot = filteredRawNodes.filter((n: any) => n.id !== rootId);
      const ring1 = nonRoot.filter((n: any) => neighborAdjacencyMap.get(rootId)?.has(n.id));
      const ring2 = nonRoot.filter((n: any) => !neighborAdjacencyMap.get(rootId)?.has(n.id));

      const r1 = Math.max(340, ring1.length * 36);
      const step1 = (2 * Math.PI) / (ring1.length || 1);
      ring1.forEach((n: any, idx: number) => {
        positions[n.id] = {
          x: originX + Math.cos(idx * step1) * r1,
          y: originY + Math.sin(idx * step1) * r1,
        };
      });

      const r2 = r1 + 320;
      const step2 = (2 * Math.PI) / (ring2.length || 1);
      ring2.forEach((n: any, idx: number) => {
        positions[n.id] = {
          x: originX + Math.cos(idx * step2) * r2,
          y: originY + Math.sin(idx * step2) * r2,
        };
      });
    } else {
      // ----------------------------------------------------
      // CATEGORY MATRIX GRID
      // ----------------------------------------------------
      const cols = Math.ceil(Math.sqrt(count * 1.5));
      const colWidth = 270;
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
  }, [filteredRawNodes, layout, rootNode, neighborAdjacencyMap]);

  // Construct Flow Nodes using dedicated custom node component
  const flowNodes: Node[] = useMemo(() => {
    return filteredRawNodes.map((n: any) => {
      const isRoot = !!(n.properties?.isRoot || n.id === rootNode?.id);
      const pos = layoutedPositions[n.id] || { x: 500, y: 350 };
      const color = NODE_TYPE_COLORS[n.type?.toLowerCase()] || '#10b981';

      const isSelected = selectedNode?.id === n.id;
      const isHovered = hoveredNode?.raw?.id === n.id;
      const isNeighbor = connectedNeighborIds.has(n.id);
      const isDimmed = selectedNode && !isNeighbor;
      const connectionCount = nodeConnectionMap.get(n.id) || 0;

      return {
        id: n.id,
        type: 'entityNode',
        position: pos,
        selected: isSelected,
        data: {
          raw: n,
          isRoot,
          connectionCount,
          color,
          isHighlighted: isHovered || (selectedNode && isNeighbor),
          isDimmed,
          isNeighbor,
        },
      };
    });
  }, [filteredRawNodes, layoutedPositions, selectedNode, hoveredNode, connectedNeighborIds, nodeConnectionMap, rootNode]);

  // Construct Flow Edges with dynamic glowing highlights & smart labels
  const flowEdges: Edge[] = useMemo(() => {
    if (!rawGraph?.edges) return [];
    const visibleIds = new Set(filteredRawNodes.map((n: any) => n.id));

    return rawGraph.edges
      .filter((e: any) => visibleIds.has(e.source) && visibleIds.has(e.target))
      .map((e: any) => {
        const isConnectedToSelected = selectedNode && (e.source === selectedNode.id || e.target === selectedNode.id);
        const isConnectedToHovered = hoveredNode?.raw && (e.source === hoveredNode.raw.id || e.target === hoveredNode.raw.id);
        const isEdgeHovered = hoveredEdge?.edge?.id === e.id;
        const isHighlighted = isConnectedToSelected || isConnectedToHovered || isEdgeHovered;
        const isDimmed = selectedNode && !isConnectedToSelected;

        // Label visibility logic
        const isRootEdge = rootNode && (e.source === rootNode.id || e.target === rootNode.id);
        const showLabel = labelMode === 'always' || (labelMode === 'smart' && (isHighlighted || isRootEdge)) || (labelMode === 'hover' && isHighlighted);

        const edgeColor = isConnectedToHovered
          ? '#3b82f6'
          : isConnectedToSelected
          ? '#10b981'
          : isEdgeHovered
          ? '#10b981'
          : isRootEdge
          ? 'rgba(16, 185, 129, 0.55)'
          : 'rgba(148, 163, 184, 0.45)';

        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: showLabel ? (e.label || e.type) : undefined,
          type: 'default', // Smooth Bezier curves
          animated: isHighlighted,
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: edgeColor,
            width: 14,
            height: 14,
          },
          style: {
            stroke: edgeColor,
            strokeWidth: isHighlighted ? 2.8 : 1.2,
            opacity: isDimmed ? 0.08 : 1,
            transition: 'all 0.25s ease',
          },
          labelStyle: {
            fill: isHighlighted ? 'var(--color-dark)' : 'var(--color-text-secondary)',
            fontSize: 9.5,
            fontWeight: isHighlighted ? 800 : 600,
          },
          labelBgPadding: [4, 7] as [number, number],
          labelBgBorderRadius: 6,
          labelBgStyle: {
            fill: 'var(--glass-bg-card)',
            fillOpacity: 0.95,
            stroke: isHighlighted ? edgeColor : 'var(--glass-border)',
            strokeWidth: 1,
          },
          data: e,
        };
      });
  }, [rawGraph?.edges, filteredRawNodes, selectedNode, hoveredNode, hoveredEdge, labelMode, rootNode]);

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
    reactFlowInstance.fitView({ padding: 0.22, duration: 450 });
  }, [reactFlowInstance]);

  const handleSelectAndCenterNode = useCallback((targetNode: any) => {
    setSelectedNode(targetNode);
    setSearchQuery('');
    setSearchFocused(false);
    const pos = layoutedPositions[targetNode.id];
    if (pos) {
      reactFlowInstance.setCenter(pos.x + 110, pos.y + 45, { zoom: 1.25, duration: 550 });
    }
  }, [layoutedPositions, reactFlowInstance]);

  const handleLayoutChange = useCallback((newLayout: LayoutType) => {
    setLayout(newLayout);
    setTimeout(() => {
      reactFlowInstance.fitView({ padding: 0.22, duration: 450 });
    }, 70);
  }, [reactFlowInstance]);

  const handleCopy = (text: string, idStr: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(idStr);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleExportGraphJson = () => {
    if (!rawGraph) return;
    const exportData = {
      investigationId: id,
      target: rootNode?.value,
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

  // Connected endpoints for selected node
  const selectedNodeConnections = useMemo(() => {
    if (!selectedNode || !rawGraph?.edges) return { outgoing: [], incoming: [] };
    const outgoing = rawGraph.edges
      .filter((e: any) => e.source === selectedNode.id)
      .map((e: any) => {
        const targetNode = rawGraph.nodes.find((n: any) => n.id === e.target);
        return { edge: e, node: targetNode };
      })
      .filter((item: any) => !!item.node);

    const incoming = rawGraph.edges
      .filter((e: any) => e.target === selectedNode.id)
      .map((e: any) => {
        const sourceNode = rawGraph.nodes.find((n: any) => n.id === e.source);
        return { edge: e, node: sourceNode };
      })
      .filter((item: any) => !!item.node);

    return { outgoing, incoming };
  }, [selectedNode, rawGraph]);

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
          <Link to={`/investigations/${id}`} className="btn btn-ghost btn-sm" title="Return to findings dossier">
            <ArrowLeft size={16} /> Findings
          </Link>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span style={{
              display: 'inline-flex',
              padding: '6px',
              borderRadius: '8px',
              background: 'rgba(16, 185, 129, 0.15)',
              color: 'var(--color-accent)'
            }}>
              <GitBranch size={17} />
            </span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <h1 style={{ fontSize: 'var(--text-sm)', fontWeight: 800, margin: 0, color: 'var(--color-dark)' }}>
                  Correlation Graph
                </h1>
                {rootNode && (
                  <span
                    className="glass-pill"
                    style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '1px 8px',
                      color: 'var(--color-accent)',
                      borderColor: 'var(--color-accent)',
                    }}
                  >
                    Target: {rootNode.value}
                  </span>
                )}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                {filteredRawNodes.length} of {rawGraph?.nodes?.length || 0} entities visible • {flowEdges.length} correlation edges
              </div>
            </div>
          </div>
        </div>

        {/* Search Bar with Autocomplete Dropdown */}
        <div style={{ position: 'relative', width: '240px' }}>
          <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
          <input
            type="text"
            className="glass-input"
            value={searchQuery}
            onFocus={() => setSearchFocused(true)}
            onBlur={() => setTimeout(() => setSearchFocused(false), 250)}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search IP, handle, domain..."
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
                      color: itemColor,
                      background: `${itemColor}15`,
                      padding: '1px 5px',
                      borderRadius: '4px',
                      textTransform: 'uppercase',
                      fontWeight: 700,
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
          {([
            { id: 'clustered', label: 'Branches' },
            { id: 'hierarchy', label: 'Tree' },
            { id: 'radial', label: 'Radial' },
            { id: 'grid', label: 'Grid' },
          ] as const).map((mode) => (
            <button
              key={mode.id}
              onClick={() => handleLayoutChange(mode.id)}
              className={`btn btn-xs ${layout === mode.id ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '11px', fontWeight: 700, padding: '3px 8px' }}
            >
              {mode.label}
            </button>
          ))}
        </div>

        {/* Edge Labels Mode Selector */}
        <div className="glass-panel-subtle" style={{ display: 'flex', alignItems: 'center', gap: '2px', padding: '3px 6px', borderRadius: 'var(--radius)' }}>
          <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginRight: '4px' }}>
            Labels:
          </span>
          {(['smart', 'always', 'hover'] as LabelMode[]).map((m) => (
            <button
              key={m}
              onClick={() => setLabelMode(m)}
              className={`btn btn-xs ${labelMode === m ? 'btn-secondary' : 'btn-ghost'}`}
              style={{ fontSize: '10.5px', textTransform: 'capitalize', padding: '2px 6px' }}
            >
              {m}
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
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginRight: 'var(--space-2)', color: 'var(--color-text-muted)', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase' }}>
          <Filter size={12} /> Filter:
        </div>

        <button
          onClick={() => setFilterType('all')}
          className={`glass-pill ${filterType === 'all' ? 'glass-pill-active' : ''}`}
          style={{ fontSize: '11px', padding: '3px 10px' }}
        >
          All ({rawGraph?.nodes?.length || 0})
        </button>

        {Object.entries(nodeTypeStats)
          .filter(([type]) => type !== 'all')
          .map(([type, count]) => {
            const isCurrent = filterType === type;
            const tColor = NODE_TYPE_COLORS[type.toLowerCase()] || '#10b981';
            return (
              <button
                key={type}
                onClick={() => setFilterType(isCurrent ? 'all' : type)}
                className={`glass-pill ${isCurrent ? 'glass-pill-active' : ''}`}
                style={{
                  fontSize: '11px',
                  padding: '3px 10px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px',
                  borderColor: isCurrent ? tColor : 'var(--glass-border)',
                }}
              >
                <span style={{ color: tColor }}>{getNodeIcon(type)}</span>
                <span style={{ textTransform: 'capitalize' }}>{type}</span>
                <span style={{
                  fontSize: '9.5px',
                  opacity: 0.8,
                  background: 'var(--color-bg-secondary)',
                  padding: '0 4px',
                  borderRadius: '6px',
                  marginLeft: '2px',
                }}>
                  {count}
                </span>
              </button>
            );
          })}

        {/* Clear isolation badge if active */}
        {isolatedNodeId && (
          <button
            onClick={() => setIsolatedNodeId(null)}
            className="btn btn-xs btn-primary"
            style={{ marginLeft: 'var(--space-2)', fontSize: '11px' }}
          >
            Clear Branch Isolation ✕
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
            nodeTypes={customNodeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            onNodeMouseEnter={(_event, node) => {
              setHoveredNode({ raw: node.data.raw, x: _event.clientX, y: _event.clientY });
            }}
            onNodeMouseLeave={() => setHoveredNode(null)}
            onEdgeMouseEnter={(_event, edge) => {
              setHoveredEdge({ edge: edge.data || edge, x: _event.clientX, y: _event.clientY });
            }}
            onEdgeMouseLeave={() => setHoveredEdge(null)}
            onPaneClick={() => {
              setSelectedNode(null);
              setHoveredNode(null);
              setHoveredEdge(null);
            }}
            fitView
            panOnScroll={false}
            zoomOnPinch={true}
            panOnDrag={true}
            zoomOnScroll={true}
            minZoom={0.12}
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
            <Background gap={22} size={1} color="var(--color-border)" />
          </ReactFlow>
        )}

        {/* Floating Quick Navigation Toolbar */}
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
            <Maximize2 size={12} /> Fit View
          </button>
        </div>

        {/* ======================================================== */}
        {/* FLOATING HOVER CARD FOR NODES                           */}
        {/* ======================================================== */}
        {hoveredNode && !selectedNode && (
          <div
            className="graph-hover-card"
            style={{
              left: Math.min(window.innerWidth - 340, hoveredNode.x + 18),
              top: Math.min(window.innerHeight - 240, hoveredNode.y + 18),
            }}
          >
            {/* Header with Type & Status */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span
                style={{
                  background: `${NODE_TYPE_COLORS[hoveredNode.raw.type?.toLowerCase()] || '#10b981'}25`,
                  color: NODE_TYPE_COLORS[hoveredNode.raw.type?.toLowerCase()] || '#10b981',
                  border: `1px solid ${NODE_TYPE_COLORS[hoveredNode.raw.type?.toLowerCase()] || '#10b981'}50`,
                  fontSize: '10px',
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
                {hoveredNode.raw.properties?.isRoot ? <Target size={11} /> : getNodeIcon(hoveredNode.raw.type, 11)}
                {hoveredNode.raw.properties?.isRoot ? 'TARGET SEED' : hoveredNode.raw.type}
              </span>

              <span style={{ fontSize: '10.5px', color: 'var(--color-text-muted)', fontWeight: 700 }}>
                {nodeConnectionMap.get(hoveredNode.raw.id) || 0} OSINT connections
              </span>
            </div>

            {/* Full Value Label */}
            <div style={{ fontSize: '13.5px', fontWeight: 800, color: 'var(--color-dark)', wordBreak: 'break-all', marginBottom: '6px', lineHeight: 1.3 }}>
              {hoveredNode.raw.label || hoveredNode.raw.value}
            </div>

            {/* Telemetry / Discovery Provenance */}
            {hoveredNode.raw.properties?.sourceNames?.length > 0 && (
              <div style={{ fontSize: '11px', color: 'var(--color-text-secondary)', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                <ShieldCheck size={13} style={{ color: 'var(--color-accent)' }} />
                <span>Discovered via: <strong>{hoveredNode.raw.properties.sourceNames.join(', ')}</strong></span>
              </div>
            )}

            {/* Sample Evidence Notes */}
            {hoveredNode.raw.properties?.sampleNotes && (
              <div style={{
                fontSize: '11px',
                color: 'var(--color-text-secondary)',
                background: 'var(--color-bg-secondary)',
                padding: '4px 8px',
                borderRadius: '6px',
                marginBottom: '8px',
                lineHeight: 1.4,
              }}>
                {hoveredNode.raw.properties.sampleNotes}
              </div>
            )}

            {/* Direct Connected Endpoints Preview */}
            {(() => {
              const edges = edgeLookupMap.get(hoveredNode.raw.id) || [];
              if (edges.length === 0) return null;
              return (
                <div style={{ borderTop: '1px solid var(--color-border)', paddingTop: '6px', marginTop: '6px' }}>
                  <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--color-text-muted)', fontWeight: 700, marginBottom: '4px' }}>
                    Connected Endpoints ({edges.length}):
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', maxHeight: '90px', overflowY: 'auto' }}>
                    {edges.slice(0, 4).map((e: any, idx: number) => {
                      const isOutgoing = e.source === hoveredNode.raw.id;
                      const otherId = isOutgoing ? e.target : e.source;
                      const otherVal = otherId.split(':').slice(1).join(':') || otherId;
                      return (
                        <div key={idx} style={{ fontSize: '10.5px', display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--color-text-secondary)' }}>
                          <span style={{ color: isOutgoing ? 'var(--color-accent)' : '#3b82f6', fontWeight: 800 }}>
                            {isOutgoing ? '➔' : '⬅'}
                          </span>
                          <span style={{ fontWeight: 600, color: 'var(--color-dark)' }}>{e.label || e.type}:</span>
                          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '170px' }}>
                            {otherVal}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })()}

            <div style={{ fontSize: '10px', color: 'var(--color-text-muted)', marginTop: '8px', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Eye size={11} style={{ color: 'var(--color-accent)' }} />
              <span>Click node to lock details & isolate this branch</span>
            </div>
          </div>
        )}

        {/* ======================================================== */}
        {/* FLOATING HOVER CARD FOR EDGES                           */}
        {/* ======================================================== */}
        {hoveredEdge && !selectedNode && !hoveredNode && (
          <div
            className="graph-hover-card"
            style={{
              left: Math.min(window.innerWidth - 320, hoveredEdge.x + 16),
              top: Math.min(window.innerHeight - 180, hoveredEdge.y + 16),
            }}
          >
            <div style={{ fontSize: '10px', fontWeight: 800, textTransform: 'uppercase', color: 'var(--color-accent)', marginBottom: '4px' }}>
              Correlation Edge Telemetry
            </div>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--color-dark)', marginBottom: '6px' }}>
              {hoveredEdge.edge.label || hoveredEdge.edge.type}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--color-text-secondary)', display: 'flex', flexDirection: 'column', gap: '3px' }}>
              <div><strong>From:</strong> <code>{hoveredEdge.edge.source}</code></div>
              <div><strong>To:</strong> <code>{hoveredEdge.edge.target}</code></div>
              {hoveredEdge.edge.confidence && (
                <div><strong>Confidence:</strong> <span style={{ textTransform: 'capitalize' }}>{hoveredEdge.edge.confidence}</span></div>
              )}
              {hoveredEdge.edge.sourceUrl && (
                <div style={{ marginTop: '4px' }}>
                  <a
                    href={hoveredEdge.edge.sourceUrl}
                    target="_blank"
                    rel="noreferrer"
                    style={{ color: 'var(--color-accent)', textDecoration: 'underline', fontSize: '10.5px' }}
                  >
                    View Provenance Source ↗
                  </a>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ======================================================== */}
        {/* SELECTED NODE INSPECTOR DRAWER                           */}
        {/* ======================================================== */}
        {selectedNode && (
          <div
            className="glass-card"
            style={{
              position: 'absolute',
              top: '20px',
              right: '20px',
              width: 'min(380px, calc(100vw - 32px))',
              maxHeight: 'calc(100vh - 160px)',
              overflowY: 'auto',
              padding: 'var(--space-5)',
              zIndex: 30,
              boxShadow: 'var(--shadow-xl)',
              border: `1.5px solid ${NODE_TYPE_COLORS[selectedNode.type?.toLowerCase()] || 'var(--glass-border)'}`,
            }}
          >
            {/* Drawer Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-3)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span
                  style={{
                    backgroundColor: `${NODE_TYPE_COLORS[selectedNode.type?.toLowerCase()] || '#10b981'}25`,
                    color: NODE_TYPE_COLORS[selectedNode.type?.toLowerCase()] || '#10b981',
                    border: `1.5px solid ${NODE_TYPE_COLORS[selectedNode.type?.toLowerCase()] || '#10b981'}`,
                    fontWeight: 800,
                    fontSize: '11px',
                    padding: '3px 10px',
                    borderRadius: '8px',
                    textTransform: 'uppercase',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                >
                  {selectedNode.properties?.isRoot ? <Target size={12} /> : getNodeIcon(selectedNode.type, 12)}
                  {selectedNode.properties?.isRoot ? 'TARGET SEED' : selectedNode.type}
                </span>

                <button
                  type="button"
                  onClick={() => setIsolatedNodeId(isolatedNodeId === selectedNode.id ? null : selectedNode.id)}
                  className={`btn btn-xs ${isolatedNodeId === selectedNode.id ? 'btn-primary' : 'btn-ghost'}`}
                  style={{ fontSize: '10.5px', padding: '2px 8px' }}
                  title="Isolate this node and its direct connections"
                >
                  {isolatedNodeId === selectedNode.id ? 'Showing Isolated' : 'Isolate Branch'}
                </button>
              </div>

              <button
                onClick={() => setSelectedNode(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-text-muted)' }}
                title="Close drawer"
              >
                <X size={18} />
              </button>
            </div>

            {/* Entity Label & Copy Action */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '8px', marginBottom: 'var(--space-3)' }}>
              <div style={{ fontSize: 'var(--text-base)', fontWeight: 800, color: 'var(--color-dark)', wordBreak: 'break-all', lineHeight: 1.4 }}>
                {selectedNode.value || selectedNode.label}
              </div>
              <button
                type="button"
                onClick={() => handleCopy(selectedNode.value || selectedNode.label, 'node-val')}
                className="btn btn-ghost btn-xs"
                title="Copy entity value"
              >
                {copiedId === 'node-val' ? <Check size={13} style={{ color: 'var(--color-accent)' }} /> : <Copy size={13} />}
              </button>
            </div>

            {/* Telemetry Findings Summary */}
            <div style={{
              background: 'var(--glass-bg-subtle)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius)',
              padding: 'var(--space-3)',
              marginBottom: 'var(--space-4)',
              fontSize: '12px',
              color: 'var(--color-text-secondary)',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Direct OSINT Links:</span>
                <strong style={{ color: 'var(--color-accent)' }}>{connectedNeighborIds.size - 1} connected</strong>
              </div>

              {selectedNode.properties?.sourceNames?.length > 0 && (
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span>Discovered via:</span>
                  <strong style={{ color: 'var(--color-dark)' }}>{selectedNode.properties.sourceNames.join(', ')}</strong>
                </div>
              )}

              {selectedNode.properties?.sampleNotes && (
                <div style={{ borderTop: '1px solid var(--color-border)', paddingTop: '6px', marginTop: '2px', fontSize: '11px', lineHeight: 1.4 }}>
                  <em>{selectedNode.properties.sampleNotes}</em>
                </div>
              )}
            </div>

            {/* ======================================================== */}
            {/* OUTGOING CONNECTIONS (WHAT THIS NODE CONNECTS TO)        */}
            {/* ======================================================== */}
            <div style={{ marginBottom: 'var(--space-4)' }}>
              <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <ArrowUpRight size={13} style={{ color: 'var(--color-accent)' }} />
                Outgoing Relationships ({selectedNodeConnections.outgoing.length})
              </div>

              {selectedNodeConnections.outgoing.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '140px', overflowY: 'auto' }}>
                  {selectedNodeConnections.outgoing.map(({ edge, node }: any) => {
                    const nColor = NODE_TYPE_COLORS[node.type?.toLowerCase()] || '#10b981';
                    return (
                      <div
                        key={edge.id}
                        onClick={() => handleSelectAndCenterNode(node)}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '6px 8px',
                          borderRadius: '6px',
                          background: 'var(--color-bg-secondary)',
                          border: '1px solid var(--color-border)',
                          cursor: 'pointer',
                          gap: '8px',
                          transition: 'background 0.15s ease',
                        }}
                        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--glass-bg-subtle)')}
                        onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--color-bg-secondary)')}
                        title={`Jump to ${node.label || node.value}`}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden' }}>
                          <span style={{ color: 'var(--color-accent)', fontWeight: 800 }}>➔</span>
                          <span style={{ fontSize: '10.5px', color: 'var(--color-text-muted)', fontWeight: 700 }}>
                            {edge.label || edge.type}:
                          </span>
                          <span style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--color-dark)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {node.label || node.value}
                          </span>
                        </div>
                        <span style={{ color: nColor, flexShrink: 0 }}>
                          {getNodeIcon(node.type, 12)}
                        </span>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontStyle: 'italic' }}>
                  No outgoing relationships from this endpoint.
                </div>
              )}
            </div>

            {/* ======================================================== */}
            {/* INCOMING CONNECTIONS (WHAT CONNECTS TO THIS NODE)        */}
            {/* ======================================================== */}
            <div style={{ marginBottom: 'var(--space-4)' }}>
              <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <ArrowDownLeft size={13} style={{ color: '#3b82f6' }} />
                Incoming Relationships ({selectedNodeConnections.incoming.length})
              </div>

              {selectedNodeConnections.incoming.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '140px', overflowY: 'auto' }}>
                  {selectedNodeConnections.incoming.map(({ edge, node }: any) => {
                    const nColor = NODE_TYPE_COLORS[node.type?.toLowerCase()] || '#10b981';
                    return (
                      <div
                        key={edge.id}
                        onClick={() => handleSelectAndCenterNode(node)}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '6px 8px',
                          borderRadius: '6px',
                          background: 'var(--color-bg-secondary)',
                          border: '1px solid var(--color-border)',
                          cursor: 'pointer',
                          gap: '8px',
                          transition: 'background 0.15s ease',
                        }}
                        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--glass-bg-subtle)')}
                        onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--color-bg-secondary)')}
                        title={`Jump to ${node.label || node.value}`}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden' }}>
                          <span style={{ color: '#3b82f6', fontWeight: 800 }}>⬅</span>
                          <span style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--color-dark)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {node.label || node.value}
                          </span>
                          <span style={{ fontSize: '10.5px', color: 'var(--color-text-muted)', fontWeight: 700 }}>
                            ➔ {edge.label || edge.type}
                          </span>
                        </div>
                        <span style={{ color: nColor, flexShrink: 0 }}>
                          {getNodeIcon(node.type, 12)}
                        </span>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontStyle: 'italic' }}>
                  No incoming relationships targeting this endpoint.
                </div>
              )}
            </div>

            {/* ======================================================== */}
            {/* EXTERNAL ACTIONS (MAPS, SHODAN, GITHUB)                 */}
            {/* ======================================================== */}
            <div style={{ borderTop: '1px solid var(--color-border)', paddingTop: 'var(--space-3)' }}>
              {/* Location specific actions */}
              {selectedNode.type?.toLowerCase() === 'location' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: 'var(--space-3)' }}>
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
              )}

              {/* IP / Host specific actions */}
              {selectedNode.type?.toLowerCase() === 'ip' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: 'var(--space-3)' }}>
                  <a
                    href={`https://www.shodan.io/host/${encodeURIComponent(selectedNode.value)}`}
                    target="_blank"
                    rel="noreferrer"
                    className="btn btn-secondary btn-sm"
                    style={{ justifyContent: 'center' }}
                  >
                    <ExternalLink size={14} /> Inspect in Shodan InternetDB
                  </a>
                </div>
              )}

              {/* URL specific actions */}
              {selectedNode.type?.toLowerCase() === 'url' && (
                <div style={{ marginBottom: 'var(--space-3)' }}>
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

              {/* Deep-link back to findings */}
              <Link
                to={`/investigations/${id}?search=${encodeURIComponent(selectedNode.value || selectedNode.label)}`}
                className="btn btn-ghost btn-xs"
                style={{ width: '100%', justifyContent: 'center', color: 'var(--color-accent)' }}
              >
                Search In Findings Dossier →
              </Link>
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
              fontWeight: 700,
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
