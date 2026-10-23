// ============================================================
// OpenSpective — Shared Types & Schemas
// ============================================================

// Target types
export type TargetType =
  | 'domain'
  | 'email'
  | 'username'
  | 'ip'
  | 'url'
  | 'person'
  | 'organization'
  | 'phone'
  | 'crypto_wallet'
  | 'unknown';

// Investigation status
export type InvestigationStatus =
  | 'queued'
  | 'running'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled';

// Collector status
export type CollectorStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'skipped'
  | 'unconfigured'
  | 'rate_limited';

// Confidence level
export type ConfidenceLevel = 'high' | 'medium' | 'low' | 'unknown';

// Finding severity
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none';

// Relationship type
export type RelationshipType =
  | 'resolves_to'
  | 'mx_record'
  | 'ns_record'
  | 'cname_record'
  | 'txt_record'
  | 'certificate_covers'
  | 'subdomain_of'
  | 'hosted_on'
  | 'owned_by'
  | 'affiliated_with'
  | 'located_in'
  | 'mentions'
  | 'registered_to'
  | 'technology_uses'
  | 'breach_includes';

// Node types for graph
export type NodeType =
  | 'person'
  | 'email'
  | 'username'
  | 'phone'
  | 'organization'
  | 'domain'
  | 'subdomain'
  | 'ip'
  | 'certificate'
  | 'repository'
  | 'technology'
  | 'crypto_wallet'
  | 'location'
  | 'url';

// ============================================================
// Core domain models
// ============================================================

export interface Investigation {
  id: string;
  userId: string | null; // null for guest
  target: string;
  targetType: TargetType;
  normalizedTarget: string;
  status: InvestigationStatus;
  modules: string[];
  startedAt: string;
  completedAt: string | null;
  errorMessage: string | null;
  aiAnalysisId: string | null;
  metadata: Record<string, unknown>;
}

export interface CollectorExecution {
  id: string;
  investigationId: string;
  collectorName: string;
  status: CollectorStatus;
  startedAt: string;
  completedAt: string | null;
  findingsCount: number;
  errorMessage: string | null;
  sourceUrl: string | null;
}

export interface Finding {
  id: string;
  investigationId: string;
  collectorExecutionId: string | null;
  category: string;
  subcategory: string | null;
  type: string;
  value: string;
  rawData: Record<string, unknown>;
  confidence: ConfidenceLevel;
  severity: FindingSeverity;
  sourceUrl: string | null;
  sourceName: string;
  firstSeen: string;
  lastSeen: string;
  isInferred: boolean;
  notes: string | null;
}

export interface Relationship {
  id: string;
  investigationId: string;
  fromEntityId: string;
  toEntityId: string;
  fromEntityType: NodeType;
  toEntityType: NodeType;
  fromValue: string;
  toValue: string;
  relationshipType: RelationshipType;
  findingId: string | null;
  sourceUrl: string | null;
  confidence: ConfidenceLevel;
  isInferred: boolean;
  collectedAt: string;
}

export interface AiAnalysis {
  id: string;
  investigationId: string;
  model: string;
  summary: string;
  technicalDetails: string;
  recommendations: string[];
  gaps: string[];
  evidenceRefs: string[];
  createdAt: string;
  tokenCount: number | null;
}

export interface Report {
  id: string;
  investigationId: string;
  userId: string | null;
  format: 'json' | 'csv' | 'html';
  storageKey: string | null;
  createdAt: string;
  expiresAt: string | null;
}

export interface UsageRecord {
  userId: string;
  period: string; // YYYY-MM format
  investigationCount: number;
  collectorCallCount: number;
  aiInferenceCount: number;
  reportCount: number;
  storageBytes: number;
}

// ============================================================
// API Request / Response shapes
// ============================================================

export interface ApiError {
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}

// POST /api/v1/investigations
export interface CreateInvestigationRequest {
  target: string;
  targetType?: TargetType; // override auto-detection
  modules?: string[];
  enableAi?: boolean;
  notes?: string;
}

export interface CreateInvestigationResponse {
  investigation: Investigation;
  classifiedAs: TargetType;
  availableModules: ModuleInfo[];
  unavailableModules: ModuleInfo[];
}

// GET /api/v1/investigations/:id/graph
export interface GraphNode {
  id: string;
  type: NodeType;
  value: string;
  label: string;
  properties: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: RelationshipType;
  label: string;
  confidence: ConfidenceLevel;
  isInferred: boolean;
  sourceUrl: string | null;
}

export interface InvestigationGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  investigationId: string;
  generatedAt: string;
}

// Module info
export interface ModuleInfo {
  name: string;
  displayName: string;
  description: string;
  targetTypes: TargetType[];
  isConfigured: boolean;
  isAvailable: boolean;
  requiresCredentials: boolean;
  credentialKey?: string;
  limitations?: string[];
}

// Classification result
export interface ClassificationResult {
  targetType: TargetType;
  normalizedTarget: string;
  confidence: ConfidenceLevel;
  alternatives: TargetType[];
  validationMessage: string | null;
  isAmbiguous: boolean;
}

// Health check
export interface HealthCheck {
  status: 'ok' | 'degraded' | 'error';
  version: string;
  timestamp: string;
  services: Record<string, 'ok' | 'error' | 'unconfigured'>;
}

// Account usage
export interface AccountUsage {
  period: string;
  limits: {
    investigations: number;
    collectorCalls: number;
    aiInferences: number;
    reports: number;
    storageBytes: number;
  };
  used: {
    investigations: number;
    collectorCalls: number;
    aiInferences: number;
    reports: number;
    storageBytes: number;
  };
  remaining: {
    investigations: number;
    collectorCalls: number;
    aiInferences: number;
    reports: number;
    storageBytes: number;
  };
}

// ============================================================
// Collector schemas
// ============================================================

export interface DnsRecord {
  type: string;
  name: string;
  value: string;
  ttl: number | null;
  priority: number | null;
  collectedAt: string;
}

export interface DnsResult {
  domain: string;
  records: DnsRecord[];
  source: string;
  collectedAt: string;
  errors: string[];
}

export interface RdapResult {
  handle: string | null;
  registrar: string | null;
  registrantOrg: string | null;
  registeredAt: string | null;
  updatedAt: string | null;
  expiresAt: string | null;
  nameservers: string[];
  status: string[];
  source: string;
  isRedacted: boolean;
  collectedAt: string;
}

export interface CertificateInfo {
  commonName: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  sanDomains: string[];
  serialNumber: string;
  fingerprint: string | null;
  source: string;
  collectedAt: string;
}

export interface SubdomainInfo {
  hostname: string;
  source: string;
  discoveryMethod: 'certificate_transparency' | 'dns_brute' | 'passive';
  resolvedIps: string[];
  collectedAt: string;
}

export interface TechIndicator {
  name: string;
  category: string;
  version: string | null;
  confidence: ConfidenceLevel;
  evidence: string;
  source: string;
}

export interface ThreatIntelResult {
  isMalicious: boolean | null;
  detectionCount: number | null;
  lastAnalysisDate: string | null;
  categories: string[];
  sources: string[];
  positives: number | null;
  total: number | null;
  permalink: string | null;
  collectedAt: string;
}

// ============================================================
// Utility types
// ============================================================

export type Result<T, E = string> =
  | { success: true; data: T }
  | { success: false; error: E };

export const FREE_TIER_LIMITS = {
  investigations: 10,
  collectorCalls: 100,
  aiInferences: 20,
  reports: 10,
  storageBytes: 100 * 1024 * 1024, // 100 MB
} as const;

export const SUPPORTED_TARGET_TYPES: TargetType[] = [
  'domain',
  'email',
  'username',
  'ip',
  'url',
  'person',
  'organization',
  'phone',
];
