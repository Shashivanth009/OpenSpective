// API client for OpenSpective frontend
// Communicates with the Cloudflare Worker backend

const API_BASE = import.meta.env.VITE_API_URL ?? '/api/v1';

// Stored auth token
let _token: string | null = localStorage.getItem('os_token');

export function setToken(token: string | null) {
  _token = token;
  if (token) localStorage.setItem('os_token', token);
  else localStorage.removeItem('os_token');
}

export function getToken(): string | null {
  return _token;
}

export interface CustomApiKeys {
  virustotal?: string;
  ipinfo?: string;
  github?: string;
  shodan?: string;
  haveibeenpwned?: string;
}

export function getCustomApiKeys(): CustomApiKeys {
  try {
    const raw = localStorage.getItem('os_api_keys');
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

export function saveCustomApiKeys(keys: CustomApiKeys): void {
  localStorage.setItem('os_api_keys', JSON.stringify(keys));
}

interface FetchOptions extends RequestInit {
  params?: Record<string, string | number | undefined>;
}

async function apiFetch<T>(
  path: string,
  options: FetchOptions = {}
): Promise<T> {
  const { params, ...init } = options;

  let url = `${API_BASE}${path}`;
  if (params) {
    const search = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined) search.set(k, String(v));
    }
    const qs = search.toString();
    if (qs) url += `?${qs}`;
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((init.headers as Record<string, string>) ?? {}),
  };

  if (_token) {
    headers['Authorization'] = `Bearer ${_token}`;
  }

  // Attach client-saved custom external API keys
  const customKeys = getCustomApiKeys();
  if (customKeys.virustotal) headers['X-Virustotal-Key'] = customKeys.virustotal;
  if (customKeys.ipinfo) headers['X-Ipinfo-Token'] = customKeys.ipinfo;
  if (customKeys.github) headers['X-Github-Token'] = customKeys.github;
  if (customKeys.shodan) headers['X-Shodan-Key'] = customKeys.shodan;
  if (customKeys.haveibeenpwned) headers['X-Hibp-Key'] = customKeys.haveibeenpwned;

  const response = await fetch(url, {
    ...init,
    headers,
  });

  if (!response.ok) {
    let errorBody: { error?: string; code?: string } = {};
    try {
      errorBody = await response.json();
    } catch {
      errorBody = { error: `HTTP ${response.status}` };
    }
    const err = new ApiError(
      errorBody.error ?? `HTTP ${response.status}`,
      errorBody.code ?? 'UNKNOWN',
      response.status
    );
    throw err;
  }

  return response.json() as Promise<T>;
}

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(
    message: string,
    code: string,
    status: number
  ) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
  }
}

// ---- Auth ----
export interface User {
  id: string;
  email: string;
  displayName: string | null;
}

export interface AuthResponse {
  user: User;
  token: string;
}

export async function signup(email: string, password: string, displayName?: string): Promise<AuthResponse> {
  return apiFetch('/auth/signup', {
    method: 'POST',
    body: JSON.stringify({ email, password, displayName }),
  });
}

export async function login(email: string, password: string): Promise<AuthResponse> {
  return apiFetch('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export async function logout(): Promise<void> {
  await apiFetch('/auth/logout', { method: 'POST' });
}

export async function getMe(): Promise<{ user: User; usage: unknown }> {
  return apiFetch('/auth/me');
}

// ---- Investigations ----
export interface Investigation {
  id: string;
  user_id: string | null;
  target: string;
  target_type: string;
  normalized_target: string;
  status: string;
  modules: string;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
  ai_analysis_id: string | null;
  enable_ai: number;
  metadata: string;
}

export interface CollectorExecution {
  id: string;
  investigation_id: string;
  collector_name: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  findings_count: number;
  error_message: string | null;
}

export interface Finding {
  id: string;
  investigation_id: string;
  category: string;
  subcategory: string | null;
  type: string;
  value: string;
  raw_data: string;
  confidence: string;
  severity: string;
  source_url: string | null;
  source_name: string;
  first_seen: string;
  is_inferred: number;
  notes: string | null;
}

export interface CreateInvestigationResult {
  investigation: Investigation;
  classifiedAs: string;
  classification: {
    targetType: string;
    normalizedTarget: string;
    confidence: string;
    alternatives: string[];
    validationMessage: string | null;
    isAmbiguous: boolean;
  };
  availableModules: Array<{
    name: string;
    displayName: string;
    description: string;
    isConfigured: boolean;
  }>;
  unavailableModules: Array<{
    name: string;
    displayName: string;
    description: string;
    credentialKey?: string;
  }>;
}

export async function createInvestigation(
  target: string,
  targetType?: string,
  modules?: string[],
  enableAi?: boolean
): Promise<CreateInvestigationResult> {
  return apiFetch('/investigations', {
    method: 'POST',
    body: JSON.stringify({ target, targetType, modules, enableAi }),
  });
}

export async function listInvestigations(page = 1, pageSize = 20): Promise<{
  data: Investigation[];
  total: number;
  page: number;
  hasMore: boolean;
}> {
  return apiFetch('/investigations', { params: { page, pageSize } });
}

export async function getInvestigation(id: string): Promise<{
  investigation: Investigation;
  executions: CollectorExecution[];
  aiAnalysis?: any;
}> {
  return apiFetch(`/investigations/${id}`);
}

export async function deleteInvestigation(id: string): Promise<{ success: boolean; message: string }> {
  return apiFetch(`/investigations/${id}`, { method: 'DELETE' });
}

export async function clearAllInvestigations(): Promise<{ success: boolean; message: string; deletedCount: number }> {
  return apiFetch('/investigations', { method: 'DELETE' });
}

export async function getFindings(
  id: string,
  category?: string,
  page = 1,
  pageSize = 50
): Promise<{ data: Finding[]; total: number; page: number; hasMore: boolean }> {
  return apiFetch(`/investigations/${id}/findings`, {
    params: { category, page, pageSize },
  });
}

export async function getGraph(id: string): Promise<{
  nodes: Array<{ id: string; type: string; value: string; label: string }>;
  edges: Array<{ id: string; source: string; target: string; type: string; label: string; confidence: string; isInferred: boolean }>;
}> {
  return apiFetch(`/investigations/${id}/graph`);
}

export async function analyzeInvestigation(id: string): Promise<{
  analysisId: string;
  summary: string;
  fullResponse: string;
  evidenceCount: number;
  model: string;
  generatedAt: string;
  disclaimer: string;
}> {
  return apiFetch(`/investigations/${id}/analyze`, { method: 'POST' });
}

export async function cancelInvestigation(id: string): Promise<void> {
  await apiFetch(`/investigations/${id}/cancel`, { method: 'POST' });
}

// ---- Reports ----
export async function generateReport(
  investigationId: string,
  format: 'json' | 'csv' | 'html'
): Promise<Response> {
  const url = `${API_BASE}/investigations/${investigationId}/reports`;
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (_token) headers['Authorization'] = `Bearer ${_token}`;
  return fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({ format }),
  });
}

// ---- Account ----
export async function getUsage(): Promise<{
  period: string;
  limits: Record<string, number>;
  used: Record<string, number>;
  remaining: Record<string, number>;
}> {
  return apiFetch('/account/usage');
}

// ---- Classify ----
export async function classifyTarget(q: string): Promise<{
  targetType: string;
  normalizedTarget: string;
  confidence: string;
  alternatives: string[];
  validationMessage: string | null;
  isAmbiguous: boolean;
}> {
  return apiFetch('/classify', { params: { q } });
}

// ---- Health ----
export async function getHealth(): Promise<{
  status: string;
  version: string;
  timestamp: string;
  services: Record<string, string>;
}> {
  return apiFetch('/health');
}
