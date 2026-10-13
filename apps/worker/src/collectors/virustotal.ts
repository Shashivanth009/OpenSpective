// OpenSpective — VirusTotal Collector
// Checks domains, IPs, and URLs against VirusTotal public API.
// Requires API key — returns unconfigured state without it.

import type { ThreatIntelResult } from '@openspective/shared';

const VT_API = 'https://www.virustotal.com/api/v3';

export interface VtResult {
  threatIntel: ThreatIntelResult;
  resourceType: 'domain' | 'ip' | 'url' | 'file';
  permalink: string | null;
  tags: string[];
  categories: Record<string, string>;
  source: string;
  collectedAt: string;
  error: string | null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseVtResponse(data: any, type: string): Pick<VtResult, 'threatIntel' | 'tags' | 'categories' | 'permalink'> {
  const attrs = data?.data?.attributes ?? {};
  const stats = attrs.last_analysis_stats ?? {};
  const results = attrs.last_analysis_results ?? {};
  const positives = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
  const total = Object.keys(results).length;
  const categories: Record<string, string> = {};

  // Collect scanner categories
  for (const [scanner, result] of Object.entries(results)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const r = result as any;
    if (r.category && r.category !== 'undetected' && r.category !== 'harmless') {
      categories[scanner] = r.category;
    }
  }

  return {
    threatIntel: {
      isMalicious: total > 0 ? positives > 0 : null,
      detectionCount: positives,
      lastAnalysisDate: attrs.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null,
      categories: Object.values(attrs.categories ?? {}),
      sources: Object.keys(results),
      positives,
      total,
      permalink: `https://www.virustotal.com/gui/${type}/${data?.data?.id ?? ''}`,
      collectedAt: new Date().toISOString(),
    },
    tags: attrs.tags ?? [],
    categories,
    permalink: `https://www.virustotal.com/gui/${type}/${data?.data?.id ?? ''}`,
  };
}

async function vtFetch(path: string, apiKey: string): Promise<{ data: unknown; status: number }> {
  try {
    const resp = await fetch(`${VT_API}${path}`, {
      headers: {
        'x-apikey': apiKey,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) return { data: null, status: resp.status };
    return { data: await resp.json(), status: resp.status };
  } catch {
    return { data: null, status: 0 };
  }
}

export async function collectVtDomain(domain: string, apiKey: string): Promise<VtResult> {
  const collectedAt = new Date().toISOString();
  const { data, status } = await vtFetch(`/domains/${encodeURIComponent(domain)}`, apiKey);

  if (!data) {
    return {
      threatIntel: { isMalicious: null, detectionCount: null, lastAnalysisDate: null, categories: [], sources: [], positives: null, total: null, permalink: null, collectedAt },
      resourceType: 'domain',
      permalink: null,
      tags: [],
      categories: {},
      source: 'VirusTotal',
      collectedAt,
      error: status === 404 ? 'Domain not found in VirusTotal' : `VirusTotal error: HTTP ${status}`,
    };
  }

  const parsed = parseVtResponse(data, 'domain');
  return {
    ...parsed,
    resourceType: 'domain',
    source: 'VirusTotal',
    collectedAt,
    error: null,
  };
}

export async function collectVtIp(ip: string, apiKey: string): Promise<VtResult> {
  const collectedAt = new Date().toISOString();
  const { data, status } = await vtFetch(`/ip_addresses/${encodeURIComponent(ip)}`, apiKey);

  if (!data) {
    return {
      threatIntel: { isMalicious: null, detectionCount: null, lastAnalysisDate: null, categories: [], sources: [], positives: null, total: null, permalink: null, collectedAt },
      resourceType: 'ip',
      permalink: null,
      tags: [],
      categories: {},
      source: 'VirusTotal',
      collectedAt,
      error: `VirusTotal error: HTTP ${status}`,
    };
  }

  const parsed = parseVtResponse(data, 'ip_address');
  return {
    ...parsed,
    resourceType: 'ip',
    source: 'VirusTotal',
    collectedAt,
    error: null,
  };
}

export async function collectVtUrl(url: string, apiKey: string): Promise<VtResult> {
  const collectedAt = new Date().toISOString();
  // VT URL ID is base64url of the URL
  const encoder = new TextEncoder();
  const bytes = encoder.encode(url);
  const b64 = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  const { data, status } = await vtFetch(`/urls/${b64}`, apiKey);

  if (!data) {
    return {
      threatIntel: { isMalicious: null, detectionCount: null, lastAnalysisDate: null, categories: [], sources: [], positives: null, total: null, permalink: null, collectedAt },
      resourceType: 'url',
      permalink: null,
      tags: [],
      categories: {},
      source: 'VirusTotal',
      collectedAt,
      error: `VirusTotal error: HTTP ${status}`,
    };
  }

  const parsed = parseVtResponse(data, 'url');
  return {
    ...parsed,
    resourceType: 'url',
    source: 'VirusTotal',
    collectedAt,
    error: null,
  };
}
