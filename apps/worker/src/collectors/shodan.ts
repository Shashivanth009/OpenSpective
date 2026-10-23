// OpenSpective — Shodan InternetDB Passive Intelligence Collector
// Completely free, passive network intelligence API provided by Shodan.
// Requires NO API key and performs NO active port scanning.
// Discovers open ports, known vulnerabilities (CVEs), hostnames, CPEs, and service tags.

export interface ShodanInternetDbResult {
  ip: string;
  ports: number[];
  cves: string[];
  hostnames: string[];
  tags: string[];
  cpes: string[];
  source: string;
  collectedAt: string;
  hasData: boolean;
  error?: string;
}

export async function collectShodanInternetDb(ip: string): Promise<ShodanInternetDbResult> {
  const collectedAt = new Date().toISOString();
  const cleanIp = ip.trim();

  try {
    const url = `https://internetdb.shodan.io/${encodeURIComponent(cleanIp)}`;
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(8000),
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; OpenSpective/0.1; +https://openspective.com)',
        Accept: 'application/json',
      },
    });

    if (resp.status === 404) {
      // 404 means Shodan has no passive port records for this IP — not an error
      return {
        ip: cleanIp,
        ports: [],
        cves: [],
        hostnames: [],
        tags: [],
        cpes: [],
        source: 'Shodan InternetDB (Passive)',
        collectedAt,
        hasData: false,
      };
    }

    if (!resp.ok) {
      return {
        ip: cleanIp,
        ports: [],
        cves: [],
        hostnames: [],
        tags: [],
        cpes: [],
        source: 'Shodan InternetDB (Passive)',
        collectedAt,
        hasData: false,
        error: `Shodan InternetDB returned HTTP ${resp.status}`,
      };
    }

    const data = await resp.json() as {
      ip?: string;
      ports?: number[];
      vulns?: string[];
      hostnames?: string[];
      tags?: string[];
      cpes?: string[];
    };

    const ports = Array.isArray(data.ports) ? data.ports : [];
    const cves = Array.isArray(data.vulns) ? data.vulns : [];
    const hostnames = Array.isArray(data.hostnames) ? data.hostnames : [];
    const tags = Array.isArray(data.tags) ? data.tags : [];
    const cpes = Array.isArray(data.cpes) ? data.cpes : [];

    return {
      ip: cleanIp,
      ports,
      cves,
      hostnames,
      tags,
      cpes,
      source: 'Shodan InternetDB (Passive Sensors)',
      collectedAt,
      hasData: ports.length > 0 || cves.length > 0 || hostnames.length > 0,
    };
  } catch (err) {
    return {
      ip: cleanIp,
      ports: [],
      cves: [],
      hostnames: [],
      tags: [],
      cpes: [],
      source: 'Shodan InternetDB (Passive Sensors)',
      collectedAt,
      hasData: false,
      error: err instanceof Error ? err.message : 'Failed to query Shodan InternetDB',
    };
  }
}
