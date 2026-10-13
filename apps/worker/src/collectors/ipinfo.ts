// OpenSpective — IP Information Collector
// Uses ipinfo.io for public IP geolocation, ASN, and org data.
// Works without API key (rate-limited) and with token.

export interface IpInfoResult {
  ip: string;
  hostname: string | null;
  org: string | null;
  asn: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  timezone: string | null;
  isAnonymous: boolean;
  isTor: boolean;
  isVpn: boolean;
  isProxy: boolean;
  isHosting: boolean;
  source: string;
  collectedAt: string;
  error: string | null;
}

interface IpInfoResponse {
  ip: string;
  hostname?: string;
  org?: string;
  country?: string;
  region?: string;
  city?: string;
  timezone?: string;
  privacy?: {
    vpn: boolean;
    proxy: boolean;
    tor: boolean;
    relay: boolean;
    hosting: boolean;
    service: string;
  };
}

export async function collectIpInfo(ip: string, token?: string): Promise<IpInfoResult> {
  const collectedAt = new Date().toISOString();
  const source = 'ipinfo.io';

  try {
    const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json${token ? `?token=${token}` : ''}`;
    const resp = await fetch(url, {
      headers: { Accept: 'application/json', 'User-Agent': 'OpenSpective/0.1' },
      signal: AbortSignal.timeout(8000),
    });

    if (!resp.ok) {
      return {
        ip,
        hostname: null,
        org: null,
        asn: null,
        country: null,
        region: null,
        city: null,
        timezone: null,
        isAnonymous: false,
        isTor: false,
        isVpn: false,
        isProxy: false,
        isHosting: false,
        source,
        collectedAt,
        error: `ipinfo.io returned HTTP ${resp.status}`,
      };
    }

    const data: IpInfoResponse = await resp.json();

    // Extract ASN from org field (format: "AS15169 Google LLC")
    let asn: string | null = null;
    let orgName: string | null = data.org ?? null;
    if (data.org) {
      const match = data.org.match(/^(AS\d+)\s+(.+)$/);
      if (match) {
        asn = match[1] ?? null;
        orgName = match[2] ?? null;
      }
    }

    return {
      ip: data.ip,
      hostname: data.hostname ?? null,
      org: orgName,
      asn,
      country: data.country ?? null,
      region: data.region ?? null,
      city: data.city ?? null,
      timezone: data.timezone ?? null,
      isAnonymous: data.privacy?.vpn ?? data.privacy?.proxy ?? data.privacy?.tor ?? false,
      isTor: data.privacy?.tor ?? false,
      isVpn: data.privacy?.vpn ?? false,
      isProxy: data.privacy?.proxy ?? false,
      isHosting: data.privacy?.hosting ?? false,
      source,
      collectedAt,
      error: null,
    };
  } catch (err) {
    return {
      ip,
      hostname: null,
      org: null,
      asn: null,
      country: null,
      region: null,
      city: null,
      timezone: null,
      isAnonymous: false,
      isTor: false,
      isVpn: false,
      isProxy: false,
      isHosting: false,
      source,
      collectedAt,
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}
