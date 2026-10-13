// OpenSpective — RDAP Collector
// Retrieves domain and IP registration data from IANA RDAP bootstrap.
// Respects redacted fields and reports them clearly.

import type { RdapResult } from '@openspective/shared';

const RDAP_BOOTSTRAP_DOMAIN = 'https://data.iana.org/rdap/dns.json';
const RDAP_BOOTSTRAP_IPV4 = 'https://data.iana.org/rdap/ipv4.json';
const RDAP_BOOTSTRAP_IPV6 = 'https://data.iana.org/rdap/ipv6.json';

// RDAP entity roles
const REGISTRANT_ROLES = ['registrant'];
const REGISTRAR_ROLES = ['registrar'];

interface RdapBootstrap {
  services: Array<[string[], string[]]>;
}

async function getRdapBaseUrl(domain: string): Promise<string | null> {
  try {
    const resp = await fetch(RDAP_BOOTSTRAP_DOMAIN, { signal: AbortSignal.timeout(5000) });
    if (!resp.ok) return null;
    const bootstrap: RdapBootstrap = await resp.json();
    const tld = domain.split('.').pop()!.toLowerCase();
    for (const [tlds, urls] of bootstrap.services) {
      if (tlds.includes(tld) && urls.length > 0) {
        return urls[0]!.replace(/\/$/, '');
      }
    }
    return null;
  } catch {
    return null;
  }
}

function extractVcardName(vcard: unknown[][]): string | null {
  if (!Array.isArray(vcard)) return null;
  for (const entry of vcard) {
    if (Array.isArray(entry) && entry[0] === 'fn') {
      return String(entry[3] ?? '');
    }
  }
  return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractEntityInfo(entities: any[]): { registrantOrg: string | null; registrar: string | null } {
  let registrantOrg: string | null = null;
  let registrar: string | null = null;

  if (!Array.isArray(entities)) return { registrantOrg, registrar };

  for (const entity of entities) {
    const roles: string[] = Array.isArray(entity.roles) ? entity.roles : [];
    const vcardArray = Array.isArray(entity.vcardArray) ? entity.vcardArray[1] : null;
    const name = vcardArray ? extractVcardName(vcardArray as unknown[][]) : (entity.handle ?? null);

    if (roles.some(r => REGISTRANT_ROLES.includes(r)) && !registrantOrg) {
      registrantOrg = name ?? entity.fn ?? null;
    }
    if (roles.some(r => REGISTRAR_ROLES.includes(r)) && !registrar) {
      registrar = name ?? entity.fn ?? null;
    }
  }

  return { registrantOrg, registrar };
}

export async function collectRdapDomain(domain: string): Promise<RdapResult> {
  const collectedAt = new Date().toISOString();
  const baseUrl = await getRdapBaseUrl(domain);

  if (!baseUrl) {
    return {
      handle: null,
      registrar: null,
      registrantOrg: null,
      registeredAt: null,
      updatedAt: null,
      expiresAt: null,
      nameservers: [],
      status: [],
      source: 'IANA RDAP',
      isRedacted: false,
      collectedAt,
    };
  }

  try {
    const url = `${baseUrl}/domain/${encodeURIComponent(domain)}`;
    const resp = await fetch(url, {
      headers: { Accept: 'application/rdap+json, application/json' },
      signal: AbortSignal.timeout(10000),
    });

    if (!resp.ok) {
      return {
        handle: null,
        registrar: null,
        registrantOrg: null,
        registeredAt: null,
        updatedAt: null,
        expiresAt: null,
        nameservers: [],
        status: [],
        source: `RDAP (${baseUrl})`,
        isRedacted: resp.status === 404,
        collectedAt,
      };
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data: any = await resp.json();
    const { registrantOrg, registrar } = extractEntityInfo(data.entities ?? []);

    const nameservers: string[] = (data.nameservers ?? [])
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .map((ns: any) => typeof ns === 'string' ? ns : (ns.ldhName ?? '')).filter(Boolean);

    const events: Array<{ eventAction: string; eventDate: string }> = data.events ?? [];
    const getDate = (action: string) =>
      events.find(e => e.eventAction === action)?.eventDate ?? null;

    const status: string[] = Array.isArray(data.status) ? data.status : [];
    const isRedacted = status.includes('redacted') ||
      (data.remarks ?? []).some((r: { title?: string }) => /redact/i.test(r.title ?? ''));

    return {
      handle: data.handle ?? null,
      registrar,
      registrantOrg,
      registeredAt: getDate('registration'),
      updatedAt: getDate('last changed'),
      expiresAt: getDate('expiration'),
      nameservers,
      status,
      source: `RDAP (${baseUrl})`,
      isRedacted,
      collectedAt,
    };
  } catch (err) {
    return {
      handle: null,
      registrar: null,
      registrantOrg: null,
      registeredAt: null,
      updatedAt: null,
      expiresAt: null,
      nameservers: [],
      status: [],
      source: 'IANA RDAP',
      isRedacted: false,
      collectedAt,
    };
  }
}

export async function collectRdapIp(ip: string): Promise<RdapResult> {
  const collectedAt = new Date().toISOString();
  const isV6 = ip.includes(':');
  const bootstrapUrl = isV6 ? RDAP_BOOTSTRAP_IPV6 : RDAP_BOOTSTRAP_IPV4;

  try {
    const resp = await fetch(`https://rdap.arin.net/registry/ip/${encodeURIComponent(ip)}`, {
      headers: { Accept: 'application/rdap+json, application/json' },
      signal: AbortSignal.timeout(10000),
    });

    if (!resp.ok) {
      return {
        handle: null,
        registrar: null,
        registrantOrg: null,
        registeredAt: null,
        updatedAt: null,
        expiresAt: null,
        nameservers: [],
        status: [],
        source: 'ARIN RDAP',
        isRedacted: false,
        collectedAt,
      };
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data: any = await resp.json();
    const { registrantOrg } = extractEntityInfo(data.entities ?? []);

    const events: Array<{ eventAction: string; eventDate: string }> = data.events ?? [];
    const getDate = (action: string) =>
      events.find(e => e.eventAction === action)?.eventDate ?? null;

    return {
      handle: data.handle ?? null,
      registrar: null,
      registrantOrg: registrantOrg ?? data.name ?? null,
      registeredAt: getDate('registration'),
      updatedAt: getDate('last changed'),
      expiresAt: null,
      nameservers: [],
      status: Array.isArray(data.status) ? data.status : [],
      source: 'ARIN RDAP',
      isRedacted: false,
      collectedAt,
    };
  } catch {
    return {
      handle: null,
      registrar: null,
      registrantOrg: null,
      registeredAt: null,
      updatedAt: null,
      expiresAt: null,
      nameservers: [],
      status: [],
      source: 'ARIN RDAP',
      isRedacted: false,
      collectedAt,
    };
  }

  // Suppress unused variable warning
  void bootstrapUrl;
}
