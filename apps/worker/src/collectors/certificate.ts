// OpenSpective — Certificate Transparency Collector
// Uses crt.sh to discover certificates and subdomains.

import type { CertificateInfo, SubdomainInfo } from '@openspective/shared';

interface CrtShEntry {
  id: number;
  logged_at: string;
  not_before: string;
  not_after: string;
  common_name: string;
  matching_identities: string;
  issuer_name: string;
}

export interface CtResult {
  certificates: CertificateInfo[];
  subdomains: SubdomainInfo[];
  source: string;
  collectedAt: string;
  error: string | null;
}

function extractSANDomains(matchingIdentities: string, commonName: string): string[] {
  const domains = new Set<string>();
  if (commonName) domains.add(commonName.toLowerCase().trim());
  if (matchingIdentities) {
    for (const d of matchingIdentities.split('\n')) {
      const trimmed = d.trim().toLowerCase();
      if (trimmed && !trimmed.startsWith('*.') === false || trimmed) {
        domains.add(trimmed);
      }
    }
  }
  return [...domains].filter(d => d.length > 0);
}

export async function collectCertificateTransparency(domain: string): Promise<CtResult> {
  const collectedAt = new Date().toISOString();
  const source = 'crt.sh (Certificate Transparency)';

  try {
    const url = `https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`;
    const resp = await fetch(url, {
      headers: { Accept: 'application/json', 'User-Agent': 'OpenSpective/0.1 OSINT-Platform' },
      signal: AbortSignal.timeout(15000),
    });

    if (!resp.ok) {
      return {
        certificates: [],
        subdomains: [],
        source,
        collectedAt,
        error: `crt.sh returned HTTP ${resp.status}`,
      };
    }

    const entries: CrtShEntry[] = await resp.json();

    // Deduplicate by common_name + not_before to avoid listing same cert multiple times
    const seenKeys = new Set<string>();
    const certificates: CertificateInfo[] = [];
    const subdomainSet = new Set<string>();

    for (const entry of entries) {
      const key = `${entry.common_name}|${entry.not_before}`;
      const sanDomains = extractSANDomains(entry.matching_identities ?? '', entry.common_name ?? '');

      for (const d of sanDomains) {
        // Remove wildcards to get base domain
        const base = d.startsWith('*.') ? d.slice(2) : d;
        if (base.endsWith('.' + domain) || base === domain) {
          subdomainSet.add(base);
        }
      }

      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        certificates.push({
          commonName: entry.common_name ?? '',
          issuer: entry.issuer_name ?? '',
          validFrom: entry.not_before ?? '',
          validTo: entry.not_after ?? '',
          sanDomains,
          serialNumber: String(entry.id),
          fingerprint: null,
          source,
          collectedAt,
        });
      }
    }

    // Cap at 100 certificates to avoid overwhelming response
    const trimmedCerts = certificates.slice(0, 100);

    const subdomains: SubdomainInfo[] = [...subdomainSet]
      .filter(s => s !== domain)
      .slice(0, 200)
      .map(hostname => ({
        hostname,
        source,
        discoveryMethod: 'certificate_transparency' as const,
        resolvedIps: [],
        collectedAt,
      }));

    return { certificates: trimmedCerts, subdomains, source, collectedAt, error: null };
  } catch (err) {
    return {
      certificates: [],
      subdomains: [],
      source,
      collectedAt,
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}
