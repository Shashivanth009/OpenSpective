// OpenSpective — Collector Registry
// Defines all available collectors and their applicability per target type.

import type { TargetType, ModuleInfo } from '@openspective/shared';
import type { Env } from '../env.ts';

export interface CollectorDefinition {
  name: string;
  displayName: string;
  description: string;
  targetTypes: TargetType[];
  requiresCredentials: boolean;
  credentialKey?: string;
  limitations?: string[];
  isConfigured: (env?: Env) => boolean;
}

export const COLLECTORS: CollectorDefinition[] = [
  {
    name: 'dns',
    displayName: 'DNS Intelligence',
    description: 'Retrieves DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA) using Cloudflare DNS over HTTPS.',
    targetTypes: ['domain', 'email', 'url', 'organization'],
    requiresCredentials: false,
    limitations: ['Limited to publicly accessible DNS records.'],
    isConfigured: () => true, // Uses CF DoH — always available
  },
  {
    name: 'rdap',
    displayName: 'RDAP Registration',
    description: 'Retrieves domain or IP registration data from RDAP/WHOIS services.',
    targetTypes: ['domain', 'ip', 'email', 'url'],
    requiresCredentials: false,
    limitations: ['Many registration fields are redacted per GDPR/ICANN policy.'],
    isConfigured: () => true,
  },
  {
    name: 'certificate_transparency',
    displayName: 'Certificate Transparency',
    description: 'Discovers certificates and subdomains via crt.sh certificate transparency logs.',
    targetTypes: ['domain', 'email', 'url', 'organization'],
    requiresCredentials: false,
    limitations: ['Results are limited to certificates in CT logs. Wildcard results may be omitted.'],
    isConfigured: () => true,
  },
  {
    name: 'ipinfo',
    displayName: 'IP Information',
    description: 'Retrieves public IP geolocation, ASN, and organization data via ipinfo.io.',
    targetTypes: ['ip', 'domain'],
    requiresCredentials: false, // free tier works without token
    credentialKey: 'IPINFO_TOKEN',
    limitations: ['Free tier is rate-limited to 50k requests/month.', 'Geolocation is approximate.'],
    isConfigured: () => true, // works without token with lower limits
  },
  {
    name: 'virustotal',
    displayName: 'VirusTotal Intelligence',
    description: 'Checks domains, IPs, and URLs against VirusTotal threat intelligence.',
    targetTypes: ['domain', 'ip', 'url', 'email'],
    requiresCredentials: true,
    credentialKey: 'VIRUSTOTAL_API_KEY',
    limitations: ['Requires a VirusTotal API key (free tier available).', 'Public API limited to 4 requests/minute.'],
    isConfigured: (env?: Env) => !!env?.VIRUSTOTAL_API_KEY,
  },
  {
    name: 'github',
    displayName: 'GitHub Public Repositories',
    description: 'Searches GitHub for public repositories associated with an organization or username.',
    targetTypes: ['organization', 'username', 'email', 'domain'],
    requiresCredentials: false,
    credentialKey: 'GITHUB_TOKEN',
    limitations: ['Unauthenticated requests limited to 60/hour.', 'Only searches public repositories.'],
    isConfigured: () => true, // works without token
  },
  {
    name: 'email_dns',
    displayName: 'Email Security Records',
    description: 'Checks SPF, DKIM-related, and DMARC DNS records for email domains.',
    targetTypes: ['email', 'domain'],
    requiresCredentials: false,
    limitations: ['DKIM record discovery requires known selector names.'],
    isConfigured: () => true,
  },
  {
    name: 'haveibeenpwned',
    displayName: 'HaveIBeenPwned Breach Check',
    description: 'Checks if an email address appears in known public breach notifications. Never exposes passwords.',
    targetTypes: ['email'],
    requiresCredentials: true,
    credentialKey: 'HAVE_I_BEEN_PWNED_API_KEY',
    limitations: [
      'Requires HaveIBeenPwned API key (subscription required).',
      'Reports breach names only — passwords or credentials are never exposed.',
    ],
    isConfigured: (env?: Env) => !!env?.HAVE_I_BEEN_PWNED_API_KEY,
  },
  {
    name: 'url_metadata',
    displayName: 'URL Metadata',
    description: 'Fetches page title, HTTP status, and basic metadata for a URL (bounded, single request).',
    targetTypes: ['url'],
    requiresCredentials: false,
    limitations: ['Single bounded request only. Respects robots.txt. No crawling.'],
    isConfigured: () => true,
  },
  {
    name: 'person_search',
    displayName: 'Public Person & Entity Search',
    description: 'Searches public indices (GitHub users by name, Wikipedia articles, Wikidata knowledge graph, HackerNews mentions).',
    targetTypes: ['person'],
    requiresCredentials: false,
    credentialKey: 'GITHUB_TOKEN',
    limitations: ['Name matching across open public indices. Does not access restricted identity databases.'],
    isConfigured: () => true,
  },
  {
    name: 'username_presence',
    displayName: 'Cross-Platform Username Footprint',
    description: 'Checks profile availability across GitHub, GitLab, HackerNews, PyPI, NPM, Keybase, DEV, and Hashnode.',
    targetTypes: ['username', 'person'],
    requiresCredentials: false,
    limitations: ['Public HTTP status verification. Subject to third-party web rate limits.'],
    isConfigured: () => true,
  },
  {
    name: 'email_identity',
    displayName: 'Email & Developer Attribution',
    description: 'Discovers verified git commits, real author names, linked GitHub profiles, Gravatar accounts, and handle footprints.',
    targetTypes: ['email'],
    requiresCredentials: false,
    credentialKey: 'GITHUB_TOKEN',
    limitations: ['Searches public repositories and open registries only.'],
    isConfigured: () => true,
  },
  {
    name: 'web_archive',
    displayName: 'Wayback Machine Archive',
    description: 'Searches Internet Archive CDX index for historical snapshots, first-seen timestamps, and archived endpoints.',
    targetTypes: ['domain', 'url', 'organization'],
    requiresCredentials: false,
    limitations: ['Limited to URLs indexed by the Internet Archive Wayback Machine.'],
    isConfigured: () => true,
  },
  {
    name: 'tech_stack',
    displayName: 'Security Headers & Tech Stack',
    description: 'Audits HTTP security hygiene (HSTS, CSP, X-Frame-Options) and detects web servers & CDN/WAF defenses.',
    targetTypes: ['domain', 'url', 'organization'],
    requiresCredentials: false,
    limitations: ['Passively inspects publicly exposed HTTP response headers.'],
    isConfigured: () => true,
  },
  {
    name: 'crypto',
    displayName: 'Blockchain & Crypto Forensics',
    description: 'Analyzes Bitcoin, Ethereum, Solana, and TRON wallet addresses for balance, transactions, and activity.',
    targetTypes: ['crypto_wallet', 'person', 'username'],
    requiresCredentials: false,
    limitations: ['Connects to open blockchain explorers. Smart contract execution tracing is bounded.'],
    isConfigured: () => true,
  },
  {
    name: 'breach',
    displayName: 'Breach & Credential Exposure',
    description: 'Correlates target against known historical data breaches and credential exposure catalogs.',
    targetTypes: ['email', 'domain', 'username'],
    requiresCredentials: false,
    credentialKey: 'HAVE_I_BEEN_PWNED_API_KEY',
    limitations: ['Does not expose passwords or private personal credentials. Strictly reports leak exposure.'],
    isConfigured: () => true,
  },
  {
    name: 'location',
    displayName: 'Geolocation & Places Intelligence',
    description: 'Geocodes physical locations, profiles, and commit timezone signatures into coordinates with OpenStreetMap and Google Maps links.',
    targetTypes: ['person', 'email', 'username', 'organization', 'ip'],
    requiresCredentials: false,
    limitations: ['Passive geocoding via OpenStreetMap Nominatim and timezone inference.'],
    isConfigured: () => true,
  },
  {
    name: 'shodan',
    displayName: 'Shodan InternetDB (Ports & CVEs)',
    description: 'Passively maps open network ports, detected software CPEs, and known CVE vulnerabilities without active socket probing.',
    targetTypes: ['ip', 'domain'],
    requiresCredentials: false,
    limitations: ['Queries Shodan InternetDB global passive sensors. Historical data may vary.'],
    isConfigured: () => true,
  },
  {
    name: 'phone',
    displayName: 'International Phone Intelligence',
    description: 'Analyzes international ITU-T E.164 dialing plans, telecom region, line type (mobile/fixed/toll-free), and OSINT search pivots.',
    targetTypes: ['phone'],
    requiresCredentials: false,
    limitations: ['E.164 numbering plan allocation analysis. Does not perform live SS7/HLR carrier subscriber tracking.'],
    isConfigured: () => true,
  },
  {
    name: 'dns_security',
    displayName: 'DNS & Email Security Hygiene',
    description: 'Audits SPF, DMARC, BIMI, MTA-STS, TLS-RPT, and DNSSEC defenses and grades domain spoofability.',
    targetTypes: ['domain', 'email', 'organization'],
    requiresCredentials: false,
    limitations: ['Audits public DNS records via Cloudflare DoH.'],
    isConfigured: () => true,
  },
];

// Get collectors applicable to a target type
export function getCollectorsForTargetType(
  targetType: TargetType,
  env?: Env
): { available: ModuleInfo[]; unavailable: ModuleInfo[] } {
  const applicable = COLLECTORS.filter(c => c.targetTypes.includes(targetType));
  const available: ModuleInfo[] = [];
  const unavailable: ModuleInfo[] = [];

  for (const collector of applicable) {
    const info: ModuleInfo = {
      name: collector.name,
      displayName: collector.displayName,
      description: collector.description,
      targetTypes: collector.targetTypes,
      isConfigured: collector.isConfigured(env),
      isAvailable: collector.isConfigured(env),
      requiresCredentials: collector.requiresCredentials,
      credentialKey: collector.credentialKey,
      limitations: collector.limitations,
    };
    if (info.isAvailable) {
      available.push(info);
    } else {
      unavailable.push(info);
    }
  }

  return { available, unavailable };
}

// Get all collectors
export function getAllCollectors(env?: Env): ModuleInfo[] {
  return COLLECTORS.map(c => ({
    name: c.name,
    displayName: c.displayName,
    description: c.description,
    targetTypes: c.targetTypes,
    isConfigured: c.isConfigured(env),
    isAvailable: c.isConfigured(env),
    requiresCredentials: c.requiresCredentials,
    credentialKey: c.credentialKey,
    limitations: c.limitations,
  }));
}
