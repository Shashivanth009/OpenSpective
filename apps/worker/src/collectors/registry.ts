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
