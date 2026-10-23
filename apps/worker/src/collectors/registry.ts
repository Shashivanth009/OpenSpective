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
    displayName: 'Authoritative DNS (Cloudflare DoH)',
    description: 'Retrieves authoritative DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA) using Cloudflare DNS over HTTPS.',
    targetTypes: ['domain', 'email', 'url', 'organization'],
    requiresCredentials: false,
    limitations: ['Limited to publicly accessible DNS records.'],
    isConfigured: () => true,
  },
  {
    name: 'rdap',
    displayName: 'RDAP & WHOIS (IANA / Verisign)',
    description: 'Retrieves authoritative domain and IP registration data from ICANN RDAP and regional internet registries.',
    targetTypes: ['domain', 'ip', 'email', 'url'],
    requiresCredentials: false,
    limitations: ['Many registration fields are redacted per GDPR/ICANN policy.'],
    isConfigured: () => true,
  },
  {
    name: 'certificate_transparency',
    displayName: 'Subfinder & crt.sh (Subdomains)',
    description: 'Discovers active subdomains, root domains, and historical SSL/TLS certificates via crt.sh CT log streams.',
    targetTypes: ['domain', 'email', 'url', 'organization'],
    requiresCredentials: false,
    limitations: ['Results are limited to certificates logged in CT infrastructure.'],
    isConfigured: () => true,
  },
  {
    name: 'ipinfo',
    displayName: 'IPinfo Geolocation & ASN Mapping',
    description: 'Retrieves public IP geolocation, autonomous system numbers (ASN), carrier, and organization route mapping.',
    targetTypes: ['ip', 'domain'],
    requiresCredentials: false,
    credentialKey: 'IPINFO_TOKEN',
    limitations: ['Geolocation is approximate to city/region level.'],
    isConfigured: () => true,
  },
  {
    name: 'virustotal',
    displayName: 'VirusTotal Threat Intelligence',
    description: 'Cross-checks domains, IPs, and URLs across 70+ antivirus and threat intelligence engines.',
    targetTypes: ['domain', 'ip', 'url', 'email'],
    requiresCredentials: true,
    credentialKey: 'VIRUSTOTAL_API_KEY',
    limitations: ['Requires a VirusTotal API key (free tier available).'],
    isConfigured: (env?: Env) => !!env?.VIRUSTOTAL_API_KEY,
  },
  {
    name: 'github',
    displayName: 'GitHub Public Intelligence & Repos',
    description: 'Searches public GitHub repositories, code commits, contributors, and organizational structures.',
    targetTypes: ['organization', 'username', 'email', 'domain'],
    requiresCredentials: false,
    credentialKey: 'GITHUB_TOKEN',
    limitations: ['Unauthenticated requests limited to 60/hour.'],
    isConfigured: () => true,
  },
  {
    name: 'email_dns',
    displayName: 'Email Security Records (SPF/DMARC)',
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
    limitations: ['Reports breach names only — passwords or credentials are never exposed.'],
    isConfigured: (env?: Env) => !!env?.HAVE_I_BEEN_PWNED_API_KEY,
  },
  {
    name: 'url_metadata',
    displayName: 'URL Metadata & Headers',
    description: 'Fetches page title, HTTP status, and basic metadata for a URL (bounded, single request).',
    targetTypes: ['url'],
    requiresCredentials: false,
    limitations: ['Single bounded request only. Respects robots.txt.'],
    isConfigured: () => true,
  },
  {
    name: 'person_search',
    displayName: 'Public Person & Entity Search',
    description: 'Searches public indices (GitHub users by name, Wikipedia articles, Wikidata knowledge graph, HackerNews mentions).',
    targetTypes: ['person'],
    requiresCredentials: false,
    credentialKey: 'GITHUB_TOKEN',
    limitations: ['Name matching across open public indices.'],
    isConfigured: () => true,
  },
  {
    name: 'username_presence',
    displayName: 'Sherlock & WhatsMyName (Profiles)',
    description: 'Performs zero-false-positive profile verification across GitHub, GitLab, DockerHub, NPM, Keybase, HackerNews, Mastodon, and 15+ registries.',
    targetTypes: ['username', 'person'],
    requiresCredentials: false,
    limitations: ['Public API status verification with strict payload validation.'],
    isConfigured: () => true,
  },
  {
    name: 'email_identity',
    displayName: 'theHarvester & Hunter (Email Recon)',
    description: 'Discovers verified git commits, real author names, linked GitHub profiles, Gravatar accounts, and handle footprints.',
    targetTypes: ['email'],
    requiresCredentials: false,
    credentialKey: 'GITHUB_TOKEN',
    limitations: ['Searches public repositories and open registries only.'],
    isConfigured: () => true,
  },
  {
    name: 'web_archive',
    displayName: 'Waybackurls & GAU (Historical Archives)',
    description: 'Searches Internet Archive CDX index for historical snapshots, first-seen timestamps, and archived endpoints.',
    targetTypes: ['domain', 'url', 'organization'],
    requiresCredentials: false,
    limitations: ['Limited to URLs indexed by the Internet Archive Wayback Machine.'],
    isConfigured: () => true,
  },
  {
    name: 'tech_stack',
    displayName: 'Wappalyzer & BuiltWith (Tech Stack)',
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
    limitations: ['Connects to open blockchain explorers.'],
    isConfigured: () => true,
  },
  {
    name: 'breach',
    displayName: 'Have I Been Pwned & Breach Records',
    description: 'Correlates target against known historical data breaches and credential exposure catalogs.',
    targetTypes: ['email', 'domain', 'username'],
    requiresCredentials: false,
    credentialKey: 'HAVE_I_BEEN_PWNED_API_KEY',
    limitations: ['Strictly reports leak exposure without sensitive credentials.'],
    isConfigured: () => true,
  },
  {
    name: 'location',
    displayName: 'Bellingcat & OpenStreetMap (GEOINT)',
    description: 'Geocodes physical locations, profiles, and commit timezone signatures into coordinates with OpenStreetMap and Google Maps links.',
    targetTypes: ['person', 'email', 'username', 'organization', 'ip'],
    requiresCredentials: false,
    limitations: ['Passive geocoding via OpenStreetMap Nominatim and timezone inference.'],
    isConfigured: () => true,
  },
  {
    name: 'shodan',
    displayName: 'Shodan & Censys (Ports & CVEs)',
    description: 'Passively maps open network ports, detected software CPEs, and known CVE vulnerabilities without active socket probing.',
    targetTypes: ['ip', 'domain'],
    requiresCredentials: false,
    limitations: ['Queries global passive sensor databases.'],
    isConfigured: () => true,
  },
  {
    name: 'phone',
    displayName: 'PhoneInfoga & Telephony Intelligence',
    description: 'Analyzes international ITU-T E.164 dialing plans, telecom region, line type (mobile/fixed/toll-free), and OSINT search pivots.',
    targetTypes: ['phone'],
    requiresCredentials: false,
    limitations: ['E.164 numbering plan allocation analysis.'],
    isConfigured: () => true,
  },
  {
    name: 'dns_security',
    displayName: 'SecurityHeaders & Defensive DNS Hygiene',
    description: 'Audits SPF, DMARC, BIMI, MTA-STS, TLS-RPT, and DNSSEC defenses and grades domain spoofability.',
    targetTypes: ['domain', 'email', 'organization'],
    requiresCredentials: false,
    limitations: ['Audits public DNS records via Cloudflare DoH.'],
    isConfigured: () => true,
  },
  {
    name: 'threat_intel',
    displayName: 'Abuse.ch URLhaus & ThreatFox',
    description: 'Queries live abuse databases for malware distribution payloads, malicious host reputation, and botnet command & control indicators.',
    targetTypes: ['domain', 'ip', 'url', 'organization'],
    requiresCredentials: false,
    limitations: ['Queries real-time open threat intelligence datasets.'],
    isConfigured: () => true,
  },
  {
    name: 'cloud_storage',
    displayName: 'S3Scanner & CloudEnum (Cloud Buckets)',
    description: 'Enumerates storage bucket naming permutations across Amazon Web Services S3, Google Cloud Storage, and Azure Blobs.',
    targetTypes: ['domain', 'organization', 'url'],
    requiresCredentials: false,
    limitations: ['Tests standard passive bucket endpoint permutations.'],
    isConfigured: () => true,
  },
  {
    name: 'search_dorks',
    displayName: 'Google Dorks & Search Intelligence',
    description: 'Compiles and checks targeted search queries across Google, GitHub Code, Shodan, Censys, FOFA, and Pastebin.',
    targetTypes: ['domain', 'ip', 'email', 'username', 'url', 'organization', 'person', 'phone'],
    requiresCredentials: false,
    limitations: ['Generates multi-engine search dorks tailored to the target.'],
    isConfigured: () => true,
  },
  {
    name: 'pgp_keys',
    displayName: 'Ubuntu PGP Public Keyserver',
    description: 'Queries Ubuntu / SKS PGP keyservers for cryptographic public keys, email identities, and creation timestamps.',
    targetTypes: ['email', 'person', 'username', 'organization', 'domain'],
    requiresCredentials: false,
    limitations: ['Queries SKS HKP keyserver protocol.'],
    isConfigured: () => true,
  },
  {
    name: 'osint_framework',
    displayName: 'OSINT Framework & Deep Search Engine',
    description: 'Synthesizes all 18 OSINT Framework categories, tool pivots, and target techniques at one place.',
    targetTypes: ['domain', 'ip', 'email', 'username', 'url', 'organization', 'person', 'phone'],
    requiresCredentials: false,
    limitations: ['Integrates open-source intelligence methods without active exploitation.'],
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
