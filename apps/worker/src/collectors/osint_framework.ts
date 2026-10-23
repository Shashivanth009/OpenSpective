// OpenSpective — OSINT Framework Search Techniques & Public Intelligence Engine
// Integrates core OSINT Framework methodologies (osintframework.com):
// - Public PGP / GPG Key Server discovery (Ubuntu Keyserver / SKS)
// - Abuse.ch URLhaus threat IOC lookup
// - Multi-engine targeted OSINT search dorks (Google, GitHub, Pastebin, Shodan, Censys, S3 Buckets)
// - Corporate registries & Public record pivots (SEC EDGAR, OpenCorporates)
// - Subdomain & Cloud Infrastructure reconnaissance

import type { TargetType } from '@openspective/shared';

export interface PgpKeyRecord {
  keyId: string;
  fingerprint?: string;
  algorithm: string;
  bitLength?: number;
  creationDate: string;
  identities: string[];
  keyserverUrl: string;
}

export interface OsintDorkItem {
  category: 'sensitive_documents' | 'exposed_secrets' | 'auth_portals' | 'cloud_buckets' | 'code_leaks' | 'pastes' | 'infrastructure' | 'corporate_records' | 'social_mentions';
  title: string;
  query: string;
  searchUrl: string;
  platform: 'Google' | 'GitHub' | 'Shodan' | 'Censys' | 'OpenCorporates' | 'Pastebin' | 'Wayback';
  description: string;
}

export interface UrlhausThreatResult {
  queryStatus: string;
  host?: string;
  threatStatus: 'clean' | 'malicious' | 'unknown';
  activePayloadsCount: number;
  urlCount: number;
  tags: string[];
  referenceUrl?: string;
}

export interface OsintFrameworkResult {
  target: string;
  targetType: TargetType;
  pgpKeys: PgpKeyRecord[];
  threatIntel?: UrlhausThreatResult;
  searchDorks: OsintDorkItem[];
  cloudStorageBuckets: Array<{ provider: string; url: string; checkStatus: string }>;
  collectedAt: string;
  source: string;
}

// ---- Query Ubuntu / SKS PGP Keyserver ----
export async function queryPgpKeyserver(query: string): Promise<PgpKeyRecord[]> {
  try {
    const url = `https://keyserver.ubuntu.com/pks/lookup?search=${encodeURIComponent(query)}&op=index&options=mr`;
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(6000),
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; OpenSpective/0.1; +https://openspective.com)' },
    });

    if (!resp.ok) return [];
    const text = await resp.text();
    const lines = text.split('\n');
    const records: PgpKeyRecord[] = [];

    let currentKey: Partial<PgpKeyRecord> | null = null;
    let currentIdentities: string[] = [];

    for (const line of lines) {
      const parts = line.split(':');
      const recordType = parts[0];

      if (recordType === 'pub') {
        if (currentKey && currentKey.keyId) {
          records.push({
            keyId: currentKey.keyId,
            fingerprint: currentKey.fingerprint,
            algorithm: currentKey.algorithm || 'RSA',
            bitLength: currentKey.bitLength,
            creationDate: currentKey.creationDate || 'Unknown',
            identities: currentIdentities,
            keyserverUrl: `https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${currentKey.keyId}`,
          });
        }

        const keyId = parts[1] || '';
        const algoNum = parts[2] || '';
        const keyLen = parts[3] ? parseInt(parts[3], 10) || undefined : undefined;
        const timestamp = parts[4] ? new Date(parseInt(parts[4], 10) * 1000).toISOString().split('T')[0] : 'Unknown';

        currentKey = {
          keyId,
          algorithm: algoNum === '1' ? 'RSA' : algoNum === '17' ? 'DSA' : 'Pubkey',
          bitLength: keyLen,
          creationDate: timestamp,
        };
        currentIdentities = [];
      } else if (recordType === 'uid') {
        const rawUid = parts[1] ? decodeURIComponent(parts[1]) : '';
        if (rawUid) currentIdentities.push(rawUid);
      } else if (recordType === 'fpr') {
        if (currentKey) currentKey.fingerprint = parts[1] || '';
      }
    }

    if (currentKey && currentKey.keyId) {
      records.push({
        keyId: currentKey.keyId,
        fingerprint: currentKey.fingerprint,
        algorithm: currentKey.algorithm || 'RSA',
        bitLength: currentKey.bitLength,
        creationDate: currentKey.creationDate || 'Unknown',
        identities: currentIdentities,
        keyserverUrl: `https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${currentKey.keyId}`,
      });
    }

    return records.slice(0, 10);
  } catch {
    return [];
  }
}

// ---- Query Abuse.ch URLhaus Passive Threat Intelligence ----
export async function queryUrlhausHost(target: string): Promise<UrlhausThreatResult> {
  try {
    const formData = new URLSearchParams();
    formData.append('host', target);

    const resp = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      body: formData,
      signal: AbortSignal.timeout(6000),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    if (!resp.ok) {
      return { queryStatus: 'error', threatStatus: 'unknown', activePayloadsCount: 0, urlCount: 0, tags: [] };
    }

    const data = await resp.json() as {
      query_status?: string;
      host?: string;
      url_count?: number;
      urls?: Array<{ url_status?: string; tags?: string[] }>;
    };

    if (data.query_status === 'no_results' || !data.urls || data.urls.length === 0) {
      return { queryStatus: 'no_results', host: target, threatStatus: 'clean', activePayloadsCount: 0, urlCount: 0, tags: [] };
    }

    const allTags = new Set<string>();
    let activeCount = 0;
    for (const item of data.urls) {
      if (item.url_status === 'online') activeCount++;
      if (Array.isArray(item.tags)) item.tags.forEach(t => allTags.add(t));
    }

    return {
      queryStatus: 'ok',
      host: target,
      threatStatus: activeCount > 0 ? 'malicious' : 'clean',
      activePayloadsCount: activeCount,
      urlCount: data.url_count || data.urls.length,
      tags: Array.from(allTags).slice(0, 8),
      referenceUrl: `https://urlhaus.abuse.ch/host/${encodeURIComponent(target)}/`,
    };
  } catch {
    return { queryStatus: 'timeout', threatStatus: 'unknown', activePayloadsCount: 0, urlCount: 0, tags: [] };
  }
}

// ---- Generate OSINT Framework Search Dorks Matrix ----
export function generateOsintFrameworkDorks(target: string, type: TargetType): OsintDorkItem[] {
  const dorks: OsintDorkItem[] = [];
  const cleanTarget = target.trim();
  const hostPart = cleanTarget.replace(/^https?:\/\//i, '').split('/')[0] || '';
  const slug = hostPart.replace(/[^a-zA-Z0-9.-]/g, '');

  if (type === 'domain' || type === 'url' || type === 'organization') {
    // 1. Confidential & Sensitive Documents
    const docQuery = `site:${slug} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:pptx) ("confidential" OR "internal use only" OR "strictly private" OR "not for distribution")`;
    dorks.push({
      category: 'sensitive_documents',
      title: 'Confidential & Proprietary Documents',
      query: docQuery,
      searchUrl: `https://www.google.com/search?q=${encodeURIComponent(docQuery)}`,
      platform: 'Google',
      description: 'Finds published PDFs, spreadsheets, and Word documents marked as confidential or internal.',
    });

    // 2. Exposed Configurations & Environment Variables
    const envQuery = `site:${slug} (filetype:env OR filetype:yml OR filetype:yaml OR filetype:json OR filetype:conf OR filetype:ini OR filetype:sql OR filetype:log) ("DB_PASSWORD" OR "api_key" OR "secret" OR "AWS_SECRET_ACCESS_KEY" OR "BEGIN RSA PRIVATE KEY")`;
    dorks.push({
      category: 'exposed_secrets',
      title: 'Exposed Configs & Private Credentials',
      query: envQuery,
      searchUrl: `https://www.google.com/search?q=${encodeURIComponent(envQuery)}`,
      platform: 'Google',
      description: 'Identifies leaked environment variables, database configuration files, and private keys.',
    });

    // 3. Administrative Portals & Dashboards
    const adminQuery = `site:${slug} (inurl:admin OR inurl:login OR inurl:portal OR inurl:cpanel OR inurl:dashboard OR inurl:phpmyadmin OR inurl:kibana OR inurl:grafana)`;
    dorks.push({
      category: 'auth_portals',
      title: 'Administrative & Single Sign-On Portals',
      query: adminQuery,
      searchUrl: `https://www.google.com/search?q=${encodeURIComponent(adminQuery)}`,
      platform: 'Google',
      description: 'Locates publicly exposed administrative interfaces, login pages, and monitoring consoles.',
    });

    // 4. Directory Listings & Exposed Backups
    const dirQuery = `site:${slug} (intitle:"index of /" OR inurl:/backup OR inurl:/backups OR inurl:/dump OR inurl:/db_backup OR intitle:"Index of /wp-content/uploads")`;
    dorks.push({
      category: 'infrastructure',
      title: 'Directory Traversal & Exposed Backups',
      query: dirQuery,
      searchUrl: `https://www.google.com/search?q=${encodeURIComponent(dirQuery)}`,
      platform: 'Google',
      description: 'Uncovers web servers with open directory browsing or database backup archives.',
    });

    // 5. GitHub Public Code & Secrets Search
    const ghQuery = `"${slug}" (password OR token OR secret OR api_key OR client_secret OR bearer)`;
    dorks.push({
      category: 'code_leaks',
      title: 'GitHub Secret & Token Leaks',
      query: ghQuery,
      searchUrl: `https://github.com/search?q=${encodeURIComponent(ghQuery)}&type=code`,
      platform: 'GitHub',
      description: 'Searches public GitHub repositories for hardcoded API keys and authorization tokens.',
    });

    // 6. Public Pastes & Leak Corpuses
    const pasteQuery = `site:pastebin.com OR site:rentry.co OR site:ghostbin.com OR site:justpaste.it "${slug}"`;
    dorks.push({
      category: 'pastes',
      title: 'Public Pastebin & Dumpster Dumps',
      query: pasteQuery,
      searchUrl: `https://www.google.com/search?q=${encodeURIComponent(pasteQuery)}`,
      platform: 'Pastebin',
      description: 'Monitors public paste sites for leaked source code, credentials, and compromised accounts.',
    });

    // 7. Shodan Passive Hostname Search
    dorks.push({
      category: 'infrastructure',
      title: 'Shodan Passive Sensor Intelligence',
      query: `hostname:${slug}`,
      searchUrl: `https://www.shodan.io/search?query=${encodeURIComponent('hostname:' + slug)}`,
      platform: 'Shodan',
      description: 'Explores global banner sensors, SSL cert matches, and open services associated with this domain.',
    });

    // 8. Censys Public Attack Surface
    dorks.push({
      category: 'infrastructure',
      title: 'Censys Global Internet Intelligence',
      query: slug,
      searchUrl: `https://search.censys.io/hosts?q=${encodeURIComponent(slug)}`,
      platform: 'Censys',
      description: 'Queries Censys scanning engine for historical certificates, IP infrastructure, and TLS handshakes.',
    });

    // 9. OpenCorporates Company Registry
    const corpName = slug.split('.')[0] || slug;
    dorks.push({
      category: 'corporate_records',
      title: 'OpenCorporates Legal Registry',
      query: corpName,
      searchUrl: `https://opencorporates.com/companies?q=${encodeURIComponent(corpName)}`,
      platform: 'OpenCorporates',
      description: 'Cross-references company names against global corporate filings, officers, and legal subsidiaries.',
    });
  } else if (type === 'email') {
    // Email OSINT Techniques
    const mailQuery = `"${cleanTarget}"`;
    dorks.push({
      category: 'social_mentions',
      title: 'Direct Identity Mentions',
      query: mailQuery,
      searchUrl: `https://www.google.com/search?q=${encodeURIComponent(mailQuery)}`,
      platform: 'Google',
      description: 'Searches the web for exact-match occurrences of this email address in forums, profiles, and filings.',
    });

    const leakQuery = `site:pastebin.com OR site:rentry.co OR site:justpaste.it "${cleanTarget}"`;
    dorks.push({
      category: 'pastes',
      title: 'Credential Leak Paste Searches',
      query: leakQuery,
      searchUrl: `https://www.google.com/search?q=${encodeURIComponent(leakQuery)}`,
      platform: 'Pastebin',
      description: 'Searches public dump sites for raw credential combinations and combo lists.',
    });

    const ghCommitQuery = `"${cleanTarget}" in:commits`;
    dorks.push({
      category: 'code_leaks',
      title: 'GitHub Commit Author Verification',
      query: ghCommitQuery,
      searchUrl: `https://github.com/search?q=${encodeURIComponent(ghCommitQuery)}&type=commits`,
      platform: 'GitHub',
      description: 'Finds verified git commit signatures linked to this email address.',
    });
  } else if (type === 'username') {
    // Username OSINT Techniques
    const userQuery = `"${cleanTarget}" (profile OR bio OR contact OR "about me")`;
    dorks.push({
      category: 'social_mentions',
      title: 'Cross-Platform Handle Search',
      query: userQuery,
      searchUrl: `https://www.google.com/search?q=${encodeURIComponent(userQuery)}`,
      platform: 'Google',
      description: 'Uncovers user biographies, personal websites, and public social handle footprints.',
    });

    const ghUserCodeQuery = `"${cleanTarget}" (password OR secret OR token)`;
    dorks.push({
      category: 'code_leaks',
      title: 'GitHub User Code Mentions',
      query: ghUserCodeQuery,
      searchUrl: `https://github.com/search?q=${encodeURIComponent(ghUserCodeQuery)}&type=code`,
      platform: 'GitHub',
      description: 'Searches public repositories for code comments, configurations, or leaks referencing this username.',
    });
  } else if (type === 'ip') {
    // IP OSINT Techniques
    dorks.push({
      category: 'infrastructure',
      title: 'Shodan IP Deep Profile',
      query: `ip:${cleanTarget}`,
      searchUrl: `https://www.shodan.io/host/${encodeURIComponent(cleanTarget)}`,
      platform: 'Shodan',
      description: 'View full Shodan host profile with vulnerabilities, open ports, and historical TLS certificates.',
    });

    dorks.push({
      category: 'infrastructure',
      title: 'Censys IP Host View',
      query: cleanTarget,
      searchUrl: `https://search.censys.io/hosts/${encodeURIComponent(cleanTarget)}`,
      platform: 'Censys',
      description: 'View Censys host page with service banners, autonomous system (ASN), and geolocation details.',
    });

    const ipDocQuery = `"${cleanTarget}" (confidential OR internal OR router OR switch OR vpn)`;
    dorks.push({
      category: 'sensitive_documents',
      title: 'Public Mentions of IP Address',
      query: ipDocQuery,
      searchUrl: `https://www.google.com/search?q=${encodeURIComponent(ipDocQuery)}`,
      platform: 'Google',
      description: 'Identifies configuration guides, network diagrams, and forum posts referencing this IP address.',
    });
  }

  return dorks;
}

// ---- Cloud Storage Bucket Permutation Recon ----
export function generateCloudBucketPermutations(target: string): Array<{ provider: string; url: string; checkStatus: string }> {
  const hostPart = target.toLowerCase().replace(/^https?:\/\//i, '').split('/')[0] || '';
  const baseName = hostPart.replace(/[^a-z0-9]/g, '');
  if (!baseName || baseName.length < 3) return [];

  const candidates = [
    baseName,
    `${baseName}-data`,
    `${baseName}-backup`,
    `${baseName}-assets`,
    `${baseName}-public`,
  ];

  const buckets: Array<{ provider: string; url: string; checkStatus: string }> = [];

  for (const name of candidates.slice(0, 3)) {
    buckets.push({
      provider: 'Amazon Web Services (S3)',
      url: `https://${name}.s3.amazonaws.com/`,
      checkStatus: 'Permutation Generated',
    });
    buckets.push({
      provider: 'Google Cloud Storage',
      url: `https://storage.googleapis.com/${name}/`,
      checkStatus: 'Permutation Generated',
    });
    buckets.push({
      provider: 'Microsoft Azure Blob',
      url: `https://${name}.blob.core.windows.net/`,
      checkStatus: 'Permutation Generated',
    });
  }

  return buckets;
}

// ---- Main OSINT Framework Collector Entry Point ----
export async function collectOsintFramework(target: string, type: TargetType): Promise<OsintFrameworkResult> {
  const collectedAt = new Date().toISOString();

  // 1. PGP Key Server search (for emails, people, domains)
  let pgpKeys: PgpKeyRecord[] = [];
  if (type === 'email' || type === 'person' || type === 'domain') {
    pgpKeys = await queryPgpKeyserver(target);
  }

  // 2. Abuse.ch URLhaus threat check (for domains and IPs)
  let threatIntel: UrlhausThreatResult | undefined = undefined;
  if (type === 'domain' || type === 'ip' || type === 'url') {
    const hostSegment = target.replace(/^https?:\/\//i, '').split('/')[0] || '';
    const cleanHost = hostSegment.split(':')[0] || target;
    threatIntel = await queryUrlhausHost(cleanHost);
  }

  // 3. Search Dorks Matrix
  const searchDorks = generateOsintFrameworkDorks(target, type);

  // 4. Cloud Storage Permutations
  const cloudStorageBuckets = (type === 'domain' || type === 'organization') ? generateCloudBucketPermutations(target) : [];

  return {
    target,
    targetType: type,
    pgpKeys,
    threatIntel,
    searchDorks,
    cloudStorageBuckets,
    collectedAt,
    source: 'OpenSpective OSINT Framework Engine',
  };
}
