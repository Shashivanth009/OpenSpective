// OpenSpective — Wayback Machine & Web Archive Collector
// Passive historical recon using the Internet Archive Wayback Machine CDX API.
// No API key required.

export interface ArchiveSnapshot {
  originalUrl: string;
  timestamp: string;
  formattedDate: string;
  mimeType: string;
  statusCode: string;
  archiveUrl: string;
}

export interface WebArchiveResults {
  domain: string;
  firstSeen: string | null;
  lastSeen: string | null;
  totalSnapshotsFound: number;
  snapshots: ArchiveSnapshot[];
  interestingPaths: string[];
  collectedAt: string;
  source: string;
  error?: string;
}

export async function collectWebArchive(domain: string): Promise<WebArchiveResults> {
  const collectedAt = new Date().toISOString();
  const cleanDomain = domain.toLowerCase().replace(/^(https?:\/\/)/, '').replace(/\/.*$/, '').trim();

  try {
    // Query CDX API for up to 25 historical snapshots
    const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(cleanDomain)}/*&output=json&limit=25&fl=original,timestamp,mimetype,statuscode&filter=statuscode:200`;
    
    const resp = await fetch(cdxUrl, {
      signal: AbortSignal.timeout(8000),
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; OpenSpective/0.1; +https://openspective.com/bot)',
        Accept: 'application/json',
      },
    });

    if (!resp.ok) {
      return {
        domain: cleanDomain,
        firstSeen: null,
        lastSeen: null,
        totalSnapshotsFound: 0,
        snapshots: [],
        interestingPaths: [],
        collectedAt,
        source: 'Wayback Machine (Internet Archive CDX)',
        error: `Archive CDX returned HTTP ${resp.status}`,
      };
    }

    const rows = await resp.json() as string[][];
    if (!Array.isArray(rows) || rows.length <= 1) {
      return {
        domain: cleanDomain,
        firstSeen: null,
        lastSeen: null,
        totalSnapshotsFound: 0,
        snapshots: [],
        interestingPaths: [],
        collectedAt,
        source: 'Wayback Machine (Internet Archive CDX)',
      };
    }

    // First row is header: ["original", "timestamp", "mimetype", "statuscode"]
    const dataRows = rows.slice(1);
    const snapshots: ArchiveSnapshot[] = [];
    const interestingKeywords = ['admin', 'api', 'login', 'backup', 'config', 'staging', 'dev', 'portal', 'test', 'v1', 'v2', 'git', 'env', 'docs', 'internal'];
    const interestingPathsSet = new Set<string>();

    let earliestTs = '';
    let latestTs = '';

    for (const row of dataRows) {
      const [originalUrl, timestamp, mimeType, statusCode] = row;
      if (!originalUrl || !timestamp) continue;

      if (!earliestTs || timestamp < earliestTs) earliestTs = timestamp;
      if (!latestTs || timestamp > latestTs) latestTs = timestamp;

      const year = timestamp.slice(0, 4);
      const month = timestamp.slice(4, 6);
      const day = timestamp.slice(6, 8);
      const formattedDate = `${year}-${month}-${day}`;

      const archiveUrl = `https://web.archive.org/web/${timestamp}/${originalUrl}`;

      snapshots.push({
        originalUrl,
        timestamp,
        formattedDate,
        mimeType: mimeType || 'unknown',
        statusCode: statusCode || '200',
        archiveUrl,
      });

      // Check for interesting paths
      try {
        const parsed = new URL(originalUrl);
        const path = parsed.pathname.toLowerCase();
        for (const kw of interestingKeywords) {
          if (path.includes(kw)) {
            interestingPathsSet.add(parsed.pathname);
            break;
          }
        }
      } catch {
        // Ignore invalid URL
      }
    }

    const formatTs = (ts: string) => {
      if (ts.length >= 8) {
        return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`;
      }
      return null;
    };

    return {
      domain: cleanDomain,
      firstSeen: formatTs(earliestTs),
      lastSeen: formatTs(latestTs),
      totalSnapshotsFound: snapshots.length,
      snapshots: snapshots.slice(0, 15),
      interestingPaths: Array.from(interestingPathsSet).slice(0, 10),
      collectedAt,
      source: 'Wayback Machine (Internet Archive CDX)',
    };
  } catch (err) {
    return {
      domain: cleanDomain,
      firstSeen: null,
      lastSeen: null,
      totalSnapshotsFound: 0,
      snapshots: [],
      interestingPaths: [],
      collectedAt,
      source: 'Wayback Machine (Internet Archive CDX)',
      error: err instanceof Error ? err.message : 'Web archive lookup timed out or failed',
    };
  }
}
