// OpenSpective — Email & Identity Intelligence Collector
// Provides deep passive reconnaissance for email addresses:
// 1. Author and Commit Attribution via GitHub Commit Search
// 2. GitHub User and Developer Profile Search
// 3. Gravatar Profile, Verified Accounts, and Avatar Discovery
// 4. Handle Footprint (local-part username) across developer and social ecosystems
// 5. HackerNews Discussions & Mentions
// 6. Consumer vs Custom Domain Classification

export interface EmailIdentityFinding {
  category: string;
  subcategory?: string;
  type: string;
  value: string;
  notes?: string | null;
  sourceUrl?: string | null;
  sourceName: string;
  confidence: 'high' | 'medium' | 'low';
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  rawData: Record<string, unknown>;
  relationships?: Array<{
    toEntityType: 'person' | 'username' | 'repository' | 'organization' | 'url' | 'domain';
    toValue: string;
    relationshipType: 'affiliated_with' | 'owned_by' | 'mentions' | 'resolves_to';
  }>;
}

export interface EmailIdentityResults {
  email: string;
  localPart: string;
  domain: string;
  isConsumerProvider: boolean;
  providerName: string | null;
  findings: EmailIdentityFinding[];
  collectedAt: string;
  errors: string[];
}

// Major consumer webmail domains
const CONSUMER_PROVIDERS: Record<string, string> = {
  'gmail.com': 'Google Gmail',
  'googlemail.com': 'Google Gmail',
  'yahoo.com': 'Yahoo! Mail',
  'ymail.com': 'Yahoo! Mail',
  'hotmail.com': 'Microsoft Hotmail / Outlook',
  'outlook.com': 'Microsoft Outlook',
  'live.com': 'Microsoft Live',
  'msn.com': 'Microsoft MSN',
  'icloud.com': 'Apple iCloud Mail',
  'me.com': 'Apple iCloud Mail',
  'mac.com': 'Apple iCloud Mail',
  'proton.me': 'Proton Mail (Encrypted)',
  'protonmail.com': 'Proton Mail (Encrypted)',
  'zoho.com': 'Zoho Mail',
  'aol.com': 'AOL Mail',
  'mail.com': 'Mail.com',
  'gmx.com': 'GMX Mail',
  'fastmail.com': 'Fastmail',
  'tutanota.com': 'Tuta Mail (Encrypted)',
  'tuta.com': 'Tuta Mail (Encrypted)',
};

// Pure TypeScript MD5 for Gravatar hash (RFC 1321)
function md5(str: string): string {
  function safeAdd(x: number, y: number): number {
    const lsw = (x & 0xffff) + (y & 0xffff);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xffff);
  }
  function bitRol(num: number, cnt: number): number {
    return (num << cnt) | (num >>> (32 - cnt));
  }
  function md5cmn(q: number, a: number, b: number, x: number, s: number, t: number): number {
    return safeAdd(bitRol(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
  }
  function md5ff(a: number, b: number, c: number, d: number, x: number, s: number, t: number): number {
    return md5cmn((b & c) | (~b & d), a, b, x, s, t);
  }
  function md5gg(a: number, b: number, c: number, d: number, x: number, s: number, t: number): number {
    return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
  }
  function md5hh(a: number, b: number, c: number, d: number, x: number, s: number, t: number): number {
    return md5cmn(b ^ c ^ d, a, b, x, s, t);
  }
  function md5ii(a: number, b: number, c: number, d: number, x: number, s: number, t: number): number {
    return md5cmn(c ^ (b | ~d), a, b, x, s, t);
  }

  const binStr: number[] = [];
  const mask = (1 << 8) - 1;
  for (let i = 0; i < str.length * 8; i += 8) {
    const idx = i >> 5;
    binStr[idx] = (binStr[idx] ?? 0) | ((str.charCodeAt(i / 8) & mask) << (i % 32));
  }
  const idx1 = str.length >> 2;
  binStr[idx1] = (binStr[idx1] ?? 0) | (0x80 << ((str.length % 4) * 8));
  const idx2 = (((str.length + 8) >> 6) << 4) + 14;
  binStr[idx2] = str.length * 8;

  let a = 1732584193;
  let b = -271733879;
  let c = -1732584194;
  let d = 271733878;

  for (let i = 0; i < binStr.length; i += 16) {
    const olda = a;
    const oldb = b;
    const oldc = c;
    const oldd = d;

    a = md5ff(a, b, c, d, binStr[i + 0] || 0, 7, -680876936);
    d = md5ff(d, a, b, c, binStr[i + 1] || 0, 12, -389564586);
    c = md5ff(c, d, a, b, binStr[i + 2] || 0, 17, 606105819);
    b = md5ff(b, c, d, a, binStr[i + 3] || 0, 22, -1044525330);
    a = md5ff(a, b, c, d, binStr[i + 4] || 0, 7, -176418897);
    d = md5ff(d, a, b, c, binStr[i + 5] || 0, 12, 1200080426);
    c = md5ff(c, d, a, b, binStr[i + 6] || 0, 17, -1473231341);
    b = md5ff(b, c, d, a, binStr[i + 7] || 0, 22, -45705983);
    a = md5ff(a, b, c, d, binStr[i + 8] || 0, 7, 1770035416);
    d = md5ff(d, a, b, c, binStr[i + 9] || 0, 12, -1958414417);
    c = md5ff(c, d, a, b, binStr[i + 10] || 0, 17, -42063);
    b = md5ff(b, c, d, a, binStr[i + 11] || 0, 22, -1990404162);
    a = md5ff(a, b, c, d, binStr[i + 12] || 0, 7, 1804603682);
    d = md5ff(d, a, b, c, binStr[i + 13] || 0, 12, -40341101);
    c = md5ff(c, d, a, b, binStr[i + 14] || 0, 17, -1502002290);
    b = md5ff(b, c, d, a, binStr[i + 15] || 0, 22, 1236535329);

    a = md5gg(a, b, c, d, binStr[i + 1] || 0, 5, -165796510);
    d = md5gg(d, a, b, c, binStr[i + 6] || 0, 9, -1069501632);
    c = md5gg(c, d, a, b, binStr[i + 11] || 0, 14, 643717713);
    b = md5gg(b, c, d, a, binStr[i + 0] || 0, 20, -373897302);
    a = md5gg(a, b, c, d, binStr[i + 5] || 0, 5, -701558691);
    d = md5gg(d, a, b, c, binStr[i + 10] || 0, 9, 38016083);
    c = md5gg(c, d, a, b, binStr[i + 15] || 0, 14, -660478335);
    b = md5gg(b, c, d, a, binStr[i + 4] || 0, 20, -405537848);
    a = md5gg(a, b, c, d, binStr[i + 9] || 0, 5, 568446438);
    d = md5gg(d, a, b, c, binStr[i + 14] || 0, 9, -1019803690);
    c = md5gg(c, d, a, b, binStr[i + 3] || 0, 14, -187363961);
    b = md5gg(b, c, d, a, binStr[i + 8] || 0, 20, 1163531501);
    a = md5gg(a, b, c, d, binStr[i + 13] || 0, 5, -1444681467);
    d = md5gg(d, a, b, c, binStr[i + 2] || 0, 9, -51403784);
    c = md5gg(c, d, a, b, binStr[i + 7] || 0, 14, 1735328473);
    b = md5gg(b, c, d, a, binStr[i + 12] || 0, 20, -1926607734);

    a = md5hh(a, b, c, d, binStr[i + 5] || 0, 4, -378558);
    d = md5hh(d, a, b, c, binStr[i + 8] || 0, 11, -2022574463);
    c = md5hh(c, d, a, b, binStr[i + 11] || 0, 16, 1839030562);
    b = md5hh(b, c, d, a, binStr[i + 14] || 0, 23, -35309556);
    a = md5hh(a, b, c, d, binStr[i + 1] || 0, 4, -1530992060);
    d = md5hh(d, a, b, c, binStr[i + 4] || 0, 11, 1272893353);
    c = md5hh(c, d, a, b, binStr[i + 7] || 0, 16, -155497632);
    b = md5hh(b, c, d, a, binStr[i + 10] || 0, 23, -1094730640);
    a = md5hh(a, b, c, d, binStr[i + 13] || 0, 4, 681279174);
    d = md5hh(d, a, b, c, binStr[i + 0] || 0, 11, -358537222);
    c = md5hh(c, d, a, b, binStr[i + 3] || 0, 16, -722521979);
    b = md5hh(b, c, d, a, binStr[i + 6] || 0, 23, 76029189);
    a = md5hh(a, b, c, d, binStr[i + 9] || 0, 4, -640364487);
    d = md5hh(d, a, b, c, binStr[i + 12] || 0, 11, -421815835);
    c = md5hh(c, d, a, b, binStr[i + 15] || 0, 16, 530742520);
    b = md5hh(b, c, d, a, binStr[i + 2] || 0, 23, -995338651);

    a = md5ii(a, b, c, d, binStr[i + 0] || 0, 6, -198630844);
    d = md5ii(d, a, b, c, binStr[i + 7] || 0, 10, 1126891415);
    c = md5ii(c, d, a, b, binStr[i + 14] || 0, 15, -1416354905);
    b = md5ii(b, c, d, a, binStr[i + 5] || 0, 21, -57434055);
    a = md5ii(a, b, c, d, binStr[i + 12] || 0, 6, 1700485571);
    d = md5ii(d, a, b, c, binStr[i + 3] || 0, 10, -1894986606);
    c = md5ii(c, d, a, b, binStr[i + 10] || 0, 15, -1051523);
    b = md5ii(b, c, d, a, binStr[i + 1] || 0, 21, -2054922799);
    a = md5ii(a, b, c, d, binStr[i + 8] || 0, 6, 1873313359);
    d = md5ii(d, a, b, c, binStr[i + 15] || 0, 10, -30611744);
    c = md5ii(c, d, a, b, binStr[i + 6] || 0, 15, -1560198380);
    b = md5ii(b, c, d, a, binStr[i + 13] || 0, 21, 1309151649);
    a = md5ii(a, b, c, d, binStr[i + 4] || 0, 6, -145523070);
    d = md5ii(d, a, b, c, binStr[i + 11] || 0, 10, -1120210379);
    c = md5ii(c, d, a, b, binStr[i + 2] || 0, 15, 718787259);
    b = md5ii(b, c, d, a, binStr[i + 9] || 0, 21, -343485551);

    a = safeAdd(a, olda);
    b = safeAdd(b, oldb);
    c = safeAdd(c, oldc);
    d = safeAdd(d, oldd);
  }

  const hexTab = '0123456789abcdef';
  let out = '';
  for (let i = 0; i < binStr.length * 4; i++) {
    out += hexTab.charAt(((binStr[i >> 2] ?? 0) >> ((i % 4) * 8 + 4)) & 0x0f) +
           hexTab.charAt(((binStr[i >> 2] ?? 0) >> ((i % 4) * 8)) & 0x0f);
  }
  return out.slice(0, 32);
}

// ---- 1. GitHub Commit Search by Author Email ----
async function searchGitHubCommitsByEmail(
  email: string,
  token?: string
): Promise<EmailIdentityFinding[]> {
  const findings: EmailIdentityFinding[] = [];
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.cloak-preview+json, application/vnd.github+json',
    'User-Agent': 'OpenSpective/0.1',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  try {
    const url = `https://api.github.com/search/commits?q=author-email:${encodeURIComponent(email)}&sort=author-date&order=desc&per_page=10`;
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(8000) });
    if (!resp.ok) return [];

    const data = await resp.json() as { total_count?: number; items?: unknown[] };
    const items = data.items ?? [];
    if (items.length === 0) return [];

    // Track authors and repos seen
    const authors = new Map<string, string>(); // name -> username
    const repos = new Set<string>();

    for (const item of items.slice(0, 8)) {
      const commit = item as Record<string, unknown>;
      const commitObj = (commit['commit'] as Record<string, unknown>) ?? {};
      const authorObj = (commitObj['author'] as Record<string, unknown>) ?? {};
      const repoObj = (commit['repository'] as Record<string, unknown>) ?? {};
      const ghAuthor = (commit['author'] as Record<string, unknown>) ?? {};

      const authorName = (authorObj['name'] as string) || '';
      const authorLogin = (ghAuthor['login'] as string) || '';
      const repoFullName = (repoObj['full_name'] as string) || '';
      const repoUrl = (repoObj['html_url'] as string) || '';
      const commitMsg = (commitObj['message'] as string) || '';
      const commitDate = (authorObj['date'] as string) || '';
      const commitUrl = (commit['html_url'] as string) || '';

      if (authorName && authorLogin) {
        authors.set(authorName, authorLogin);
      } else if (authorName && !authors.has(authorName)) {
        authors.set(authorName, '');
      }

      if (repoFullName) repos.add(repoFullName);

      const firstLine = commitMsg.split('\n')[0] ?? '';
      findings.push({
        category: 'developer_activity',
        subcategory: 'git_commit',
        type: 'git_commit_activity',
        value: `${repoFullName}: "${firstLine.slice(0, 120)}"`,
        notes: `Date: ${commitDate ? new Date(commitDate).toLocaleDateString() : 'Unknown'}. Author: ${authorName}${authorLogin ? ` (@${authorLogin})` : ''}.`,
        sourceUrl: commitUrl || repoUrl,
        sourceName: 'GitHub Commit History',
        confidence: 'high',
        severity: 'info',
        rawData: {
          authorName,
          authorLogin,
          authorEmail: email,
          repoFullName,
          repoUrl,
          commitDate,
          commitMessage: commitMsg,
        },
        relationships: [
          ...(authorName ? [{ toEntityType: 'person' as const, toValue: authorName, relationshipType: 'affiliated_with' as const }] : []),
          ...(authorLogin ? [{ toEntityType: 'username' as const, toValue: authorLogin, relationshipType: 'affiliated_with' as const }] : []),
          ...(repoFullName ? [{ toEntityType: 'repository' as const, toValue: repoFullName, relationshipType: 'owned_by' as const }] : []),
        ],
      });
    }

    // Add aggregate author attribution findings
    for (const [name, login] of authors.entries()) {
      findings.push({
        category: 'identity_attribution',
        subcategory: 'author_profile',
        type: 'git_verified_author',
        value: login ? `${name} (@${login})` : name,
        notes: `Verified git commit author for ${email} across ${repos.size} public repository(s).`,
        sourceUrl: login ? `https://github.com/${login}` : null,
        sourceName: 'GitHub Commit Authorship',
        confidence: 'high',
        severity: 'info',
        rawData: { authorName: name, authorLogin: login, email, repoCount: repos.size },
        relationships: [
          { toEntityType: 'person', toValue: name, relationshipType: 'affiliated_with' },
          ...(login ? [{ toEntityType: 'username' as const, toValue: login, relationshipType: 'affiliated_with' as const }] : []),
        ],
      });

      // If author login is present, fetch their GitHub profile
      if (login) {
        try {
          const profileResp = await fetch(`https://api.github.com/users/${encodeURIComponent(login)}`, {
            headers,
            signal: AbortSignal.timeout(5000),
          });
          if (profileResp.ok) {
            const profile = await profileResp.json() as Record<string, unknown>;
            findings.push({
              category: 'public_profile',
              subcategory: 'github',
              type: 'github_profile_correlated',
              value: `${String(profile['name'] ?? name)} (@${login})`,
              notes: [
                profile['bio'] ? `Bio: ${profile['bio']}` : null,
                profile['location'] ? `Location: ${profile['location']}` : null,
                profile['company'] ? `Company: ${profile['company']}` : null,
                profile['blog'] ? `Website: ${profile['blog']}` : null,
                profile['public_repos'] !== undefined ? `Public Repos: ${profile['public_repos']}` : null,
              ].filter(Boolean).join(' | '),
              sourceUrl: String(profile['html_url'] ?? `https://github.com/${login}`),
              sourceName: 'GitHub Public Profile',
              confidence: 'high',
              severity: 'info',
              rawData: profile,
              relationships: [
                { toEntityType: 'username', toValue: login, relationshipType: 'affiliated_with' },
                ...(profile['name'] ? [{ toEntityType: 'person' as const, toValue: String(profile['name']), relationshipType: 'affiliated_with' as const }] : []),
              ],
            });
          }
        } catch {
          // Profile fetch failed — continue
        }
      }
    }

    return findings;
  } catch {
    return [];
  }
}

// ---- 2. Gravatar Profile Reconnaissance ----
async function searchGravatar(email: string): Promise<EmailIdentityFinding[]> {
  const findings: EmailIdentityFinding[] = [];
  const hash = md5(email.trim().toLowerCase());

  try {
    const jsonUrl = `https://en.gravatar.com/${hash}.json`;
    const resp = await fetch(jsonUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
      signal: AbortSignal.timeout(5000),
    });

    if (resp.ok) {
      const data = await resp.json() as { entry?: Array<Record<string, unknown>> };
      const entry = data.entry?.[0];
      if (entry) {
        const displayName = (entry['displayName'] as string) || (entry['preferredUsername'] as string) || '';
        const aboutMe = (entry['aboutMe'] as string) || '';
        const location = (entry['currentLocation'] as string) || '';
        const profileUrl = (entry['profileUrl'] as string) || `https://gravatar.com/${entry['hash']}`;
        const accounts = (entry['accounts'] as Array<{ domain: string; display: string; url: string }>) || [];

        findings.push({
          category: 'public_profile',
          subcategory: 'gravatar',
          type: 'gravatar_profile',
          value: displayName || email,
          notes: [
            aboutMe ? `Bio: ${aboutMe}` : null,
            location ? `Location: ${location}` : null,
            accounts.length > 0 ? `Linked: ${accounts.map(a => `${a.domain}: ${a.display}`).join(', ')}` : null,
          ].filter(Boolean).join(' | ') || 'Active Gravatar public profile found.',
          sourceUrl: profileUrl,
          sourceName: 'Gravatar Public Registry',
          confidence: 'high',
          severity: 'info',
          rawData: entry,
          relationships: displayName ? [
            { toEntityType: 'person', toValue: displayName, relationshipType: 'affiliated_with' },
          ] : [],
        });

        // Add linked accounts as individual findings
        for (const acc of accounts) {
          findings.push({
            category: 'social_profile',
            subcategory: acc.domain,
            type: 'verified_account',
            value: `${acc.domain}: ${acc.display}`,
            notes: `Verified account linked via Gravatar`,
            sourceUrl: acc.url,
            sourceName: 'Gravatar Verified Accounts',
            confidence: 'high',
            severity: 'info',
            rawData: acc,
            relationships: [
              { toEntityType: 'url', toValue: acc.url, relationshipType: 'affiliated_with' },
            ],
          });
        }
      }
    } else {
      // Check if avatar image exists
      const avatarResp = await fetch(`https://www.gravatar.com/avatar/${hash}?d=404`, {
        method: 'HEAD',
        signal: AbortSignal.timeout(4000),
      });
      if (avatarResp.status === 200) {
        findings.push({
          category: 'public_profile',
          subcategory: 'gravatar',
          type: 'gravatar_avatar_active',
          value: `Active Gravatar Avatar (${email})`,
          notes: 'An active user profile photo is configured on Gravatar for this email address.',
          sourceUrl: `https://www.gravatar.com/avatar/${hash}`,
          sourceName: 'Gravatar Avatar Service',
          confidence: 'high',
          severity: 'info',
          rawData: { hash, email },
        });
      }
    }
  } catch {
    // Gravatar check failed
  }

  return findings;
}

// ---- 3. Multi-platform Handle Footprint for Email Username ----
const PLATFORM_CHECKS: Array<{ name: string; urlTemplate: string; userKey: string }> = [
  { name: 'GitHub', urlTemplate: 'https://github.com/{user}', userKey: 'github' },
  { name: 'GitLab', urlTemplate: 'https://gitlab.com/{user}', userKey: 'gitlab' },
  { name: 'HackerNews', urlTemplate: 'https://news.ycombinator.com/user?id={user}', userKey: 'hn' },
  { name: 'PyPI', urlTemplate: 'https://pypi.org/user/{user}/', userKey: 'pypi' },
  { name: 'NPM', urlTemplate: 'https://www.npmjs.com/~{user}', userKey: 'npm' },
  { name: 'Keybase', urlTemplate: 'https://keybase.io/{user}', userKey: 'keybase' },
  { name: 'DEV.to', urlTemplate: 'https://dev.to/{user}', userKey: 'devto' },
  { name: 'Hashnode', urlTemplate: 'https://hashnode.com/@{user}', userKey: 'hashnode' },
  { name: 'Pinterest', urlTemplate: 'https://www.pinterest.com/{user}/', userKey: 'pinterest' },
  { name: 'Medium', urlTemplate: 'https://medium.com/@{user}', userKey: 'medium' },
  { name: 'Linktree', urlTemplate: 'https://linktr.ee/{user}', userKey: 'linktree' },
  { name: 'Reddit', urlTemplate: 'https://www.reddit.com/user/{user}/about.json', userKey: 'reddit' },
];

async function checkHandleFootprint(handle: string): Promise<EmailIdentityFinding[]> {
  const findings: EmailIdentityFinding[] = [];

  const checks = PLATFORM_CHECKS.map(async (platform) => {
    const url = platform.urlTemplate.replace('{user}', encodeURIComponent(handle));
    try {
      const resp = await fetch(url, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          Accept: 'text/html,application/xhtml+xml,application/json',
        },
      });

      if (resp.status === 200) {
        findings.push({
          category: 'social_profile',
          subcategory: platform.name.toLowerCase(),
          type: 'account_presence',
          value: `${platform.name}: ${handle}`,
          notes: `Public profile active at ${url}`,
          sourceUrl: url,
          sourceName: `${platform.name} Public Web`,
          confidence: 'medium',
          severity: 'info',
          rawData: { platform: platform.name, url, handle, status: 200 },
          relationships: [
            { toEntityType: 'username', toValue: handle, relationshipType: 'affiliated_with' },
            { toEntityType: 'url', toValue: url, relationshipType: 'affiliated_with' },
          ],
        });
      }
    } catch {
      // platform timeout / blocked
    }
  });

  // Batch in chunks of 4
  for (let i = 0; i < checks.length; i += 4) {
    await Promise.allSettled(checks.slice(i, i + 4));
  }

  return findings;
}

// ---- 4. HackerNews Algolia Mentions ----
async function searchHackerNewsByQuery(query: string): Promise<EmailIdentityFinding[]> {
  const findings: EmailIdentityFinding[] = [];
  try {
    const url = `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(query)}&hitsPerPage=3`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(6000) });
    if (!resp.ok) return [];

    const data = await resp.json() as { hits?: Array<{ author?: string; objectID: string; title?: string; url?: string; story_text?: string; comment_text?: string }> };
    for (const hit of (data.hits ?? []).slice(0, 3)) {
      const title = hit.title || (hit.comment_text ? hit.comment_text.replace(/<[^>]+>/g, '').slice(0, 100) : null);
      if (!title && !hit.author) continue;

      findings.push({
        category: 'public_mention',
        subcategory: 'hackernews',
        type: 'forum_mention',
        value: title || `Mention by ${hit.author}`,
        notes: `Hacker News discussion: author ${hit.author || 'unknown'}`,
        sourceUrl: hit.url || `https://news.ycombinator.com/item?id=${hit.objectID}`,
        sourceName: 'HackerNews Algolia API',
        confidence: 'low',
        severity: 'info',
        rawData: hit,
      });
    }
  } catch {
    // HN search error
  }
  return findings;
}

// ============================================================
// Main Email Identity Collector Entry Point
// ============================================================

export async function collectEmailIdentity(
  email: string,
  githubToken?: string
): Promise<EmailIdentityResults> {
  const collectedAt = new Date().toISOString();
  const errors: string[] = [];
  const findings: EmailIdentityFinding[] = [];

  const parts = email.toLowerCase().trim().split('@');
  const localPart = parts[0] || '';
  const domain = parts[1] || '';

  const providerName = CONSUMER_PROVIDERS[domain] ?? null;
  const isConsumerProvider = !!providerName;

  // 1. Mail Provider Structure Finding
  findings.push({
    category: 'email_infrastructure',
    subcategory: 'provider',
    type: 'mail_provider_analysis',
    value: isConsumerProvider ? `${providerName} (${domain})` : `Custom Domain (${domain})`,
    notes: isConsumerProvider
      ? `Target uses standard consumer webmail (${providerName}). Identity correlation focuses on the handle "${localPart}" and public developer registries.`
      : `Target uses custom domain mail (${domain}). Domain infrastructure and DNS indicate direct organization affiliation.`,
    sourceUrl: null,
    sourceName: 'OpenSpective Provider Classifier',
    confidence: 'high',
    severity: 'info',
    rawData: { email, localPart, domain, isConsumerProvider, providerName },
    relationships: [
      { toEntityType: 'username', toValue: localPart, relationshipType: 'affiliated_with' },
      ...(isConsumerProvider ? [] : [{ toEntityType: 'domain' as const, toValue: domain, relationshipType: 'affiliated_with' as const }]),
    ],
  });

  // 2. Parallel Deep Intelligence Gathering
  const [githubCommits, gravatarResults, handleResults, hnResults] = await Promise.allSettled([
    searchGitHubCommitsByEmail(email, githubToken),
    searchGravatar(email),
    localPart.length >= 3 ? checkHandleFootprint(localPart) : Promise.resolve([]),
    searchHackerNewsByQuery(email),
  ]);

  if (githubCommits.status === 'fulfilled') {
    findings.push(...githubCommits.value);
  } else {
    errors.push('GitHub commit search failed');
  }

  if (gravatarResults.status === 'fulfilled') {
    findings.push(...gravatarResults.value);
  } else {
    errors.push('Gravatar search failed');
  }

  if (handleResults.status === 'fulfilled') {
    findings.push(...handleResults.value);
  } else {
    errors.push('Handle footprint check failed');
  }

  if (hnResults.status === 'fulfilled') {
    findings.push(...hnResults.value);
  } else {
    errors.push('HackerNews search failed');
  }

  // If handle is unique and HN by email was empty, also try HN by handle
  if (hnResults.status === 'fulfilled' && hnResults.value.length === 0 && localPart.length >= 4) {
    try {
      const hnHandleFindings = await searchHackerNewsByQuery(localPart);
      findings.push(...hnHandleFindings);
    } catch {
      // ignore
    }
  }

  return {
    email,
    localPart,
    domain,
    isConsumerProvider,
    providerName,
    findings,
    collectedAt,
    errors,
  };
}
