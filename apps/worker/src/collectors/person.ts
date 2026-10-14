// OpenSpective — Person & Username Search Collector
// Passive intelligence sources for individuals & usernames:
// - GitHub User Search (by name and profile search)
// - Wikipedia Article Search
// - Wikidata Entity Search
// - HackerNews (Algolia) Mentions & Stories
// - Multi-platform Username Presence Check (GitHub, GitLab, HN, NPM, PyPI, Keybase, DEV, Hashnode)

export interface PersonSearchResult {
  source: string;
  platform: string;
  profileUrl: string | null;
  displayName: string | null;
  bio: string | null;
  location: string | null;
  avatarUrl: string | null;
  metadata: Record<string, unknown>;
  confidence: 'high' | 'medium' | 'low';
  collectedAt: string;
}

export interface PersonSearchResults {
  github: PersonSearchResult[];
  wikipedia: PersonSearchResult[];
  wikidata: PersonSearchResult[];
  hackernews: PersonSearchResult[];
  collectedAt: string;
  errors: string[];
}

// ---- GitHub User Search ----
async function searchGitHubByName(
  name: string,
  token?: string
): Promise<PersonSearchResult[]> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'OpenSpective/0.1',
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  try {
    // First try with in:name, fallback to general search if empty
    let url = `https://api.github.com/search/users?q=${encodeURIComponent(name + ' in:name')}&per_page=5`;
    let resp = await fetch(url, { headers, signal: AbortSignal.timeout(8000) });
    let data = resp.ok ? (await resp.json() as { items?: unknown[] }) : { items: [] };

    if (!data.items || data.items.length === 0) {
      url = `https://api.github.com/search/users?q=${encodeURIComponent(name)}&per_page=5`;
      resp = await fetch(url, { headers, signal: AbortSignal.timeout(8000) });
      if (resp.ok) {
        data = await resp.json() as { items?: unknown[] };
      }
    }

    const items = data.items ?? [];
    const results: PersonSearchResult[] = [];

    for (const item of items.slice(0, 5)) {
      const u = item as Record<string, unknown>;
      try {
        const profileResp = await fetch(String(u['url'] ?? ''), { headers, signal: AbortSignal.timeout(4000) });
        if (profileResp.ok) {
          const profile = await profileResp.json() as Record<string, unknown>;
          results.push({
            source: 'GitHub Public API',
            platform: 'GitHub',
            profileUrl: String(profile['html_url'] ?? ''),
            displayName: (profile['name'] as string) ?? String(u['login'] ?? ''),
            bio: (profile['bio'] as string) ?? null,
            location: (profile['location'] as string) ?? null,
            avatarUrl: (profile['avatar_url'] as string) ?? null,
            metadata: {
              login: profile['login'],
              public_repos: profile['public_repos'],
              followers: profile['followers'],
              company: profile['company'],
              blog: profile['blog'],
              twitter_username: profile['twitter_username'],
            },
            confidence: profile['name'] ? 'medium' : 'low',
            collectedAt: new Date().toISOString(),
          });
          continue;
        }
      } catch {
        // Fall back to un-enriched item
      }

      results.push({
        source: 'GitHub Public API',
        platform: 'GitHub',
        profileUrl: String(u['html_url'] ?? ''),
        displayName: String(u['login'] ?? ''),
        bio: null,
        location: null,
        avatarUrl: String(u['avatar_url'] ?? ''),
        metadata: { login: u['login'] },
        confidence: 'low',
        collectedAt: new Date().toISOString(),
      });
    }

    return results;
  } catch {
    return [];
  }
}

// ---- Wikipedia Search ----
async function searchWikipedia(name: string): Promise<PersonSearchResult[]> {
  try {
    const searchUrl = `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(name)}&srlimit=3&format=json&origin=*`;
    const resp = await fetch(searchUrl, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) return [];

    const data = await resp.json() as { query?: { search?: Array<{ title: string; snippet: string; pageid: number }> } };
    const results: PersonSearchResult[] = [];

    for (const article of (data.query?.search ?? []).slice(0, 3)) {
      const plainSnippet = article.snippet.replace(/<[^>]+>/g, '').trim();
      results.push({
        source: 'Wikipedia (free API)',
        platform: 'Wikipedia',
        profileUrl: `https://en.wikipedia.org/wiki/${encodeURIComponent(article.title.replace(/ /g, '_'))}`,
        displayName: article.title,
        bio: plainSnippet || null,
        location: null,
        avatarUrl: null,
        metadata: { pageid: article.pageid, title: article.title },
        confidence: 'medium',
        collectedAt: new Date().toISOString(),
      });
    }

    return results;
  } catch {
    return [];
  }
}

// ---- Wikidata Search ----
async function searchWikidata(name: string): Promise<PersonSearchResult[]> {
  try {
    const url = `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(name)}&language=en&format=json&limit=3&origin=*`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) return [];

    const data = await resp.json() as { search?: Array<{ id: string; label: string; description?: string; concepturi: string }> };
    const results: PersonSearchResult[] = [];

    for (const item of (data.search ?? []).slice(0, 3)) {
      results.push({
        source: 'Wikidata Knowledge Graph',
        platform: 'Wikidata',
        profileUrl: item.concepturi || `https://www.wikidata.org/wiki/${item.id}`,
        displayName: item.label,
        bio: item.description ?? null,
        location: null,
        avatarUrl: null,
        metadata: { wikidataId: item.id },
        confidence: 'medium',
        collectedAt: new Date().toISOString(),
      });
    }

    return results;
  } catch {
    return [];
  }
}

// ---- HackerNews Search (Algolia API — free, no auth) ----
async function searchHackerNews(name: string): Promise<PersonSearchResult[]> {
  try {
    const url = `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(name)}&hitsPerPage=5`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) return [];

    const data = await resp.json() as { hits?: Array<{ author?: string; objectID: string; title?: string; url?: string; story_text?: string; comment_text?: string }> };
    const results: PersonSearchResult[] = [];

    for (const hit of (data.hits ?? []).slice(0, 5)) {
      const title = hit.title || (hit.comment_text ? hit.comment_text.replace(/<[^>]+>/g, '').slice(0, 100) : null);
      if (!title && !hit.author) continue;

      results.push({
        source: 'HackerNews (Algolia API)',
        platform: 'HackerNews',
        profileUrl: hit.url || `https://news.ycombinator.com/item?id=${hit.objectID}`,
        displayName: title ?? (hit.author ? `Mention by ${hit.author}` : 'HackerNews Discussion'),
        bio: hit.author ? `Author/Contributor: ${hit.author}` : null,
        location: null,
        avatarUrl: null,
        metadata: { objectID: hit.objectID, author: hit.author, directUrl: hit.url },
        confidence: 'low',
        collectedAt: new Date().toISOString(),
      });
    }

    return results;
  } catch {
    return [];
  }
}

// ---- Main person search ----
export async function collectPersonSearch(
  name: string,
  githubToken?: string
): Promise<PersonSearchResults> {
  const collectedAt = new Date().toISOString();
  const errors: string[] = [];

  const [githubResults, wikiResults, wikidataResults, hnResults] = await Promise.allSettled([
    searchGitHubByName(name, githubToken),
    searchWikipedia(name),
    searchWikidata(name),
    searchHackerNews(name),
  ]);

  return {
    github: githubResults.status === 'fulfilled' ? githubResults.value : (errors.push('GitHub search failed'), []),
    wikipedia: wikiResults.status === 'fulfilled' ? wikiResults.value : (errors.push('Wikipedia search failed'), []),
    wikidata: wikidataResults.status === 'fulfilled' ? wikidataResults.value : (errors.push('Wikidata search failed'), []),
    hackernews: hnResults.status === 'fulfilled' ? hnResults.value : (errors.push('HackerNews search failed'), []),
    collectedAt,
    errors,
  };
}

// ---- Username search across platforms ----
export interface UsernameCheckResult {
  platform: string;
  url: string;
  status: 'found' | 'not_found' | 'unknown';
  collectedAt: string;
}

const USERNAME_PLATFORMS: Array<{ name: string; url: string; userKey: string }> = [
  { name: 'GitHub', url: 'https://github.com/{user}', userKey: 'github' },
  { name: 'GitLab', url: 'https://gitlab.com/{user}', userKey: 'gitlab' },
  { name: 'HackerNews', url: 'https://news.ycombinator.com/user?id={user}', userKey: 'hn' },
  { name: 'NPM', url: 'https://www.npmjs.com/~{user}', userKey: 'npm' },
  { name: 'PyPI', url: 'https://pypi.org/user/{user}/', userKey: 'pypi' },
  { name: 'Keybase', url: 'https://keybase.io/{user}', userKey: 'keybase' },
  { name: 'DEV.to', url: 'https://dev.to/{user}', userKey: 'devto' },
  { name: 'Hashnode', url: 'https://hashnode.com/@{user}', userKey: 'hashnode' },
];

export async function checkUsernamePresence(username: string): Promise<UsernameCheckResult[]> {
  const collectedAt = new Date().toISOString();
  const results: UsernameCheckResult[] = [];

  const checks = USERNAME_PLATFORMS.map(async (platform) => {
    const url = platform.url.replace('{user}', encodeURIComponent(username));
    try {
      const resp = await fetch(url, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
        redirect: 'follow',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          Accept: 'text/html,application/xhtml+xml',
        },
      });
      const status: UsernameCheckResult['status'] =
        resp.status === 200 ? 'found' :
        resp.status === 404 ? 'not_found' : 'unknown';
      return { platform: platform.name, url, status, collectedAt };
    } catch {
      return { platform: platform.name, url, status: 'unknown' as const, collectedAt };
    }
  });

  for (let i = 0; i < checks.length; i += 4) {
    const batch = checks.slice(i, i + 4);
    const batchResults = await Promise.allSettled(batch);
    for (const r of batchResults) {
      if (r.status === 'fulfilled') results.push(r.value);
    }
  }

  return results;
}
