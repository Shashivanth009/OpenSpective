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

export interface GitCommitRecord {
  sha: string;
  message: string;
  repo: string;
  repoUrl: string;
  commitUrl: string;
  authorName: string;
  authorEmail: string;
  date: string;
}

export interface PersonSearchResults {
  github: PersonSearchResult[];
  gitCommits: GitCommitRecord[];
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

// ---- GitHub Commit Search by Author / Committer Name ----
async function searchGitHubCommitsByAuthorName(
  name: string,
  token?: string
): Promise<GitCommitRecord[]> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.cloak-preview+json, application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'OpenSpective/0.1',
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  try {
    const cleanName = name.replace(/['"]/g, '').trim();
    const query = cleanName.includes(' ')
      ? `author-name:"${cleanName}"`
      : `author-name:${cleanName}`;
    const url = `https://api.github.com/search/commits?q=${encodeURIComponent(query)}&per_page=10`;
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(8000) });
    if (!resp.ok) return [];

    const data = await resp.json() as { items?: unknown[] };
    const items = data.items ?? [];
    const commits: GitCommitRecord[] = [];

    for (const item of items.slice(0, 10)) {
      const it = item as Record<string, unknown>;
      const commitObj = (it['commit'] as Record<string, unknown>) ?? {};
      const authorObj = (commitObj['author'] as Record<string, unknown>) ?? {};
      const repoObj = (it['repository'] as Record<string, unknown>) ?? {};

      commits.push({
        sha: String(it['sha'] ?? '').slice(0, 8),
        message: (String(commitObj['message'] ?? '').split('\n')[0] ?? '').slice(0, 200),
        repo: String(repoObj['full_name'] ?? ''),
        repoUrl: String(repoObj['html_url'] ?? ''),
        commitUrl: String(it['html_url'] ?? ''),
        authorName: String(authorObj['name'] ?? ''),
        authorEmail: String(authorObj['email'] ?? ''),
        date: String(authorObj['date'] ?? ''),
      });
    }

    return commits;
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

  const [githubResults, commitsResult, wikiResults, wikidataResults, hnResults] = await Promise.allSettled([
    searchGitHubByName(name, githubToken),
    searchGitHubCommitsByAuthorName(name, githubToken),
    searchWikipedia(name),
    searchWikidata(name),
    searchHackerNews(name),
  ]);

  return {
    github: githubResults.status === 'fulfilled' ? githubResults.value : (errors.push('GitHub search failed'), []),
    gitCommits: commitsResult.status === 'fulfilled' ? commitsResult.value : (errors.push('Git commits search failed'), []),
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
  category: 'developer' | 'social' | 'community' | 'creative' | 'gaming' | 'audio' | 'finance';
  url: string;
  status: 'found' | 'not_found' | 'unknown';
  verified: boolean;
  verificationProof?: string | null;
  location?: string | null;
  bio?: string | null;
  displayName?: string | null;
  avatarUrl?: string | null;
  collectedAt: string;
}

interface PlatformDefinition {
  name: string;
  category: UsernameCheckResult['category'];
  url: string;
  checkUrl?: string;
  userKey: string;
  customCheck: (resp: Response, bodyText: string, username: string) => Promise<{ found: boolean; proof?: string | null; location?: string | null; bio?: string | null; name?: string | null; avatar?: string | null } | boolean>;
}

export const USERNAME_PLATFORMS: PlatformDefinition[] = [
  // Developer & Coding
  {
    name: 'GitHub',
    category: 'developer',
    url: 'https://github.com/{user}',
    checkUrl: 'https://api.github.com/users/{user}',
    userKey: 'github',
    customCheck: async (resp, text, u) => {
      if (resp.status === 200) {
        try {
          const d = JSON.parse(text);
          if (d.login && d.login.toLowerCase() === u.toLowerCase()) {
            return {
              found: true,
              proof: `Verified GitHub User ID ${d.id} (${d.public_repos ?? 0} public repos)`,
              name: d.name || d.login,
              bio: d.bio || null,
              location: d.location || null,
              avatar: d.avatar_url || null,
            };
          }
        } catch {
          // fall through
        }
      }
      return false;
    },
  },
  {
    name: 'GitLab',
    category: 'developer',
    url: 'https://gitlab.com/{user}',
    checkUrl: 'https://gitlab.com/api/v4/users?username={user}',
    userKey: 'gitlab',
    customCheck: async (resp, text, u) => {
      if (resp.status === 200) {
        try {
          const arr = JSON.parse(text);
          if (Array.isArray(arr) && arr.length > 0) {
            const match = arr.find((item: any) => item.username?.toLowerCase() === u.toLowerCase());
            if (match) {
              return {
                found: true,
                proof: `Verified GitLab Account ID ${match.id}`,
                name: match.name || match.username,
                avatar: match.avatar_url || null,
                bio: match.bio || null,
                location: match.location || null,
              };
            }
          }
        } catch {
          // fall through
        }
      }
      return false;
    },
  },
  {
    name: 'Bitbucket',
    category: 'developer',
    url: 'https://bitbucket.org/{user}/',
    checkUrl: 'https://api.bitbucket.org/2.0/users/{user}',
    userKey: 'bitbucket',
    customCheck: async (resp, text) => {
      if (resp.status === 200) {
        try {
          const d = JSON.parse(text);
          if (d.uuid && (d.nickname || d.display_name)) {
            return {
              found: true,
              proof: `Verified Bitbucket Account UUID ${d.uuid}`,
              name: d.display_name || d.nickname,
              avatar: d.links?.avatar?.href || null,
            };
          }
        } catch {
          // fall through
        }
      }
      return false;
    },
  },
  {
    name: 'HackerNews',
    category: 'developer',
    url: 'https://news.ycombinator.com/user?id={user}',
    userKey: 'hn',
    customCheck: async (resp, text) => {
      if (resp.status === 200) {
        // HackerNews returns 200 with "No such user." if absent!
        if (text.includes('No such user.')) return false;
        if (text.includes('karma:') || text.includes('created:')) {
          const karmaMatch = text.match(/karma:\s*<\/td><td>(\d+)/i);
          const karma = karmaMatch ? karmaMatch[1] : 'active';
          return {
            found: true,
            proof: `Verified HackerNews Account (Karma: ${karma})`,
          };
        }
      }
      return false;
    },
  },
  {
    name: 'DockerHub',
    category: 'developer',
    url: 'https://hub.docker.com/u/{user}',
    checkUrl: 'https://hub.docker.com/v2/users/{user}/',
    userKey: 'dockerhub',
    customCheck: async (resp, text, u) => {
      if (resp.status === 200) {
        try {
          const d = JSON.parse(text);
          if (d.id && d.username && d.username.toLowerCase() === u.toLowerCase()) {
            return {
              found: true,
              proof: `Verified DockerHub Namespace ID ${d.id}`,
              name: d.full_name || d.username,
              location: d.location || null,
            };
          }
        } catch {
          // fall through
        }
      }
      return false;
    },
  },
  {
    name: 'NPM',
    category: 'developer',
    url: 'https://www.npmjs.com/~{user}',
    checkUrl: 'https://registry.npmjs.org/-/v1/search?text=maintainer:{user}&size=1',
    userKey: 'npm',
    customCheck: async (resp, text, u) => {
      if (resp.status === 200) {
        try {
          const d = JSON.parse(text);
          if (typeof d.total === 'number' && d.total > 0) {
            return {
              found: true,
              proof: `Verified NPM Package Maintainer (${d.total} published packages)`,
            };
          }
        } catch {
          // fallback to web
        }
      }
      return false;
    },
  },
  {
    name: 'PyPI',
    category: 'developer',
    url: 'https://pypi.org/user/{user}/',
    userKey: 'pypi',
    customCheck: async (resp, text, u) => {
      if (resp.status === 200 && !text.includes('Page Not Found') && !text.includes('404')) {
        if (text.toLowerCase().includes(u.toLowerCase())) {
          return {
            found: true,
            proof: `Verified PyPI Package Author Profile`,
          };
        }
      }
      return false;
    },
  },
  {
    name: 'Keybase',
    category: 'developer',
    url: 'https://keybase.io/{user}',
    checkUrl: 'https://keybase.io/_/api/1.0/user/lookup.json?usernames={user}',
    userKey: 'keybase',
    customCheck: async (resp, text) => {
      if (resp.status === 200) {
        try {
          const d = JSON.parse(text);
          if (d.status?.code === 0 && Array.isArray(d.them) && d.them.length > 0 && d.them[0] !== null) {
            const usr = d.them[0];
            return {
              found: true,
              proof: `Verified Keybase Cryptographic Identity ID ${usr.id}`,
              name: usr.profile?.full_name || usr.basics?.username,
              bio: usr.profile?.bio || null,
              location: usr.profile?.location || null,
            };
          }
        } catch {
          // fall through
        }
      }
      return false;
    },
  },
  {
    name: 'DEV.to',
    category: 'developer',
    url: 'https://dev.to/{user}',
    checkUrl: 'https://dev.to/api/users/by_username?url={user}',
    userKey: 'devto',
    customCheck: async (resp, text, u) => {
      if (resp.status === 200) {
        try {
          const d = JSON.parse(text);
          if (d.username && d.username.toLowerCase() === u.toLowerCase()) {
            return {
              found: true,
              proof: `Verified DEV.to Community Author ID ${d.id}`,
              name: d.name || d.username,
              bio: d.summary || null,
              location: d.location || null,
              avatar: d.profile_image || null,
            };
          }
        } catch {
          // fall through
        }
      }
      return false;
    },
  },
  {
    name: 'Codeforces',
    category: 'developer',
    url: 'https://codeforces.com/profile/{user}',
    checkUrl: 'https://codeforces.com/api/user.info?handles={user}',
    userKey: 'codeforces',
    customCheck: async (resp, text) => {
      if (resp.status === 200) {
        try {
          const d = JSON.parse(text);
          if (d.status === 'OK' && Array.isArray(d.result) && d.result.length > 0) {
            const u = d.result[0];
            return {
              found: true,
              proof: `Verified Codeforces Competitive Programmer (Rank: ${u.rank || 'Active'}, Rating: ${u.rating || 'N/A'})`,
              name: [u.firstName, u.lastName].filter(Boolean).join(' ') || u.handle,
              avatar: u.titlePhoto || null,
              location: [u.city, u.country].filter(Boolean).join(', ') || null,
            };
          }
        } catch {
          // fall through
        }
      }
      return false;
    },
  },
  {
    name: 'HuggingFace',
    category: 'developer',
    url: 'https://huggingface.co/{user}',
    checkUrl: 'https://huggingface.co/api/users/{user}/overview',
    userKey: 'huggingface',
    customCheck: async (resp, text, u) => {
      if (resp.status === 200) {
        try {
          const d = JSON.parse(text);
          if (d.user && d.user.toLowerCase() === u.toLowerCase()) {
            return {
              found: true,
              proof: `Verified Hugging Face Machine Learning Profile`,
              name: d.fullname || d.user,
              avatar: d.avatarUrl || null,
            };
          }
        } catch {
          // fall through
        }
      }
      return false;
    },
  },

  // Social & Community
  {
    name: 'Reddit',
    category: 'community',
    url: 'https://www.reddit.com/user/{user}',
    checkUrl: 'https://www.reddit.com/user/{user}/about.json',
    userKey: 'reddit',
    customCheck: async (resp, text) => {
      if (resp.status === 200) {
        try {
          const d = JSON.parse(text);
          if (d.kind === 't2' && d.data && !d.data.is_suspended) {
            return {
              found: true,
              proof: `Verified Reddit User (Karma: ${d.data.total_karma ?? 0})`,
              name: d.data.name,
              avatar: d.data.icon_img?.split('?')[0] || null,
            };
          }
        } catch {
          // fall through
        }
      }
      return false;
    },
  },
  {
    name: 'Medium',
    category: 'social',
    url: 'https://medium.com/@{user}',
    checkUrl: 'https://medium.com/feed/@{user}',
    userKey: 'medium',
    customCheck: async (resp, text) => {
      if (resp.status === 200 && text.includes('<rss') && text.includes('<title>')) {
        const titleMatch = text.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/i) || text.match(/<title>(.*?)<\/title>/i);
        const title = titleMatch ? titleMatch[1] : null;
        return {
          found: true,
          proof: `Verified Medium Publication RSS Feed (${title || 'Active'})`,
          name: title,
        };
      }
      return false;
    },
  },
  {
    name: 'Substack',
    category: 'social',
    url: 'https://{user}.substack.com',
    checkUrl: 'https://{user}.substack.com/api/v1/archive?sort=new&limit=1',
    userKey: 'substack',
    customCheck: async (resp, text) => {
      if (resp.status === 200) {
        try {
          const arr = JSON.parse(text);
          if (Array.isArray(arr)) {
            return {
              found: true,
              proof: `Verified Substack Newsletter Publication`,
            };
          }
        } catch {
          // fall through
        }
      }
      return false;
    },
  },
  {
    name: 'Mastodon',
    category: 'social',
    url: 'https://mastodon.social/@{user}',
    checkUrl: 'https://mastodon.social/api/v1/accounts/lookup?acct={user}',
    userKey: 'mastodon',
    customCheck: async (resp, text) => {
      if (resp.status === 200) {
        try {
          const d = JSON.parse(text);
          if (d.id && d.username) {
            return {
              found: true,
              proof: `Verified Mastodon Fediverse Profile ID ${d.id}`,
              name: d.display_name || d.username,
              bio: d.note ? d.note.replace(/<[^>]+>/g, '') : null,
              avatar: d.avatar || null,
            };
          }
        } catch {
          // fall through
        }
      }
      return false;
    },
  },
  {
    name: 'Chess.com',
    category: 'gaming',
    url: 'https://www.chess.com/member/{user}',
    checkUrl: 'https://api.chess.com/pub/player/{user}',
    userKey: 'chess',
    customCheck: async (resp, text) => {
      if (resp.status === 200) {
        try {
          const d = JSON.parse(text);
          if (d.player_id && d.username) {
            return {
              found: true,
              proof: `Verified Chess.com Player ID ${d.player_id}`,
              name: d.name || d.username,
              location: d.location || null,
              avatar: d.avatar || null,
            };
          }
        } catch {
          // fall through
        }
      }
      return false;
    },
  },
  {
    name: 'Steam',
    category: 'gaming',
    url: 'https://steamcommunity.com/id/{user}',
    userKey: 'steam',
    customCheck: async (resp, text) => {
      if (resp.status === 200) {
        if (!text.includes('The specified profile could not be found') && (text.includes('actual_persona_name') || text.includes('playerAvatar'))) {
          const personaMatch = text.match(/<span class="actual_persona_name">([^<]+)<\/span>/i);
          return {
            found: true,
            proof: `Verified Steam Community Profile`,
            name: personaMatch ? personaMatch[1] : null,
          };
        }
      }
      return false;
    },
  },
  {
    name: 'Telegram',
    category: 'social',
    url: 'https://t.me/{user}',
    userKey: 'telegram',
    customCheck: async (resp, text) => {
      if (resp.status === 200) {
        const titleMatch = text.match(/<div class="tgme_page_title"[^>]*>([\s\S]*?)<\/div>/i);
        const rawTitle = (titleMatch && titleMatch[1]) ? titleMatch[1].replace(/<[^>]+>/g, '').trim() : '';
        const notFound = text.includes('User not found') ||
                         text.includes('If you have Telegram, you can view and join') ||
                         (!rawTitle && text.includes('If you have <strong>Telegram</strong>, you can contact'));
        if (rawTitle && rawTitle.length > 0 && !notFound) {
          return {
            found: true,
            proof: `Verified Public Telegram Channel / User Contact: "${rawTitle}"`,
            name: rawTitle,
          };
        }
      }
      return false;
    },
  },
];

export async function checkUsernamePresence(username: string): Promise<UsernameCheckResult[]> {
  const collectedAt = new Date().toISOString();
  const results: UsernameCheckResult[] = [];

  const checks = USERNAME_PLATFORMS.map(async (platform) => {
    const targetUrl = platform.url.replace('{user}', encodeURIComponent(username));
    const queryUrl = (platform.checkUrl || platform.url).replace('{user}', encodeURIComponent(username));

    try {
      const resp = await fetch(queryUrl, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          Accept: 'application/json,text/html,application/xhtml+xml',
        },
      });

      let status: UsernameCheckResult['status'] = 'not_found';
      let verified = false;
      let verificationProof: string | null = null;
      let location: string | null = null;
      let bio: string | null = null;
      let displayName: string | null = null;
      let avatarUrl: string | null = null;

      const text = await resp.text().catch(() => '');
      const checkResult = await platform.customCheck(resp, text, username);

      if (typeof checkResult === 'object' && checkResult !== null) {
        status = checkResult.found ? 'found' : 'not_found';
        verified = checkResult.found;
        verificationProof = checkResult.proof ?? null;
        location = checkResult.location ?? null;
        bio = checkResult.bio ?? null;
        displayName = checkResult.name ?? null;
        avatarUrl = checkResult.avatar ?? null;
      } else {
        status = checkResult ? 'found' : 'not_found';
        verified = !!checkResult;
      }

      return {
        platform: platform.name,
        category: platform.category,
        url: targetUrl,
        status,
        verified,
        verificationProof,
        location,
        bio,
        displayName,
        avatarUrl,
        collectedAt,
      };
    } catch {
      return {
        platform: platform.name,
        category: platform.category,
        url: targetUrl,
        status: 'unknown' as const,
        verified: false,
        collectedAt,
      };
    }
  });

  // Batch concurrently in sets of 6
  for (let i = 0; i < checks.length; i += 6) {
    const batch = checks.slice(i, i + 6);
    const batchResults = await Promise.allSettled(batch);
    for (const r of batchResults) {
      if (r.status === 'fulfilled') results.push(r.value);
    }
  }

  return results;
}
