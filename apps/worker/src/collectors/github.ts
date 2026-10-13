// OpenSpective — GitHub Collector
// Discovers public repositories and organizational metadata via GitHub public API.
// Works without token (60 req/hr) and with PAT (5000 req/hr).

export interface GitHubRepo {
  name: string;
  fullName: string;
  description: string | null;
  url: string;
  stars: number;
  forks: number;
  language: string | null;
  topics: string[];
  isForked: boolean;
  updatedAt: string;
  createdAt: string;
}

export interface GitHubOrgInfo {
  login: string;
  name: string | null;
  description: string | null;
  location: string | null;
  email: string | null;
  blog: string | null;
  publicRepos: number;
  followers: number;
  createdAt: string;
  avatarUrl: string | null;
  isVerified: boolean;
}

export interface GitHubResult {
  orgInfo: GitHubOrgInfo | null;
  repos: GitHubRepo[];
  userInfo: GitHubOrgInfo | null;
  source: string;
  collectedAt: string;
  error: string | null;
  isRateLimited: boolean;
}

const GITHUB_API = 'https://api.github.com';

async function fetchGitHub<T>(
  path: string,
  token?: string
): Promise<{ data: T | null; status: number; rateLimited: boolean }> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'OpenSpective/0.1',
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  try {
    const resp = await fetch(`${GITHUB_API}${path}`, {
      headers,
      signal: AbortSignal.timeout(10000),
    });

    if (resp.status === 429 || resp.status === 403) {
      return { data: null, status: resp.status, rateLimited: true };
    }

    if (!resp.ok) {
      return { data: null, status: resp.status, rateLimited: false };
    }

    const data: T = await resp.json();
    return { data, status: resp.status, rateLimited: false };
  } catch {
    return { data: null, status: 0, rateLimited: false };
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mapOrgOrUser(data: any): GitHubOrgInfo {
  return {
    login: data.login ?? '',
    name: data.name ?? null,
    description: data.description ?? data.bio ?? null,
    location: data.location ?? null,
    email: data.email ?? null,
    blog: data.blog || null,
    publicRepos: data.public_repos ?? 0,
    followers: data.followers ?? 0,
    createdAt: data.created_at ?? '',
    avatarUrl: data.avatar_url ?? null,
    isVerified: data.is_verified ?? false,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mapRepo(data: any): GitHubRepo {
  return {
    name: data.name ?? '',
    fullName: data.full_name ?? '',
    description: data.description ?? null,
    url: data.html_url ?? '',
    stars: data.stargazers_count ?? 0,
    forks: data.forks_count ?? 0,
    language: data.language ?? null,
    topics: Array.isArray(data.topics) ? data.topics : [],
    isForked: data.fork ?? false,
    updatedAt: data.updated_at ?? '',
    createdAt: data.created_at ?? '',
  };
}

export async function collectGitHubOrg(
  orgName: string,
  token?: string
): Promise<GitHubResult> {
  const collectedAt = new Date().toISOString();
  const source = 'GitHub Public API';
  const slug = orgName.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '');

  // Try org first, then user
  const orgResp = await fetchGitHub<unknown>(`/orgs/${slug}`, token);
  const userResp = orgResp.data === null
    ? await fetchGitHub<unknown>(`/users/${slug}`, token)
    : { data: null, status: 0, rateLimited: false };

  const isRateLimited = orgResp.rateLimited || userResp.rateLimited;
  if (isRateLimited) {
    return { orgInfo: null, repos: [], userInfo: null, source, collectedAt, error: 'Rate limited by GitHub API', isRateLimited: true };
  }

  const profileData = orgResp.data ?? userResp.data;
  if (!profileData) {
    return { orgInfo: null, repos: [], userInfo: null, source, collectedAt, error: null, isRateLimited: false };
  }

  const isOrg = !!orgResp.data;
  const info = mapOrgOrUser(profileData);

  // Fetch repos
  const reposResp = await fetchGitHub<unknown[]>(
    isOrg ? `/orgs/${slug}/repos?per_page=20&sort=updated` : `/users/${slug}/repos?per_page=20&sort=updated`,
    token
  );

  const repos = Array.isArray(reposResp.data)
    ? reposResp.data.map(mapRepo).filter(r => !r.isForked).slice(0, 15)
    : [];

  return {
    orgInfo: isOrg ? info : null,
    userInfo: !isOrg ? info : null,
    repos,
    source,
    collectedAt,
    error: null,
    isRateLimited: false,
  };
}

export async function collectGitHubUser(
  username: string,
  token?: string
): Promise<GitHubResult> {
  const collectedAt = new Date().toISOString();
  const source = 'GitHub Public API';

  const userResp = await fetchGitHub<unknown>(`/users/${encodeURIComponent(username)}`, token);

  if (userResp.rateLimited) {
    return { orgInfo: null, repos: [], userInfo: null, source, collectedAt, error: 'Rate limited by GitHub API', isRateLimited: true };
  }

  if (!userResp.data) {
    return { orgInfo: null, repos: [], userInfo: null, source, collectedAt, error: null, isRateLimited: false };
  }

  const info = mapOrgOrUser(userResp.data);

  const reposResp = await fetchGitHub<unknown[]>(
    `/users/${encodeURIComponent(username)}/repos?per_page=20&sort=updated`,
    token
  );

  const repos = Array.isArray(reposResp.data)
    ? reposResp.data.map(mapRepo).filter(r => !r.isForked).slice(0, 15)
    : [];

  return {
    orgInfo: null,
    userInfo: info,
    repos,
    source,
    collectedAt,
    error: null,
    isRateLimited: false,
  };
}
