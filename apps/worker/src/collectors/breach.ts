// OpenSpective — Breach & Credential Exposure Intelligence Collector
// Assesses account and domain exposure against known historical public breaches.
// Uses HaveIBeenPwned if API key is provided, or passive catalog signatures if unconfigured.

export interface BreachRecord {
  name: string;
  title: string;
  domain: string;
  breachDate: string;
  addedDate: string;
  pwnCount: number;
  dataClasses: string[];
  isVerified: boolean;
  description: string;
}

export interface BreachCheckResults {
  target: string;
  targetType: 'email' | 'domain' | 'username';
  isPwned: boolean;
  breachCount: number;
  breaches: BreachRecord[];
  compromisedDataClasses: string[];
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
  source: string;
  collectedAt: string;
  error?: string;
}

// Well-known historic global breaches catalog for passive correlation
const HISTORIC_BREACH_CATALOG: Array<{ domain: string; name: string; title: string; date: string; count: number; classes: string[] }> = [
  { domain: 'adobe.com', name: 'Adobe', title: 'Adobe (2013)', date: '2013-10-04', count: 152994970, classes: ['Email addresses', 'Password hints', 'Passwords', 'Usernames'] },
  { domain: 'linkedin.com', name: 'LinkedIn', title: 'LinkedIn (2016)', date: '2016-05-18', count: 164611595, classes: ['Email addresses', 'Passwords'] },
  { domain: 'canva.com', name: 'Canva', title: 'Canva (2019)', date: '2019-05-24', count: 137454228, classes: ['Email addresses', 'Geographic locations', 'Names', 'Passwords', 'Usernames'] },
  { domain: 'dropbox.com', name: 'Dropbox', title: 'Dropbox (2012)', date: '2012-07-01', count: 68648009, classes: ['Email addresses', 'Passwords'] },
  { domain: 'myspace.com', name: 'MySpace', title: 'MySpace (2008)', date: '2008-07-01', count: 359420698, classes: ['Email addresses', 'Passwords', 'Usernames'] },
  { domain: 'twitter.com', name: 'Twitter', title: 'Twitter 200M Leak (2023)', date: '2023-01-04', count: 211522128, classes: ['Email addresses', 'Names', 'Screen names', 'Usernames'] },
  { domain: 'zynga.com', name: 'Zynga', title: 'Zynga (2019)', date: '2019-09-01', count: 172855421, classes: ['Email addresses', 'Passwords', 'Phone numbers', 'Usernames'] },
  { domain: 'wattpad.com', name: 'Wattpad', title: 'Wattpad (2020)', date: '2020-06-20', count: 268755495, classes: ['Dates of birth', 'Email addresses', 'IP addresses', 'Names', 'Passwords'] },
];

export async function collectBreachIntelligence(
  target: string,
  targetType: 'email' | 'domain' | 'username',
  apiKey?: string
): Promise<BreachCheckResults> {
  const collectedAt = new Date().toISOString();
  const cleanTarget = target.trim().toLowerCase();

  // If HIBP API key is provided and target is email, call HIBP
  if (apiKey && targetType === 'email') {
    try {
      const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(cleanTarget)}?truncateResponse=false`;
      const resp = await fetch(url, {
        headers: {
          'hibp-api-key': apiKey,
          'User-Agent': 'OpenSpective/0.1',
        },
        signal: AbortSignal.timeout(8000),
      });

      if (resp.status === 404) {
        return {
          target: cleanTarget,
          targetType,
          isPwned: false,
          breachCount: 0,
          breaches: [],
          compromisedDataClasses: [],
          riskLevel: 'none',
          source: 'Have I Been Pwned (HIBP API)',
          collectedAt,
        };
      }

      if (resp.ok) {
        const rawBreaches = await resp.json() as any[];
        const breaches: BreachRecord[] = rawBreaches.map(b => ({
          name: b.Name,
          title: b.Title,
          domain: b.Domain,
          breachDate: b.BreachDate,
          addedDate: b.AddedDate,
          pwnCount: b.PwnCount,
          dataClasses: b.DataClasses ?? [],
          isVerified: Boolean(b.IsVerified),
          description: (b.Description ?? '').replace(/<[^>]+>/g, '').slice(0, 300),
        }));

        const dataClasses = Array.from(new Set(breaches.flatMap(b => b.dataClasses)));
        const riskLevel = breaches.length >= 5 ? 'critical' : breaches.length >= 2 ? 'high' : breaches.length === 1 ? 'medium' : 'none';

        return {
          target: cleanTarget,
          targetType,
          isPwned: breaches.length > 0,
          breachCount: breaches.length,
          breaches,
          compromisedDataClasses: dataClasses,
          riskLevel,
          source: 'Have I Been Pwned (HIBP API)',
          collectedAt,
        };
      }
    } catch {
      // Fallback to passive catalog check
    }
  }

  // Domain-based breach correlation
  if (targetType === 'domain') {
    const matched = HISTORIC_BREACH_CATALOG.filter(b => b.domain === cleanTarget || cleanTarget.endsWith(`.${b.domain}`));
    if (matched.length > 0) {
      const breaches: BreachRecord[] = matched.map(m => ({
        name: m.name,
        title: m.title,
        domain: m.domain,
        breachDate: m.date,
        addedDate: m.date,
        pwnCount: m.count,
        dataClasses: m.classes,
        isVerified: true,
        description: `Verified historical mass data compromise affecting ${m.title}. Over ${m.count.toLocaleString()} user records exposed.`,
      }));

      const dataClasses = Array.from(new Set(breaches.flatMap(b => b.dataClasses)));

      return {
        target: cleanTarget,
        targetType,
        isPwned: true,
        breachCount: breaches.length,
        breaches,
        compromisedDataClasses: dataClasses,
        riskLevel: 'high',
        source: 'OpenSpective Verified Breach Catalog',
        collectedAt,
      };
    }
  }

  // Uncompromised or clean result
  return {
    target: cleanTarget,
    targetType,
    isPwned: false,
    breachCount: 0,
    breaches: [],
    compromisedDataClasses: [],
    riskLevel: 'low',
    source: apiKey ? 'Have I Been Pwned' : 'OpenSpective Breach Catalog',
    collectedAt,
  };
}
