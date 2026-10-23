import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Compass, Search, ExternalLink, Copy, Check, Sparkles
} from 'lucide-react';

interface OsintTool {
  id: string;
  name: string;
  category: string;
  subcategory: string;
  description: string;
  urlTemplate: string; // supports {target}, {domain}, {username}, {email}, {ip}
  directUrl: string;
  tags: string[];
  requiresApiKey: boolean;
  freeTier: boolean;
}

const OSINT_FRAMEWORK_DATA: OsintTool[] = [
  // --- USERNAME & IDENTITY ---
  {
    id: 'whatsmyname',
    name: 'WhatsMyName Web',
    category: 'Usernames',
    subcategory: 'Cross-Platform Footprint',
    description: 'Fast, passive username enumeration tool checking 500+ open-web services.',
    urlTemplate: 'https://whatsmyname.app/?q={username}',
    directUrl: 'https://whatsmyname.app/',
    tags: ['username', 'social', 'profiles'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'keybase',
    name: 'Keybase Public Directory',
    category: 'Usernames',
    subcategory: 'Cryptographic Identity',
    description: 'Cryptographically proven identity directory linking GitHub, Twitter, Reddit, and PGP keys.',
    urlTemplate: 'https://keybase.io/{username}',
    directUrl: 'https://keybase.io/',
    tags: ['identity', 'crypto', 'pgp'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'namechk',
    name: 'Namechk Handle Availability',
    category: 'Usernames',
    subcategory: 'Brand & Handle Monitoring',
    description: 'Check brand and handle registration across dozens of social networks and domains.',
    urlTemplate: 'https://namechk.com/',
    directUrl: 'https://namechk.com/',
    tags: ['brand', 'social', 'domains'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'gravatar',
    name: 'Gravatar Profile & Hash Resolver',
    category: 'Usernames',
    subcategory: 'Avatar & Bio Intelligence',
    description: 'Globally recognized avatar service linking email MD5 hashes to public names and accounts.',
    urlTemplate: 'https://en.gravatar.com/{username}',
    directUrl: 'https://gravatar.com/',
    tags: ['email', 'avatar', 'identity'],
    requiresApiKey: false,
    freeTier: true,
  },

  // --- EMAIL INTELLIGENCE ---
  {
    id: 'epieos',
    name: 'Epieos Google & Account Finder',
    category: 'Email',
    subcategory: 'Linked Account Discovery',
    description: 'Finds Google accounts, Google Maps reviews, calendars, and services linked to an email without alerting the target.',
    urlTemplate: 'https://epieos.com/?q={email}',
    directUrl: 'https://epieos.com/',
    tags: ['email', 'google', 'passive'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'ubuntu-pgp',
    name: 'Ubuntu Keyserver (SKS / OpenPGP)',
    category: 'Email',
    subcategory: 'Cryptographic Key Registry',
    description: 'Global public PGP key index containing public keys, linked email addresses, and key creation history.',
    urlTemplate: 'https://keyserver.ubuntu.com/pks/lookup?search={email}&op=index',
    directUrl: 'https://keyserver.ubuntu.com/',
    tags: ['pgp', 'crypto', 'email'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'hunter-io',
    name: 'Hunter.io Email Permutations',
    category: 'Email',
    subcategory: 'Corporate Pattern Discovery',
    description: 'Discovers corporate email format patterns (e.g. {first}.{last}@domain) and verified public addresses.',
    urlTemplate: 'https://hunter.io/try/search/{domain}',
    directUrl: 'https://hunter.io/',
    tags: ['corporate', 'domain', 'email'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'emailrep',
    name: 'EmailRep.io Reputation & Footprint',
    category: 'Email',
    subcategory: 'Fraud & Deliverability',
    description: 'Reputation engine analyzing deliverability, social presence, spam history, and disposable providers.',
    urlTemplate: 'https://emailrep.io/{email}',
    directUrl: 'https://emailrep.io/',
    tags: ['reputation', 'deliverability', 'email'],
    requiresApiKey: false,
    freeTier: true,
  },

  // --- DOMAIN & SUBDOMAINS ---
  {
    id: 'crt-sh',
    name: 'crt.sh Certificate Transparency',
    category: 'Domains',
    subcategory: 'Subdomain Discovery',
    description: 'Search Certificate Transparency logs to discover all active and historical subdomains for any root domain.',
    urlTemplate: 'https://crt.sh/?q=%25.{domain}',
    directUrl: 'https://crt.sh/',
    tags: ['tls', 'certificates', 'subdomains'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'alienvault-otx',
    name: 'AlienVault OTX Passive DNS',
    category: 'Domains',
    subcategory: 'Threat Exchange & Historical DNS',
    description: 'Open Threat Exchange containing passive DNS resolutions, historical IP mapping, and threat pulses.',
    urlTemplate: 'https://otx.alienvault.com/indicator/domain/{domain}',
    directUrl: 'https://otx.alienvault.com/',
    tags: ['passive-dns', 'threats', 'ioc'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'securitytrails',
    name: 'SecurityTrails DNS History',
    category: 'Domains',
    subcategory: 'Historical A / MX / NS Records',
    description: 'Explore historical DNS changes to discover origin server IPs prior to CDN/Cloudflare onboarding.',
    urlTemplate: 'https://securitytrails.com/domain/{domain}/dns',
    directUrl: 'https://securitytrails.com/',
    tags: ['history', 'dns', 'origin-ip'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'hackertarget-dns',
    name: 'HackerTarget Host Search',
    category: 'Domains',
    subcategory: 'Fast Subdomain Enumeration',
    description: 'Passive querying of forward DNS dataset to map subdomains and hosted IP addresses.',
    urlTemplate: 'https://hackertarget.com/find-dns-host-records/?the_target={domain}',
    directUrl: 'https://hackertarget.com/',
    tags: ['subdomains', 'dns', 'lookup'],
    requiresApiKey: false,
    freeTier: true,
  },

  // --- IP & NETWORK INFRASTRUCTURE ---
  {
    id: 'shodan-host',
    name: 'Shodan Global Device Search',
    category: 'IP & Infrastructure',
    subcategory: 'Network Banners & Ports',
    description: 'The world\'s search engine for Internet-connected devices, industrial controllers, and open ports.',
    urlTemplate: 'https://www.shodan.io/host/{ip}',
    directUrl: 'https://www.shodan.io/',
    tags: ['ports', 'banners', 'iot'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'censys-search',
    name: 'Censys Search Engine',
    category: 'IP & Infrastructure',
    subcategory: 'TLS & Host Fingerprinting',
    description: 'Continuous Internet scanning engine providing deep TLS handshakes, virtual hosts, and software signatures.',
    urlTemplate: 'https://search.censys.io/hosts/{ip}',
    directUrl: 'https://search.censys.io/',
    tags: ['tls', 'fingerprinting', 'ip'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'bgpview',
    name: 'BGPView ASN & Prefix Routing',
    category: 'IP & Infrastructure',
    subcategory: 'BGP Routing & Peering',
    description: 'Analyze Autonomous System Numbers (ASN), BGP prefixes, upstream transits, and IX peers.',
    urlTemplate: 'https://bgpview.io/ip/{ip}',
    directUrl: 'https://bgpview.io/',
    tags: ['bgp', 'asn', 'routing'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB Threat Reports',
    category: 'IP & Infrastructure',
    subcategory: 'Abuse & Attack History',
    description: 'Crowdsourced database of reported malicious IPs engaging in SSH brute force, port scans, and web attacks.',
    urlTemplate: 'https://www.abuseipdb.com/check/{ip}',
    directUrl: 'https://www.abuseipdb.com/',
    tags: ['abuse', 'attacks', 'reputation'],
    requiresApiKey: false,
    freeTier: true,
  },

  // --- THREAT INTELLIGENCE & IOCS ---
  {
    id: 'urlhaus',
    name: 'Abuse.ch URLhaus Malware Database',
    category: 'Threat Intelligence',
    subcategory: 'Malware Distribution URLs',
    description: 'Community-driven project sharing malicious URLs that are being used for malware distribution.',
    urlTemplate: 'https://urlhaus.abuse.ch/browse.php?search={domain}',
    directUrl: 'https://urlhaus.abuse.ch/',
    tags: ['malware', 'payloads', 'c2'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'threatfox',
    name: 'ThreatFox Indicators of Compromise',
    category: 'Threat Intelligence',
    subcategory: 'C2 & IOC Tracking',
    description: 'Free platform to share and query indicators of compromise associated with cyber threats.',
    urlTemplate: 'https://threatfox.abuse.ch/browse.php?search={domain}',
    directUrl: 'https://threatfox.abuse.ch/',
    tags: ['ioc', 'c2', 'threats'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'virustotal',
    name: 'VirusTotal Multi-Engine Scanner',
    category: 'Threat Intelligence',
    subcategory: 'Antivirus & URL Heuristics',
    description: 'Aggregate reports from 70+ antivirus scanners and URL/domain blacklists.',
    urlTemplate: 'https://www.virustotal.com/gui/domain/{domain}',
    directUrl: 'https://www.virustotal.com/',
    tags: ['antivirus', 'scanners', 'ioc'],
    requiresApiKey: false,
    freeTier: true,
  },

  // --- DOCUMENTS, CODE & LEAKS ---
  {
    id: 'github-code-search',
    name: 'GitHub Code Secrets Search',
    category: 'Documents & Leaks',
    subcategory: 'Public Code Leakage',
    description: 'Search billions of lines of public code for leaked credentials, private keys, and configuration tokens.',
    urlTemplate: 'https://github.com/search?q=%22{domain}%22+password+OR+secret+OR+token&type=code',
    directUrl: 'https://github.com/search',
    tags: ['github', 'code', 'secrets'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'wayback-machine',
    name: 'Wayback Machine Archive',
    category: 'Documents & Leaks',
    subcategory: 'Historical Snapshots',
    description: 'Internet Archive of 800+ billion web pages, historical versions, and removed files.',
    urlTemplate: 'https://web.archive.org/web/*/{domain}',
    directUrl: 'https://archive.org/',
    tags: ['archive', 'history', 'snapshots'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'pastebin-search',
    name: 'Public Paste & Dumps Search',
    category: 'Documents & Leaks',
    subcategory: 'Pastebin & Leak Search',
    description: 'Search public paste sites (Pastebin, Ghostbin, Rentry) for published data dumps and logs.',
    urlTemplate: 'https://www.google.com/search?q=site:pastebin.com+OR+site:rentry.co+%22{target}%22',
    directUrl: 'https://pastebin.com/',
    tags: ['pastebin', 'dumps', 'leaks'],
    requiresApiKey: false,
    freeTier: true,
  },

  // --- CORPORATE & LEGAL REGISTRIES ---
  {
    id: 'opencorporates',
    name: 'OpenCorporates Global Registry',
    category: 'Corporate & Legal',
    subcategory: 'Global Company Filings',
    description: 'The largest open database of company filings, officers, corporate entities, and jurisdictions.',
    urlTemplate: 'https://opencorporates.com/companies?q={target}',
    directUrl: 'https://opencorporates.com/',
    tags: ['company', 'officers', 'legal'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'sec-edgar',
    name: 'SEC EDGAR Public Filings',
    category: 'Corporate & Legal',
    subcategory: 'US Securities & Financial Filings',
    description: 'Official US Securities and Exchange Commission filings (10-K, 10-Q, 8-K) for publicly traded corporations.',
    urlTemplate: 'https://www.sec.gov/edgar/searchedgar/companysearch?companyName={target}',
    directUrl: 'https://www.sec.gov/edgar/searchedgar/companysearch',
    tags: ['sec', 'financial', 'filings'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'companies-house',
    name: 'UK Companies House Register',
    category: 'Corporate & Legal',
    subcategory: 'UK Enterprise & Directors',
    description: 'Official register of UK businesses, directors, accounts, and registered office addresses.',
    urlTemplate: 'https://find-and-update.company-information.service.gov.uk/search?q={target}',
    directUrl: 'https://find-and-update.company-information.service.gov.uk/',
    tags: ['uk', 'directors', 'companies'],
    requiresApiKey: false,
    freeTier: true,
  },

  // --- GEOLOCATION & SATELLITE ---
  {
    id: 'suncalc',
    name: 'SunCalc Sunlight & Shadow Calculator',
    category: 'Geolocation & Satellite',
    subcategory: 'Chronolocation & Shadow Analysis',
    description: 'Calculate sun movement and shadow lengths to pinpoint the exact time and location of photos/videos.',
    urlTemplate: 'https://www.suncalc.org/',
    directUrl: 'https://www.suncalc.org/',
    tags: ['shadows', 'sun', 'chronolocation'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'overpass-turbo',
    name: 'Overpass Turbo (OpenStreetMap)',
    category: 'Geolocation & Satellite',
    subcategory: 'Geospatial Query Engine',
    description: 'Web-based data mining tool for OpenStreetMap to find features matching specific visual or spatial criteria.',
    urlTemplate: 'https://overpass-turbo.eu/',
    directUrl: 'https://overpass-turbo.eu/',
    tags: ['osm', 'geospatial', 'maps'],
    requiresApiKey: false,
    freeTier: true,
  },
  {
    id: 'adsbexchange',
    name: 'ADS-B Exchange Flight Tracking',
    category: 'Geolocation & Satellite',
    subcategory: 'Live Aircraft & Radar Tracking',
    description: 'Unfiltered flight tracking cooperative tracking civilian and military aircraft worldwide.',
    urlTemplate: 'https://globe.adsbexchange.com/',
    directUrl: 'https://globe.adsbexchange.com/',
    tags: ['aviation', 'radar', 'tracking'],
    requiresApiKey: false,
    freeTier: true,
  },
];

export default function OsintFrameworkPage() {
  const navigate = useNavigate();
  const [activeTarget, setActiveTarget] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Categories list
  const categories = useMemo(() => {
    const set = new Set<string>();
    OSINT_FRAMEWORK_DATA.forEach(t => set.add(t.category));
    return ['All', ...Array.from(set)];
  }, []);

  // Filtered tools
  const filteredTools = useMemo(() => {
    return OSINT_FRAMEWORK_DATA.filter(tool => {
      const matchCat = selectedCategory === 'All' || tool.category === selectedCategory;
      const matchSearch = !searchQuery ||
        tool.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        tool.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        tool.subcategory.toLowerCase().includes(searchQuery.toLowerCase()) ||
        tool.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));
      return matchCat && matchSearch;
    });
  }, [selectedCategory, searchQuery]);

  // Interpolate query URL for active target
  const resolveTargetUrl = (tool: OsintTool) => {
    if (!activeTarget.trim()) return tool.directUrl;
    const clean = activeTarget.trim();
    const cleanDomain = clean.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
    const userSlug = clean.split('@')[0].replace(/[^a-zA-Z0-9_-]/g, '');

    return tool.urlTemplate
      .replace('{target}', encodeURIComponent(clean))
      .replace('{domain}', encodeURIComponent(cleanDomain))
      .replace('{username}', encodeURIComponent(userSlug))
      .replace('{email}', encodeURIComponent(clean))
      .replace('{ip}', encodeURIComponent(clean));
  };

  const handleLaunchInvestigation = () => {
    if (!activeTarget.trim()) return;
    navigate(`/investigate?target=${encodeURIComponent(activeTarget.trim())}`);
  };

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', padding: 'var(--space-6) var(--space-4)' }}>
      {/* Header */}
      <div style={{ marginBottom: 'var(--space-8)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-2)' }}>
          <div style={{
            width: 40,
            height: 40,
            borderRadius: 'var(--radius)',
            background: 'var(--color-accent-soft)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--color-accent)'
          }}>
            <Compass size={24} />
          </div>
          <div>
            <h1 style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, margin: 0, color: 'var(--color-dark)' }}>
              OSINT Framework & Intelligence Hub
            </h1>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', margin: 0 }}>
              Curated open-source intelligence methods, direct reconnaissance pivots, and automated search techniques.
            </p>
          </div>
        </div>
      </div>

      {/* Target Pivot Launcher Bar */}
      <div className="card" style={{
        marginBottom: 'var(--space-8)',
        padding: 'var(--space-5)',
        background: 'var(--color-surface-elevated)',
        border: '1.5px solid var(--color-accent-soft)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
          <Sparkles size={16} style={{ color: 'var(--color-accent)' }} />
          <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--color-dark)' }}>
            Active Target Pivot Engine
          </strong>
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
            Enter any target to dynamically populate pre-configured queries across all tools below
          </span>
        </div>

        <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 260, position: 'relative' }}>
            <input
              type="text"
              className="input"
              placeholder="e.g. example.com, analyst@company.org, torvalds, 1.1.1.1, +14155552671"
              value={activeTarget}
              onChange={(e) => setActiveTarget(e.target.value)}
              style={{ width: '100%', paddingLeft: 'var(--space-4)' }}
            />
          </div>

          <button
            onClick={handleLaunchInvestigation}
            disabled={!activeTarget.trim()}
            className="btn btn-primary"
            style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}
          >
            <Search size={16} /> Run Full OpenSpective Scan
          </button>
        </div>

        {activeTarget.trim() && (
          <div style={{ marginTop: 'var(--space-3)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-xs)' }}>
            <span style={{ color: 'var(--color-text-secondary)' }}>Active pivot target:</span>
            <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)' }}>
              {activeTarget}
            </span>
            <span style={{ color: 'var(--color-text-muted)' }}>
              All 28 tools below have live query links ready to launch.
            </span>
          </div>
        )}
      </div>

      {/* Search and Category Filters */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-4)', marginBottom: 'var(--space-6)' }}>
        <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
          {categories.map(cat => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`btn btn-sm ${selectedCategory === cat ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: 'var(--text-xs)' }}
            >
              {cat}
            </button>
          ))}
        </div>

        <div style={{ position: 'relative', width: 220 }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: 11, color: 'var(--color-text-muted)' }} />
          <input
            type="text"
            className="input input-sm"
            placeholder="Search OSINT tools..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ width: '100%', paddingLeft: 30 }}
          />
        </div>
      </div>

      {/* Tools Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 'var(--space-5)' }}>
        {filteredTools.map(tool => {
          const resolvedUrl = resolveTargetUrl(tool);
          const hasActiveQuery = activeTarget.trim().length > 0;

          return (
            <div key={tool.id} className="card" style={{
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              padding: 'var(--space-5)',
              transition: 'transform 0.15s ease, border-color 0.15s ease',
            }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 'var(--space-2)' }}>
                  <div>
                    <span className="badge badge-neutral" style={{ fontSize: '10px', textTransform: 'uppercase', marginBottom: 4 }}>
                      {tool.subcategory}
                    </span>
                    <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, margin: 0, color: 'var(--color-dark)' }}>
                      {tool.name}
                    </h3>
                  </div>

                  <span className="badge badge-success" style={{ fontSize: '10px' }}>
                    Free / Open
                  </span>
                </div>

                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: 'var(--space-4)' }}>
                  {tool.description}
                </p>

                {/* Tags */}
                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginBottom: 'var(--space-4)' }}>
                  {tool.tags.map(t => (
                    <span key={t} style={{
                      fontSize: '10px',
                      padding: '2px 6px',
                      borderRadius: 4,
                      background: 'var(--color-bg)',
                      border: '1px solid var(--color-border)',
                      color: 'var(--color-text-muted)'
                    }}>
                      #{t}
                    </span>
                  ))}
                </div>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', gap: 'var(--space-2)', paddingTop: 'var(--space-3)', borderTop: '1px solid var(--color-border)' }}>
                <a
                  href={resolvedUrl}
                  target="_blank"
                  rel="noreferrer"
                  className={`btn btn-sm ${hasActiveQuery ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ flex: 1, textDecoration: 'none', justifyContent: 'center' }}
                >
                  <span>{hasActiveQuery ? 'Query Target' : 'Open Tool'}</span>
                  <ExternalLink size={13} />
                </a>

                <button
                  onClick={() => handleCopy(tool.id, resolvedUrl)}
                  className="btn btn-ghost btn-sm"
                  title="Copy direct URL"
                  style={{ padding: '0 var(--space-3)' }}
                >
                  {copiedId === tool.id ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {filteredTools.length === 0 && (
        <div className="card" style={{ padding: 'var(--space-12)', textAlign: 'center', color: 'var(--color-text-muted)' }}>
          No OSINT Framework tools matched your search criteria.
        </div>
      )}
    </div>
  );
}
