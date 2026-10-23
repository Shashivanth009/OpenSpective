import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { collectPhoneIntelligence } from '../collectors/phone.ts';
import { collectShodanInternetDb } from '../collectors/shodan.ts';
import { collectDnsSecurity } from '../collectors/dns_security.ts';
import { getAllCollectors, getCollectorsForTargetType } from '../collectors/registry.ts';

describe('Enrichment Collectors Unit Tests', () => {
  describe('International Phone Number Intelligence', () => {
    it('accurately parses US phone numbers and creates OSINT pivots', async () => {
      const result = await collectPhoneIntelligence('+1 (415) 555-2671');
      expect(result.countryCode).toBe('+1');
      expect(result.isoCountry).toBe('US');
      expect(result.countryName).toContain('United States');
      expect(result.validLength).toBe(true);
      expect(result.e164Format).toBe('+14155552671');
      expect(result.coordinates).not.toBeNull();
      expect(result.osintPivots.length).toBeGreaterThan(0);
      expect(result.osintPivots.some(p => p.url.includes('google.com'))).toBe(true);
    });

    it('classifies UK mobile numbers correctly', async () => {
      const result = await collectPhoneIntelligence('+44 7911 123456');
      expect(result.countryCode).toBe('+44');
      expect(result.isoCountry).toBe('GB');
      expect(result.lineType).toBe('mobile');
      expect(result.validLength).toBe(true);
    });

    it('identifies toll-free numbers', async () => {
      const result = await collectPhoneIntelligence('+1 800 555 0199');
      expect(result.countryCode).toBe('+1');
      expect(result.lineType).toBe('toll_free');
    });

    it('gracefully handles unknown country prefixes', async () => {
      const result = await collectPhoneIntelligence('+999 12345678');
      expect(result.countryCode).toBe('Unknown');
      expect(result.countryName).toBe('Unknown Country / International');
      expect(result.lineType).toBe('unknown');
    });
  });

  describe('Shodan InternetDB Passive Intelligence', () => {
    const originalFetch = globalThis.fetch;

    afterEach(() => {
      globalThis.fetch = originalFetch;
    });

    it('parses open ports, CVEs, CPEs, and hostnames', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          ip: '8.8.8.8',
          ports: [53, 443],
          vulns: ['CVE-2021-1234'],
          hostnames: ['dns.google'],
          tags: ['dns'],
          cpes: ['cpe:/a:google:dns:1.0'],
        }),
      } as any);

      const result = await collectShodanInternetDb('8.8.8.8');
      expect(result.hasData).toBe(true);
      expect(result.ports).toEqual([53, 443]);
      expect(result.cves).toEqual(['CVE-2021-1234']);
      expect(result.hostnames).toEqual(['dns.google']);
      expect(result.cpes).toEqual(['cpe:/a:google:dns:1.0']);
    });

    it('returns empty hasData=false on 404 without error', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      } as any);

      const result = await collectShodanInternetDb('1.2.3.4');
      expect(result.hasData).toBe(false);
      expect(result.ports).toHaveLength(0);
      expect(result.cves).toHaveLength(0);
      expect(result.error).toBeUndefined();
    });
  });

  describe('DNS & Email Security Hygiene Collector', () => {
    const originalFetch = globalThis.fetch;

    afterEach(() => {
      globalThis.fetch = originalFetch;
    });

    it('grades domain with comprehensive SPF, DMARC, and DNSSEC', async () => {
      globalThis.fetch = vi.fn().mockImplementation((url: string) => {
        if (url.includes('type=TXT') && url.includes('_dmarc.')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              Answer: [{ data: '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"' }],
            }),
          });
        }
        if (url.includes('type=TXT') && url.includes('_mta-sts.')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              Answer: [{ data: '"v=STSv1; id=20240101"' }],
            }),
          });
        }
        if (url.includes('type=TXT') && url.includes('_smtp._tls.')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              Answer: [{ data: '"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"' }],
            }),
          });
        }
        if (url.includes('type=TXT') && url.includes('default._bimi.')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              Answer: [{ data: '"v=BIMI1; l=https://example.com/logo.svg"' }],
            }),
          });
        }
        if (url.includes('type=TXT')) {
          // Domain TXT (SPF)
          return Promise.resolve({
            ok: true,
            json: async () => ({
              Answer: [{ data: '"v=spf1 include:_spf.google.com -all"' }],
            }),
          });
        }
        if (url.includes('type=DS')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              Status: 0,
              Answer: [{ type: 43 }],
            }),
          });
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ Answer: [] }),
        });
      });

      const res = await collectDnsSecurity('example.com');
      expect(res.domain).toBe('example.com');
      expect(res.hasSpf).toBe(true);
      expect(res.hasDmarc).toBe(true);
      expect(res.hasBimi).toBe(true);
      expect(res.hasMtaSts).toBe(true);
      expect(res.hasDnssec).toBe(true);
      expect(res.securityScore).toBeGreaterThanOrEqual(90);
      expect(res.securityGrade).toBe('A+');
    });
  });

  describe('Strict Username Presence Validation', () => {
    const originalFetch = globalThis.fetch;

    afterEach(() => {
      globalThis.fetch = originalFetch;
    });

    it('rejects HackerNews soft-404 with "No such user."', async () => {
      const { checkUsernamePresence } = await import('../collectors/person.ts');
      globalThis.fetch = vi.fn().mockImplementation((url: string) => {
        if (url.includes('news.ycombinator.com')) {
          return Promise.resolve({
            status: 200,
            text: async () => '<html><body>No such user.</body></html>',
          } as any);
        }
        return Promise.resolve({
          status: 404,
          text: async () => '',
        } as any);
      });

      const results = await checkUsernamePresence('nonexistentuser123');
      const hn = results.find(r => r.platform === 'HackerNews');
      expect(hn).toBeDefined();
      expect(hn?.status).toBe('not_found');
      expect(hn?.verified).toBe(false);
    });

    it('validates genuine GitHub and GitLab profiles with proof', async () => {
      const { checkUsernamePresence } = await import('../collectors/person.ts');
      globalThis.fetch = vi.fn().mockImplementation((url: string) => {
        if (url.includes('api.github.com/users/octocat')) {
          return Promise.resolve({
            status: 200,
            text: async () => JSON.stringify({
              login: 'octocat',
              id: 583231,
              name: 'The Octocat',
              public_repos: 8,
              bio: 'GitHub mascot',
              avatar_url: 'https://avatars.githubusercontent.com/u/583231',
            }),
          } as any);
        }
        if (url.includes('gitlab.com/api/v4/users')) {
          return Promise.resolve({
            status: 200,
            text: async () => JSON.stringify([
              { id: 12345, username: 'octocat', name: 'Octocat' },
            ]),
          } as any);
        }
        return Promise.resolve({
          status: 404,
          text: async () => '',
        } as any);
      });

      const results = await checkUsernamePresence('octocat');
      const gh = results.find(r => r.platform === 'GitHub');
      expect(gh?.status).toBe('found');
      expect(gh?.verified).toBe(true);
      expect(gh?.verificationProof).toContain('Verified GitHub User ID');

      const gl = results.find(r => r.platform === 'GitLab');
      expect(gl?.status).toBe('found');
      expect(gl?.verified).toBe(true);
      expect(gl?.verificationProof).toContain('Verified GitLab Account ID');
    });
  });

  describe('OSINT Framework Public Intelligence', () => {
    const originalFetch = globalThis.fetch;

    afterEach(() => {
      globalThis.fetch = originalFetch;
    });

    it('generates rich search dorks across documents, secrets, and auth portals', async () => {
      const { generateOsintFrameworkDorks, generateCloudBucketPermutations } = await import('../collectors/osint_framework.ts');
      const dorks = generateOsintFrameworkDorks('example.com', 'domain');
      expect(dorks.length).toBeGreaterThanOrEqual(8);
      expect(dorks.some(d => d.category === 'sensitive_documents')).toBe(true);
      expect(dorks.some(d => d.category === 'exposed_secrets')).toBe(true);
      expect(dorks.some(d => d.category === 'auth_portals')).toBe(true);
      expect(dorks.some(d => d.platform === 'GitHub')).toBe(true);
      expect(dorks.some(d => d.platform === 'Shodan')).toBe(true);

      const buckets = generateCloudBucketPermutations('example.com');
      expect(buckets.length).toBeGreaterThan(0);
      expect(buckets.some(b => b.provider.includes('Amazon Web Services'))).toBe(true);
    });

    it('parses Ubuntu PGP keyserver responses into structured key records', async () => {
      const { queryPgpKeyserver } = await import('../collectors/osint_framework.ts');
      const fakePksResponse = `info:1:2
pub:A1B2C3D4E5F60718:1:4096:1609459200::
uid:Satoshi Nakamoto <satoshin@gmx.com>
fpr:11223344556677889900AABBCCDDEEFF00112233`;

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: async () => fakePksResponse,
      } as any);

      const keys = await queryPgpKeyserver('satoshin@gmx.com');
      expect(keys.length).toBe(1);
      expect(keys[0].keyId).toBe('A1B2C3D4E5F60718');
      expect(keys[0].identities[0]).toContain('Satoshi Nakamoto');
      expect(keys[0].algorithm).toBe('RSA');
      expect(keys[0].bitLength).toBe(4096);
    });
  });

  describe('Registry Verification', () => {
    it('registers shodan, phone, dns_security, and osint_framework in the collector catalog', () => {
      const all = getAllCollectors();
      const names = all.map(c => c.name);
      expect(names).toContain('shodan');
      expect(names).toContain('phone');
      expect(names).toContain('dns_security');
      expect(names).toContain('osint_framework');
    });

    it('assigns phone collector to phone target type', () => {
      const { available } = getCollectorsForTargetType('phone');
      expect(available.map(c => c.name)).toContain('phone');
    });

    it('assigns shodan collector to ip and domain targets', () => {
      const ipCollectors = getCollectorsForTargetType('ip').available.map(c => c.name);
      expect(ipCollectors).toContain('shodan');
      const domainCollectors = getCollectorsForTargetType('domain').available.map(c => c.name);
      expect(domainCollectors).toContain('shodan');
    });

    it('assigns osint_framework across all target types', () => {
      const types = ['domain', 'ip', 'email', 'username', 'phone', 'person'] as const;
      for (const t of types) {
        const collectors = getCollectorsForTargetType(t).available.map(c => c.name);
        expect(collectors).toContain('osint_framework');
      }
    });
  });
});
