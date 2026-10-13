import { BookOpen, Shield, Globe, Database, Cpu } from 'lucide-react';

export default function DocsPage() {
  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: 'var(--space-8) var(--space-8)' }}>
      {/* Header */}
      <div style={{ marginBottom: 'var(--space-10)', borderBottom: '1px solid var(--color-border)', paddingBottom: 'var(--space-6)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', color: 'var(--color-accent)', fontWeight: 700, fontSize: 'var(--text-sm)' }}>
          <BookOpen size={18} /> DOCUMENTATION & METHODOLOGY
        </div>
        <h1 style={{ fontSize: 'var(--text-4xl)', fontWeight: 800, color: 'var(--color-dark)', letterSpacing: '-0.03em', marginTop: 'var(--space-2)' }}>
          OpenSpective Architecture & OSINT Guide
        </h1>
        <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--text-lg)', marginTop: 'var(--space-3)', lineHeight: 1.6 }}>
          Learn how OpenSpective aggregates passive public telemetry, correlates entity graphs, and runs evidence-grounded AI synthesis without intrusive scanning.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-8)' }}>
        {/* Section 1: Philosophy & Passive OSINT */}
        <section className="card" style={{ padding: 'var(--space-8)' }}>
          <h2 style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <Shield size={24} style={{ color: 'var(--color-accent)' }} /> 1. Passive Reconnaissance Principles
          </h2>
          <p style={{ color: 'var(--color-text-secondary)', lineHeight: 1.7, fontSize: 'var(--text-base)' }}>
            Traditional security scanners often fire intrusive SYN packets, sweep network ports, or crawl web applications, generating noticeable traffic and potentially violating terms of service.
          </p>
          <div style={{
            background: 'var(--color-bg)',
            padding: 'var(--space-5)',
            borderRadius: 'var(--radius)',
            borderLeft: '4px solid var(--color-accent)',
            margin: 'var(--space-4) 0',
          }}>
            <strong style={{ color: 'var(--color-dark)' }}>The OpenSpective Rule:</strong>
            <p style={{ margin: 'var(--space-2) 0 0', color: 'var(--color-text-primary)', fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
              All intelligence gathered originates strictly from third-party public repositories, Certificate Transparency append-only logs, and authoritative DNS over HTTPS (DoH) queries. The target's infrastructure is never directly scanned or contacted.
            </p>
          </div>
        </section>

        {/* Section 2: Supported Target Identifiers */}
        <section className="card" style={{ padding: 'var(--space-8)' }}>
          <h2 style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <Globe size={24} style={{ color: 'var(--color-accent)' }} /> 2. Supported Target Types
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 'var(--space-4)' }}>
            {[
              { type: 'Domain Name', example: 'cloudflare.com', desc: 'Queries authoritative DoH, CT log SANs, and RDAP registration.' },
              { type: 'IP Address', example: '1.1.1.1 / 2606:4700::', desc: 'Resolves RIR allocation blocks, ASN route, and geographic region.' },
              { type: 'Email Address', example: 'analyst@domain.com', desc: 'Validates MX routes, SPF/DMARC policies, and breach exposure.' },
              { type: 'Username', example: 'octocat', desc: 'Queries public code repositories and platform metadata.' },
              { type: 'Organization', example: 'Cloudflare, Inc.', desc: 'Correlates public GitHub organizations and associated domains.' },
              { type: 'URL', example: 'https://site.org/page', desc: 'Executes a single bounded HTTP metadata and header check.' },
            ].map(t => (
              <div key={t.type} style={{ padding: 'var(--space-4)', borderRadius: 'var(--radius)', background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)' }}>
                <div style={{ fontWeight: 700, color: 'var(--color-dark)', fontSize: 'var(--text-sm)' }}>{t.type}</div>
                <code style={{ fontSize: '11px', display: 'inline-block', margin: '4px 0', color: 'var(--color-accent-dark)' }}>{t.example}</code>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', margin: 0 }}>{t.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Section 3: Collector Engines */}
        <section className="card" style={{ padding: 'var(--space-8)' }}>
          <h2 style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <Database size={24} style={{ color: 'var(--color-accent)' }} /> 3. Data Providers & Engines
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div style={{ borderBottom: '1px solid var(--color-border)', paddingBottom: 'var(--space-3)' }}>
              <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, margin: 0 }}>Cloudflare DNS over HTTPS (1.1.1.1)</h3>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', marginTop: '4px' }}>
                Queries RFC 8484 compliant DoH endpoints for A, AAAA, MX, NS, TXT, CNAME, SOA, and CAA records. Provides sub-millisecond edge response without leaking local DNS telemetry.
              </p>
            </div>

            <div style={{ borderBottom: '1px solid var(--color-border)', paddingBottom: 'var(--space-3)' }}>
              <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, margin: 0 }}>Certificate Transparency Logs (crt.sh)</h3>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', marginTop: '4px' }}>
                Monitors append-only cryptographic CT logs to discover all historical and active TLS certificates issued for a domain, revealing internal subdomains and staging environments.
              </p>
            </div>

            <div style={{ borderBottom: '1px solid var(--color-border)', paddingBottom: 'var(--space-3)' }}>
              <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, margin: 0 }}>RDAP & Regional Internet Registries</h3>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', marginTop: '4px' }}>
                Queries ICANN and RIR (ARIN, RIPE, APNIC, LACNIC, AFRINIC) endpoints for standardized JSON registration records, respecting GDPR privacy redactions.
              </p>
            </div>

            <div>
              <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, margin: 0 }}>Workers AI Synthesizer</h3>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', marginTop: '4px' }}>
                Executes @cf/meta/llama-3-8b-instruct directly on Cloudflare GPU workers. Generates risk assessments and summaries constrained strictly to discovered findings.
              </p>
            </div>
          </div>
        </section>

        {/* Section 4: API Quick Reference */}
        <section className="card" style={{ padding: 'var(--space-8)' }}>
          <h2 style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <Cpu size={24} style={{ color: 'var(--color-accent)' }} /> 4. REST API Endpoints
          </h2>
          <div style={{ overflowX: 'auto' }}>
            <table className="table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><code>POST</code></td>
                  <td><code>/api/v1/investigations</code></td>
                  <td>Initialize a new OSINT investigation</td>
                </tr>
                <tr>
                  <td><code>GET</code></td>
                  <td><code>/api/v1/investigations/:id</code></td>
                  <td>Fetch investigation status and execution counts</td>
                </tr>
                <tr>
                  <td><code>GET</code></td>
                  <td><code>/api/v1/investigations/:id/findings</code></td>
                  <td>List paginated findings with filter support</td>
                </tr>
                <tr>
                  <td><code>GET</code></td>
                  <td><code>/api/v1/investigations/:id/graph</code></td>
                  <td>Generate entity relationship node/edge graph</td>
                </tr>
                <tr>
                  <td><code>POST</code></td>
                  <td><code>/api/v1/investigations/:id/analyze</code></td>
                  <td>Trigger Workers AI evidence-grounded synthesis</td>
                </tr>
                <tr>
                  <td><code>GET</code></td>
                  <td><code>/api/v1/classify?q=...</code></td>
                  <td>Auto-classify target identifier format and type</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}
