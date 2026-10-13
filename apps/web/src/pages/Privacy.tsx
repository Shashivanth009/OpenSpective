import { Shield } from 'lucide-react';

export default function PrivacyPage() {
  return (
    <div style={{ maxWidth: '900px', margin: '0 auto', padding: 'var(--space-8) var(--space-8)' }}>
      <div style={{ marginBottom: 'var(--space-8)', borderBottom: '1px solid var(--color-border)', paddingBottom: 'var(--space-6)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', color: 'var(--color-accent)', fontWeight: 700, fontSize: 'var(--text-sm)' }}>
          <Shield size={18} /> PRIVACY & DATA GOVERNANCE
        </div>
        <h1 style={{ fontSize: 'var(--text-4xl)', fontWeight: 800, color: 'var(--color-dark)', letterSpacing: '-0.03em', marginTop: 'var(--space-2)' }}>
          OpenSpective Privacy Policy
        </h1>
        <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--text-base)', marginTop: 'var(--space-2)' }}>
          Last updated: October 2026. Committed to lawful, ethical, and transparent public intelligence gathering.
        </p>
      </div>

      <div className="card" style={{ padding: 'var(--space-8)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)', lineHeight: 1.7, color: 'var(--color-text-primary)' }}>
          <section>
            <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
              1. Our Stance on Privacy
            </h2>
            <p>
              OpenSpective is designed from the ground up as a <strong>passive reconnaissance platform</strong>. We do not engage in unauthorized network intrusion, active port exploitation, credential stuffing, or surveillance. Our mission is to assist security researchers, compliance officers, and system administrators in assessing their public digital footprint using strictly open, publicly available sources.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
              2. Data We Process
            </h2>
            <p>When you initiate an investigation, our edge infrastructure processes:</p>
            <ul style={{ paddingLeft: 'var(--space-6)', marginTop: 'var(--space-2)' }}>
              <li><strong>Target Identifiers:</strong> Domains, IP addresses, emails, or usernames submitted by the user.</li>
              <li><strong>Public Telemetry:</strong> DNS records queried from DoH resolvers, Certificate Transparency logs published in public CT monitors, and standardized RDAP registry outputs.</li>
              <li><strong>Account Credentials:</strong> If authenticated, email address and cryptographic password hashes (PBKDF2/Argon2) are securely stored in Cloudflare D1. We never store raw passwords.</li>
            </ul>
          </section>

          <section>
            <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
              3. No Direct Target Scanning
            </h2>
            <p>
              We do not probe target servers or fire TCP packets at private infrastructure. We strictly interface with intermediary public registries (such as ICANN RDAP servers, Regional Internet Registries, and public certificate logs like crt.sh).
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
              4. Data Retention & Deletion
            </h2>
            <p>
              Investigation findings are associated with your user ID. You retain full ownership of your investigation data. You may download all findings as JSON/CSV or delete your investigation history at any time.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
              5. Contact
            </h2>
            <p>
              For questions regarding privacy, GDPR data subject requests, or security inquiries, contact <code>privacy@openspective.io</code>.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
