import { FileText } from 'lucide-react';

export default function TermsPage() {
  return (
    <div style={{ maxWidth: '900px', margin: '0 auto', padding: 'var(--space-8) var(--space-8)' }}>
      <div style={{ marginBottom: 'var(--space-8)', borderBottom: '1px solid var(--color-border)', paddingBottom: 'var(--space-6)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', color: 'var(--color-accent)', fontWeight: 700, fontSize: 'var(--text-sm)' }}>
          <FileText size={18} /> TERMS OF SERVICE & ACCEPTABLE USE
        </div>
        <h1 style={{ fontSize: 'var(--text-4xl)', fontWeight: 800, color: 'var(--color-dark)', letterSpacing: '-0.03em', marginTop: 'var(--space-2)' }}>
          OpenSpective Terms of Service
        </h1>
        <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--text-base)', marginTop: 'var(--space-2)' }}>
          Effective October 2026. Please read carefully before utilizing the platform.
        </p>
      </div>

      <div className="card" style={{ padding: 'var(--space-8)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)', lineHeight: 1.7, color: 'var(--color-text-primary)' }}>
          <section>
            <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
              1. Acceptance of Terms
            </h2>
            <p>
              By accessing OpenSpective or conducting an inquiry, you agree to comply with and be bound by these Terms of Service. If you do not agree, you must discontinue use immediately.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
              2. Acceptable Use Policy (AUP)
            </h2>
            <p>
              OpenSpective is provided exclusively for legitimate cybersecurity research, perimeter asset inventory, fraud prevention, and academic intelligence analysis. You agree NOT to:
            </p>
            <ul style={{ paddingLeft: 'var(--space-6)', marginTop: 'var(--space-2)' }}>
              <li>Use findings to stalk, harass, dox, or intimidate any individual.</li>
              <li>Attempt to conduct unauthorized access or exploitation using correlated findings.</li>
              <li>Exceed stated rate limits or attempt denial-of-service attacks against platform APIs or upstream data providers.</li>
              <li>Use the platform in violation of any applicable local, national, or international laws.</li>
            </ul>
          </section>

          <section>
            <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
              3. Nature of Telemetry & Disclaimer of Accuracy
            </h2>
            <p>
              All intelligence, DNS records, registration data, and threat vendor scores are retrieved passively from third-party public repositories. OpenSpective makes no warranty regarding the completeness, accuracy, or real-time currency of third-party public records.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
              4. Limitation of Liability
            </h2>
            <p>
              To the fullest extent permitted by law, OpenSpective and its maintainers shall not be liable for any indirect, incidental, punitive, or consequential damages resulting from your use of or reliance upon platform findings.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
              5. Governing Law & Modification
            </h2>
            <p>
              We reserve the right to modify these terms at any time. Continued use of OpenSpective following notice of updates constitutes your acceptance of the revised terms.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
