// OpenSpective — Reports Routes
// POST /api/v1/investigations/:id/reports
// GET  /api/v1/reports/:id

import { Hono } from 'hono';
import type { Env } from '../env.ts';
import type { AuthUser } from '../middleware/auth.ts';
import { authMiddleware, requireAuth } from '../middleware/auth.ts';
import { generateId, nowIso } from '../utils.ts';

type Variables = { user: AuthUser | null };

export const reportsRouter = new Hono<{ Bindings: Env; Variables: Variables }>();
reportsRouter.use('*', authMiddleware);

// Generate and store a report (Free & open access)
reportsRouter.post('/investigations/:id/reports', async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  let body: { format?: string } = {};
  try { body = await c.req.json(); } catch { /* defaults */ }

  const format = (body.format ?? 'json') as 'json' | 'csv' | 'html' | 'pdf';
  if (!['json', 'csv', 'html', 'pdf'].includes(format)) {
    return c.json({ error: 'Supported formats: json, csv, html, pdf.', code: 'VALIDATION_ERROR' }, 400);
  }

  const investigation = await c.env.DB
    .prepare(`SELECT * FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);

  const findings = await c.env.DB
    .prepare(`SELECT * FROM findings WHERE investigation_id = ?`)
    .bind(id)
    .all();

  const executions = await c.env.DB
    .prepare(`SELECT * FROM collector_executions WHERE investigation_id = ?`)
    .bind(id)
    .all();

  const aiAnalysis = investigation['ai_analysis_id']
    ? await c.env.DB
        .prepare(`SELECT * FROM ai_analyses WHERE id = ?`)
        .bind(investigation['ai_analysis_id'])
        .first()
    : null;

  const reportData = {
    meta: {
      title: 'OpenSpective Investigation Report',
      generatedAt: nowIso(),
      target: investigation['target'],
      targetType: investigation['target_type'],
      normalizedTarget: investigation['normalized_target'],
      status: investigation['status'],
      startedAt: investigation['started_at'],
      completedAt: investigation['completed_at'],
      methodology: 'Passive open-source intelligence collection using publicly available data sources.',
      disclaimer: 'This report contains information collected from public sources at the time of investigation. Findings may have changed. All conclusions should be independently verified.',
    },
    investigation,
    collectors: executions.results,
    findings: findings.results,
    aiAnalysis: aiAnalysis ?? null,
    limitations: executions.results
      .filter(e => e['status'] !== 'completed')
      .map(e => `${e['collector_name']}: ${e['status']}${e['error_message'] ? ` — ${e['error_message']}` : ''}`),
  };

  let content: string;
  let contentType: string;

  if (format === 'json') {
    content = JSON.stringify(reportData, null, 2);
    contentType = 'application/json';
  } else if (format === 'csv') {
    const headers = ['id', 'category', 'type', 'value', 'confidence', 'severity', 'source_name', 'source_url', 'first_seen', 'notes'];
    const rows = findings.results.map(f =>
      headers.map(h => {
        const val = String(f[h] ?? '');
        return val.includes(',') || val.includes('"') || val.includes('\n')
          ? `"${val.replace(/"/g, '""')}"`
          : val;
      }).join(',')
    );
    content = [headers.join(','), ...rows].join('\n');
    contentType = 'text/csv';
  } else {
    // HTML / PDF-printable report
    const escapeHtml = (s: any) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    const findingsHtml = findings.results.map(f => `
      <tr>
        <td><span class="badge badge-${escapeHtml(f['severity'] || 'info')}">${escapeHtml(String(f['severity'] || 'info').toUpperCase())}</span></td>
        <td><strong>${escapeHtml(f['category'])}</strong><div class="sub">${escapeHtml(f['type'])}</div></td>
        <td class="code-val">${escapeHtml(f['value'])}</td>
        <td><span class="conf conf-${escapeHtml(f['confidence'] || 'medium')}">${escapeHtml(String(f['confidence'] || 'medium').toUpperCase())}</span></td>
        <td>${escapeHtml(f['source_name'] || 'OpenSpective')}</td>
        <td class="notes">${escapeHtml(f['notes'] || '—')}</td>
      </tr>`).join('');

    const collectorsHtml = executions.results.map(e => `
      <tr>
        <td><strong>${escapeHtml(e['collector_name'])}</strong></td>
        <td><span class="status status-${escapeHtml(e['status'])}">${escapeHtml(String(e['status']).toUpperCase())}</span></td>
        <td><strong>${e['findings_count']}</strong> artifacts</td>
        <td>${e['completed_at'] ?? 'In progress'}</td>
        <td class="sub">${escapeHtml(e['error_message'] || 'Clean execution')}</td>
      </tr>`).join('');

    const aiText = aiAnalysis ? String(aiAnalysis['technical_details'] || aiAnalysis['summary'] || '') : '';
    const aiSectionsHtml = aiText ? aiText
      .split(/(?=(?:^|\n)(?:#{1,3}\s+|\d+\.\s+[*#A-Za-z]))/g)
      .map(sec => {
        const lines = sec.trim().split('\n');
        const title = (lines[0] || '').replace(/^[#*\s\d.]+\s*/, '').replace(/[*_#:]+/g, '').trim();
        const body = lines.slice(1).map(l => {
          const clean = l.trim();
          if (!clean) return '';
          if (clean.startsWith('- ') || clean.startsWith('* ')) {
            return `<li>${escapeHtml(clean.replace(/^[-*]\s+/, ''))}</li>`;
          }
          return `<p style="margin: 4px 0;">${escapeHtml(clean)}</p>`;
        }).join('');
        return `
          <div class="ai-section">
            <h4>🛡️ ${escapeHtml(title)}</h4>
            <div class="ai-body">${body}</div>
          </div>
        `;
      }).join('') : '';

    content = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenSpective Intelligence Dossier — ${escapeHtml(investigation['target'])}</title>
<style>
  :root {
    --bg: #090d16;
    --surface: #0f172a;
    --surface-card: rgba(15, 23, 42, 0.75);
    --border: rgba(255, 255, 255, 0.08);
    --border-accent: rgba(16, 185, 129, 0.3);
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --accent: #10b981;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 2.5rem;
    line-height: 1.5;
  }
  .header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding-bottom: 2rem;
    border-bottom: 1.5px solid var(--border-accent);
    margin-bottom: 2rem;
  }
  .brand { display: flex; align-items: center; gap: 14px; }
  .brand-icon {
    width: 44px;
    height: 44px;
    border-radius: 12px;
    background: linear-gradient(135deg, #10b981, #059669);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
    color: white;
  }
  .title { font-size: 1.85rem; font-weight: 800; letter-spacing: -0.02em; }
  .subtitle { color: var(--text-muted); font-size: 0.9rem; margin-top: 2px; }
  .classification-badge {
    display: inline-block;
    padding: 4px 10px;
    background: rgba(16, 185, 129, 0.15);
    border: 1px solid var(--accent);
    border-radius: 6px;
    color: var(--accent);
    font-size: 0.75rem;
    font-weight: 800;
    text-transform: uppercase;
  }
  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1.25rem;
    margin-bottom: 2.5rem;
  }
  .metric-card {
    background: var(--surface-card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 1.35rem;
  }
  .metric-label { font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; margin-bottom: 6px; }
  .metric-value { font-size: 1.85rem; font-weight: 800; color: var(--text); }
  .section-title {
    font-size: 1.35rem;
    font-weight: 800;
    margin: 2.5rem 0 1.2rem;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .section-title::before {
    content: '';
    display: inline-block;
    width: 4px;
    height: 20px;
    background: var(--accent);
    border-radius: 2px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    background: var(--surface-card);
    border-radius: 14px;
    overflow: hidden;
    border: 1px solid var(--border);
    margin-bottom: 2.5rem;
    font-size: 0.875rem;
  }
  th {
    background: #0b1120;
    text-align: left;
    padding: 14px 18px;
    color: var(--text-muted);
    font-weight: 700;
    text-transform: uppercase;
    font-size: 0.72rem;
    border-bottom: 1px solid var(--border);
  }
  td { padding: 13px 18px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 0.72rem; font-weight: 800; text-transform: uppercase; }
  .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.35); }
  .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.35); }
  .badge-medium { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.35); }
  .badge-low, .badge-info { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.35); }
  .status { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 0.72rem; font-weight: 700; }
  .status-completed { color: #34d399; background: rgba(16, 185, 129, 0.15); }
  .code-val { font-family: ui-monospace, monospace; word-break: break-all; color: #38bdf8; font-weight: 600; font-size: 0.85rem; }
  .sub { font-size: 0.75rem; color: var(--text-muted); margin-top: 3px; }
  .notes { color: #cbd5e1; font-size: 0.8rem; }
  .conf { font-weight: 700; font-size: 0.75rem; text-transform: uppercase; }
  .conf-high { color: #34d399; }
  .conf-medium { color: #facc15; }
  .conf-low { color: #94a3b8; }
  .ai-container {
    background: var(--surface-card);
    border: 1px solid var(--border-accent);
    border-radius: 14px;
    padding: 1.75rem;
    margin-bottom: 2.5rem;
  }
  .ai-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
    gap: 1.25rem;
  }
  .ai-section {
    background: rgba(11, 17, 32, 0.7);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.25rem;
  }
  .ai-section h4 {
    color: var(--accent);
    font-size: 0.95rem;
    font-weight: 800;
    margin-bottom: 0.75rem;
  }
  .ai-body { font-size: 0.85rem; color: #cbd5e1; line-height: 1.6; }
  .footer {
    text-align: center;
    color: var(--text-muted);
    font-size: 0.8rem;
    margin-top: 4rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
  }
  @media print {
    body { background: white !important; color: black !important; padding: 1rem; }
    .metric-card, table, .ai-container, .ai-section { background: white !important; border: 1px solid #ccc !important; color: black !important; }
    th { background: #f1f5f9 !important; color: black !important; }
    td { border-bottom: 1px solid #eee !important; }
    .code-val { color: #0369a1 !important; }
  }
</style>
</head>
<body>
  <div class="header">
    <div class="brand">
      <div class="brand-icon">⚡</div>
      <div>
        <div class="title">OpenSpective OSINT Intelligence Dossier</div>
        <div class="subtitle">Multi-Engine Passive Reconnaissance & Threat Attack Surface Mapped</div>
      </div>
    </div>
    <div style="text-align: right;">
      <div class="classification-badge">TLP:CLEAR / OPEN INTELLIGENCE</div>
      <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 6px;">Generated: ${nowIso()}</div>
    </div>
  </div>

  <div class="metrics-grid">
    <div class="metric-card">
      <div class="metric-label">Target Entity</div>
      <div class="metric-value" style="font-size: 1.35rem; word-break: break-all;">${escapeHtml(investigation['target'])}</div>
      <div class="sub" style="text-transform: capitalize; color: var(--accent); font-weight: 700;">${escapeHtml(investigation['target_type'])} Target</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Investigation Status</div>
      <div class="metric-value" style="color: #34d399; text-transform: uppercase; font-size: 1.45rem;">
        ${escapeHtml(investigation['status'])}
      </div>
      <div class="sub">${executions.results.length} Specialized OSINT Engines</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Discovered Findings</div>
      <div class="metric-value" style="color: #38bdf8;">${findings.results.length}</div>
      <div class="sub">Verified Telemetry Artifacts</div>
    </div>
  </div>

  ${aiSectionsHtml ? `
    <div class="section-title">AI Executive Threat Synthesis & Vulnerability Analysis</div>
    <div class="ai-container">
      <div class="ai-grid">${aiSectionsHtml}</div>
    </div>
  ` : ''}

  <div class="section-title">Discovered Intelligence Findings (${findings.results.length})</div>
  <table>
    <thead>
      <tr>
        <th style="width: 100px;">Severity</th>
        <th style="width: 170px;">Category & Type</th>
        <th>Discovered Value / Observed Artifact</th>
        <th style="width: 110px;">Confidence</th>
        <th style="width: 160px;">Source Engine</th>
        <th>Context / Notes</th>
      </tr>
    </thead>
    <tbody>
      ${findingsHtml || '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">No findings recorded.</td></tr>'}
    </tbody>
  </table>

  <div class="section-title">OSINT Collector Engines & Execution Logs (${executions.results.length})</div>
  <table>
    <thead>
      <tr>
        <th>Engine Collector</th>
        <th>Status</th>
        <th>Findings Produced</th>
        <th>Completed At</th>
        <th>Diagnostic Notes</th>
      </tr>
    </thead>
    <tbody>
      ${collectorsHtml || '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">No collector records.</td></tr>'}
    </tbody>
  </table>

  <div class="footer">
    OpenSpective Intelligence Framework — Passive OSINT Reconnaissance Platform — Strictly For Authorized Security Research.
  </div>
</body>
</html>`;
    contentType = 'text/html';
  }

  // Store in R2 if available
  let storageKey: string | null = null;
  if (c.env.REPORTS) {
    try {
      const ownerId = user?.id ?? 'public';
      storageKey = `reports/${ownerId}/${id}/${format}-${Date.now()}.${format}`;
      await c.env.REPORTS.put(storageKey, content, {
        httpMetadata: { contentType },
        customMetadata: { userId: ownerId, investigationId: id, format },
      });
    } catch {
      // R2 unavailable — serve directly without storing
    }
  }

  // Record report in DB
  const reportId = generateId('rpt');
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  await c.env.DB
    .prepare(`INSERT INTO reports (id, investigation_id, user_id, format, storage_key, created_at, expires_at, size_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(reportId, id, user?.id ?? null, format, storageKey, nowIso(), expiresAt, content.length)
    .run();

  // Return the report content directly
  return new Response(content, {
    status: 200,
    headers: {
      'Content-Type': contentType,
      'Content-Disposition': `attachment; filename="openspective-${id}.${format}"`,
      'X-Report-Id': reportId,
    },
  });
});

// GET report by ID (R2-backed)
reportsRouter.get('/reports/:reportId', async (c) => {
  const { reportId } = c.req.param();

  const report = await c.env.DB
    .prepare(`SELECT * FROM reports WHERE id = ?`)
    .bind(reportId)
    .first();

  if (!report) return c.json({ error: 'Report not found.', code: 'NOT_FOUND' }, 404);

  if (report['storage_key'] && c.env.REPORTS) {
    const obj = await c.env.REPORTS.get(report['storage_key'] as string);
    if (obj) {
      const contentType = report['format'] === 'json' ? 'application/json'
        : report['format'] === 'csv' ? 'text/csv' : 'text/html';
      return new Response(obj.body, {
        headers: { 'Content-Type': contentType },
      });
    }
  }

  return c.json({ error: 'Report content not available.', code: 'NOT_FOUND' }, 404);
});
