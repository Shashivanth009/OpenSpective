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

  const format = (body.format ?? 'json') as 'json' | 'csv' | 'html';
  if (!['json', 'csv', 'html'].includes(format)) {
    return c.json({ error: 'Supported formats: json, csv, html.', code: 'VALIDATION_ERROR' }, 400);
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
    // HTML report
    const findingsHtml = findings.results.map(f => `
      <tr>
        <td>${f['category']}</td>
        <td>${f['type']}</td>
        <td style="word-break:break-all">${String(f['value']).replace(/</g, '&lt;').replace(/>/g, '&gt;')}</td>
        <td>${f['confidence']}</td>
        <td>${f['severity']}</td>
        <td>${f['source_name']}</td>
        <td>${f['first_seen']}</td>
      </tr>`).join('');

    const collectorsHtml = executions.results.map(e => `
      <tr>
        <td>${e['collector_name']}</td>
        <td>${e['status']}</td>
        <td>${e['findings_count']}</td>
        <td>${e['completed_at'] ?? 'N/A'}</td>
        <td>${e['error_message'] ?? ''}</td>
      </tr>`).join('');

    content = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenSpective Report — ${String(investigation['target']).replace(/</g, '&lt;')}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 1200px; margin: 0 auto; padding: 2rem; color: #40513B; background: #EDF1D6; }
  h1 { color: #40513B; } h2 { color: #609966; border-bottom: 2px solid #9DC08B; padding-bottom: .5rem; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th, td { text-align: left; padding: .5rem; border: 1px solid #9DC08B; font-size: 0.85rem; }
  th { background: #609966; color: white; }
  tr:nth-child(even) { background: rgba(157,192,139,0.15); }
  .meta { background: white; padding: 1rem; border-radius: 8px; margin-bottom: 2rem; border: 1px solid #9DC08B; }
  .disclaimer { background: #fff3cd; padding: 1rem; border-radius: 8px; border: 1px solid #ffc107; margin: 1rem 0; }
  .ai { background: white; padding: 1rem; border-radius: 8px; border: 1px solid #9DC08B; margin: 1rem 0; white-space: pre-wrap; }
  @media print { body { background: white; } }
</style>
</head>
<body>
<h1>🔍 OpenSpective Investigation Report</h1>
<div class="meta">
  <strong>Target:</strong> ${String(investigation['target']).replace(/</g, '&lt;')} (${investigation['target_type']})<br>
  <strong>Status:</strong> ${investigation['status']}<br>
  <strong>Started:</strong> ${investigation['started_at']}<br>
  <strong>Completed:</strong> ${investigation['completed_at'] ?? 'N/A'}<br>
  <strong>Generated:</strong> ${nowIso()}<br>
  <strong>Methodology:</strong> Passive open-source intelligence collection using publicly available data sources.
</div>
<div class="disclaimer">
  ⚠️ <strong>Disclaimer:</strong> This report contains information from public sources collected at the time of investigation. Findings may have changed. All conclusions should be independently verified. OpenSpective is for authorized research only.
</div>

<h2>Collectors</h2>
<table><thead><tr><th>Collector</th><th>Status</th><th>Findings</th><th>Completed</th><th>Notes</th></tr></thead>
<tbody>${collectorsHtml || '<tr><td colspan="5">No collectors ran.</td></tr>'}</tbody></table>

<h2>Findings (${findings.results.length})</h2>
<table><thead><tr><th>Category</th><th>Type</th><th>Value</th><th>Confidence</th><th>Severity</th><th>Source</th><th>Collected</th></tr></thead>
<tbody>${findingsHtml || '<tr><td colspan="7">No findings.</td></tr>'}</tbody></table>

${aiAnalysis ? `<h2>AI Analysis <small>(model: ${aiAnalysis['model']})</small></h2>
<div class="ai">${String(aiAnalysis['technical_details']).replace(/</g, '&lt;')}</div>
<p><em>AI analysis is generated from actual findings only. It may contain errors. Verify conclusions independently.</em></p>` : ''}

<footer style="margin-top:3rem;color:#609966;font-size:0.8rem;">
  Generated by OpenSpective v0.1 — open-intelligence.dev — For authorized research only.
</footer>
</body></html>`;
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
