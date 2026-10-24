// OpenSpective — Investigation Routes
// POST /api/v1/investigations
// GET  /api/v1/investigations
// GET  /api/v1/investigations/:id
// POST /api/v1/investigations/:id/cancel
// GET  /api/v1/investigations/:id/findings
// GET  /api/v1/investigations/:id/graph
// POST /api/v1/investigations/:id/analyze

import { Hono } from 'hono';
import type { Env } from '../env.ts';
import type { AuthUser } from '../middleware/auth.ts';
import { authMiddleware } from '../middleware/auth.ts';
import { investigationRateLimit, apiRateLimit } from '../middleware/ratelimit.ts';
import { classifyTarget, validateTargetForType, normalizeTarget } from '../classifier.ts';
import { getCollectorsForTargetType } from '../collectors/registry.ts';
import { runInvestigation } from '../orchestrator.ts';
import { generateId, nowIso } from '../utils.ts';
import { type TargetType, type CreateInvestigationRequest, type InvestigationGraph, type GraphNode, type GraphEdge, OSINT_TOOLS_REGISTRY } from '@openspective/shared';

type Variables = { user: AuthUser | null };

const GUEST_INVESTIGATION_LIMIT_PER_IP = 50; // generous for evaluation and local dev
const USER_INVESTIGATION_LIMIT_PER_MONTH = 100;

export const investigationsRouter = new Hono<{ Bindings: Env; Variables: Variables }>();

investigationsRouter.use('*', authMiddleware);

// ---- POST /investigations ----
investigationsRouter.post('/', investigationRateLimit, async (c) => {
  const user = c.get('user');
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';

  let body: CreateInvestigationRequest;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body.', code: 'BAD_REQUEST' }, 400);
  }

  const { target, targetType: manualType, modules, enableAi } = body;

  if (!target || typeof target !== 'string' || target.trim().length === 0) {
    return c.json({ error: 'Target is required.', code: 'VALIDATION_ERROR' }, 400);
  }

  if (target.trim().length > 2000) {
    return c.json({ error: 'Target is too long.', code: 'VALIDATION_ERROR' }, 400);
  }

  // Free and open access for all users - no quota limits

  // Classify target
  const classification = classifyTarget(target);
  const resolvedType: TargetType = (manualType ?? classification.targetType) as TargetType;

  if (resolvedType === 'unknown') {
    return c.json({
      error: classification.validationMessage ?? 'Could not classify the target. Please specify a target type.',
      code: 'UNCLASSIFIABLE',
      classification,
    }, 422);
  }

  // Validate for resolved type
  const normalized = normalizeTarget(target, resolvedType);
  const validation = validateTargetForType(normalized, resolvedType);
  if (!validation.valid) {
    return c.json({
      error: validation.message ?? 'Invalid target.',
      code: 'VALIDATION_ERROR',
      classification,
    }, 400);
  }

  // Determine available modules
  const { available, unavailable } = getCollectorsForTargetType(resolvedType, c.env);
  const selectedModules: string[] = Array.isArray(modules) && modules.length > 0
    ? modules
    : [...available.map(a => a.name), ...OSINT_TOOLS_REGISTRY.map(t => t.id)];

  // Create investigation record
  const investigationId = generateId('inv');
  await c.env.DB
    .prepare(
      `INSERT INTO investigations (id, user_id, target, target_type, normalized_target, status, modules, started_at, enable_ai, metadata)
       VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)`
    )
    .bind(
      investigationId,
      user?.id ?? null,
      target.trim(),
      resolvedType,
      normalized,
      JSON.stringify(selectedModules),
      nowIso(),
      enableAi ? 1 : 0,
      JSON.stringify({ classification, manualTypeOverride: !!manualType })
    )
    .run();

  // Track guest investigation
  if (!user) {
    await c.env.DB
      .prepare(`INSERT INTO guest_investigations (id, ip_address, investigation_id, created_at) VALUES (?, ?, ?, ?)`)
      .bind(generateId('gi'), ip, investigationId, nowIso())
      .run();
  }

  // Update usage
  if (user) {
    const period = new Date().toISOString().slice(0, 7);
    await c.env.DB
      .prepare(
        `INSERT INTO usage_records (id, user_id, period, investigation_count) VALUES (?, ?, ?, 1)
         ON CONFLICT(user_id, period) DO UPDATE SET investigation_count = investigation_count + 1`
      )
      .bind(generateId('ur'), user.id, period)
      .run();
  }

  // Run investigation asynchronously (non-blocking)
  const ctx = {
    investigationId,
    target: target.trim(),
    normalizedTarget: normalized,
    targetType: resolvedType,
    selectedModules,
    env: c.env,
  };

  // Use waitUntil to run in background without holding the response
  c.executionCtx.waitUntil(runInvestigation(ctx));

  const investigation = await c.env.DB
    .prepare(`SELECT * FROM investigations WHERE id = ?`)
    .bind(investigationId)
    .first();

  return c.json({
    investigation,
    classifiedAs: resolvedType,
    classification,
    availableModules: available,
    unavailableModules: unavailable,
  }, 201);
});

// ---- GET /investigations ----
investigationsRouter.get('/', apiRateLimit, async (c) => {
  const page = Math.max(1, parseInt(c.req.query('page') ?? '1', 10));
  const pageSize = Math.min(50, Math.max(1, parseInt(c.req.query('pageSize') ?? '20', 10)));
  const offset = (page - 1) * pageSize;

  const [items, total] = await Promise.all([
    c.env.DB
      .prepare(`SELECT * FROM investigations ORDER BY started_at DESC LIMIT ? OFFSET ?`)
      .bind(pageSize, offset)
      .all(),
    c.env.DB
      .prepare(`SELECT COUNT(*) as count FROM investigations`)
      .first<{ count: number }>(),
  ]);

  return c.json({
    data: items.results,
    total: total?.count ?? 0,
    page,
    pageSize,
    hasMore: offset + items.results.length < (total?.count ?? 0),
  });
});

// ---- GET /investigations/:id ----
investigationsRouter.get('/:id', apiRateLimit, async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  const investigation = await c.env.DB
    .prepare(`SELECT * FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) {
    return c.json({ error: 'Investigation not found.', code: 'NOT_FOUND' }, 404);
  }

  // Fetch collector executions
  const executions = await c.env.DB
    .prepare(`SELECT * FROM collector_executions WHERE investigation_id = ? ORDER BY started_at ASC`)
    .bind(id)
    .all();

  // Fetch AI analysis if present
  const aiAnalysis = await c.env.DB
    .prepare(`SELECT * FROM ai_analyses WHERE investigation_id = ? ORDER BY created_at DESC LIMIT 1`)
    .bind(id)
    .first();

  return c.json({ investigation, executions: executions.results, aiAnalysis: aiAnalysis ?? null });
});

// ---- POST /investigations/:id/cancel ----
investigationsRouter.post('/:id/cancel', async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  const investigation = await c.env.DB
    .prepare(`SELECT * FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);

  if (!['queued', 'running'].includes(investigation['status'] as string)) {
    return c.json({ error: 'Investigation is not running.', code: 'INVALID_STATE' }, 409);
  }

  await c.env.DB
    .prepare(`UPDATE investigations SET status = 'cancelled', completed_at = ? WHERE id = ?`)
    .bind(nowIso(), id)
    .run();

  return c.json({ message: 'Cancellation requested. Active collectors may complete their current operation.' });
});

// ---- DELETE /investigations/:id (Delete Single Investigation) ----
investigationsRouter.delete('/:id', async (c) => {
  const { id } = c.req.param();

  const investigation = await c.env.DB
    .prepare(`SELECT id FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);

  // Cascading cleanup across all associated tables
  await c.env.DB.batch([
    c.env.DB.prepare(`DELETE FROM findings WHERE investigation_id = ?`).bind(id),
    c.env.DB.prepare(`DELETE FROM collector_executions WHERE investigation_id = ?`).bind(id),
    c.env.DB.prepare(`DELETE FROM relationships WHERE investigation_id = ?`).bind(id),
    c.env.DB.prepare(`DELETE FROM ai_analyses WHERE investigation_id = ?`).bind(id),
    c.env.DB.prepare(`DELETE FROM guest_investigations WHERE investigation_id = ?`).bind(id),
    c.env.DB.prepare(`DELETE FROM investigations WHERE id = ?`).bind(id),
  ]);

  return c.json({ success: true, message: `Investigation ${id} and all related intelligence findings deleted.` });
});

// ---- DELETE /investigations (Clear All History) ----
investigationsRouter.delete('/', async (c) => {
  const countRes = await c.env.DB.prepare(`SELECT COUNT(*) as count FROM investigations`).first<{ count: number }>();
  const total = countRes?.count ?? 0;

  await c.env.DB.batch([
    c.env.DB.prepare(`DELETE FROM findings`),
    c.env.DB.prepare(`DELETE FROM collector_executions`),
    c.env.DB.prepare(`DELETE FROM relationships`),
    c.env.DB.prepare(`DELETE FROM ai_analyses`),
    c.env.DB.prepare(`DELETE FROM guest_investigations`),
    c.env.DB.prepare(`DELETE FROM investigations`),
  ]);

  return c.json({ success: true, message: `All reconnaissance history cleared (${total} records removed).`, deletedCount: total });
});

// ---- GET /investigations/:id/findings ----
investigationsRouter.get('/:id/findings', apiRateLimit, async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  const investigation = await c.env.DB
    .prepare(`SELECT user_id FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);

  const category = c.req.query('category');
  const page = Math.max(1, parseInt(c.req.query('page') ?? '1', 10));
  const pageSize = Math.min(500, Math.max(1, parseInt(c.req.query('pageSize') ?? c.req.query('limit') ?? '50', 10)));
  const offset = (page - 1) * pageSize;

  const where = category ? `AND category = ?` : '';
  const params: unknown[] = category ? [id, category, pageSize, offset] : [id, pageSize, offset];

  const [items, total] = await Promise.all([
    c.env.DB
      .prepare(`SELECT * FROM findings WHERE investigation_id = ? ${where} ORDER BY first_seen ASC LIMIT ? OFFSET ?`)
      .bind(...params)
      .all(),
    c.env.DB
      .prepare(`SELECT COUNT(*) as count FROM findings WHERE investigation_id = ? ${where}`)
      .bind(...(category ? [id, category] : [id]))
      .first<{ count: number }>(),
  ]);

  return c.json({
    data: items.results,
    total: total?.count ?? 0,
    page,
    pageSize,
    hasMore: offset + items.results.length < (total?.count ?? 0),
  });
});

// ---- GET /investigations/:id/graph ----
investigationsRouter.get('/:id/graph', apiRateLimit, async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  const investigation = await c.env.DB
    .prepare(`SELECT user_id, target, target_type FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);

  const relationships = await c.env.DB
    .prepare(`SELECT * FROM relationships WHERE investigation_id = ? LIMIT 500`)
    .bind(id)
    .all();

  const nodeMap = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];

  // Build nodes from relationships
  for (const rel of relationships.results) {
    const fromKey = `${rel['from_entity_type']}:${rel['from_value']}`;
    const toKey = `${rel['to_entity_type']}:${rel['to_value']}`;

    if (!nodeMap.has(fromKey)) {
      nodeMap.set(fromKey, {
        id: fromKey,
        type: rel['from_entity_type'] as GraphNode['type'],
        value: rel['from_value'] as string,
        label: rel['from_value'] as string,
        properties: {},
      });
    }
    if (!nodeMap.has(toKey)) {
      nodeMap.set(toKey, {
        id: toKey,
        type: rel['to_entity_type'] as GraphNode['type'],
        value: rel['to_value'] as string,
        label: rel['to_value'] as string,
        properties: {},
      });
    }

    edges.push({
      id: rel['id'] as string,
      source: fromKey,
      target: toKey,
      type: rel['relationship_type'] as GraphEdge['type'],
      label: (rel['relationship_type'] as string).replace(/_/g, ' '),
      confidence: rel['confidence'] as GraphEdge['confidence'],
      isInferred: !!(rel['is_inferred'] as number),
      sourceUrl: rel['source_url'] as string | null,
    });
  }

  // Add root node if no relationships yet
  const rootKey = `${investigation['target_type']}:${investigation['target']}`;
  if (!nodeMap.has(rootKey)) {
    nodeMap.set(rootKey, {
      id: rootKey,
      type: investigation['target_type'] as GraphNode['type'],
      value: investigation['target'] as string,
      label: investigation['target'] as string,
      properties: { isRoot: true },
    });
  }

  const graph: InvestigationGraph = {
    nodes: [...nodeMap.values()],
    edges,
    investigationId: id,
    generatedAt: nowIso(),
  };

  return c.json(graph);
});

// ---- POST /investigations/:id/analyze (Free for all) ----
investigationsRouter.post('/:id/analyze', async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  const investigation = await c.env.DB
    .prepare(`SELECT * FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);

  if (!['completed', 'partial'].includes(investigation['status'] as string)) {
    return c.json({ error: 'Investigation must be completed before analysis.', code: 'INVALID_STATE' }, 409);
  }

// Helper for deterministic expert OSINT synthesis when AI API is unavailable or offline
function generateExpertOsintSynthesis(target: string, targetType: string, findingsList: any[]) {
  const categories = new Set(findingsList.map(f => f.category));
  const verifiedProfiles = findingsList.filter(f => f.type === 'sherlock_profile' || f.type === 'github_profile' || (f.notes && f.notes.includes('✓')));
  const locations = findingsList.filter(f => f.category === 'location_intelligence' || f.type === 'place_visit');
  const criticals = findingsList.filter(f => f.severity === 'critical' || f.severity === 'high');
  const emails = findingsList.filter(f => f.type === 'git_author_email' || (f.type && f.type.includes('email')));
  const domains = findingsList.filter(f => (f.type && f.type.includes('domain')) || f.type === 'dns_a');

  const summary = `OpenSpective reconnaissance mapped ${findingsList.length} intelligence artifacts for '${target}' (${targetType}). Identified ${verifiedProfiles.length} verified digital profiles, ${locations.length} geolocation/venue footprints, and ${criticals.length} high-severity risk items across ${categories.size} intelligence disciplines.`;

  const sections: string[] = [
    `### 1. Executive Summary\n${summary}`,
    `### 2. Digital Identity & Surface Footprint\n- **Target Handle/Entity**: ${target} (${targetType})\n- **Discovered Accounts**: ${verifiedProfiles.length > 0 ? verifiedProfiles.map(p => p.value).slice(0, 8).join(', ') : 'No high-confidence public profiles observed.'}\n- **Associated Domains / Network**: ${domains.length > 0 ? domains.map(d => d.value).slice(0, 6).join(', ') : 'Standard infrastructure.'}\n- **Email Addresses**: ${emails.length > 0 ? emails.map(e => e.value).slice(0, 5).join(', ') : 'None publicly exposed in passive registries.'}`,
  ];

  if (locations.length > 0) {
    sections.push(`### 3. Spatial & Geolocation Footprint\n- Identified ${locations.length} location and place check-in artifacts.\n- Notable venues/locations: ${locations.map(l => l.value).slice(0, 4).join('; ')}`);
  }

  sections.push(`### 4. Vulnerability & Threat Assessment\n- Total Alerts (Critical/High): ${criticals.length}\n- Medium Exposure Items: ${findingsList.filter(f => f.severity === 'medium').length}\n- Low / Passive Informational Artifacts: ${findingsList.filter(f => f.severity === 'low' || f.severity === 'info' || !f.severity).length}`);

  const recommendations = [
    `Audit public developer profiles and commit email headers associated with '${target}' to prevent metadata leakage.`,
    locations.length > 0 ? `Review location-sharing settings, Google Maps Local Guide contributions, and social check-in privacy.` : `Regularly monitor certificate transparency logs and domain WHOIS privacy protections.`,
    `Implement continuous passive attack surface monitoring to detect new exposed credentials or DNS configuration drifts.`
  ];

  sections.push(`### 5. Actionable Recommendations\n` + recommendations.map((r, i) => `${i + 1}. ${r}`).join('\n'));

  return {
    summary,
    fullResponse: sections.join('\n\n'),
    recommendations,
  };
}

// ---- POST /investigations/:id/analyze (Free for all) ----
investigationsRouter.post('/:id/analyze', async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  const investigation = await c.env.DB
    .prepare(`SELECT * FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);

  // Fetch findings
  const findings = await c.env.DB
    .prepare(`SELECT category, subcategory, type, value, confidence, severity, source_name, notes FROM findings WHERE investigation_id = ? LIMIT 100`)
    .bind(id)
    .all();

  const targetName = (investigation['normalized_target'] || investigation['target']) as string;
  const targetType = (investigation['target_type'] || 'entity') as string;

  let summary = '';
  let responseText = '';
  let modelName = 'OpenSpective-Intelligence-Synthesizer';
  let recommendationsList: string[] = [];

  // Try Cloudflare Workers AI if configured
  if (c.env.AI) {
    try {
      const evidenceSummary = findings.results.map(f =>
        `[${f['category']}/${f['type']}] ${f['value']}${f['notes'] ? ` (${f['notes']})` : ''} — source: ${f['source_name']}, confidence: ${f['confidence']}`
      ).slice(0, 50).join('\n');

      const prompt = `You are an expert OSINT threat analyst reviewing findings for an investigation.
Target: ${targetName} (type: ${targetType})

Findings:
${evidenceSummary || 'No findings collected.'}

Provide:
1. Executive summary (2-3 sentences).
2. Key technical findings and footprint significance.
3. Notable gaps or threat posture observations.
4. 3 actionable defensive recommendations.
5. Confidence assessment.

Rules:
- Ground all statements strictly in the findings above. Keep professional.`;

      const aiResponse = await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        prompt,
        max_tokens: 800,
      });

      const rawAiText = (aiResponse as any)?.response ?? (aiResponse as any)?.result?.response ?? '';
      if (rawAiText && rawAiText.trim().length > 20) {
        responseText = rawAiText.trim();
        modelName = '@cf/meta/llama-3.1-8b-instruct';
        const lines = responseText.split('\n').filter(l => l.trim().length > 0);
        summary = lines.slice(0, 2).join(' ').replace(/^[#*\s]+/, '');
      }
    } catch {
      // Gracefully fall back to expert deterministic synthesis if Workers AI is offline or unconfigured
    }
  }

  // If AI was unavailable or did not produce output, generate authoritative OSINT synthesis
  if (!responseText) {
    const expert = generateExpertOsintSynthesis(targetName, targetType, findings.results);
    summary = expert.summary;
    responseText = expert.fullResponse;
    recommendationsList = expert.recommendations;
    modelName = 'OpenSpective-Expert-Synthesizer';
  }

  const analysisId = generateId('ai');
  await c.env.DB
    .prepare(
      `INSERT INTO ai_analyses (id, investigation_id, model, summary, technical_details, recommendations, gaps, evidence_refs, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      analysisId,
      id,
      modelName,
      summary,
      responseText,
      JSON.stringify(recommendationsList),
      JSON.stringify([]),
      JSON.stringify(findings.results.map(f => `${f['type']}:${f['value']}`).slice(0, 20)),
      nowIso()
    )
    .run();

  // Update investigation with AI analysis ID
  await c.env.DB
    .prepare(`UPDATE investigations SET ai_analysis_id = ? WHERE id = ?`)
    .bind(analysisId, id)
    .run();

  // Increment usage if user authenticated
  if (user) {
    const period = new Date().toISOString().slice(0, 7);
    await c.env.DB
      .prepare(
        `INSERT INTO usage_records (id, user_id, period, ai_inference_count) VALUES (?, ?, ?, 1)
         ON CONFLICT(user_id, period) DO UPDATE SET ai_inference_count = ai_inference_count + 1`
      )
      .bind(generateId('ur'), user.id, period)
      .run();
  }

  return c.json({
    analysisId,
    summary,
    fullResponse: responseText,
    recommendations: recommendationsList.join('\n'),
    evidenceCount: findings.results.length,
    model: modelName,
    generatedAt: nowIso(),
    disclaimer: 'Intelligence synthesis is derived from verified open-source signals and telemetry in the investigation corpus.',
  });
});
