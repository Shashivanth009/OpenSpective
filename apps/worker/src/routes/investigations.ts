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
import type { TargetType, CreateInvestigationRequest, InvestigationGraph, GraphNode, GraphEdge } from '@openspective/shared';

type Variables = { user: AuthUser | null };

const GUEST_INVESTIGATION_LIMIT_PER_IP = 3; // per day
const USER_INVESTIGATION_LIMIT_PER_MONTH = 50;

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

  // Rate limiting for guests
  if (!user) {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const guestCount = await c.env.DB
      .prepare(`SELECT COUNT(*) as count FROM guest_investigations WHERE ip_address = ? AND created_at > ?`)
      .bind(ip, oneDayAgo)
      .first<{ count: number }>();

    if ((guestCount?.count ?? 0) >= GUEST_INVESTIGATION_LIMIT_PER_IP) {
      return c.json({
        error: `Guest investigations are limited to ${GUEST_INVESTIGATION_LIMIT_PER_IP} per day. Please sign up for a free account.`,
        code: 'QUOTA_EXCEEDED',
      }, 429);
    }
  }

  // Rate limiting for authenticated users
  if (user) {
    const period = new Date().toISOString().slice(0, 7);
    const usage = await c.env.DB
      .prepare(`SELECT investigation_count FROM usage_records WHERE user_id = ? AND period = ?`)
      .bind(user.id, period)
      .first<{ investigation_count: number }>();

    if ((usage?.investigation_count ?? 0) >= USER_INVESTIGATION_LIMIT_PER_MONTH) {
      return c.json({
        error: `Monthly investigation limit (${USER_INVESTIGATION_LIMIT_PER_MONTH}) reached. Limit resets at the start of next month.`,
        code: 'QUOTA_EXCEEDED',
      }, 429);
    }
  }

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
    ? modules.filter(m => available.some(a => a.name === m))
    : available.map(a => a.name);

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
  const user = c.get('user');
  const page = Math.max(1, parseInt(c.req.query('page') ?? '1', 10));
  const pageSize = Math.min(50, Math.max(1, parseInt(c.req.query('pageSize') ?? '20', 10)));
  const offset = (page - 1) * pageSize;

  if (!user) {
    // Guests can't list investigations
    return c.json({ data: [], total: 0, page, pageSize, hasMore: false });
  }

  const [items, total] = await Promise.all([
    c.env.DB
      .prepare(`SELECT * FROM investigations WHERE user_id = ? ORDER BY started_at DESC LIMIT ? OFFSET ?`)
      .bind(user.id, pageSize, offset)
      .all(),
    c.env.DB
      .prepare(`SELECT COUNT(*) as count FROM investigations WHERE user_id = ?`)
      .bind(user.id)
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

  // Ownership check: investigation must belong to this user, or be a guest investigation
  if (investigation['user_id'] !== null && investigation['user_id'] !== user?.id) {
    return c.json({ error: 'Access denied.', code: 'FORBIDDEN' }, 403);
  }

  // Fetch collector executions
  const executions = await c.env.DB
    .prepare(`SELECT * FROM collector_executions WHERE investigation_id = ? ORDER BY started_at ASC`)
    .bind(id)
    .all();

  return c.json({ investigation, executions: executions.results });
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
  if (investigation['user_id'] !== null && investigation['user_id'] !== user?.id) {
    return c.json({ error: 'Access denied.', code: 'FORBIDDEN' }, 403);
  }

  if (!['queued', 'running'].includes(investigation['status'] as string)) {
    return c.json({ error: 'Investigation is not running.', code: 'INVALID_STATE' }, 409);
  }

  await c.env.DB
    .prepare(`UPDATE investigations SET status = 'cancelled', completed_at = ? WHERE id = ?`)
    .bind(nowIso(), id)
    .run();

  return c.json({ message: 'Cancellation requested. Active collectors may complete their current operation.' });
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
  if (investigation['user_id'] !== null && investigation['user_id'] !== user?.id) {
    return c.json({ error: 'Access denied.', code: 'FORBIDDEN' }, 403);
  }

  const category = c.req.query('category');
  const page = Math.max(1, parseInt(c.req.query('page') ?? '1', 10));
  const pageSize = Math.min(100, Math.max(1, parseInt(c.req.query('pageSize') ?? '50', 10)));
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
  if (investigation['user_id'] !== null && investigation['user_id'] !== user?.id) {
    return c.json({ error: 'Access denied.', code: 'FORBIDDEN' }, 403);
  }

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

// ---- POST /investigations/:id/analyze ----
investigationsRouter.post('/:id/analyze', async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  if (!user) {
    return c.json({ error: 'Authentication required for AI analysis.', code: 'UNAUTHORIZED' }, 401);
  }

  const investigation = await c.env.DB
    .prepare(`SELECT * FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);
  if (investigation['user_id'] !== user.id) {
    return c.json({ error: 'Access denied.', code: 'FORBIDDEN' }, 403);
  }

  if (!['completed', 'partial'].includes(investigation['status'] as string)) {
    return c.json({ error: 'Investigation must be completed before analysis.', code: 'INVALID_STATE' }, 409);
  }

  // Check if AI binding is available
  if (!c.env.AI) {
    return c.json({ error: 'AI analysis is not available in the current configuration.', code: 'UNAVAILABLE' }, 503);
  }

  // Check usage quota
  const period = new Date().toISOString().slice(0, 7);
  const usage = await c.env.DB
    .prepare(`SELECT ai_inference_count FROM usage_records WHERE user_id = ? AND period = ?`)
    .bind(user.id, period)
    .first<{ ai_inference_count: number }>();

  const AI_INFERENCE_LIMIT = 20;
  if ((usage?.ai_inference_count ?? 0) >= AI_INFERENCE_LIMIT) {
    return c.json({
      error: `AI inference limit (${AI_INFERENCE_LIMIT}/month) reached.`,
      code: 'QUOTA_EXCEEDED',
    }, 429);
  }

  // Fetch findings (cap at 50 to control token usage)
  const findings = await c.env.DB
    .prepare(`SELECT category, subcategory, type, value, confidence, severity, source_name, notes FROM findings WHERE investigation_id = ? LIMIT 50`)
    .bind(id)
    .all();

  // Build compact evidence summary for AI
  const evidenceSummary = findings.results.map(f =>
    `[${f['category']}/${f['type']}] ${f['value']}${f['notes'] ? ` (${f['notes']})` : ''} — source: ${f['source_name']}, confidence: ${f['confidence']}`
  ).join('\n');

  const prompt = `You are an OSINT analyst reviewing findings for an investigation.

Target: ${investigation['normalized_target']} (type: ${investigation['target_type']})

Findings:
${evidenceSummary || 'No findings collected.'}

Provide:
1. A brief executive summary (2-3 sentences) of what was found.
2. Key technical findings and their significance.
3. Notable gaps or limitations in the data.
4. 2-3 actionable defensive recommendations (if applicable).
5. A confidence assessment.

Rules:
- Only reference the actual findings listed above.
- Do not invent data, CVEs, or claims not supported by the findings.
- Clearly distinguish observed facts from inferences.
- If findings are sparse, say so honestly.
- Keep the response factual and professional.`;

  try {
    const aiResponse = await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
      prompt,
      max_tokens: 800,
    });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const responseText = (aiResponse as any)?.response ?? (aiResponse as any)?.result?.response ?? '';

    if (!responseText) {
      return c.json({ error: 'AI returned an empty response.', code: 'AI_ERROR' }, 500);
    }

    // Parse structured sections (simple heuristic)
    const lines = responseText.split('\n');
    const summary = lines.slice(0, 3).join(' ').trim();

    const analysisId = generateId('ai');
    await c.env.DB
      .prepare(
        `INSERT INTO ai_analyses (id, investigation_id, model, summary, technical_details, recommendations, gaps, evidence_refs, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        analysisId,
        id,
        '@cf/meta/llama-3.1-8b-instruct',
        summary,
        responseText,
        JSON.stringify([]),
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

    // Increment AI usage
    await c.env.DB
      .prepare(
        `INSERT INTO usage_records (id, user_id, period, ai_inference_count) VALUES (?, ?, ?, 1)
         ON CONFLICT(user_id, period) DO UPDATE SET ai_inference_count = ai_inference_count + 1`
      )
      .bind(generateId('ur'), user.id, period)
      .run();

    return c.json({
      analysisId,
      summary,
      fullResponse: responseText,
      evidenceCount: findings.results.length,
      model: '@cf/meta/llama-3.1-8b-instruct',
      generatedAt: nowIso(),
      disclaimer: 'AI analysis is generated from actual investigation findings only. It may contain errors or omissions. Always verify conclusions independently.',
    });
  } catch (err) {
    return c.json({
      error: 'AI analysis failed. Core investigation features remain available.',
      code: 'AI_ERROR',
      details: err instanceof Error ? err.message : 'Unknown error',
    }, 500);
  }
});
