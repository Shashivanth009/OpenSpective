// OpenSpective — Account & Usage Routes
// GET /api/v1/account/usage
// GET /api/v1/classify (helper for frontend)

import { Hono } from 'hono';
import type { Env } from '../env.ts';
import type { AuthUser } from '../middleware/auth.ts';
import { authMiddleware, requireAuth } from '../middleware/auth.ts';
import { classifyTarget } from '../classifier.ts';
import { getAllCollectors } from '../collectors/registry.ts';
import type { AccountUsage } from '@openspective/shared';
import { FREE_TIER_LIMITS } from '@openspective/shared';

type Variables = { user: AuthUser | null };

export const accountRouter = new Hono<{ Bindings: Env; Variables: Variables }>();
accountRouter.use('*', authMiddleware);

// GET /account/usage
accountRouter.get('/usage', async (c) => {
  const user = c.get('user');
  const period = new Date().toISOString().slice(0, 7);

  let used = {
    investigations: 0,
    collectorCalls: 0,
    aiInferences: 0,
    reports: 0,
    storageBytes: 0,
  };

  if (user) {
    const usage = await c.env.DB
      .prepare(`SELECT * FROM usage_records WHERE user_id = ? AND period = ?`)
      .bind(user.id, period)
      .first();

    used = {
      investigations: (usage?.['investigation_count'] as number) ?? 0,
      collectorCalls: (usage?.['collector_call_count'] as number) ?? 0,
      aiInferences: (usage?.['ai_inference_count'] as number) ?? 0,
      reports: (usage?.['report_count'] as number) ?? 0,
      storageBytes: (usage?.['storage_bytes'] as number) ?? 0,
    };
  }

  const limits = { ...FREE_TIER_LIMITS };
  const accountUsage: AccountUsage = {
    period,
    limits: {
      investigations: limits.investigations,
      collectorCalls: limits.collectorCalls,
      aiInferences: limits.aiInferences,
      reports: limits.reports,
      storageBytes: limits.storageBytes,
    },
    used,
    remaining: {
      investigations: Math.max(0, limits.investigations - used.investigations),
      collectorCalls: Math.max(0, limits.collectorCalls - used.collectorCalls),
      aiInferences: Math.max(0, limits.aiInferences - used.aiInferences),
      reports: Math.max(0, limits.reports - used.reports),
      storageBytes: Math.max(0, limits.storageBytes - used.storageBytes),
    },
  };

  return c.json(accountUsage);
});

// GET /classify — classify a target input (no auth required, no persistence)
export const classifyRouter = new Hono<{ Bindings: Env; Variables: Variables }>();
classifyRouter.get('/', async (c) => {
  const input = c.req.query('q');
  if (!input) {
    return c.json({ error: 'q parameter required.', code: 'VALIDATION_ERROR' }, 400);
  }
  const result = classifyTarget(input);
  return c.json(result);
});

// GET /modules — list all modules and their status
export const modulesRouter = new Hono<{ Bindings: Env; Variables: Variables }>();
modulesRouter.get('/', async (c) => {
  const modules = getAllCollectors(c.env);
  return c.json({ modules });
});
