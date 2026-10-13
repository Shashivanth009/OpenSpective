// OpenSpective — Authentication Routes
// POST /api/v1/auth/signup
// POST /api/v1/auth/login
// POST /api/v1/auth/logout
// GET  /api/v1/auth/me

import { Hono } from 'hono';
import type { Env } from '../env.ts';
import { hashPassword, verifyPassword, generateId, nowIso } from '../utils.ts';
import { createSession, deleteSession, authMiddleware, requireAuth, SESSION_COOKIE } from '../middleware/auth.ts';
import { authRateLimit } from '../middleware/ratelimit.ts';

type Variables = { user: { id: string; email: string; displayName: string | null } | null };

export const authRouter = new Hono<{ Bindings: Env; Variables: Variables }>();

// POST /signup
authRouter.post('/signup', authRateLimit, async (c) => {
  let body: { email?: string; password?: string; displayName?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body.', code: 'BAD_REQUEST' }, 400);
  }

  const { email, password, displayName } = body;

  // Validate
  if (!email || !password) {
    return c.json({ error: 'Email and password are required.', code: 'VALIDATION_ERROR' }, 400);
  }

  const emailLower = email.trim().toLowerCase();
  if (!/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(emailLower)) {
    return c.json({ error: 'Invalid email address.', code: 'VALIDATION_ERROR' }, 400);
  }

  if (password.length < 8) {
    return c.json({ error: 'Password must be at least 8 characters.', code: 'VALIDATION_ERROR' }, 400);
  }
  if (password.length > 128) {
    return c.json({ error: 'Password too long.', code: 'VALIDATION_ERROR' }, 400);
  }

  // Check existing user
  const existing = await c.env.DB
    .prepare(`SELECT id FROM users WHERE email = ?`)
    .bind(emailLower)
    .first();

  if (existing) {
    return c.json({ error: 'An account with this email already exists.', code: 'CONFLICT' }, 409);
  }

  // Create user
  const userId = generateId('u');
  const passwordHash = await hashPassword(password);

  await c.env.DB
    .prepare(`INSERT INTO users (id, email, password_hash, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`)
    .bind(userId, emailLower, passwordHash, displayName?.trim() ?? null, nowIso(), nowIso())
    .run();

  // Create session
  const userAgent = c.req.header('User-Agent') ?? null;
  const ip = c.req.header('CF-Connecting-IP') ?? null;
  const token = await createSession(c.env.DB, userId, userAgent, ip);

  // Initialize usage record
  const period = new Date().toISOString().slice(0, 7);
  await c.env.DB
    .prepare(`INSERT OR IGNORE INTO usage_records (id, user_id, period) VALUES (?, ?, ?)`)
    .bind(generateId('ur'), userId, period)
    .run();

  const response = c.json({
    user: { id: userId, email: emailLower, displayName: displayName?.trim() ?? null },
    token,
  }, 201);

  return response;
});

// POST /login
authRouter.post('/login', authRateLimit, async (c) => {
  let body: { email?: string; password?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body.', code: 'BAD_REQUEST' }, 400);
  }

  const { email, password } = body;
  if (!email || !password) {
    return c.json({ error: 'Email and password are required.', code: 'VALIDATION_ERROR' }, 400);
  }

  const emailLower = email.trim().toLowerCase();
  const user = await c.env.DB
    .prepare(`SELECT id, email, password_hash, display_name, is_active FROM users WHERE email = ?`)
    .bind(emailLower)
    .first();

  if (!user || !(user['is_active'] as number)) {
    // Constant-time response to avoid user enumeration
    await hashPassword('dummy_timing_safe_check');
    return c.json({ error: 'Invalid email or password.', code: 'UNAUTHORIZED' }, 401);
  }

  const valid = await verifyPassword(password, user['password_hash'] as string);
  if (!valid) {
    return c.json({ error: 'Invalid email or password.', code: 'UNAUTHORIZED' }, 401);
  }

  const userAgent = c.req.header('User-Agent') ?? null;
  const ip = c.req.header('CF-Connecting-IP') ?? null;
  const token = await createSession(c.env.DB, user['id'] as string, userAgent, ip);

  return c.json({
    user: {
      id: user['id'] as string,
      email: user['email'] as string,
      displayName: user['display_name'] as string | null,
    },
    token,
  });
});

// POST /logout
authRouter.post('/logout', authMiddleware, async (c) => {
  const authHeader = c.req.header('Authorization');
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const cookieToken = c.req.header('Cookie')
    ?.split(';')
    .map(s => s.trim().split('='))
    .find(([k]) => k === SESSION_COOKIE)?.[1] ?? null;

  const activeToken = token ?? cookieToken;
  if (activeToken) {
    await deleteSession(c.env.DB, activeToken);
  }

  return c.json({ message: 'Signed out successfully.' });
});

// GET /me
authRouter.get('/me', authMiddleware, requireAuth, async (c) => {
  const user = c.get('user')!;
  const period = new Date().toISOString().slice(0, 7);

  const usage = await c.env.DB
    .prepare(`SELECT * FROM usage_records WHERE user_id = ? AND period = ?`)
    .bind(user.id, period)
    .first();

  return c.json({
    user,
    usage: usage ?? {
      investigation_count: 0,
      collector_call_count: 0,
      ai_inference_count: 0,
      report_count: 0,
      storage_bytes: 0,
    },
  });
});
