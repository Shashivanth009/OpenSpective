// OpenSpective — Cloudflare Worker Entry Point
// Hono-based API with CORS, security headers, and all routes.

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import type { Env } from './env.ts';
import { authRouter } from './routes/auth.ts';
import { investigationsRouter } from './routes/investigations.ts';
import { reportsRouter } from './routes/reports.ts';
import { accountRouter, classifyRouter, modulesRouter } from './routes/account.ts';

const app = new Hono<{ Bindings: Env }>();

// ---- Security headers ----
app.use('*', secureHeaders({
  xFrameOptions: 'DENY',
  xContentTypeOptions: 'nosniff',
  referrerPolicy: 'strict-origin-when-cross-origin',
}));

// ---- CORS ----
app.use('/api/*', cors({
  origin: (origin, c) => {
    if (!origin) return '*';
    const frontendUrl = c.env.FRONTEND_URL ?? 'https://openspective.vercel.app';
    if (origin === frontendUrl) return origin;
    if (origin === 'http://localhost:5173' || origin === 'http://localhost:3000' || origin === 'http://127.0.0.1:5173' || origin === 'http://127.0.0.1:3000') return origin;
    // Allow vercel and cloudflare pages deployments
    if (/^https:\/\/([a-zA-Z0-9_-]+\.)*vercel\.app$/.test(origin) || /^https:\/\/([a-zA-Z0-9_-]+\.)*pages\.dev$/.test(origin)) {
      return origin;
    }
    return null;
  },
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  exposeHeaders: ['X-Report-Id'],
  maxAge: 3600,
  credentials: true,
}));

// ---- Health check ----
app.get('/api/v1/health', async (c) => {
  const services: Record<string, 'ok' | 'error' | 'unconfigured'> = {
    api: 'ok',
    database: 'unconfigured',
    r2: 'unconfigured',
    ai: 'unconfigured',
    virustotal: 'unconfigured',
    haveibeenpwned: 'unconfigured',
    github: 'ok', // works without token
    ipinfo: 'ok', // works without token
    dns: 'ok',
    rdap: 'ok',
    certificate_transparency: 'ok',
  };

  // Check D1
  try {
    await c.env.DB.prepare('SELECT 1').first();
    services['database'] = 'ok';
  } catch {
    services['database'] = 'error';
  }

  // Check optional services
  if (c.env.REPORTS) services['r2'] = 'ok';
  if (c.env.AI) services['ai'] = 'ok';
  if (c.env.VIRUSTOTAL_API_KEY) services['virustotal'] = 'ok';
  if (c.env.HAVE_I_BEEN_PWNED_API_KEY) services['haveibeenpwned'] = 'ok';
  if (c.env.GITHUB_TOKEN) services['github'] = 'ok';
  if (c.env.IPINFO_TOKEN) services['ipinfo'] = 'ok';

  const hasError = Object.values(services).includes('error');
  const status = hasError ? 'degraded' : 'ok';

  return c.json({
    status,
    version: c.env.APP_VERSION ?? '0.1.0',
    timestamp: new Date().toISOString(),
    environment: c.env.ENVIRONMENT ?? 'unknown',
    services,
  }, hasError ? 503 : 200);
});

// ---- Routes ----
app.route('/api/v1/auth', authRouter);
app.route('/api/v1/investigations', investigationsRouter);
app.route('/api/v1/account', accountRouter);
app.route('/api/v1/classify', classifyRouter);
app.route('/api/v1/modules', modulesRouter);
app.route('/api/v1', reportsRouter);

// ---- 404 handler ----
app.notFound((c) => {
  return c.json({ error: 'Endpoint not found.', code: 'NOT_FOUND' }, 404);
});

// ---- Error handler ----
app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.json({
    error: 'An internal error occurred.',
    code: 'INTERNAL_ERROR',
  }, 500);
});

export default app;
