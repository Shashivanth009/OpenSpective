// OpenSpective — Rate Limiting Middleware
// Simple in-memory rate limiter using Cloudflare's built-in cache API.
// For production, consider Cloudflare Rate Limiting rules.

import { createMiddleware } from 'hono/factory';
import type { Env } from '../env.ts';

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  keyPrefix: string;
}

type HonoContext = {
  Variables: Record<string, unknown>;
  Bindings: Env;
};

function getClientIp(req: Request): string {
  return (
    req.headers.get('CF-Connecting-IP') ??
    req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
    'unknown'
  );
}

// Simple cache-based rate limiter using KV-style cache storage
export function rateLimit(config: RateLimitConfig) {
  return createMiddleware<HonoContext>(async (c, next) => {
    const ip = getClientIp(c.req.raw);
    const cacheKey = `${config.keyPrefix}:${ip}`;
    const now = Date.now();
    const windowStart = now - config.windowMs;

    // Use CF Cache API for transient rate limit storage
    try {
      const cache = await caches.open('rate_limits');
      const cacheUrl = `https://rate-limit.internal/${cacheKey}`;
      const cached = await cache.match(cacheUrl);

      let count = 0;
      if (cached) {
        const data = await cached.json() as { count: number; windowStart: number };
        if (data.windowStart > windowStart) {
          count = data.count;
        }
      }

      if (count >= config.maxRequests) {
        return c.json(
          { error: 'Too many requests. Please try again later.', code: 'RATE_LIMITED' },
          429
        );
      }

      // Update count
      const newCount = count + 1;
      const response = new Response(JSON.stringify({ count: newCount, windowStart: now }), {
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': `max-age=${Math.ceil(config.windowMs / 1000)}`,
        },
      });
      c.executionCtx?.waitUntil(cache.put(cacheUrl, response));
    } catch {
      // Cache unavailable — allow request to proceed
    }

    await next();
  });
}

// Pre-configured limiters
export const investigationRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 5,
  keyPrefix: 'inv',
});

export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 10,
  keyPrefix: 'auth',
});

export const apiRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 60,
  keyPrefix: 'api',
});
