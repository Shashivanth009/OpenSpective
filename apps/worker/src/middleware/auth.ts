// OpenSpective — Authentication Middleware & Helpers
// Session-based authentication using tokens stored in D1.

import { createMiddleware } from 'hono/factory';
import type { Env } from '../env.ts';
import { generateToken, sha256Hex, nowIso } from '../utils.ts';

export interface AuthUser {
  id: string;
  email: string;
  displayName: string | null;
}

type HonoContext = {
  Variables: {
    user: AuthUser | null;
  };
  Bindings: Env;
};

const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const SESSION_COOKIE = 'os_session';

// Extract token from Authorization header or cookie
function extractToken(req: Request): string | null {
  const auth = req.headers.get('Authorization');
  if (auth?.startsWith('Bearer ')) {
    return auth.slice(7).trim();
  }
  // Parse cookie header
  const cookieHeader = req.headers.get('Cookie');
  if (cookieHeader) {
    const cookies = Object.fromEntries(
      cookieHeader.split(';').map(c => {
        const [k, ...v] = c.trim().split('=');
        return [k!.trim(), v.join('=')];
      })
    );
    return cookies[SESSION_COOKIE] ?? null;
  }
  return null;
}

// Auth middleware — attaches user to context (or null for guests)
export const authMiddleware = createMiddleware<HonoContext>(async (c, next) => {
  const token = extractToken(c.req.raw);
  c.set('user', null);

  if (token) {
    try {
      const tokenHash = await sha256Hex(token);
      const session = await c.env.DB
        .prepare(
          `SELECT s.user_id, s.expires_at, u.email, u.display_name
           FROM sessions s
           JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ? AND u.is_active = 1`
        )
        .bind(tokenHash)
        .first();

      if (session && new Date(session['expires_at'] as string) > new Date()) {
        c.set('user', {
          id: session['user_id'] as string,
          email: session['email'] as string,
          displayName: session['display_name'] as string | null,
        });

        // Update last_used_at (non-blocking)
        c.env.DB
          .prepare(`UPDATE sessions SET last_used_at = ? WHERE token_hash = ?`)
          .bind(nowIso(), tokenHash)
          .run()
          .catch(() => {});
      }
    } catch {
      // Invalid token — treat as unauthenticated
    }
  }

  await next();
});

// Require authentication
export const requireAuth = createMiddleware<HonoContext>(async (c, next) => {
  const user = c.get('user');
  if (!user) {
    return c.json({ error: 'Authentication required.', code: 'UNAUTHORIZED' }, 401);
  }
  await next();
});

// Create a new session
export async function createSession(
  db: D1Database,
  userId: string,
  userAgent: string | null,
  ipAddress: string | null
): Promise<string> {
  const token = generateToken();
  const tokenHash = await sha256Hex(token);
  const id = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();

  await db
    .prepare(
      `INSERT INTO sessions (id, user_id, token_hash, expires_at, user_agent, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .bind(id, userId, tokenHash, expiresAt, userAgent, ipAddress)
    .run();

  return token;
}

// Delete a session by token
export async function deleteSession(db: D1Database, token: string): Promise<void> {
  const tokenHash = await sha256Hex(token);
  await db
    .prepare(`DELETE FROM sessions WHERE token_hash = ?`)
    .bind(tokenHash)
    .run();
}

// Clean up expired sessions
export async function cleanExpiredSessions(db: D1Database): Promise<void> {
  await db
    .prepare(`DELETE FROM sessions WHERE expires_at < ?`)
    .bind(nowIso())
    .run();
}

export { SESSION_COOKIE };
