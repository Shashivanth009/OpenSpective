// Dependency re-exports to avoid repeated imports
// nanoid for Cloudflare Workers — use crypto.randomUUID as fallback
export function nanoid(size = 21): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  return Array.from(bytes, b => chars[b % chars.length]!).join('');
}
