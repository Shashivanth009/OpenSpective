# OpenSpective Architecture Specification

## 1. System Overview

OpenSpective is an enterprise-grade, privacy-conscious OSINT and passive reconnaissance platform. The application is structured as an npm monorepo with strict separation of concerns across presentation, orchestration, persistence, and intelligence collection.

```
                      ┌────────────────────────────────────────┐
                      │          React 19 + Vite SPA           │
                      │  (Hosted on Vercel / Cloudflare Pages) │
                      └───────────────────┬────────────────────┘
                                          │ HTTPS / JSON API
                                          ▼
                      ┌────────────────────────────────────────┐
                      │        Cloudflare Worker (Hono)        │
                      │  - SSRF Protection & Target Classifier │
                      │  - JWT Auth & Sliding-Window Limiter   │
                      │  - Non-blocking Async Orchestrator     │
                      └───────┬───────────┬────────────┬───────┘
                              │           │            │
            ┌─────────────────┴──┐   ┌────┴─────┐   ┌──┴────────────────┐
            ▼                    ▼   ▼          ▼   ▼                   ▼
    ┌───────────────┐     ┌─────────────┐   ┌───────────────┐   ┌───────────────┐
    │ Cloudflare D1 │     │ Cloudflare  │   │  Cloudflare   │   │   Passive     │
    │   (SQLite)    │     │ R2 Storage  │   │  Workers AI   │   │  Recon Feeds  │
    │               │     │   Dossiers  │   │  (LLaMA 3.1)  │   │ (DoH, RDAP,   │
    │               │     │             │   │               │   │  crt.sh, etc) │
    └───────────────┘     └─────────────┘   └───────────────┘   └───────────────┘
```

---

## 2. Monorepo Organization

- **`apps/web`**: Single Page Application built on React 19, TypeScript, Vite, React Router 6, and ReactFlow. Contains zero hardcoded secrets or backend business logic.
- **`apps/worker`**: Cloudflare Worker running Hono. Exposes `/api/v1/*` endpoints, executes investigation pipelines via `c.executionCtx.waitUntil(...)`, enforces rate limiting, and interfaces with D1, R2, and Workers AI.
- **`packages/shared`**: Universal data contracts, TypeScript interfaces, target type schemas, and system constants shared verbatim between backend and frontend.
- **`migrations`**: Declarative SQL migration files applied directly to Cloudflare D1.

---

## 3. Core Data Flow & Investigation Lifecycle

1. **Submission & Deterministic Classification:**
   - User inputs an arbitrary string into the universal search interface.
   - The client performs client-side pattern matching and queries `POST /api/v1/classify` for server-side verification.
   - `classifier.ts` deterministically determines whether the target is an email, domain, URL, IPv4, IPv6, private IP, username, phone, or organization without calling non-deterministic AI models.
   - If classified as a private or loopback IP (e.g. `10.0.0.0/8`, `127.0.0.1`), external scanning is blocked immediately.

2. **Investigation Scheduling:**
   - Client sends `POST /api/v1/investigations`.
   - The Worker validates ownership/guest quotas, inserts a `queued` row into the D1 `investigations` table, and returns a `201 Created` payload with the investigation ID.
   - The worker activates the execution pipeline via `c.executionCtx.waitUntil(runInvestigation(ctx))`, allowing the HTTP response to complete in `<50ms` while collectors execute in the background.

3. **Collector Execution & Normalization:**
   - `orchestrator.ts` retrieves the registered collectors applicable to the target type.
   - For each collector (e.g., DNS, RDAP, crt.sh, IPInfo), a `collector_executions` record is recorded.
   - Collectors execute concurrently using bounded `Promise.allSettled` queries with defensive timeouts.
   - Every raw finding is normalized into the `Finding` schema:
     - `category`, `subcategory`, `type`, `value`
     - `confidence` (`low`, `medium`, `high`, `verified`)
     - `severity` (`info`, `low`, `medium`, `high`, `critical`)
     - `source_name`, `source_url`, `first_seen`, `last_seen`
     - `raw_data` (complete JSON payload preserved for auditability)

4. **Entity Correlation & Graph Generation:**
   - Collectors yield structured `Relationship` items connecting entities (e.g. `Domain -> IP`, `Domain -> Subdomain`, `Email -> Domain`, `Org -> Repository`).
   - Relationships are persisted to the D1 `relationships` table.
   - The client polls `GET /api/v1/investigations/:id` until status is `completed` or `partial`, then queries `/graph` to render the interactive ReactFlow canvas.

5. **AI Synthesis (Optional):**
   - When requested via `POST /api/v1/investigations/:id/analyze`, the Worker selects up to 50 compact findings, builds an evidence-grounded prompt, and runs `@cf/meta/llama-3.1-8b-instruct` via Cloudflare Workers AI.
   - The analysis is stored in `ai_analyses` and linked to the investigation.
