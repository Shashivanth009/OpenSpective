# OpenSpective

> **Open Intelligence. Clearer Insights.**  
> AI-assisted open-source intelligence (OSINT), public-data investigation, and passive reconnaissance platform.

---

## 1. Product Identity & Vision

OpenSpective is a unified web platform engineered for security researchers, penetration testers, intelligence analysts, and compliance teams. It allows authorized users to investigate diverse target types—including **domains**, **IP addresses**, **URLs**, **email addresses**, **organizations**, **usernames**, and **phone numbers**—using exclusively legitimate, public, and non-intrusive data sources.

### Core Capabilities:
- **Deterministic Universal Target Classification:** Instant auto-detection of input type (IPv4, IPv6, private IP ranges, domains, URLs, RFC 5322 emails, E.164 phone numbers, usernames).
- **Passive Cybersecurity Reconnaissance:** Cloudflare DoH (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA), crt.sh Certificate Transparency logs, IANA RDAP registration/whois, and IPInfo geolocation/ASN.
- **Threat Intelligence & Reputation:** VirusTotal security engine verdicts and detections (when API key is provided).
- **Evidence-Backed Attribution & Findings Graph:** Every discovery records source attribution, timestamps, raw payloads, confidence scores, and relation links.
- **AI-Assisted Synthesis:** Cloudflare Workers AI integration (`@cf/meta/llama-3-8b-instruct`) for automated intelligence summaries and threat risk categorization.
- **Structured Report Generation:** Markdown and JSON intelligence dossier export.
- **Privacy & Compliance First:** Strictly passive reconnaissance; zero intrusive port scanning, zero active probing.

---

## 2. System Architecture

OpenSpective is built as a monorepo containing three workspaces:

```
OpenSpective/
├── apps/
│   ├── web/                    # React 19 + TypeScript + Vite Single-Page Application
│   │   ├── src/
│   │   │   ├── pages/          # Landing, Investigate, Detail, History, Settings, Docs, Terms, Privacy, Login, Signup
│   │   │   ├── components/     # Layout, Navigation, Modals, Evidence Badges
│   │   │   ├── api.ts          # Strongly typed client API layer with JWT auth
│   │   │   └── AuthContext.tsx # User session & token state management
│   │   └── package.json
│   └── worker/                 # Cloudflare Worker API backend (Hono + D1 + R2 + Workers AI)
│       ├── src/
│       │   ├── collectors/     # DNS, RDAP, Certificate Transparency, IPInfo, VirusTotal, GitHub
│       │   ├── middleware/     # JWT Auth, Sliding-Window IP/Account Rate Limiting, Security Headers
│       │   ├── routes/         # Auth, Investigations, Reports, Account telemetry
│       │   ├── classifier.ts   # Deterministic RFC-compliant target classification
│       │   ├── orchestrator.ts # Investigation pipeline execution and finding persistence
│       │   └── index.ts        # Hono application routing and CORS
│       ├── wrangler.toml       # Cloudflare Worker configuration & bindings
│       └── package.json
├── packages/
│   └── shared/                 # Shared TypeScript models, contracts, and constants
│       └── src/index.ts
├── migrations/                 # Cloudflare D1 SQL Schema Migrations
│   └── 0001_initial_schema.sql # Tables: users, investigations, collector_executions, findings, relationships, reports
└── package.json                # Root monorepo workspace scripts
```

---

## 3. Implemented Features & Verification Status

| Feature / Subsystem | Status | Verification Detail |
| :--- | :--- | :--- |
| **Universal Target Classifier** | Verified | Tested via 13 Vitest unit tests covering domain, IP, private IP, email, URL, phone, and username syntax. |
| **DNS Intelligence Collector** | Verified | Cloudflare 1.1.1.1 DoH DoH endpoint querying 8 record types with batching and error resiliency. |
| **RDAP / Whois Collector** | Verified | IANA bootstrap lookup for domains and IPs with GDPR redaction handling. |
| **Certificate Transparency** | Verified | crt.sh query with subdomain extraction and date parsing. |
| **IPInfo Geolocation & ASN** | Verified | Handles both unauthenticated public quota and token-authenticated lookups. |
| **VirusTotal Integration** | Verified | Gracefully detects key availability; extracts positives and detection tallies. |
| **GitHub OSINT Collector** | Verified | Queries public user/org metadata and repositories without credentials (60 req/hr). |
| **D1 Database Persistence** | Verified | Initial SQL schema with relational integrity and indexes on target, status, and dates. |
| **JWT Authentication & Auth Routes** | Verified | Sign-in, sign-up, session refresh, and guest mode support with bcrypt/PBKDF2 passwords. |
| **Frontend Web Application** | Verified | Modern, responsive UI with light/dark theme support, live polling, and full audit history. |
| **Full Workspace Typecheck** | Verified | `npm run typecheck` passes with zero errors across all 3 packages. |
| **Production Build Pipeline** | Verified | `npm run build` (Vite) and `npm run build:worker` (Wrangler dry-run) build cleanly. |

---

## 4. External APIs & Credentials

The system is operational out-of-the-box using public free tiers without mandatory API keys. Optional credentials unlock extended rate limits:

| Provider | Purpose | Optional / Required | Default Fallback |
| :--- | :--- | :--- | :--- |
| **Cloudflare DoH (1.1.1.1)** | DNS Record Lookups | Built-in | Unlimited public DoH |
| **IANA RDAP Bootstrap** | Domain & IP Registration | Built-in | Public RDAP servers |
| **crt.sh** | Certificate Transparency | Built-in | Public CT log search |
| **IPInfo.io** | IP Geolocation & ASN | Optional (`IPINFO_TOKEN`) | 50,000 req/month free tier |
| **VirusTotal** | Threat Intelligence Verdicts | Optional (`VIRUSTOTAL_API_KEY`) | Skipped gracefully if unset |
| **GitHub API** | Public Org / User Search | Optional (`GITHUB_TOKEN`) | 60 unauthenticated req/hr |
| **HaveIBeenPwned** | Breach Notification Lookups | Optional (`HAVE_I_BEEN_PWNED_API_KEY`) | Skipped gracefully if unset |

---

## 5. Local Development Quickstart

### Prerequisites
- Node.js >= 20.0.0
- npm >= 10.0.0

### Step 1: Install Dependencies
```bash
npm install
```

### Step 2: Configure Worker Local Secrets
Create `apps/worker/.dev.vars` from the example template:
```bash
cp apps/worker/.dev.vars.example apps/worker/.dev.vars
```
Update `JWT_SECRET` with any secure 32+ character random string.

### Step 3: Run Database Migrations Locally
```bash
npm run db:migrate:local
```

### Step 4: Run Tests & Typechecks
```bash
npm run typecheck
npm test
```

### Step 5: Start Local Development Servers
In two separate terminals:
```bash
# Terminal 1: Backend Cloudflare Worker API (http://localhost:8787)
npm run dev:worker

# Terminal 2: Frontend Vite Development Server (http://localhost:5173)
npm run dev
```

---

## 6. Deployment Guide

### Deploying the Backend (Cloudflare Workers)

1. **Log in to Cloudflare:**
   ```bash
   npx wrangler login
   ```
2. **Create the D1 Database:**
   ```bash
   npx wrangler d1 create openspective-db
   ```
   *Copy the generated `database_id` into `apps/worker/wrangler.toml` under `[[d1_databases]]`.*

3. **Apply Remote Migrations:**
   ```bash
   npm run db:migrate:remote
   ```

4. **Create R2 Bucket (for reports):**
   ```bash
   npx wrangler r2 bucket create openspective-reports
   ```

5. **Set Production Secrets:**
   ```bash
   npx wrangler secret put JWT_SECRET --config apps/worker/wrangler.toml
   npx wrangler secret put VIRUSTOTAL_API_KEY --config apps/worker/wrangler.toml
   npx wrangler secret put IPINFO_TOKEN --config apps/worker/wrangler.toml
   ```

6. **Deploy Worker:**
   ```bash
   npm run deploy:worker
   ```

### Deploying the Frontend (Cloudflare Pages or Vercel)

- **Vite Build Command:** `npm run build`
- **Output Directory:** `apps/web/dist`
- **Environment Variables:**
  - `VITE_API_URL`: Your deployed Worker URL (e.g. `https://openspective-worker.<subdomain>.workers.dev/api`)

---

## 7. Free-Tier Limits & Bottlenecks

- **Cloudflare Workers Free Tier:** 100,000 requests/day, 10ms CPU time per request. The async investigation queue model is engineered to keep CPU time minimal by delegating I/O waits.
- **crt.sh CT Log Availability:** crt.sh can intermittently throttle or return 504 Gateway Timeouts under high load. OpenSpective handles this via timeouts and marks collector execution as `partial` without crashing the scan.
- **VirusTotal Free API:** Restricted to 4 requests/minute and 500 requests/day.
- **IPInfo Unauthenticated:** 50,000 requests/month tied to IP range.

---

## 8. Security & Ethical Governance

- **Passive Reconnaissance Only:** OpenSpective does not send exploit payloads, perform port scanning, or attempt unauthorized authentication against targets.
- **Rate-Limited Endpoints:** Guest investigations are throttled to 3/day per IP; registered users are capped to prevent abusive query floods.
- **Credential Storage:** API tokens are stored exclusively as encrypted environment variables in Cloudflare Worker secrets and never returned to the frontend.
- **CORS & Headers:** Strict Content Security Policy, strict origin headers, and `X-Content-Type-Options: nosniff` are enforced across all endpoints.

---

## 9. Next Priority Roadmap

1. **Interactive Force-Directed Graph:** Integrate `@react-sigma` / D3 canvas visualization in `InvestigationDetail.tsx` for visual relationship exploration.
2. **Shodan Internetdb Integration:** Integrate Shodan's free open-source `internetdb.shodan.io` API for passive open port discovery without active scanning.
3. **Automated Scheduled Monitoring:** Cloudflare Worker Cron Triggers to re-scan targets weekly and notify on DNS/certificate diffs.
4. **Export to STIX 2.1 / MISP:** Export findings into standard cybersecurity threat intelligence exchange formats.
5. **Team Workspaces & RBAC:** Multi-tenant organization support for collaborative investigations.
