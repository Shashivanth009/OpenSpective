# OpenSpective Production Deployment Guide

This guide provides step-by-step instructions for deploying OpenSpective completely within free-tier infrastructure.

---

## 1. Prerequisites & Required CLI Tools

- Node.js >= 20.0.0
- npm >= 10.0.0
- Wrangler CLI: `npm install -g wrangler` or use `npx wrangler`

---

## 2. Backend Deployment (Cloudflare Workers + D1 + R2)

### Step 1: Cloudflare Authentication
```bash
npx wrangler login
```

### Step 2: Provision Cloudflare D1 Database
```bash
npx wrangler d1 create openspective-db
```
*Note the returned `database_id` value.*

Open `apps/worker/wrangler.toml` and paste the ID:
```toml
[[d1_databases]]
binding = "DB"
database_name = "openspective-db"
database_id = "PASTE_YOUR_DATABASE_ID_HERE"
```

### Step 3: Apply Remote Database Migrations
Run the schema migration against the production Cloudflare D1 instance:
```bash
npm run db:migrate:remote
```

### Step 4: Create Cloudflare R2 Bucket
```bash
npx wrangler r2 bucket create openspective-reports
```

### Step 5: Configure Production Secrets
Set sensitive tokens directly into Cloudflare's secure secret store:
```bash
# Required: Strong random JWT signing secret (min 32 characters)
npx wrangler secret put JWT_SECRET --config apps/worker/wrangler.toml

# Optional: Enhanced rate limits & threat feeds
npx wrangler secret put VIRUSTOTAL_API_KEY --config apps/worker/wrangler.toml
npx wrangler secret put IPINFO_TOKEN --config apps/worker/wrangler.toml
npx wrangler secret put GITHUB_TOKEN --config apps/worker/wrangler.toml
npx wrangler secret put HAVE_I_BEEN_PWNED_API_KEY --config apps/worker/wrangler.toml
```

### Step 6: Deploy the Worker
```bash
npm run deploy:worker
```
Your backend API will be live at: `https://openspective-worker.<subdomain>.workers.dev`.

---

## 3. Frontend Deployment (Vercel / Cloudflare Pages)

### Deploying on Vercel
1. Import the repository into your Vercel Dashboard.
2. Configure Project Settings:
   - **Framework Preset:** Vite
   - **Root Directory:** `./`
   - **Build Command:** `npm run build`
   - **Output Directory:** `apps/web/dist`
   - **Install Command:** `npm install`
3. Environment Variables:
   - `VITE_API_URL`: `https://openspective-worker.<subdomain>.workers.dev/api/v1`

### Deploying on Cloudflare Pages
```bash
npm run build
npx wrangler pages deploy apps/web/dist --project-name openspective
```
Set `VITE_API_URL` under Pages > Settings > Environment variables.
