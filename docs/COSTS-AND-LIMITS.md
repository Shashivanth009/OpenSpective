# OpenSpective Free-Tier Limits & Cost Analysis

OpenSpective is architected to operate with **₹0 initial operating expense** by taking full advantage of generous provider free tiers. This document details exact free allowances, system bottlenecks, and theoretical scaling costs.

---

## 1. Free-Tier Allowances & Architecture Fit

| Component / Provider | Free Allowance | OpenSpective Usage Profile | Cost Risk / Bottleneck |
| :--- | :--- | :--- | :--- |
| **Cloudflare Workers** | 100,000 reqs/day, 10ms CPU/req | Investigations run asynchronously via `waitUntil`; CPU usage is strictly I/O binding (~3-5ms CPU). | Zero risk under standard usage; 100k daily reqs supports thousands of investigations. |
| **Cloudflare D1** | 5M read units/mo, 100k write units/mo | Investigation, executions, and findings batch inserts consume ~15 writes per scan. | Allows ~6,500 full investigations per month before exceeding free tier. |
| **Cloudflare R2** | 10 GB storage, 1M Class A operations/mo | Generated reports average ~15-40 KB each. | Negligible; holds >200,000 dossiers for free. |
| **Cloudflare Workers AI** | 10,000 Neurons/day (~free allocation) | Capped at 20 inferences per user per month. | Free daily neurons comfortably cover 50-100 LLaMA 3.1 8B analyses daily. |
| **Vercel Frontend** | 100 GB bandwidth / month | Static Vite bundle is only ~540 KB (gzip: ~158 KB). | Supports >500,000 page views per month. |
| **Cloudflare DoH (1.1.1.1)** | Unlimited Public DNS queries | Batched in groups of 4 record types. | Free and public. |
| **IPinfo.io** | 50,000 lookups / month | One lookup per unique public IP target. | Resets monthly; falls back gracefully. |
| **crt.sh CT Log** | Public non-commercial query service | Subdomain enumeration per domain scan. | Can return 504 Gateway Timeout during peak crt.sh load. |
| **VirusTotal API** | 4 req/min, 500 req/day | Triggered only when `VIRUSTOTAL_API_KEY` is provided. | Free personal community key tier. |

---

## 2. System Bottlenecks & Failure Mitigations

1. **Third-Party Upstream Timeouts (crt.sh):**
   - The primary bottleneck in passive recon is crt.sh rate limiting or query queues.
   - *Mitigation:* The certificate collector applies an 8-second defensive timeout with `AbortSignal`. If crt.sh times out, the collector marks its status as `partial`/`failed` without blocking DNS, RDAP, or the rest of the scan.

2. **D1 Write Concurrency:**
   - D1 is based on SQLite and handles writes sequentially.
   - *Mitigation:* Findings are stored in batches using prepared multi-statement transactions to minimize connection hold times.

---

## 3. Commercial Scaling Costs (Optional Future Upgrades)

If usage exceeds the free tier:
- **Cloudflare Workers Paid Plan:** $5/month (Includes 10M requests, 30s CPU time, 25B D1 row reads).
- **IPInfo Basic Tier:** $49/month for 250k requests with VPN/proxy detection.
- **VirusTotal Premium:** Custom enterprise pricing (not required for standard OSINT).
