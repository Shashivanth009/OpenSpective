# OpenSpective Passive Collectors & Providers

This document outlines the architecture, data sources, rate limits, and configuration of each reconnaissance module supported by OpenSpective.

---

## 1. Collector Summary Table

| Collector ID | Module Name | Target Types | External Credential | Source Provider | Rate Limits & Constraints |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `dns` | DNS Intelligence | Domain, Email, URL, Org | None (Built-in) | Cloudflare 1.1.1.1 DoH | Anycast DoH; queries batched in groups of 4. |
| `rdap` | RDAP Registration | Domain, IP | None (Built-in) | IANA RDAP Bootstrap | ICANN/GDPR redactions marked explicitly. |
| `certificate_transparency` | Certificate Logs | Domain | None (Built-in) | crt.sh PostgreSQL Web API | Rate-sensitive; queries time out after 8s. |
| `ipinfo` | IP Geolocation & ASN | IP, Domain | Optional (`IPINFO_TOKEN`) | IPinfo.io | 50,000 req/month unauthenticated. |
| `virustotal` | Threat Intelligence | Domain, IP, URL, Email | Required (`VIRUSTOTAL_API_KEY`) | VirusTotal v3 API | 4 req/min and 500 req/day on free tier. |
| `github` | GitHub OSINT | Org, Username, Email, Domain | Optional (`GITHUB_TOKEN`) | GitHub REST API v3 | 60 req/hr unauthenticated; 5,000 req/hr with token. |
| `email_dns` | Email Security | Email, Domain | None (Built-in) | Cloudflare DoH | Inspects SPF, DMARC, and DKIM indicators. |
| `haveibeenpwned` | Breach Check | Email | Required (`HAVE_I_BEEN_PWNED_API_KEY`) | HaveIBeenPwned API v3 | Subscription key required; returns breach names only. |
| `url_metadata` | URL Fingerprint | URL | None (Built-in) | Bounded HTTP Client | Single fetch with 6s timeout, max 512KB. |

---

## 2. In-Depth Collector Implementations

### DNS Intelligence (`collectors/dns.ts`)
- **Transport:** HTTP GET with `Accept: application/dns-json` sent to `https://cloudflare-dns.com/dns-query`.
- **Record Types Covered:**
  - `A` / `AAAA` — Direct IPv4/IPv6 address resolutions.
  - `MX` — Mail server routing and priority values.
  - `NS` — Authoritative nameserver delegations.
  - `TXT` — SPF strings, domain ownership verifications, and site policies.
  - `CNAME` — Canonical host aliases.
  - `SOA` — Zone administrative contacts and serial timers.
  - `CAA` — Certificate Authority Authorization directives.

### RDAP Registration (`collectors/rdap.ts`)
- **Transport:** Standard RFC 7484 / RFC 9083 IANA bootstrap discovery.
- **Features:** Queries top-level registrar and regional registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC). Resolves registrar name, creation date, expiration date, name servers, and registered entity roles.

### Certificate Transparency (`collectors/certificate.ts`)
- **Transport:** `https://crt.sh/?q=%.<domain>&output=json`.
- **Features:** Discovers issued certificates and extracts all Subject Alternative Names (SANs) to passively enumerate active and historic subdomains without brute-force DNS probing.

### IP Geolocation & ASN (`collectors/ipinfo.ts`)
- **Transport:** `https://ipinfo.io/<ip>/json`.
- **Features:** Extracts ASN (`AS13335`), organization name, city, region, country, coordinates, and timezone. Operates transparently without token for low-volume investigations.

### VirusTotal Threat Intelligence (`collectors/virustotal.ts`)
- **Transport:** `https://www.virustotal.com/api/v3/{domains|ip_addresses|urls}`.
- **Features:** Parses `last_analysis_stats` (malicious, suspicious, harmless, undetected). Flags positive vendor detection tallies and surfaces the canonical permalink.

---

## 3. Adding New Collectors

To implement a new collector:
1. Implement the collector function in `apps/worker/src/collectors/<name>.ts`.
2. Return a standardized interface with `source`, `collectedAt`, and `errors`.
3. Register the definition in `COLLECTORS` inside `apps/worker/src/collectors/registry.ts`.
4. Add the execution runner step in `apps/worker/src/orchestrator.ts`.
