# OpenSpective Security Model & Governance

## 1. Threat Model & Security Posture

OpenSpective is specifically designed for public intelligence gathering and passive reconnaissance. It rejects intrusive actions, active scanning, and unauthorized data collection by architecture.

```
       [ Client Request ]
               │
               ▼
   [ Server-Side Classifier ] ──> Blocks Private / Loopback IPs (10.0.0.0/8, 127.0.0.0/8, etc.)
               │
               ▼
   [ SSRF Sanitizer & Router ] ──> Whitelisted Outbound APIs (DoH, RDAP Bootstrap, crt.sh)
               │
               ▼
   [ Bounded HTTP Clients ]  ──> Strict Timeouts (10s), Max 1MB Payload, Safe Headers
```

---

## 2. Server-Side Request Forgery (SSRF) Mitigations

Because OSINT platforms query user-provided targets (domains, URLs, IPs), SSRF protection is paramount:

1. **IP Range Blacklisting (`isPrivateIp`):**
   - All IPv4 targets and resolved addresses are checked against RFC 1918, RFC 3927 (link-local), RFC 5737 (test nets), and loopback ranges (`127.0.0.0/8`).
   - Private IP lookups (e.g. `192.168.1.1`, `10.0.0.1`, `169.254.169.254`) return immediate validation failures and are never requested over the network.
   - Cloud metadata IP (`169.254.169.254`) is explicitly blocked.

2. **Protocol & Port Constraints:**
   - Outbound requests only use HTTPS (`https://`).
   - No raw socket connections, TCP syn scans, or arbitrary port probes are initiated.
   - Target queries are delegated exclusively to authoritative public third-party APIs (Cloudflare 1.1.1.1 DoH, IANA RDAP, crt.sh, IPInfo, VirusTotal).

3. **URL Metadata Bounded Ingestion:**
   - URL target fetching is bounded to a single non-following or single-redirect request with a strict `AbortSignal` timeout of 6,000ms.
   - Response size is capped at 512 KB to prevent denial-of-service via decompression bombs.

---

## 3. Authentication & Ownership Enforcement

- **Stateless JWT:** Authenticated tokens are signed via HMAC-SHA256 (`JWT_SECRET`) with configurable expiry (7 days).
- **Ownership Verification:** Every mutation (`POST /cancel`, `POST /analyze`) and query (`GET /findings`, `GET /graph`) verifies that the requesting user's `id` matches `investigations.user_id`.
- **Guest Isolation:** Unauthenticated users can perform up to 3 investigations per rolling 24-hour window tracked by hashed IP address. Guest scans are publicly accessible only by exact cryptographic UUID and cannot be enumerated via the list endpoint.

---

## 4. Rate Limiting & Abuse Prevention

- **Per-IP Guest Limits:** 3 scans per 24 hours.
- **Per-Account Limits:** 50 investigations per month on the standard tier.
- **AI Inference Cap:** 20 Workers AI inference prompts per user per month to eliminate runaway LLM token costs.
- **Collector polite throttling:** crt.sh and DoH queries are spaced in concurrency batches of 4 to prevent upstream provider blacklisting.

---

## 5. Responsible Use & Compliance Rules

- **Zero Exploit Capability:** OpenSpective contains no exploit payloads, fuzzers, dictionary attack engines, or brute-force scripts.
- **Credential Hygiene:** Never searches for, displays, or caches raw passwords or authentication hashes. Breach notifications from HaveIBeenPwned report only breach breach names and public breach dates.
- **GDPR Redaction Respect:** When RDAP returns redacted registrant details (e.g., `REDACTED FOR PRIVACY`), the engine records the field as redacted and warns the analyst accordingly.
