# OpenSpective Privacy, Ethical Guidelines & Data Governance

## 1. Ethical Mission Statement

OpenSpective is committed to ethical, lawful, and defensive cybersecurity intelligence gathering. The platform strictly enforces **passive reconnaissance**:
- No active port scanning or TCP/UDP socket probing.
- No credential verification, brute-forcing, or password dictionary testing.
- No vulnerability exploitation, injection testing, or web application fuzzing.
- No interception of private network communications.

---

## 2. Personal Data Minimization

When investigating email addresses, usernames, or individuals:
1. **No Invasive Profiling:** The platform only discovers publicly observable domain bindings, public code repositories, and RFC-compliant routing records.
2. **Password Redaction:** OpenSpective never stores, searches for, displays, or exposes plaintext passwords or password hashes. Breach checks (HaveIBeenPwned) expose only historical breach names and dates.
3. **Respect for ICANN & GDPR Redactions:** Registrant names or addresses redacted in RDAP/WHOIS responses are never unmasked or correlated through invasive scrapers.
4. **No Carrier/Location Tracking:** Phone inquiries are strictly limited to international numbering plan metadata and country code definitions. Real-time location tracking and subscriber lookup databases are explicitly rejected.

---

## 3. Data Retention & Deletion Policy

- **Investigation Lifecycles:** Saved investigations and findings remain associated with the owner's account until explicitly deleted.
- **Guest Inquiries:** Unauthenticated guest inquiries are stored with hashed IP references and automatically purged after 30 days.
- **Account Deletion:** Users can delete investigations and account records via the platform API.

---

## 4. Subprocessors & Third-Party Service Handlers

| Service | Data Transmitted | Purpose |
| :--- | :--- | :--- |
| **Cloudflare DoH (1.1.1.1)** | Domain name string | DNS resolution |
| **IANA / RDAP Registries** | Domain name or public IP | Registration lookups |
| **crt.sh** | Domain name string | Certificate Transparency discovery |
| **IPinfo.io** | Public IP address string | Geolocation & ASN lookup |
| **VirusTotal** | Domain, IP, or URL string | Aggregated vendor malware verdicts |
| **Cloudflare Workers AI** | Compact findings text | AI explanation and report synthesis |
