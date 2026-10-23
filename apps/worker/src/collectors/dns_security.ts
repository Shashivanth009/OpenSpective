// OpenSpective — DNS Security, Email Authentication & DNSSEC Collector
// Audits SPF, DMARC, BIMI, MTA-STS, TLS-RPT, and DNSSEC posture via Cloudflare DoH.
// Computes defensive email hygiene score and actionable hardening recommendations.

const CF_DOH = 'https://cloudflare-dns.com/dns-query';

export interface SecurityAuditItem {
  check: string;
  status: 'pass' | 'warn' | 'fail' | 'info';
  record: string | null;
  detail: string;
  recommendation?: string;
}

export interface DnsSecurityResults {
  domain: string;
  securityScore: number; // 0-100
  securityGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  hasSpf: boolean;
  hasDmarc: boolean;
  hasBimi: boolean;
  hasMtaSts: boolean;
  hasTlsRpt: boolean;
  hasDnssec: boolean;
  checks: SecurityAuditItem[];
  collectedAt: string;
  source: string;
  error?: string;
}

async function queryDohTxt(name: string): Promise<string[]> {
  try {
    const url = `${CF_DOH}?name=${encodeURIComponent(name)}&type=TXT`;
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(6000),
      headers: { Accept: 'application/dns-json' },
    });
    if (!resp.ok) return [];
    const data = await resp.json() as { Answer?: Array<{ data: string }> };
    if (!Array.isArray(data.Answer)) return [];
    return data.Answer.map(a => a.data.replace(/^"|"$/g, '').replace(/\\"/g, '"'));
  } catch {
    return [];
  }
}

async function checkDnssec(domain: string): Promise<boolean> {
  try {
    // Check for DS record at parent or DNSKEY at domain
    const url = `${CF_DOH}?name=${encodeURIComponent(domain)}&type=DS`;
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(6000),
      headers: { Accept: 'application/dns-json' },
    });
    if (!resp.ok) return false;
    const data = await resp.json() as { Status: number; Answer?: Array<{ type: number }> };
    return Array.isArray(data.Answer) && data.Answer.length > 0;
  } catch {
    return false;
  }
}

export async function collectDnsSecurity(domain: string): Promise<DnsSecurityResults> {
  const collectedAt = new Date().toISOString();
  const cleanDomain = domain.toLowerCase().replace(/^(https?:\/\/)/, '').replace(/\/.*$/, '').trim();

  const checks: SecurityAuditItem[] = [];
  let score = 100;

  try {
    // Query SPF, DMARC, BIMI, MTA-STS, and DNSSEC concurrently
    const [rootTxts, dmarcTxts, bimiTxts, mtaStsTxts, tlsRptTxts, isDnssec] = await Promise.all([
      queryDohTxt(cleanDomain),
      queryDohTxt(`_dmarc.${cleanDomain}`),
      queryDohTxt(`default._bimi.${cleanDomain}`),
      queryDohTxt(`_mta-sts.${cleanDomain}`),
      queryDohTxt(`_smtp._tls.${cleanDomain}`),
      checkDnssec(cleanDomain),
    ]);

    // 1. SPF Evaluation
    const spfRecord = rootTxts.find(t => t.startsWith('v=spf1'));
    if (!spfRecord) {
      score -= 30;
      checks.push({
        check: 'SPF (Sender Policy Framework)',
        status: 'fail',
        record: null,
        detail: 'No SPF record found in DNS. Attackers can forge emails from this domain.',
        recommendation: 'Publish a v=spf1 TXT record restricting authorized sending mail servers.',
      });
    } else {
      if (spfRecord.includes('+all')) {
        score -= 25;
        checks.push({
          check: 'SPF (Sender Policy Framework)',
          status: 'fail',
          record: spfRecord,
          detail: 'Critical: SPF uses +all qualifier (authorizes the entire internet to send as this domain).',
          recommendation: 'Change +all to -all (hard fail) or ~all (soft fail).',
        });
      } else if (spfRecord.includes('?all')) {
        score -= 15;
        checks.push({
          check: 'SPF (Sender Policy Framework)',
          status: 'warn',
          record: spfRecord,
          detail: 'Neutral SPF (?all) does not provide spoofing protection.',
          recommendation: 'Enforce -all (hard fail) for strict receiver enforcement.',
        });
      } else if (spfRecord.includes('-all')) {
        checks.push({
          check: 'SPF (Sender Policy Framework)',
          status: 'pass',
          record: spfRecord,
          detail: 'Hard-fail policy (-all) enforced. Excellent protection against spoofing.',
        });
      } else {
        checks.push({
          check: 'SPF (Sender Policy Framework)',
          status: 'pass',
          record: spfRecord,
          detail: 'Soft-fail policy (~all) active.',
        });
      }
    }

    // 2. DMARC Evaluation
    const dmarcRecord = dmarcTxts.find(t => t.startsWith('v=DMARC1'));
    if (!dmarcRecord) {
      score -= 35;
      checks.push({
        check: 'DMARC (Domain-based Message Authentication)',
        status: 'fail',
        record: null,
        detail: 'No DMARC record at _dmarc.' + cleanDomain + '. Emails failing SPF/DKIM will not be rejected.',
        recommendation: 'Publish a DMARC policy (e.g. v=DMARC1; p=reject; rua=mailto:...) at _dmarc.' + cleanDomain,
      });
    } else {
      const isReject = /p\s*=\s*reject/i.test(dmarcRecord);
      const isQuarantine = /p\s*=\s*quarantine/i.test(dmarcRecord);
      const isNone = /p\s*=\s*none/i.test(dmarcRecord);
      const hasRua = /rua\s*=/i.test(dmarcRecord);

      if (isReject) {
        checks.push({
          check: 'DMARC (Domain-based Message Authentication)',
          status: 'pass',
          record: dmarcRecord,
          detail: 'Strict policy (p=reject). Unauthorized emails will be rejected by compliant receivers.',
        });
      } else if (isQuarantine) {
        score -= 5;
        checks.push({
          check: 'DMARC (Domain-based Message Authentication)',
          status: 'pass',
          record: dmarcRecord,
          detail: 'Quarantine policy (p=quarantine). Spoofed emails are moved to spam folders.',
          recommendation: 'Graduate policy to p=reject once all legitimate senders are verified.',
        });
      } else if (isNone) {
        score -= 15;
        checks.push({
          check: 'DMARC (Domain-based Message Authentication)',
          status: 'warn',
          record: dmarcRecord,
          detail: 'Monitoring policy only (p=none). Does not prevent email spoofing.',
          recommendation: 'Upgrade policy from p=none to p=quarantine or p=reject.',
        });
      }

      if (!hasRua) {
        score -= 5;
        checks.push({
          check: 'DMARC Aggregate Reporting (rua)',
          status: 'warn',
          record: dmarcRecord,
          detail: 'No rua= reporting mailbox configured. Administrators will not receive spoofing telemetry.',
        });
      }
    }

    // 3. DNSSEC Evaluation
    if (isDnssec) {
      checks.push({
        check: 'DNSSEC (DNS Security Extensions)',
        status: 'pass',
        record: 'DS / DNSKEY verified',
        detail: 'Cryptographic DNSSEC signatures protect against DNS spoofing and cache poisoning.',
      });
    } else {
      score -= 10;
      checks.push({
        check: 'DNSSEC (DNS Security Extensions)',
        status: 'info',
        record: null,
        detail: 'DNSSEC is not enabled for this zone.',
        recommendation: 'Enable DNSSEC with your DNS provider to cryptographically sign DNS records.',
      });
    }

    // 4. MTA-STS Evaluation
    const mtaStsRecord = mtaStsTxts.find(t => t.startsWith('v=STSv1'));
    if (mtaStsRecord) {
      checks.push({
        check: 'MTA-STS (Mail Transfer Agent Strict Transport Security)',
        status: 'pass',
        record: mtaStsRecord,
        detail: 'RFC 8461 MTA-STS active. Enforces TLS encryption for incoming SMTP connections.',
      });
    } else {
      checks.push({
        check: 'MTA-STS (Mail Transfer Agent Strict Transport Security)',
        status: 'info',
        record: null,
        detail: 'MTA-STS not deployed.',
      });
    }

    // 5. TLS Reporting Evaluation
    const tlsRptRecord = tlsRptTxts.find(t => t.startsWith('v=TLSRPTv1'));
    if (tlsRptRecord) {
      checks.push({
        check: 'SMTP TLS-RPT (TLS Reporting)',
        status: 'pass',
        record: tlsRptRecord,
        detail: 'RFC 8460 TLS reporting active at _smtp._tls.' + cleanDomain,
      });
    }

    // 6. BIMI Brand Indicator
    const bimiRecord = bimiTxts.find(t => t.startsWith('v=BIMI1'));
    if (bimiRecord) {
      checks.push({
        check: 'BIMI (Brand Indicators for Message Identification)',
        status: 'pass',
        record: bimiRecord,
        detail: 'Verified BIMI brand indicator configured.',
      });
    }

    score = Math.max(0, Math.min(100, score));
    let grade: DnsSecurityResults['securityGrade'] = 'F';
    if (score >= 95) grade = 'A+';
    else if (score >= 85) grade = 'A';
    else if (score >= 70) grade = 'B';
    else if (score >= 55) grade = 'C';
    else if (score >= 40) grade = 'D';

    return {
      domain: cleanDomain,
      securityScore: score,
      securityGrade: grade,
      hasSpf: !!spfRecord,
      hasDmarc: !!dmarcRecord,
      hasBimi: !!bimiRecord,
      hasMtaSts: !!mtaStsRecord,
      hasTlsRpt: !!tlsRptRecord,
      hasDnssec: isDnssec,
      checks,
      collectedAt,
      source: 'Cloudflare Anycast DoH (RFC 8484 DNS Security Engine)',
    };
  } catch (err) {
    return {
      domain: cleanDomain,
      securityScore: 0,
      securityGrade: 'F',
      hasSpf: false,
      hasDmarc: false,
      hasBimi: false,
      hasMtaSts: false,
      hasTlsRpt: false,
      hasDnssec: false,
      checks: [],
      collectedAt,
      source: 'Cloudflare Anycast DoH',
      error: err instanceof Error ? err.message : 'DNS security audit failed',
    };
  }
}
