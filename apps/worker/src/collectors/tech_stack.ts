// OpenSpective — Security Headers & Tech Stack Fingerprinting Collector
// Passive inspection of public HTTP response headers.
// Measures security hygiene, server software, CDN/WAF exposure, and OWASP defense-in-depth posture.

export interface SecurityHeaderCheck {
  header: string;
  present: boolean;
  value: string | null;
  status: 'pass' | 'warn' | 'fail';
  recommendation?: string;
}

export interface TechStackResults {
  targetUrl: string;
  finalUrl: string;
  statusCode: number;
  server: string | null;
  poweredBy: string | null;
  cdnWaf: string | null;
  securityGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  securityScore: number; // 0-100
  headersChecked: SecurityHeaderCheck[];
  missingCriticalHeaders: string[];
  collectedAt: string;
  source: string;
  error?: string;
}

export async function collectTechStack(target: string): Promise<TechStackResults> {
  const collectedAt = new Date().toISOString();
  let url = target.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = `https://${url}`;
  }

  try {
    const resp = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(8000),
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OpenSpective/0.1',
        Accept: 'text/html,application/xhtml+xml',
      },
    });

    const headers = resp.headers;
    const server = headers.get('server');
    const poweredBy = headers.get('x-powered-by');

    // Detect CDN / WAF
    let cdnWaf: string | null = null;
    if (headers.has('cf-ray') || (server && server.toLowerCase().includes('cloudflare'))) {
      cdnWaf = 'Cloudflare';
    } else if (headers.has('x-amz-cf-id') || headers.has('x-amz-cf-pop')) {
      cdnWaf = 'Amazon CloudFront';
    } else if (headers.has('x-akamai-transformed') || headers.has('akamai-grn')) {
      cdnWaf = 'Akamai Technologies';
    } else if (headers.has('x-fastly-request-id')) {
      cdnWaf = 'Fastly CDN';
    } else if (headers.has('x-iinfo') || headers.has('x-cdn') && headers.get('x-cdn')?.includes('Imperva')) {
      cdnWaf = 'Imperva / Incapsula';
    } else if (headers.has('x-sucuri-id')) {
      cdnWaf = 'Sucuri CloudProxy';
    }

    // Security Headers Audit
    let score = 100;
    const missing: string[] = [];
    const checks: SecurityHeaderCheck[] = [];

    // 1. Strict-Transport-Security (HSTS)
    const hsts = headers.get('strict-transport-security');
    if (hsts) {
      checks.push({
        header: 'Strict-Transport-Security',
        present: true,
        value: hsts,
        status: 'pass',
      });
    } else {
      score -= 25;
      missing.push('Strict-Transport-Security');
      checks.push({
        header: 'Strict-Transport-Security',
        present: false,
        value: null,
        status: 'fail',
        recommendation: 'Enforce HTTPS and prevent SSL stripping by configuring Strict-Transport-Security.',
      });
    }

    // 2. Content-Security-Policy (CSP)
    const csp = headers.get('content-security-policy');
    if (csp) {
      checks.push({
        header: 'Content-Security-Policy',
        present: true,
        value: csp.slice(0, 150) + (csp.length > 150 ? '...' : ''),
        status: 'pass',
      });
    } else {
      score -= 25;
      missing.push('Content-Security-Policy');
      checks.push({
        header: 'Content-Security-Policy',
        present: false,
        value: null,
        status: 'fail',
        recommendation: 'Mitigate XSS and data injection attacks by deploying a strict Content-Security-Policy.',
      });
    }

    // 3. X-Frame-Options
    const xfo = headers.get('x-frame-options');
    if (xfo || (csp && csp.includes('frame-ancestors'))) {
      checks.push({
        header: 'X-Frame-Options',
        present: true,
        value: xfo || 'Protected via CSP frame-ancestors',
        status: 'pass',
      });
    } else {
      score -= 15;
      missing.push('X-Frame-Options');
      checks.push({
        header: 'X-Frame-Options',
        present: false,
        value: null,
        status: 'warn',
        recommendation: 'Prevent clickjacking attacks by defining DENY or SAMEORIGIN in X-Frame-Options.',
      });
    }

    // 4. X-Content-Type-Options
    const xcto = headers.get('x-content-type-options');
    if (xcto && xcto.toLowerCase().includes('nosniff')) {
      checks.push({
        header: 'X-Content-Type-Options',
        present: true,
        value: xcto,
        status: 'pass',
      });
    } else {
      score -= 10;
      missing.push('X-Content-Type-Options');
      checks.push({
        header: 'X-Content-Type-Options',
        present: false,
        value: null,
        status: 'warn',
        recommendation: 'Prevent MIME-type sniffing vulnerabilities by setting X-Content-Type-Options: nosniff.',
      });
    }

    // 5. Referrer-Policy
    const refPol = headers.get('referrer-policy');
    if (refPol) {
      checks.push({
        header: 'Referrer-Policy',
        present: true,
        value: refPol,
        status: 'pass',
      });
    } else {
      score -= 10;
      missing.push('Referrer-Policy');
      checks.push({
        header: 'Referrer-Policy',
        present: false,
        value: null,
        status: 'warn',
        recommendation: 'Control referrer information leakage by setting Referrer-Policy: strict-origin-when-cross-origin.',
      });
    }

    // 6. Permissions-Policy
    const permPol = headers.get('permissions-policy');
    if (permPol) {
      checks.push({
        header: 'Permissions-Policy',
        present: true,
        value: permPol.slice(0, 100),
        status: 'pass',
      });
    } else {
      score -= 5;
      checks.push({
        header: 'Permissions-Policy',
        present: false,
        value: null,
        status: 'warn',
        recommendation: 'Restrict access to browser APIs (camera, microphone, geolocation) with Permissions-Policy.',
      });
    }

    // Determine letter grade
    const finalScore = Math.max(0, score);
    let securityGrade: TechStackResults['securityGrade'] = 'F';
    if (finalScore >= 95) securityGrade = 'A+';
    else if (finalScore >= 85) securityGrade = 'A';
    else if (finalScore >= 70) securityGrade = 'B';
    else if (finalScore >= 55) securityGrade = 'C';
    else if (finalScore >= 40) securityGrade = 'D';

    return {
      targetUrl: url,
      finalUrl: resp.url,
      statusCode: resp.status,
      server,
      poweredBy,
      cdnWaf,
      securityGrade,
      securityScore: finalScore,
      headersChecked: checks,
      missingCriticalHeaders: missing,
      collectedAt,
      source: 'HTTP Passive Response Headers Analysis',
    };
  } catch (err) {
    return {
      targetUrl: url,
      finalUrl: url,
      statusCode: 0,
      server: null,
      poweredBy: null,
      cdnWaf: null,
      securityGrade: 'F',
      securityScore: 0,
      headersChecked: [],
      missingCriticalHeaders: ['Strict-Transport-Security', 'Content-Security-Policy'],
      collectedAt,
      source: 'HTTP Passive Response Headers Analysis',
      error: err instanceof Error ? err.message : 'HTTP connection failed',
    };
  }
}
