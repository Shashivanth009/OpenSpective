// OpenSpective — Investigation Orchestrator
// Runs applicable collectors for a given investigation target type,
// persists findings to D1, and updates investigation status.

import type { Env } from './env.ts';
import type { TargetType, Finding, Relationship, CollectorStatus } from '@openspective/shared';
import { generateId, nowIso } from './utils.ts';
import { collectDns, domainFromEmail } from './collectors/dns.ts';
import { collectRdapDomain, collectRdapIp } from './collectors/rdap.ts';
import { collectCertificateTransparency } from './collectors/certificate.ts';
import { collectIpInfo } from './collectors/ipinfo.ts';
import { collectGitHubOrg, collectGitHubUser } from './collectors/github.ts';
import { collectVtDomain, collectVtIp, collectVtUrl } from './collectors/virustotal.ts';
import { collectPersonSearch, checkUsernamePresence } from './collectors/person.ts';
import { collectEmailIdentity } from './collectors/email_identity.ts';
import { collectWebArchive } from './collectors/web_archive.ts';
import { collectTechStack } from './collectors/tech_stack.ts';
import { collectCryptoWallet, detectCryptoNetwork } from './collectors/crypto.ts';
import { collectBreachIntelligence } from './collectors/breach.ts';
import { collectLocationIntelligence } from './collectors/location.ts';
import { collectShodanInternetDb } from './collectors/shodan.ts';
import { collectPhoneIntelligence } from './collectors/phone.ts';
import { collectDnsSecurity } from './collectors/dns_security.ts';

interface OrchestratorContext {
  investigationId: string;
  target: string;
  normalizedTarget: string;
  targetType: TargetType;
  selectedModules: string[];
  env: Env;
}

async function updateInvestigationStatus(
  db: D1Database,
  investigationId: string,
  status: string,
  errorMessage?: string
): Promise<void> {
  const completedAt = ['completed', 'partial', 'failed', 'cancelled'].includes(status) ? nowIso() : null;
  await db
    .prepare(
      `UPDATE investigations SET status = ?, completed_at = ?, error_message = ?, updated_at = ? WHERE id = ?`
    )
    .bind(status, completedAt, errorMessage ?? null, nowIso(), investigationId)
    .run().catch(() => {
      // Table might not have updated_at — try without it
      db.prepare(
        `UPDATE investigations SET status = ?, completed_at = ?, error_message = ? WHERE id = ?`
      ).bind(status, completedAt, errorMessage ?? null, investigationId).run();
    });
}

async function createCollectorExecution(
  db: D1Database,
  investigationId: string,
  collectorName: string
): Promise<string> {
  const id = generateId('ce');
  await db
    .prepare(
      `INSERT INTO collector_executions (id, investigation_id, collector_name, status, started_at) VALUES (?, ?, ?, 'running', ?)`
    )
    .bind(id, investigationId, collectorName, nowIso())
    .run();
  return id;
}

async function updateCollectorExecution(
  db: D1Database,
  executionId: string,
  status: CollectorStatus,
  findingsCount: number,
  errorMessage: string | null
): Promise<void> {
  await db
    .prepare(
      `UPDATE collector_executions SET status = ?, completed_at = ?, findings_count = ?, error_message = ? WHERE id = ?`
    )
    .bind(status, nowIso(), findingsCount, errorMessage, executionId)
    .run();
}

async function persistFindings(
  db: D1Database,
  findings: Omit<Finding, 'id'>[]
): Promise<void> {
  for (const finding of findings) {
    const id = generateId('f');
    await db
      .prepare(
        `INSERT INTO findings (id, investigation_id, collector_execution_id, category, subcategory, type, value, raw_data, confidence, severity, source_url, source_name, first_seen, last_seen, is_inferred, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        id,
        finding.investigationId,
        finding.collectorExecutionId ?? null,
        finding.category,
        finding.subcategory ?? null,
        finding.type,
        finding.value,
        JSON.stringify(finding.rawData),
        finding.confidence,
        finding.severity,
        finding.sourceUrl ?? null,
        finding.sourceName,
        finding.firstSeen,
        finding.lastSeen,
        finding.isInferred ? 1 : 0,
        finding.notes ?? null
      )
      .run();
  }
}

async function persistRelationship(
  db: D1Database,
  rel: Omit<Relationship, 'id'>
): Promise<void> {
  const id = generateId('r');
  await db
    .prepare(
      `INSERT OR IGNORE INTO relationships (id, investigation_id, from_entity_type, to_entity_type, from_value, to_value, relationship_type, finding_id, source_url, confidence, is_inferred, collected_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      id,
      rel.investigationId,
      rel.fromEntityType,
      rel.toEntityType,
      rel.fromValue,
      rel.toValue,
      rel.relationshipType,
      rel.findingId ?? null,
      rel.sourceUrl ?? null,
      rel.confidence,
      rel.isInferred ? 1 : 0,
      rel.collectedAt
    )
    .run();
}

// ---- DNS collector runner ----
async function runDnsCollector(ctx: OrchestratorContext, domain: string): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'dns');
  try {
    const result = await collectDns(domain);
    const findings: Omit<Finding, 'id'>[] = result.records.map(record => ({
      investigationId: ctx.investigationId,
      collectorExecutionId: execId,
      category: 'dns',
      subcategory: record.type,
      type: `dns_${record.type.toLowerCase()}`,
      value: record.value,
      rawData: { ...record },
      confidence: 'high',
      severity: 'info',
      sourceUrl: 'https://cloudflare-dns.com/dns-query',
      sourceName: result.source,
      firstSeen: result.collectedAt,
      lastSeen: result.collectedAt,
      isInferred: false,
      notes: record.priority != null ? `Priority: ${record.priority}` : null,
    }));

    await persistFindings(ctx.env.DB, findings);

    // Create relationships: domain resolves_to IP
    for (const f of findings) {
      if (f.type === 'dns_a' || f.type === 'dns_aaaa') {
        await persistRelationship(ctx.env.DB, {
          investigationId: ctx.investigationId,
          fromEntityType: 'domain',
          toEntityType: 'ip',
          fromValue: domain,
          toValue: f.value,
          relationshipType: 'resolves_to',
          findingId: null,
          sourceUrl: 'https://cloudflare-dns.com/dns-query',
          confidence: 'high',
          isInferred: false,
          collectedAt: result.collectedAt,
          fromEntityId: '',
          toEntityId: '',
        });
      }
      if (f.type === 'dns_mx') {
        await persistRelationship(ctx.env.DB, {
          investigationId: ctx.investigationId,
          fromEntityType: 'domain',
          toEntityType: 'domain',
          fromValue: domain,
          toValue: f.value,
          relationshipType: 'mx_record',
          findingId: null,
          sourceUrl: 'https://cloudflare-dns.com/dns-query',
          confidence: 'high',
          isInferred: false,
          collectedAt: result.collectedAt,
          fromEntityId: '',
          toEntityId: '',
        });
      }
    }

    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, result.errors.join('; ') || null);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- RDAP collector runner ----
async function runRdapCollector(ctx: OrchestratorContext, target: string, type: 'domain' | 'ip'): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'rdap');
  try {
    const result = type === 'domain' ? await collectRdapDomain(target) : await collectRdapIp(target);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    const addFinding = (fieldType: string, value: string | null, notes?: string) => {
      if (!value) return;
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'rdap',
        subcategory: fieldType,
        type: `rdap_${fieldType}`,
        value,
        rawData: { field: fieldType, value, isRedacted: result.isRedacted },
        confidence: 'high',
        severity: 'info',
        sourceUrl: null,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: notes ?? (result.isRedacted ? 'Some fields are redacted per ICANN/GDPR policy.' : null),
      });
    };

    addFinding('registrar', result.registrar);
    addFinding('registrant_org', result.registrantOrg);
    addFinding('registered_at', result.registeredAt);
    addFinding('expires_at', result.expiresAt);
    addFinding('updated_at', result.updatedAt);
    for (const ns of result.nameservers) addFinding('nameserver', ns);

    if (result.isRedacted) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'rdap',
        subcategory: 'privacy',
        type: 'rdap_redacted',
        value: 'Registration fields are redacted per ICANN/GDPR policy.',
        rawData: {},
        confidence: 'high',
        severity: 'info',
        sourceUrl: null,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: null,
      });
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, null);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- Certificate Transparency runner ----
async function runCertificateCollector(ctx: OrchestratorContext, domain: string): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'certificate_transparency');
  try {
    const result = await collectCertificateTransparency(domain);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    for (const cert of result.certificates) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'certificate',
        subcategory: 'tls_certificate',
        type: 'certificate',
        value: cert.commonName,
        rawData: { ...cert },
        confidence: 'high',
        severity: 'info',
        sourceUrl: 'https://crt.sh',
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: `Valid: ${cert.validFrom} — ${cert.validTo}. Issuer: ${cert.issuer}`,
      });
    }

    for (const sub of result.subdomains) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'subdomain',
        subcategory: 'certificate_transparency',
        type: 'subdomain',
        value: sub.hostname,
        rawData: { ...sub },
        confidence: 'medium',
        severity: 'info',
        sourceUrl: 'https://crt.sh',
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: 'Discovered via certificate transparency logs. DNS resolution not verified.',
      });

      await persistRelationship(ctx.env.DB, {
        investigationId: ctx.investigationId,
        fromEntityType: 'subdomain',
        toEntityType: 'domain',
        fromValue: sub.hostname,
        toValue: domain,
        relationshipType: 'subdomain_of',
        findingId: null,
        sourceUrl: 'https://crt.sh',
        confidence: 'medium',
        isInferred: false,
        collectedAt: ts,
        fromEntityId: '',
        toEntityId: '',
      });
    }

    if (result.error) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'certificate',
        subcategory: 'error',
        type: 'collector_error',
        value: result.error,
        rawData: {},
        confidence: 'unknown',
        severity: 'info',
        sourceUrl: null,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: null,
      });
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, result.error ? 'partial' as CollectorStatus : 'completed', findings.length, result.error);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- IP Info runner ----
async function runIpInfoCollector(ctx: OrchestratorContext, ip: string): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'ipinfo');
  try {
    const result = await collectIpInfo(ip, ctx.env.IPINFO_TOKEN);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    const addField = (type: string, value: string | null, notes?: string) => {
      if (!value) return;
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'ip_info',
        subcategory: type,
        type: `ip_${type}`,
        value,
        rawData: { field: type, ...result },
        confidence: 'medium',
        severity: 'info',
        sourceUrl: `https://ipinfo.io/${ip}`,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: notes ?? null,
      });
    };

    addField('org', result.org);
    addField('asn', result.asn);
    addField('hostname', result.hostname);
    addField('country', result.country);
    addField('region', result.region ? `${result.city ?? ''}, ${result.region}`.trim().replace(/^,\s*/, '') : null, 'Approximate geolocation only.');
    if (result.isTor) addField('tor_exit', 'true', 'IP is associated with a Tor exit node (public list).');
    if (result.isVpn) addField('vpn', 'true', 'IP is associated with a known VPN service (public lists).');
    if (result.isHosting) addField('hosting', 'true', 'IP belongs to a hosting or datacenter network.');

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, result.error ? 'partial' as CollectorStatus : 'completed', findings.length, result.error);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- GitHub runner ----
async function runGitHubCollector(ctx: OrchestratorContext, query: string, isUsername: boolean): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'github');
  try {
    const result = isUsername
      ? await collectGitHubUser(query, ctx.env.GITHUB_TOKEN)
      : await collectGitHubOrg(query, ctx.env.GITHUB_TOKEN);

    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    const profile = result.orgInfo ?? result.userInfo;
    if (profile) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'public_profile',
        subcategory: 'github',
        type: 'github_profile',
        value: profile.login,
        rawData: { ...profile },
        confidence: 'high',
        severity: 'info',
        sourceUrl: `https://github.com/${profile.login}`,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: `Public repos: ${profile.publicRepos}. Followers: ${profile.followers}.`,
      });
    }

    for (const repo of result.repos) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'repository',
        subcategory: 'github',
        type: 'github_repo',
        value: repo.fullName,
        rawData: { ...repo },
        confidence: 'high',
        severity: 'info',
        sourceUrl: repo.url,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: `Stars: ${repo.stars}. Language: ${repo.language ?? 'unknown'}.`,
      });
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(
      ctx.env.DB,
      execId,
      result.isRateLimited ? 'rate_limited' : 'completed',
      findings.length,
      result.error
    );
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- VirusTotal runner ----
async function runVtCollector(ctx: OrchestratorContext, target: string, targetType: 'domain' | 'ip' | 'url'): Promise<void> {
  if (!ctx.env.VIRUSTOTAL_API_KEY) {
    const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'virustotal');
    await updateCollectorExecution(ctx.env.DB, execId, 'unconfigured', 0, 'VIRUSTOTAL_API_KEY not configured.');
    return;
  }

  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'virustotal');
  try {
    const result = targetType === 'domain'
      ? await collectVtDomain(target, ctx.env.VIRUSTOTAL_API_KEY)
      : targetType === 'ip'
        ? await collectVtIp(target, ctx.env.VIRUSTOTAL_API_KEY)
        : await collectVtUrl(target, ctx.env.VIRUSTOTAL_API_KEY);

    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;
    const ti = result.threatIntel;

    if (ti.total !== null && ti.total > 0) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'threat_intelligence',
        subcategory: 'virustotal',
        type: 'vt_analysis',
        value: `${ti.positives ?? 0}/${ti.total} engines flagged`,
        rawData: { ...ti, tags: result.tags, categories: result.categories },
        confidence: ti.positives! > 2 ? 'high' : 'medium',
        severity: ti.positives! > 5 ? 'high' : ti.positives! > 0 ? 'medium' : 'info',
        sourceUrl: result.permalink ?? null,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: ti.positives! > 0
          ? `${ti.positives} out of ${ti.total} security vendors flagged this resource.`
          : 'No security vendors flagged this resource.',
      });
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, result.error ? 'failed' : 'completed', findings.length, result.error);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- URL Metadata collector ----
async function runUrlMetadataCollector(ctx: OrchestratorContext, url: string): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'url_metadata');
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname;

    // Fetch with strict limits
    const resp = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; OpenSpective/0.1; +https://openspective.com/bot)',
        Accept: 'text/html,application/xhtml+xml',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
    });

    const findings: Omit<Finding, 'id'>[] = [];
    const ts = nowIso();

    findings.push({
      investigationId: ctx.investigationId,
      collectorExecutionId: execId,
      category: 'url_metadata',
      subcategory: 'http_status',
      type: 'http_status',
      value: String(resp.status),
      rawData: { status: resp.status, url, finalUrl: resp.url, headers: Object.fromEntries([...resp.headers.entries()].filter(([k]) => !['set-cookie', 'cookie'].includes(k))) },
      confidence: 'high',
      severity: 'info',
      sourceUrl: url,
      sourceName: 'HTTP Request (single, bounded)',
      firstSeen: ts,
      lastSeen: ts,
      isInferred: false,
      notes: `Final URL: ${resp.url}`,
    });

    // Extract title from HTML (simple regex — not parsing full DOM)
    const contentType = resp.headers.get('content-type') ?? '';
    if (contentType.includes('text/html')) {
      const text = await resp.text().then(t => t.slice(0, 50000)); // cap at 50KB
      const titleMatch = text.match(/<title[^>]*>([^<]{0,300})<\/title>/i);
      if (titleMatch && titleMatch[1]) {
        findings.push({
          investigationId: ctx.investigationId,
          collectorExecutionId: execId,
          category: 'url_metadata',
          subcategory: 'page_title',
          type: 'page_title',
          value: titleMatch[1].trim(),
          rawData: { title: titleMatch[1].trim(), url },
          confidence: 'high',
          severity: 'info',
          sourceUrl: url,
          sourceName: 'HTTP Request (single, bounded)',
          firstSeen: ts,
          lastSeen: ts,
          isInferred: false,
          notes: null,
        });
      }
    }

    // Add domain relationship
    await persistRelationship(ctx.env.DB, {
      investigationId: ctx.investigationId,
      fromEntityType: 'url',
      toEntityType: 'domain',
      fromValue: url,
      toValue: domain,
      relationshipType: 'resolves_to',
      findingId: null,
      sourceUrl: url,
      confidence: 'high',
      isInferred: false,
      collectedAt: ts,
      fromEntityId: '',
      toEntityId: '',
    });

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, null);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- Person Search runner ----
async function runPersonSearchCollector(ctx: OrchestratorContext, name: string): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'person_search');
  try {
    const result = await collectPersonSearch(name, ctx.env.GITHUB_TOKEN);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    // 1. GitHub User Matches
    for (const gh of result.github) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'public_profile',
        subcategory: 'github',
        type: 'github_user_match',
        value: gh.displayName || String(gh.metadata?.login ?? name),
        rawData: { ...gh },
        confidence: gh.confidence,
        severity: 'info',
        sourceUrl: gh.profileUrl,
        sourceName: gh.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: [
          gh.bio ? `Bio: ${gh.bio}` : null,
          gh.location ? `Location: ${gh.location}` : null,
          gh.metadata?.company ? `Company: ${gh.metadata.company}` : null,
        ].filter(Boolean).join(' | ') || `Public profile: ${gh.profileUrl}`,
      });

      if (gh.displayName || gh.metadata?.login) {
        await persistRelationship(ctx.env.DB, {
          investigationId: ctx.investigationId,
          fromEntityType: 'person',
          toEntityType: 'username',
          fromValue: name,
          toValue: String(gh.metadata?.login ?? gh.displayName),
          relationshipType: 'affiliated_with',
          findingId: null,
          sourceUrl: gh.profileUrl,
          confidence: gh.confidence,
          isInferred: false,
          collectedAt: ts,
          fromEntityId: '',
          toEntityId: '',
        });
      }

      if (gh.location) {
        const mapsUrl = `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(gh.location)}`;
        await persistRelationship(ctx.env.DB, {
          investigationId: ctx.investigationId,
          fromEntityType: 'person',
          toEntityType: 'location',
          fromValue: name,
          toValue: gh.location,
          relationshipType: 'located_in',
          findingId: null,
          sourceUrl: mapsUrl,
          confidence: gh.confidence,
          isInferred: false,
          collectedAt: ts,
          fromEntityId: '',
          toEntityId: '',
        });
        await persistRelationship(ctx.env.DB, {
          investigationId: ctx.investigationId,
          fromEntityType: 'location',
          toEntityType: 'url',
          fromValue: gh.location,
          toValue: mapsUrl,
          relationshipType: 'resolves_to',
          findingId: null,
          sourceUrl: mapsUrl,
          confidence: gh.confidence,
          isInferred: false,
          collectedAt: ts,
          fromEntityId: '',
          toEntityId: '',
        });
      }
    }

    // 2. Git Commit Authorship Matches
    const seenEmails = new Set<string>();
    const seenRepos = new Set<string>();

    for (const c of result.gitCommits ?? []) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'developer_activity',
        subcategory: 'git_commit',
        type: 'git_commit',
        value: `${c.repo}@${c.sha}: ${c.message}`,
        rawData: { ...c },
        confidence: 'high',
        severity: 'info',
        sourceUrl: c.commitUrl,
        sourceName: 'GitHub Commit Authorship',
        firstSeen: c.date || ts,
        lastSeen: c.date || ts,
        isInferred: false,
        notes: `Repo: ${c.repo} | Author: ${c.authorName} | Commit: ${c.message}`,
      });

      if (c.repo && !seenRepos.has(c.repo)) {
        seenRepos.add(c.repo);
        await persistRelationship(ctx.env.DB, {
          investigationId: ctx.investigationId,
          fromEntityType: 'person',
          toEntityType: 'repository',
          fromValue: name,
          toValue: c.repo,
          relationshipType: 'affiliated_with',
          findingId: null,
          sourceUrl: c.repoUrl || c.commitUrl,
          confidence: 'high',
          isInferred: false,
          collectedAt: ts,
          fromEntityId: '',
          toEntityId: '',
        });
      }

      if (c.authorEmail && !c.authorEmail.includes('noreply') && !seenEmails.has(c.authorEmail)) {
        seenEmails.add(c.authorEmail);
        findings.push({
          investigationId: ctx.investigationId,
          collectorExecutionId: execId,
          category: 'identity_attribution',
          subcategory: 'email',
          type: 'git_author_email',
          value: c.authorEmail,
          rawData: { email: c.authorEmail, authorName: c.authorName, repo: c.repo },
          confidence: 'high',
          severity: 'info',
          sourceUrl: c.commitUrl,
          sourceName: 'Git Verified Identity',
          firstSeen: c.date || ts,
          lastSeen: c.date || ts,
          isInferred: false,
          notes: `Discovered public email <${c.authorEmail}> from author commits in repository ${c.repo}.`,
        });

        await persistRelationship(ctx.env.DB, {
          investigationId: ctx.investigationId,
          fromEntityType: 'person',
          toEntityType: 'email',
          fromValue: name,
          toValue: c.authorEmail,
          relationshipType: 'affiliated_with',
          findingId: null,
          sourceUrl: c.commitUrl,
          confidence: 'high',
          isInferred: false,
          collectedAt: ts,
          fromEntityId: '',
          toEntityId: '',
        });
      }
    }

    // 3. Wikipedia Articles
    for (const wiki of result.wikipedia) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'public_record',
        subcategory: 'wikipedia',
        type: 'wikipedia_article',
        value: wiki.displayName || name,
        rawData: { ...wiki },
        confidence: wiki.confidence,
        severity: 'info',
        sourceUrl: wiki.profileUrl,
        sourceName: wiki.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: wiki.bio ? `Article summary: ${wiki.bio}` : 'Wikipedia entry found.',
      });
    }

    // 3. Wikidata Knowledge Graph
    for (const wd of result.wikidata) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'public_record',
        subcategory: 'wikidata',
        type: 'wikidata_entity',
        value: wd.displayName || name,
        rawData: { ...wd },
        confidence: wd.confidence,
        severity: 'info',
        sourceUrl: wd.profileUrl,
        sourceName: wd.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: wd.bio ? `Knowledge entity: ${wd.bio}` : 'Wikidata knowledge entity.',
      });
    }

    // 4. HackerNews Mentions
    for (const hn of result.hackernews) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'public_mention',
        subcategory: 'hackernews',
        type: 'hackernews_mention',
        value: hn.displayName || name,
        rawData: { ...hn },
        confidence: 'low',
        severity: 'info',
        sourceUrl: hn.profileUrl,
        sourceName: hn.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: hn.bio || 'Public mention found in Hacker News discussion.',
      });
    }

    // If 0 findings, record structured informative finding
    if (findings.length === 0) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'system',
        subcategory: 'passive_recon',
        type: 'no_records_found',
        value: `No indexed public profiles found for "${name}" across GitHub, Wikipedia, Wikidata, or Hacker News.`,
        rawData: { queriedTarget: name, sourcesChecked: ['GitHub', 'Wikipedia', 'Wikidata', 'HackerNews'] },
        confidence: 'high',
        severity: 'info',
        sourceUrl: null,
        sourceName: 'OpenSpective Passive Recon',
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: 'Tip: Passive OSINT queries open public registries. Try searching by specific username, handle, domain, or email address.',
      });
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, null);

    // Automatically connect the dots: gather physical location clues and commit timestamp offsets
    const extractedLocations: string[] = [];
    const commitDates: string[] = [];
    for (const gh of result.github) {
      if (gh.location) extractedLocations.push(gh.location);
    }
    for (const c of result.gitCommits ?? []) {
      if (c.date) commitDates.push(c.date);
    }
    if (extractedLocations.length > 0 || commitDates.length > 0) {
      await runLocationCollector(ctx, extractedLocations, commitDates);
    }
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- Username Presence runner ----
async function runUsernamePresenceCollector(ctx: OrchestratorContext, username: string): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'username_presence');
  try {
    const results = await checkUsernamePresence(username);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = nowIso();

    const foundResults = results.filter(r => r.status === 'found');
    for (const r of foundResults) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'social_profile',
        subcategory: r.platform.toLowerCase(),
        type: 'account_presence',
        value: `${r.platform}: ${username}`,
        rawData: { ...r },
        confidence: 'medium',
        severity: 'info',
        sourceUrl: r.url,
        sourceName: `${r.platform} Public Web`,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: [
          `Public profile found at ${r.url}`,
          r.displayName ? `Name: ${r.displayName}` : null,
          r.location ? `Location: ${r.location}` : null,
          r.bio ? `Bio: ${r.bio}` : null,
        ].filter(Boolean).join(' | '),
      });

      await persistRelationship(ctx.env.DB, {
        investigationId: ctx.investigationId,
        fromEntityType: 'username',
        toEntityType: 'url',
        fromValue: username,
        toValue: r.url,
        relationshipType: 'affiliated_with',
        findingId: null,
        sourceUrl: r.url,
        confidence: 'medium',
        isInferred: false,
        collectedAt: ts,
        fromEntityId: '',
        toEntityId: '',
      });

      if (r.location) {
        const mapsUrl = `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(r.location)}`;
        await persistRelationship(ctx.env.DB, {
          investigationId: ctx.investigationId,
          fromEntityType: 'username',
          toEntityType: 'location',
          fromValue: username,
          toValue: r.location,
          relationshipType: 'located_in',
          findingId: null,
          sourceUrl: mapsUrl,
          confidence: 'medium',
          isInferred: false,
          collectedAt: ts,
          fromEntityId: '',
          toEntityId: '',
        });
        await persistRelationship(ctx.env.DB, {
          investigationId: ctx.investigationId,
          fromEntityType: 'location',
          toEntityType: 'url',
          fromValue: r.location,
          toValue: mapsUrl,
          relationshipType: 'resolves_to',
          findingId: null,
          sourceUrl: mapsUrl,
          confidence: 'medium',
          isInferred: false,
          collectedAt: ts,
          fromEntityId: '',
          toEntityId: '',
        });
      }
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, null);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- Email & Identity Intelligence runner ----
async function runEmailIdentityCollector(ctx: OrchestratorContext, email: string): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'email_identity');
  try {
    const result = await collectEmailIdentity(email, ctx.env.GITHUB_TOKEN);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    for (const f of result.findings) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: f.category,
        subcategory: f.subcategory ?? null,
        type: f.type,
        value: f.value,
        rawData: f.rawData,
        confidence: f.confidence,
        severity: f.severity,
        sourceUrl: f.sourceUrl ?? null,
        sourceName: f.sourceName,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: f.notes ?? null,
      });

      if (f.relationships) {
        for (const rel of f.relationships) {
          await persistRelationship(ctx.env.DB, {
            investigationId: ctx.investigationId,
            fromEntityType: 'email',
            toEntityType: rel.toEntityType,
            fromValue: email,
            toValue: rel.toValue,
            relationshipType: rel.relationshipType,
            findingId: null,
            sourceUrl: f.sourceUrl ?? null,
            confidence: f.confidence,
            isInferred: false,
            collectedAt: ts,
            fromEntityId: '',
            toEntityId: '',
          });
        }
      }
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, null);

    // Automated correlation: Extract locations and git commit dates from email findings
    const emailLocs: string[] = [];
    const emailDates: string[] = [];
    for (const f of result.findings) {
      if (f.rawData && typeof f.rawData['location'] === 'string' && f.rawData['location']) {
        emailLocs.push(f.rawData['location'] as string);
      }
      if (f.rawData && typeof f.rawData['date'] === 'string' && f.rawData['date']) {
        emailDates.push(f.rawData['date'] as string);
      }
    }
    if (emailLocs.length > 0 || emailDates.length > 0) {
      await runLocationCollector(ctx, emailLocs, emailDates);
    }
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- Wayback Machine Archive runner ----
async function runWebArchiveCollector(ctx: OrchestratorContext, domain: string): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'web_archive');
  try {
    const result = await collectWebArchive(domain);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    if (result.totalSnapshotsFound > 0) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'historical_archive',
        subcategory: 'wayback_snapshots',
        type: 'archive_history_summary',
        value: `${result.totalSnapshotsFound} snapshots archived (First seen: ${result.firstSeen ?? 'unknown'})`,
        rawData: { ...result },
        confidence: 'high',
        severity: 'info',
        sourceUrl: `https://web.archive.org/web/*/${result.domain}`,
        sourceName: result.source,
        firstSeen: result.firstSeen ?? ts,
        lastSeen: result.lastSeen ?? ts,
        isInferred: false,
        notes: `Domain first archived on ${result.firstSeen}. Latest snapshot: ${result.lastSeen}.`,
      });

      for (const p of result.interestingPaths) {
        findings.push({
          investigationId: ctx.investigationId,
          collectorExecutionId: execId,
          category: 'historical_archive',
          subcategory: 'interesting_endpoint',
          type: 'archive_historical_path',
          value: p,
          rawData: { path: p, domain: result.domain },
          confidence: 'medium',
          severity: 'info',
          sourceUrl: `https://web.archive.org/web/*/${result.domain}${p}`,
          sourceName: result.source,
          firstSeen: ts,
          lastSeen: ts,
          isInferred: false,
          notes: `Historical endpoint indexed in Wayback Machine.`,
        });
      }
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, result.error ?? null);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- Tech Stack & Security Headers runner ----
async function runTechStackCollector(ctx: OrchestratorContext, target: string): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'tech_stack');
  try {
    const result = await collectTechStack(target);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    // Overall Security Grade
    findings.push({
      investigationId: ctx.investigationId,
      collectorExecutionId: execId,
      category: 'security_posture',
      subcategory: 'security_headers',
      type: 'security_hygiene_score',
      value: `Grade: ${result.securityGrade} (Score: ${result.securityScore}/100)`,
      rawData: { ...result },
      confidence: 'high',
      severity: result.securityScore < 50 ? 'high' : result.securityScore < 75 ? 'medium' : 'info',
      sourceUrl: result.finalUrl,
      sourceName: result.source,
      firstSeen: ts,
      lastSeen: ts,
      isInferred: false,
      notes: `Evaluated ${result.headersChecked.length} defense-in-depth headers. Missing critical: ${result.missingCriticalHeaders.join(', ') || 'None'}.`,
    });

    // Server & CDN/WAF
    if (result.server || result.poweredBy) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'technology',
        subcategory: 'web_server',
        type: 'server_signature',
        value: [result.server ? `Server: ${result.server}` : null, result.poweredBy ? `Powered-By: ${result.poweredBy}` : null].filter(Boolean).join(' | '),
        rawData: { server: result.server, poweredBy: result.poweredBy },
        confidence: 'high',
        severity: 'info',
        sourceUrl: result.finalUrl,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: 'Public web server banner exposed in HTTP headers.',
      });
    }

    if (result.cdnWaf) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'technology',
        subcategory: 'cdn_waf',
        type: 'proxy_shield',
        value: `Protected by ${result.cdnWaf}`,
        rawData: { cdnWaf: result.cdnWaf },
        confidence: 'high',
        severity: 'info',
        sourceUrl: result.finalUrl,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: `Traffic routed through ${result.cdnWaf} edge network. Origin server IP may be shielded.`,
      });
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, result.error ?? null);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- Crypto Forensics runner ----
async function runCryptoCollector(ctx: OrchestratorContext, address: string): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'crypto');
  try {
    const result = await collectCryptoWallet(address);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    if (result.isValid) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'financial_forensics',
        subcategory: result.network,
        type: 'crypto_wallet_profile',
        value: `${result.network.toUpperCase()}: ${result.address}`,
        rawData: { ...result },
        confidence: 'high',
        severity: 'info',
        sourceUrl: result.explorerUrl,
        sourceName: result.source,
        firstSeen: result.firstActivity ?? ts,
        lastSeen: result.lastActivity ?? ts,
        isInferred: false,
        notes: [
          result.balanceFormatted ? `Balance: ${result.balanceFormatted}` : null,
          result.transactionCount != null ? `Transactions: ${result.transactionCount}` : null,
          result.totalReceivedFormatted ? `Total Received: ${result.totalReceivedFormatted}` : null,
        ].filter(Boolean).join(' | ') || `Valid ${result.network} blockchain address.`,
      });

      await persistRelationship(ctx.env.DB, {
        investigationId: ctx.investigationId,
        fromEntityType: 'crypto_wallet',
        toEntityType: 'url',
        fromValue: address,
        toValue: result.explorerUrl,
        relationshipType: 'affiliated_with',
        findingId: null,
        sourceUrl: result.explorerUrl,
        confidence: 'high',
        isInferred: false,
        collectedAt: ts,
        fromEntityId: '',
        toEntityId: '',
      });
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, result.error ?? null);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- Breach & Credential Exposure runner ----
async function runBreachCollector(ctx: OrchestratorContext, target: string, targetType: 'email' | 'domain' | 'username'): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'breach');
  try {
    const result = await collectBreachIntelligence(target, targetType, ctx.env.HAVE_I_BEEN_PWNED_API_KEY);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    if (result.isPwned) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'threat_intelligence',
        subcategory: 'breach_exposure',
        type: 'compromised_credential_alert',
        value: `Compromised in ${result.breachCount} known breach event(s)`,
        rawData: { ...result },
        confidence: 'high',
        severity: result.riskLevel === 'critical' ? 'critical' : result.riskLevel === 'high' ? 'high' : 'medium',
        sourceUrl: null,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: `Compromised attributes: ${result.compromisedDataClasses.join(', ')}.`,
      });

      for (const b of result.breaches.slice(0, 10)) {
        findings.push({
          investigationId: ctx.investigationId,
          collectorExecutionId: execId,
          category: 'threat_intelligence',
          subcategory: 'breach_event',
          type: 'breach_record',
          value: `${b.title} (${b.breachDate})`,
          rawData: { ...b },
          confidence: 'high',
          severity: 'medium',
          sourceUrl: b.domain ? `https://${b.domain}` : null,
          sourceName: result.source,
          firstSeen: b.breachDate || ts,
          lastSeen: b.addedDate || ts,
          isInferred: false,
          notes: b.description,
        });
      }
    } else {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'threat_intelligence',
        subcategory: 'breach_exposure',
        type: 'clean_exposure_status',
        value: `No documented public data breaches recorded for ${target}.`,
        rawData: { target, checkedAt: ts },
        confidence: 'medium',
        severity: 'none',
        sourceUrl: null,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: 'Target was not identified in monitored public breach corpuses.',
      });
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, result.error ?? null);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- Geolocation & Places Intelligence runner ----
async function runLocationCollector(
  ctx: OrchestratorContext,
  locationClues: string[],
  commitDates: string[] = []
): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'location');
  try {
    const result = await collectLocationIntelligence(locationClues, commitDates);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    // 1. Geocoded physical locations
    for (const loc of result.resolvedLocations) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'location_intelligence',
        subcategory: 'geocoding',
        type: 'geocoded_location',
        value: loc.displayName,
        rawData: { ...loc },
        confidence: loc.confidence,
        severity: 'info',
        sourceUrl: loc.googleMapsCoordUrl,
        sourceName: loc.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: `Physical Location: ${loc.city || ''} ${loc.state || ''} ${loc.country || ''} | Coordinates: ${loc.lat}, ${loc.lon} | Google Maps: ${loc.googleMapsCoordUrl}`,
      });

      // Connect the dots on the knowledge graph:
      // Entity -> Location
      await persistRelationship(ctx.env.DB, {
        investigationId: ctx.investigationId,
        fromEntityType: (['person', 'email', 'username', 'organization', 'ip'].includes(ctx.targetType) ? ctx.targetType : 'person') as any,
        toEntityType: 'location',
        fromValue: ctx.target,
        toValue: loc.displayName,
        relationshipType: 'located_in',
        findingId: null,
        sourceUrl: loc.googleMapsCoordUrl,
        confidence: 'high',
        isInferred: false,
        collectedAt: ts,
        fromEntityId: '',
        toEntityId: '',
      });

      // Location -> Google Maps URL
      await persistRelationship(ctx.env.DB, {
        investigationId: ctx.investigationId,
        fromEntityType: 'location',
        toEntityType: 'url',
        fromValue: loc.displayName,
        toValue: loc.googleMapsCoordUrl,
        relationshipType: 'resolves_to',
        findingId: null,
        sourceUrl: loc.googleMapsCoordUrl,
        confidence: 'high',
        isInferred: false,
        collectedAt: ts,
        fromEntityId: '',
        toEntityId: '',
      });
    }

    // 2. Commit Timezone Inferences
    for (const tz of result.timezoneInferences) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'location_intelligence',
        subcategory: 'timezone_inference',
        type: 'commit_timezone_signature',
        value: `${tz.timezoneName} (${tz.offset})`,
        rawData: { ...tz },
        confidence: 'medium',
        severity: 'info',
        sourceUrl: null,
        sourceName: 'Git Timestamp Temporal Analysis',
        firstSeen: tz.sampleCommitDate || ts,
        lastSeen: tz.sampleCommitDate || ts,
        isInferred: true,
        notes: `Git author commit offset ${tz.offset} establishes regional presence in: ${tz.likelyRegions.join(', ')}. Sample commit: ${tz.sampleCommitDate || 'N/A'}.`,
      });

      for (const region of tz.likelyRegions) {
        await persistRelationship(ctx.env.DB, {
          investigationId: ctx.investigationId,
          fromEntityType: (['person', 'email', 'username', 'organization', 'ip'].includes(ctx.targetType) ? ctx.targetType : 'person') as any,
          toEntityType: 'location',
          fromValue: ctx.target,
          toValue: region,
          relationshipType: 'located_in',
          findingId: null,
          sourceUrl: null,
          confidence: 'medium',
          isInferred: true,
          collectedAt: ts,
          fromEntityId: '',
          toEntityId: '',
        });
      }
    }

    // If no locations could be resolved
    if (findings.length === 0) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'location_intelligence',
        subcategory: 'passive_recon',
        type: 'no_location_clues',
        value: `No physical location tags or commit timezones identified for ${ctx.target}.`,
        rawData: { cluesChecked: locationClues, commitDatesChecked: commitDates },
        confidence: 'medium',
        severity: 'info',
        sourceUrl: null,
        sourceName: 'OpenSpective Geolocation Engine',
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: 'Target does not expose public location clues or git commit timezone signatures in public profiles.',
      });
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, null);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- Shodan InternetDB Passive Intelligence runner ----
async function runShodanCollector(ctx: OrchestratorContext, target: string, isDomain: boolean = false): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'shodan');
  try {
    let targetIp = target;
    if (isDomain) {
      try {
        const dnsRes = await collectDns(target);
        const aRecord = dnsRes.records.find(r => r.type === 'A');
        if (aRecord) {
          targetIp = aRecord.value;
        } else {
          await updateCollectorExecution(ctx.env.DB, execId, 'completed', 0, 'No A record resolved for domain');
          return;
        }
      } catch {
        await updateCollectorExecution(ctx.env.DB, execId, 'completed', 0, 'DNS resolution failed before Shodan query');
        return;
      }
    }

    const result = await collectShodanInternetDb(targetIp);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    if (result.hasData) {
      // 1. Passive open ports
      if (result.ports.length > 0) {
        const highRiskPorts = [21, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017];
        const hasRisk = result.ports.some(p => highRiskPorts.includes(p));
        findings.push({
          investigationId: ctx.investigationId,
          collectorExecutionId: execId,
          category: 'infrastructure',
          subcategory: 'open_ports',
          type: 'passive_open_ports',
          value: `Observed Ports: ${result.ports.join(', ')}`,
          rawData: { ip: targetIp, ports: result.ports },
          confidence: 'high',
          severity: hasRisk ? 'medium' : 'info',
          sourceUrl: `https://internetdb.shodan.io/${targetIp}`,
          sourceName: result.source,
          firstSeen: ts,
          lastSeen: ts,
          isInferred: false,
          notes: `Passive reconnaissance discovered ${result.ports.length} open port(s) on ${targetIp}. High-risk services: ${result.ports.filter(p => highRiskPorts.includes(p)).join(', ') || 'None'}.`,
        });
      }

      // 2. Known CVEs
      if (result.cves.length > 0) {
        findings.push({
          investigationId: ctx.investigationId,
          collectorExecutionId: execId,
          category: 'threat_intelligence',
          subcategory: 'vulnerabilities',
          type: 'known_cves_summary',
          value: `${result.cves.length} Known CVE(s) Indexed: ${result.cves.slice(0, 5).join(', ')}${result.cves.length > 5 ? '...' : ''}`,
          rawData: { ip: targetIp, cves: result.cves },
          confidence: 'high',
          severity: 'high',
          sourceUrl: `https://internetdb.shodan.io/${targetIp}`,
          sourceName: result.source,
          firstSeen: ts,
          lastSeen: ts,
          isInferred: false,
          notes: `Shodan passive vulnerability index matched ${result.cves.length} published CVEs against services operating on this IP.`,
        });

        for (const cve of result.cves.slice(0, 10)) {
          findings.push({
            investigationId: ctx.investigationId,
            collectorExecutionId: execId,
            category: 'threat_intelligence',
            subcategory: 'cve_vulnerability',
            type: 'known_cve',
            value: cve,
            rawData: { ip: targetIp, cve },
            confidence: 'high',
            severity: 'high',
            sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve}`,
            sourceName: 'NVD / Shodan',
            firstSeen: ts,
            lastSeen: ts,
            isInferred: false,
            notes: `Passive vulnerability detection for ${targetIp}. Reference: https://nvd.nist.gov/vuln/detail/${cve}`,
          });
        }
      }

      // 3. Reverse Hostnames
      if (result.hostnames.length > 0) {
        findings.push({
          investigationId: ctx.investigationId,
          collectorExecutionId: execId,
          category: 'infrastructure',
          subcategory: 'passive_dns',
          type: 'reverse_hostnames',
          value: result.hostnames.join(', '),
          rawData: { ip: targetIp, hostnames: result.hostnames },
          confidence: 'high',
          severity: 'info',
          sourceUrl: `https://internetdb.shodan.io/${targetIp}`,
          sourceName: result.source,
          firstSeen: ts,
          lastSeen: ts,
          isInferred: false,
          notes: `Reverse hostnames observed by Shodan sensors.`,
        });

        for (const host of result.hostnames.slice(0, 5)) {
          await persistRelationship(ctx.env.DB, {
            investigationId: ctx.investigationId,
            fromEntityType: 'ip',
            toEntityType: 'domain',
            fromValue: targetIp,
            toValue: host,
            relationshipType: 'resolves_to',
            findingId: null,
            sourceUrl: `https://internetdb.shodan.io/${targetIp}`,
            confidence: 'high',
            isInferred: false,
            collectedAt: ts,
            fromEntityId: '',
            toEntityId: '',
          });
        }
      }

      // 4. Software CPEs
      if (result.cpes.length > 0) {
        findings.push({
          investigationId: ctx.investigationId,
          collectorExecutionId: execId,
          category: 'technology',
          subcategory: 'cpe_signatures',
          type: 'software_cpe',
          value: result.cpes.slice(0, 6).join(', '),
          rawData: { ip: targetIp, cpes: result.cpes },
          confidence: 'high',
          severity: 'info',
          sourceUrl: `https://internetdb.shodan.io/${targetIp}`,
          sourceName: result.source,
          firstSeen: ts,
          lastSeen: ts,
          isInferred: false,
          notes: `Common Platform Enumeration (CPE) signatures passively captured for ${targetIp}.`,
        });

        for (const cpe of result.cpes.slice(0, 4)) {
          await persistRelationship(ctx.env.DB, {
            investigationId: ctx.investigationId,
            fromEntityType: 'ip',
            toEntityType: 'technology',
            fromValue: targetIp,
            toValue: cpe,
            relationshipType: 'technology_uses',
            findingId: null,
            sourceUrl: `https://internetdb.shodan.io/${targetIp}`,
            confidence: 'medium',
            isInferred: false,
            collectedAt: ts,
            fromEntityId: '',
            toEntityId: '',
          });
        }
      }
    } else {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'infrastructure',
        subcategory: 'passive_shodan',
        type: 'shodan_unindexed',
        value: `No open ports or public CVE vulnerabilities indexed for IP ${targetIp}.`,
        rawData: { ip: targetIp, checkedAt: ts },
        confidence: 'high',
        severity: 'none',
        sourceUrl: `https://internetdb.shodan.io/${targetIp}`,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: 'Target IP is not currently exposing ports indexed in Shodan InternetDB.',
      });
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, result.error ?? null);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- International Phone Number Intelligence runner ----
async function runPhoneCollector(ctx: OrchestratorContext, phone: string): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'phone');
  try {
    const result = await collectPhoneIntelligence(phone);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    // 1. Phone attribution profile
    findings.push({
      investigationId: ctx.investigationId,
      collectorExecutionId: execId,
      category: 'identity',
      subcategory: 'phone_intelligence',
      type: 'phone_profile',
      value: `${result.internationalFormat} — ${result.countryName} (${result.lineType.toUpperCase()})`,
      rawData: { ...result },
      confidence: result.validLength ? 'high' : 'medium',
      severity: 'info',
      sourceUrl: null,
      sourceName: result.source,
      firstSeen: ts,
      lastSeen: ts,
      isInferred: false,
      notes: `ITU-T E.164 Profile: Country: ${result.countryName} (+${result.countryCode}), Region: ${result.region}, Line Type: ${result.lineType}, Length Valid: ${result.validLength ? 'Yes' : 'No'}.`,
    });

    // 2. Geolocation attribution & map coordinates
    if (result.coordinates) {
      const mapUrl = `https://maps.google.com/?q=${result.coordinates.lat},${result.coordinates.lon}`;
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'location_intelligence',
        subcategory: 'phone_origin',
        type: 'telecom_country_attribution',
        value: `${result.countryName} (${result.region})`,
        rawData: { country: result.countryName, coordinates: result.coordinates },
        confidence: 'high',
        severity: 'info',
        sourceUrl: mapUrl,
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: `Phone dial plan allocated to ${result.countryName}. Geographic centroid: ${result.coordinates.lat}, ${result.coordinates.lon}.`,
      });

      await persistRelationship(ctx.env.DB, {
        investigationId: ctx.investigationId,
        fromEntityType: 'phone',
        toEntityType: 'location',
        fromValue: result.e164Format || phone,
        toValue: result.countryName,
        relationshipType: 'located_in',
        findingId: null,
        sourceUrl: mapUrl,
        confidence: 'high',
        isInferred: false,
        collectedAt: ts,
        fromEntityId: '',
        toEntityId: '',
      });
    }

    // 3. OSINT Pivot Links
    for (const pivot of result.osintPivots) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'reconnaissance',
        subcategory: 'osint_pivot',
        type: 'osint_search_dork',
        value: `${pivot.name}: ${pivot.description}`,
        rawData: { ...pivot },
        confidence: 'high',
        severity: 'info',
        sourceUrl: pivot.url,
        sourceName: 'OpenSpective OSINT Dork Engine',
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: `OSINT Investigation Query: ${pivot.url}`,
      });

      await persistRelationship(ctx.env.DB, {
        investigationId: ctx.investigationId,
        fromEntityType: 'phone',
        toEntityType: 'url',
        fromValue: result.e164Format || phone,
        toValue: pivot.url,
        relationshipType: 'mentions',
        findingId: null,
        sourceUrl: pivot.url,
        confidence: 'medium',
        isInferred: false,
        collectedAt: ts,
        fromEntityId: '',
        toEntityId: '',
      });
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, result.error ?? null);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ---- DNS & Email Security Hygiene runner ----
async function runDnsSecurityCollector(ctx: OrchestratorContext, domain: string): Promise<void> {
  const execId = await createCollectorExecution(ctx.env.DB, ctx.investigationId, 'dns_security');
  try {
    const result = await collectDnsSecurity(domain);
    const findings: Omit<Finding, 'id'>[] = [];
    const ts = result.collectedAt;

    // 1. Overall Hygiene Score & Grade
    findings.push({
      investigationId: ctx.investigationId,
      collectorExecutionId: execId,
      category: 'security_posture',
      subcategory: 'email_authentication',
      type: 'dns_security_score',
      value: `Grade: ${result.securityGrade} (Score: ${result.securityScore}/100)`,
      rawData: { ...result },
      confidence: 'high',
      severity: result.securityScore < 50 ? 'high' : result.securityScore < 75 ? 'medium' : 'info',
      sourceUrl: 'https://cloudflare-dns.com/dns-query',
      sourceName: result.source,
      firstSeen: ts,
      lastSeen: ts,
      isInferred: false,
      notes: `Defensive posture: SPF: ${result.hasSpf ? 'Configured' : 'Missing'} | DMARC: ${result.hasDmarc ? 'Configured' : 'Missing'} | BIMI: ${result.hasBimi ? 'Configured' : 'Missing'} | MTA-STS: ${result.hasMtaSts ? 'Configured' : 'Missing'} | DNSSEC: ${result.hasDnssec ? 'Configured' : 'Missing'}.`,
    });

    // 2. Individual Security Checks
    for (const check of result.checks) {
      findings.push({
        investigationId: ctx.investigationId,
        collectorExecutionId: execId,
        category: 'security_posture',
        subcategory: 'dns_hygiene_check',
        type: `check_${check.check.toLowerCase().replace(/[^a-z0-9]/g, '_')}`,
        value: `${check.check}: [${check.status.toUpperCase()}] ${check.detail}`,
        rawData: { ...check },
        confidence: 'high',
        severity: check.status === 'fail' ? 'high' : check.status === 'warn' ? 'medium' : 'info',
        sourceUrl: 'https://cloudflare-dns.com/dns-query',
        sourceName: result.source,
        firstSeen: ts,
        lastSeen: ts,
        isInferred: false,
        notes: check.recommendation ? `Recommendation: ${check.recommendation}` : (check.record ? `Record: ${check.record}` : null),
      });
    }

    await persistFindings(ctx.env.DB, findings);
    await updateCollectorExecution(ctx.env.DB, execId, 'completed', findings.length, result.error ?? null);
  } catch (err) {
    await updateCollectorExecution(ctx.env.DB, execId, 'failed', 0, err instanceof Error ? err.message : 'Unknown error');
  }
}

// ============================================================
// Main orchestration entry point
// ============================================================

export async function runInvestigation(ctx: OrchestratorContext): Promise<void> {
  const { investigationId, normalizedTarget, targetType, selectedModules, env } = ctx;

  try {
    await updateInvestigationStatus(env.DB, investigationId, 'running');

    const runners: Array<() => Promise<void>> = [];

    // Determine which collectors to run based on target type and selected modules
    const shouldRun = (name: string) =>
      selectedModules.length === 0 || selectedModules.includes(name);

    switch (targetType) {
      case 'domain': {
        if (shouldRun('dns')) runners.push(() => runDnsCollector(ctx, normalizedTarget));
        if (shouldRun('dns_security')) runners.push(() => runDnsSecurityCollector(ctx, normalizedTarget));
        if (shouldRun('shodan')) runners.push(() => runShodanCollector(ctx, normalizedTarget, true));
        if (shouldRun('rdap')) runners.push(() => runRdapCollector(ctx, normalizedTarget, 'domain'));
        if (shouldRun('certificate_transparency')) runners.push(() => runCertificateCollector(ctx, normalizedTarget));
        if (shouldRun('virustotal')) runners.push(() => runVtCollector(ctx, normalizedTarget, 'domain'));
        if (shouldRun('github')) runners.push(() => runGitHubCollector(ctx, normalizedTarget, false));
        if (shouldRun('web_archive')) runners.push(() => runWebArchiveCollector(ctx, normalizedTarget));
        if (shouldRun('tech_stack')) runners.push(() => runTechStackCollector(ctx, normalizedTarget));
        if (shouldRun('breach')) runners.push(() => runBreachCollector(ctx, normalizedTarget, 'domain'));
        break;
      }

      case 'email': {
        const domain = domainFromEmail(normalizedTarget);
        const isConsumer = [
          'gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'hotmail.com',
          'outlook.com', 'live.com', 'msn.com', 'icloud.com', 'proton.me',
          'protonmail.com', 'zoho.com', 'aol.com', 'mail.com', 'gmx.com'
        ].includes(domain.toLowerCase());

        // Always run deep email & identity intelligence (git commit history, verified author names, Gravatar, handle footprint)
        if (shouldRun('email_identity')) runners.push(() => runEmailIdentityCollector(ctx, normalizedTarget));
        if (shouldRun('breach')) runners.push(() => runBreachCollector(ctx, normalizedTarget, 'email'));
        if (shouldRun('location')) runners.push(() => runLocationCollector(ctx, []));

        // For corporate/custom domains, also run infrastructure DNS/RDAP/CT/WebArchive/Security Hygiene
        if (!isConsumer) {
          if (shouldRun('dns')) runners.push(() => runDnsCollector(ctx, domain));
          if (shouldRun('dns_security')) runners.push(() => runDnsSecurityCollector(ctx, domain));
          if (shouldRun('shodan')) runners.push(() => runShodanCollector(ctx, domain, true));
          if (shouldRun('rdap')) runners.push(() => runRdapCollector(ctx, domain, 'domain'));
          if (shouldRun('certificate_transparency')) runners.push(() => runCertificateCollector(ctx, domain));
          if (shouldRun('web_archive')) runners.push(() => runWebArchiveCollector(ctx, domain));
          if (shouldRun('tech_stack')) runners.push(() => runTechStackCollector(ctx, domain));
        }
        break;
      }

      case 'ip': {
        if (shouldRun('rdap')) runners.push(() => runRdapCollector(ctx, normalizedTarget, 'ip'));
        if (shouldRun('ipinfo')) runners.push(() => runIpInfoCollector(ctx, normalizedTarget));
        if (shouldRun('shodan')) runners.push(() => runShodanCollector(ctx, normalizedTarget, false));
        if (shouldRun('virustotal')) runners.push(() => runVtCollector(ctx, normalizedTarget, 'ip'));
        if (shouldRun('location')) runners.push(() => runLocationCollector(ctx, [normalizedTarget]));
        break;
      }

      case 'url': {
        try {
          const parsedUrl = new URL(normalizedTarget);
          const domain = parsedUrl.hostname;
          if (shouldRun('url_metadata')) runners.push(() => runUrlMetadataCollector(ctx, normalizedTarget));
          if (shouldRun('dns')) runners.push(() => runDnsCollector(ctx, domain));
          if (shouldRun('dns_security')) runners.push(() => runDnsSecurityCollector(ctx, domain));
          if (shouldRun('virustotal')) runners.push(() => runVtCollector(ctx, normalizedTarget, 'url'));
          if (shouldRun('web_archive')) runners.push(() => runWebArchiveCollector(ctx, domain));
          if (shouldRun('tech_stack')) runners.push(() => runTechStackCollector(ctx, normalizedTarget));
        } catch {
          // Invalid URL — skip
        }
        break;
      }

      case 'username': {
        if (shouldRun('github')) runners.push(() => runGitHubCollector(ctx, normalizedTarget, true));
        if (shouldRun('username_presence')) runners.push(() => runUsernamePresenceCollector(ctx, normalizedTarget));
        if (shouldRun('breach')) runners.push(() => runBreachCollector(ctx, normalizedTarget, 'username'));
        if (detectCryptoNetwork(normalizedTarget) !== 'unknown' && shouldRun('crypto')) {
          runners.push(() => runCryptoCollector(ctx, normalizedTarget));
        }
        if (shouldRun('location')) runners.push(() => runLocationCollector(ctx, [normalizedTarget]));
        break;
      }

      case 'crypto_wallet': {
        if (shouldRun('crypto')) runners.push(() => runCryptoCollector(ctx, normalizedTarget));
        break;
      }

      case 'organization': {
        if (shouldRun('github')) runners.push(() => runGitHubCollector(ctx, normalizedTarget, false));
        // Try to find domain — heuristic only
        const slug = normalizedTarget.toLowerCase().replace(/\s+/g, '').replace(/[^a-z0-9]/g, '');
        const candidateDomain = `${slug}.com`;
        if (shouldRun('dns')) runners.push(() => runDnsCollector(ctx, candidateDomain));
        if (shouldRun('dns_security')) runners.push(() => runDnsSecurityCollector(ctx, candidateDomain));
        if (shouldRun('shodan')) runners.push(() => runShodanCollector(ctx, candidateDomain, true));
        if (shouldRun('web_archive')) runners.push(() => runWebArchiveCollector(ctx, candidateDomain));
        if (shouldRun('tech_stack')) runners.push(() => runTechStackCollector(ctx, candidateDomain));
        if (shouldRun('location')) runners.push(() => runLocationCollector(ctx, [normalizedTarget]));
        break;
      }

      case 'person': {
        if (shouldRun('person_search')) runners.push(() => runPersonSearchCollector(ctx, normalizedTarget));
        const candidateSlug = normalizedTarget.toLowerCase().replace(/[^a-z0-9]/g, '');
        if (candidateSlug && candidateSlug.length >= 3 && candidateSlug.length <= 30 && shouldRun('username_presence')) {
          runners.push(() => runUsernamePresenceCollector(ctx, candidateSlug));
        }
        if (shouldRun('location')) runners.push(() => runLocationCollector(ctx, [normalizedTarget]));
        break;
      }

      case 'phone': {
        if (shouldRun('phone')) runners.push(() => runPhoneCollector(ctx, normalizedTarget));
        break;
      }
    }

    // Run all applicable collectors concurrently (with a limit)
    // Process in batches of 3 to avoid overwhelming external services
    for (let i = 0; i < runners.length; i += 3) {
      const batch = runners.slice(i, i + 3);
      await Promise.allSettled(batch.map(fn => fn()));
    }

    // Determine final status
    const executions = await env.DB
      .prepare(`SELECT status FROM collector_executions WHERE investigation_id = ?`)
      .bind(investigationId)
      .all<{ status: string }>();

    const statuses = executions.results.map((r: { status: string }) => r.status);
    const hasCompleted = statuses.some((s: string) => s === 'completed');
    const hasFailed = statuses.some((s: string) => s === 'failed');

    let finalStatus: string;
    if (statuses.length === 0) {
      finalStatus = 'completed'; // no collectors ran — still done
    } else if (hasCompleted && hasFailed) {
      finalStatus = 'partial';
    } else if (!hasCompleted && hasFailed) {
      finalStatus = 'failed';
    } else {
      finalStatus = 'completed';
    }

    await updateInvestigationStatus(env.DB, investigationId, finalStatus);
  } catch (err) {
    await updateInvestigationStatus(
      env.DB,
      investigationId,
      'failed',
      err instanceof Error ? err.message : 'Unknown orchestration error'
    );
  }
}
