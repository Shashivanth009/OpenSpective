// OpenSpective — Investigation Routes
// POST /api/v1/investigations
// GET  /api/v1/investigations
// GET  /api/v1/investigations/:id
// POST /api/v1/investigations/:id/cancel
// GET  /api/v1/investigations/:id/findings
// GET  /api/v1/investigations/:id/graph
// POST /api/v1/investigations/:id/analyze

import { Hono } from 'hono';
import type { Env } from '../env.ts';
import type { AuthUser } from '../middleware/auth.ts';
import { authMiddleware } from '../middleware/auth.ts';
import { investigationRateLimit, apiRateLimit } from '../middleware/ratelimit.ts';
import { classifyTarget, validateTargetForType, normalizeTarget } from '../classifier.ts';
import { getCollectorsForTargetType } from '../collectors/registry.ts';
import { runInvestigation } from '../orchestrator.ts';
import { generateId, nowIso } from '../utils.ts';
import { type TargetType, type CreateInvestigationRequest, type InvestigationGraph, type GraphNode, type GraphEdge, OSINT_TOOLS_REGISTRY } from '@openspective/shared';

type Variables = { user: AuthUser | null };

const GUEST_INVESTIGATION_LIMIT_PER_IP = 50; // generous for evaluation and local dev
const USER_INVESTIGATION_LIMIT_PER_MONTH = 100;

export const investigationsRouter = new Hono<{ Bindings: Env; Variables: Variables }>();

investigationsRouter.use('*', authMiddleware);

// ---- POST /investigations ----
investigationsRouter.post('/', investigationRateLimit, async (c) => {
  const user = c.get('user');
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';

  let body: CreateInvestigationRequest;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body.', code: 'BAD_REQUEST' }, 400);
  }

  const { target, targetType: manualType, modules, enableAi } = body;

  if (!target || typeof target !== 'string' || target.trim().length === 0) {
    return c.json({ error: 'Target is required.', code: 'VALIDATION_ERROR' }, 400);
  }

  if (target.trim().length > 2000) {
    return c.json({ error: 'Target is too long.', code: 'VALIDATION_ERROR' }, 400);
  }

  // Free and open access for all users - no quota limits

  // Classify target
  const classification = classifyTarget(target);
  const resolvedType: TargetType = (manualType ?? classification.targetType) as TargetType;

  if (resolvedType === 'unknown') {
    return c.json({
      error: classification.validationMessage ?? 'Could not classify the target. Please specify a target type.',
      code: 'UNCLASSIFIABLE',
      classification,
    }, 422);
  }

  // Validate for resolved type
  const normalized = normalizeTarget(target, resolvedType);
  const validation = validateTargetForType(normalized, resolvedType);
  if (!validation.valid) {
    return c.json({
      error: validation.message ?? 'Invalid target.',
      code: 'VALIDATION_ERROR',
      classification,
    }, 400);
  }

  // Determine available modules
  const { available, unavailable } = getCollectorsForTargetType(resolvedType, c.env);
  const selectedModules: string[] = Array.isArray(modules) && modules.length > 0
    ? modules
    : [...available.map(a => a.name), ...OSINT_TOOLS_REGISTRY.map(t => t.id)];

  // Create investigation record
  const investigationId = generateId('inv');
  await c.env.DB
    .prepare(
      `INSERT INTO investigations (id, user_id, target, target_type, normalized_target, status, modules, started_at, enable_ai, metadata)
       VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)`
    )
    .bind(
      investigationId,
      user?.id ?? null,
      target.trim(),
      resolvedType,
      normalized,
      JSON.stringify(selectedModules),
      nowIso(),
      enableAi ? 1 : 0,
      JSON.stringify({ classification, manualTypeOverride: !!manualType })
    )
    .run();

  // Track guest investigation
  if (!user) {
    await c.env.DB
      .prepare(`INSERT INTO guest_investigations (id, ip_address, investigation_id, created_at) VALUES (?, ?, ?, ?)`)
      .bind(generateId('gi'), ip, investigationId, nowIso())
      .run();
  }

  // Update usage
  if (user) {
    const period = new Date().toISOString().slice(0, 7);
    await c.env.DB
      .prepare(
        `INSERT INTO usage_records (id, user_id, period, investigation_count) VALUES (?, ?, ?, 1)
         ON CONFLICT(user_id, period) DO UPDATE SET investigation_count = investigation_count + 1`
      )
      .bind(generateId('ur'), user.id, period)
      .run();
  }

  // Extract any custom API credentials passed by client from Settings
  const clientVtKey = c.req.header('x-virustotal-key');
  const clientIpinfoToken = c.req.header('x-ipinfo-token');
  const clientGithubToken = c.req.header('x-github-token');
  const clientShodanKey = c.req.header('x-shodan-key');
  const clientHibpKey = c.req.header('x-hibp-key');

  const effectiveEnv: Env = {
    ...c.env,
    ...(clientVtKey ? { VIRUSTOTAL_API_KEY: clientVtKey } : {}),
    ...(clientIpinfoToken ? { IPINFO_TOKEN: clientIpinfoToken } : {}),
    ...(clientGithubToken ? { GITHUB_TOKEN: clientGithubToken } : {}),
    ...(clientShodanKey ? { SHODAN_API_KEY: clientShodanKey } : {}),
    ...(clientHibpKey ? { HAVE_I_BEEN_PWNED_API_KEY: clientHibpKey } : {}),
  };

  // Run investigation asynchronously (non-blocking)
  const ctx = {
    investigationId,
    target: target.trim(),
    normalizedTarget: normalized,
    targetType: resolvedType,
    selectedModules,
    env: effectiveEnv,
  };

  // Use waitUntil to run in background without holding the response
  c.executionCtx.waitUntil(runInvestigation(ctx));

  const investigation = await c.env.DB
    .prepare(`SELECT * FROM investigations WHERE id = ?`)
    .bind(investigationId)
    .first();

  return c.json({
    investigation,
    classifiedAs: resolvedType,
    classification,
    availableModules: available,
    unavailableModules: unavailable,
  }, 201);
});

// ---- GET /investigations ----
investigationsRouter.get('/', async (c) => {
  const page = Math.max(1, parseInt(c.req.query('page') ?? '1', 10));
  const pageSize = Math.min(50, Math.max(1, parseInt(c.req.query('pageSize') ?? '20', 10)));
  const offset = (page - 1) * pageSize;

  const [items, total] = await Promise.all([
    c.env.DB
      .prepare(`SELECT * FROM investigations ORDER BY started_at DESC LIMIT ? OFFSET ?`)
      .bind(pageSize, offset)
      .all(),
    c.env.DB
      .prepare(`SELECT COUNT(*) as count FROM investigations`)
      .first<{ count: number }>(),
  ]);

  return c.json({
    data: items.results,
    total: total?.count ?? 0,
    page,
    pageSize,
    hasMore: offset + items.results.length < (total?.count ?? 0),
  });
});

// ---- GET /investigations/:id ----
investigationsRouter.get('/:id', async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  const investigation = await c.env.DB
    .prepare(`SELECT * FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) {
    return c.json({ error: 'Investigation not found.', code: 'NOT_FOUND' }, 404);
  }

  // Fetch collector executions
  const executions = await c.env.DB
    .prepare(`SELECT * FROM collector_executions WHERE investigation_id = ? ORDER BY started_at ASC`)
    .bind(id)
    .all();

  // Fetch AI analysis if present
  const aiAnalysis = await c.env.DB
    .prepare(`SELECT * FROM ai_analyses WHERE investigation_id = ? ORDER BY created_at DESC LIMIT 1`)
    .bind(id)
    .first();

  return c.json({ investigation, executions: executions.results, aiAnalysis: aiAnalysis ?? null });
});

// ---- POST /investigations/:id/cancel ----
investigationsRouter.post('/:id/cancel', async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  const investigation = await c.env.DB
    .prepare(`SELECT * FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);

  if (!['queued', 'running'].includes(investigation['status'] as string)) {
    return c.json({ error: 'Investigation is not running.', code: 'INVALID_STATE' }, 409);
  }

  await c.env.DB
    .prepare(`UPDATE investigations SET status = 'cancelled', completed_at = ? WHERE id = ?`)
    .bind(nowIso(), id)
    .run();

  return c.json({ message: 'Cancellation requested. Active collectors may complete their current operation.' });
});

// ---- DELETE /investigations/:id (Delete Single Investigation) ----
investigationsRouter.delete('/:id', async (c) => {
  const { id } = c.req.param();

  const investigation = await c.env.DB
    .prepare(`SELECT id FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);

  // Cascading cleanup across all associated tables
  await c.env.DB.batch([
    c.env.DB.prepare(`DELETE FROM findings WHERE investigation_id = ?`).bind(id),
    c.env.DB.prepare(`DELETE FROM collector_executions WHERE investigation_id = ?`).bind(id),
    c.env.DB.prepare(`DELETE FROM relationships WHERE investigation_id = ?`).bind(id),
    c.env.DB.prepare(`DELETE FROM ai_analyses WHERE investigation_id = ?`).bind(id),
    c.env.DB.prepare(`DELETE FROM guest_investigations WHERE investigation_id = ?`).bind(id),
    c.env.DB.prepare(`DELETE FROM investigations WHERE id = ?`).bind(id),
  ]);

  return c.json({ success: true, message: `Investigation ${id} and all related intelligence findings deleted.` });
});

// ---- DELETE /investigations (Clear All History) ----
investigationsRouter.delete('/', async (c) => {
  const countRes = await c.env.DB.prepare(`SELECT COUNT(*) as count FROM investigations`).first<{ count: number }>();
  const total = countRes?.count ?? 0;

  await c.env.DB.batch([
    c.env.DB.prepare(`DELETE FROM findings`),
    c.env.DB.prepare(`DELETE FROM collector_executions`),
    c.env.DB.prepare(`DELETE FROM relationships`),
    c.env.DB.prepare(`DELETE FROM ai_analyses`),
    c.env.DB.prepare(`DELETE FROM guest_investigations`),
    c.env.DB.prepare(`DELETE FROM investigations`),
  ]);

  return c.json({ success: true, message: `All reconnaissance history cleared (${total} records removed).`, deletedCount: total });
});

// ---- GET /investigations/:id/findings ----
investigationsRouter.get('/:id/findings', async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  const investigation = await c.env.DB
    .prepare(`SELECT user_id FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);

  const category = c.req.query('category');
  const page = Math.max(1, parseInt(c.req.query('page') ?? '1', 10));
  const pageSize = Math.min(500, Math.max(1, parseInt(c.req.query('pageSize') ?? c.req.query('limit') ?? '50', 10)));
  const offset = (page - 1) * pageSize;

  const where = category ? `AND category = ?` : '';
  const params: unknown[] = category ? [id, category, pageSize, offset] : [id, pageSize, offset];

  const [items, total] = await Promise.all([
    c.env.DB
      .prepare(`SELECT * FROM findings WHERE investigation_id = ? ${where} ORDER BY first_seen ASC LIMIT ? OFFSET ?`)
      .bind(...params)
      .all(),
    c.env.DB
      .prepare(`SELECT COUNT(*) as count FROM findings WHERE investigation_id = ? ${where}`)
      .bind(...(category ? [id, category] : [id]))
      .first<{ count: number }>(),
  ]);

  return c.json({
    data: items.results,
    total: total?.count ?? 0,
    page,
    pageSize,
    hasMore: offset + items.results.length < (total?.count ?? 0),
  });
});

// ---- GET /investigations/:id/graph ----
investigationsRouter.get('/:id/graph', async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  const investigation = await c.env.DB
    .prepare(`SELECT user_id, target, target_type FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);

  const [relationships, findingsRes] = await Promise.all([
    c.env.DB
      .prepare(`SELECT * FROM relationships WHERE investigation_id = ? LIMIT 500`)
      .bind(id)
      .all(),
    c.env.DB
      .prepare(`SELECT type, category, value, severity, source_name, notes, source_url FROM findings WHERE investigation_id = ?`)
      .bind(id)
      .all(),
  ]);

  const findingsList = (findingsRes?.results || []) as any[];
  const findingMap = new Map<string, any[]>();
  for (const f of findingsList) {
    const val = String(f['value'] || '').trim().toLowerCase();
    if (!val) continue;
    if (!findingMap.has(val)) findingMap.set(val, []);
    findingMap.get(val)!.push(f);
  }

  const nodeMap = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];

  // Build nodes from relationships
  for (const rel of relationships.results) {
    // Sanity filter: skip malformed domain entities that are actually emails
    if (rel['from_entity_type'] === 'domain' && String(rel['from_value']).includes('@')) continue;
    if (rel['to_entity_type'] === 'domain' && String(rel['to_value']).includes('@')) continue;

    const fromKey = `${rel['from_entity_type']}:${rel['from_value']}`;
    const toKey = `${rel['to_entity_type']}:${rel['to_value']}`;

    if (!nodeMap.has(fromKey)) {
      nodeMap.set(fromKey, {
        id: fromKey,
        type: rel['from_entity_type'] as GraphNode['type'],
        value: rel['from_value'] as string,
        label: rel['from_value'] as string,
        properties: {},
      });
    }
    if (!nodeMap.has(toKey)) {
      nodeMap.set(toKey, {
        id: toKey,
        type: rel['to_entity_type'] as GraphNode['type'],
        value: rel['to_value'] as string,
        label: rel['to_value'] as string,
        properties: {},
      });
    }

    edges.push({
      id: rel['id'] as string,
      source: fromKey,
      target: toKey,
      type: rel['relationship_type'] as GraphEdge['type'],
      label: (rel['relationship_type'] as string).replace(/_/g, ' '),
      confidence: rel['confidence'] as GraphEdge['confidence'],
      isInferred: !!(rel['is_inferred'] as number),
      sourceUrl: rel['source_url'] as string | null,
    });
  }

  // Ensure root target node is always present and marked as isRoot
  const rootKey = `${investigation['target_type']}:${investigation['target']}`;
  if (!nodeMap.has(rootKey)) {
    nodeMap.set(rootKey, {
      id: rootKey,
      type: investigation['target_type'] as GraphNode['type'],
      value: investigation['target'] as string,
      label: investigation['target'] as string,
      properties: { isRoot: true },
    });
  } else {
    const rootNode = nodeMap.get(rootKey)!;
    rootNode.properties = { ...rootNode.properties, isRoot: true };
  }

  // Enrich each node with telemetry findings & provenance
  for (const [key, node] of nodeMap.entries()) {
    const valKey = String(node.value || '').trim().toLowerCase();
    const matched = findingMap.get(valKey) || [];
    const sourceNames = [...new Set(matched.map(m => m.source_name).filter(Boolean))];
    const hasCrit = matched.some(m => m.severity === 'critical');
    const hasHigh = matched.some(m => m.severity === 'high');

    node.properties = {
      ...node.properties,
      findingsCount: matched.length,
      sourceNames,
      severity: hasCrit ? 'critical' : hasHigh ? 'high' : 'low',
      sampleNotes: matched[0]?.notes || null,
      sampleCategory: matched[0]?.category || null,
    };
  }

  const graph: InvestigationGraph = {
    nodes: [...nodeMap.values()],
    edges,
    investigationId: id,
    generatedAt: nowIso(),
  };

  return c.json(graph);
});

// Helper for deterministic expert OSINT synthesis grounded on real findings
function generateExpertOsintSynthesis(target: string, targetType: string, findingsList: any[]) {
  const categories = new Set(findingsList.map(f => f.category));
  const verifiedProfiles = findingsList.filter(f => f.type === 'sherlock_profile' || f.type === 'github_profile' || f.category === 'social_profile' || (f.notes && f.notes.includes('✓')));
  const locations = findingsList.filter(f => f.category === 'location_intelligence' || f.type === 'geocoded_location' || f.type === 'place_visit');
  const criticals = findingsList.filter(f => f.severity === 'critical' || f.severity === 'high');
  const mediums = findingsList.filter(f => f.severity === 'medium');
  const emails = findingsList.filter(f => f.type === 'git_author_email' || (f.type && f.type.includes('email')) || f.category === 'identity_attribution');
  const dnsRecords = findingsList.filter(f => f.category === 'dns');
  const subdomains = findingsList.filter(f => f.category === 'certificate' || f.type === 'subdomain');
  const openPorts = findingsList.filter(f => f.type === 'passive_open_ports' || f.type === 'open_port');
  const cves = findingsList.filter(f => f.type && (f.type.includes('cve') || f.type.includes('vuln')));
  const breaches = findingsList.filter(f => f.category === 'breach' || f.type === 'breach_record');
  const techStack = findingsList.filter(f => f.category === 'technology');
  const securityScores = findingsList.filter(f => f.type === 'dns_security_score' || f.type === 'security_hygiene_score');
  const cryptoWallets = findingsList.filter(f => f.category === 'blockchain' || f.type === 'crypto_wallet');

  // Compute calculated risk level based on actual findings
  let riskLevel = 'LOW';
  let threatScore = 18;
  if (criticals.length > 0 || breaches.length > 0 || cves.length > 0) {
    riskLevel = 'CRITICAL';
    threatScore = Math.min(96, 75 + criticals.length * 6 + breaches.length * 4);
  } else if (mediums.length >= 2 || emails.length > 0) {
    riskLevel = 'HIGH';
    threatScore = Math.min(74, 55 + mediums.length * 4 + emails.length * 3);
  } else if (openPorts.length > 0 || verifiedProfiles.length > 2) {
    riskLevel = 'MODERATE';
    threatScore = Math.min(54, 35 + openPorts.length * 5);
  }

  const summary = `OpenSpective AI Intelligence Synthesis for '${target}' (${targetType.toUpperCase()}): Overall threat posture assessed as [${riskLevel} RISK] (Threat Score: ${threatScore}/100). Analyzed ${findingsList.length} verified intelligence artifacts across ${categories.size} telemetry categories. Identified ${emails.length} exposed identity/email vectors, ${subdomains.length} network attack surface hostnames, ${openPorts.length} passive open service ports, and ${breaches.length} historical compromise records.`;

  // Specific misconfiguration & vulnerability detections
  const misconfigs: string[] = [];
  if (emails.length > 0) {
    misconfigs.push(`**Exposed Developer Email in Public Commits**: Email \`${emails[0]?.value}\` is publicly readable in git commit author metadata. This enables spear-phishing, credential stuffing, and social engineering attacks.`);
  }
  if (dnsRecords.length > 0) {
    const hasDmarc = dnsRecords.some(d => String(d.value).includes('v=DMARC1'));
    const hasSpf = dnsRecords.some(d => String(d.value).includes('v=spf1'));
    if (!hasDmarc) {
      misconfigs.push(`**Missing or Incomplete DMARC Policy**: No strict DMARC rejection policy (\`p=reject\`) detected in authoritative DNS TXT records. Adversaries can forge emails impersonating this domain without receiving server rejections.`);
    }
    if (!hasSpf) {
      misconfigs.push(`**Missing SPF Anti-Spoofing Record**: SPF TXT record is absent or permissive, allowing unauthorized mail transfer agents (MTAs) to send mail on behalf of the domain.`);
    }
  }
  if (openPorts.length > 0) {
    misconfigs.push(`**Publicly Reachable Service Ports**: Discovered open network services (${openPorts.map(p => `\`${p.value}\``).join(', ')}). Exposing raw listening ports without zero-trust ingress tunnels increases external attack surface.`);
  }
  if (subdomains.length > 3) {
    misconfigs.push(`**Subdomain Proliferation & Shadow IT**: Discovered ${subdomains.length} hostnames. Unmonitored staging or development subdomains (e.g. dev, test, admin) frequently suffer from dangling CNAME subdomain takeover vulnerabilities.`);
  }
  if (misconfigs.length === 0) {
    misconfigs.push(`No critical security misconfigurations flagged in passive public telemetry.`);
  }

  // Vulnerability & zero-day exposure analysis
  const vulnPoints: string[] = [];
  if (breaches.length > 0) {
    vulnPoints.push(`**Historical Credential Compromises**: Target is correlated with ${breaches.length} known public data breach records (${breaches.slice(0, 3).map(b => b.value).join(', ')}). Risk of password reuse attacks and credential stuffing across corporate portals.`);
  }
  if (cves.length > 0) {
    vulnPoints.push(`**Unpatched Known Vulnerabilities (CVEs)**: Detected CVE signatures (${cves.map(c => `\`${c.value}\``).join(', ')}). Immediate patch deployment required to prevent automated exploitation.`);
  } else if (techStack.length > 0) {
    vulnPoints.push(`**Software Supply Chain & Component Fingerprinting**: Running software components (${techStack.slice(0, 5).map(t => `\`${t.value}\``).join(', ')}). Outdated minor versions pose exposure to published web application vulnerabilities (RCE, XSS, SSRF).`);
  }
  if (openPorts.some(p => String(p.value).includes('22') || String(p.value).includes('3389') || String(p.value).includes('445') || String(p.value).includes('6379') || String(p.value).includes('9200'))) {
    vulnPoints.push(`**Critical Administrative Ingress Exposure**: High-risk ports (SSH/RDP/SMB/Database/Redis) detected in external internet scan databases. Risk of brute-force dictionary attacks, ransomware lateral movement, and unauthenticated RCE.`);
  }
  if (vulnPoints.length === 0) {
    vulnPoints.push(`No active unpatched CVE signatures flagged in passive perimeter scans.`);
  }

  // Exact step-by-step remediation fixes
  const remediationSteps: string[] = [
    `**Enforce Strict Email Security Policies (DMARC/SPF/DKIM)**:\n   Publish a strict DMARC TXT record in your DNS zone:\n   \`v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@${target.includes('@') ? target.split('@')[1] : target}; aspf=s;\`\n   And configure SPF to reject unauthorized senders:\n   \`v=spf1 mx -all\``,
    emails.length > 0
      ? `**Sanitize Git Commit Author Headers & Scrub Public History**:\n   Configure GitHub/GitLab to use private noreply email addresses (\`ID+username@users.noreply.github.com\`).\n   Use \`git-filter-repo\` to rewrite historical commits exposing developer addresses:\n   \`git filter-repo --email-callback "return email if b'noreply' in email else b'security@target.com'"`
      : `**Implement Continuous Certificate Transparency Monitoring**:\n   Enable automated webhook notifications on crt.sh and Cloudflare to receive real-time alerts whenever new SSL/TLS certificates are issued for your domain namespace.`,
    openPorts.length > 0
      ? `**Zero Trust Network Isolation & Access Gateways**:\n   Close direct internet ingress on port ${openPorts[0]?.value}. Place administrative services behind Cloudflare Zero Trust Tunnels (cloudflared), Tailscale, or AWS Security Group ACLs restricted by IP whitelist.`
      : `**Regular Credential Audits & FIDO2 Security Keys**:\n   Enforce hardware-backed Multi-Factor Authentication (WebAuthn/FIDO2) across all corporate accounts and developer consoles to eliminate credential stuffing risk.`,
    `**Attack Surface Hardening & Subdomain Hygiene**:\n   Audit all DNS CNAME and NS records for dangling pointers pointing to decommissioned GitHub Pages, AWS S3 buckets, or Heroku apps to prevent subdomain takeover.`,
  ];

  const sections: string[] = [
    `### 1. Executive Intelligence Summary & Threat Posture\n${summary}`,
    `### 2. Discovered Network & Asset Footprint\n` +
      `- **Primary Target Entity**: \`${target}\` (Classified as ${targetType.toUpperCase()})\n` +
      `- **Authoritative DNS Architecture**: ${dnsRecords.length > 0 ? `${dnsRecords.length} records mapped (A, AAAA, MX, TXT, NS, SOA)` : 'Standard public records'}\n` +
      `- **Discovered Subdomains & Hostnames**: ${subdomains.length > 0 ? subdomains.slice(0, 10).map(s => `\`${s.value}\``).join(', ') : 'Root domain only'}\n` +
      `- **Passive Open Ports & Services**: ${openPorts.length > 0 ? openPorts.map(p => `\`${p.value}\``).join(', ') : 'No high-risk exposed management ports discovered'}\n` +
      `- **Identified Technologies & CMS**: ${techStack.length > 0 ? techStack.slice(0, 8).map(t => `\`${t.value}\``).join(' | ') : 'Default web stack'}`,
    `### 3. Identity, People & Attribution Analysis\n` +
      `- **Verified Public Accounts**: ${verifiedProfiles.length > 0 ? verifiedProfiles.slice(0, 8).map(p => `${p.value} (${p.source_name || 'OSINT'})`).join(', ') : 'No verified social or code author identities matched'}\n` +
      `- **Identified Email Addresses**: ${emails.length > 0 ? emails.slice(0, 6).map(e => `\`${e.value}\``).join(', ') : 'None publicly exposed in commit logs or registries'}\n` +
      (cryptoWallets.length > 0 ? `- **Cryptographic Addresses**: ${cryptoWallets.map(w => `\`${w.value}\``).join(', ')}\n` : '') +
      `- **Historical Compromises & Breaches**: ${breaches.length > 0 ? `⚠️ ${breaches.length} breach records correlated (${breaches.slice(0, 4).map(b => b.value).join(', ')})` : 'Zero known breached records matched in public dumps'}`,
  ];

  if (locations.length > 0) {
    sections.push(
      `### 4. Verified Spatial & Geolocation Footprint\n` +
      `- Identified **${locations.length}** verified geographic locations and coordinate traces.\n` +
      locations.slice(0, 5).map(l => `- 📍 **${l.value}**${l.notes ? ` — ${l.notes}` : ''}`).join('\n')
    );
  }

  sections.push(
    `### 5. Security Misconfigurations & Threat Vectors\n` +
    misconfigs.map(m => `- ${m}`).join('\n')
  );

  sections.push(
    `### 6. Vulnerabilities, CVEs & Zero-Day Threat Exposure\n` +
    vulnPoints.map(v => `- ${v}`).join('\n')
  );

  sections.push(
    `### 7. Actionable Step-by-Step Remediation Blueprints (Exact Fixes)\n` +
    remediationSteps.map((r, i) => `${i + 1}. ${r}`).join('\n\n')
  );

  return {
    summary,
    fullResponse: sections.join('\n\n'),
    recommendations: remediationSteps,
    riskLevel,
    threatScore,
  };
}

// ---- POST /investigations/:id/analyze (Free for all) ----
investigationsRouter.post('/:id/analyze', async (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  const investigation = await c.env.DB
    .prepare(`SELECT * FROM investigations WHERE id = ?`)
    .bind(id)
    .first();

  if (!investigation) return c.json({ error: 'Not found.', code: 'NOT_FOUND' }, 404);

  // Fetch up to 500 findings for thorough analysis
  const findings = await c.env.DB
    .prepare(`SELECT category, subcategory, type, value, confidence, severity, source_name, notes FROM findings WHERE investigation_id = ? LIMIT 500`)
    .bind(id)
    .all();

  const targetName = (investigation['normalized_target'] || investigation['target']) as string;
  const targetType = (investigation['target_type'] || 'entity') as string;

  let summary = '';
  let responseText = '';
  let modelName = 'OpenSpective-Intelligence-Synthesizer';
  let recommendationsList: string[] = [];

  // Generate grounded expert synthesis directly from the collected artifacts
  const expert = generateExpertOsintSynthesis(targetName, targetType, findings.results);
  summary = expert.summary;
  responseText = expert.fullResponse;
  recommendationsList = expert.recommendations;
  modelName = 'OpenSpective-Expert-Synthesizer';

  // Try Cloudflare Workers AI if configured to enhance the synthesis
  if (c.env.AI) {
    try {
      const evidenceSummary = findings.results.map(f =>
        `[${f['category']}/${f['type']}] ${f['value']}${f['notes'] ? ` (${f['notes']})` : ''} — source: ${f['source_name']}, severity: ${f['severity']}`
      ).slice(0, 60).join('\n');

      const prompt = `You are a Principal Threat Intelligence Analyst & Offensive Security Consultant.
Target: ${targetName} (${targetType})
Collected OSINT Artifacts:
${evidenceSummary || 'No evidence collected.'}

Draft a comprehensive, highly actionable intelligence dossier covering:
1. Executive Risk Posture (CRITICAL, HIGH, MODERATE, or LOW) with quantitative justification.
2. Asset & Attack Surface Inventory (DNS records, subdomains, open ports, identity clues).
3. Security Misconfigurations (SPF/DKIM/DMARC email spoofing risks, exposed commit emails, open services).
4. Vulnerabilities, Outdated Software & Zero-Day Threat Exposure (CVEs, credential stuffing from breaches, attack vectors).
5. Actionable Step-by-Step Remediation Blueprints with exact configuration commands, DNS TXT syntax, and mitigation controls.

Ground all analysis strictly in the verified findings. Do not invent unobserved facts.`;

      const aiResponse = await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        prompt,
        max_tokens: 1200,
      });

      const rawAiText = (aiResponse as any)?.response ?? (aiResponse as any)?.result?.response ?? '';
      if (rawAiText && rawAiText.trim().length > 100) {
        responseText = rawAiText.trim();
        modelName = '@cf/meta/llama-3.1-8b-instruct';
        const lines = responseText.split('\n').filter(l => l.trim().length > 0);
        summary = lines.slice(0, 2).join(' ').replace(/^[#*\s]+/, '');
      }
    } catch {
      // Kept expert deterministic synthesis
    }
  }

  const analysisId = generateId('ai');
  await c.env.DB
    .prepare(
      `INSERT INTO ai_analyses (id, investigation_id, model, summary, technical_details, recommendations, gaps, evidence_refs, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      analysisId,
      id,
      modelName,
      summary,
      responseText,
      JSON.stringify(recommendationsList),
      JSON.stringify([]),
      JSON.stringify(findings.results.map(f => `${f['type']}:${f['value']}`).slice(0, 20)),
      nowIso()
    )
    .run();

  // Update investigation with AI analysis ID
  await c.env.DB
    .prepare(`UPDATE investigations SET ai_analysis_id = ? WHERE id = ?`)
    .bind(analysisId, id)
    .run();

  // Increment usage if user authenticated
  if (user) {
    const period = new Date().toISOString().slice(0, 7);
    await c.env.DB
      .prepare(
        `INSERT INTO usage_records (id, user_id, period, ai_inference_count) VALUES (?, ?, ?, 1)
         ON CONFLICT(user_id, period) DO UPDATE SET ai_inference_count = ai_inference_count + 1`
      )
      .bind(generateId('ur'), user.id, period)
      .run();
  }

  return c.json({
    analysisId,
    summary,
    fullResponse: responseText,
    recommendations: recommendationsList.join('\n'),
    evidenceCount: findings.results.length,
    model: modelName,
    generatedAt: nowIso(),
    disclaimer: 'Intelligence synthesis is derived from verified open-source signals and telemetry in the investigation corpus.',
  });
});
