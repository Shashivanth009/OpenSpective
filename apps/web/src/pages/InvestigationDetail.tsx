import { useState, useEffect, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  AlertTriangle, GitBranch, RefreshCw, Sparkles,
  FileText, ChevronDown, ChevronRight, Clock,
  ShieldCheck, BarChart3, CornerUpRight, ExternalLink,
  Copy, Check, Database, MapPin, Compass, Search
} from 'lucide-react';
import * as api from '../api.ts';

export default function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [investigation, setInvestigation] = useState<api.Investigation | null>(null);
  const [executions, setExecutions] = useState<api.CollectorExecution[]>([]);
  const [findings, setFindings] = useState<api.Finding[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchFilter, setSearchFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [analyzingAi, setAnalyzingAi] = useState(false);
  const [aiReport, setAiReport] = useState<any>(null);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'findings' | 'timeline' | 'scorecard' | 'dorks'>('findings');
  const [dorkEngineFilter, setDorkEngineFilter] = useState<string>('all');
  const [selectedCollector, setSelectedCollector] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);

  const COLLECTOR_OSINT_META: Record<string, { label: string; suite: string; icon: string }> = {
    certificate_transparency: { label: 'Subfinder & crt.sh', suite: 'Passive Subdomain Discovery', icon: '🌐' },
    username_presence: { label: 'Sherlock & WhatsMyName', suite: 'Account Footprint & Verification', icon: '👤' },
    email_identity: { label: 'theHarvester & Hunter', suite: 'Email Recon & Author Footprint', icon: '📧' },
    tech_stack: { label: 'Wappalyzer & BuiltWith', suite: 'Tech Stack & CMS Fingerprinting', icon: '⚡' },
    web_archive: { label: 'Waybackurls & GAU', suite: 'Historical Archive & Endpoints', icon: '🏛️' },
    shodan: { label: 'Shodan & Censys', suite: 'Port Scanning & Exposed CVEs', icon: '🛡️' },
    threat_intel: { label: 'URLhaus & ThreatFox', suite: 'Malware IOCs & Abuse Intel', icon: '☣️' },
    cloud_storage: { label: 'S3Scanner & CloudEnum', suite: 'Cloud Bucket Permutations', icon: '☁️' },
    search_dorks: { label: 'Google Dorks & Search Intel', suite: 'Config & Secret Leak Queries', icon: '🔍' },
    pgp_keys: { label: 'Ubuntu PGP Keyserver', suite: 'Cryptographic Public Keys', icon: '🔑' },
    dns_security: { label: 'SecurityHeaders & DNS Hygiene', suite: 'SPF, DMARC, BIMI & DNSSEC', icon: '🔒' },
    rdap: { label: 'ICANN RDAP & WHOIS', suite: 'Domain & IP Registry Info', icon: '📋' },
    dns: { label: 'MassDNS & Cloudflare DNS', suite: 'Authoritative DNS Records', icon: '📡' },
    ipinfo: { label: 'BGPView & GeoIP', suite: 'ASN & Autonomous Systems', icon: '🗺️' },
    github: { label: 'GitHub Git Forensics', suite: 'Public Repos & Author Leaks', icon: '🐙' },
    breach: { label: 'HaveIBeenPwned & Leak Intel', suite: 'Compromised Credentials & Dumps', icon: '🚨' },
    location: { label: 'OpenStreetMap & Nominatim', suite: 'Geocoding & Spatial Intel', icon: '📍' },
    phone: { label: 'Numverify & Global E.164', suite: 'Telephony & Carrier Attribution', icon: '📱' },
    crypto: { label: 'Etherscan & Blockchain Explorer', suite: 'Ledger Audit & Wallet Balance', icon: '🪙' },
    person_search: { label: 'Wikipedia & Entity Graph', suite: 'Public Entity & Identity Recon', icon: '👥' },
  };

  const getRawDataObj = (f: api.Finding): any => {
    if (!f.raw_data) return null;
    if (typeof f.raw_data === 'object') return f.raw_data;
    try {
      return JSON.parse(f.raw_data);
    } catch {
      return null;
    }
  };

  const fetchData = async () => {
    if (!id) return;
    try {
      const [invRes, findRes] = await Promise.all([
        api.getInvestigation(id),
        api.getFindings(id, undefined, 1, 300),
      ]);
      setInvestigation(invRes.investigation);
      setExecutions(invRes.executions);
      setFindings(findRes.data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load investigation details.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    // Auto-poll every 1000ms while running or queued for real-time telemetry updates
    let timer: ReturnType<typeof setInterval> | undefined;
    if (investigation?.status === 'running' || investigation?.status === 'queued') {
      timer = setInterval(() => {
        fetchData();
      }, 1000);
    }
    return () => clearInterval(timer);
  }, [id, investigation?.status]);

  // Live timer ticker for scan execution duration
  useEffect(() => {
    if (!investigation) return;
    const isScanning = investigation.status === 'running' || investigation.status === 'queued';
    if (!isScanning) {
      if (investigation.completed_at && investigation.started_at) {
        const diff = Math.max(0, Math.round((new Date(investigation.completed_at).getTime() - new Date(investigation.started_at).getTime()) / 1000));
        setElapsedSeconds(diff);
      }
      return;
    }

    const startTs = new Date(investigation.started_at).getTime();
    const updateElapsed = () => {
      setElapsedSeconds(Math.max(0, Math.round((Date.now() - startTs) / 1000)));
    };
    updateElapsed();
    const interval = setInterval(updateElapsed, 500);
    return () => clearInterval(interval);
  }, [investigation?.started_at, investigation?.completed_at, investigation?.status]);

  const handleRunAiAnalysis = async () => {
    if (!id) return;
    setAnalyzingAi(true);
    try {
      const report = await api.analyzeInvestigation(id);
      setAiReport(report);
      fetchData();
    } catch (err: any) {
      alert(err?.message || 'AI analysis failed.');
    } finally {
      setAnalyzingAi(false);
    }
  };

  const handleExport = async (format: 'json' | 'csv' | 'html') => {
    if (!id) return;
    try {
      const res = await api.generateReport(id, format);
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `openspective-report-${investigation?.target || id}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err: any) {
      alert(err?.message || 'Export failed.');
    }
  };

  // Client-side OASIS STIX 2.1 Threat Intel Bundle generator
  const handleExportStix = () => {
    if (!investigation) return;
    const now = new Date().toISOString();
    const bundleId = `bundle--${Math.random().toString(36).slice(2, 11)}-${Date.now()}`;
    const identityId = `identity--${Math.random().toString(36).slice(2, 11)}`;

    const stixObjects: any[] = [
      {
        type: 'identity',
        spec_version: '2.1',
        id: identityId,
        created: now,
        modified: now,
        name: 'OpenSpective Passive OSINT Platform',
        identity_class: 'system',
      },
      {
        type: 'observed-data',
        spec_version: '2.1',
        id: `observed-data--${Math.random().toString(36).slice(2, 11)}`,
        created_by_ref: identityId,
        created: now,
        modified: now,
        first_observed: investigation.started_at,
        last_observed: investigation.completed_at || now,
        number_observed: findings.length,
        objects: {
          '0': {
            type: investigation.target_type === 'ip' ? 'ipv4-addr' : investigation.target_type === 'email' ? 'email-addr' : 'domain-name',
            value: investigation.target,
          },
        },
      },
    ];

    findings.forEach((f) => {
      stixObjects.push({
        type: 'indicator',
        spec_version: '2.1',
        id: `indicator--${Math.random().toString(36).slice(2, 11)}`,
        created_by_ref: identityId,
        created: f.first_seen || now,
        modified: f.first_seen || now,
        name: `${f.category}: ${f.type}`,
        description: f.notes || f.value,
        indicator_types: [f.severity === 'critical' || f.severity === 'high' ? 'malicious-activity' : 'anomalous-activity'],
        pattern_type: 'stix',
        pattern: `[artifact:payload_bin = '${f.value}']`,
        valid_from: f.first_seen || now,
        confidence: f.confidence === 'high' ? 90 : f.confidence === 'medium' ? 60 : 30,
      });
    });

    const bundle = {
      type: 'bundle',
      id: bundleId,
      objects: stixObjects,
    };

    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `stix2.1-${investigation.target}-${investigation.id}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  const handleCopyRaw = (text: string, fid: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(fid);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Helper to extract a pivotable target from a finding
  const detectPivotTarget = (f: api.Finding): { target: string; type: string } | null => {
    if (f.type === 'git_author_email' && f.value.includes('@')) {
      return { target: f.value, type: 'email' };
    }
    if (f.type === 'account_presence') {
      const match = f.value.match(/^[^:]+:\s*([^\s]+)/);
      if (match && match[1]) return { target: match[1], type: 'username' };
    }
    if (f.type === 'git_commit') {
      const match = f.value.match(/^([^@]+)@/);
      if (match && match[1]) return { target: match[1], type: 'organization' };
    }
    if (f.type === 'dns_a' || f.type === 'dns_aaaa') {
      return { target: f.value, type: 'ip' };
    }
    if (f.type === 'dns_mx') {
      return { target: f.value, type: 'domain' };
    }
    if (f.type === 'github_profile') {
      return { target: f.value, type: 'username' };
    }
    return null;
  };

  // Timeline events extracted and sorted chronologically
  const timelineEvents = useMemo(() => {
    return findings
      .map(f => {
        let eventDate = f.first_seen;
        try {
          const raw = typeof f.raw_data === 'string' ? JSON.parse(f.raw_data) : f.raw_data;
          if (raw?.date) eventDate = raw.date;
          else if (raw?.firstActivity) eventDate = raw.firstActivity;
          else if (raw?.registeredAt) eventDate = raw.registeredAt;
          else if (raw?.breachDate) eventDate = raw.breachDate;
          else if (raw?.timestamp && raw.timestamp.length >= 8) {
            const y = raw.timestamp.slice(0, 4);
            const m = raw.timestamp.slice(4, 6);
            const d = raw.timestamp.slice(6, 8);
            eventDate = `${y}-${m}-${d}`;
          }
        } catch {
          // ignore parse error
        }

        return {
          id: f.id,
          finding: f,
          category: f.category,
          type: f.type,
          value: f.value,
          notes: f.notes,
          severity: f.severity,
          source: f.source_name,
          sourceUrl: f.source_url,
          timestamp: eventDate || f.first_seen,
        };
      })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [findings]);

  // Executive Intelligence Scorecard calculations
  const scorecard = useMemo(() => {
    const total = findings.length;
    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const highCount = findings.filter(f => f.severity === 'high').length;
    const mediumCount = findings.filter(f => f.severity === 'medium').length;

    // Attribute depth
    const emailsFound = findings.filter(f => f.category === 'identity_attribution' || f.type.includes('email')).length;
    const commitsFound = findings.filter(f => f.category === 'developer_activity' || f.type === 'git_commit').length;
    const profilesFound = findings.filter(f => f.category === 'social_profile' || f.category === 'public_profile').length;
    const infraFound = findings.filter(f => f.category === 'dns' || f.category === 'rdap' || f.category === 'certificate' || f.category === 'technology' || f.category === 'infrastructure').length;
    const breachesFound = findings.filter(f => f.category === 'threat_intelligence' && f.type === 'breach_record').length;
    const portsAndCvesFound = findings.filter(f => f.type === 'passive_open_ports' || f.type === 'known_cve' || f.type === 'known_cves_summary').length;
    const locationsFound = findings.filter(f => f.category === 'location_intelligence').length;
    const phoneFound = findings.filter(f => f.category === 'identity' && (f.type === 'phone_profile' || f.type === 'osint_search_dork')).length;
    const securityFinding = findings.find(f => f.type === 'dns_security_score' || f.type === 'security_hygiene_score');

    let exposureScore = Math.min(100, Math.round(
      (commitsFound * 12) +
      (emailsFound * 20) +
      (profilesFound * 8) +
      (breachesFound * 25) +
      (portsAndCvesFound * 15) +
      (infraFound * 5)
    ));
    if (exposureScore === 0 && total > 0) exposureScore = 25;

    let attributionLevel = 'Unverified Surface';
    if (emailsFound > 0 && commitsFound > 0) attributionLevel = 'Directly Attributed (Verified Code Author)';
    else if (phoneFound > 0) attributionLevel = 'Telephony & Carrier Allocated';
    else if (portsAndCvesFound > 0) attributionLevel = 'Network & Service Vulnerability Exposure';
    else if (emailsFound > 0 || profilesFound >= 3) attributionLevel = 'High Footprint Correlation';
    else if (infraFound > 0) attributionLevel = 'Infrastructure Mapping';

    return {
      total,
      criticalCount,
      highCount,
      mediumCount,
      exposureScore,
      attributionLevel,
      emailsFound,
      commitsFound,
      profilesFound,
      infraFound,
      breachesFound,
      portsAndCvesFound,
      locationsFound,
      phoneFound,
      securityScore: securityFinding?.value || null,
    };
  }, [findings]);

  const isFindingFromCollector = (f: api.Finding, collector: string): boolean => {
    const src = (f.source_name || '').toLowerCase();
    const cat = (f.category || '').toLowerCase();
    const typ = (f.type || '').toLowerCase();
    switch (collector) {
      case 'certificate_transparency':
        return src.includes('crt') || src.includes('subfinder') || cat === 'certificate' || cat === 'subdomain';
      case 'username_presence':
        return src.includes('sherlock') || src.includes('whatsmyname') || typ === 'account_presence';
      case 'email_identity':
        return src.includes('theharvester') || src.includes('hunter') || typ.includes('email');
      case 'tech_stack':
        return src.includes('wappalyzer') || src.includes('builtwith') || cat === 'technology';
      case 'web_archive':
        return src.includes('wayback') || src.includes('gau') || typ === 'archive_url';
      case 'shodan':
        return src.includes('shodan') || src.includes('censys') || typ === 'passive_open_ports' || typ.includes('cve');
      case 'threat_intel':
        return src.includes('urlhaus') || src.includes('threatfox') || typ === 'threat_ioc';
      case 'cloud_storage':
        return src.includes('s3scanner') || src.includes('cloudenum') || typ === 'cloud_bucket';
      case 'search_dorks':
        return src.includes('dork') || typ === 'osint_search_dork';
      case 'pgp_keys':
        return src.includes('pgp') || typ === 'pgp_public_key';
      case 'dns_security':
        return src.includes('securityheaders') || typ.includes('dns_sec') || typ === 'security_hygiene_score';
      case 'rdap':
        return src.includes('rdap') || cat === 'rdap';
      case 'dns':
        return src.includes('dns') || cat === 'dns';
      case 'ipinfo':
        return src.includes('ipinfo') || src.includes('bgp') || typ === 'ip_asn';
      case 'github':
        return src.includes('github') || cat === 'developer_activity';
      case 'breach':
        return src.includes('haveibeenpwned') || cat === 'breach' || typ === 'breach_record';
      case 'location':
        return src.includes('openstreetmap') || cat === 'location_intelligence';
      case 'phone':
        return src.includes('numverify') || (cat === 'identity' && typ === 'phone_profile');
      case 'crypto':
        return src.includes('blockchain') || cat === 'blockchain';
      case 'person_search':
        return src.includes('wikipedia') || src.includes('wikidata') || src.includes('hackernews');
      default:
        return src.includes(collector.toLowerCase());
    }
  };

  const filteredFindings = findings.filter(f => {
    const matchesCat = selectedCategory === 'all' || f.category.toLowerCase() === selectedCategory.toLowerCase();
    const matchesSearch = !searchFilter ||
      f.value.toLowerCase().includes(searchFilter.toLowerCase()) ||
      f.type.toLowerCase().includes(searchFilter.toLowerCase()) ||
      (f.notes && f.notes.toLowerCase().includes(searchFilter.toLowerCase()));
    const matchesCollector = !selectedCollector || isFindingFromCollector(f, selectedCollector);
    return matchesCat && matchesSearch && matchesCollector;
  });

  const categories = ['all', ...Array.from(new Set(findings.map(f => f.category)))];

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed': return <span className="badge badge-success">✓ 100% Done</span>;
      case 'running': return <span className="badge badge-info"><span className="spinner" style={{ width: 10, height: 10 }} /> Scanning...</span>;
      case 'queued': return <span className="badge badge-warning">⏳ Queued</span>;
      case 'partial': return <span className="badge badge-warning">Partial</span>;
      case 'failed': return <span className="badge badge-error">Failed</span>;
      default: return <span className="badge badge-neutral">{status}</span>;
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'critical': return <span className="badge badge-error">Critical</span>;
      case 'high': return <span className="badge badge-error">High</span>;
      case 'medium': return <span className="badge badge-warning">Medium</span>;
      case 'low': return <span className="badge badge-success">Low</span>;
      default: return <span className="badge badge-neutral">Info</span>;
    }
  };

  if (loading && !investigation) {
    return (
      <div style={{ maxWidth: '1400px', margin: '0 auto', padding: 'var(--space-12)', textAlign: 'center' }}>
        <span className="spinner" style={{ width: 28, height: 28, marginBottom: 'var(--space-4)' }} />
        <p style={{ color: 'var(--color-text-secondary)' }}>Loading investigation telemetry...</p>
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div style={{ maxWidth: '800px', margin: 'var(--space-12) auto', padding: 'var(--space-6)' }}>
        <div className="alert alert-error">
          <AlertTriangle size={20} />
          <span>{error || 'Investigation not found.'}</span>
        </div>
        <Link to="/dashboard" className="btn btn-secondary" style={{ marginTop: 'var(--space-4)' }}>
          Back to Dashboard
        </Link>
      </div>
    );
  }

  // Live progress metrics
  const totalExecutions = executions.length;
  const completedExecutions = executions.filter(e => e.status === 'completed').length;
  const runningExecutions = executions.filter(e => e.status === 'running').length;
  const queuedExecutions = executions.filter(e => e.status === 'queued').length;
  const failedExecutions = executions.filter(e => e.status === 'failed').length;

  const runningToolNames = executions
    .filter(e => e.status === 'running')
    .map(e => COLLECTOR_OSINT_META[e.collector_name]?.label || e.collector_name.replace(/_/g, ' '));

  let progressPercent = 0;
  if (investigation.status === 'completed') {
    progressPercent = 100;
  } else if (investigation.status === 'partial') {
    progressPercent = 95;
  } else if (investigation.status === 'failed') {
    progressPercent = 100;
  } else if (totalExecutions > 0) {
    const weighted = completedExecutions + failedExecutions + (runningExecutions * 0.5);
    progressPercent = Math.min(95, Math.max(12, Math.round((weighted / totalExecutions) * 100)));
  } else if (investigation.status === 'running') {
    progressPercent = 25;
  } else if (investigation.status === 'queued') {
    progressPercent = 8;
  }

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto', padding: 'var(--space-6) var(--space-8)' }}>
      {/* Target Banner */}
      <div className="card" style={{ marginBottom: 'var(--space-6)', padding: 'var(--space-6)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 'var(--space-4)' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-2)' }}>
              <h1 style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, color: 'var(--color-dark)', margin: 0 }}>
                {investigation.target}
              </h1>
              <span className="badge badge-neutral" style={{ textTransform: 'capitalize' }}>
                {investigation.target_type.replace('_', ' ')}
              </span>
              {getStatusBadge(investigation.status)}
            </div>

            <div style={{ display: 'flex', gap: 'var(--space-4)', fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
              <span>ID: <code>{investigation.id}</code></span>
              <span>Started: {new Date(investigation.started_at).toLocaleTimeString()}</span>
              {investigation.completed_at && (
                <span>Completed: {new Date(investigation.completed_at).toLocaleTimeString()}</span>
              )}
            </div>
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
            <Link to={`/investigations/${investigation.id}/graph`} className="btn btn-secondary btn-sm">
              <GitBranch size={16} /> Interactive Graph
            </Link>

            <button
              onClick={handleRunAiAnalysis}
              disabled={analyzingAi}
              className="btn btn-secondary btn-sm"
              title="Synthesize findings with Workers AI"
            >
              <Sparkles size={16} style={{ color: 'var(--color-accent)' }} />
              {analyzingAi ? 'Synthesizing...' : 'AI Synthesis'}
            </button>

            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <button onClick={() => handleExport('json')} className="btn btn-ghost btn-sm" title="Export JSON">
                JSON
              </button>
              <button onClick={() => handleExport('csv')} className="btn btn-ghost btn-sm" title="Export CSV">
                CSV
              </button>
              <button onClick={handleExportStix} className="btn btn-ghost btn-sm" title="Export OASIS STIX 2.1 Threat Intel">
                <ShieldCheck size={14} style={{ color: 'var(--color-accent)' }} /> STIX 2.1
              </button>
              <button onClick={() => handleExport('html')} className="btn btn-ghost btn-sm" title="Download HTML Report">
                <FileText size={16} /> Report
              </button>
            </div>

            <button onClick={fetchData} className="btn btn-ghost btn-sm" title="Refresh">
              <RefreshCw size={16} />
            </button>
          </div>
        </div>
      </div>

      {/* ======================================================== */}
      {/* PROMINENT SCAN STATUS & LIVE TELEMETRY BLOCK ELEMENT     */}
      {/* ======================================================== */}
      <div
        className="card"
        style={{
          marginBottom: 'var(--space-6)',
          padding: 'var(--space-6)',
          background: investigation.status === 'running'
            ? 'linear-gradient(135deg, rgba(37, 99, 235, 0.08) 0%, rgba(16, 185, 129, 0.05) 100%)'
            : investigation.status === 'completed'
            ? 'linear-gradient(135deg, rgba(16, 185, 129, 0.06) 0%, rgba(37, 99, 235, 0.03) 100%)'
            : 'var(--color-surface)',
          border: investigation.status === 'running'
            ? '1.5px solid var(--color-accent)'
            : '1.5px solid var(--color-border)',
          boxShadow: investigation.status === 'running'
            ? '0 0 24px rgba(37, 99, 235, 0.16)'
            : 'var(--shadow-sm)',
          position: 'relative',
          overflow: 'hidden'
        }}
      >
        {/* Top Header Row inside Block */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            {investigation.status === 'running' ? (
              <span style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 38,
                height: 38,
                borderRadius: '50%',
                background: 'rgba(37, 99, 235, 0.15)',
                color: 'var(--color-accent)',
                flexShrink: 0
              }}>
                <span className="spinner" style={{ width: 20, height: 20 }} />
              </span>
            ) : investigation.status === 'completed' ? (
              <span style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 38,
                height: 38,
                borderRadius: '50%',
                background: 'rgba(16, 185, 129, 0.15)',
                color: 'var(--color-success)',
                flexShrink: 0
              }}>
                <Check size={22} />
              </span>
            ) : (
              <span style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 38,
                height: 38,
                borderRadius: '50%',
                background: 'rgba(234, 179, 8, 0.15)',
                color: 'var(--color-warning)',
                flexShrink: 0
              }}>
                <Clock size={20} />
              </span>
            )}

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 800, margin: 0, color: 'var(--color-dark)' }}>
                  {investigation.status === 'running'
                    ? 'OSINT Scan In Progress'
                    : investigation.status === 'completed'
                    ? 'Scan Complete — Reconnaissance Surface Mapped'
                    : investigation.status === 'partial'
                    ? 'Scan Complete (Partial Coverage)'
                    : `Investigation Status: ${investigation.status.toUpperCase()}`}
                </h2>
                {getStatusBadge(investigation.status)}
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginTop: '3px' }}>
                {investigation.status === 'running'
                  ? runningToolNames.length > 0
                    ? `Currently Executing: ${runningToolNames.join(', ')}`
                    : 'Dispatching background intelligence workers...'
                  : `All ${totalExecutions} OSINT engines finished analysis on ${investigation.target}`}
              </div>
            </div>
          </div>

          {/* Big Percentage Badge */}
          <div style={{ textAlign: 'right' }}>
            <div style={{
              fontSize: '2rem',
              fontWeight: 900,
              fontFamily: 'var(--font-mono)',
              color: investigation.status === 'completed'
                ? '#059669'
                : 'var(--color-accent)',
              lineHeight: 1
            }}>
              {progressPercent}%
            </div>
            <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 600, marginTop: '3px' }}>
              Execution Progress
            </div>
          </div>
        </div>

        {/* Dynamic Progress Bar */}
        <div style={{
          width: '100%',
          height: '10px',
          background: 'var(--color-border)',
          borderRadius: '999px',
          overflow: 'hidden',
          marginBottom: 'var(--space-4)',
          position: 'relative'
        }}>
          <div style={{
            height: '100%',
            width: `${progressPercent}%`,
            background: investigation.status === 'completed'
              ? 'linear-gradient(90deg, #10b981 0%, #059669 100%)'
              : 'linear-gradient(90deg, #2563eb 0%, #3b82f6 50%, #10b981 100%)',
            borderRadius: '999px',
            transition: 'width 0.3s ease',
            boxShadow: '0 0 10px rgba(37, 99, 235, 0.4)'
          }} />
        </div>

        {/* Multi-Stat Telemetry Badges Strip */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: 'var(--space-3)',
          background: 'var(--color-surface)',
          padding: 'var(--space-3) var(--space-4)',
          borderRadius: 'var(--radius)',
          border: '1px solid var(--color-border-subtle)'
        }}>
          <div>
            <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--color-text-muted)', fontWeight: 700 }}>
              Engines Executed
            </div>
            <div style={{ fontSize: 'var(--text-base)', fontWeight: 800, color: 'var(--color-dark)', marginTop: '2px' }}>
              {completedExecutions} <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 500 }}>/ {totalExecutions} Tools</span>
            </div>
            {runningExecutions > 0 && (
              <div style={{ fontSize: '10px', color: 'var(--color-accent)', fontWeight: 600 }}>
                {runningExecutions} running, {queuedExecutions} queued
              </div>
            )}
          </div>

          <div>
            <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--color-text-muted)', fontWeight: 700 }}>
              Discovered Findings
            </div>
            <div style={{ fontSize: 'var(--text-base)', fontWeight: 800, color: '#059669', marginTop: '2px' }}>
              {findings.length} <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 500 }}>records</span>
            </div>
          </div>

          <div>
            <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--color-text-muted)', fontWeight: 700 }}>
              Elapsed Time
            </div>
            <div style={{ fontSize: 'var(--text-base)', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--color-dark)', marginTop: '2px' }}>
              {elapsedSeconds > 0 ? `${elapsedSeconds}s` : '< 1s'}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--color-text-muted)', fontWeight: 700 }}>
              Critical / High Risks
            </div>
            <div style={{
              fontSize: 'var(--text-base)',
              fontWeight: 800,
              color: (scorecard.criticalCount + scorecard.highCount) > 0 ? '#dc2626' : 'var(--color-text-secondary)',
              marginTop: '2px'
            }}>
              {scorecard.criticalCount + scorecard.highCount} <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 500 }}>alerts</span>
            </div>
          </div>

          <div>
            <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--color-text-muted)', fontWeight: 700 }}>
              Attribution Level
            </div>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--color-dark)', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={scorecard.attributionLevel}>
              {scorecard.attributionLevel}
            </div>
          </div>
        </div>
      </div>

      {/* Collector Executions Progress Row */}
      <div className="card" style={{ marginBottom: 'var(--space-6)', padding: 'var(--space-5)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-3)', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
          <div>
            <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 800, color: 'var(--color-dark)', margin: 0 }}>
              Active Intelligence Telemetry ({executions.length} OSINT Tool Engines Executed)
            </h3>
            <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
              Click any tool card below to isolate and view its specific discovered findings
            </span>
          </div>
          {selectedCollector && (
            <button
              onClick={() => setSelectedCollector(null)}
              className="btn btn-ghost btn-xs"
              style={{ fontSize: '11px', color: 'var(--color-accent)', fontWeight: 700 }}
            >
              Reset Filter (Showing: {COLLECTOR_OSINT_META[selectedCollector]?.label || selectedCollector})
            </button>
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 'var(--space-3)' }}>
          {executions.map(exec => {
            const meta = COLLECTOR_OSINT_META[exec.collector_name] || {
              label: exec.collector_name.replace(/_/g, ' '),
              suite: 'Intelligence Engine',
              icon: '⚡',
            };
            const isFilterActive = selectedCollector === exec.collector_name;
            const durationMs = exec.completed_at && exec.started_at
              ? Math.max(0, new Date(exec.completed_at).getTime() - new Date(exec.started_at).getTime())
              : null;

            return (
              <div
                key={exec.id}
                onClick={() => {
                  setSelectedCollector(isFilterActive ? null : exec.collector_name);
                  setActiveTab('findings');
                }}
                style={{
                  padding: 'var(--space-3)',
                  borderRadius: 'var(--radius)',
                  background: isFilterActive ? 'var(--color-bg-secondary)' : 'var(--color-bg)',
                  border: isFilterActive ? '2px solid var(--color-accent)' : '1px solid var(--color-border)',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  boxShadow: isFilterActive ? '0 0 0 1px var(--color-accent)' : 'none',
                }}
                title={`Click to filter findings from ${meta.label}`}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ fontSize: '14px' }}>{meta.icon}</span>
                    <strong style={{ fontSize: '12px', fontWeight: 800, color: 'var(--color-dark)' }}>
                      {meta.label}
                    </strong>
                  </div>
                  {getStatusBadge(exec.status)}
                </div>

                <div style={{ fontSize: '10px', color: 'var(--color-text-muted)', marginBottom: '6px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {meta.suite}
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', color: 'var(--color-text-secondary)', borderTop: '1px solid var(--color-border-subtle)', paddingTop: '4px' }}>
                  <span style={{ fontWeight: exec.findings_count > 0 ? 700 : 400, color: exec.findings_count > 0 ? 'var(--color-dark)' : 'var(--color-text-muted)' }}>
                    {exec.findings_count} {exec.findings_count === 1 ? 'finding' : 'findings'}
                  </span>
                  {durationMs !== null && (
                    <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
                      {durationMs}ms
                    </span>
                  )}
                </div>

                {/* Individual Tool Mini Progress Bar */}
                <div style={{
                  width: '100%',
                  height: '4px',
                  background: 'var(--color-border)',
                  borderRadius: '2px',
                  overflow: 'hidden',
                  marginTop: '6px'
                }}>
                  <div style={{
                    height: '100%',
                    width: exec.status === 'completed' ? '100%' : exec.status === 'running' ? '65%' : exec.status === 'failed' ? '100%' : '15%',
                    background: exec.status === 'completed'
                      ? '#10b981'
                      : exec.status === 'running'
                      ? 'var(--color-accent)'
                      : exec.status === 'failed'
                      ? '#ef4444'
                      : 'var(--color-border)',
                    transition: 'width 0.3s ease'
                  }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* AI Intelligence Synthesis Section (if generated) */}
      {(aiReport || investigation.ai_analysis_id) && (
        <div className="card" style={{
          marginBottom: 'var(--space-6)',
          padding: 'var(--space-6)',
          border: '1.5px solid var(--color-accent-soft)',
          background: 'var(--color-surface-elevated)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
            <Sparkles size={20} style={{ color: 'var(--color-accent)' }} />
            <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, margin: 0, color: 'var(--color-dark)' }}>
              AI Intelligence Synthesis
            </h2>
          </div>

          <div style={{
            fontSize: 'var(--text-sm)',
            lineHeight: 1.7,
            color: 'var(--color-text-primary)',
            background: 'var(--color-surface)',
            padding: 'var(--space-5)',
            borderRadius: 'var(--radius)',
            border: '1px solid var(--color-border)',
            whiteSpace: 'pre-wrap',
          }}>
            {aiReport?.summary || aiReport?.fullResponse || 'Intelligence analysis generated by Cloudflare Workers AI based on collected findings.'}
          </div>

          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginTop: 'var(--space-3)' }}>
            ⚠️ Evidence-grounded synthesis. No facts invented. Generated by {aiReport?.model || '@cf/meta/llama-3-8b-instruct'}.
          </div>
        </div>
      )}

      {/* View Switcher Tabs */}
      <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-4)', flexWrap: 'wrap' }}>
        <button
          onClick={() => setActiveTab('findings')}
          className={`btn btn-sm ${activeTab === 'findings' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <Database size={15} /> Discovered Findings ({findings.length})
        </button>
        <button
          onClick={() => setActiveTab('timeline')}
          className={`btn btn-sm ${activeTab === 'timeline' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <Clock size={15} /> Chronological Timeline ({timelineEvents.length})
        </button>
        <button
          onClick={() => setActiveTab('scorecard')}
          className={`btn btn-sm ${activeTab === 'scorecard' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <BarChart3 size={15} /> Intelligence Scorecard
        </button>
        <button
          onClick={() => setActiveTab('dorks')}
          className={`btn btn-sm ${activeTab === 'dorks' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <Compass size={15} /> OSINT Framework & Techniques ({findings.filter(f => f.category === 'osint_framework' || f.type === 'osint_search_dork' || f.type === 'pgp_public_key' || f.type === 'threat_ioc' || f.type === 'cloud_bucket').length})
        </button>
      </div>

      {/* TAB 1: FINDINGS TABLE */}
      {activeTab === 'findings' && (
        <div className="card">
          <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-4)' }}>
            <div>
              <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, margin: 0 }}>
                Discovered Findings ({filteredFindings.length})
              </h2>
            </div>

            <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center', flexWrap: 'wrap' }}>
              {/* Filter by Category */}
              <div style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                {categories.map(cat => (
                  <button
                    key={cat}
                    onClick={() => setSelectedCategory(cat)}
                    className={`btn btn-xs ${selectedCategory === cat ? 'btn-primary' : 'btn-ghost'}`}
                    style={{ textTransform: 'capitalize' }}
                  >
                    {cat.replace('_', ' ')}
                  </button>
                ))}
              </div>

              {/* Search Input */}
              <input
                type="text"
                className="input input-sm"
                placeholder="Search findings..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                style={{ width: '180px' }}
              />
            </div>
          </div>

          <div className="card-body" style={{ padding: 0 }}>
            {filteredFindings.length === 0 ? (
              <div style={{ padding: 'var(--space-12)', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                No findings matched the selected criteria.
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="table" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th style={{ width: '120px' }}>Category</th>
                      <th style={{ width: '140px' }}>Type</th>
                      <th>Value</th>
                      <th style={{ width: '100px' }}>Severity</th>
                      <th style={{ width: '100px' }}>Confidence</th>
                      <th style={{ width: '160px' }}>Source</th>
                      <th style={{ width: '90px' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFindings.map(f => {
                      const isExpanded = expandedFinding === f.id;
                      const pivot = detectPivotTarget(f);
                      return (
                        <>
                          <tr key={f.id} style={{ cursor: 'pointer' }} onClick={() => setExpandedFinding(isExpanded ? null : f.id)}>
                            <td>
                              <span className="badge badge-neutral" style={{ textTransform: 'capitalize' }}>
                                {f.category.replace('_', ' ')}
                              </span>
                            </td>
                            <td style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)' }}>
                              {f.type}
                            </td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', wordBreak: 'break-all' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                                <span>{f.value}</span>
                                {getRawDataObj(f)?.verified === true && (
                                  <span className="badge badge-success" style={{ fontSize: '10px', padding: '1px 6px', display: 'inline-flex', alignItems: 'center', gap: '3px', background: '#ecfdf5', color: '#047857', border: '1px solid #a7f3d0' }}>
                                    <Check size={10} /> Verified Profile
                                  </span>
                                )}
                                {f.source_url && (
                                  <a
                                    href={f.source_url}
                                    target="_blank"
                                    rel="noreferrer"
                                    onClick={(e) => e.stopPropagation()}
                                    title="Open source URL in new tab"
                                    style={{ color: 'var(--color-accent)', display: 'inline-flex' }}
                                  >
                                    <ExternalLink size={13} />
                                  </a>
                                )}
                              </div>
                              {f.notes && (
                                <div style={{ fontSize: 'var(--text-xs)', color: f.notes.includes('✓') ? '#059669' : 'var(--color-text-secondary)', fontFamily: 'var(--font-sans)', marginTop: 2, fontWeight: f.notes.includes('✓') ? 600 : 400 }}>
                                  {f.notes}
                                </div>
                              )}
                              {f.type === 'osint_search_dork' && f.source_url && (
                                <div style={{ marginTop: '6px' }}>
                                  <a
                                    href={f.source_url}
                                    target="_blank"
                                    rel="noreferrer"
                                    onClick={(e) => e.stopPropagation()}
                                    className="btn btn-xs"
                                    style={{
                                      background: 'var(--color-surface-elevated)',
                                      color: 'var(--color-accent)',
                                      border: '1px solid var(--color-border)',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '4px',
                                      fontSize: '11px',
                                      padding: '2px 8px'
                                    }}
                                  >
                                    <Search size={11} /> Launch OSINT Technique ({getRawDataObj(f)?.search_engine || 'Web'})
                                  </a>
                                </div>
                              )}
                              {f.category === 'location_intelligence' && (
                                <div style={{ marginTop: '6px', display: 'flex', gap: '8px', alignItems: 'center' }}>
                                  <a
                                    href={f.source_url || `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(f.value)}`}
                                    target="_blank"
                                    rel="noreferrer"
                                    onClick={(e) => e.stopPropagation()}
                                    className="btn btn-xs"
                                    style={{
                                      background: '#fff1f2',
                                      color: '#e11d48',
                                      border: '1px solid #fecdd3',
                                      fontWeight: 600,
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '4px',
                                      padding: '2px 8px'
                                    }}
                                  >
                                    <MapPin size={12} /> Open in Google Maps
                                  </a>
                                </div>
                              )}
                            </td>
                            <td>{getSeverityBadge(f.severity)}</td>
                            <td>
                              <span style={{ fontSize: 'var(--text-xs)', textTransform: 'capitalize' }}>
                                {f.confidence}
                              </span>
                            </td>
                            <td style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)' }}>
                              {f.source_name}
                            </td>
                            <td style={{ textAlign: 'center' }}>
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 'var(--space-2)' }}>
                                {pivot && (
                                  <Link
                                    to={`/investigate?q=${encodeURIComponent(pivot.target)}`}
                                    onClick={(e) => e.stopPropagation()}
                                    className="btn btn-xs btn-ghost"
                                    title={`Pivot to new investigation on ${pivot.target}`}
                                    style={{ color: 'var(--color-accent)' }}
                                  >
                                    <CornerUpRight size={14} />
                                  </Link>
                                )}
                                {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                              </div>
                            </td>
                          </tr>

                          {isExpanded && (
                            <tr key={`${f.id}-expanded`} style={{ background: 'var(--color-surface-elevated)' }}>
                              <td colSpan={7} style={{ padding: 'var(--space-4) var(--space-6)' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
                                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
                                    RAW ARTIFACT DATA (FIRST SEEN: {new Date(f.first_seen).toLocaleString()})
                                  </div>
                                  <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                                    {pivot && (
                                      <Link
                                        to={`/investigate?q=${encodeURIComponent(pivot.target)}`}
                                        className="btn btn-xs btn-primary"
                                        style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                      >
                                        <CornerUpRight size={12} /> Pivot to {pivot.target}
                                      </Link>
                                    )}
                                    <button
                                      onClick={() => handleCopyRaw(typeof f.raw_data === 'string' ? f.raw_data : JSON.stringify(f.raw_data, null, 2), f.id)}
                                      className="btn btn-xs btn-ghost"
                                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                    >
                                      {copiedId === f.id ? <Check size={12} /> : <Copy size={12} />}
                                      {copiedId === f.id ? 'Copied' : 'Copy JSON'}
                                    </button>
                                  </div>
                                </div>
                                <pre style={{
                                  margin: 0,
                                  padding: 'var(--space-3)',
                                  background: 'var(--color-surface)',
                                  borderRadius: 'var(--radius)',
                                  border: '1px solid var(--color-border)',
                                  fontSize: '11px',
                                  overflowX: 'auto',
                                }}>
                                  {(() => {
                                    try {
                                      return JSON.stringify(typeof f.raw_data === 'string' ? JSON.parse(f.raw_data) : f.raw_data, null, 2);
                                    } catch {
                                      return String(f.raw_data);
                                    }
                                  })()}
                                </pre>
                              </td>
                            </tr>
                          )}
                        </>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: CHRONOLOGICAL TIMELINE */}
      {activeTab === 'timeline' && (
        <div className="card" style={{ padding: 'var(--space-6)' }}>
          <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginBottom: 'var(--space-6)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Clock size={20} style={{ color: 'var(--color-accent)' }} /> Chronological Intelligence Timeline
          </h2>

          <div style={{ position: 'relative', paddingLeft: 'var(--space-6)', borderLeft: '2px solid var(--color-border)' }}>
            {timelineEvents.map((evt) => (
              <div key={evt.id} style={{ position: 'relative', marginBottom: 'var(--space-6)' }}>
                {/* Timeline node dot */}
                <div style={{
                  position: 'absolute',
                  left: 'calc(-1 * var(--space-6) - 5px)',
                  top: '4px',
                  width: '10px',
                  height: '10px',
                  borderRadius: '50%',
                  background: evt.severity === 'critical' || evt.severity === 'high' ? 'var(--color-error)' : 'var(--color-accent)',
                  boxShadow: '0 0 0 3px var(--color-bg)',
                }} />

                <div style={{
                  background: 'var(--color-bg)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius)',
                  padding: 'var(--space-4)',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                      <span className="badge badge-neutral" style={{ textTransform: 'capitalize', fontSize: '11px' }}>
                        {evt.category.replace('_', ' ')}
                      </span>
                      <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--color-dark)' }}>
                        {evt.type}
                      </strong>
                    </div>
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {new Date(evt.timestamp).toLocaleDateString()} {new Date(evt.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', color: 'var(--color-text-primary)', wordBreak: 'break-all' }}>
                    {evt.value}
                  </div>

                  {evt.notes && (
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', marginTop: 'var(--space-2)' }}>
                      {evt.notes}
                    </div>
                  )}

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 'var(--space-3)', fontSize: '11px', color: 'var(--color-text-muted)' }}>
                    <span>Source: {evt.source}</span>
                    {evt.sourceUrl && (
                      <a href={evt.sourceUrl} target="_blank" rel="noreferrer" style={{ color: 'var(--color-accent)', display: 'inline-flex', alignItems: 'center', gap: '3px' }}>
                        Source artifact <ExternalLink size={11} />
                      </a>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: INTELLIGENCE SCORECARD */}
      {activeTab === 'scorecard' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 'var(--space-6)' }}>
          {/* Exposure Gauge Card */}
          <div className="card" style={{ padding: 'var(--space-6)', textAlign: 'center' }}>
            <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: 'var(--space-4)' }}>
              Public Exposure & Surface Score
            </h3>
            <div style={{
              fontSize: '48px',
              fontWeight: 900,
              color: scorecard.exposureScore >= 75 ? 'var(--color-accent)' : scorecard.exposureScore >= 40 ? 'var(--color-warning)' : 'var(--color-text-primary)',
              lineHeight: 1,
              marginBottom: 'var(--space-2)',
            }}>
              {scorecard.exposureScore}/100
            </div>
            <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-dark)', marginBottom: 'var(--space-4)' }}>
              {scorecard.attributionLevel}
            </div>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
              Calculated based on verified Git commits, cross-platform usernames, published public emails, historical archives, and public infrastructure exposure.
            </p>
          </div>

          {/* Footprint Breakdown */}
          <div className="card" style={{ padding: 'var(--space-6)' }}>
            <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: 'var(--space-4)' }}>
              Discovered Entity Breakdown
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Verified Developer Commits</span>
                <strong style={{ color: 'var(--color-dark)' }}>{scorecard.commitsFound}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Correlated Email Identifiers</span>
                <strong style={{ color: 'var(--color-dark)' }}>{scorecard.emailsFound}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Social & Registry Profiles</span>
                <strong style={{ color: 'var(--color-dark)' }}>{scorecard.profilesFound}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Infrastructure & DNS Records</span>
                <strong style={{ color: 'var(--color-dark)' }}>{scorecard.infraFound}</strong>
              </div>
              {scorecard.portsAndCvesFound > 0 && (
                <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Ports & Vulnerabilities (Shodan)</span>
                  <strong style={{ color: 'var(--color-error)' }}>{scorecard.portsAndCvesFound}</strong>
                </div>
              )}
              {scorecard.locationsFound > 0 && (
                <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Geocoded Places & Coordinates</span>
                  <strong style={{ color: 'var(--color-accent)' }}>{scorecard.locationsFound}</strong>
                </div>
              )}
              {scorecard.phoneFound > 0 && (
                <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>E.164 Telephony & OSINT Dorks</span>
                  <strong style={{ color: 'var(--color-accent)' }}>{scorecard.phoneFound}</strong>
                </div>
              )}
              {scorecard.securityScore && (
                <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 'var(--space-2)', borderBottom: '1px solid var(--color-border)' }}>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Defensive Hygiene Posture</span>
                  <strong style={{ color: 'var(--color-dark)', fontSize: '12px' }}>{scorecard.securityScore}</strong>
                </div>
              )}
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>Compromised Breach Records</span>
                <strong style={{ color: scorecard.breachesFound > 0 ? 'var(--color-error)' : 'var(--color-dark)' }}>{scorecard.breachesFound}</strong>
              </div>
            </div>
          </div>

          {/* Threat & Severity Distribution */}
          <div className="card" style={{ padding: 'var(--space-6)' }}>
            <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: 'var(--space-4)' }}>
              Severity & Risk Distribution
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
              <div style={{ padding: 'var(--space-3)', background: 'var(--color-bg)', borderRadius: 'var(--radius)', border: '1px solid var(--color-border)' }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Critical / High</div>
                <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: 'var(--color-error)' }}>
                  {scorecard.criticalCount + scorecard.highCount}
                </div>
              </div>
              <div style={{ padding: 'var(--space-3)', background: 'var(--color-bg)', borderRadius: 'var(--radius)', border: '1px solid var(--color-border)' }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Medium / Low</div>
                <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: 'var(--color-warning)' }}>
                  {scorecard.mediumCount}
                </div>
              </div>
              <div style={{ gridColumn: 'span 2', padding: 'var(--space-3)', background: 'var(--color-bg)', borderRadius: 'var(--radius)', border: '1px solid var(--color-border)' }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>Total Intelligence Artifacts</div>
                <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: 'var(--color-accent)' }}>
                  {scorecard.total}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: OSINT FRAMEWORK & SEARCH TECHNIQUES */}
      {activeTab === 'dorks' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
          {/* Header & Quick Launch Bar */}
          <div className="card" style={{ padding: 'var(--space-6)', background: 'linear-gradient(135deg, rgba(37,99,235,0.06), rgba(16,185,129,0.06))', border: '1.5px solid var(--color-accent-soft)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-4)' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
                  <Compass size={22} style={{ color: 'var(--color-accent)' }} />
                  <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 800, margin: 0, color: 'var(--color-dark)' }}>
                    OSINT Framework & Search Operations
                  </h2>
                </div>
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', margin: 0, maxWidth: '750px' }}>
                  Targeted search techniques, dork strings, public keyserver correlations, cloud storage permutations, and threat intelligence telemetry tailored for <code style={{ fontWeight: 700, color: 'var(--color-dark)' }}>{investigation.target}</code>.
                </p>
              </div>

              <Link
                to={`/framework?target=${encodeURIComponent(investigation.target)}&type=${investigation.target_type}`}
                className="btn btn-primary"
                style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}
              >
                <Compass size={16} /> Open Interactive Hub
              </Link>
            </div>
          </div>

          {/* Engine Filter Bar */}
          <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginRight: 'var(--space-2)' }}>
              Filter Technique:
            </span>
            {['all', 'Google', 'GitHub', 'Shodan', 'Censys', 'Pastebin', 'Ubuntu PGP', 'Cloud Buckets'].map(eng => {
              const count = findings.filter(f => {
                if (eng === 'all') return f.category === 'osint_framework' || f.type === 'osint_search_dork' || f.type === 'pgp_public_key' || f.type === 'threat_ioc' || f.type === 'cloud_bucket';
                const raw = getRawDataObj(f);
                const name = (raw?.search_engine || raw?.provider || f.source_name || f.type).toLowerCase();
                return name.includes(eng.toLowerCase());
              }).length;

              return (
                <button
                  key={eng}
                  onClick={() => setDorkEngineFilter(eng)}
                  className={`btn btn-xs ${dorkEngineFilter === eng ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ textTransform: 'capitalize' }}
                >
                  {eng} ({count})
                </button>
              );
            })}
          </div>

          {/* Techniques Grid */}
          {(() => {
            const techniques = findings.filter(f => {
              const isTech = f.category === 'osint_framework' || f.type === 'osint_search_dork' || f.type === 'pgp_public_key' || f.type === 'threat_ioc' || f.type === 'cloud_bucket';
              if (!isTech) return false;
              if (dorkEngineFilter === 'all') return true;
              const raw = getRawDataObj(f);
              const name = (raw?.search_engine || raw?.provider || f.source_name || f.type).toLowerCase();
              return name.includes(dorkEngineFilter.toLowerCase());
            });

            if (techniques.length === 0) {
              return (
                <div className="card" style={{ padding: 'var(--space-12)', textAlign: 'center' }}>
                  <Search size={32} style={{ color: 'var(--color-text-muted)', marginBottom: 'var(--space-3)' }} />
                  <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
                    No automated techniques found in this category
                  </h3>
                  <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)', marginBottom: 'var(--space-4)' }}>
                    Launch the full interactive OSINT Framework Hub to query across all 28+ open-source intelligence services.
                  </p>
                  <Link
                    to={`/framework?target=${encodeURIComponent(investigation.target)}&type=${investigation.target_type}`}
                    className="btn btn-secondary btn-sm"
                  >
                    Open Framework Hub
                  </Link>
                </div>
              );
            }

            return (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 'var(--space-4)' }}>
                {techniques.map(tech => {
                  const raw = getRawDataObj(tech);
                  const engineName = raw?.search_engine || raw?.provider || tech.source_name || 'OSINT';
                  const queryText = raw?.query || tech.value;

                  return (
                    <div
                      key={tech.id}
                      className="card"
                      style={{
                        padding: 'var(--space-5)',
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'space-between',
                        gap: 'var(--space-3)',
                        border: '1px solid var(--color-border)',
                        background: 'var(--color-surface)',
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
                          <span className="badge badge-primary" style={{ fontSize: '11px', fontWeight: 700 }}>
                            {engineName}
                          </span>
                          <span className="badge badge-neutral" style={{ fontSize: '10px', textTransform: 'capitalize' }}>
                            {tech.type.replace(/_/g, ' ')}
                          </span>
                        </div>

                        <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-dark)', marginBottom: 'var(--space-2)' }}>
                          {tech.notes || raw?.purpose || tech.value}
                        </div>

                        {/* Query Preview Box */}
                        <div style={{
                          background: 'var(--color-bg)',
                          border: '1px solid var(--color-border)',
                          borderRadius: 'var(--radius)',
                          padding: 'var(--space-3)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: 'var(--text-xs)',
                          color: 'var(--color-text-primary)',
                          wordBreak: 'break-all',
                          maxHeight: '80px',
                          overflowY: 'auto',
                        }}>
                          {queryText}
                        </div>
                      </div>

                      {/* Action buttons */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 'var(--space-2)', borderTop: '1px solid var(--color-border-subtle)' }}>
                        <button
                          onClick={() => handleCopyRaw(queryText, tech.id)}
                          className="btn btn-ghost btn-xs"
                          style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                        >
                          {copiedId === tech.id ? <Check size={12} /> : <Copy size={12} />}
                          {copiedId === tech.id ? 'Copied' : 'Copy Query'}
                        </button>

                        {tech.source_url && (
                          <a
                            href={tech.source_url}
                            target="_blank"
                            rel="noreferrer"
                            className="btn btn-primary btn-xs"
                            style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                          >
                            <ExternalLink size={12} /> Launch in {engineName}
                          </a>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
