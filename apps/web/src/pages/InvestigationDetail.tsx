import { useState, useEffect, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  AlertTriangle, GitBranch, RefreshCw, Sparkles,
  FileText, ChevronDown, ChevronRight, Clock,
  ShieldCheck, BarChart3, CornerUpRight, ExternalLink,
  Copy, Check, Database, MapPin, Compass, Search,
  FileSpreadsheet, FileCode
} from 'lucide-react';
import { OSINT_TOOLS_REGISTRY, OSINT_CATEGORIES } from '@openspective/shared';
import { jsPDF } from 'jspdf';
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
  const [engineSearchFilter, setEngineSearchFilter] = useState('');
  const [engineCategoryFilter, setEngineCategoryFilter] = useState<string>('All');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);
  const [exportToast, setExportToast] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState<string | null>(null);
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

  const getToolMeta = (collectorName: string) => {
    if (COLLECTOR_OSINT_META[collectorName]) {
      return COLLECTOR_OSINT_META[collectorName];
    }
    const tool = OSINT_TOOLS_REGISTRY.find(t => t.id === collectorName);
    if (tool) {
      return {
        label: tool.name,
        suite: tool.subcategory || tool.category,
        icon: '🛡️',
      };
    }
    return {
      label: collectorName.replace(/_/g, ' '),
      suite: 'OSINT Intelligence Engine',
      icon: '⚡',
    };
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

  const triggerDownload = (blob: Blob, filename: string) => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      a.remove();
      window.URL.revokeObjectURL(url);
    }, 250);
  };

  const handleExport = async (format: 'json' | 'csv' | 'stix' | 'html' | 'pdf') => {
    if (!investigation) return;
    setIsExporting(format);

    try {
      // Ensure we export all findings from the database, not just the initial page
      let exportFindings = findings;
      try {
        const fullFindingsRes = await api.getFindings(investigation.id, undefined, 1, 3000);
        if (fullFindingsRes.data && fullFindingsRes.data.length > 0) {
          exportFindings = fullFindingsRes.data;
        }
      } catch {
        // fallback to state findings
      }

      const targetSlug = (investigation.target || 'target').replace(/[^a-zA-Z0-9_-]/g, '_');
      const filename = `openspective-${targetSlug}-${investigation.id.slice(0, 8)}.${format === 'stix' ? 'stix21.json' : format}`;

      if (format === 'pdf') {
        const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
        const pageWidth = 210;
        const pageHeight = 297;
        const margin = 14;
        const contentWidth = pageWidth - margin * 2; // 182mm

        const drawPageHeader = (_pageNum: number) => {
          doc.setFillColor(15, 23, 42); // slate-900
          doc.rect(0, 0, pageWidth, 28, 'F');
          
          doc.setFillColor(16, 185, 129); // emerald-500
          doc.rect(0, 28, pageWidth, 1.5, 'F');

          doc.setFont('helvetica', 'bold');
          doc.setFontSize(13);
          doc.setTextColor(255, 255, 255);
          doc.text('OPENSPECTIVE OSINT INTELLIGENCE PLATFORM', margin, 12);

          doc.setFont('helvetica', 'normal');
          doc.setFontSize(8);
          doc.setTextColor(148, 163, 184);
          doc.text('PASSIVE RECONNAISSANCE & ATTACK SURFACE DOSSIER', margin, 18);

          doc.setFont('helvetica', 'bold');
          doc.setFontSize(8);
          doc.setTextColor(52, 211, 153);
          doc.text('TLP:CLEAR / OPEN INTELLIGENCE', pageWidth - margin, 12, { align: 'right' });

          doc.setFont('helvetica', 'normal');
          doc.setTextColor(148, 163, 184);
          doc.text(`Generated: ${new Date().toLocaleDateString()}`, pageWidth - margin, 18, { align: 'right' });
        };

        const drawPageFooter = (pageNum: number, totalPages: number) => {
          doc.setDrawColor(203, 213, 225);
          doc.setLineWidth(0.3);
          doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);

          doc.setFont('helvetica', 'normal');
          doc.setFontSize(7.5);
          doc.setTextColor(100, 116, 139);
          doc.text('OpenSpective Intelligence Framework — Passive Threat & Footprint Analysis', margin, pageHeight - 7);
          doc.text(`Page ${pageNum} of ${totalPages}`, pageWidth - margin, pageHeight - 7, { align: 'right' });
        };

        drawPageHeader(1);
        let curY = 36;

        // Target Overview Box
        doc.setFillColor(248, 250, 252);
        doc.roundedRect(margin, curY, contentWidth, 32, 2, 2, 'F');
        doc.setDrawColor(226, 232, 240);
        doc.roundedRect(margin, curY, contentWidth, 32, 2, 2, 'S');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(100, 116, 139);
        doc.text('TARGET ENTITY', margin + 6, curY + 7);
        doc.text('STATUS & TELEMETRY', margin + 95, curY + 7);

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(14);
        doc.setTextColor(15, 23, 42);
        const targetTrunc = investigation.target.length > 32 ? investigation.target.slice(0, 32) + '...' : investigation.target;
        doc.text(targetTrunc, margin + 6, curY + 16);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8.5);
        doc.setTextColor(16, 185, 129);
        doc.text(`Target Type: ${investigation.target_type.toUpperCase()}`, margin + 6, curY + 23);
        doc.setTextColor(100, 116, 139);
        doc.text(`Investigation ID: ${investigation.id}`, margin + 6, curY + 28);

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(10);
        const statusColor = investigation.status === 'completed' ? [16, 185, 129] : [59, 130, 246];
        doc.setTextColor(statusColor[0], statusColor[1], statusColor[2]);
        doc.text(`STATUS: ${investigation.status.toUpperCase()}`, margin + 95, curY + 16);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8.5);
        doc.setTextColor(100, 116, 139);
        doc.text(`Engines Dispatched: ${executions.length} OSINT Collectors`, margin + 95, curY + 23);
        doc.text(`Total Intelligence Findings: ${exportFindings.length}`, margin + 95, curY + 28);

        curY += 38;

        // Metrics Scorecard Cards
        const cardWidth = (contentWidth - 9) / 4;
        const criticalCount = exportFindings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
        const mediumCount = exportFindings.filter(f => f.severity === 'medium').length;
        const lowCount = exportFindings.filter(f => f.severity === 'low' || f.severity === 'info' || !f.severity).length;
        const highConfCount = exportFindings.filter(f => f.confidence === 'high').length;

        const metrics = [
          { label: 'CRITICAL / HIGH', val: String(criticalCount), color: [239, 68, 68] },
          { label: 'MEDIUM ALERTS', val: String(mediumCount), color: [234, 179, 8] },
          { label: 'LOW / INFO', val: String(lowCount), color: [59, 130, 246] },
          { label: 'HIGH CONFIDENCE', val: String(highConfCount), color: [16, 185, 129] },
        ];

        metrics.forEach((m, idx) => {
          const x = margin + idx * (cardWidth + 3);
          doc.setFillColor(248, 250, 252);
          doc.roundedRect(x, curY, cardWidth, 18, 1.5, 1.5, 'F');
          doc.setDrawColor(226, 232, 240);
          doc.roundedRect(x, curY, cardWidth, 18, 1.5, 1.5, 'S');

          doc.setFont('helvetica', 'bold');
          doc.setFontSize(6.5);
          doc.setTextColor(100, 116, 139);
          doc.text(m.label, x + 4, curY + 6);

          doc.setFont('helvetica', 'bold');
          doc.setFontSize(12);
          doc.setTextColor(m.color[0], m.color[1], m.color[2]);
          doc.text(m.val, x + 4, curY + 14);
        });

        curY += 24;

        // AI Summary if exists
        if (aiReport?.summary) {
          doc.setFillColor(240, 253, 244); // emerald-50
          doc.setDrawColor(187, 247, 208);
          const aiLines = doc.splitTextToSize(`Executive Synthesis: ${aiReport.summary}`, contentWidth - 10);
          const boxHeight = Math.min(32, aiLines.length * 4.2 + 8);
          doc.roundedRect(margin, curY, contentWidth, boxHeight, 1.5, 1.5, 'FD');

          doc.setFont('helvetica', 'bold');
          doc.setFontSize(8);
          doc.setTextColor(21, 128, 61);
          doc.text('AI EXECUTIVE SYNTHESIS', margin + 5, curY + 6);

          doc.setFont('helvetica', 'normal');
          doc.setFontSize(7.5);
          doc.setTextColor(51, 65, 85);
          doc.text(aiLines.slice(0, 5), margin + 5, curY + 12);
          curY += boxHeight + 6;
        }

        // Section Title: Discovered Findings
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(10);
        doc.setTextColor(15, 23, 42);
        doc.text(`INTELLIGENCE FINDINGS & MULTI-HOP ARTIFACTS (${exportFindings.length})`, margin, curY);
        curY += 4;

        // Table Header
        const colX = {
          sev: margin + 2,
          cat: margin + 24,
          type: margin + 54,
          val: margin + 84,
          source: margin + 148,
          conf: margin + 172,
        };

        const drawTableHeader = (y: number) => {
          doc.setFillColor(226, 232, 240);
          doc.rect(margin, y, contentWidth, 7, 'F');
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(7);
          doc.setTextColor(51, 65, 85);
          doc.text('SEVERITY', colX.sev, y + 5);
          doc.text('CATEGORY', colX.cat, y + 5);
          doc.text('TYPE', colX.type, y + 5);
          doc.text('DISCOVERED VALUE', colX.val, y + 5);
          doc.text('SOURCE', colX.source, y + 5);
          doc.text('CONF.', colX.conf, y + 5);
        };

        drawTableHeader(curY);
        curY += 8;

        // Table Rows
        exportFindings.forEach((f, idx) => {
          if (curY > pageHeight - 20) {
            doc.addPage();
            drawPageHeader(doc.getNumberOfPages());
            curY = 36;
            drawTableHeader(curY);
            curY += 8;
          }

          if (idx % 2 === 1) {
            doc.setFillColor(248, 250, 252);
            doc.rect(margin, curY - 1, contentWidth, 6.5, 'F');
          }

          // Severity badge
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(6.5);
          if (f.severity === 'critical') doc.setTextColor(220, 38, 38);
          else if (f.severity === 'high') doc.setTextColor(234, 88, 12);
          else if (f.severity === 'medium') doc.setTextColor(202, 138, 4);
          else doc.setTextColor(71, 85, 105);
          doc.text((f.severity || 'info').toUpperCase(), colX.sev, curY + 3.5);

          // Category
          doc.setFont('helvetica', 'normal');
          doc.setFontSize(6.5);
          doc.setTextColor(15, 23, 42);
          const catStr = f.category.length > 15 ? f.category.slice(0, 15) : f.category;
          doc.text(catStr, colX.cat, curY + 3.5);

          // Type
          const typeStr = f.type.length > 15 ? f.type.slice(0, 15) : f.type;
          doc.text(typeStr, colX.type, curY + 3.5);

          // Value
          doc.setFont('helvetica', 'bold');
          doc.setTextColor(2, 132, 199);
          const valStr = f.value.length > 36 ? f.value.slice(0, 35) + '...' : f.value;
          doc.text(valStr, colX.val, curY + 3.5);

          // Source
          doc.setFont('helvetica', 'normal');
          doc.setTextColor(100, 116, 139);
          const srcStr = (f.source_name || 'OpenSpective').slice(0, 14);
          doc.text(srcStr, colX.source, curY + 3.5);

          // Confidence
          doc.setFont('helvetica', 'bold');
          if (f.confidence === 'high') doc.setTextColor(16, 185, 129);
          else if (f.confidence === 'medium') doc.setTextColor(202, 138, 4);
          else doc.setTextColor(148, 163, 184);
          doc.text((f.confidence || 'med').toUpperCase().slice(0, 4), colX.conf, curY + 3.5);

          curY += 6.5;
        });

        // Add page footers to all pages
        const totalPages = doc.getNumberOfPages();
        for (let i = 1; i <= totalPages; i++) {
          doc.setPage(i);
          drawPageFooter(i, totalPages);
        }

        doc.save(filename);
      } else if (format === 'json') {
        const reportData = {
          meta: {
            title: 'OpenSpective Passive OSINT Platform Report',
            target: investigation.target,
            targetType: investigation.target_type,
            status: investigation.status,
            startedAt: investigation.started_at,
            completedAt: investigation.completed_at,
            findingsCount: exportFindings.length,
            collectorsCount: executions.length,
            generatedAt: new Date().toISOString(),
            methodology: 'Passive multi-engine intelligence collection across public DNS, RDAP, certificate transparency, threat IOCs, developer registries, social check-in footprints, Google Maps reviews, and search dorks.',
          },
          investigation,
          collectors: executions,
          findings: exportFindings,
          aiAnalysis: aiReport || null,
        };
        const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
        triggerDownload(blob, filename);
      } else if (format === 'csv') {
        const headers = ['id', 'category', 'subcategory', 'type', 'value', 'confidence', 'severity', 'source_name', 'source_url', 'first_seen', 'notes'];
        const escapeCsv = (val: any) => {
          const s = String(val ?? '');
          return s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')
            ? `"${s.replace(/"/g, '""')}"`
            : s;
        };
        const rows = exportFindings.map(f => [
          escapeCsv(f.id),
          escapeCsv(f.category),
          escapeCsv(f.subcategory),
          escapeCsv(f.type),
          escapeCsv(f.value),
          escapeCsv(f.confidence),
          escapeCsv(f.severity),
          escapeCsv(f.source_name),
          escapeCsv(f.source_url),
          escapeCsv(f.first_seen),
          escapeCsv(f.notes)
        ].join(','));
        const csvContent = '\uFEFF' + [headers.join(','), ...rows].join('\r\n');
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        triggerDownload(blob, filename);
      } else if (format === 'stix') {
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
            number_observed: exportFindings.length,
            objects: {
              '0': {
                type: investigation.target_type === 'ip' ? 'ipv4-addr' : investigation.target_type === 'email' ? 'email-addr' : 'domain-name',
                value: investigation.target,
              },
            },
          },
        ];

        exportFindings.forEach((f) => {
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
        triggerDownload(blob, filename);
      } else if (format === 'html') {
        const escapeHtml = (s: any) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        
        const findingsRows = exportFindings.map(f => `
          <tr>
            <td><span class="badge badge-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></td>
            <td><strong>${escapeHtml(f.category)}</strong><div class="sub">${escapeHtml(f.type)}</div></td>
            <td class="code-val">${escapeHtml(f.value)}</td>
            <td><span class="conf conf-${escapeHtml(f.confidence)}">${escapeHtml(f.confidence)}</span></td>
            <td>${escapeHtml(f.source_name || 'OpenSpective')}</td>
            <td class="notes">${escapeHtml(f.notes || '—')}</td>
          </tr>
        `).join('');

        const collectorsRows = executions.map(e => `
          <tr>
            <td><strong>${escapeHtml(e.collector_name)}</strong></td>
            <td><span class="status status-${escapeHtml(e.status)}">${escapeHtml(e.status)}</span></td>
            <td>${e.findings_count} findings</td>
            <td>${e.completed_at ? new Date(e.completed_at).toLocaleTimeString() : 'In progress'}</td>
            <td class="sub">${escapeHtml(e.error_message || 'Clean execution')}</td>
          </tr>
        `).join('');

        const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenSpective Intelligence Dossier — ${escapeHtml(investigation.target)}</title>
<style>
  :root {
    --bg: #0f172a;
    --surface: #1e293b;
    --border: #334155;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --accent: #10b981;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 2.5rem; line-height: 1.5; }
  .header { display: flex; justify-content: space-between; align-items: flex-start; padding-bottom: 2rem; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand-icon { width: 40px; height: 40px; border-radius: 10px; background: linear-gradient(135deg, #10b981, #3b82f6); display: flex; align-items: center; justify-content: center; font-size: 20px; font-weight: bold; color: white; }
  .title { font-size: 1.75rem; font-weight: 800; }
  .subtitle { color: var(--text-muted); font-size: 0.9rem; }
  .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .metric-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; }
  .metric-label { font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; margin-bottom: 4px; }
  .metric-value { font-size: 1.85rem; font-weight: 800; color: var(--text); }
  .section-title { font-size: 1.25rem; font-weight: 700; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 12px; overflow: hidden; border: 1px solid var(--border); margin-bottom: 2rem; font-size: 0.875rem; }
  th { background: #162032; text-align: left; padding: 12px 16px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
  td { padding: 12px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
  .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
  .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }
  .badge-medium { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }
  .badge-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
  .badge-info, .badge-none { background: rgba(148, 163, 184, 0.15); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.2); }
  .status { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; }
  .status-completed { color: #34d399; }
  .status-running { color: #60a5fa; }
  .status-failed { color: #f87171; }
  .code-val { font-family: ui-monospace, SFMono-Regular, monospace; word-break: break-all; color: #38bdf8; }
  .sub { font-size: 0.75rem; color: var(--text-muted); margin-top: 2px; }
  .notes { color: var(--text-muted); font-size: 0.8rem; }
  .conf { font-weight: 600; font-size: 0.8rem; text-transform: capitalize; }
  .conf-high { color: #34d399; }
  .conf-medium { color: #facc15; }
  .conf-low { color: #94a3b8; }
  .ai-box { background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; line-height: 1.6; }
  .footer { text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 4rem; padding-top: 1.5rem; border-top: 1px solid var(--border); }
  @media print {
    body { background: white; color: black; padding: 1rem; }
    .metric-card, table, .ai-box { background: white; border: 1px solid #ccc; color: black; }
    th { background: #f1f5f9; color: black; }
    td { border-bottom: 1px solid #eee; }
    .code-val { color: black; }
  }
</style>
</head>
<body>
  <div class="header">
    <div class="brand">
      <div class="brand-icon">⚡</div>
      <div>
        <div class="title">OpenSpective OSINT Dossier</div>
        <div class="subtitle">Comprehensive Multi-Engine Intelligence & Attack Surface Analysis</div>
      </div>
    </div>
    <div style="text-align: right;">
      <div style="font-size: 0.8rem; color: var(--text-muted);">Generated: ${new Date().toLocaleString()}</div>
      <div style="font-size: 0.85rem; font-weight: 700; color: var(--accent); margin-top: 4px;">Classification: Open Intelligence</div>
    </div>
  </div>

  <div class="metrics-grid">
    <div class="metric-card">
      <div class="metric-label">Target Entity</div>
      <div class="metric-value" style="font-size: 1.25rem; word-break: break-all;">${escapeHtml(investigation.target)}</div>
      <div class="sub" style="text-transform: capitalize;">${escapeHtml(investigation.target_type)} Target</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Status</div>
      <div class="metric-value" style="color: ${investigation.status === 'completed' ? '#34d399' : '#60a5fa'}; text-transform: uppercase; font-size: 1.5rem;">${escapeHtml(investigation.status)}</div>
      <div class="sub">${executions.length} Collectors Dispatched</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Discovered Findings</div>
      <div class="metric-value" style="color: #38bdf8;">${exportFindings.length}</div>
      <div class="sub">${exportFindings.filter(f => f.confidence === 'high').length} High Confidence</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Critical / High Alerts</div>
      <div class="metric-value" style="color: ${exportFindings.filter(f => f.severity === 'critical' || f.severity === 'high').length > 0 ? '#f87171' : '#34d399'};">
        ${exportFindings.filter(f => f.severity === 'critical' || f.severity === 'high').length}
      </div>
      <div class="sub">Immediate attention items</div>
    </div>
  </div>

  ${aiReport?.summary ? `
    <div class="section-title">🤖 AI Executive Synthesis</div>
    <div class="ai-box">
      <strong>Executive Summary:</strong>
      <p style="margin-top: 8px;">${escapeHtml(aiReport.summary)}</p>
      ${aiReport.recommendations ? `<div style="margin-top: 12px;"><strong>Key Recommendations:</strong><p style="margin-top: 4px;">${escapeHtml(aiReport.recommendations)}</p></div>` : ''}
    </div>
  ` : ''}

  <div class="section-title">📊 Intelligence Findings (${exportFindings.length})</div>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Category & Type</th>
        <th>Discovered Value</th>
        <th>Confidence</th>
        <th>Source</th>
        <th>Notes / Context</th>
      </tr>
    </thead>
    <tbody>
      ${findingsRows || '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No findings recorded.</td></tr>'}
    </tbody>
  </table>

  <div class="section-title">⚙️ OSINT Engines & Execution Telemetry (${executions.length})</div>
  <table>
    <thead>
      <tr>
        <th>Engine / Collector</th>
        <th>Status</th>
        <th>Findings</th>
        <th>Execution Timestamp</th>
        <th>Diagnostic Notes</th>
      </tr>
    </thead>
    <tbody>
      ${collectorsRows || '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No collector records.</td></tr>'}
    </tbody>
  </table>

  <div class="footer">
    OpenSpective Intelligence Platform — Passive OSINT Reconnaissance Framework — Strictly For Authorized Security Research.
  </div>
</body>
</html>`;
        const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8;' });
        triggerDownload(blob, filename);
      }

      setExportToast(`Exported ${format.toUpperCase()} report successfully!`);
      setTimeout(() => setExportToast(null), 3500);
    } catch (err: any) {
      alert(`Export error: ${err?.message || 'Failed to generate report.'}`);
    } finally {
      setIsExporting(null);
    }
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
    <div className="ambient-bg-wrapper" style={{ maxWidth: '1400px', margin: '0 auto', padding: 'var(--space-6) var(--space-8)', position: 'relative' }}>
      {/* Ambient Blurry Floating Glow Orbs */}
      <div className="ambient-orb ambient-orb-primary" style={{ top: '-100px', right: '5%' }} />
      <div className="ambient-orb ambient-orb-blue" style={{ top: '250px', left: '-80px' }} />
      <div className="ambient-orb ambient-orb-purple" style={{ bottom: '150px', right: '-60px' }} />

      {/* Target Banner */}
      <div className="glass-panel" style={{ marginBottom: 'var(--space-6)', padding: 'var(--space-6)', position: 'relative', zIndex: 1 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 'var(--space-4)' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-2)' }}>
              <h1 style={{ fontSize: 'var(--text-3xl)', fontWeight: 800, color: 'var(--color-dark)', margin: 0 }}>
                {investigation.target}
              </h1>
              <span className="glass-pill" style={{ textTransform: 'capitalize' }}>
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

            <div className="glass-panel-subtle" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)', padding: '4px 8px', borderRadius: 'var(--radius)' }}>
              <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginRight: '4px', letterSpacing: '0.05em' }}>
                Export:
              </span>
              <button
                onClick={() => handleExport('json')}
                disabled={isExporting !== null}
                className="btn btn-ghost btn-xs"
                title="Export complete JSON raw dump"
                style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}
              >
                <FileCode size={13} style={{ color: 'var(--color-accent)' }} /> JSON
              </button>
              <button
                onClick={() => handleExport('csv')}
                disabled={isExporting !== null}
                className="btn btn-ghost btn-xs"
                title="Export Excel/Sheets UTF-8 CSV"
                style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}
              >
                <FileSpreadsheet size={13} style={{ color: 'var(--color-info)' }} /> CSV
              </button>
              <button
                onClick={() => handleExport('stix')}
                disabled={isExporting !== null}
                className="btn btn-ghost btn-xs"
                title="Export OASIS STIX 2.1 Threat Intel Bundle"
                style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}
              >
                <ShieldCheck size={13} style={{ color: '#9333ea' }} /> STIX 2.1
              </button>
              <button
                onClick={() => handleExport('html')}
                disabled={isExporting !== null}
                className="btn btn-ghost btn-xs"
                title="Download Standalone HTML Intelligence Dossier"
                style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}
              >
                <FileText size={13} style={{ color: 'var(--color-accent)' }} /> HTML
              </button>
              <button
                onClick={() => handleExport('pdf')}
                disabled={isExporting !== null}
                className="btn btn-ghost btn-xs"
                title="Generate and Download Official PDF Intelligence Report"
                style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}
              >
                <FileText size={13} style={{ color: '#ef4444' }} /> {isExporting === 'pdf' ? 'Rendering...' : 'PDF'}
              </button>
            </div>

            {/* Export Success Toast */}
            {exportToast && (
              <div
                className="glass-pill"
                style={{
                  position: 'fixed',
                  bottom: '24px',
                  right: '24px',
                  background: 'rgba(16, 185, 129, 0.9)',
                  color: 'white',
                  padding: '10px 18px',
                  borderRadius: 'var(--radius-lg)',
                  boxShadow: '0 8px 30px rgba(0,0,0,0.25)',
                  zIndex: 9999,
                  fontSize: '13px',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  animation: 'shimmerAnim 2s infinite'
                }}
              >
                <Check size={16} /> {exportToast}
              </div>
            )}

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
        className="glass-card"
        style={{
          marginBottom: 'var(--space-6)',
          padding: 'var(--space-6)',
          background: investigation.status === 'running'
            ? 'linear-gradient(135deg, rgba(37, 99, 235, 0.12) 0%, rgba(16, 185, 129, 0.08) 100%)'
            : investigation.status === 'completed'
            ? 'linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(37, 99, 235, 0.05) 100%)'
            : 'var(--glass-bg-card)',
          border: investigation.status === 'running'
            ? '1.5px solid var(--color-accent)'
            : '1px solid var(--glass-border)',
          boxShadow: investigation.status === 'running'
            ? '0 0 28px rgba(37, 99, 235, 0.22)'
            : 'var(--glass-shadow)',
          position: 'relative',
          overflow: 'hidden',
          zIndex: 1,
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
      <div className="card glass-panel" style={{ marginBottom: 'var(--space-6)', padding: 'var(--space-5)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-3)', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
          <div>
            <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 800, color: 'var(--color-dark)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldCheck size={18} style={{ color: 'var(--color-accent)' }} />
              Active Intelligence Telemetry ({executions.length} OSINT Tool Engines Executed)
            </h3>
            <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
              All 173 intelligence collectors record isolated telemetry, timing, and discovered artifacts. Click any engine to view its specific findings.
            </span>
          </div>
          {selectedCollector && (
            <button
              onClick={() => setSelectedCollector(null)}
              className="btn btn-ghost btn-xs"
              style={{ fontSize: '11px', color: 'var(--color-accent)', fontWeight: 700 }}
            >
              Reset Filter (Showing: {getToolMeta(selectedCollector).label})
            </button>
          )}
        </div>

        {/* Engine Search & Category Filter Controls */}
        <div style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-4)', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: '1 1 240px', position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
            <input
              type="text"
              className="input"
              style={{ paddingLeft: '32px', height: '34px', fontSize: '12px' }}
              placeholder="Search 173 executed engines (e.g. Shodan, WHOIS, Sherlock, crt.sh)..."
              value={engineSearchFilter}
              onChange={(e) => setEngineSearchFilter(e.target.value)}
            />
            {engineSearchFilter && (
              <button
                type="button"
                onClick={() => setEngineSearchFilter('')}
                style={{ position: 'absolute', right: '8px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer', fontSize: '11px' }}
              >
                ✕
              </button>
            )}
          </div>
          <div style={{ flex: '0 1 220px' }}>
            <select
              className="input"
              style={{ height: '34px', fontSize: '12px' }}
              value={engineCategoryFilter}
              onChange={(e) => setEngineCategoryFilter(e.target.value)}
            >
              {OSINT_CATEGORIES.map(cat => (
                <option key={cat} value={cat}>
                  {cat}
                </option>
              ))}
            </select>
          </div>
          <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 600 }}>
            Showing {executions.filter(exec => {
              const meta = getToolMeta(exec.collector_name);
              if (engineCategoryFilter !== 'All Tools' && engineCategoryFilter !== 'All') {
                if (!meta.suite.toLowerCase().includes(engineCategoryFilter.toLowerCase())) return false;
              }
              if (!engineSearchFilter.trim()) return true;
              const q = engineSearchFilter.toLowerCase();
              return meta.label.toLowerCase().includes(q) || meta.suite.toLowerCase().includes(q) || exec.collector_name.toLowerCase().includes(q);
            }).length} of {executions.length} OSINT engines
          </div>
        </div>

        {/* Scrollable Telemetry Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(210px, 1fr))',
          gap: 'var(--space-3)',
          maxHeight: '440px',
          overflowY: 'auto',
          paddingRight: '6px'
        }}>
          {executions
            .filter(exec => {
              const meta = getToolMeta(exec.collector_name);
              if (engineCategoryFilter !== 'All Tools' && engineCategoryFilter !== 'All') {
                if (!meta.suite.toLowerCase().includes(engineCategoryFilter.toLowerCase())) return false;
              }
              if (!engineSearchFilter.trim()) return true;
              const q = engineSearchFilter.toLowerCase();
              return meta.label.toLowerCase().includes(q) || meta.suite.toLowerCase().includes(q) || exec.collector_name.toLowerCase().includes(q);
            })
            .map(exec => {
              const meta = getToolMeta(exec.collector_name);
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
                  className="glass-card"
                  style={{
                    padding: 'var(--space-3)',
                    borderRadius: 'var(--radius)',
                    background: isFilterActive ? 'rgba(37, 99, 235, 0.12)' : 'var(--color-bg)',
                    border: isFilterActive ? '2px solid var(--color-accent)' : '1px solid var(--color-border)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    boxShadow: isFilterActive ? '0 0 12px rgba(37, 99, 235, 0.25)' : 'none',
                  }}
                  title={`Click to filter findings from ${meta.label}`}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '4px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden' }}>
                      <span style={{ fontSize: '13px' }}>{meta.icon}</span>
                      <strong style={{ fontSize: '11px', fontWeight: 800, color: 'var(--color-dark)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {meta.label}
                      </strong>
                    </div>
                    {getStatusBadge(exec.status)}
                  </div>

                  <div style={{ fontSize: '10px', color: 'var(--color-text-muted)', marginBottom: '6px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {meta.suite}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', color: 'var(--color-text-secondary)', borderTop: '1px solid var(--color-border-subtle)', paddingTop: '4px' }}>
                    <span style={{ fontWeight: exec.findings_count > 0 ? 700 : 400, color: exec.findings_count > 0 ? 'var(--color-dark)' : 'var(--color-text-muted)', fontSize: '10px' }}>
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
                    height: '3px',
                    background: 'var(--color-border)',
                    borderRadius: '2px',
                    overflow: 'hidden',
                    marginTop: '5px'
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
