// OpenSpective — DNS Collector
// Uses Cloudflare DNS over HTTPS (1.1.1.1) for passive resolution.
// No direct DNS socket access needed in Workers.

import type { DnsResult, DnsRecord } from '@openspective/shared';

const CF_DOH_URL = 'https://cloudflare-dns.com/dns-query';
const DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'] as const;
type DnsRecordType = (typeof DNS_RECORD_TYPES)[number];

interface DoHAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DoHResponse {
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
  Question: Array<{ name: string; type: number }>;
  Answer?: DoHAnswer[];
  Authority?: DoHAnswer[];
}

// DNS type numbers
const DNS_TYPE_MAP: Record<DnsRecordType, number> = {
  A: 1,
  AAAA: 28,
  CNAME: 5,
  MX: 15,
  NS: 2,
  TXT: 16,
  SOA: 6,
  CAA: 257,
};

async function queryDnsRecord(
  domain: string,
  type: DnsRecordType
): Promise<DnsRecord[]> {
  const url = `${CF_DOH_URL}?name=${encodeURIComponent(domain)}&type=${type}`;

  const response = await fetch(url, {
    headers: { Accept: 'application/dns-json' },
    signal: AbortSignal.timeout(8000),
  });

  if (!response.ok) return [];

  const data: DoHResponse = await response.json();
  if (data.Status !== 0) return []; // NXDOMAIN or error

  const records: DnsRecord[] = [];
  const answers = data.Answer ?? [];
  const expectedType = DNS_TYPE_MAP[type];

  for (const answer of answers) {
    if (answer.type !== expectedType) continue;
    let value = answer.data;
    let priority: number | null = null;

    // MX records come as "10 mail.example.com." — extract priority
    if (type === 'MX') {
      const parts = value.split(' ');
      if (parts.length === 2) {
        priority = parseInt(parts[0]!, 10);
        value = parts[1]!.replace(/\.$/, '');
      }
    }

    // Remove trailing dot from domain values
    if (['CNAME', 'NS', 'SOA'].includes(type)) {
      value = value.replace(/\.$/, '');
    }

    // TXT records come quoted
    if (type === 'TXT') {
      value = value.replace(/^"|"$/g, '').replace(/"\s*"/g, '');
    }

    records.push({
      type,
      name: answer.name.replace(/\.$/, ''),
      value,
      ttl: answer.TTL,
      priority,
      collectedAt: new Date().toISOString(),
    });
  }

  return records;
}

export async function collectDns(domain: string): Promise<DnsResult> {
  const collectedAt = new Date().toISOString();
  const allRecords: DnsRecord[] = [];
  const errors: string[] = [];

  // Query each record type with bounded concurrency (batches of 4)
  const types = [...DNS_RECORD_TYPES];
  for (let i = 0; i < types.length; i += 4) {
    const batch = types.slice(i, i + 4);
    const results = await Promise.allSettled(
      batch.map(type => queryDnsRecord(domain, type))
    );
    for (let j = 0; j < results.length; j++) {
      const result = results[j];
      const type = batch[j]!;
      if (!result) continue;
      if (result.status === 'fulfilled') {
        allRecords.push(...result.value);
      } else {
        errors.push(`DNS ${type} query failed: ${result.reason}`);
      }
    }
  }

  return {
    domain,
    records: allRecords,
    source: 'Cloudflare DNS over HTTPS (1.1.1.1)',
    collectedAt,
    errors,
  };
}

// Extract domain from email
export function domainFromEmail(email: string): string {
  const parts = email.split('@');
  return parts[parts.length - 1]!.toLowerCase();
}
