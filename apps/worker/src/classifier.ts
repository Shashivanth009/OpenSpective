// OpenSpective — Target Type Classifier
// Deterministic server-side classification of investigation targets.
// AI is NOT used for classification — this is purely syntactic/regex-based.

import type { TargetType, ClassificationResult, ConfidenceLevel } from '@openspective/shared';
import { detectCryptoNetwork } from './collectors/crypto.ts';

// Regex patterns
const EMAIL_REGEX = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
const IPV4_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
// Simplified IPv6 check — covers most common forms
const IPV6_REGEX = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::([fF]{4}(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;
const DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const URL_REGEX = /^(https?|ftp):\/\/.+/i;
// International phone: +CC followed by 6-14 digits
const PHONE_REGEX = /^\+[1-9]\d{6,14}$/;
// Username starting with @ or containing only alphanumeric/underscore/hyphen/dot
const USERNAME_AT_REGEX = /^@[a-zA-Z0-9._\-]{1,50}$/;
const USERNAME_PLAIN_REGEX = /^[a-zA-Z0-9._\-]{2,30}$/;

// Private/reserved IP ranges
const PRIVATE_IP_RANGES = [
  [0x0a000000, 0x0affffff], // 10.0.0.0/8
  [0xac100000, 0xac1fffff], // 172.16.0.0/12
  [0xc0a80000, 0xc0a8ffff], // 192.168.0.0/16
  [0x7f000000, 0x7fffffff], // 127.0.0.0/8
  [0xa9fe0000, 0xa9feffff], // 169.254.0.0/16 (link-local)
  [0xe0000000, 0xefffffff], // 224.0.0.0/4 (multicast)
  [0xf0000000, 0xffffffff], // 240.0.0.0/4 (reserved)
  [0x00000000, 0x00ffffff], // 0.0.0.0/8
  [0x64400000, 0x647fffff], // 100.64.0.0/10 (shared address space)
  [0xc0000000, 0xc00000ff], // 192.0.0.0/24
  [0xc0000200, 0xc00002ff], // 192.0.2.0/24 (TEST-NET-1)
  [0xc6336400, 0xc63364ff], // 198.51.100.0/24 (TEST-NET-2)
  [0xcb007100, 0xcb0071ff], // 203.0.113.0/24 (TEST-NET-3)
];

export function isPrivateIp(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  const num =
    ((parts[0]! << 24) >>> 0) +
    ((parts[1]! << 16) >>> 0) +
    ((parts[2]! << 8) >>> 0) +
    (parts[3]! >>> 0);
  return PRIVATE_IP_RANGES.some(([start, end]) => num >= start! && num <= end!);
}

export function validateIpv4(ip: string): boolean {
  if (!IPV4_REGEX.test(ip)) return false;
  const parts = ip.split('.').map(Number);
  return parts.every(p => p >= 0 && p <= 255);
}

// Normalize a target string
export function normalizeTarget(target: string, type: TargetType): string {
  const trimmed = target.trim();
  switch (type) {
    case 'email':
      return trimmed.toLowerCase();
    case 'domain':
      return trimmed.toLowerCase().replace(/^www\./, '');
    case 'url':
      try {
        const url = new URL(trimmed);
        return url.href;
      } catch {
        return trimmed.toLowerCase();
      }
    case 'ip':
      return trimmed.toLowerCase();
    case 'username':
      return trimmed.startsWith('@') ? trimmed.slice(1).toLowerCase() : trimmed.toLowerCase();
    case 'phone': {
      // Remove spaces and hyphens, keep + and digits
      return trimmed.replace(/[\s\-().]/g, '');
    }
    case 'crypto_wallet':
      return trimmed;
    case 'person':
    case 'organization':
      // Title-case
      return trimmed
        .split(/\s+/)
        .map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
        .join(' ');
    default:
      return trimmed;
  }
}

// Main classification function
export function classifyTarget(rawInput: string): ClassificationResult {
  const input = rawInput.trim();

  if (!input) {
    return {
      targetType: 'unknown',
      normalizedTarget: '',
      confidence: 'unknown',
      alternatives: [],
      validationMessage: 'Input is empty.',
      isAmbiguous: false,
    };
  }

  // URL check — must come before domain check
  if (URL_REGEX.test(input)) {
    try {
      const url = new URL(input);
      return {
        targetType: 'url',
        normalizedTarget: url.href,
        confidence: 'high',
        alternatives: ['domain'],
        validationMessage: null,
        isAmbiguous: false,
      };
    } catch {
      // falls through
    }
  }

  // Email check — must come before domain/username
  if (EMAIL_REGEX.test(input)) {
    return {
      targetType: 'email',
      normalizedTarget: input.toLowerCase(),
      confidence: 'high',
      alternatives: [],
      validationMessage: null,
      isAmbiguous: false,
    };
  }

  // Cryptocurrency Wallet check (Bitcoin, Ethereum, Solana, TRON)
  const cryptoNet = detectCryptoNetwork(input);
  if (cryptoNet !== 'unknown') {
    return {
      targetType: 'crypto_wallet',
      normalizedTarget: input,
      confidence: 'high',
      alternatives: ['username'],
      validationMessage: null,
      isAmbiguous: false,
    };
  }

  // IPv6
  if (IPV6_REGEX.test(input)) {
    return {
      targetType: 'ip',
      normalizedTarget: input.toLowerCase(),
      confidence: 'high',
      alternatives: [],
      validationMessage: null,
      isAmbiguous: false,
    };
  }

  // IPv4
  if (validateIpv4(input)) {
    if (isPrivateIp(input)) {
      return {
        targetType: 'ip',
        normalizedTarget: input,
        confidence: 'high',
        alternatives: [],
        validationMessage: `${input} is a private/reserved address. Only public IPs can be investigated externally.`,
        isAmbiguous: false,
      };
    }
    return {
      targetType: 'ip',
      normalizedTarget: input,
      confidence: 'high',
      alternatives: [],
      validationMessage: null,
      isAmbiguous: false,
    };
  }

  // Phone (international format)
  if (PHONE_REGEX.test(input)) {
    return {
      targetType: 'phone',
      normalizedTarget: input,
      confidence: 'high',
      alternatives: [],
      validationMessage: null,
      isAmbiguous: false,
    };
  }

  // Username starting with @
  if (USERNAME_AT_REGEX.test(input)) {
    return {
      targetType: 'username',
      normalizedTarget: input.slice(1).toLowerCase(),
      confidence: 'high',
      alternatives: [],
      validationMessage: null,
      isAmbiguous: false,
    };
  }

  // Domain check
  if (DOMAIN_REGEX.test(input)) {
    const normalized = input.toLowerCase().replace(/^www\./, '');
    return {
      targetType: 'domain',
      normalizedTarget: normalized,
      confidence: 'high',
      alternatives: ['organization'],
      validationMessage: null,
      isAmbiguous: false,
    };
  }

  // Ambiguous text — could be person, organization, or username
  const wordCount = input.split(/\s+/).length;

  if (wordCount >= 2) {
    // Multi-word — likely person or organization
    // Heuristic: if all words start with capital letters, lean person/org
    const looksLikeProper = input.split(/\s+/).every(w => /^[A-Z]/.test(w));
    if (looksLikeProper) {
      return {
        targetType: wordCount <= 3 ? 'person' : 'organization',
        normalizedTarget: input.trim(),
        confidence: 'low',
        alternatives: ['organization', 'person'],
        validationMessage: `"${input}" is ambiguous. Please confirm whether this is a person name or organization name.`,
        isAmbiguous: true,
      };
    }
    return {
      targetType: 'organization',
      normalizedTarget: input.trim(),
      confidence: 'low',
      alternatives: ['person'],
      validationMessage: `"${input}" is ambiguous. Please confirm the target type.`,
      isAmbiguous: true,
    };
  }

  // Single word — could be username or organization
  if (USERNAME_PLAIN_REGEX.test(input)) {
    return {
      targetType: 'username',
      normalizedTarget: input.toLowerCase(),
      confidence: 'low',
      alternatives: ['organization', 'person'],
      validationMessage: `"${input}" is ambiguous. It could be a username, organization, or person. Please confirm the target type.`,
      isAmbiguous: true,
    };
  }

  return {
    targetType: 'unknown',
    normalizedTarget: input,
    confidence: 'unknown',
    alternatives: [],
    validationMessage: `Could not classify "${input}". Please select a target type manually.`,
    isAmbiguous: true,
  };
}

// Validate a target given a confirmed type
export function validateTargetForType(
  target: string,
  type: TargetType
): { valid: boolean; message: string | null } {
  const input = target.trim();

  switch (type) {
    case 'email':
      if (!EMAIL_REGEX.test(input)) return { valid: false, message: 'Invalid email address format.' };
      return { valid: true, message: null };

    case 'domain':
      if (!DOMAIN_REGEX.test(input)) return { valid: false, message: 'Invalid domain name format.' };
      return { valid: true, message: null };

    case 'ip':
      if (validateIpv4(input)) {
        if (isPrivateIp(input)) return { valid: false, message: `${input} is a private/reserved address and cannot be investigated externally.` };
        return { valid: true, message: null };
      }
      if (IPV6_REGEX.test(input)) return { valid: true, message: null };
      return { valid: false, message: 'Invalid IP address.' };

    case 'url':
      try {
        const url = new URL(input);
        if (!['http:', 'https:'].includes(url.protocol)) {
          return { valid: false, message: 'Only http and https URLs are supported.' };
        }
        return { valid: true, message: null };
      } catch {
        return { valid: false, message: 'Invalid URL format.' };
      }

    case 'phone':
      if (!PHONE_REGEX.test(input)) return { valid: false, message: 'Phone numbers must be in international format (e.g., +12025551234).' };
      return { valid: true, message: null };

    case 'username':
      if (input.length < 2 || input.length > 50) return { valid: false, message: 'Username must be 2–50 characters.' };
      if (/[^\w.\-@]/.test(input)) return { valid: false, message: 'Username contains invalid characters.' };
      return { valid: true, message: null };

    case 'person':
      if (input.length < 2) return { valid: false, message: 'Name must be at least 2 characters.' };
      if (input.length > 200) return { valid: false, message: 'Name too long.' };
      return { valid: true, message: null };

    case 'organization':
      if (input.length < 2) return { valid: false, message: 'Organization name must be at least 2 characters.' };
      if (input.length > 200) return { valid: false, message: 'Organization name too long.' };
      return { valid: true, message: null };

    case 'crypto_wallet': {
      const net = detectCryptoNetwork(input);
      if (net === 'unknown') return { valid: false, message: 'Invalid cryptocurrency address format (BTC, ETH, SOL, TRX supported).' };
      return { valid: true, message: null };
    }

    default:
      return { valid: false, message: 'Unknown target type.' };
  }
}
