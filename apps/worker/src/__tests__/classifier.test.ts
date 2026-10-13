import { describe, it, expect } from 'vitest';
import {
  classifyTarget,
  normalizeTarget,
  validateTargetForType,
  isPrivateIp,
  validateIpv4,
} from '../classifier.ts';
import { getCollectorsForTargetType, getAllCollectors } from '../collectors/registry.ts';

describe('Classifier Unit Tests', () => {
  it('correctly classifies email addresses', () => {
    const res = classifyTarget('analyst@example.org');
    expect(res.targetType).toBe('email');
    expect(res.confidence).toBe('high');
    expect(res.normalizedTarget).toBe('analyst@example.org');
    expect(res.validationMessage).toBeNull();
  });

  it('correctly classifies domains and strips leading www in normalization', () => {
    const res = classifyTarget('www.example.com');
    expect(res.targetType).toBe('domain');
    expect(res.normalizedTarget).toBe('example.com');
    expect(res.confidence).toBe('high');
  });

  it('correctly classifies URLs', () => {
    const res = classifyTarget('https://security.example.com/reports?id=123');
    expect(res.targetType).toBe('url');
    expect(res.confidence).toBe('high');
    expect(res.alternatives).toContain('domain');
  });

  it('correctly classifies public IPv4 addresses', () => {
    const res = classifyTarget('1.1.1.1');
    expect(res.targetType).toBe('ip');
    expect(res.confidence).toBe('high');
    expect(res.validationMessage).toBeNull();
  });

  it('flags private IPv4 addresses with appropriate validation messages', () => {
    const res = classifyTarget('192.168.1.1');
    expect(res.targetType).toBe('ip');
    expect(res.validationMessage).toContain('private');
    expect(isPrivateIp('192.168.1.1')).toBe(true);
    expect(isPrivateIp('10.0.0.1')).toBe(true);
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('8.8.8.8')).toBe(false);
  });

  it('validates IPv4 octet bounds', () => {
    expect(validateIpv4('255.255.255.255')).toBe(true);
    expect(validateIpv4('256.0.0.1')).toBe(false);
    expect(validateIpv4('1.2.3')).toBe(false);
  });

  it('correctly classifies international phone numbers', () => {
    const res = classifyTarget('+14155552671');
    expect(res.targetType).toBe('phone');
    expect(res.confidence).toBe('high');
  });

  it('correctly handles usernames', () => {
    const res = classifyTarget('@torvalds');
    expect(res.targetType).toBe('username');
    expect(res.normalizedTarget).toBe('torvalds');
  });

  it('validates targets for given types', () => {
    expect(validateTargetForType('test@domain.com', 'email').valid).toBe(true);
    expect(validateTargetForType('notanemail', 'email').valid).toBe(false);
    expect(validateTargetForType('example.com', 'domain').valid).toBe(true);
    expect(validateTargetForType('999.999.999.999', 'ip').valid).toBe(false);
  });

  it('normalizes target inputs accurately', () => {
    expect(normalizeTarget('  TEST@DOMAIN.COM  ', 'email')).toBe('test@domain.com');
    expect(normalizeTarget('WWW.GITHUB.COM', 'domain')).toBe('github.com');
    expect(normalizeTarget('@hacker', 'username')).toBe('hacker');
  });
});

describe('Collector Registry Unit Tests', () => {
  it('returns all registered collectors', () => {
    const all = getAllCollectors();
    expect(all.length).toBeGreaterThan(0);
    const names = all.map(c => c.name);
    expect(names).toContain('dns');
    expect(names).toContain('rdap');
    expect(names).toContain('certificate_transparency');
  });

  it('returns appropriate collectors for domain targets', () => {
    const { available } = getCollectorsForTargetType('domain');
    const names = available.map(c => c.name);
    expect(names).toContain('dns');
    expect(names).toContain('rdap');
    expect(names).toContain('certificate_transparency');
  });

  it('returns appropriate collectors for IP targets', () => {
    const { available } = getCollectorsForTargetType('ip');
    const names = available.map(c => c.name);
    expect(names).toContain('rdap');
    expect(names).toContain('ipinfo');
  });
});

