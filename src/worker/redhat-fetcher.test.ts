import { describe, it, expect } from 'vitest';
import {
  mapSeverity,
  stripEpoch,
  parseCveElement,
  parseCriterionComment,
  collectCriteria,
} from './redhat-fetcher.js';

describe('mapSeverity', () => {
  it('maps known OVAL severity names', () => {
    expect(mapSeverity('critical')).toBe('CRITICAL');
    expect(mapSeverity('important')).toBe('HIGH');
    expect(mapSeverity('moderate')).toBe('MEDIUM');
    expect(mapSeverity('low')).toBe('LOW');
  });

  it('is case-insensitive on input', () => {
    expect(mapSeverity('Critical')).toBe('CRITICAL');
  });

  it('passes through unknown values uppercased', () => {
    expect(mapSeverity('none')).toBe('NONE');
  });

  it('handles numeric-coerced values from fast-xml-parser', () => {
    expect(mapSeverity(0)).toBe('0');
  });

  it('returns undefined for empty/nullish input', () => {
    expect(mapSeverity(undefined)).toBeUndefined();
    expect(mapSeverity(null)).toBeUndefined();
    expect(mapSeverity('')).toBeUndefined();
  });
});

describe('stripEpoch', () => {
  it('strips a numeric epoch prefix', () => {
    expect(stripEpoch('0:2.9.13-9.el9')).toBe('2.9.13-9.el9');
  });

  it('leaves versions without an epoch unchanged', () => {
    expect(stripEpoch('2.9.13-9.el9')).toBe('2.9.13-9.el9');
  });
});

describe('parseCveElement', () => {
  it('parses a plain CVE string', () => {
    expect(parseCveElement('CVE-2026-1234')).toEqual({ cveId: 'CVE-2026-1234' });
  });

  it('returns null for a non-CVE string', () => {
    expect(parseCveElement('not-a-cve')).toBeNull();
  });

  it('parses an object with CVSS3 score and vector', () => {
    expect(parseCveElement({ '#text': 'CVE-2026-1234', '@_cvss3': '7.5/CVSS:3.1/AV:N/AC:L' })).toEqual({
      cveId: 'CVE-2026-1234',
      cvssScore: 7.5,
      cvssVector: 'CVSS:3.1/AV:N/AC:L',
    });
  });

  it('parses an object without CVSS3', () => {
    expect(parseCveElement({ '#text': 'CVE-2026-1234' })).toEqual({
      cveId: 'CVE-2026-1234',
      cvssScore: undefined,
      cvssVector: undefined,
    });
  });

  it('returns null for an object with a non-CVE #text', () => {
    expect(parseCveElement({ '#text': 'not-a-cve' })).toBeNull();
  });

  it('returns null for unsupported types', () => {
    expect(parseCveElement(123)).toBeNull();
    expect(parseCveElement(null)).toBeNull();
  });
});

describe('parseCriterionComment', () => {
  it('parses a version-range criterion', () => {
    expect(parseCriterionComment('rsync is earlier than 0:3.2.5-3.el9_7.2')).toEqual({
      packageName: 'rsync',
      versionEnd: '3.2.5-3.el9_7.2',
    });
  });

  it('returns null for a non-version criterion', () => {
    expect(parseCriterionComment('Red Hat Enterprise Linux 9 is signed with Red Hat key')).toBeNull();
  });

  it('returns null for arbitrary text', () => {
    expect(parseCriterionComment('some unrelated comment')).toBeNull();
  });
});

describe('collectCriteria', () => {
  it('collects criterion elements from a flat criteria node', () => {
    const node = { criterion: [{ '@_comment': 'a' }, { '@_comment': 'b' }] };
    expect(collectCriteria(node)).toEqual([{ '@_comment': 'a' }, { '@_comment': 'b' }]);
  });

  it('collects a single criterion (non-array) node', () => {
    const node = { criterion: { '@_comment': 'a' } };
    expect(collectCriteria(node)).toEqual([{ '@_comment': 'a' }]);
  });

  it('recurses into nested criteria', () => {
    const node = {
      criterion: [{ '@_comment': 'top' }],
      criteria: {
        criterion: [{ '@_comment': 'nested' }],
      },
    };
    expect(collectCriteria(node)).toEqual([{ '@_comment': 'top' }, { '@_comment': 'nested' }]);
  });

  it('returns an empty array for non-object input', () => {
    expect(collectCriteria(null)).toEqual([]);
    expect(collectCriteria(undefined)).toEqual([]);
  });
});
