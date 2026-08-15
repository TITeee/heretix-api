import { describe, it, expect } from 'vitest';
import {
  mapSeverity,
  stripEpoch,
  parseCveElement,
  parseCriterionComment,
  extractModuleMajor,
  collectCriteria,
} from './oracle-linux-fetcher.js';

describe('mapSeverity', () => {
  it('maps known OVAL severity names', () => {
    expect(mapSeverity('critical')).toBe('CRITICAL');
    expect(mapSeverity('important')).toBe('HIGH');
    expect(mapSeverity('moderate')).toBe('MEDIUM');
    expect(mapSeverity('low')).toBe('LOW');
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
});

describe('parseCriterionComment', () => {
  it('parses a version-range criterion', () => {
    expect(parseCriterionComment('rsync is earlier than 0:3.2.5-3.el9_7.2')).toEqual({
      packageName: 'rsync',
      versionEnd: '3.2.5-3.el9_7.2',
    });
  });

  it('returns null for a non-version criterion (e.g. platform/module checks)', () => {
    expect(parseCriterionComment('Oracle Linux 9 is installed')).toBeNull();
  });
});

describe('extractModuleMajor', () => {
  it('extracts an integer stream label from a module-enabled criterion', () => {
    expect(extractModuleMajor('Module nodejs:22 is enabled')).toBe('22');
  });

  it('extracts a dotted major.minor stream label verbatim', () => {
    expect(extractModuleMajor('Module mysql:8.4 is enabled')).toBe('8.4');
    expect(extractModuleMajor('Module mariadb:10.11 is enabled')).toBe('10.11');
  });

  it('returns null for non-module criteria', () => {
    expect(extractModuleMajor('Oracle Linux 9 is installed')).toBeNull();
  });
});

describe('collectCriteria', () => {
  it('recurses into nested criteria, with no module context', () => {
    const node = {
      criterion: [{ '@_comment': 'top' }],
      criteria: {
        criterion: [{ '@_comment': 'nested' }],
      },
    };
    expect(collectCriteria(node)).toEqual([
      { node: { '@_comment': 'top' }, moduleMajor: null },
      { node: { '@_comment': 'nested' }, moduleMajor: null },
    ]);
  });

  it('returns an empty array for non-object input', () => {
    expect(collectCriteria(null)).toEqual([]);
  });

  it('propagates a "Module X:N is enabled" sibling criterion to nested descendants', () => {
    // Mirrors the real Oracle Linux 9 OVAL shape (identical to RHEL's): a
    // module-enabled check and the OR-of-packages it guards are siblings
    // under the same AND parent, one extra arch-check level deep.
    const node = {
      criteria: {
        criteria: {
          criterion: [{ '@_comment': 'Module nodejs:22 is enabled' }],
          criteria: {
            criteria: [
              { criterion: [{ '@_comment': 'nodejs is earlier than 1:22.23.1-2.module+el9' }] },
              { criterion: [{ '@_comment': 'nodejs-devel is earlier than 1:22.23.1-2.module+el9' }] },
            ],
          },
        },
      },
    };
    const result = collectCriteria(node);
    const nodejsCrit = result.find(r => r.node['@_comment']?.toString().startsWith('nodejs is earlier'));
    const develCrit = result.find(r => r.node['@_comment']?.toString().startsWith('nodejs-devel'));
    expect(nodejsCrit?.moduleMajor).toBe('22');
    expect(develCrit?.moduleMajor).toBe('22');
  });
});
