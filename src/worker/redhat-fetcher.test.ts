import { describe, it, expect } from 'vitest';
import {
  mapSeverity,
  stripEpoch,
  parseCveElement,
  parseCriterionComment,
  extractModuleMajor,
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

describe('extractModuleMajor', () => {
  it('extracts the major version from a module-enabled criterion', () => {
    expect(extractModuleMajor('Module nodejs:20 is enabled')).toBe(20);
    expect(extractModuleMajor('Module postgresql:16 is enabled')).toBe(16);
  });

  it('returns null for non-module criteria', () => {
    expect(extractModuleMajor('nodejs is earlier than 1:20.8.1-1.module+el9')).toBeNull();
    expect(extractModuleMajor('Red Hat Enterprise Linux 9 is installed')).toBeNull();
  });
});

describe('collectCriteria', () => {
  it('collects criterion elements from a flat criteria node, with no module context', () => {
    const node = { criterion: [{ '@_comment': 'a' }, { '@_comment': 'b' }] };
    expect(collectCriteria(node)).toEqual([
      { node: { '@_comment': 'a' }, moduleMajor: null },
      { node: { '@_comment': 'b' }, moduleMajor: null },
    ]);
  });

  it('collects a single criterion (non-array) node', () => {
    const node = { criterion: { '@_comment': 'a' } };
    expect(collectCriteria(node)).toEqual([{ node: { '@_comment': 'a' }, moduleMajor: null }]);
  });

  it('recurses into nested criteria', () => {
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
    expect(collectCriteria(undefined)).toEqual([]);
  });

  it('propagates a "Module X:N is enabled" sibling criterion to nested descendants', () => {
    // Mirrors the real RHEL9 OVAL shape: a module-enabled check and the
    // OR-of-packages it guards are siblings under the same AND parent.
    const node = {
      criterion: [{ '@_comment': 'Module nodejs:20 is enabled' }],
      criteria: {
        criteria: [
          { criterion: [{ '@_comment': 'nodejs is earlier than 1:20.8.1-1.module+el9' }] },
          { criterion: [{ '@_comment': 'nodejs-devel is earlier than 1:20.8.1-1.module+el9' }] },
        ],
      },
    };
    const result = collectCriteria(node);
    const moduleCrit = result.find(r => r.node['@_comment'] === 'Module nodejs:20 is enabled');
    const nodejsCrit = result.find(r => r.node['@_comment']?.toString().startsWith('nodejs is earlier'));
    const develCrit = result.find(r => r.node['@_comment']?.toString().startsWith('nodejs-devel'));
    expect(moduleCrit?.moduleMajor).toBe(20);
    expect(nodejsCrit?.moduleMajor).toBe(20);
    expect(develCrit?.moduleMajor).toBe(20);
  });

  it('does not leak a module major across unrelated sibling branches', () => {
    const node = {
      criteria: [
        {
          criterion: [{ '@_comment': 'Module nodejs:20 is enabled' }],
          criteria: { criterion: [{ '@_comment': 'nodejs is earlier than 1:20.8.1-1.module+el9' }] },
        },
        {
          // No module criterion in this branch — e.g. the non-modular
          // "nodejs is earlier than 1:16.16.0-1.el9_0" default-stream package.
          criterion: [{ '@_comment': 'rsync is earlier than 0:3.2.5-3.el9' }],
        },
      ],
    };
    const result = collectCriteria(node);
    const rsyncCrit = result.find(r => r.node['@_comment']?.toString().startsWith('rsync'));
    expect(rsyncCrit?.moduleMajor).toBeNull();
  });
});
