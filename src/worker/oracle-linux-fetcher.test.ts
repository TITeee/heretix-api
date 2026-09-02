import { describe, it, expect } from 'vitest';
import {
  mapSeverity,
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
  it('keeps the epoch on a version-range criterion (a 0 epoch, RPM\'s "no epoch")', () => {
    expect(parseCriterionComment('rsync is earlier than 0:3.2.5-3.el9_7.2')).toEqual({
      packageName: 'rsync',
      versionEnd: '0:3.2.5-3.el9_7.2',
    });
  });

  it('keeps a real, nonzero epoch', () => {
    // openssl-libs: a real package carrying a nonzero epoch. Dropping it (as
    // this used to) makes an installed build with the epoch read as newer
    // than any epoch-omitted (implicitly epoch-0) fix row regardless of its
    // actual version/release, so every fix for it silently stops matching.
    expect(parseCriterionComment('openssl-libs is earlier than 1:3.5.5-4.el9_8')).toEqual({
      packageName: 'openssl-libs',
      versionEnd: '1:3.5.5-4.el9_8',
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
      { node: { '@_comment': 'top' }, moduleMajor: null, isBuildVariant: false },
      { node: { '@_comment': 'nested' }, moduleMajor: null, isBuildVariant: false },
    ]);
  });

  it('returns an empty array for non-object input', () => {
    expect(collectCriteria(null)).toEqual([]);
  });

  it('tolerates a purely numeric @_comment (fast-xml-parser coerces "0" to a number, not a crash)', () => {
    // Hit a live Oracle Linux feed 2026-09-02 and crashed the fetcher with
    // "comment.match is not a function" -- the `as string` cast doesn't
    // actually make it one.
    const node = { criterion: [{ '@_comment': 0 }] };
    expect(() => collectCriteria(node)).not.toThrow();
    expect(collectCriteria(node)).toEqual([{ node: { '@_comment': 0 }, moduleMajor: null, isBuildVariant: false }]);
  });

  it('marks a criterion as a build variant when a sibling says "is fips patched" (real Oracle Linux 9/openssl-libs shape)', () => {
    // ELSA-2026-50075: openssl-libs's regular fix track is a separate,
    // lower-epoch advisory: importing this FIPS-track version boundary into
    // the same (product, vendor) bucket made a fully-patched regular
    // install read as vulnerable, since epoch 1 (regular) < epoch 10 (this
    // track) regardless of the actual release history.
    const node = {
      criterion: [
        { '@_comment': 'openssl-libs is earlier than 10:3.5.1-7.0.1.el9_7_fips' },
        { '@_comment': 'openssl-libs is signed with the Oracle Linux 9 key' },
        { '@_comment': 'openssl-libs is fips patched' },
      ],
    };
    const result = collectCriteria(node);
    expect(result.every(r => r.isBuildVariant)).toBe(true);
  });

  it('marks a criterion as a build variant when a sibling says "is ksplice-based" (real Oracle Linux 9/openssl shape)', () => {
    const node = {
      criterion: [
        { '@_comment': 'openssl is earlier than 2:3.5.1-7.0.1.ksplice1.el9_7' },
        { '@_comment': 'openssl is signed with the Oracle Linux 9 key' },
        { '@_comment': 'openssl is ksplice-based' },
      ],
    };
    const result = collectCriteria(node);
    expect(result.every(r => r.isBuildVariant)).toBe(true);
  });

  it('does not mark an ordinary AND block (no variant sibling) as a build variant', () => {
    const node = {
      criterion: [
        { '@_comment': 'rsync is earlier than 0:3.2.5-3.el9_7.2' },
        { '@_comment': 'rsync is signed with the Oracle Linux 9 key' },
      ],
    };
    expect(collectCriteria(node).every(r => !r.isBuildVariant)).toBe(true);
  });

  it('scopes isBuildVariant to the criterion array it was found in, not inherited by nested criteria', () => {
    // Each package's own AND block carries its own independent variant
    // marker (or lack of one) -- unlike moduleMajor, this must not leak into
    // a sibling package's unrelated nested criteria.
    const node = {
      criterion: [{ '@_comment': 'openssl is fips patched' }],
      criteria: {
        criterion: [{ '@_comment': 'rsync is earlier than 0:3.2.5-3.el9_7.2' }],
      },
    };
    const result = collectCriteria(node);
    const rsyncCrit = result.find(r => r.node['@_comment']?.toString().startsWith('rsync'));
    expect(rsyncCrit?.isBuildVariant).toBe(false);
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
