import { describe, it, expect } from 'vitest';
import {
  dedup,
  versionRangeWhere,
  isDistroEcosystem,
  isLanguageEcosystem,
  normalizeEcosystem,
  rpmAdvisoryVendor,
  type VulnerabilityResult,
} from './search-helpers.js';

function makeResult(overrides: Partial<VulnerabilityResult>): VulnerabilityResult {
  return {
    id: 'v1',
    externalId: 'CVE-2026-1234',
    source: 'nvd',
    sources: ['nvd'],
    severity: null,
    cvssScore: null,
    cvssVector: null,
    summary: null,
    publishedAt: null,
    approximateMatch: false,
    isKev: false,
    epssScore: null,
    epssPercentile: null,
    fixedVersion: null,
    ...overrides,
  };
}

describe('dedup', () => {
  it('merges sources for items sharing the same master id', () => {
    const items = [
      makeResult({ id: 'v1', sources: ['nvd'] }),
      makeResult({ id: 'v1', sources: ['osv'] }),
    ];
    const result = dedup(items);
    expect(result).toHaveLength(1);
    expect(result[0].sources).toEqual(['nvd', 'osv']);
  });

  it('does not duplicate a source that already exists', () => {
    const items = [
      makeResult({ id: 'v1', sources: ['nvd'] }),
      makeResult({ id: 'v1', sources: ['nvd'] }),
    ];
    expect(dedup(items)[0].sources).toEqual(['nvd']);
  });

  it('keeps the first non-null fixedVersion without overwriting it', () => {
    const items = [
      makeResult({ id: 'v1', sources: ['nvd'], fixedVersion: '1.2.3' }),
      makeResult({ id: 'v1', sources: ['osv'], fixedVersion: '9.9.9' }),
    ];
    expect(dedup(items)[0].fixedVersion).toBe('1.2.3');
  });

  it('fills in fixedVersion from a later item when the first is null', () => {
    const items = [
      makeResult({ id: 'v1', sources: ['nvd'], fixedVersion: null }),
      makeResult({ id: 'v1', sources: ['osv'], fixedVersion: '2.0.0' }),
    ];
    expect(dedup(items)[0].fixedVersion).toBe('2.0.0');
  });

  it('keeps distinct master ids as separate results', () => {
    const items = [makeResult({ id: 'v1' }), makeResult({ id: 'v2' })];
    expect(dedup(items)).toHaveLength(2);
  });
});

describe('versionRangeWhere', () => {
  it('builds a WHERE clause bounding introducedInt and fixedInt', () => {
    const where = versionRangeWhere(1002003000n);
    expect(where).toEqual({
      AND: [
        { OR: [{ introducedInt: { lte: 1002003000n } }, { introducedInt: null }] },
        {
          OR: [
            { fixedInt: { gt: 1002003000n } },
            { fixedInt: null, OR: [{ lastAffectedInt: null }, { lastAffectedInt: { gte: 1002003000n } }] },
          ],
        },
      ],
    });
  });
});

describe('isDistroEcosystem', () => {
  it('recognizes distro ecosystem prefixes', () => {
    expect(isDistroEcosystem('Red Hat:9')).toBe(true);
    expect(isDistroEcosystem('Ubuntu:22.04:LTS')).toBe(true);
  });

  it('rejects language ecosystems', () => {
    expect(isDistroEcosystem('npm')).toBe(false);
  });
});

describe('isLanguageEcosystem', () => {
  it('recognizes known language ecosystems', () => {
    expect(isLanguageEcosystem('npm')).toBe(true);
    expect(isLanguageEcosystem('PyPI')).toBe(true);
  });

  it('rejects distro and unknown ecosystems', () => {
    expect(isLanguageEcosystem('Ubuntu:22.04')).toBe(false);
    expect(isLanguageEcosystem('unknown')).toBe(false);
  });
});

describe('normalizeEcosystem', () => {
  it('maps composer to Packagist', () => {
    expect(normalizeEcosystem('composer')).toBe('Packagist');
  });

  it('is case-insensitive on the alias key', () => {
    expect(normalizeEcosystem('Composer')).toBe('Packagist');
  });

  it('passes through unmapped ecosystems unchanged', () => {
    expect(normalizeEcosystem('npm')).toBe('npm');
  });

  it('passes through undefined', () => {
    expect(normalizeEcosystem(undefined)).toBeUndefined();
  });
});

describe('rpmAdvisoryVendor', () => {
  it('maps Red Hat ecosystem to the red-hat vendor', () => {
    expect(rpmAdvisoryVendor('Red Hat:9')).toBe('red-hat');
  });

  it('returns null for non-RPM ecosystems', () => {
    expect(rpmAdvisoryVendor('Ubuntu:22.04')).toBeNull();
  });

  it('returns null when the prefix matches but without the colon separator', () => {
    expect(rpmAdvisoryVendor('Red Hat')).toBeNull();
  });
});
