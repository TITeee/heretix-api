import { describe, it, expect } from 'vitest';
import {
  dedup,
  versionRangeWhere,
  isDistroEcosystem,
  isDpkgStyleDistro,
  isLanguageEcosystem,
  normalizeEcosystem,
  rpmAdvisoryVendor,
  matchesDpkgStyleVersion,
  matchesRpmVersionRange,
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

  it('recognizes the version-less oracle-linux ecosystem', () => {
    expect(isDistroEcosystem('oracle-linux')).toBe(true);
  });

  it('recognizes the prefixed "Oracle Linux:N" alias', () => {
    expect(isDistroEcosystem('Oracle Linux:9')).toBe(true);
  });

  it('rejects language ecosystems', () => {
    expect(isDistroEcosystem('npm')).toBe(false);
  });
});

describe('isDpkgStyleDistro', () => {
  it('recognizes Ubuntu, Debian, and Alpine', () => {
    expect(isDpkgStyleDistro('Ubuntu:22.04:LTS')).toBe(true);
    expect(isDpkgStyleDistro('Debian:12')).toBe(true);
    expect(isDpkgStyleDistro('Alpine:v3.21')).toBe(true);
  });

  it('rejects RPM-based distros and non-distro ecosystems', () => {
    expect(isDpkgStyleDistro('Red Hat:9')).toBe(false);
    expect(isDpkgStyleDistro('oracle-linux')).toBe(false);
    expect(isDpkgStyleDistro('npm')).toBe(false);
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

  it('maps the version-less oracle-linux ecosystem to the oracle-linux vendor', () => {
    expect(rpmAdvisoryVendor('oracle-linux')).toBe('oracle-linux');
  });

  it('maps the prefixed "Oracle Linux:N" alias to the same oracle-linux vendor', () => {
    // Older heretix-cli builds (750b4ee..reverted) sent this form; kept as an
    // alias so a client still emitting it doesn't silently fall back to the
    // lossy BigInt search path.
    expect(rpmAdvisoryVendor('Oracle Linux:9')).toBe('oracle-linux');
  });

  it('returns null for non-RPM ecosystems', () => {
    expect(rpmAdvisoryVendor('Ubuntu:22.04')).toBeNull();
  });

  it('returns null when the prefix matches but without the colon separator', () => {
    expect(rpmAdvisoryVendor('Red Hat')).toBeNull();
  });
});

describe('matchesDpkgStyleVersion', () => {
  // OSVAffectedPackage column shape; only the fields this predicate reads.
  const row = (o: Partial<Parameters<typeof matchesDpkgStyleVersion>[0]> = {}) => ({
    affectedVersions: [],
    introducedVersion: null,
    fixedVersion: null,
    lastAffectedVersion: null,
    ...o,
  });

  it('matches a version present in the enumerated affectedVersions list', () => {
    expect(matchesDpkgStyleVersion(
      row({ affectedVersions: ['15.3-0+deb12u1', '15.4-1'] }), '15.4-1',
    )).toBe(true);
  });

  it('does not match when the row carries no range info and the version is not in the list', () => {
    // Guard: without this, a row with every range field null would fall through
    // each null check below and match every version queried.
    expect(matchesDpkgStyleVersion(
      row({ affectedVersions: ['15.3-0+deb12u1'] }), '99.0',
    )).toBe(false);
  });

  it('matches a range-only row (no enumerated list) — the ~68% of Debian OSV data that exact-match alone missed', () => {
    expect(matchesDpkgStyleVersion(
      row({ introducedVersion: '0', fixedVersion: '15.7-0+deb12u1' }), '15.6-0+deb12u1',
    )).toBe(true);
  });

  it('treats fixedVersion as an exclusive upper bound', () => {
    const r = row({ introducedVersion: '0', fixedVersion: '15.7-0+deb12u1' });
    expect(matchesDpkgStyleVersion(r, '15.7-0+deb12u1')).toBe(false);
    expect(matchesDpkgStyleVersion(r, '15.8-0+deb12u1')).toBe(false);
  });

  it('excludes versions below introducedVersion', () => {
    expect(matchesDpkgStyleVersion(
      row({ introducedVersion: '15.5-1', fixedVersion: '15.7-1' }), '15.4-1',
    )).toBe(false);
  });

  it('treats lastAffectedVersion as an inclusive upper bound', () => {
    const r = row({ introducedVersion: '0', lastAffectedVersion: '15.6-1' });
    expect(matchesDpkgStyleVersion(r, '15.6-1')).toBe(true);
    expect(matchesDpkgStyleVersion(r, '15.7-1')).toBe(false);
  });

  it('prefers the exact-match list over the range, so already-correct results are unaffected', () => {
    // Listed as affected even though it sits at/above the fixed version.
    expect(matchesDpkgStyleVersion(
      row({ affectedVersions: ['15.7-0+deb12u1'], introducedVersion: '0', fixedVersion: '15.7-0+deb12u1' }),
      '15.7-0+deb12u1',
    )).toBe(true);
  });

  it('uses dpkg ordering, not string comparison, for "~" pre-release versions', () => {
    // dpkg: "1.0~rc1" sorts *before* "1.0", so it is still affected.
    expect(matchesDpkgStyleVersion(
      row({ introducedVersion: '0', fixedVersion: '1.0' }), '1.0~rc1',
    )).toBe(true);
  });
});

describe('matchesRpmVersionRange', () => {
  const row = (versionEnd: string | null, versionStart: string | null = null) => ({ versionStart, versionEnd });

  it('matches a version below the fix version', () => {
    expect(matchesRpmVersionRange(row('1.9.15-8.p5.el10_0.2'), '1.9.15-8.p5.el10_0.1')).toBe(true);
  });

  it('excludes the fix version itself (exclusive upper bound)', () => {
    // OVAL states "sudo is earlier than 0:1.9.15-8.p5.el10_0.2" — that exact
    // build is the patched one and must not be reported (CVE-2025-32463).
    expect(matchesRpmVersionRange(row('1.9.15-8.p5.el10_0.2'), '1.9.15-8.p5.el10_0.2')).toBe(false);
  });

  it('excludes versions above the fix version', () => {
    expect(matchesRpmVersionRange(row('1.9.15-8.p5.el10_0.2'), '1.9.16-1.el10')).toBe(false);
  });

  it('never matches a row with no upper bound', () => {
    expect(matchesRpmVersionRange(row(null), '1.0-1.el9')).toBe(false);
  });

  it('respects an inferred versionStart floor so one module stream does not swallow another', () => {
    // postgresql:18 fix must not match a postgresql:16 query (versionStart now
    // comes straight from RedHatFetcher/OracleLinuxFetcher's Module criterion parsing).
    const pg18 = row('18.4-2.module+el9.8.0+24359+da7fad50', '18.0');
    expect(matchesRpmVersionRange(pg18, '16.4')).toBe(false);
    expect(matchesRpmVersionRange(pg18, '18.2')).toBe(true);
  });

  it('treats versionStart as inclusive', () => {
    expect(matchesRpmVersionRange(row('18.4', '18.0'), '18.0')).toBe(true);
  });

  it('uses rpmvercmp ordering for sub-releases, not string comparison', () => {
    // rpmvercmp: "3.2.5-3.el9" < "3.2.5-3.el9_7.2"
    expect(matchesRpmVersionRange(row('3.2.5-3.el9_7.2'), '3.2.5-3.el9')).toBe(true);
  });
});
