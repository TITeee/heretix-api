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
  matchesRpmStyleOsvVersion,
  matchesRpmVersionRange,
  isRpmStyleOsvDistro,
  buildAliases,
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
    aliases: ['CVE-2026-1234'],
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

  it('unions aliases across sources rather than keeping only the first', () => {
    // Each source knows this finding by the id on its own row. Keeping only the
    // winner's would drop the very mapping a consumer needs to follow an alert
    // raised under the id a source used before a CVE was assigned.
    const items = [
      makeResult({ id: 'v1', sources: ['nvd'], aliases: ['CVE-2026-1234'] }),
      makeResult({ id: 'v1', sources: ['osv'], aliases: ['CVE-2026-1234', 'GHSA-aaaa-bbbb-cccc'] }),
    ];
    expect(dedup(items)[0].aliases).toEqual(['CVE-2026-1234', 'GHSA-aaaa-bbbb-cccc']);
  });

  it('does not mutate the input items when merging', () => {
    const first = makeResult({ id: 'v1', sources: ['nvd'], aliases: ['CVE-2026-1234'] });
    dedup([first, makeResult({ id: 'v1', sources: ['osv'], aliases: ['GHSA-aaaa-bbbb-cccc'] })]);
    expect(first.aliases).toEqual(['CVE-2026-1234']);
    expect(first.sources).toEqual(['nvd']);
  });
});

describe('buildAliases', () => {
  it('collects every identifier the master carries', () => {
    expect(buildAliases({ cveId: 'CVE-2026-1234', osvId: 'GHSA-x', advisoryId: 'ZBV-1' }))
      .toEqual(['CVE-2026-1234', 'GHSA-x', 'ZBV-1']);
  });

  it('includes the source row\'s own id, which the master loses once a CVE is assigned', () => {
    // Post-assignment shape: the master is keyed by CVE only, and the vendor id
    // survives solely on the advisory row.
    expect(buildAliases({ cveId: 'CVE-2026-1234', osvId: null, advisoryId: null }, 'ZBV-2026-05-06-3'))
      .toEqual(['CVE-2026-1234', 'ZBV-2026-05-06-3']);
  });

  it('drops nulls and de-duplicates when the source id repeats the master id', () => {
    expect(buildAliases({ cveId: 'CVE-2026-1234', osvId: null, advisoryId: null }, 'CVE-2026-1234'))
      .toEqual(['CVE-2026-1234']);
  });

  it('returns an empty list when nothing identifies the finding', () => {
    expect(buildAliases({}, null)).toEqual([]);
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

  it('recognizes "Rocky Linux:N" (not "Rocky:" -- that value never matched OSV\'s own ecosystem string)', () => {
    expect(isDistroEcosystem('Rocky Linux:8')).toBe(true);
  });

  it('rejects language ecosystems', () => {
    expect(isDistroEcosystem('npm')).toBe(false);
  });

  it('rejects CentOS -- no OSV ecosystem or dedicated fetcher exists for it', () => {
    expect(isDistroEcosystem('CentOS:7')).toBe(false);
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

describe('isRpmStyleOsvDistro', () => {
  it('recognizes AlmaLinux, Rocky Linux, and Red Hat', () => {
    expect(isRpmStyleOsvDistro('AlmaLinux:9')).toBe(true);
    expect(isRpmStyleOsvDistro('Rocky Linux:8')).toBe(true);
    expect(isRpmStyleOsvDistro('Red Hat:9')).toBe(true);
  });

  it('rejects dpkg-based distros and non-distro ecosystems', () => {
    expect(isRpmStyleOsvDistro('Debian:12')).toBe(false);
    expect(isRpmStyleOsvDistro('npm')).toBe(false);
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
  it('maps Red Hat ecosystem to a version-qualified vendor', () => {
    // Not just "red-hat": AdvisoryAffectedProduct is looked up by (product,
    // vendor) alone, so a version-less vendor would compare an installed
    // RHEL9 package against every RHEL release's fix versions at once.
    expect(rpmAdvisoryVendor('Red Hat:9')).toBe('red-hat-9');
    expect(rpmAdvisoryVendor('Red Hat:8')).toBe('red-hat-8');
  });

  it('maps the version-qualified "Oracle Linux:N" ecosystem to a version-qualified vendor', () => {
    expect(rpmAdvisoryVendor('Oracle Linux:9')).toBe('oracle-linux-9');
  });

  it('maps the legacy version-less oracle-linux ecosystem to the version-less vendor', () => {
    // What heretix-cli sent from 2026 until 2026-09-01, before this file's
    // vendor values carried a version at all. A client still emitting this
    // form gets the same lossy, version-blind matching it always did, not
    // zero results — see the row-level fallback in OracleLinuxFetcher.
    expect(rpmAdvisoryVendor('oracle-linux')).toBe('oracle-linux');
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

describe('matchesRpmStyleOsvVersion', () => {
  // OSVAffectedPackage column shape; only the fields this predicate reads.
  const row = (o: Partial<Parameters<typeof matchesRpmStyleOsvVersion>[0]> = {}) => ({
    affectedVersions: [],
    introducedVersion: null,
    fixedVersion: null,
    lastAffectedVersion: null,
    ...o,
  });

  it('matches a range-only row (no enumerated list) — every AlmaLinux/Rocky Linux OSV row has this shape', () => {
    // Real AlmaLinux:9 data: dbus, introducedVersion="0", fixedVersion="1:1.12.20-7.el9_1".
    expect(matchesRpmStyleOsvVersion(
      row({ introducedVersion: '0', fixedVersion: '1:1.12.20-7.el9_1' }), '1:1.12.20-6.el9_1',
    )).toBe(true);
  });

  it('treats fixedVersion as an exclusive upper bound', () => {
    const r = row({ introducedVersion: '0', fixedVersion: '1:1.12.20-7.el9_1' });
    expect(matchesRpmStyleOsvVersion(r, '1:1.12.20-7.el9_1')).toBe(false);
    expect(matchesRpmStyleOsvVersion(r, '1:1.12.20-8.el9_1')).toBe(false);
  });

  it('matches a version present in the enumerated affectedVersions list', () => {
    expect(matchesRpmStyleOsvVersion(
      row({ affectedVersions: ['1.12.20-6.el9'] }), '1.12.20-6.el9',
    )).toBe(true);
  });

  it('uses compareRpmVersions, not compareDpkgVersions — the two disagree on "~"', () => {
    // dpkg's verrevcmp special-cases "~" to sort before everything, so
    // "1.0~rc1" < "1.0" there; this codebase's rpmvercmp has no such special
    // case, so "~" is skipped like any other non-alphanumeric separator and
    // "1.0~rc1" compares as "1.0" + digit "1" > "1.0". Substituting
    // compareDpkgVersions() here by mistake would flip this row from
    // "already fixed" to "still affected".
    expect(matchesRpmStyleOsvVersion(
      row({ introducedVersion: '0', fixedVersion: '1.0' }), '1.0~rc1',
    )).toBe(false);
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
