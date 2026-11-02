import { describe, it, expect } from 'vitest';
import {
  dedup,
  versionRangeWhere,
  isDistroEcosystem,
  isDpkgStyleDistro,
  isLanguageEcosystem,
  normalizeEcosystem,
  rpmAdvisoryVendor,
  isRpmAdvisoryVendor,
  matchesDpkgStyleVersion,
  matchesRpmStyleOsvVersion,
  matchesGoVersion,
  compareGoOrEncoded,
  matchesRpmVersionRange,
  fixAboveInstalled,
  orderByEncoding,
  isRpmStyleOsvDistro,
  isAdvisoryOnlyEcosystem,
  cnaVersionWhere,
  buildAliases,
  filterBySeverity,
  summaryBudgetChars,
  truncateSummaries,
  batchResultCap,
  keepMostSevere,
  BATCH_RESULTS_PER_PACKAGE,
  BATCH_RESULTS_TOTAL,
  suggestPrefixVariants,
  suggestVendorVariants,
  escapeLikePattern,
  type VulnerabilityResult,
} from './search-helpers.js';
import { encodeAdvisoryVersion, BROADCOM_VENDOR } from './advisory-version.js';

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
    distroPriority: null,
    fixStatus: null,
    fixStatusDetail: null,
    aliases: ['CVE-2026-1234'],
    ...overrides,
  };
}

describe('dedup', () => {
  it('keeps the distro priority from whichever source carries one', () => {
    const merged = dedup([
      makeResult({ id: 'v1', sources: ['nvd'] }),
      makeResult({ id: 'v1', sources: ['osv'], distroPriority: 'negligible' }),
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0].distroPriority).toBe('negligible');
  });

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

  it('keeps the first non-null fixedVersion when nothing else tells two apart', () => {
    const items = [
      makeResult({ id: 'v1', sources: ['nvd'], fixedVersion: '1.2.3' }),
      makeResult({ id: 'v1', sources: ['nvd'], fixedVersion: '9.9.9' }),
    ];
    expect(dedup(items)[0].fixedVersion).toBe('1.2.3');
  });

  it("takes OSV's fixedVersion over NVD's", () => {
    const items = [
      makeResult({ id: 'v1', sources: ['nvd'], fixedVersion: '1.2.3' }),
      makeResult({ id: 'v1', sources: ['osv'], fixedVersion: '9.9.9' }),
    ];
    expect(dedup(items)[0].fixedVersion).toBe('9.9.9');
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

describe('isAdvisoryOnlyEcosystem', () => {
  it('recognizes the sentinel heretix-management sends for curated vendor products', () => {
    expect(isAdvisoryOnlyEcosystem('advisory')).toBe(true);
  });

  it('does not mistake real ecosystems for it', () => {
    for (const eco of ['npm', 'PyPI', 'Debian:12', 'Red Hat:9', 'Alpine:v3.20', '', 'advisories', 'Advisory']) {
      expect(isAdvisoryOnlyEcosystem(eco), eco).toBe(false);
    }
  });
});

describe('cnaVersionWhere', () => {
  it('matches an encodable version by range or by exact equality', () => {
    expect(cnaVersionWhere(1002003000n, '1.2.3')).toEqual({
      OR: [
        {
          AND: [
            // The guard: a row with no bound at all must not reach the range
            // comparison, where every null-fallback below would resolve true
            // and match every version queried.
            {
              OR: [
                { versionStartInt: { not: null } },
                { versionEndInt: { not: null } },
                { lastAffectedInt: { not: null } },
              ],
            },
            { OR: [{ versionStartInt: { lte: 1002003000n } }, { versionStartInt: null }] },
            {
              OR: [
                { versionEndInt: { gt: 1002003000n } },
                {
                  versionEndInt: null,
                  OR: [{ lastAffectedInt: null }, { lastAffectedInt: { gte: 1002003000n } }],
                },
              ],
            },
          ],
        },
        { affectedVersions: { has: '1.2.3' } },
      ],
    });
  });

  it('treats versionEnd as exclusive and lastAffected as inclusive', () => {
    const where = cnaVersionWhere(1002003000n, '1.2.3') as {
      OR: [{ AND: [unknown, unknown, { OR: [{ versionEndInt: { gt: bigint } }, { OR: [unknown, { lastAffectedInt: { gte: bigint } }] }] }] }, unknown];
    };
    const upper = where.OR[0].AND[2].OR;
    expect(upper[0]).toEqual({ versionEndInt: { gt: 1002003000n } });
    expect(upper[1].OR[1]).toEqual({ lastAffectedInt: { gte: 1002003000n } });
  });

  it('falls back to exact equality when the version cannot be encoded', () => {
    // Appliance firmware routinely fails normalizeVersion() but is exactly what
    // the asset reports, and 94.5% of the appliance rows are exact-version.
    expect(cnaVersionWhere(null, '4.1.2cu.5241_B20210927')).toEqual({
      affectedVersions: { has: '4.1.2cu.5241_B20210927' },
    });
  });

  it('places no version constraint when no version was given', () => {
    expect(cnaVersionWhere(null, undefined)).toEqual({});
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

describe('isRpmAdvisoryVendor', () => {
  it('recognizes version-qualified Red Hat and Oracle Linux vendors', () => {
    expect(isRpmAdvisoryVendor('red-hat-9')).toBe(true);
    expect(isRpmAdvisoryVendor('red-hat-8')).toBe(true);
    expect(isRpmAdvisoryVendor('oracle-linux-9')).toBe(true);
  });

  it('recognizes the bare, version-less vendor forms', () => {
    expect(isRpmAdvisoryVendor('red-hat')).toBe(true);
    expect(isRpmAdvisoryVendor('oracle-linux')).toBe(true);
  });

  it('rejects unrelated vendors, including ones sharing a prefix substring', () => {
    expect(isRpmAdvisoryVendor('sophos')).toBe(false);
    expect(isRpmAdvisoryVendor('broadcom')).toBe(false);
    // Not a real vendor value in this codebase, but guards against a naive
    // .includes()-style check matching on "red-hat" appearing mid-string.
    expect(isRpmAdvisoryVendor('not-red-hat-9')).toBe(false);
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

  describe('a range that starts at or above its own fixed version', () => {
    // Alpine:v3.21 openssl: {introduced 3.4.0} {fixed 3.3.7-r1}. As written it matches nothing.
    const inverted = row({ introducedVersion: '3.4.0', fixedVersion: '3.3.7-r1' });

    it('is read as starting from the beginning, so versions below the fix match', () => {
      expect(matchesDpkgStyleVersion(inverted, '3.3.3-r0')).toBe(true);
    });

    it('still excludes the fixed version and anything after it', () => {
      expect(matchesDpkgStyleVersion(inverted, '3.3.7-r1')).toBe(false);
      expect(matchesDpkgStyleVersion(inverted, '3.5.0-r0')).toBe(false);
    });

    it('also covers a start equal to the fix', () => {
      const r = row({ introducedVersion: '1.2.3-r0', fixedVersion: '1.2.3-r0' });
      expect(matchesDpkgStyleVersion(r, '1.2.2-r0')).toBe(true);
      expect(matchesDpkgStyleVersion(r, '1.2.3-r0')).toBe(false);
    });

    it('leaves a coherent range alone, so a version below its start is still excluded', () => {
      // Alpine:v3.21 curl CVE-2025-5399: introduced 8.13.0, fixed 8.14.1-r0; 8.12.1-r1 predates the bug.
      const r = row({ introducedVersion: '8.13.0', fixedVersion: '8.14.1-r0' });
      expect(matchesDpkgStyleVersion(r, '8.12.1-r1')).toBe(false);
      expect(matchesDpkgStyleVersion(r, '8.13.5-r0')).toBe(true);
    });
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

describe('matchesGoVersion', () => {
  const row = (o: Partial<Parameters<typeof matchesGoVersion>[0]> = {}) => ({
    affectedVersions: [],
    introducedVersion: null,
    fixedVersion: null,
    lastAffectedVersion: null,
    ...o,
  });

  it('matches an untagged module up to its fixed pseudo-version (minio)', () => {
    const r = row({ introducedVersion: '0', fixedVersion: '0.0.0-20240527191746-e0fe7cc39172' });
    expect(matchesGoVersion(r, 'v0.0.0-20240101000000-aaaaaaaaaaaa')).toBe(true);
    expect(matchesGoVersion(r, 'v0.0.0-20240527191746-e0fe7cc39172')).toBe(false);
    expect(matchesGoVersion(r, 'v0.0.0-20240601000000-bbbbbbbbbbbb')).toBe(false);
  });

  it('matches between two pseudo-versions of one release (Nginx-UI)', () => {
    const r = row({ introducedVersion: '1.9.10-0.20250517140552-daee3ac7ade1', fixedVersion: '1.9.10-0.20260728074433-a3999bd78a3b' });
    expect(matchesGoVersion(r, 'v1.9.10-0.20251005005631-6de168c94540')).toBe(true);
    expect(matchesGoVersion(r, 'v1.9.9')).toBe(false);
    expect(matchesGoVersion(r, 'v1.9.10')).toBe(false);
  });

  it('matches between two pre-releases (stdlib 1.27.0-0 to 1.27.0-rc.3)', () => {
    const r = row({ introducedVersion: '1.27.0-0', fixedVersion: '1.27.0-rc.3' });
    expect(matchesGoVersion(r, '1.27.0-rc.1')).toBe(true);
    expect(matchesGoVersion(r, '1.27.0-rc.3')).toBe(false);
  });

  it('keeps tagged ranges as they were, and honours last_affected', () => {
    expect(matchesGoVersion(row({ introducedVersion: '0', fixedVersion: '0.33.0' }), 'v0.32.0')).toBe(true);
    expect(matchesGoVersion(row({ introducedVersion: '0', fixedVersion: '0.33.0' }), 'v0.33.0')).toBe(false);
    expect(matchesGoVersion(row({ introducedVersion: '1.0.0', lastAffectedVersion: '1.2.0' }), 'v1.2.0')).toBe(true);
    expect(matchesGoVersion(row({ introducedVersion: '1.0.0', lastAffectedVersion: '1.2.0' }), 'v1.2.1')).toBe(false);
  });

  it('falls back to the encoding for a bound that is not a module version', () => {
    expect(compareGoOrEncoded('1.12.5', '1.13')).toBe(-1);
    expect(matchesGoVersion(row({ introducedVersion: '0', fixedVersion: '1.13' }), '1.12.5')).toBe(true);
    expect(matchesGoVersion(row({ introducedVersion: '0', fixedVersion: '1.13' }), '1.13.1')).toBe(false);
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

  it('never matches a row with no upper bound and unknown patch status', () => {
    expect(matchesRpmVersionRange(row(null), '1.0-1.el9')).toBe(false);
  });

  it('matches unconditionally when patchAvailable is explicitly false (RedHatVexFetcher unfixed row)', () => {
    // e.g. bzip2-libs on RHEL9: Red Hat's own CSAF VEX data confirms this CVE
    // affects it with no fix recorded anywhere, not merely a row a fetcher
    // failed to extract a range for.
    expect(matchesRpmVersionRange({ ...row(null), patchAvailable: false }, '1.0.8-11.el9')).toBe(true);
  });

  it('does not match a row with no upper bound just because patchAvailable is unset', () => {
    // Distinguishes "confirmed unfixed" from "ordinary parse gap" -- only the
    // explicit false is trusted, not merely an absent/null value.
    expect(matchesRpmVersionRange({ ...row(null), patchAvailable: null }, '1.0-1.el9')).toBe(false);
    expect(matchesRpmVersionRange({ ...row(null), patchAvailable: true }, '1.0-1.el9')).toBe(false);
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

describe('matchesRpmVersionRange with per-stream fixes', () => {
  // A kernel CVE unfixed on RHEL 9, fixed only in the 9.4 and 9.6 sustaining streams.
  const row = {
    versionStart: null,
    versionEnd: '0:5.14.0-570.140.1.el9_6',
    patchAvailable: false,
    streamFixes: ['0:5.14.0-427.149.1.el9_4', '0:5.14.0-570.140.1.el9_6'],
  };

  it('matches a build in a stream with no fix even when it is newer than every fix', () => {
    expect(matchesRpmVersionRange(row, '5.14.0-687.58.1.el9_8')).toBe(true);
  });

  it('judges a build against the fix of its own stream', () => {
    expect(matchesRpmVersionRange(row, '5.14.0-427.100.1.el9_4')).toBe(true);
    expect(matchesRpmVersionRange(row, '5.14.0-427.149.1.el9_4')).toBe(false);
    expect(matchesRpmVersionRange(row, '5.14.0-427.150.1.el9_4')).toBe(false);
  });

  it('does not match a build past its own stream fix but below another stream fix', () => {
    // Past the 9.4 fix, below the 9.6 bound: the cross-stream bound alone would still match it.
    expect(matchesRpmVersionRange(row, '5.14.0-500.1.1.el9_4')).toBe(false);
  });

  it('falls back to the cross-stream bound for a build with no stream tag', () => {
    expect(matchesRpmVersionRange(row, '5.14.0-500.el9')).toBe(true);
    expect(matchesRpmVersionRange(row, '5.14.0-687.el9')).toBe(false);
  });

  it('behaves as before for a row that carries no stream fixes', () => {
    const plain = { versionStart: null, versionEnd: '0:5.14.0-570.140.1.el9_6', patchAvailable: false, streamFixes: [] };
    expect(matchesRpmVersionRange(plain, '5.14.0-687.58.1.el9_8')).toBe(false);
  });
});

describe('summaryBudgetChars', () => {
  it('leaves ordinary batches alone', () => {
    // 100 packages x 500 results allows 7,600 chars, well past the longest
    // summary in the database (3,998), so nothing is shortened.
    expect(summaryBudgetChars(50_000)).toBeNull();
    expect(summaryBudgetChars(5_000)).toBeNull();
    expect(summaryBudgetChars(500)).toBeNull();
    expect(summaryBudgetChars(0)).toBeNull();
  });

  it('shortens only once the batch is big enough to overflow', () => {
    // The crash case: 1,000 packages x 500 results.
    expect(summaryBudgetChars(500_000)).toBe(400);
  });

  it('keeps every reachable batch inside the V8 string limit', () => {
    // 500,000 is the most a batch returns (BATCH_RESULTS_TOTAL, see
    // batchResultCap). Beyond that even a zero-length summary would not fit,
    // so raising it needs more than this helper.
    const V8_MAX = 536_870_888;
    for (const total of [1, 5_000, 50_000, 90_000, 100_000, 250_000, 500_000]) {
      const allowed = summaryBudgetChars(total) ?? 4_000;
      expect(total * (allowed + 400), `${total} results`).toBeLessThan(V8_MAX);
    }
  });

  it('never returns a negative length', () => {
    expect(summaryBudgetChars(500_000_000)).toBe(0);
  });
});

describe('batchResultCap', () => {
  it('allows the full per-package cap while the batch total fits', () => {
    expect(batchResultCap([])).toBe(BATCH_RESULTS_PER_PACKAGE);
    expect(batchResultCap([9_133, 3, 0])).toBe(BATCH_RESULTS_PER_PACKAGE);
    expect(batchResultCap(Array(25).fill(20_000))).toBe(BATCH_RESULTS_PER_PACKAGE);
  });

  it('lowers the cap just enough to bring the total within the budget', () => {
    // 200 packages of 5,000 would be 1,000,000: 2,500 each brings it to 500,000.
    expect(batchResultCap(Array(200).fill(5_000))).toBe(2_500);
    // Small packages keep everything; only the large ones are cut.
    const counts = [...Array(900).fill(10), ...Array(100).fill(9_000)];
    const cap = batchResultCap(counts);
    const total = counts.reduce((n, c) => n + Math.min(c, cap), 0);
    expect(total).toBeLessThanOrEqual(BATCH_RESULTS_TOTAL);
    expect(counts.reduce((n, c) => n + Math.min(c, cap + 1), 0)).toBeGreaterThan(BATCH_RESULTS_TOTAL);
  });

  it('never cuts a package below the old 500', () => {
    // The schema's worst case: 1,000 packages, each matching far more than the cap.
    expect(batchResultCap(Array(1_000).fill(20_000))).toBe(500);
  });
});

describe('keepMostSevere', () => {
  it('returns everything, in its order, when it fits', () => {
    const items = [makeResult({ id: 'a', cvssScore: 3 }), makeResult({ id: 'b', cvssScore: 9 })];
    expect(keepMostSevere(items, 2)).toBe(items);
  });

  it('keeps known exploited first, then the highest CVSS, unscored last', () => {
    const items = [
      makeResult({ id: 'low', cvssScore: 3.1 }),
      makeResult({ id: 'none', cvssScore: null }),
      makeResult({ id: 'kev', cvssScore: 5.5, isKev: true }),
      makeResult({ id: 'crit', cvssScore: 9.8 }),
      makeResult({ id: 'high', cvssScore: 7.5 }),
    ];
    expect(keepMostSevere(items, 3).map(r => r.id)).toEqual(['kev', 'crit', 'high']);
    expect(keepMostSevere(items, 4).map(r => r.id)).toEqual(['kev', 'crit', 'high', 'low']);
    expect(keepMostSevere(items, 5).map(r => r.id)).toEqual(['low', 'none', 'kev', 'crit', 'high']);
  });

  it('ranks by severity word before CVSS, as clients badge them', () => {
    const items = [
      makeResult({ id: 'scored-high', severity: 'HIGH', cvssScore: 8.8 }),
      makeResult({ id: 'rated-critical', severity: 'CRITICAL', cvssScore: null }),
      makeResult({ id: 'rated-low', severity: 'LOW', cvssScore: 9.8 }),
      makeResult({ id: 'moderate', severity: 'moderate', cvssScore: 5 }),
    ];
    expect(keepMostSevere(items, 3).map(r => r.id)).toEqual(['rated-critical', 'scored-high', 'moderate']);
  });

  it('breaks ties on CVSS, then EPSS', () => {
    const items = [
      makeResult({ id: 'a', severity: 'HIGH', cvssScore: 7.5, epssScore: 0.01 }),
      makeResult({ id: 'b', severity: 'HIGH', cvssScore: 7.5, epssScore: 0.9 }),
      makeResult({ id: 'c', severity: 'HIGH', cvssScore: 8.1, epssScore: null }),
    ];
    expect(keepMostSevere(items, 2).map(r => r.id)).toEqual(['c', 'b']);
  });
});

describe('truncateSummaries', () => {
  it('shortens only summaries over the limit, leaving other fields intact', () => {
    const long = makeResult({ id: 'v1', summary: 'x'.repeat(50), cvssScore: 7.5 });
    const short = makeResult({ id: 'v2', summary: 'fine' });
    const none = makeResult({ id: 'v3', summary: null });
    const results = [{ vulnerabilities: [long, short, none] }];

    expect(truncateSummaries(results, 10)).toBe(1);
    expect(results[0].vulnerabilities[0].summary).toBe('x'.repeat(10));
    expect(results[0].vulnerabilities[1].summary).toBe('fine');
    expect(results[0].vulnerabilities[2].summary).toBeNull();
    // Everything but summary survives untouched.
    expect(results[0].vulnerabilities[0]).toEqual({ ...long, summary: 'x'.repeat(10) });
  });

  it('copies rather than mutating, so cached rows are not poisoned', () => {
    // searchVulnerabilities can hand back objects held in searchResultCache;
    // writing to them would shorten later, smaller requests too.
    const cached = makeResult({ summary: 'y'.repeat(50) });
    truncateSummaries([{ vulnerabilities: [cached] }], 10);
    expect(cached.summary).toBe('y'.repeat(50));
  });
});

describe('filterBySeverity', () => {
  it('passes everything through when no severity filter is given', () => {
    const items = [makeResult({ severity: 'HIGH' }), makeResult({ severity: null })];
    expect(filterBySeverity(items, undefined)).toEqual(items);
    expect(filterBySeverity(items, [])).toEqual(items);
  });

  it('keeps only results matching one of the requested severities', () => {
    const critical = makeResult({ id: 'v1', severity: 'CRITICAL' });
    const high = makeResult({ id: 'v2', severity: 'HIGH' });
    const medium = makeResult({ id: 'v3', severity: 'MEDIUM' });
    expect(filterBySeverity([critical, high, medium], ['CRITICAL', 'HIGH'])).toEqual([critical, high]);
  });

  it('excludes a result with no severity, since there is nothing to compare', () => {
    const unrated = makeResult({ severity: null });
    expect(filterBySeverity([unrated], ['CRITICAL'])).toEqual([]);
  });

  it('matches case-sensitively, consistent with how ecosystem is matched', () => {
    const high = makeResult({ severity: 'HIGH' });
    expect(filterBySeverity([high], ['high'])).toEqual([]);
    expect(filterBySeverity([high], ['HIGH'])).toEqual([high]);
  });

  it('supports a scale outside NVD\'s own (e.g. GHSA\'s MODERATE)', () => {
    const moderate = makeResult({ severity: 'MODERATE' });
    expect(filterBySeverity([moderate], ['MODERATE'])).toEqual([moderate]);
  });
});

describe('suggestPrefixVariants', () => {
  it('matches in lowercase, with spaces as they are, as "_" and as "-"', () => {
    expect(suggestPrefixVariants('Connect secure')).toEqual(['connect secure', 'connect_secure', 'connect-secure']);
  });

  it('does not repeat a spelling, and ignores surrounding whitespace', () => {
    expect(suggestPrefixVariants('  NGINX ')).toEqual(['nginx']);
    expect(suggestPrefixVariants('   ')).toEqual([]);
  });

  it('leaves case to the lowercase match: a model number needs no uppercase variant', () => {
    expect(suggestPrefixVariants('BR-6208')).toEqual(['br-6208']);
  });
});

describe('suggestVendorVariants', () => {
  it('drops or joins the spaces of a typed vendor, in lowercase', () => {
    expect(suggestVendorVariants('Palo Alto')).toEqual(['palo alto', 'paloalto', 'palo_alto', 'palo-alto']);
    expect(suggestVendorVariants('Ivanti')).toEqual(['ivanti']);
  });
});

describe('escapeLikePattern', () => {
  it('escapes the wildcards and the escape character', () => {
    expect(escapeLikePattern('big_ip%')).toBe('big\\_ip\\%');
    expect(escapeLikePattern('a\\b')).toBe('a\\\\b');
  });
});

describe('fixAboveInstalled', () => {
  const byInt = orderByEncoding(v => (/^\d+$/.test(v) ? BigInt(v) : null));

  it('keeps a fix newer than the installed version', () => {
    expect(fixAboveInstalled('11', '10', byInt)).toBe('11');
  });

  it('drops a fix older than or equal to the installed version', () => {
    expect(fixAboveInstalled('9', '10', byInt)).toBeNull();
    expect(fixAboveInstalled('10', '10', byInt)).toBeNull();
  });

  it('keeps the fix when the order cannot tell', () => {
    expect(fixAboveInstalled('9', '10-beta', byInt)).toBe('9');
  });

  it('keeps the fix when no installed version is known', () => {
    expect(fixAboveInstalled('9', undefined, byInt)).toBe('9');
  });

  it('passes a missing fix through', () => {
    expect(fixAboveInstalled(null, '10', byInt)).toBeNull();
  });
});

describe('orderByEncoding', () => {
  // Like normalizeVersion(): 9.3.2408.100 and 9.3.2408.110 encode alike.
  const clamped = orderByEncoding(v => (v.startsWith('9.3.2408.') ? 9003999000n : null));

  it('cannot tell two different versions apart when they encode alike', () => {
    expect(clamped('9.3.2408.107', '9.3.2408.110')).toBeNull();
  });

  it('reads the same string as equal', () => {
    expect(clamped('9.3.2408.107', '9.3.2408.107')).toBe(0);
  });
});

describe('orderByEncoding with plainOnly', () => {
  // Reads a suffix as a pre-release, like normalizeVersion() does for most of them.
  const encode = (v: string) => { const m = v.match(/^(\d+)\.(\d+)\.(\d+)(-.+)?$/); return m ? BigInt(m[1]) * 1_000_000n + BigInt(m[2]) * 1_000n + BigInt(m[3]) - (m[4] ? 1n : 0n) : null; };
  const plain = orderByEncoding(encode, true);

  it('orders dotted numbers', () => {
    expect(plain('6.2.7', '6.5.2')).toBe(-1);
  });

  it('cannot tell once either side has a suffix, so a build like 7.0.1-R1456 is not read as older', () => {
    expect(plain('7.0.1-R1456', '7.0.1')).toBeNull();
    expect(fixAboveInstalled('7.0.1-R1456', '7.0.1', plain)).toBe('7.0.1-R1456');
  });
});

describe('dedup choosing among fixed versions', () => {
  const plain = orderByEncoding(v => { const p = v.split('.').map(Number); return p.some(Number.isNaN) ? null : BigInt(p[0] ?? 0) * 1_000_000n + BigInt(p[1] ?? 0) * 1_000n + BigInt(p[2] ?? 0); }, true);
  const fixOf = (items: VulnerabilityResult[], installed?: string) => dedup(items, installed, plain)[0].fixedVersion;

  it("prefers the vendor's fix over NVD's, whichever came first", () => {
    expect(fixOf([
      makeResult({ source: 'nvd', sources: ['nvd'], fixedVersion: '10.1.37' }),
      makeResult({ sources: ['advisory-tomcat'], fixedVersion: '10.1.39' }),
    ], '10.1.36')).toBe('10.1.39');
  });

  it('ranks OSV above the CNA record and the CNA record above NVD', () => {
    expect(fixOf([
      makeResult({ source: 'nvd', sources: ['nvd'], fixedVersion: '1.0.3' }),
      makeResult({ source: 'cna', sources: ['cna'], fixedVersion: '1.0.2' }),
    ], '1.0.0')).toBe('1.0.2');
    expect(fixOf([
      makeResult({ source: 'cna', sources: ['cna'], fixedVersion: '1.0.2' }),
      makeResult({ source: 'osv', sources: ['osv'], fixedVersion: '1.0.4' }),
    ], '1.0.0')).toBe('1.0.4');
  });

  it("prefers the fix on the installed version's release line", () => {
    expect(fixOf([
      makeResult({ source: 'advisory-splunk', sources: ['advisory-splunk'], fixedVersion: '10.0.2' }),
      makeResult({ source: 'advisory-splunk', sources: ['advisory-splunk'], fixedVersion: '9.4.6' }),
    ], '9.4.5')).toBe('9.4.6');
  });

  it('takes the nearest fix on the same line', () => {
    expect(fixOf([
      makeResult({ source: 'advisory-x', sources: ['advisory-x'], fixedVersion: '8.18.7' }),
      makeResult({ source: 'advisory-x', sources: ['advisory-x'], fixedVersion: '8.18.6' }),
    ], '8.18.5')).toBe('8.18.6');
  });

  it('keeps the first when nothing tells them apart', () => {
    expect(fixOf([
      makeResult({ source: 'advisory-x', sources: ['advisory-x'], fixedVersion: '6.5.4.8-89n' }),
      makeResult({ source: 'advisory-x', sources: ['advisory-x'], fixedVersion: '6.5.4.9-1n' }),
    ], '6.5.4.7')).toBe('6.5.4.8-89n');
  });

  it("orders two fixes from one feed the feed's way when it has its own order", () => {
    const esxi = new Map([['advisory-broadcom', orderByEncoding(v => encodeAdvisoryVersion(BROADCOM_VENDOR, v))]]);
    const items = [
      makeResult({ source: 'advisory-broadcom', sources: ['advisory-broadcom'], fixedVersion: 'ESXi70U3c-19193900' }),
      makeResult({ source: 'advisory-broadcom', sources: ['advisory-broadcom'], fixedVersion: 'ESXi70U2e-19290878' }),
    ];
    expect(dedup(items, '7.0 U2', plain, esxi)[0].fixedVersion).toBe('ESXi70U2e-19290878');
    expect(dedup(items, '7.0 U2', plain)[0].fixedVersion).toBe('ESXi70U3c-19193900');
  });

  it('keeps a lone fix whichever source gave it', () => {
    expect(fixOf([
      makeResult({ source: 'advisory-x', sources: ['advisory-x'], fixedVersion: null }),
      makeResult({ source: 'nvd', sources: ['nvd'], fixedVersion: '2.0.0' }),
    ], '1.0.0')).toBe('2.0.0');
  });
});
