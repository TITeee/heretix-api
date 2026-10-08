import { describe, it, expect } from 'vitest';
import { normalizeVersion, isValidVersion, isVersionInRange } from './version.js';

describe('normalizeVersion', () => {
  it('normalizes a standard semver', () => {
    expect(normalizeVersion('1.2.3')).toBe(1002003000n);
  });

  describe('Go module pseudo-versions', () => {
    // Real CVE-2022-29526 declaration: the fix is expressed as a pseudo-version
    // with no earlier reachable tag (base 0.0.0). Before this fix, a digit-led
    // hash misread the 14-digit timestamp as an RPM release number and
    // overflowed MAX_COMPONENT, returning null -- which versionRangeWhere()
    // treats as "no fix yet", matching every version queried forever.
    it('normalizes a base-0.0.0 pseudo-version with a digit-led hash to 0, not null', () => {
      expect(normalizeVersion('0.0.0-20220412211240-33da011f77ad')).toBe(0n);
    });

    // Real code.cloudfoundry.org/gorouter (CVE-2019-11289) declaration: a
    // letter-led hash tripped the pre-release check, collapsing straight to 0
    // -- already correct by accident for this base-0.0.0 case, so this locks
    // in that the fix doesn't change it.
    it('normalizes a base-0.0.0 pseudo-version with a letter-led hash to 0 as well', () => {
      expect(normalizeVersion('0.0.0-20191101214924-b1b5c44e050f')).toBe(0n);
    });

    // Real data: a pseudo-version with a known prior/next tag as its base sits
    // one step below that tag, same as any other pre-release.
    it('normalizes a non-zero-base pseudo-version to one step below its base', () => {
      const base = normalizeVersion('1.0.1');
      expect(normalizeVersion('1.0.1-20260311144920-9eb2d33064b7')).toBe((base as bigint) - 1n);
    });

    it('handles the "v" prefix the same way as no prefix', () => {
      expect(normalizeVersion('v0.0.0-20220412211240-33da011f77ad')).toBe(0n);
    });

    // Not observed in this DB's data, but valid per the Go spec: a "-0." or
    // "-pre.0." infix joins the timestamp with a dot instead of a hyphen.
    it('extracts the base through a dot-joined "-0." infix', () => {
      const base = normalizeVersion('1.2.4');
      expect(normalizeVersion('v1.2.4-0.20180830153604-fb81aa4f8c6e')).toBe((base as bigint) - 1n);
    });

    it('does not mistake an ordinary RPM release or pre-release for a pseudo-version', () => {
      expect(normalizeVersion('2.9.13-6.el9')).toBe(2009013006n);
      expect(normalizeVersion('2.0.0-beta.1')).toBe((normalizeVersion('2.0.0') as bigint) - 1n);
    });
  });

  it('includes the RPM release number as the 4th component', () => {
    expect(normalizeVersion('2.9.13-6.el9')).toBe(2009013006n);
  });

  it('treats a pre-release as slightly less than the release version', () => {
    const release = normalizeVersion('2.0.0');
    const pre = normalizeVersion('2.0.0-beta.1');
    expect(pre).toBe((release as bigint) - 1n);
  });

  it('does not treat a numeric RPM revision as a pre-release', () => {
    // "0.1.15-2.git..." -> release component 2, not pre-release decrement
    expect(normalizeVersion('0.1.15-2.gitabcdef')).toBe(1015002n);
  });

  it('strips an epoch prefix', () => {
    expect(normalizeVersion('1:2.9.13-6.el9')).toBe(2009013006n);
  });

  it('converts NVD "_update_N" suffix', () => {
    expect(normalizeVersion('6_update_4')).toBe(normalizeVersion('6.4'));
  });

  it('converts Broadcom/VMware "X.Y UNa" update-level format', () => {
    // "8.0 U3d" -> "8.0.3-4" -> major=8 minor=0 patch=3 release=4
    expect(normalizeVersion('8.0 U3d')).toBe(8000003004n);
  });

  it('returns null for abnormally large components', () => {
    expect(normalizeVersion('9999999.0.0')).toBeNull();
  });

  it('clamps a minor component >= 1000 instead of overflowing into major (NVD CPE "9999" convention)', () => {
    // Real data: cpanel CVEs use "67.9999.64" to mean "any 9999.x build of major 67".
    // Before clamping this normalized to 76999064000, sorting *above* "68.0.15"
    // (a different, later major) -- non-monotonic, not just imprecise.
    const introduced = normalizeVersion('67.9999.64')!;
    const fixed = normalizeVersion('68.0.15')!;
    expect(introduced).toBeLessThan(fixed);
  });

  it('clamps a release component >= 1000 instead of overflowing into patch (Oracle Linux UEK kernel builds)', () => {
    // Before clamping, "4.14.35-1844..." overflowed to encode as if patch=36,
    // colliding with the unrelated "4.14.36-..." line.
    const sameLineHigherRelease = normalizeVersion('4.14.35-1844.4.5.el7uek')!;
    const differentLaterPatch = normalizeVersion('4.14.36-100.el7uek')!;
    expect(sameLineHigherRelease).toBeLessThan(differentLaterPatch);
  });

  it('still rejects a truly extreme component as garbage rather than clamping it', () => {
    // Distinguishes "legitimately large" (clamp) from "obviously not a version
    // component at all, e.g. a timestamp" (reject) -- both a plain 7-digit
    // major and the same value from split() into minor hit this.
    expect(normalizeVersion('1.9999999.0')).toBeNull();
  });

  it('returns null for non-numeric garbage', () => {
    expect(normalizeVersion('not-a-version')).not.toBeNull(); // strips to "0" components, does not fail
  });

  it('handles missing minor/patch as zero', () => {
    expect(normalizeVersion('5')).toBe(5000000000n);
  });

  describe('a label attached straight to the number', () => {
    const ordered = (...versions: string[]) => {
      const encoded = versions.map(v => normalizeVersion(v) as bigint);
      for (let i = 1; i < encoded.length; i++) {
        expect(encoded[i - 1], `${versions[i - 1]} < ${versions[i]}`).toBeLessThan(encoded[i]);
      }
    };

    it('does not read the label number into the previous component (Zabbix "6.0.18rc1" read as patch 181)', () => {
      expect(normalizeVersion('6.0.18rc1')).toBeLessThan(normalizeVersion('6.0.18') as bigint);
      expect(normalizeVersion('6.0.18rc1')).toBeGreaterThan(normalizeVersion('6.0.17') as bigint);
    });

    it('orders pre-releases by stage and number, just below their release', () => {
      ordered('1.2.2', '1.2.3.dev1', '1.2.3a1', '1.2.3b2', '1.2.3rc1', '1.2.3rc2', '1.2.3', '1.2.4');
      ordered('3.14.0', '3.15.0a1', '3.15.0a6', '3.15.0b3', '3.15.0rc1', '3.15.0');
      ordered('9.0.0.M1', '9.0.0');
      ordered('2.1.0.dev2', '2.1.0b3.dev13', '2.1.0');
    });

    it('keeps a hyphenated pre-release at release - 1, above every attached one', () => {
      expect(normalizeVersion('1.0.0-rc1')).toBe((normalizeVersion('1.0.0') as bigint) - 1n);
      ordered('1.0.0rc1', '1.0.0-rc1', '1.0.0');
    });

    it('puts a post-release label number in the release slot', () => {
      expect(normalizeVersion('7.4p1')).toBe(normalizeVersion('7.4-1'));
      ordered('7.4', '7.4p1', '7.5', '7.5p1', '7.10p1');
      ordered('1.9.5', '1.9.5p2', '1.9.6', '1.9.10');
      ordered('2.3.0', '2.3.0p9', '2.3.0p49', '2.3.1');
      ordered('17.3R3', '17.3R10', '17.4R1', '18.1R1');
      ordered('17.12.1', '17.12.1z2', '17.12.2');
      ordered('2.5.STABLE3', '2.5.STABLE10', '2.6.STABLE1');
    });

    it('ignores what follows the first hyphen once a label is found', () => {
      expect(normalizeVersion('17.3R3-S2')).toBe(normalizeVersion('17.3R3'));
    });

    it('leaves opaque identifiers with the encoding they had', () => {
      // Each of these used to encode as shown, and changing it would turn an
      // exact-string match into a range match.
      expect(normalizeVersion('v200r007c00spcb00')).toBeNull();
      expect(normalizeVersion('1.305b241111')).toBeNull();
      expect(normalizeVersion('21h1')).toBe(211000000000n);
      expect(normalizeVersion('2023.Q3.1')).toBe(2023003001000n);
      expect(normalizeVersion('1.0.2b05_20181207')).toBe(normalizeVersion('1.0.2505_20181207'));
    });
  });
});

describe('isValidVersion', () => {
  it('accepts standard semver', () => {
    expect(isValidVersion('1.2.3')).toBe(true);
  });

  it('accepts semver with pre-release and build metadata', () => {
    expect(isValidVersion('1.2.3-beta.1+build.5')).toBe(true);
  });

  it('rejects a bare major.minor', () => {
    expect(isValidVersion('1.2')).toBe(false);
  });
});

describe('isVersionInRange', () => {
  it('returns true when within [introduced, fixed)', () => {
    expect(isVersionInRange('1.5.0', '1.0.0', '2.0.0')).toBe(true);
  });

  it('returns false when equal to the exclusive fixed bound', () => {
    expect(isVersionInRange('2.0.0', '1.0.0', '2.0.0')).toBe(false);
  });

  it('returns false when below the introduced bound', () => {
    expect(isVersionInRange('0.9.0', '1.0.0', '2.0.0')).toBe(false);
  });

  it('respects an inclusive lastAffected bound', () => {
    expect(isVersionInRange('2.0.0', '1.0.0', undefined, '2.0.0')).toBe(true);
    expect(isVersionInRange('2.0.1', '1.0.0', undefined, '2.0.0')).toBe(false);
  });

  it('returns false when the target version fails to normalize', () => {
    expect(isVersionInRange('9999999.0.0', '1.0.0', '2.0.0')).toBe(false);
  });
});
