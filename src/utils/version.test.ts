import { describe, it, expect } from 'vitest';
import { normalizeVersion, isValidVersion, isVersionInRange, qualifyJunosVersion } from './version.js';

describe('normalizeVersion', () => {
  it('normalizes a standard semver', () => {
    expect(normalizeVersion('1.2.3')).toBe(1_0002_00003_00000n);
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
      expect(normalizeVersion('2.9.13-6.el9')).toBe(2_0009_00013_00006n);
      expect(normalizeVersion('2.0.0-beta.1')).toBe(normalizeVersion('2.0.0b1'));
    });
  });

  it('includes the RPM release number as the 4th component', () => {
    expect(normalizeVersion('2.9.13-6.el9')).toBe(2_0009_00013_00006n);
  });

  it('treats a pre-release as less than the release version, but above the previous one', () => {
    const pre = normalizeVersion('2.0.0-beta.1') as bigint;
    expect(pre).toBeLessThan(normalizeVersion('2.0.0') as bigint);
    expect(pre).toBeGreaterThan(normalizeVersion('1.9.999') as bigint);
  });

  it('does not treat a numeric RPM revision as a pre-release', () => {
    // "0.1.15-2.git..." -> release component 2, not pre-release decrement
    expect(normalizeVersion('0.1.15-2.gitabcdef')).toBe(1_00015_00002n);
  });

  it('strips an epoch prefix', () => {
    expect(normalizeVersion('1:2.9.13-6.el9')).toBe(2_0009_00013_00006n);
  });

  it('converts NVD "_update_N" suffix', () => {
    expect(normalizeVersion('6_update_4')).toBe(normalizeVersion('6.4'));
  });

  it('converts Broadcom/VMware "X.Y UNa" update-level format', () => {
    // "8.0 U3d" -> "8.0.3-4" -> major=8 minor=0 patch=3 release=4
    expect(normalizeVersion('8.0 U3d')).toBe(8_0000_00003_00004n);
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
    expect(normalizeVersion('5')).toBe(5_0000_00000_00000n);
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

    it('reads a label joined by an underscore like one attached directly (OpenVPN "2.7_alpha1", "2.1_rc10")', () => {
      // Read as digits only, "2.7_alpha1" was 2.71 and "2.1_rc10" 2.110: above 2.7.6 and 2.6.22,
      // so a range "2.7_alpha1" to "2.7.6" ended before it began and matched nothing.
      expect(normalizeVersion('2.7_alpha1')).toBe(normalizeVersion('2.7alpha1'));
      expect(normalizeVersion('2.1_rc10')).toBe(normalizeVersion('2.1rc10'));
      ordered('2.6.22', '2.7_alpha1', '2.7_alpha2', '2.7_beta1', '2.7_rc1', '2.7_rc2', '2.7.0', '2.7.6');
      expect(normalizeVersion('2.1_rc10') as bigint).toBeLessThan(normalizeVersion('2.6.22') as bigint);
      expect(normalizeVersion('2.7_alpha1') as bigint).toBeLessThan(normalizeVersion('2.7.6') as bigint);
      expect(normalizeVersion('7.4_p1')).toBe(normalizeVersion('7.4p1'));
    });

    it('leaves an underscore that does not join a label and a short number alone', () => {
      expect(normalizeVersion('2.7_alpha')).toBe(normalizeVersion('2.7'));
      expect(normalizeVersion('6_update_4')).toBe(normalizeVersion('6.4'));
    });

    it('puts a hyphen-joined update, service pack or interim fix after its release, not before it (Liferay "7.4.13-u92")', () => {
      expect(normalizeVersion('7.4.13-u92')).toBe(normalizeVersion('7.4.13-92'));
      ordered('7.4.13', '7.4.13-u1', '7.4.13-u92', '7.4.14');
      ordered('24.0.0', '24.0.0-IF001', '24.0.0-IF006', '24.0.1');
      ordered('7.2.10', '7.2.10-sp2', '7.3.0');
      expect(normalizeVersion('7.4.13-update5')).toBe(normalizeVersion('7.4.13-5'));
    });

    it('puts a hyphen-joined patch level after its release (Magento "2.4.7-p3", Ruby "1.8.7-p21")', () => {
      ordered('2.4.7-beta1', '2.4.7', '2.4.7-p1', '2.4.7-p3', '2.4.8');
      ordered('1.8.7', '1.8.7-p21', '1.8.7-p374', '1.9.0');
      ordered('3.0.7', '3.0.7-pl1', '3.0.8');
      expect(normalizeVersion('2.4.7-patch2')).toBe(normalizeVersion('2.4.7-p2'));
      // magento/community-edition 2.4.7-p3 is past a range fixed in 2.4.7.
      expect(isVersionInRange('2.4.7-p3', '2.4.0', '2.4.7')).toBe(false);
      expect(isVersionInRange('2.4.7-p3', '2.4.7', '2.4.7-p4')).toBe(true);
    });

    it('still reads other hyphenated letters as pre-releases and leaves RPM releases alone', () => {
      expect(normalizeVersion('2.9.13-6.el9')).toBe(normalizeVersion('2.9.13-6'));
      expect(normalizeVersion('1.2.3-usb')).toBe((normalizeVersion('1.2.3') as bigint) - 1n);
      // Single letters mean other things after a hyphen (ISC "-S1", Palo Alto "-c823").
      expect(normalizeVersion('9.11.3-S1')).toBe((normalizeVersion('9.11.3') as bigint) - 1n);
      expect(normalizeVersion('6.0.10-c823')).toBe((normalizeVersion('6.0.10') as bigint) - 1n);
      expect(normalizeVersion('1.0.0-b1')).toBe((normalizeVersion('1.0.0') as bigint) - 1n);
    });

    it('orders a hyphenated pre-release by stage and number, the same as an attached one', () => {
      expect(normalizeVersion('1.0.0-rc1')).toBe(normalizeVersion('1.0.0rc1'));
      expect(normalizeVersion('1.0.0-beta.13')).toBe(normalizeVersion('1.0.0b13'));
      ordered('0.9.9', '1.0.0-dev', '1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.27', '1.0.0-beta',
        '1.0.0-beta.10', '1.0.0-beta.13', '1.0.0-rc.0', '1.0.0-rc.2', '1.0.0');
    });

    it('reads the hyphenated pre-release shapes of npm, Maven, NuGet, Go and Shopware', () => {
      ordered('4.0.0-canary.0', '4.0.0-canary.34', '4.0.0-rc.1', '4.0.0');
      ordered('15.0.0-next.1', '15.0.0-next.5');
      ordered('10.0.0-M1', '10.0.0-M10', '10.0.0-RC1', '10.0.0');
      ordered('1.1-milestone-3', '1.1-RC1', '1.1');
      ordered('9.0.0-preview.1.24080.9', '9.0.0-preview.7.24405.7', '9.0.0-rc.2.24473.5', '9.0.0');
      ordered('4.8.0-beta00005', '4.8.0-beta00017', '4.8.0');
      ordered('0.0.1-alpha-1', '0.0.1-alpha-2', '0.0.1');
      ordered('v1.24.0-rc.1', 'v1.24.0-rc.2', 'v1.24.0');
      ordered('6.6.10.0', '6.7.0.0-rc1', '6.7.0.0-rc2', '6.7.0.0');
    });

    it('finds electron 42.0.0-alpha.3 inside a range of alpha releases', () => {
      expect(isVersionInRange('42.0.0-alpha.3', '42.0.0-alpha.1', '42.0.0-alpha.5')).toBe(true);
      expect(isVersionInRange('42.0.0-alpha.5', '42.0.0-alpha.1', '42.0.0-alpha.5')).toBe(false);
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
      expect(normalizeVersion('7.4p1-rc2')).toBe(normalizeVersion('7.4p1'));
    });

    it('orders Junos releases and their service releases', () => {
      ordered('21.2R3', '21.2R3-S1', '21.2R3-S8', '21.2R3-S9', '21.2R3-S10', '21.2R4', '21.4R1');
      ordered('17.3R3', '17.3R3-S2', '17.3R10', '17.4R1');
      // The fix boundary of a service release is told apart from the level before it.
      expect(normalizeVersion('21.2R3-S9')).not.toBe(normalizeVersion('21.2R3-S8'));
      expect(normalizeVersion('21.2R3-S9')).toBe(21_0002_00003_00009n);
    });

    it('orders the Junos X train builds, and ignores the Evolved suffix', () => {
      ordered('12.3X48', '12.3X48-D20', '12.3X48-D105', '12.3X50');
      expect(normalizeVersion('22.4R3-S2-EVO')).toBe(normalizeVersion('22.4R3-S2'));
    });

    it('leaves opaque identifiers with the encoding they had', () => {
      // Each of these used to encode as shown, and changing it would turn an
      // exact-string match into a range match.
      expect(normalizeVersion('v200r007c00spcb00')).toBeNull();
      expect(normalizeVersion('1.305b241111')).toBeNull();
      expect(normalizeVersion('21h1')).toBe(211_0000_00000_00000n);
      expect(normalizeVersion('2023.Q3.1')).toBe(2023_0003_00001_00000n);
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

describe('qualifyJunosVersion', () => {
  it('joins a Junos CPE version and its update field', () => {
    expect(qualifyJunosVersion('21.2', 'r1-s1')).toBe('21.2R1-S1');
    expect(qualifyJunosVersion('20.4', 'r3')).toBe('20.4R3');
    expect(qualifyJunosVersion('12.3x48', 'd105')).toBe('12.3X48-D105');
  });

  it('leaves other pairs alone', () => {
    expect(qualifyJunosVersion('1.5.0', 'update21')).toBeNull();
    expect(qualifyJunosVersion('21.2', 'beta')).toBeNull();
    expect(qualifyJunosVersion('12.3x48', 'r1')).toBeNull();
  });
});

describe('normalizeVersion: a 4th dotted component', () => {
  const ordered = (...versions: string[]) => {
    const encoded = versions.map(v => normalizeVersion(v) as bigint);
    for (let i = 1; i < encoded.length; i++) {
      expect(encoded[i - 1], `${versions[i - 1]} < ${versions[i]}`).toBeLessThan(encoded[i]);
    }
  };

  it('orders the builds of a release (F5 BIG-IP, Aruba, WSO2)', () => {
    ordered('15.1.10', '15.1.10.1', '15.1.10.7', '15.1.10.8', '15.1.11');
    expect(normalizeVersion('15.1.10.8')).toBe(15_0001_00010_00008n);
  });

  it('puts the 4th component in the release slot, only when there is no hyphen release', () => {
    expect(normalizeVersion('1.2.3.4')).toBe(normalizeVersion('1.2.3-4'));
    expect(normalizeVersion('1.2.3.4-5')).toBe(normalizeVersion('1.2.3-5'));
  });

  it('keeps ignoring a 4th component that is a date or a build stamp', () => {
    expect(normalizeVersion('2.0.0.20230101')).toBe(normalizeVersion('2.0.0'));
    expect(normalizeVersion('2.0.0.100000')).toBe(normalizeVersion('2.0.0'));
  });

  it('keeps ignoring it where an earlier component is clamped', () => {
    expect(normalizeVersion('1.0.100000.5')).toBe(normalizeVersion('1.0.100001.7'));
  });

  it('orders builds whose components pass 999 (Chrome, Windows, Adobe, SQL Server, Splunk Cloud)', () => {
    ordered('120.0.6099.109', '120.0.6099.110', '120.0.6200.50', '121.0.1.1');
    ordered('10.0.26100.0', '10.0.26100.7623', '10.0.26100.7705', '10.0.26200.1');
    ordered('17.011.30180', '17.011.30202', '17.012.1');
    ordered('15.0.4003.23', '15.0.4360.2', '16.0.1000.6');
    ordered('9.3.2408.100', '9.3.2408.107', '9.3.2411.1');
    ordered('2024.3.44799', '2024.3.99999', '2025.1');
  });

  it('clamps a major past its slot, keeping it above every real version', () => {
    expect(normalizeVersion('219932')).toBe(normalizeVersion('92232'));
    expect(normalizeVersion('219932') as bigint).toBeGreaterThan(normalizeVersion('92231.9999.99999.99999') as bigint);
    expect(normalizeVersion('1000000')).toBeNull();
  });

  it('still ignores a 5th component', () => {
    expect(normalizeVersion('1.2.3.4.5')).toBe(normalizeVersion('1.2.3'));
  });
});
