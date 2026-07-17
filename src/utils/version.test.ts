import { describe, it, expect } from 'vitest';
import { normalizeVersion, isValidVersion, isVersionInRange } from './version.js';

describe('normalizeVersion', () => {
  it('normalizes a standard semver', () => {
    expect(normalizeVersion('1.2.3')).toBe(1002003000n);
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

  it('returns null for non-numeric garbage', () => {
    expect(normalizeVersion('not-a-version')).not.toBeNull(); // strips to "0" components, does not fail
  });

  it('handles missing minor/patch as zero', () => {
    expect(normalizeVersion('5')).toBe(5000000000n);
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
