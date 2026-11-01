import { describe, it, expect } from 'vitest';
import { compareGoVersions, parseGoVersion } from './go-version.js';
import { normalizeVersion } from './version.js';

describe('parseGoVersion', () => {
  it('reads a module version, with or without "v", ignoring build metadata', () => {
    expect(parseGoVersion('v1.9.10')).toEqual({ core: [1, 9, 10], pre: [] });
    expect(parseGoVersion('1.9.10-0.20250517140552-daee3ac7ade1')).toEqual({ core: [1, 9, 10], pre: ['0', '20250517140552-daee3ac7ade1'] });
    expect(parseGoVersion('2.0.14+incompatible')).toEqual({ core: [2, 0, 14], pre: [] });
  });

  it('returns null for what is not a module version', () => {
    for (const v of ['', '0', '1.13', '0.4.4.3', '9.6.0b1', 'devel']) expect(parseGoVersion(v), v).toBeNull();
  });
});

describe('compareGoVersions', () => {
  const ordered = (...versions: string[]) => {
    for (let i = 1; i < versions.length; i++) {
      expect(compareGoVersions(versions[i - 1], versions[i]), `${versions[i - 1]} < ${versions[i]}`).toBe(-1);
      expect(compareGoVersions(versions[i], versions[i - 1]), `${versions[i]} > ${versions[i - 1]}`).toBe(1);
    }
  };

  it('orders the pseudo-versions of an untagged module by their timestamp (all encode to 0)', () => {
    expect(normalizeVersion('0.0.0-20220623162515-580d9db85e04')).toBe(normalizeVersion('0.0.0-20241213221912-68b004a48f41'));
    ordered('0', '0.0.0-20220623162515-580d9db85e04', '0.0.0-20240527191746-e0fe7cc39172', '0.0.0-20241213221912-68b004a48f41', 'v0.0.1');
  });

  it('puts pseudo-versions after the release they build on and before the next', () => {
    ordered('1.9.9', '1.9.10-0.20250517140552-daee3ac7ade1', '1.9.10-0.20260728074433-a3999bd78a3b', '1.9.10');
    ordered('v1.2.3', 'v1.2.4-0.20240101000000-abcdefabcdef', 'v1.2.4');
  });

  it('follows semver pre-release order: numbers by value and below words', () => {
    ordered('1.27.0-0', '1.27.0-rc.1', '1.27.0-rc.3', '1.27.0-rc.10', '1.27.0');
    ordered('1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0');
  });

  it('ignores "v" and build metadata', () => {
    expect(compareGoVersions('v2.0.14+incompatible', '2.0.14')).toBe(0);
  });

  it('returns null when a side is not a module version', () => {
    expect(compareGoVersions('1.13', '1.13.1')).toBeNull();
  });
});
