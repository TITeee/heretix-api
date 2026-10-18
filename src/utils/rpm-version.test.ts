import { describe, it, expect } from 'vitest';
import { rpmvercmp, compareRpmVersions, rpmReleaseStream } from './rpm-version.js';

describe('rpmvercmp', () => {
  it('returns 0 for identical strings', () => {
    expect(rpmvercmp('1.0.0', '1.0.0')).toBe(0);
  });

  it('compares numeric segments numerically, not lexicographically', () => {
    expect(rpmvercmp('1.9', '1.10')).toBe(-1);
    expect(rpmvercmp('1.10', '1.9')).toBe(1);
  });

  it('strips leading zeros before numeric comparison', () => {
    expect(rpmvercmp('01.02', '1.2')).toBe(0);
  });

  it('treats a digit segment as greater than an alpha segment', () => {
    expect(rpmvercmp('1.0', '1.a')).toBe(1);
    expect(rpmvercmp('1.a', '1.0')).toBe(-1);
  });

  it('compares alpha segments lexicographically', () => {
    expect(rpmvercmp('1.a', '1.b')).toBe(-1);
  });

  it('treats the longer string as greater when the other is exhausted', () => {
    expect(rpmvercmp('1.0.1', '1.0')).toBe(1);
  });
});

describe('compareRpmVersions', () => {
  it('compares by epoch first', () => {
    expect(compareRpmVersions('1:1.0-1', '0:9.0-1')).toBe(1);
  });

  it('defaults epoch to 0 when omitted', () => {
    expect(compareRpmVersions('1.0-1', '0:1.0-1')).toBe(0);
  });

  it('falls back to version comparison when epochs are equal', () => {
    expect(compareRpmVersions('1.0-1', '2.0-1')).toBe(-1);
  });

  it('falls back to release comparison when version is equal', () => {
    expect(compareRpmVersions('7.76.1-23.el9', '7.76.1-26.el9_3.3')).toBe(-1);
  });

  it('reports equality for identical epoch:version-release', () => {
    expect(compareRpmVersions('3.2.5-3.el9_7.2', '3.2.5-3.el9_7.2')).toBe(0);
  });

  it('handles a version with no release component', () => {
    expect(compareRpmVersions('3.2.5', '3.2.6')).toBe(-1);
  });
});

describe('rpmReleaseStream', () => {
  it('reads the minor-release tag from the release', () => {
    expect(rpmReleaseStream('5.14.0-687.58.1.el9_8')).toBe('el9_8');
    expect(rpmReleaseStream('0:5.14.0-570.140.1.el9_6')).toBe('el9_6');
    expect(rpmReleaseStream('4.18.0-553.87.1.el8_10')).toBe('el8_10');
    expect(rpmReleaseStream('6.12.0-55.98.1.el10_0')).toBe('el10_0');
  });

  it('is null for a build that carries no minor tag', () => {
    expect(rpmReleaseStream('0.10.4-13.el9')).toBeNull();
    expect(rpmReleaseStream('3.0.7-1.module+el9.2.0+123+abc')).toBeNull();
    expect(rpmReleaseStream('1.0')).toBeNull();
  });

  it('does not take a tag from the version part', () => {
    expect(rpmReleaseStream('1.el9_2-3.el9')).toBeNull();
  });
});
