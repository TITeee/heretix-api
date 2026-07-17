import { describe, it, expect } from 'vitest';
import { rpmvercmp, compareRpmVersions } from './rpm-version.js';

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
