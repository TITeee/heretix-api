import { describe, it, expect } from 'vitest';
import { verrevcmp, compareDpkgVersions } from './dpkg-version.js';

describe('verrevcmp', () => {
  it('returns 0 for identical strings', () => {
    expect(verrevcmp('1.0.0', '1.0.0')).toBe(0);
  });

  it('compares numeric segments numerically, not lexicographically', () => {
    expect(verrevcmp('1.9', '1.10')).toBe(-1);
    expect(verrevcmp('1.10', '1.9')).toBe(1);
  });

  it('strips leading zeros before numeric comparison', () => {
    expect(verrevcmp('01.02', '1.2')).toBe(0);
  });

  it('sorts a tilde before anything, including the end of the string', () => {
    expect(verrevcmp('1.0~beta1', '1.0')).toBe(-1);
    expect(verrevcmp('1.0~~', '1.0~')).toBe(-1);
  });

  it('sorts letters before other non-digit characters', () => {
    expect(verrevcmp('1.0a', '1.0+')).toBe(-1);
  });

  it('compares letter segments lexicographically', () => {
    expect(verrevcmp('1.a', '1.b')).toBe(-1);
  });

  it('treats a shorter string as less than a longer one with an extra trailing segment', () => {
    // Matches real dpkg behavior: `dpkg --compare-versions 1.0 lt 1.0.0` is true —
    // the extra "." itself (not just the "0" after it) makes "1.0.0" greater.
    expect(verrevcmp('1.0', '1.0.0')).toBe(-1);
  });
});

describe('compareDpkgVersions', () => {
  it('compares by epoch first', () => {
    expect(compareDpkgVersions('1:1.0-1', '0:9.0-1')).toBe(1);
  });

  it('defaults epoch to 0 when omitted', () => {
    expect(compareDpkgVersions('1.0-1', '0:1.0-1')).toBe(0);
  });

  it('falls back to upstream_version comparison when epochs are equal', () => {
    expect(compareDpkgVersions('1.0-1', '2.0-1')).toBe(-1);
  });

  it('falls back to debian_revision comparison when upstream_version is equal', () => {
    expect(compareDpkgVersions('2.9.13-6', '2.9.13-9')).toBe(-1);
  });

  it('reports equality for identical epoch:version-revision', () => {
    expect(compareDpkgVersions('16.02+dfsg-8', '16.02+dfsg-8')).toBe(0);
  });

  it('handles a version with no debian_revision', () => {
    expect(compareDpkgVersions('2005.06.R1', '2005.08.R1')).toBe(-1);
  });

  it('treats a pre-release tilde suffix as less than the plain release', () => {
    expect(compareDpkgVersions('2.9.2-r1~rc1', '2.9.2-r1')).toBe(-1);
  });
});
